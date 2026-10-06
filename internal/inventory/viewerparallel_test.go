package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestViewerTaskPoolOverlapAndBound(t *testing.T) {
	for _, limit := range []int{1, 3, 8} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			c := &Client{Concurrency: limit}
			var active, peak atomic.Int32
			gate := make(chan struct{})
			ready := make(chan struct{}, limit)
			var once sync.Once
			tasks := make([]viewerTask, 25)
			for i := range tasks {
				tasks[i] = viewerTask{run: func() {
					n := active.Add(1)
					for old := peak.Load(); n > old; old = peak.Load() {
						if peak.CompareAndSwap(old, n) {
							break
						}
					}
					select {
					case ready <- struct{}{}:
					default:
					}
					<-gate
					active.Add(-1)
				}}
			}
			done := make(chan struct{})
			go func() { c.runViewerTasks(context.Background(), tasks); close(done) }()
			defer once.Do(func() { close(gate) })
			for i := 0; i < limit; i++ {
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("workers did not overlap")
				}
			}
			once.Do(func() { close(gate) })
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("pool did not finish")
			}
			if got := peak.Load(); got != int32(limit) {
				t.Fatalf("peak %d, wanted %d", got, limit)
			}
		})
	}
}

func TestViewerTaskPoolCancellationDoesNotStartQueuedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{Concurrency: 1}
	var starts atomic.Int32
	tasks := make([]viewerTask, 100)
	for i := range tasks {
		tasks[i] = viewerTask{run: func() { starts.Add(1); cancel() }}
	}
	c.runViewerTasks(ctx, tasks)
	if starts.Load() != 1 {
		t.Fatalf("started %d after cancellation", starts.Load())
	}
	c.runViewerTasks(ctx, tasks)
	if starts.Load() != 1 {
		t.Fatal("cancelled context started work")
	}
}

func TestViewerTaskPoolPerProjectLimitDoesNotStarveOtherProjects(t *testing.T) {
	c := &Client{Concurrency: 4, PerProjectConcurrency: 2}
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	started := make(chan string, 4)
	var mu sync.Mutex
	active := map[string]int{}
	var violation atomic.Bool
	var tasks []viewerTask
	for _, scope := range []string{"projects/1", "projects/2"} {
		for i := 0; i < 8; i++ {
			scope := scope
			tasks = append(tasks, viewerTask{scope: scope, run: func() {
				mu.Lock()
				active[scope]++
				if active[scope] > 2 {
					violation.Store(true)
				}
				mu.Unlock()
				select {
				case started <- scope:
				default:
				}
				<-gate
				mu.Lock()
				active[scope]--
				mu.Unlock()
			}})
		}
	}
	done := make(chan struct{})
	go func() { c.runViewerTasks(context.Background(), tasks); close(done) }()
	counts := map[string]int{}
	for i := 0; i < 4; i++ {
		select {
		case scope := <-started:
			counts[scope]++
		case <-time.After(5 * time.Second):
			t.Fatal("busy project starved another project")
		}
	}
	if counts["projects/1"] != 2 || counts["projects/2"] != 2 || violation.Load() {
		t.Fatalf("per-project limits violated: %v", counts)
	}
	release.Do(func() { close(gate) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler did not finish")
	}
	if violation.Load() {
		t.Fatal("per-project concurrency exceeded")
	}
}

func TestViewerFamilyDependencyOrder(t *testing.T) {
	c := &Client{}
	families := c.viewerFamilies()
	names := map[string][]string{}
	collectors := 0
	for _, family := range families {
		for _, collect := range family.collect {
			collectors++
			fn := runtime.FuncForPC(reflect.ValueOf(collect).Pointer()).Name()
			fn = strings.TrimSuffix(fn[strings.LastIndex(fn, ".")+1:], "-fm")
			names[family.name] = append(names[family.name], fn)
		}
	}
	if len(families) != 34 || collectors != 58 {
		t.Fatalf("collector topology changed: %d families / %d collectors", len(families), collectors)
	}
	for family, expected := range map[string][]string{
		"alloydb":                        {"CollectViewerAlloyDB", "CollectViewerAlloyDBUsers"},
		"bigtable":                       {"CollectViewerBigtable", "CollectViewerBigtableAuthorizedViews"},
		"spanner":                        {"CollectViewerSpanner", "CollectViewerSpannerDDL"},
		"dns":                            {"CollectViewerDNSIAM", "CollectViewerDNSRecords", "CollectViewerDNSPolicies", "CollectViewerDNSResponseRules"},
		"secrets-kms":                    {"CollectViewerKeyMetadata", "CollectViewerRegionalSecrets", "CollectViewerSecretAliases", "CollectViewerSecretIAM"},
		"serverless-build-workflows":     {"CollectViewerServerless", "CollectViewerBuildWorkflows", "CollectViewerWorkflowExecutions", "CollectViewerHistoricalSecrets", "CollectViewerBuildRepositoryReferences"},
		"compute-network":                {"viewerCompute", "CollectViewerBackendServices", "CollectViewerRoutes", "CollectViewerComputeExtras", "CollectViewerComputeDisks", "CollectViewerNetworks", "CollectViewerEffectiveFirewalls", "CollectViewerRegionalEffectiveFirewalls"},
		"api-gateway-service-management": {"CollectViewerAPIGateway", "CollectViewerServiceManagement"},
	} {
		if !reflect.DeepEqual(names[family], expected) {
			t.Fatalf("%s dependency order: %v", family, names[family])
		}
	}
}

func TestViewerTaskSchedulerProgressAccounting(t *testing.T) {
	for _, cancelWork := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelWork), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []ProgressEvent
			c := &Client{Concurrency: 1, Progress: func(e ProgressEvent) {
				if e.Phase == "scheduler" {
					events = append(events, e)
				}
			}}
			tasks := make([]viewerTask, 12)
			for i := range tasks {
				tasks[i] = viewerTask{family: "fixture", run: func() {
					if cancelWork {
						cancel()
					}
				}}
			}
			c.runViewerTasks(ctx, tasks)
			previous := 0
			for _, e := range events {
				if e.Total != len(tasks) || e.Queued+e.Running+e.Completed+e.Cancelled != e.Total || e.Running > 1 || e.Completed < previous {
					t.Fatalf("invalid accounting: %+v", e)
				}
				previous = e.Completed
			}
			last := events[len(events)-1]
			if last.Running != 0 || last.Queued != 0 || (!cancelWork && last.Completed != len(tasks)) || (cancelWork && last.Cancelled != len(tasks)) {
				t.Fatalf("invalid terminal accounting: %+v", last)
			}
		})
	}
}

// Exercise the actual ViewerCloud entry point, not only the scheduler. Both
// project metadata and independent project/service requests must overlap, and
// serial/parallel output must be byte-identical despite reversed completion.
func TestViewerCloudParallelProjectsAndFamiliesDeterministic(t *testing.T) {
	collect := func(limit int) (Snapshot, int32, bool, bool, bool) {
		var active, peak atomic.Int32
		var metadataActive, serviceActive atomic.Int32
		var metadataOverlap, serviceOverlap atomic.Bool
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			path := r.URL.Path
			if r.URL.Host == "cloudresourcemanager.googleapis.com" {
				switch path {
				case "/v3/projects":
					return response(200, `{"projects":[{"name":"projects/123","parent":"organizations/9","state":"ACTIVE"},{"name":"projects/456","parent":"organizations/9","state":"ACTIVE"}]}`), nil
				case "/v3/folders":
					return response(200, `{}`), nil
				case "/v3/organizations/9":
					return response(200, `{"name":"organizations/9"}`), nil
				case "/v3/projects/123", "/v3/projects/456":
					if metadataActive.Add(1) > 1 {
						metadataOverlap.Store(true)
					}
					defer metadataActive.Add(-1)
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-time.After(10 * time.Millisecond):
					}
					id := "demo-one"
					if strings.HasSuffix(path, "456") {
						id = "demo-two"
					}
					return response(200, fmt.Sprintf(`{"name":%q,"projectId":%q,"parent":"organizations/9"}`, strings.TrimPrefix(path, "/v3/"), id)), nil
				default:
					return response(200, `{"bindings":[]}`), nil
				}
			}
			if r.URL.Host == "cloudasset.googleapis.com" && strings.HasSuffix(path, ":searchAllIamPolicies") {
				return response(200, `{}`), nil
			}
			// A real cross-service enrichment formerly depended on serial global
			// snapshot visibility. Keep this populated fixture to catch splitting
			// API Gateway and Service Management into isolated snapshots again.
			switch r.URL.Host + path {
			case "apigateway.googleapis.com/v1/projects/demo-one/locations/global/apis":
				return response(200, `{"apis":[{"name":"projects/demo-one/locations/global/apis/api","managedService":"example.com"}]}`), nil
			case "apigateway.googleapis.com/v1/projects/demo-one/locations/global/apis/api/configs":
				return response(200, `{"apiConfigs":[{"name":"projects/demo-one/locations/global/apis/api/configs/config","serviceConfigId":"compiled"}]}`), nil
			case "apigateway.googleapis.com/v1/projects/demo-one/locations/global/apis/api/configs/config":
				return response(200, `{"name":"projects/demo-one/locations/global/apis/api/configs/config","serviceConfigId":"compiled"}`), nil
			case "apigateway.googleapis.com/v1/projects/demo-one/locations":
				return response(200, `{"locations":[{"name":"projects/demo-one/locations/us-central1","locationId":"us-central1"}]}`), nil
			case "apigateway.googleapis.com/v1/projects/demo-one/locations/us-central1/gateways":
				return response(200, `{"gateways":[{"name":"projects/demo-one/locations/us-central1/gateways/gateway","state":"ACTIVE","apiConfig":"projects/demo-one/locations/global/apis/api/configs/config"}]}`), nil
			case "servicemanagement.googleapis.com/v1/services":
				if r.URL.Query().Get("producerProjectId") == "demo-one" {
					return response(200, `{"services":[{"serviceName":"example.com","producerProjectId":"demo-one"}]}`), nil
				}
			case "servicemanagement.googleapis.com/v1/services/example.com":
				return response(200, `{"serviceName":"example.com","producerProjectId":"demo-one"}`), nil
			case "servicemanagement.googleapis.com/v1/services/example.com/configs":
				return response(200, `{"serviceConfigs":[{"name":"example.com","id":"compiled","producerProjectId":"demo-one"}]}`), nil
			case "servicemanagement.googleapis.com/v1/services/example.com/configs/compiled":
				return response(200, `{"name":"example.com","id":"compiled","producerProjectId":"demo-one"}`), nil
			}
			if serviceActive.Add(1) > 1 {
				serviceOverlap.Store(true)
			}
			defer serviceActive.Add(-1)
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-time.After(time.Millisecond):
			}
			return response(404, `{}`), nil
		})
		c.Concurrency = limit
		var firstFamilies []ProgressEvent
		c.Progress = func(e ProgressEvent) {
			if e.Phase == "collector" && e.Status == "started" && e.Collector != "metadata" && e.Collector != "iam-search" && len(firstFamilies) < 2 {
				firstFamilies = append(firstFamilies, e)
			}
		}
		out := c.ViewerCloud(context.Background(), "organizations/9")
		mixed := len(firstFamilies) == 2 && firstFamilies[0].Scope != firstFamilies[1].Scope && firstFamilies[0].Collector != firstFamilies[1].Collector
		return out, peak.Load(), metadataOverlap.Load(), serviceOverlap.Load(), mixed
	}
	serial, serialPeak, _, _, serialMixed := collect(1)
	parallel, parallelPeak, metadata, service, _ := collect(3)
	// Verify dispatch ordering with serial callbacks: concurrent workers may
	// report their starts in a different order after receiving their tasks.
	if !serialMixed {
		t.Fatal("scheduler did not mix projects and service families")
	}
	if serialPeak != 1 || parallelPeak > 3 || parallelPeak < 2 || !metadata || !service {
		t.Fatalf("serial peak=%d parallel=%d metadata overlap=%v service overlap=%v", serialPeak, parallelPeak, metadata, service)
	}
	a, err := json.Marshal(serial)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(parallel)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("serial and parallel inventory differ")
	}
	var pins []any
	for _, asset := range parallel.Assets {
		if asset.Type == ServiceConfigType {
			pins = List(asset.Resource.Data["_gcpbusterGatewayPins"])
		}
	}
	if len(pins) != 1 || len(List(Obj(pins[0])["gateways"])) != 1 {
		t.Fatal("cross-service API Gateway deployment pins lost", pins)
	}
}
