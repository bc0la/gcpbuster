package inventory

import (
	"context"
	"sync"
	"time"
)

type viewerProject struct{ id, number string }
type viewerCollector func(context.Context, *Snapshot, string, string)
type viewerFamily struct {
	name    string
	collect []viewerCollector
}
type viewerTask struct {
	scope, family, account string
	run                    func()
	out                    *Snapshot
}

// runViewerTasks uses one global pool for a stage: projects never create nested
// service pools. Library callers default to serial; the CLI explicitly opts in.
// The dispatcher checks cancellation before handing out any more work, and each
// worker checks it again after receiving a task. In-flight HTTP uses the context.
func (c *Client) runViewerTasks(ctx context.Context, tasks []viewerTask) {
	n := c.Concurrency
	if n < 1 {
		n = 1
	}
	if n > len(tasks) {
		n = len(tasks)
	}
	if n == 0 {
		return
	}
	// Counters are stage-local and emitted while holding this lock so callback
	// consumers observe a monotonic completed count even with concurrent workers.
	var stateMu sync.Mutex
	queued, running, completed, cancelled := len(tasks), 0, 0, 0
	stage := tasks[0].family
	for _, task := range tasks {
		if task.family != stage {
			stage = "service-families"
			break
		}
	}
	emitState := func(status string) {
		c.ReportProgress(ProgressEvent{Phase: "scheduler", Collector: stage, Status: status, Total: len(tasks), Queued: queued, Running: running, Completed: completed, Cancelled: cancelled})
	}
	emitState("started")
	// Publish the whole plan before any starts so per-project views can show
	// queued work even when their project has not reached a worker yet.
	for _, task := range tasks {
		c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Account: task.account, Collector: task.family, Status: "queued"})
	}
	queue := make(chan viewerTask)
	finished := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range queue {
				stateMu.Lock()
				if ctx.Err() != nil {
					queued--
					cancelled++
					emitState("progress")
					stateMu.Unlock()
					c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Account: task.account, Collector: task.family, Status: "cancelled"})
					finished <- task.scope
					continue
				}
				queued--
				running++
				emitState("progress")
				stateMu.Unlock()
				started := time.Now()
				c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Account: task.account, Collector: task.family, Status: "started"})
				restored := false
				cacheable := c.CollectionCheckpoint != nil && task.out != nil && checkpointFamily(task.family)
				if cacheable {
					saved, found, err := c.CollectionCheckpoint.Load(ctx, task.scope, task.family)
					if err != nil {
						c.ReportProgress(ProgressEvent{Phase: "checkpoint", Scope: task.scope, Account: task.account, Collector: task.family, Status: "failed", Reason: "checkpoint read failed; collecting again"})
					} else if found && checkpointComplete(saved) {
						*task.out = saved
						restored = true
					}
				}
				if !restored {
					task.run()
					if cacheable && ctx.Err() == nil && checkpointComplete(*task.out) {
						if err := c.CollectionCheckpoint.Save(ctx, task.scope, task.family, *task.out); err != nil {
							task.out.Coverage = append(task.out.Coverage, Coverage{Source: "collection-checkpoint:" + task.scope + ":" + task.family, Status: "incomplete", Error: "Private collection checkpoint could not be saved; this task must be collected again on resume."})
						}
					}
				}
				status := "completed"
				count, failures := 0, 0
				if task.out != nil {
					count = len(task.out.Assets)
					for _, coverage := range task.out.Coverage {
						if coverage.Status == "failed" || coverage.Status == "incomplete" {
							failures++
						}
					}
				}
				if ctx.Err() != nil {
					status = "cancelled"
				} else if restored {
					c.ReportProgress(ProgressEvent{Phase: "checkpoint", Scope: task.scope, Account: task.account, Collector: task.family, Status: "restored", Count: count})
				}
				c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Account: task.account, Cached: restored, Collector: task.family, Status: status, Count: count, Failures: failures, Duration: time.Since(started)})
				stateMu.Lock()
				running--
				if status == "cancelled" {
					cancelled++
				} else {
					completed++
				}
				emitState("progress")
				stateMu.Unlock()
				finished <- task.scope
			}
		}()
	}
	// Match BezosBuster's per-account + global limits without having workers
	// occupy global slots while waiting on a busy project's semaphore. Only
	// eligible tasks are handed to a worker; other projects can make progress.
	perProject := c.PerProjectConcurrency
	if perProject < 1 || perProject > n {
		perProject = n
	}
	active := make(map[string]int)
	pending := append([]viewerTask(nil), tasks...)
	inFlight := 0
dispatch:
	for len(pending) > 0 || inFlight > 0 {
		if ctx.Err() != nil {
			break
		}
		eligible := -1
		for i, task := range pending {
			if active[task.scope] < perProject {
				eligible = i
				break
			}
		}
		var send chan viewerTask
		var next viewerTask
		if eligible >= 0 && inFlight < n {
			send, next = queue, pending[eligible]
		}
		select {
		case <-ctx.Done():
			break dispatch
		case scope := <-finished:
			active[scope]--
			inFlight--
		case send <- next:
			active[next.scope]++
			inFlight++
			pending = append(pending[:eligible], pending[eligible+1:]...)
		}
	}
	close(queue)
	wg.Wait()
	// Pending tasks never reached a worker but still need a terminal event so
	// Accounts cannot retain stale queued counts after cancellation.
	for _, task := range pending {
		c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Account: task.account, Collector: task.family, Status: "cancelled"})
	}
	stateMu.Lock()
	status := "completed"
	if ctx.Err() != nil {
		status = "cancelled"
		cancelled += queued
		queued = 0
	}
	emitState(status)
	stateMu.Unlock()
}

// Dependent enrichers remain ordered in the same family and share only their
// own snapshot. Independent families never read or mutate another's output.
func (c *Client) viewerFamilies() []viewerFamily {
	return []viewerFamily{
		{"compute-network", []viewerCollector{c.viewerCompute, c.CollectViewerBackendServices, c.CollectViewerRoutes, c.CollectViewerComputeExtras, c.CollectViewerComputeDisks, c.CollectViewerNetworks, c.CollectViewerEffectiveFirewalls, c.CollectViewerRegionalEffectiveFirewalls}},
		{"model-armor", []viewerCollector{c.CollectViewerModelArmor}},
		{"storage", []viewerCollector{c.viewerBuckets}},
		{"sql-gke", []viewerCollector{c.CollectViewerSQLGKE}},
		{"redis", []viewerCollector{c.CollectViewerRedis}},
		{"memcache", []viewerCollector{c.CollectViewerMemcache}},
		{"alloydb", []viewerCollector{c.CollectViewerAlloyDB, c.CollectViewerAlloyDBUsers}},
		{"filestore", []viewerCollector{c.CollectViewerFilestore}},
		{"bigtable", []viewerCollector{c.CollectViewerBigtable, c.CollectViewerBigtableAuthorizedViews}},
		{"spanner", []viewerCollector{c.CollectViewerSpanner, c.CollectViewerSpannerDDL}},
		{"firestore", []viewerCollector{c.CollectViewerFirestore}},
		{"healthcare", []viewerCollector{c.CollectViewerHealthcare}},
		{"apigee", []viewerCollector{c.CollectViewerApigee}},
		{"serverless-build-workflows", []viewerCollector{c.CollectViewerServerless, c.CollectViewerBuildWorkflows, c.CollectViewerWorkflowExecutions, c.CollectViewerHistoricalSecrets, c.CollectViewerBuildRepositoryReferences}},
		{"dns", []viewerCollector{c.CollectViewerDNSIAM, c.CollectViewerDNSRecords, c.CollectViewerDNSPolicies, c.CollectViewerDNSResponseRules}},
		{"api-keys", []viewerCollector{c.CollectViewerAPIKeys}},
		{"secrets-kms", []viewerCollector{c.CollectViewerKeyMetadata, c.CollectViewerRegionalSecrets, c.CollectViewerSecretAliases, c.CollectViewerSecretIAM}},
		{"parameters", []viewerCollector{c.CollectViewerParameterManager}},
		{"deployment-manager", []viewerCollector{c.CollectViewerDeploymentManager}},
		{"automation", []viewerCollector{c.CollectViewerAutomation}},
		{"pubsub", []viewerCollector{c.CollectViewerPubSub, c.CollectViewerPubSubSchemas, c.CollectViewerPubSubSnapshots}},
		{"data-identity-config", []viewerCollector{c.CollectViewerDataConfig}},
		{"tasks-vertex", []viewerCollector{c.CollectViewerTasksVertex}},
		// Managed compiled configs correlate explicit API Gateway deployment pins.
		{"api-gateway-service-management", []viewerCollector{c.CollectViewerAPIGateway, c.CollectViewerServiceManagement}},
		{"service-usage", []viewerCollector{c.CollectViewerServiceUsage}},
		{"app-engine", []viewerCollector{c.CollectViewerAppEngine, c.CollectViewerAppEngineFirewall}},
		{"federation", []viewerCollector{c.CollectViewerFederation}},
		{"dataflow", []viewerCollector{c.CollectViewerDataflow}},
		{"dataproc", []viewerCollector{c.CollectViewerDataprocSecrets}},
		{"workbench", []viewerCollector{c.CollectViewerNotebookSecrets}},
		{"cloud-deploy", []viewerCollector{c.CollectViewerCloudDeploy}},
		{"app-hosting", []viewerCollector{c.CollectViewerAppHosting}},
		{"data-fusion", []viewerCollector{c.CollectViewerDataFusionSecrets}},
		{"composer", []viewerCollector{c.CollectViewerComposer}},
	}
}
