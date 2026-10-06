package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func tasksVertexClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Small actual Viewer-permitted subset; deliberately no Tasks fullView,
	// dispatch/creation or Vertex invocation/training creation permission.
	c.viewerPolicy.permissions = map[string]bool{}
	for _, p := range []string{"cloudtasks.locations.list", "cloudtasks.queues.list", "cloudtasks.tasks.list", "aiplatform.locations.list", "aiplatform.customJobs.list", "aiplatform.customJobs.get", "aiplatform.pipelineJobs.list", "aiplatform.pipelineJobs.get"} {
		c.viewerPolicy.permissions[p] = true
	}
	return c
}

func TestViewerTasksVertexConfigAndPayloadExclusion(t *testing.T) {
	taskPages := 0
	c := tasksVertexClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("unexpected invocation/mutation")
		}
		if strings.HasSuffix(r.URL.Host, "-aiplatform.googleapis.com") {
			if strings.HasSuffix(r.URL.Path, "/customJobs") || strings.HasSuffix(r.URL.Path, "/pipelineJobs") {
				if r.URL.Query().Get("readMask") != "name" {
					t.Fatal("Vertex list not identity-only")
				}
			} else if fields := r.URL.Query().Get("fields"); fields == "" || strings.Contains(fields, "jobDetail") || strings.Contains(fields, "webAccessUris") {
				t.Fatal("Vertex outputs not excluded at API")
			}
		}
		switch r.URL.Host + r.URL.Path {
		case "cloudtasks.googleapis.com/v2/projects/p/locations", "aiplatform.googleapis.com/v1/projects/p/locations":
			return response(200, `{"locations":[{"name":"projects/p/locations/us-central1"}]}`), nil
		case "cloudtasks.googleapis.com/v2/projects/p/locations/us-central1/queues":
			return response(200, `{"queues":[{"name":"projects/p/locations/us-central1/queues/_queue","stackdriverLoggingConfig":{"samplingRatio":0},"httpTarget":{"oidcToken":{"serviceAccountEmail":"queue@p.iam.gserviceaccount.com"}}}]}`), nil
		case "cloudtasks.googleapis.com/v2/projects/123/locations/us-central1/queues/_queue/tasks":
			if r.URL.Query().Get("responseView") != "BASIC" {
				t.Fatal("non-BASIC task query")
			}
			if r.URL.Query().Get("fields") != viewerTaskFields || strings.Contains(viewerTaskFields, "body") {
				t.Fatal("task payloads not excluded at API")
			}
			taskPages++
			if taskPages == 1 {
				return response(200, `{"nextPageToken":"more"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "more" {
				t.Fatal("task pagination omitted")
			}
			return response(200, `{"tasks":[{"name":"projects/p/locations/us-central1/queues/_queue/tasks/_task","httpRequest":{"url":"https://example.invalid/path","oidcToken":{"serviceAccountEmail":"task@p.iam.gserviceaccount.com"},"body":"FORBIDDEN_TASK_BODY","headers":{"Authorization":"FORBIDDEN_HEADER"}},"appEngineHttpRequest":{"body":"FORBIDDEN_APPENGINE_BODY"},"body":"FORBIDDEN_TOPLEVEL_BODY"}]}`), nil
		case "us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/customJobs":
			return response(200, `{"customJobs":[{"name":"projects/123/locations/us-central1/customJobs/100"}]}`), nil
		case "us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/customJobs/100":
			return response(200, `{"name":"projects/p/locations/us-central1/customJobs/100","jobSpec":{"network":"projects/p/global/networks/private","serviceAccount":"custom@p.iam.gserviceaccount.com","workerPoolSpecs":[{"containerSpec":{"imageUri":"example.invalid/image","env":[{"name":"PASSWORD","value":"synthetic"}]}}]},"webAccessUris":{"worker":"FORBIDDEN_ACCESS_URI"}}`), nil
		case "us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/pipelineJobs":
			return response(200, `{"pipelineJobs":[{"name":"projects/p/locations/us-central1/pipelineJobs/pipe"}]}`), nil
		case "us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/pipelineJobs/pipe":
			return response(200, `{"name":"projects/123/locations/us-central1/pipelineJobs/pipe","pipelineSpec":{"root":{}},"serviceAccount":"pipeline@p.iam.gserviceaccount.com","runtimeConfig":{"parameterValues":{"password":"synthetic"}},"jobDetail":{"taskDetails":[{"outputs":"FORBIDDEN_EXECUTION_OUTPUT"}]}}`), nil
		default:
			t.Fatal("wrong host, scope, or unreviewed endpoint", r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerTasksVertex(context.Background(), &s, "p", "projects/123")
	if hasCoverage(s, "failed") || hasCoverage(s, "incomplete") || len(s.Assets) != 4 || taskPages != 2 {
		t.Fatal(s, taskPages)
	}
	for _, a := range s.Assets {
		if !strings.Contains(a.Name, "/projects/123/") || a.Resource.Location != "us-central1" {
			t.Fatal(a)
		}
	}
	if Str(Get(s.Assets[1].Resource.Data, "httpRequest", "oidcToken", "serviceAccountEmail")) != "task@p.iam.gserviceaccount.com" || Str(Get(s.Assets[2].Resource.Data, "jobSpec", "network")) == "" || Obj(s.Assets[3].Resource.Data["runtimeConfig"]) == nil {
		t.Fatal("config schema lost")
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "FORBIDDEN_") {
		t.Fatal("payload/output metadata leaked", string(b))
	}
}

func TestViewerTasksRejectForeignQueueAndMalformedRequests(t *testing.T) {
	for _, body := range []string{
		`{"tasks":[{"name":"projects/p/locations/us-central1/queues/other/tasks/task"}]}`,
		`{"tasks":[{"name":"projects/other/locations/us-central1/queues/q/tasks/task"}]}`,
		`{"tasks":[{"name":"projects/p/locations/us-central1/queues/q/tasks/task","httpRequest":42}]}`,
		`{"tasks":{}}`,
	} {
		c := tasksVertexClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		s := Snapshot{}
		c.viewerTasks(context.Background(), &s, "projects/123/locations/us-central1/queues/q", "p", "projects/123")
		if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
			t.Fatal(s)
		}
	}
}

func TestViewerVertexMissingOrMismatchedDetailsDoNotInferPosture(t *testing.T) {
	for _, body := range []string{`{"name":"projects/123/locations/us-central1/customJobs/100"}`, `{"name":"projects/foreign/locations/us-central1/customJobs/100","jobSpec":{}}`, `{"name":"projects/123/locations/europe-west1/customJobs/100","jobSpec":{}}`} {
		c := tasksVertexClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/customJobs") {
				return response(200, `{"customJobs":[{"name":"projects/p/locations/us-central1/customJobs/100"}]}`), nil
			}
			return response(200, body), nil
		})
		s := Snapshot{}
		c.viewerVertexJobs(context.Background(), &s, "p", "projects/123", "us-central1", "customJobs")
		if (!hasCoverage(s, "failed") && !hasCoverage(s, "incomplete")) || len(s.Assets) != 0 {
			t.Fatal(s)
		}
	}
}

func TestViewerTasksVertexNoGuessAfterLocationFailure(t *testing.T) {
	calls := 0
	c := tasksVertexClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasSuffix(r.URL.Path, "/locations") {
			t.Fatal("guessed region")
		}
		return response(403, "DO_NOT_SAVE_ERROR"), nil
	})
	s := Snapshot{}
	c.CollectViewerTasksVertex(context.Background(), &s, "p", "projects/123")
	if calls != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_SAVE_ERROR") {
		t.Fatal("upstream body persisted")
	}
}

func TestViewerTasksVertexContinuesAfterUnreachablePage(t *testing.T) {
	pages := 0
	c := tasksVertexClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/100") {
			return response(200, `{"name":"projects/123/locations/us-central1/customJobs/100","jobSpec":{}}`), nil
		}
		pages++
		if pages == 1 {
			return response(200, `{"unreachable":["other"],"nextPageToken":"more"}`), nil
		}
		return response(200, `{"customJobs":[{"name":"projects/p/locations/us-central1/customJobs/100"}]}`), nil
	})
	s := Snapshot{}
	c.viewerVertexJobs(context.Background(), &s, "p", "projects/123", "us-central1", "customJobs")
	if pages != 2 || len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s, pages)
	}
}
