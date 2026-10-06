package inventory

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestViewerBuildWorkflowsNativeConfigAndCanonicalNames(t *testing.T) {
	locationPages, buildPages, workflowGets := 0, 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("mutation or execution requested")
		}
		switch r.URL.Host + r.URL.Path {
		case "cloudbuild.googleapis.com/v2/projects/p/locations":
			locationPages++
			if locationPages == 1 {
				return response(200, `{"locations":[{"name":"projects/p/locations/us-central1"}],"nextPageToken":"more"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "more" {
				t.Fatal("missing location pagination")
			}
			return response(200, `{"locations":[{"name":"projects/123/locations/us-central1"},{"name":"projects/p/locations/global"}]}`), nil
		case "cloudbuild.googleapis.com/v1/projects/p/locations/global/builds":
			if r.URL.Query().Get("projectId") != "p" {
				t.Fatal("required projectId missing")
			}
			return response(200, `{"builds":[{"id":"global-build","projectId":"p","serviceAccount":"projects/p/serviceAccounts/build@p.iam.gserviceaccount.com","steps":[{"name":"shell","env":["PASSWORD=synthetic-secret"]}]}]}`), nil
		case "cloudbuild.googleapis.com/v1/projects/p/locations/global/triggers":
			return response(200, `{"triggers":[{"id":"global-trigger","name":"human-readable","build":{"steps":[{"args":["password=trigger-secret"]}]}}]}`), nil
		case "cloudbuild.googleapis.com/v1/projects/p/locations/us-central1/builds":
			buildPages++
			if buildPages == 1 {
				return response(200, `{"builds":[{"id":"regional-build","projectId":"p","name":"projects/p/locations/us-central1/builds/regional-build"}],"nextPageToken":"next"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "next" {
				t.Fatal("missing build pagination")
			}
			return response(200, `{}`), nil
		case "cloudbuild.googleapis.com/v1/projects/p/locations/us-central1/triggers":
			return response(200, `{"triggers":[{"id":"regional-trigger","resourceName":"projects/123/locations/us-central1/triggers/regional-trigger"}]}`), nil
		case "workflows.googleapis.com/v1/projects/p/locations":
			return response(200, `{"locations":[{"name":"projects/p/locations/europe-west1","locationId":"europe-west1"}]}`), nil
		case "workflows.googleapis.com/v1/projects/p/locations/europe-west1/workflows":
			return response(200, `{"workflows":[{"name":"projects/123/locations/europe-west1/workflows/flow","serviceAccount":"old@p.iam.gserviceaccount.com"}]}`), nil
		case "workflows.googleapis.com/v1/projects/p/locations/europe-west1/workflows/flow":
			workflowGets++
			return response(200, `{"name":"projects/123/locations/europe-west1/workflows/flow","serviceAccount":"projects/p/serviceAccounts/flow@p.iam.gserviceaccount.com","sourceContents":"main: password=WORKFLOW_SYNTHETIC","userEnvVars":{"TOKEN":"synthetic"}}`), nil
		default:
			t.Fatal("unexpected region/API/source/execution call", r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerBuildWorkflows(context.Background(), &s, "p", "projects/123")
	if hasCoverage(s, "failed") || hasCoverage(s, "incomplete") || len(s.Assets) != 5 || locationPages != 2 || buildPages != 2 || workflowGets != 1 {
		t.Fatal(s, locationPages, buildPages, workflowGets)
	}
	for _, a := range s.Assets {
		if a.Type == "workflows.googleapis.com/Workflow" {
			if !strings.Contains(a.Name, "/projects/p/") || !strings.Contains(Str(a.Resource.Data["sourceContents"]), "WORKFLOW_SYNTHETIC") {
				t.Fatal(a)
			}
			ids, _ := workloadIdentities(a)
			if len(ids) != 1 || ids[0].email != "flow@p.iam.gserviceaccount.com" {
				t.Fatal("workflow identity not preserved", ids)
			}
		} else if !strings.Contains(a.Name, "/projects/123/") {
			t.Fatal("noncanonical Build project", a.Name)
		}
	}
}

func TestViewerBuildPublicTriggersSurviveInvalidEarlierRows(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/projects/demo/locations/global/triggers" {
			t.Fatal(r.URL)
		}
		return response(200, `{"triggers":[false,{"id":"../wrong"},{"id":"outside","resourceName":"projects/foreign/locations/global/triggers/outside"},{"id":"public-pr","github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}}}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"cloudbuild.builds.list": true}
	out := Snapshot{}
	c.viewerBuildConfig(context.Background(), &out, "demo", "projects/123", "global", "triggers")
	if len(out.Assets) != 1 || !hasCoverage(out, "failed") || Str(Get(out.Assets[0].Resource.Data, "github", "pullRequest", "commentControl")) != "COMMENTS_DISABLED" {
		t.Fatal(out)
	}
}

func TestViewerBuildWorkflowsDiscoveryFailureStillReadsDocumentedGlobal(t *testing.T) {
	globalCalls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/locations") {
			return response(403, "sensitive"), nil
		}
		if strings.Contains(r.URL.Path, "/locations/global/") {
			globalCalls++
			return response(200, `{}`), nil
		}
		t.Fatal("guessed regional location", r.URL)
		return nil, nil
	})
	s := Snapshot{}
	c.CollectViewerBuildWorkflows(context.Background(), &s, "p", "projects/123")
	if globalCalls != 2 || !hasCoverage(s, "failed") {
		t.Fatal(s, globalCalls)
	}
}

func TestViewerWorkflowDetailFailurePreservesOnlyValidatedListMetadata(t *testing.T) {
	for _, body := range []string{`{"name":"projects/other/locations/us-central1/workflows/flow","sourceContents":"FOREIGN_CONTENT"}`, `{"name":"projects/p/locations/us-central1/workflows/other","sourceContents":"FOREIGN_CONTENT"}`} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/workflows") {
				return response(200, `{"workflows":[{"name":"projects/p/locations/us-central1/workflows/flow","serviceAccount":"list@p.iam.gserviceaccount.com"}]}`), nil
			}
			return response(200, body), nil
		})
		s := Snapshot{}
		c.viewerWorkflowConfig(context.Background(), &s, "p", "projects/123", "us-central1")
		if !hasCoverage(s, "failed") || len(s.Assets) != 1 || s.Assets[0].Resource.Data["sourceContents"] != nil {
			t.Fatal(s)
		}
	}
}

func TestViewerBuildRejectsConflictingScopeAndRetainsPriorRows(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"builds":[{"id":"good","projectId":"p","name":"projects/123/locations/us-central1/builds/good"},{"id":"bad","projectId":"other"}]}`), nil
	})
	s := Snapshot{}
	c.viewerBuildConfig(context.Background(), &s, "p", "projects/123", "us-central1", "builds")
	if !hasCoverage(s, "failed") || len(s.Assets) != 1 {
		t.Fatal(s)
	}
}

func TestViewerWorkflowMissingSourceAndUnreachableNotClean(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/workflows") {
			return response(200, `{"workflows":[{"name":"projects/p/locations/us-central1/workflows/flow"}],"unreachable":["other-region"]}`), nil
		}
		return response(200, `{"name":"projects/p/locations/us-central1/workflows/flow"}`), nil
	})
	s := Snapshot{}
	c.viewerWorkflowConfig(context.Background(), &s, "p", "projects/123", "us-central1")
	if !hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") || len(s.Assets) != 1 {
		t.Fatal(s)
	}
}

func TestViewerBuildWorkflowUnreachableKeepsLaterPages(t *testing.T) {
	for _, collection := range []string{"locations", "builds", "workflows"} {
		t.Run(collection, func(t *testing.T) {
			pages := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "/workflows/") {
					return response(200, `{"name":"projects/p/locations/us-central1/workflows/later","sourceContents":"main: {}"}`), nil
				}
				pages++
				if pages == 1 {
					return response(200, `{"unreachable":["temporarily-unreachable"],"nextPageToken":"later"}`), nil
				}
				if r.URL.Query().Get("pageToken") != "later" {
					t.Fatal("missing later page")
				}
				switch collection {
				case "locations":
					return response(200, `{"locations":[{"name":"projects/p/locations/us-central1"}]}`), nil
				case "builds":
					return response(200, `{"builds":[{"id":"later","projectId":"p"}]}`), nil
				default:
					return response(200, `{"workflows":[{"name":"projects/p/locations/us-central1/workflows/later"}]}`), nil
				}
			})
			s := Snapshot{}
			switch collection {
			case "locations":
				regions := c.viewerBuildWorkflowLocations(context.Background(), &s, "p", "projects/123", "cloudbuild.googleapis.com", "v2")
				if !regions["us-central1"] {
					t.Fatal("later reachable location lost")
				}
			case "builds":
				c.viewerBuildConfig(context.Background(), &s, "p", "projects/123", "global", "builds")
			case "workflows":
				c.viewerWorkflowConfig(context.Background(), &s, "p", "projects/123", "us-central1")
			}
			if pages != 2 || !hasCoverage(s, "failed") {
				t.Fatal("unreachable marked complete or stopped pagination", pages, s)
			}
			if collection != "locations" && len(s.Assets) != 1 {
				t.Fatal("later accessible resource lost", s)
			}
		})
	}
}

func TestViewerWorkflowEmptyDefinitionsIncomplete(t *testing.T) {
	for _, source := range []string{`""`, `" \n\t "`, `null`, `42`} {
		t.Run(source, func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/workflows") {
					return response(200, `{"workflows":[{"name":"projects/p/locations/us-central1/workflows/flow"}]}`), nil
				}
				return response(200, `{"name":"projects/p/locations/us-central1/workflows/flow","sourceContents":`+source+`}`), nil
			})
			s := Snapshot{}
			c.viewerWorkflowConfig(context.Background(), &s, "p", "projects/123", "us-central1")
			if !hasCoverage(s, "incomplete") || len(s.Assets) != 1 {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerBuildWorkflowMalformedUnreachableFailsClosed(t *testing.T) {
	for _, value := range []any{Object{}, []any{42}, []any{" "}} {
		if _, err := viewerBuildWorkflowUnreachable(Object{"unreachable": value}); err == nil {
			t.Fatal("malformed unreachable marker accepted", value)
		}
	}
}
