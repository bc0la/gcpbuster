package inventory

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func viewerAutomationClient(t *testing.T, fn roundTrip) *Client {
	t.Helper()
	t.Setenv("VIEWER_AUTOMATION_TOKEN", "test-token")
	c := &Client{TokenEnv: "VIEWER_AUTOMATION_TOKEN", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			return response(200, `{}`), nil
		}
		return fn(r)
	})}}
	// Actual Viewer-permitted method permissions, not historical privileged
	// collector capabilities. No artifact payload or execution grants.
	c.viewerPolicy.permissions = map[string]bool{
		"artifactregistry.locations.list": true, "artifactregistry.repositories.list": true, "artifactregistry.repositories.getIamPolicy": true,
		"cloudscheduler.locations.list": true, "cloudscheduler.jobs.list": true,
		"pubsub.subscriptions.list": true,
	}
	return c
}

func TestViewerAutomationPaginatedLocationsAndConfiguration(t *testing.T) {
	calls := map[string]int{}
	c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal(r.Method, r.URL)
		}
		key := r.URL.Host + r.URL.Path
		calls[key]++
		if strings.HasSuffix(r.URL.Path, "/locations") {
			if r.URL.Query().Get("pageToken") == "second" {
				return response(200, `{"locations":[{"name":"projects/123/locations/us-central1","locationId":"us-central1"}]}`), nil
			}
			return response(200, `{"locations":[],"nextPageToken":"second"}`), nil
		}
		switch r.URL.Host {
		case "artifactregistry.googleapis.com":
			if r.URL.Query().Get("pageToken") == "repos" {
				return response(200, `{"repositories":[{"name":"projects/demo/locations/us-central1/repositories/public","mode":"REMOTE_REPOSITORY","remoteRepositoryConfig":{"pythonRepository":{"publicRepository":"PYPI"}}}]}`), nil
			}
			return response(200, `{"repositories":[{"name":"projects/demo/locations/us-central1/repositories/virtual","mode":"VIRTUAL_REPOSITORY","virtualRepositoryConfig":{"upstreamPolicies":[{"repository":"projects/demo/locations/us-central1/repositories/public","priority":100}]}}],"nextPageToken":"repos"}`), nil
		case "cloudscheduler.googleapis.com":
			return response(200, `{"jobs":[{"name":"projects/demo/locations/us-central1/jobs/nightly","state":"ENABLED","httpTarget":{"uri":"https://example.invalid/run","oidcToken":{"serviceAccountEmail":"worker@demo.iam.gserviceaccount.com"},"headers":{"Authorization":"Bearer TEST_CONFIG_SECRET"}}}]}`), nil
		case "pubsub.googleapis.com":
			if r.URL.Query().Get("pageToken") == "subs" {
				return response(200, `{"subscriptions":[{"name":"projects/demo/subscriptions/push","pushConfig":{"pushEndpoint":"http://example.invalid/push","oidcToken":{"serviceAccountEmail":"worker@demo.iam.gserviceaccount.com"}}}]}`), nil
			}
			return response(200, `{"subscriptions":[],"nextPageToken":"subs"}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerAutomation(context.Background(), &s, "demo", "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 4 {
		t.Fatal(s)
	}
	if Str(Get(s.Assets[2].Resource.Data, "httpTarget", "headers", "Authorization")) != "Bearer TEST_CONFIG_SECRET" {
		t.Fatal("configuration fields lost before redacted assessment")
	}
	for _, a := range s.Assets {
		if len(a.Ancestors) != 1 || a.Ancestors[0] != "projects/123" {
			t.Fatal(a)
		}
	}
	if calls["artifactregistry.googleapis.com/v1/projects/demo/locations"] != 2 || calls["artifactregistry.googleapis.com/v1/projects/demo/locations/us-central1/repositories"] != 2 || calls["pubsub.googleapis.com/v1/projects/demo/subscriptions"] != 2 {
		t.Fatal(calls)
	}
	ResolveArtifactUpstreams(&s)
	if hasCoverage(s, "incomplete") || len(s.Assets) != 5 {
		t.Fatal(s)
	}
	upstreams := List(s.Assets[4].Resource.Data["upstreams"])
	if len(upstreams) != 1 || !Bool(Obj(upstreams[0])["publicRemote"]) {
		t.Fatal("public upstream correlation lost", upstreams)
	}
}

func TestViewerAutomationDeniedRegionRetainsOtherServices(t *testing.T) {
	c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/locations") {
			if r.URL.Host == "cloudscheduler.googleapis.com" {
				return response(403, `SECRET_ERROR`), nil
			}
			if r.URL.Query().Get("pageToken") == "denied" {
				return response(403, `SECRET_ERROR`), nil
			}
			return response(200, `{"locations":[{"name":"projects/demo/locations/us"}],"nextPageToken":"denied"}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/repositories") {
			return response(200, `{"repositories":[{"name":"projects/demo/locations/us/repositories/one","mode":"STANDARD_REPOSITORY"}]}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/subscriptions") {
			return response(200, `{"subscriptions":[{"name":"projects/demo/subscriptions/one"}]}`), nil
		}
		t.Fatal(r.URL)
		return nil, nil
	})
	s := Snapshot{}
	c.CollectViewerAutomation(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(s.Assets) != 2 {
		t.Fatal(s)
	}
	for _, cv := range s.Coverage {
		if strings.Contains(cv.Error, "SECRET_ERROR") {
			t.Fatal(cv)
		}
	}
}

func TestViewerAutomationRejectsMalformedIdentityAndPages(t *testing.T) {
	for _, payload := range []string{
		`{"locations":{}}`,
		`{"locations":[{"name":"projects/other/locations/us"}]}`,
		`{"locations":[{"name":"projects/demo/locations/us","locationId":"eu"}]}`,
		`{"locations":[{"name":"projects/demo/locations/-"}]}`,
		`{"locations":[],"nextPageToken":123}`,
	} {
		c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/locations") {
				return response(200, payload), nil
			}
			if strings.HasSuffix(r.URL.Path, "/subscriptions") {
				return response(200, `{}`), nil
			}
			t.Fatal("invalid location used", r.URL)
			return nil, nil
		})
		s := Snapshot{}
		c.CollectViewerAutomation(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
			t.Fatal(payload, s)
		}
	}
	for _, name := range []string{"projects/other/subscriptions/x", "projects/demo/topics/x", "projects/demo/subscriptions/../x", "projects/demo/subscriptions/x?query"} {
		c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
			return response(200, `{"subscriptions":[{"name":"`+name+`"}]}`), nil
		})
		s := Snapshot{}
		c.viewerAutomationRows(context.Background(), &s, "https://pubsub.googleapis.com/v1/projects/demo/subscriptions", "pubsub.googleapis.com", "subscriptions", "Subscription", "demo", "projects/123", "")
		if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
			t.Fatal(name, s)
		}
	}
}

func TestViewerAutomationMissingPermissionAndRepeatedPage(t *testing.T) {
	requests := 0
	c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		return response(200, `{"nextPageToken":"same"}`), nil
	})
	s := Snapshot{}
	c.CollectViewerAutomation(context.Background(), &s, "../invalid", "projects/123")
	if requests != 0 || !hasCoverage(s, "failed") {
		t.Fatal(requests, s)
	}
	delete(c.viewerPolicy.permissions, "pubsub.subscriptions.list")
	s = Snapshot{}
	c.CollectViewerAutomation(context.Background(), &s, "demo", "projects/123")
	if requests != 4 || !hasCoverage(s, "failed") {
		t.Fatal(requests, s)
	}
}

func TestViewerAutomationRegionalRowsRejectMismatchedParents(t *testing.T) {
	for _, name := range []string{
		"projects/demo/locations/eu/repositories/one",
		"projects/other/locations/us/repositories/one",
		"projects/demo/locations/us/jobs/one",
		"projects/demo/locations/us/repositories/..",
	} {
		c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
			return response(200, `{"repositories":[{"name":"projects/demo/locations/us/repositories/valid"},{"name":"`+name+`"}]}`), nil
		})
		s := Snapshot{}
		c.viewerAutomationRows(context.Background(), &s, "https://artifactregistry.googleapis.com/v1/projects/demo/locations/us/repositories", "artifactregistry.googleapis.com", "repositories", "Repository", "demo", "projects/123", "us")
		if !hasCoverage(s, "failed") || len(s.Assets) != 1 {
			t.Fatal(name, s)
		}
	}
}

func TestViewerAutomationCanonicalProjectAndRawName(t *testing.T) {
	for _, spec := range []struct{ host, collection, kind, location string }{
		{"artifactregistry.googleapis.com", "repositories", "Repository", "us"},
		{"cloudscheduler.googleapis.com", "jobs", "Job", "us"},
		{"pubsub.googleapis.com", "subscriptions", "Subscription", ""},
	} {
		suffix := "/" + spec.collection + "/resource"
		if spec.location != "" {
			suffix = "/locations/us" + suffix
		}
		numeric, canonical := "projects/123"+suffix, "projects/demo"+suffix
		calls := 0
		c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return response(200, `{"`+spec.collection+`":[{"name":"`+numeric+`"}],"nextPageToken":"more"}`), nil
			}
			return response(200, `{"`+spec.collection+`":[{"name":"`+canonical+`"}]}`), nil
		})
		endpoint := "https://" + spec.host + "/v1/" + strings.TrimSuffix(canonical, "/resource")
		s := Snapshot{}
		c.viewerAutomationRows(context.Background(), &s, endpoint, spec.host, spec.collection, spec.kind, "demo", "projects/123", spec.location)
		if hasCoverage(s, "failed") || len(s.Assets) != 1 || s.Assets[0].Name != "//"+spec.host+"/"+canonical || Str(s.Assets[0].Resource.Data["name"]) != numeric {
			t.Fatal(spec, s)
		}
	}
}

func TestViewerAutomationPartialFieldsPreserveRecords(t *testing.T) {
	for _, field := range []string{`"unreachable":["eu"]`, `"unreachableLocations":["eu"]`, `"unreachable":{}`, `"unreachableLocations":[42]`} {
		c := viewerAutomationClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/locations") {
				return response(200, `{"locations":[{"name":"projects/demo/locations/us"}],`+field+`}`), nil
			}
			collection := "subscriptions"
			name := "projects/demo/subscriptions/one"
			if strings.HasSuffix(r.URL.Path, "/repositories") {
				collection = "repositories"
				name = "projects/demo/locations/us/repositories/one"
			}
			if strings.HasSuffix(r.URL.Path, "/jobs") {
				collection = "jobs"
				name = "projects/demo/locations/us/jobs/one"
			}
			return response(200, `{"`+collection+`":[{"name":"`+name+`"}],`+field+`}`), nil
		})
		s := Snapshot{}
		c.CollectViewerAutomation(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 3 || !hasCoverage(s, "failed") {
			t.Fatal(field, s)
		}
		for _, cv := range s.Coverage {
			if strings.HasPrefix(cv.Source, "viewer-artifact-iam:") {
				continue
			}
			if cv.Status != "failed" {
				t.Fatal("partial recorded as complete", field, cv)
			}
		}
	}
}
