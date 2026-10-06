package inventory

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestViewerServerlessPaginationIdentityAndNativeSchemas(t *testing.T) {
	servicePages, locationPages := 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("non-read method")
		}
		if strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			return response(200, `{}`), nil
		}
		switch r.URL.Host + r.URL.Path {
		case "run.googleapis.com/v1/projects/p/locations":
			locationPages++
			if locationPages == 1 {
				return response(200, `{"locations":[{"name":"projects/123/locations/us-central1","locationId":"us-central1"}],"nextPageToken":"more"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "more" {
				t.Fatal("missing location page token")
			}
			return response(200, `{"locations":[{"name":"projects/p/locations/us-central1"}]}`), nil
		case "run.googleapis.com/v2/projects/p/locations/us-central1/services":
			servicePages++
			if servicePages == 1 {
				return response(200, `{"services":[{"name":"projects/123/locations/us-central1/services/web","invokerIamDisabled":true,"template":{"serviceAccount":"sa@p.iam.gserviceaccount.com","containers":[{"env":[{"name":"PASSWORD","value":"synthetic"}]}]}}],"nextPageToken":"second"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "second" {
				t.Fatal("missing service page token")
			}
			return response(200, `{}`), nil
		case "run.googleapis.com/v2/projects/p/locations/us-central1/jobs":
			return response(200, `{"jobs":[{"name":"projects/p/locations/us-central1/jobs/job","template":{"template":{"serviceAccount":"job@p.iam.gserviceaccount.com"}}}]}`), nil
		case "cloudfunctions.googleapis.com/v1/projects/p/locations/-/functions":
			return response(200, `{"functions":[{"name":"projects/p/locations/us-central1/functions/old","serviceAccountEmail":"old@p.iam.gserviceaccount.com","sourceArchiveUrl":"gs://bucket/source.zip"}]}`), nil
		case "cloudfunctions.googleapis.com/v2/projects/p/locations/-/functions":
			return response(200, `{"functions":[{"name":"projects/p/locations/us-central1/functions/new","serviceConfig":{"serviceAccountEmail":"new@p.iam.gserviceaccount.com","environmentVariables":{"PASSWORD":"synthetic"}},"buildConfig":{"source":{"storageSource":{"bucket":"bucket","object":"source.zip","generation":"1"}}}}]}`), nil
		default:
			t.Fatal("unreviewed/default region or endpoint", r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectViewerServerless(context.Background(), &s, "p", "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 4 || locationPages != 2 || servicePages != 2 {
		t.Fatal(s, locationPages, servicePages)
	}
	for _, a := range s.Assets {
		if !strings.Contains(a.Name, "/projects/p/") || a.Resource.Location != "us-central1" || len(a.Ancestors) != 1 || a.Ancestors[0] != "projects/123" {
			t.Fatal(a)
		}
		identities, _ := workloadIdentities(a)
		if len(identities) != 1 {
			t.Fatal("native service-account schema lost", a)
		}
	}
	if !Bool(s.Assets[0].Resource.Data["invokerIamDisabled"]) || Str(Get(s.Assets[3].Resource.Data, "serviceConfig", "environmentVariables", "PASSWORD")) != "synthetic" {
		t.Fatal("configuration fields flattened/dropped")
	}
}

func TestViewerServerlessPartialRowsAndUnreachable(t *testing.T) {
	for _, body := range []string{
		`{"functions":[{"name":"projects/p/locations/us-central1/functions/good"}],"unreachable":["europe-west1"]}`,
		`{"functions":[{"name":"projects/p/locations/us-central1/functions/good"},{"name":"projects/other/locations/us-central1/functions/bad"}]}`,
		`{"functions":[{"name":"projects/p/locations/us-central1/functions/good"}],"nextPageToken":42}`,
		`{"functions":[{"name":"projects/p/locations/us-central1/functions/good"}],"unreachable":{}}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
			s := Snapshot{}
			c.viewerServerlessList(context.Background(), &s, "p", "projects/123", "cloudfunctions.googleapis.com", "v2", "-", "functions", "Function")
			if !hasCoverage(s, "failed") || len(s.Assets) != 1 {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerServerlessFailureDoesNotGuessRegions(t *testing.T) {
	runRequests := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "run.googleapis.com" {
			runRequests++
			if r.URL.Path != "/v1/projects/p/locations" {
				t.Fatal("guessed location")
			}
			return response(403, `sensitive`), nil
		}
		return response(200, `{}`), nil
	})
	s := Snapshot{}
	c.CollectViewerServerless(context.Background(), &s, "p", "projects/123")
	if runRequests != 1 || !hasCoverage(s, "failed") {
		t.Fatal(runRequests, s)
	}
	for _, coverage := range s.Coverage {
		if strings.Contains(coverage.Error, "sensitive") {
			t.Fatal("upstream body leaked")
		}
	}
}

func TestViewerServerlessRejectsForeignLocations(t *testing.T) {
	for _, body := range []string{
		`{"locations":[{"name":"projects/foreign/locations/us-central1"}]}`,
		`{"locations":[{"name":"projects/p/locations/us-central1","locationId":"europe-west1"}]}`,
		`{"locations":[{"name":"projects/p/locations/-"}]}`,
		`{"locations":{}}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "run.googleapis.com" {
					if r.URL.Path != "/v1/projects/p/locations" {
						t.Fatal("unvalidated location queried")
					}
					return response(200, body), nil
				}
				return response(200, `{}`), nil
			})
			s := Snapshot{}
			c.CollectViewerServerless(context.Background(), &s, "p", "projects/123")
			if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
				t.Fatal(s)
			}
		})
	}
}

func TestViewerServerlessRejectsScopeAndRepeatedPagination(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("invalid scope reached API"); return nil, nil })
	s := Snapshot{}
	c.CollectViewerServerless(context.Background(), &s, "p/escape", "projects/123")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	c = testClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"functions":[],"nextPageToken":"same"}`), nil
	})
	s = Snapshot{}
	c.viewerServerlessList(context.Background(), &s, "p", "projects/123", "cloudfunctions.googleapis.com", "v2", "-", "functions", "Function")
	if !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
