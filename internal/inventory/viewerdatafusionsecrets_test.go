package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDataFusionSelectedOptionsAndIdentity(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "datafusion.googleapis.com" || r.Method != "GET" {
				t.Fatal(r.URL)
			}
			if strings.HasSuffix(r.URL.Path, "/locations") {
				return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`), nil
			}
			project := "demo"
			if foreign {
				project = "other"
			}
			return response(200, `{"instances":[{"name":"projects/`+project+`/locations/us-central1/instances/etl","options":{"password":"EXAMPLE_OPTION"},"secureKey":{"secret":"DO_NOT_CAPTURE"},"apiEndpoint":"DO_NOT_FOLLOW"}]}`), nil
		})
		c.viewerPolicy.permissions = map[string]bool{"datafusion.locations.list": true, "datafusion.instances.list": true}
		c.SecretCapture = NewSecretCapture(0, 0, 0)
		var s Snapshot
		c.CollectViewerDataFusionSecrets(context.Background(), &s, "demo", "projects/123")
		if foreign {
			if len(c.SecretCapture.Samples()) != 0 || !hasCoverage(s, "failed") {
				t.Fatal("foreign accepted", s)
			}
			continue
		}
		ss := c.SecretCapture.Samples()
		if len(ss) != 1 || string(ss[0].Data) != "password=EXAMPLE_OPTION" || len(s.Assets) != 1 {
			t.Fatal(s, ss)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "EXAMPLE_OPTION") || strings.Contains(string(b), "DO_NOT") {
			t.Fatal("raw config persisted")
		}
	}
}

func TestDataFusionGuardOnlyReviewedLists(t *testing.T) {
	u, _ := url.Parse("https://datafusion.googleapis.com/v1/projects/123/locations/us-central1/instances")
	q := url.Values{"fields": {dataFusionInstancesFields}, "pageSize": {"100"}}
	p, err := dataFusionSecretPermission("GET", u, q)
	if err != nil || len(p) != 1 || p[0] != "datafusion.instances.list" {
		t.Fatal(p, err)
	}
	for _, mutation := range []string{"POST", "DELETE"} {
		if _, err := dataFusionSecretPermission(mutation, u, q); err == nil {
			t.Fatal("mutation allowed")
		}
	}
	q.Set("fields", "*")
	if _, err := dataFusionSecretPermission("GET", u, q); err == nil {
		t.Fatal("wildcard allowed")
	}
	for _, path := range []string{"/v1/projects/123/locations/us-central1/instances/i:restart", "/v1/projects/123/locations/us-central1/instances/i/namespaces/n/secureKeys/k", "/v1/projects/123/locations/-/instances"} {
		u.Path = path
		if _, err := dataFusionSecretPermission("GET", u, url.Values{"fields": {dataFusionInstancesFields}, "pageSize": {"100"}}); err == nil {
			t.Fatal("unreviewed endpoint allowed")
		}
	}
}
