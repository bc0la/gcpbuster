package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func regionalSecretsClient(t *testing.T, fn roundTrip) *Client {
	c := testClient(t, fn)
	// Synthetic capabilities; not a role-membership fixture.
	c.viewerPolicy.permissions = map[string]bool{"secretmanager.locations.list": true, "secretmanager.secrets.list": true, "secretmanager.versions.list": true}
	return c
}

func TestViewerRegionalSecretsPaginationAndProjection(t *testing.T) {
	calls := 0
	c := regionalSecretsClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || strings.Contains(r.URL.Path, ":") {
			t.Fatal(r.URL)
		}
		switch r.URL.Path {
		case "/v1/projects/123/locations":
			if r.URL.Host != "secretmanager.googleapis.com" || r.URL.Query().Get("fields") != "locations(name,locationId),nextPageToken" {
				t.Fatal(r.URL)
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}],"nextPageToken":"loc"}`), nil
			}
			return response(200, `{"locations":[{"name":"projects/123/locations/us-central1"},{"name":"projects/demo/locations/global"}]}`), nil
		case "/v1/projects/123/locations/us-central1/secrets":
			if r.URL.Host != "secretmanager.us-central1.rep.googleapis.com" || r.URL.Query().Get("fields") != viewerRegionalSecretFields {
				t.Fatal(r.URL)
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"secrets":[{"name":"projects/demo/locations/us-central1/secrets/key","rotation":{"nextRotationTime":"2026-10-01T00:00:00Z","rotationPeriod":"86400s","credentials":"PRIVATE"},"customerManagedEncryption":{"kmsKeyName":"projects/demo/locations/us-central1/keyRings/r/cryptoKeys/k"},"topics":[{"name":"projects/demo/topics/rotate","payload":"PRIVATE"}],"payload":{"data":"PRIVATE"},"annotations":{"password":"PRIVATE"}}],"nextPageToken":"secret"}`), nil
			}
			return response(200, `{"secrets":[{"name":"projects/123/locations/us-central1/secrets/key"}]}`), nil
		case "/v1/projects/123/locations/us-central1/secrets/key/versions":
			if r.URL.Host != "secretmanager.us-central1.rep.googleapis.com" || r.URL.Query().Get("fields") != viewerRegionalVersionFields {
				t.Fatal(r.URL)
			}
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"versions":[{"name":"projects/123/locations/us-central1/secrets/key/versions/1","state":"ENABLED","payload":{"data":"PRIVATE"},"customerManagedEncryption":{"kmsKeyVersionName":"projects/demo/locations/us-central1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"}}],"nextPageToken":"version"}`), nil
			}
			return response(200, `{"versions":[{"name":"projects/demo/locations/us-central1/secrets/key/versions/2","state":"DISABLED","scheduledDestroyTime":"2026-12-01T00:00:00Z"}]}`), nil
		default:
			t.Fatal(r.URL)
			return nil, nil
		}
	})
	var s Snapshot
	c.CollectViewerRegionalSecrets(context.Background(), &s, "demo", "projects/123")
	if calls != 6 || len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(s, calls)
	}
	if s.Assets[0].Name != "//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/key" || Str(Get(s.Assets[0].Resource.Data, "rotation", "rotationPeriod")) != "86400s" || s.Assets[2].Resource.Location != "us-central1" {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("non-metadata content retained")
	}
}

func TestViewerRegionalSecretsLocationPartialKeepsRegions(t *testing.T) {
	c := regionalSecretsClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "secretmanager.googleapis.com" {
			if r.URL.Query().Get("pageToken") == "" {
				return response(200, `{"locations":[{"name":"projects/other/locations/us-east1"},{"name":"projects/demo/locations/us-central1"}],"unreachable":["eu"],"nextPageToken":"next"}`), nil
			}
			return response(200, `{"locations":[{"name":"projects/demo/locations/eu"}]}`), nil
		}
		if r.URL.Host == "secretmanager.eu.rep.googleapis.com" {
			return response(403, "PRIVATE"), nil
		}
		if r.URL.Host != "secretmanager.us-central1.rep.googleapis.com" {
			t.Fatal(r.URL)
		}
		return response(200, `{}`), nil
	})
	var s Snapshot
	c.CollectViewerRegionalSecrets(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(s.Coverage) != 4 {
		t.Fatal(s)
	}
}

func TestViewerRegionalSecretsScopeAndMalformedRecords(t *testing.T) {
	for _, bad := range []string{`null`, `{"name":"projects/other/locations/us-central1/secrets/x"}`, `{"name":"projects/demo/locations/us-east1/secrets/x"}`, `{"name":"projects/demo/locations/us-central1/secrets/x/versions/1"}`, `{"name":"projects/demo/locations/us-central1/secrets/x","rotation":[]}`, `{"name":"projects/demo/locations/us-central1/secrets/x","createTime":"bad"}`} {
		c := regionalSecretsClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/locations") {
				return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1"}]}`), nil
			}
			if strings.HasSuffix(r.URL.Path, "/versions") {
				t.Fatal("invalid secret triggered version discovery")
			}
			return response(200, `{"secrets":[`+bad+`]}`), nil
		})
		var s Snapshot
		c.CollectViewerRegionalSecrets(context.Background(), &s, "demo", "projects/123")
		if !hasCoverage(s, "failed") || len(s.Assets) != 0 {
			t.Fatal(bad, s)
		}
	}
}

func TestViewerRegionalSecretVersionsPartialAndLateFailure(t *testing.T) {
	c := regionalSecretsClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/locations") {
			return response(200, `{"locations":[{"name":"projects/demo/locations/us-central1"}]}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/secrets") {
			return response(200, `{"secrets":[{"name":"projects/123/locations/us-central1/secrets/x"}]}`), nil
		}
		if r.URL.Query().Get("pageToken") != "" {
			return response(403, "PRIVATE"), nil
		}
		return response(200, `{"versions":[{"name":"projects/123/locations/us-central1/secrets/x/versions/1","state":"ENABLED"},{"name":"projects/123/locations/us-central1/secrets/other/versions/2","state":"ENABLED"},{"name":"projects/123/locations/us-central1/secrets/x/versions/latest","state":"ENABLED"}],"nextPageToken":"next"}`), nil
	})
	var s Snapshot
	c.CollectViewerRegionalSecrets(context.Background(), &s, "demo", "projects/123")
	if !hasCoverage(s, "failed") || len(s.Assets) != 2 {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("upstream error leaked")
	}
}

func TestViewerRegionalSecretsPermissionAndIdentity(t *testing.T) {
	c := regionalSecretsClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{}
	for _, project := range []string{"demo", "../bad"} {
		var s Snapshot
		c.CollectViewerRegionalSecrets(context.Background(), &s, project, "projects/123")
		if !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
}

func TestViewerRegionalSecretManagedRotationMetadataOnly(t *testing.T) {
	const principal = "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/uid1"
	c := regionalSecretsClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || strings.Contains(r.URL.Path, ":") {
			t.Fatal("non-metadata method", r.URL)
		}
		if strings.HasSuffix(r.URL.Path, "/locations") {
			return response(200, `{"locations":[{"name":"projects/123/locations/us-central1"}]}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/versions") {
			return response(200, `{}`), nil
		}
		fields := r.URL.Query().Get("fields")
		for _, required := range []string{"secretType", "policyMember(iamPolicyUidPrincipal,iamPolicyNamePrincipal)", "managedRotationStatus(state)"} {
			if !strings.Contains(fields, required) {
				t.Fatal("missing metadata projection", required)
			}
		}
		for _, forbidden := range []string{"password", "cloudSqlSingleUserCredentials", "payload", "error"} {
			if strings.Contains(fields, forbidden) {
				t.Fatal("credential or unstructured error requested", fields)
			}
		}
		return response(200, `{"secrets":[{"name":"projects/123/locations/us-central1/secrets/db","secretType":"CLOUD_SQL_DB_CREDENTIALS","policyMember":{"iamPolicyUidPrincipal":"`+principal+`","iamPolicyNamePrincipal":"principal://secretmanager.googleapis.com/projects/123/name/locations/us-central1/secrets/db","credentials":"PRIVATE"},"rotation":{"managedRotationStatus":{"state":"ACTIVE","error":{"message":"PRIVATE","details":[{"target":"PRIVATE"}]}}},"cloudSqlSingleUserCredentials":{"instanceId":"PRIVATE","username":"PRIVATE","password":"PRIVATE"},"payload":{"data":"PRIVATE"}}]}`), nil
	})
	var s Snapshot
	c.CollectViewerRegionalSecrets(context.Background(), &s, "demo", "projects/123")
	if hasCoverage(s, "failed") || len(s.Assets) != 1 {
		t.Fatal(s)
	}
	d := s.Assets[0].Resource.Data
	if d["secretType"] != "CLOUD_SQL_DB_CREDENTIALS" || Get(d, "policyMember", "iamPolicyUidPrincipal") != principal || Get(d, "rotation", "managedRotationStatus", "state") != "ACTIVE" {
		t.Fatal(d)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("credentials or unstructured errors retained")
	}
}

func TestViewerRegionalSecretManagedMetadataMalformed(t *testing.T) {
	for _, fields := range []Object{
		{"secretType": 42},
		{"policyMember": []any{}},
		{"policyMember": Object{"iamPolicyUidPrincipal": false}},
		{"rotation": Object{"managedRotationStatus": []any{}}},
		{"rotation": Object{"managedRotationStatus": Object{"state": 42}}},
	} {
		fields["name"] = "projects/123/locations/us-central1/secrets/db"
		if _, err := viewerRegionalSecretProjection(fields, false); err == nil {
			t.Fatal("malformed managed metadata accepted", fields)
		}
	}
	for _, state := range []string{"ACTIVE", "INACTIVE", "STATE_UNSPECIFIED"} {
		clean, err := viewerRegionalSecretProjection(Object{"name": "projects/123/locations/us-central1/secrets/db", "rotation": Object{"managedRotationStatus": Object{"state": state}}}, false)
		if err != nil || Get(clean, "rotation", "managedRotationStatus", "state") != state {
			t.Fatal(clean, err)
		}
	}
}
