package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerCloudCoreAndPolicySearch(t *testing.T) {
	calls := map[string]int{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		key := r.URL.Host + r.URL.Path
		calls[key]++
		if r.Method != "GET" && !(r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":getIamPolicy")) {
			t.Fatal(r.Method, r.URL)
		}
		switch key {
		case "compute.googleapis.com/compute/v1/projects/demo-project/global/routes":
			return response(200, `{}`), nil
		case "modelarmor.googleapis.com/v1/projects/123/locations/global/floorSetting":
			return response(200, `{"name":"projects/123/locations/global/floorSetting"}`), nil
		case "modelarmor.us-central1.rep.googleapis.com/v1/projects/123/locations":
			return response(200, `{}`), nil
		case "cloudresourcemanager.googleapis.com/v3/projects/demo-project":
			return response(200, `{"name":"projects/123","projectId":"demo-project","parent":"folders/9"}`), nil
		case "cloudresourcemanager.googleapis.com/v3/projects/123:getIamPolicy":
			return response(200, `{"bindings":[{"role":"roles/viewer","members":["user:viewer@example.com"]}]}`), nil
		case "compute.googleapis.com/compute/v1/projects/demo-project":
			return response(200, `{"name":"demo-project","commonInstanceMetadata":{"items":[{"key":"enable-oslogin","value":"FALSE"}]}}`), nil
		case "compute.googleapis.com/compute/v1/projects/demo-project/global/firewalls":
			return response(200, `{"items":[{"name":"open-ssh","sourceRanges":["0.0.0.0/0"]}]}`), nil
		case "compute.googleapis.com/compute/v1/projects/demo-project/aggregated/instances":
			if r.URL.Query().Get("returnPartialSuccess") != "true" {
				t.Fatal(r.URL)
			}
			if r.URL.Query().Get("pageToken") == "second" {
				return response(200, `{"items":{"zones/us-east1-b":{"instances":[{"name":"vm-two"}]}}}`), nil
			}
			return response(200, `{"items":{"zones/us-central1-a":{"instances":[{"name":"vm-one","selfLink":"https://www.googleapis.com/compute/v1/projects/demo-project/zones/us-central1-a/instances/vm-one"}]}},"nextPageToken":"second"}`), nil
		case "storage.googleapis.com/storage/v1/b":
			if r.URL.Query().Get("project") != "demo-project" || r.URL.Query().Get("projection") != "noAcl" {
				t.Fatal(r.URL)
			}
			return response(200, `{"items":[{"name":"sample-bucket","projectNumber":"123","iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true}}}]}`), nil
		case "cloudasset.googleapis.com/v1/projects/123:searchAllIamPolicies":
			if r.URL.Query().Get("query") != "" {
				t.Fatal("filtered policy search")
			}
			return response(200, `{"results":[{"resource":"//storage.googleapis.com/sample-bucket","assetType":"storage.googleapis.com/Bucket","project":"projects/123","policy":{"version":3,"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"],"condition":{"expression":"true"}}]}},{"resource":"//cloudresourcemanager.googleapis.com/projects/123","assetType":"cloudresourcemanager.googleapis.com/Project","project":"projects/123","policy":{"bindings":[]}}]}`), nil
		case "sqladmin.googleapis.com/v1/projects/demo-project/instances", "container.googleapis.com/v1/projects/demo-project/locations/-/clusters", "run.googleapis.com/v1/projects/demo-project/locations", "cloudfunctions.googleapis.com/v1/projects/demo-project/locations/-/functions", "cloudfunctions.googleapis.com/v2/projects/demo-project/locations/-/functions", "dns.googleapis.com/dns/v1/projects/demo-project/managedZones", "iam.googleapis.com/v1/projects/demo-project/serviceAccounts":
			return response(200, `{}`), nil
		case "apikeys.googleapis.com/v2/projects/123/locations/global/keys", "secretmanager.googleapis.com/v1/projects/123/secrets", "cloudkms.googleapis.com/v1/projects/demo-project/locations", "cloudbuild.googleapis.com/v2/projects/demo-project/locations", "cloudbuild.googleapis.com/v1/projects/demo-project/locations/global/builds", "cloudbuild.googleapis.com/v1/projects/demo-project/locations/global/triggers", "workflows.googleapis.com/v1/projects/demo-project/locations", "artifactregistry.googleapis.com/v1/projects/demo-project/locations", "cloudscheduler.googleapis.com/v1/projects/demo-project/locations", "pubsub.googleapis.com/v1/projects/demo-project/subscriptions", "pubsub.googleapis.com/v1/projects/demo-project/topics", "pubsub.googleapis.com/v1/projects/demo-project/schemas", "pubsub.googleapis.com/v1/projects/demo-project/snapshots":
			return response(200, `{}`), nil
		case "identitytoolkit.googleapis.com/v2/projects/123/oauthIdpConfigs", "identitytoolkit.googleapis.com/v2/projects/123/inboundSamlConfigs", "bigquery.googleapis.com/bigquery/v2/projects/demo-project/datasets", "identitytoolkit.googleapis.com/v2/projects/123/tenants", "cloudtasks.googleapis.com/v2/projects/demo-project/locations", "aiplatform.googleapis.com/v1/projects/demo-project/locations":
			return response(200, `{}`), nil
		case "compute.googleapis.com/compute/v1/projects/demo-project/aggregated/instanceTemplates", "compute.googleapis.com/compute/v1/projects/demo-project/global/machineImages", "compute.googleapis.com/compute/v1/projects/demo-project/global/images", "compute.googleapis.com/compute/v1/projects/demo-project/global/snapshots", "compute.googleapis.com/compute/v1/projects/demo-project/regions", "compute.googleapis.com/compute/v1/projects/demo-project/global/networks", "compute.googleapis.com/compute/v1/projects/demo-project/aggregated/subnetworks", "iam.googleapis.com/v1/projects/123/locations/global/workloadIdentityPools", "dataflow.googleapis.com/v1b3/projects/demo-project/jobs:aggregated":
			return response(200, `{}`), nil
		case "identitytoolkit.googleapis.com/admin/v2/projects/123/config":
			return response(200, `{"name":"projects/123/config"}`), nil
		case "cloudasset.googleapis.com/v1/projects/123:searchAllResources":
			return response(200, `{}`), nil
		case "secretmanager.googleapis.com/v1/projects/123/locations":
			return response(200, `{}`), nil
		case "parametermanager.googleapis.com/v1/projects/123/locations", "parametermanager.googleapis.com/v1/projects/123/locations/global/parameters":
			return response(200, `{}`), nil
		case "apigateway.googleapis.com/v1/projects/demo-project/locations", "apigateway.googleapis.com/v1/projects/demo-project/locations/global/apis":
			return response(200, `{}`), nil
		case "servicemanagement.googleapis.com/v1/services":
			return response(200, `{}`), nil
		case "healthcare.googleapis.com/v1/projects/demo-project/locations", "firestore.googleapis.com/v1/projects/demo-project/databases", "firestore.googleapis.com/v1/projects/demo-project/locations/-/backups", "spanner.googleapis.com/v1/projects/demo-project/instances", "bigtableadmin.googleapis.com/v2/projects/demo-project/instances", "file.googleapis.com/v1/projects/demo-project/locations/-/instances", "alloydb.googleapis.com/v1/projects/demo-project/locations/-/clusters", "alloydb.googleapis.com/v1/projects/demo-project/locations/-/clusters/-/instances":
			return response(200, `{}`), nil
		case "redis.googleapis.com/v1/projects/demo-project/locations/-/instances", "redis.googleapis.com/v1/projects/demo-project/locations/-/clusters", "memcache.googleapis.com/v1/projects/demo-project/locations/-/instances":
			return response(200, `{}`), nil
		case "dns.googleapis.com/dns/v1/projects/demo-project/policies", "dns.googleapis.com/dns/v1/projects/demo-project/responsePolicies":
			return response(200, `{}`), nil
		case "serviceusage.googleapis.com/v1/projects/123/services", "appengine.googleapis.com/v1/apps/demo-project/services":
			return response(200, `{}`), nil
		case "appengine.googleapis.com/v1/apps/demo-project":
			return response(200, `{"name":"apps/demo-project","id":"demo-project"}`), nil
		case "apigee.googleapis.com/v1/organizations/demo-project":
			return response(200, `{"name":"demo-project","projectId":"demo-project"}`), nil
		case "firebaseappcheck.googleapis.com/v1/projects/123/services", "firebaseappcheck.googleapis.com/v1/projects/123/services/oauth2.googleapis.com/resourcePolicies":
			return response(200, `{}`), nil
		case "compute.googleapis.com/compute/v1/projects/demo-project/aggregated/backendServices":
			return response(200, `{}`), nil
		case "apigee.googleapis.com/v1/organizations/demo-project/apiproducts", "apigee.googleapis.com/v1/organizations/demo-project/envgroups", "apigee.googleapis.com/v1/organizations/demo-project/deployments":
			return response(200, `{}`), nil
		case "appengine.googleapis.com/v1/apps/demo-project/firewall/ingressRules":
			return response(200, `{"ingressRules":[{"priority":2147483647,"action":"DENY","sourceRange":"*"}]}`), nil
		default:
			t.Fatalf("unexpected endpoint %s", key)
			return nil, nil
		}
	})
	c.viewerPolicy.permissions["parametermanager.locations.list"] = true
	c.viewerPolicy.permissions["parametermanager.parameters.list"] = true
	s := c.ViewerCloud(context.Background(), "projects/demo-project")
	if len(s.Assets) != 11 || hasCoverage(s, "failed") || !hasCoverage(s, "incomplete") {
		t.Fatalf("%+v", s)
	}
	if calls["compute.googleapis.com/compute/v1/projects/demo-project/aggregated/instances"] != 2 {
		t.Fatal(calls)
	}
	bindings := List(s.Assets[len(s.Assets)-1].IAM["bindings"])
	if len(bindings) != 1 || Str(Get(Obj(bindings[0]), "condition", "expression")) != "true" {
		t.Fatal("search condition lost")
	}
	if len(List(s.Assets[0].IAM["bindings"])) != 1 {
		t.Fatal("search overwrote direct IAM")
	}
	if len(s.Assets[0].Ancestors) != 0 {
		t.Fatal("invented complete ancestors")
	}
}

func TestViewerCloudRejectsInvalidScopeBeforeNetwork(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("network used"); return nil, nil })
	s := c.ViewerCloud(context.Background(), "projects/../../escape")
	if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerComputePartialResultsAndScopeChecks(t *testing.T) {
	for _, body := range []string{
		`{"items":{"zones/us-central1-a":{"instances":[{"name":"good"},{"name":"bad","selfLink":"https://www.googleapis.com/compute/v1/projects/other/zones/us-central1-a/instances/bad"}]}}}`,
		`{"items":{"zones/us-central1-a":{"instances":[{"name":"good"}],"warning":{"code":"UNREACHABLE"}}}}`,
		`{"items":{"zones/us-central1-a":{"instances":[{"name":"good"}]}},"unreachables":["zones/us-east1-b"]}`,
	} {
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "aggregated/instances") {
				return response(200, body), nil
			}
			if strings.HasSuffix(r.URL.Path, "global/firewalls") {
				return response(403, "PRIVATE"), nil
			}
			return response(200, `{"name":"demo"}`), nil
		})
		var s Snapshot
		c.viewerCompute(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 2 || !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "PRIVATE") {
			t.Fatal("error leaked")
		}
	}
}

func TestViewerBucketsRejectOtherProjectAndMalformedPages(t *testing.T) {
	for _, body := range []string{`{"items":[{"name":"bucket-name","projectNumber":"999"}]}`, `{"items":{}}`, `{"items":[null]}`, `{"nextPageToken":3}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		var s Snapshot
		c.viewerBuckets(context.Background(), &s, "demo", "projects/123")
		if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
			t.Fatal(s)
		}
	}
}

func TestViewerIAMSearchRejectsScopeMismatchAndPreservesPagination(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"results":[{"resource":"//storage.googleapis.com/bucket","assetType":"storage.googleapis.com/Bucket","project":"projects/123","policy":{"bindings":[]}}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"results":[{"resource":"//storage.googleapis.com/other","assetType":"storage.googleapis.com/Bucket","project":"projects/999","policy":{"bindings":[]}}]}`), nil
	})
	var s Snapshot
	c.viewerSearchIAM(context.Background(), &s, "projects/123")
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}

func TestViewerPagesRepeatedToken(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, `{"nextPageToken":"same"}`), nil })
	err := c.viewerPages(context.Background(), "https://storage.googleapis.com/storage/v1/b", nil, func(Object) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatal(err)
	}
}

func TestViewerCloudHierarchyStaysWithinSelectedRoot(t *testing.T) {
	var projectReads int
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "folders/9:getIamPolicy") || (r.URL.Host == "cloudresourcemanager.googleapis.com" && strings.Contains(r.URL.Path, "organizations/")) {
			t.Fatal("restricted policy or outside-root metadata read", r.URL)
		}
		switch r.URL.Host + r.URL.Path {
		case "modelarmor.googleapis.com/v1/projects/123/locations/global/floorSetting":
			return response(200, `{"name":"projects/123/locations/global/floorSetting"}`), nil
		case "cloudresourcemanager.googleapis.com/v3/projects":
			if r.URL.Query().Get("parent") != "folders/9" {
				t.Fatal(r.URL)
			}
			return response(200, `{"projects":[{"name":"projects/123","projectId":"demo","parent":"folders/9","state":"ACTIVE"}]}`), nil
		case "cloudresourcemanager.googleapis.com/v3/folders":
			return response(200, `{}`), nil
		case "cloudresourcemanager.googleapis.com/v3/folders/9":
			return response(200, `{"name":"folders/9","parent":"organizations/1"}`), nil
		case "cloudresourcemanager.googleapis.com/v3/projects/123":
			projectReads++
			return response(200, `{"name":"projects/123","projectId":"demo","parent":"folders/9"}`), nil
		case "cloudresourcemanager.googleapis.com/v3/projects/123:getIamPolicy":
			return response(200, `{}`), nil
		case "compute.googleapis.com/compute/v1/projects/demo":
			return response(200, `{"name":"demo"}`), nil
		case "appengine.googleapis.com/v1/apps/demo":
			return response(200, `{"name":"apps/demo","id":"demo"}`), nil
		case "apigee.googleapis.com/v1/organizations/demo":
			return response(200, `{"name":"demo","projectId":"demo"}`), nil
		case "appengine.googleapis.com/v1/apps/demo/firewall/ingressRules":
			return response(200, `{"ingressRules":[{"priority":2147483647,"action":"DENY","sourceRange":"*"}]}`), nil
		case "cloudasset.googleapis.com/v1/projects/123:searchAllIamPolicies":
			return response(200, `{}`), nil
		case "identitytoolkit.googleapis.com/admin/v2/projects/123/config":
			return response(200, `{"name":"projects/123/config"}`), nil
		default:
			return response(200, `{}`), nil
		}
	})
	c.viewerPolicy.permissions["parametermanager.locations.list"] = true
	c.viewerPolicy.permissions["parametermanager.parameters.list"] = true
	s := c.ViewerCloud(context.Background(), "folders/9")
	if projectReads != 1 || hasCoverage(s, "failed") || len(s.Assets) != 7 {
		t.Fatal(s, projectReads)
	}
}

func TestViewerComputeBenignEmptyWarning(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "aggregated/instances") {
			return response(200, `{"warning":{"code":"NO_RESULTS_ON_PAGE"},"unreachables":[]}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "global/firewalls") {
			return response(200, `{}`), nil
		}
		return response(200, `{"name":"demo"}`), nil
	})
	var s Snapshot
	c.viewerCompute(context.Background(), &s, "demo", "projects/123")
	if hasCoverage(s, "failed") {
		t.Fatal(s)
	}
}
