package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestViewerPermissionMapping(t *testing.T) {
	tests := []struct {
		method, endpoint string
		query            url.Values
		want             []string
	}{
		{"GET", "https://cloudresourcemanager.googleapis.com/v3/projects/123", nil, []string{"resourcemanager.projects.get"}},
		{"GET", "https://cloudresourcemanager.googleapis.com/v3/folders", nil, []string{"resourcemanager.folders.list"}},
		{"POST", "https://cloudresourcemanager.googleapis.com/v3/organizations/123:getIamPolicy", nil, []string{"resourcemanager.organizations.getIamPolicy"}},
		{"GET", "https://cloudasset.googleapis.com/v1/projects/123/assets", url.Values{"contentType": {"IAM_POLICY"}}, []string{"cloudasset.assets.listIamPolicy"}},
		{"GET", "https://cloudasset.googleapis.com/v1/projects/123:searchAllIamPolicies", nil, []string{"cloudasset.assets.searchAllIamPolicies"}},
		{"GET", "https://storage.googleapis.com/storage/v1/b", url.Values{"project": {"p"}}, []string{"storage.buckets.list"}},
		{"GET", "https://storage.googleapis.com/storage/v1/b/bucket/o/file%2Fname?alt=media", nil, []string{"storage.objects.get"}},
		{"POST", "https://iap.googleapis.com/v1/projects/123/iap_web/appengine-app/services/default/versions/v1:getIamPolicy", nil, []string{"iap.webServiceVersions.getIamPolicy"}},
		{"GET", "https://iap.googleapis.com/v1/projects/123/iap_web/compute/services/id:iapSettings", nil, []string{"iap.webServices.getSettings"}},
		{"GET", "https://appengine.googleapis.com/v1/apps/app/services/default/versions/v1", url.Values{"view": {"FULL"}}, []string{"appengine.versions.get"}},
		{"POST", "https://logging.googleapis.com/v2/entries:list", nil, []string{"logging.logEntries.list"}},
		{"GET", "https://sqladmin.googleapis.com/v1/projects/demo/instances", nil, []string{"cloudsql.instances.list"}},
		{"GET", "https://container.googleapis.com/v1/projects/demo/locations/-/clusters", nil, []string{"container.clusters.list"}},
		{"GET", "https://run.googleapis.com/v1/projects/demo/locations", nil, []string{"run.locations.list"}},
		{"GET", "https://run.googleapis.com/v2/projects/demo/locations/us-central1/services", nil, []string{"run.services.list"}},
		{"GET", "https://run.googleapis.com/v2/projects/demo/locations/us-central1/jobs", nil, []string{"run.jobs.list"}},
		{"GET", "https://cloudfunctions.googleapis.com/v1/projects/demo/locations/-/functions", nil, []string{"cloudfunctions.functions.list"}},
		{"GET", "https://cloudfunctions.googleapis.com/v2/projects/demo/locations/-/functions", nil, []string{"cloudfunctions.functions.list"}},
		{"GET", "https://dns.googleapis.com/dns/v1/projects/demo/managedZones", nil, []string{"dns.managedZones.list"}},
		{"GET", "https://iam.googleapis.com/v1/projects/demo/serviceAccounts", nil, []string{"iam.serviceAccounts.list"}},
		{"GET", "https://apikeys.googleapis.com/v2/projects/123/locations/global/keys", nil, []string{"apikeys.keys.list"}},
		{"GET", "https://secretmanager.googleapis.com/v1/projects/123/secrets/db/versions", nil, []string{"secretmanager.versions.list"}},
		{"GET", "https://cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions", nil, []string{"cloudkms.cryptoKeyVersions.list"}},
		{"GET", "https://cloudbuild.googleapis.com/v2/projects/demo/locations", nil, []string{"cloudbuild.locations.list"}},
		{"GET", "https://cloudbuild.googleapis.com/v1/projects/demo/locations/global/triggers", nil, []string{"cloudbuild.builds.list"}},
		{"GET", "https://workflows.googleapis.com/v1/projects/demo/locations/us-central1/workflows/flow", nil, []string{"workflows.workflows.get"}},
		{"GET", "https://artifactregistry.googleapis.com/v1/projects/demo/locations/us/repositories", nil, []string{"artifactregistry.repositories.list"}},
		{"GET", "https://cloudscheduler.googleapis.com/v1/projects/demo/locations/us-central1/jobs", nil, []string{"cloudscheduler.jobs.list"}},
		{"GET", "https://pubsub.googleapis.com/v1/projects/demo/subscriptions", nil, []string{"pubsub.subscriptions.list"}},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			got, err := viewerRequestPermissions(tt.method, tt.endpoint, tt.query)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestViewerServiceUsageGuard(t *testing.T) {
	endpoint := "https://serviceusage.googleapis.com/v1/projects/123/services"
	valid := func() url.Values {
		return url.Values{"filter": {"state:ENABLED"}, "fields": {viewerServiceUsageFields}, "pageSize": {"200"}}
	}
	if got, err := viewerRequestPermissions("GET", endpoint, valid()); err != nil || !reflect.DeepEqual(got, []string{"serviceusage.services.list"}) {
		t.Fatal(got, err)
	}
	for _, change := range []func(url.Values){func(q url.Values) { q.Set("filter", "state:DISABLED") }, func(q url.Values) { q.Del("filter") }, func(q url.Values) { q.Add("filter", "state:ENABLED") }, func(q url.Values) { q.Set("fields", "*") }, func(q url.Values) { q.Set("pageSize", "201") }, func(q url.Values) { q.Set("unknown", "x") }} {
		q := valid()
		change(q)
		if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
			t.Fatal(q)
		}
	}
	for _, target := range []string{"https://serviceusage.googleapis.com/v1/projects/demo/services", endpoint + "/run.googleapis.com", endpoint + ":enable"} {
		if _, err := viewerRequestPermissions("GET", target, valid()); err == nil {
			t.Fatal(target)
		}
	}
	if _, err := viewerRequestPermissions("POST", endpoint, valid()); err == nil {
		t.Fatal("mutation accepted")
	}
}

func TestViewerDNSPolicyGuard(t *testing.T) {
	for _, tc := range []struct{ collection, fields, permission string }{{"policies", viewerDNSPolicyFields, "dns.policies.list"}, {"responsePolicies", viewerDNSResponsePolicyFields, "dns.responsePolicies.list"}} {
		endpoint := "https://dns.googleapis.com/dns/v1/projects/demo/" + tc.collection
		valid := func() url.Values { return url.Values{"fields": {tc.fields}, "maxResults": {"100"}} }
		if p, err := viewerRequestPermissions("GET", endpoint, valid()); err != nil || len(p) != 1 || p[0] != tc.permission {
			t.Fatal(p, err)
		}
		for _, change := range []func(url.Values){func(q url.Values) { q.Set("fields", "*") }, func(q url.Values) { q.Del("maxResults") }, func(q url.Values) { q.Add("maxResults", "100") }, func(q url.Values) { q.Set("filter", "name=x") }} {
			q := valid()
			change(q)
			if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
				t.Fatal(q)
			}
		}
		for _, method := range []string{"POST", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, endpoint, valid()); err == nil {
				t.Fatal(method)
			}
		}
		if _, err := viewerRequestPermissions("GET", endpoint+"/policy", valid()); err == nil {
			t.Fatal("unreviewed get allowed")
		}
	}
}

func TestViewerDNSResponseRuleGuard(t *testing.T) {
	endpoint := "https://dns.googleapis.com/dns/v1/projects/demo/responsePolicies/policy/rules"
	valid := func() url.Values { return url.Values{"fields": {viewerDNSResponseRuleFields}, "maxResults": {"100"}} }
	if got, err := viewerRequestPermissions("GET", endpoint, valid()); err != nil || !reflect.DeepEqual(got, []string{"dns.responsePolicyRules.list"}) {
		t.Fatal(got, err)
	}
	for _, change := range []func(url.Values){func(q url.Values) { q.Set("fields", "*") }, func(q url.Values) { q.Set("maxResults", "200") }, func(q url.Values) { q.Add("fields", viewerDNSResponseRuleFields) }, func(q url.Values) { q.Set("filter", "x") }} {
		q := valid()
		change(q)
		if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
			t.Fatal(q)
		}
	}
	if _, err := viewerRequestPermissions("GET", endpoint+"/rule", valid()); err == nil {
		t.Fatal("unreviewed get")
	}
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		if _, err := viewerRequestPermissions(method, endpoint, valid()); err == nil {
			t.Fatal(method)
		}
	}
	// Existing optional probe uses the same read-only rrsets permission with
	// no metadata field selector; default collection must not break that mode.
	if _, err := viewerRequestPermissions("GET", "https://dns.googleapis.com/dns/v1/projects/demo/managedZones/zone/rrsets", nil); err != nil {
		t.Fatal(err)
	}
}

func TestViewerMemorystoreGuard(t *testing.T) {
	for _, tc := range []struct{ host, collection, fields, permission string }{{"redis.googleapis.com", "instances", viewerRedisInstanceFields, "redis.instances.list"}, {"redis.googleapis.com", "clusters", viewerRedisClusterFields, "redis.clusters.list"}, {"memcache.googleapis.com", "instances", viewerMemcacheFields, "memcache.instances.list"}} {
		endpoint := "https://" + tc.host + "/v1/projects/demo/locations/-/" + tc.collection
		valid := func() url.Values { return url.Values{"fields": {tc.fields}, "pageSize": {"100"}} }
		if got, err := viewerRequestPermissions("GET", endpoint, valid()); err != nil || !reflect.DeepEqual(got, []string{tc.permission}) {
			t.Fatal(got, err)
		}
		for _, change := range []func(url.Values){func(q url.Values) { q.Set("fields", "*") }, func(q url.Values) { q.Add("pageSize", "100") }, func(q url.Values) { q.Set("filter", "x") }} {
			q := valid()
			change(q)
			if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
				t.Fatal(q)
			}
		}
		for _, suffix := range []string{"/cache", "/cache/authString", "/cache:getAuthString", "/cache:export", "/cache:import", "/cache/tokenAuthUsers"} {
			if _, err := viewerRequestPermissions("GET", endpoint+suffix, valid()); err == nil {
				t.Fatal(suffix)
			}
		}
		if _, err := viewerRequestPermissions("POST", endpoint, valid()); err == nil {
			t.Fatal("mutation allowed")
		}
	}
}

func TestViewerRedisSecretEndpointsBlockedDespitePermissions(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("secret endpoint reached network")
		return nil, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"redis.instances.getAuthString": true, "redis.clusters.get": true, "redis.instances.export": true, "redis.instances.import": true, "redis.tokenAuthUsers.get": true, "redis.tokenAuthUsers.list": true}
	for _, endpoint := range []string{"https://redis.googleapis.com/v1/projects/demo/locations/us-central1/instances/cache/authString", "https://redis.googleapis.com/v1/projects/demo/locations/us-central1/instances/cache:getAuthString", "https://redis.googleapis.com/v1/projects/demo/locations/us-central1/clusters/cache/tokenAuthUsers"} {
		if _, err := c.get(context.Background(), endpoint, url.Values{"fields": {viewerRedisInstanceFields}, "pageSize": {"100"}}); err == nil {
			t.Fatal("secret endpoint accepted")
		}
	}
}

func TestViewerBigtableTableNamesMatchingCollections(t *testing.T) {
	base := "https://bigtableadmin.googleapis.com/v2/projects/demo/instances/db/tables/"
	for _, name := range []string{"tables", "instances", "authorizedViews"} {
		q := url.Values{"fields": {viewerBigtableTableFields}, "view": {"FULL"}}
		got, err := viewerRequestPermissions("GET", base+name, q)
		if err != nil || !reflect.DeepEqual(got, []string{"bigtable.tables.get"}) {
			t.Fatal(name, got, err)
		}
		for _, suffix := range []string{":readRows", ":sampleRowKeys", ":dropRowRange", ":executeQuery"} {
			if _, err := viewerRequestPermissions("GET", base+name+suffix, q); err == nil {
				t.Fatal(name, suffix)
			}
		}
		q = url.Values{"fields": {viewerBigtableAuthorizedViewFields}, "view": {"FULL"}, "pageSize": {"100"}}
		got, err = viewerRequestPermissions("GET", base+name+"/authorizedViews", q)
		if err != nil || !reflect.DeepEqual(got, []string{"bigtable.authorizedViews.list"}) {
			t.Fatal(name, got, err)
		}
		if _, err := viewerRequestPermissions("GET", base+name, q); err == nil {
			t.Fatal("collection query accepted on table", name)
		}
	}
}

func TestViewerHealthcareMetadataPolicyGuard(t *testing.T) {
	base := "https://healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/ds"
	for _, collection := range []string{"fhirStores", "dicomStores", "hl7V2Stores"} {
		q := url.Values{"fields": {collection + "(name),nextPageToken"}, "pageSize": {"100"}}
		if p, e := viewerRequestPermissions("GET", base+"/"+collection, q); e != nil || !reflect.DeepEqual(p, []string{"healthcare." + collection + ".list"}) {
			t.Fatal(p, e)
		}
		endpoint := base + "/" + collection + "/store:getIamPolicy"
		q = url.Values{"fields": {"version,bindings,etag"}, "options.requestedPolicyVersion": {"3"}}
		if p, e := viewerRequestPermissions("GET", endpoint, q); e != nil || !reflect.DeepEqual(p, []string{"healthcare." + collection + ".getIamPolicy"}) {
			t.Fatal(p, e)
		}
		q.Set("options.requestedPolicyVersion", "1")
		if _, e := viewerRequestPermissions("GET", endpoint, q); e == nil {
			t.Fatal("old policy version")
		}
	}
	for _, path := range []string{"/fhirStores/store/fhir/Patient", "/fhirStores/store/fhir:search", "/dicomStores/store/dicomWeb/studies", "/hl7V2Stores/store/messages", "/hl7V2Stores/store/messages:ingest", "/fhirStores/store:export", "/fhirStores/store:setIamPolicy"} {
		if _, e := viewerRequestPermissions("GET", base+path, url.Values{"fields": {"version,bindings,etag"}, "options.requestedPolicyVersion": {"3"}}); e == nil {
			t.Fatal(path)
		}
	}
}

func TestViewerAlloyDBMetadataGuard(t *testing.T) {
	for _, tc := range []struct{ path, fields, permission string }{{"locations/-/clusters", viewerAlloyDBClusterFields, "alloydb.clusters.list"}, {"locations/-/clusters/-/instances", viewerAlloyDBInstanceFields, "alloydb.instances.list"}, {"locations/us-central1/clusters/cluster/users", viewerAlloyDBUserFields, "alloydb.users.list"}} {
		endpoint := "https://alloydb.googleapis.com/v1/projects/demo/" + tc.path
		valid := func() url.Values { return url.Values{"fields": {tc.fields}, "pageSize": {"100"}} }
		if got, err := viewerRequestPermissions("GET", endpoint, valid()); err != nil || !reflect.DeepEqual(got, []string{tc.permission}) {
			t.Fatal(got, err)
		}
		for _, change := range []func(url.Values){func(q url.Values) { q.Set("fields", "*") }, func(q url.Values) { q.Set("view", "INSTANCE_VIEW_FULL") }, func(q url.Values) { q.Add("pageSize", "100") }, func(q url.Values) { q.Set("filter", "x") }} {
			q := valid()
			change(q)
			if _, err := viewerRequestPermissions("GET", endpoint, q); err == nil {
				t.Fatal(q)
			}
		}
		if _, err := viewerRequestPermissions("POST", endpoint, valid()); err == nil {
			t.Fatal("mutation allowed")
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("sensitive endpoint reached"); return nil, nil })
	c.viewerPolicy.permissions = map[string]bool{"alloydb.instances.executeSql": true, "alloydb.instances.connect": true, "alloydb.clusters.export": true, "alloydb.clusters.import": true, "alloydb.clusters.generateClientCertificate": true}
	for _, suffix := range []string{":export", ":import", ":generateClientCertificate", "/instances/main:executeSql", "/instances/main:connect"} {
		if _, err := c.get(context.Background(), "https://alloydb.googleapis.com/v1/projects/demo/locations/us-central1/clusters/cluster"+suffix, url.Values{"fields": {viewerAlloyDBClusterFields}, "pageSize": {"100"}}); err == nil {
			t.Fatal(suffix)
		}
	}
}

func TestViewerUnknownRequestsFailBeforeCredentials(t *testing.T) {
	c := &Client{TokenEnv: "GCPBUSTER_ABSENT_POLICY_TOKEN"}
	for _, endpoint := range []string{
		"https://example.invalid/assets", "http://compute.googleapis.com/compute/v1/projects/p", "https://compute.googleapis.com:443/compute/v1/projects/p", "https://user@compute.googleapis.com/compute/v1/projects/p",
		"https://compute.googleapis.com/compute/v1/projects/p?userProject=bill", "https://admin.googleapis.com/admin/directory/v1/users", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a:generateAccessToken",
		"https://cloudasset.googleapis.com/v1/projects/p/assets", "https://compute.googleapis.com/compute/v1/projects/p#fragment",
		"https://storage.googleapis.com/storage/v1/b/bucket/o/object/acl",
	} {
		err := c.requireViewerPermissions(context.Background(), "GET", endpoint, nil)
		if err == nil || strings.Contains(err.Error(), "environment") {
			t.Fatalf("%s: %v", endpoint, err)
		}
	}
	if err := c.requireViewerPermissions(context.Background(), "DELETE", "https://compute.googleapis.com/compute/v1/projects/p", nil); err == nil || strings.Contains(err.Error(), "environment") {
		t.Fatal(err)
	}
}

func TestViewerServiceMethodsDoNotAuthorizeWritesOrPayloadAPIs(t *testing.T) {
	for _, endpoint := range []string{
		"https://sqladmin.googleapis.com/v1/projects/demo/instances",
		"https://container.googleapis.com/v1/projects/demo/locations/-/clusters",
		"https://run.googleapis.com/v2/projects/demo/locations/us-central1/services",
		"https://run.googleapis.com/v2/projects/demo/locations/us-central1/jobs",
		"https://cloudfunctions.googleapis.com/v2/projects/demo/locations/-/functions",
		"https://dns.googleapis.com/dns/v1/projects/demo/managedZones",
		"https://iam.googleapis.com/v1/projects/demo/serviceAccounts",
	} {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, endpoint, nil); err == nil {
				t.Fatalf("service collection authorized write: %s %s", method, endpoint)
			}
		}
	}
	for _, endpoint := range []string{
		"https://sqladmin.googleapis.com/v1/projects/demo/instances/db/connectSettings",
		"https://run.googleapis.com/v2/projects/demo/locations/us-central1/jobs/job:run",
		"https://cloudfunctions.googleapis.com/v1/projects/demo/locations/us-central1/functions/fn:generateDownloadUrl",
		"https://iam.googleapis.com/v1/projects/demo/serviceAccounts/123/keys/key",
		"https://apikeys.googleapis.com/v2/projects/123/locations/global/keys/key/keyString",
		"https://apikeys.googleapis.com/v2/projects/123/locations/global/keys/key:getKeyString",
		"https://secretmanager.googleapis.com/v1/projects/123/secrets/db/versions/1:access",
		"https://cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key:decrypt",
		"https://cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1/publicKey",
		"https://pubsub.googleapis.com/v1/projects/demo/subscriptions/sub:pull",
		"https://cloudscheduler.googleapis.com/v1/projects/demo/locations/us-central1/jobs/job:run",
		"https://workflowexecutions.googleapis.com/v1/projects/demo/locations/us-central1/workflows/flow/executions",
	} {
		if _, err := viewerRequestPermissions("GET", endpoint, nil); err == nil {
			t.Fatal("metadata listing enabled a new unreviewed API", endpoint)
		}
	}
}

func TestViewerRoleUnionCachedAndExtraCredentialPermissionsIgnored(t *testing.T) {
	t.Setenv("GCPBUSTER_POLICY_TEST", "privileged-but-limited")
	calls := 0
	c := &Client{TokenEnv: "GCPBUSTER_POLICY_TEST", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "iam.googleapis.com" || r.Header.Get("Authorization") != "Bearer privileged-but-limited" {
			t.Fatalf("unexpected bootstrap: %v", r)
		}
		role := strings.TrimPrefix(r.URL.Path, "/v1/")
		permissions := []string{"iam.roles.get"}
		switch role {
		case "roles/viewer":
			permissions = append(permissions, "compute.projects.get")
		case "roles/resourcemanager.folderViewer":
			permissions = append(permissions, "resourcemanager.folders.get")
		case "roles/resourcemanager.organizationViewer":
			permissions = append(permissions, "resourcemanager.organizations.get")
		default:
			t.Fatalf("unexpected role %s", role)
		}
		b, _ := json.Marshal(Object{"name": role, "includedPermissions": permissions})
		return response(200, string(b)), nil
	})}}
	for _, endpoint := range []string{"https://compute.googleapis.com/compute/v1/projects/p", "https://cloudresourcemanager.googleapis.com/v3/folders/1", "https://cloudresourcemanager.googleapis.com/v3/organizations/2"} {
		if err := c.requireViewerPermissions(context.Background(), "GET", endpoint, nil); err != nil {
			t.Fatal(err)
		}
	}
	err := c.requireViewerPermissions(context.Background(), "GET", "https://storage.googleapis.com/storage/v1/b/bucket/o/file?alt=media", nil)
	if err == nil || !strings.Contains(err.Error(), "storage.objects.get") {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("role requests = %d, want 3", calls)
	}
}

func TestViewerRoleDefinitionFailuresAreClosed(t *testing.T) {
	t.Setenv("GCPBUSTER_POLICY_TEST", "token")
	for _, body := range []string{`{}`, `{"name":"roles/owner","includedPermissions":["compute.projects.get"]}`, `{"name":"roles/viewer","includedPermissions":["*"]}`, `{"name":"roles/viewer","deleted":true,"includedPermissions":["compute.projects.get"]}`, `{"name":"roles/viewer","includedPermissions":[]}`} {
		c := &Client{TokenEnv: "GCPBUSTER_POLICY_TEST", HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return response(200, body), nil })}}
		if err := c.requireViewerPermissions(context.Background(), "GET", "https://compute.googleapis.com/compute/v1/projects/p", nil); err == nil {
			t.Fatalf("accepted %s", body)
		}
		if c.viewerPolicy.permissions != nil {
			t.Fatal("cached partial/unverified permission set")
		}
	}
	c := &Client{TokenEnv: "GCPBUSTER_POLICY_TEST", HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return response(403, "secret-upstream-body"), nil })}}
	if err := c.requireViewerPermissions(context.Background(), "GET", "https://compute.googleapis.com/compute/v1/projects/p", nil); err == nil || strings.Contains(err.Error(), "secret-upstream") {
		t.Fatal(err)
	}
}
