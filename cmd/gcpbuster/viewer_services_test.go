package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
)

// Unlike contentTransport, this fixture exposes only the permissions needed by
// current Viewer service collectors. It is a contract test, not a role snapshot
// or evidence that the test credentials have any real Google Cloud authority.
type viewerServicesTransport struct{ t *testing.T }

func (f viewerServicesTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Helper()
	respond := func(body string) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	}
	if r.Method != "GET" && !(r.Method == "POST" && (r.URL.Path == "/v3/projects/123:getIamPolicy" || r.URL.Path == "/v2/projects/123/locations/global/buckets/short/views/_AllLogs:getIamPolicy" || ((r.URL.Host == "bigtableadmin.googleapis.com" || r.URL.Host == "spanner.googleapis.com") && strings.HasSuffix(r.URL.Path, ":getIamPolicy")))) {
		f.t.Fatalf("unexpected method: %s %s", r.Method, r.URL)
	}
	key := r.URL.Host + r.URL.Path
	if r.URL.Host == "iam.googleapis.com" && (strings.HasPrefix(r.URL.Path, "/v1/roles/") || r.URL.Path == "/v1/projects/demo/roles/snapshotSource") {
		role := strings.TrimPrefix(r.URL.Path, "/v1/")
		permissions := []string{"iam.roles.get"}
		switch role {
		case "roles/viewer":
			permissions = append(permissions, "parametermanager.locations.list", "parametermanager.parameters.list")
			permissions = append(permissions, "source.repos.get")
			permissions = append(permissions, "apigee.apiproducts.list")
			permissions = append(permissions, "compute.networks.getRegionEffectiveFirewalls")
			permissions = append(permissions, "compute.networks.getEffectiveFirewalls")
			permissions = append(permissions, "cloudbuild.repositories.get")
			permissions = append(permissions, "compute.routes.list")
			permissions = append(permissions, "modelarmor.locations.list", "modelarmor.templates.list", "modelarmor.floorSettings.get")
			permissions = append(permissions, "compute.backendServices.list")
			permissions = append(permissions, "firebaseappcheck.services.get", "firebaseappcheck.resourcePolicies.get")
			permissions = append(permissions, "apigee.organizations.get", "apigee.deployments.list", "apigee.envgroups.list", "apigee.envgroupattachments.list", "apigee.proxyrevisions.get", "apigee.flowhooks.getSharedFlow", "apigee.sharedflowrevisions.get")
			permissions = append(permissions, "artifactregistry.repositories.getIamPolicy")
			permissions = append(permissions, "healthcare.locations.list", "healthcare.datasets.list", "healthcare.datasets.getIamPolicy", "healthcare.fhirStores.list", "healthcare.fhirStores.getIamPolicy", "healthcare.dicomStores.list", "healthcare.dicomStores.getIamPolicy", "healthcare.hl7V2Stores.list", "healthcare.hl7V2Stores.getIamPolicy")
			permissions = append(permissions, "datastore.databases.list", "datastore.backups.list", "run.services.getIamPolicy", "cloudfunctions.functions.getIamPolicy")
			permissions = append(permissions, "spanner.instances.list", "spanner.instances.getIamPolicy", "spanner.databases.list", "spanner.databases.getIamPolicy", "spanner.databases.getDdl", "spanner.backups.list", "spanner.backups.getIamPolicy")
			permissions = append(permissions, "bigtable.instances.list", "bigtable.instances.getIamPolicy", "bigtable.tables.list", "bigtable.tables.get", "bigtable.tables.getIamPolicy", "bigtable.authorizedViews.list", "bigtable.authorizedViews.getIamPolicy")
			permissions = append(permissions, "file.instances.list")
			permissions = append(permissions, "alloydb.clusters.list", "alloydb.instances.list", "alloydb.users.list")
			permissions = append(permissions, "redis.instances.list", "redis.clusters.list", "memcache.instances.list")
			permissions = append(permissions, "dns.resourceRecordSets.list", "dns.responsePolicyRules.list")
			permissions = append(permissions, "dns.policies.list", "dns.responsePolicies.list")
			permissions = append(permissions, "serviceusage.services.list", "appengine.applications.get", "appengine.services.list", "appengine.versions.list", "appengine.versions.get")
			permissions = append(permissions, "servicemanagement.services.list", "servicemanagement.services.get")
			permissions = append(permissions, "apigateway.locations.list", "apigateway.apis.list", "apigateway.apiconfigs.list", "apigateway.apiconfigs.get", "apigateway.gateways.list")
			permissions = append(permissions, "resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy", "compute.projects.get", "compute.instances.list", "compute.firewalls.list", "storage.buckets.list", "cloudasset.assets.searchAllIamPolicies", "cloudsql.instances.list", "container.clusters.list", "run.locations.list", "run.services.list", "run.jobs.list", "cloudfunctions.functions.list", "dns.managedZones.list", "iam.serviceAccounts.list", "iam.serviceAccountKeys.list")
			permissions = append(permissions, "apikeys.keys.list", "secretmanager.secrets.list", "secretmanager.versions.list", "cloudkms.locations.list", "cloudkms.keyRings.list", "cloudkms.cryptoKeys.list", "cloudkms.cryptoKeyVersions.list", "cloudbuild.locations.list", "cloudbuild.builds.list", "workflows.locations.list", "workflows.workflows.list", "workflows.workflows.get", "artifactregistry.locations.list", "artifactregistry.repositories.list", "cloudscheduler.locations.list", "cloudscheduler.jobs.list", "pubsub.subscriptions.list", "pubsub.topics.list", "pubsub.schemas.list", "pubsub.schemas.listRevisions", "pubsub.snapshots.list")
			permissions = append(permissions, "bigquery.datasets.get", "bigquery.datasets.getIamPolicy", "firebaseauth.configs.get", "identitytoolkit.tenants.list", "identitytoolkit.tenants.get", "cloudtasks.locations.list", "cloudtasks.queues.list", "cloudtasks.tasks.list", "aiplatform.locations.list", "aiplatform.customJobs.list", "aiplatform.customJobs.get", "aiplatform.pipelineJobs.list", "aiplatform.pipelineJobs.get")
			permissions = append(permissions, "compute.instanceTemplates.list", "compute.machineImages.list", "compute.networks.list", "compute.subnetworks.list", "compute.subnetworks.getIamPolicy", "compute.images.list", "compute.snapshots.list", "compute.regions.list", "compute.images.getIamPolicy", "compute.snapshots.getIamPolicy", "iam.workloadIdentityPools.list", "iam.workloadIdentityPoolProviders.list", "dataflow.jobs.list", "dataflow.jobs.get")
			permissions = append(permissions, "cloudsql.users.list", "cloudkms.keyRings.getIamPolicy", "cloudkms.cryptoKeys.getIamPolicy")
			permissions = append(permissions, "cloudsql.databases.list", "cloudsql.backupRuns.list", "cloudsql.backupRuns.get")
			permissions = append(permissions, "cloudasset.assets.searchAllResources", "composer.environments.get")
			permissions = append(permissions, "secretmanager.locations.list", "secretmanager.secrets.get", "secretmanager.secrets.getIamPolicy", "logging.buckets.list", "logging.views.list", "logging.views.getIamPolicy", "logging.links.list", "logging.logMetrics.list")
		case "roles/resourcemanager.folderViewer":
			permissions = append(permissions, "resourcemanager.folders.get")
		case "roles/resourcemanager.organizationViewer":
			permissions = append(permissions, "resourcemanager.organizations.get")
		case "roles/iam.serviceAccountKeyAdmin":
			// Definitions of roles assigned to assessed principals, not grants
			// to the scanning identity or additions to its three-role union.
			permissions = []string{"iam.serviceAccountKeys.create"}
		case "roles/cloudkms.cryptoKeyDecrypter":
			permissions = []string{"cloudkms.cryptoKeyVersions.useToDecrypt"}
		case "roles/artifactregistry.reader":
			permissions = []string{"artifactregistry.repositories.downloadArtifacts"}
		case "roles/logging.viewAccessor":
			permissions = []string{"logging.views.access"}
		case "roles/compute.imageUser":
			permissions = []string{"compute.images.useReadOnly"}
		case "projects/demo/roles/snapshotSource":
			permissions = []string{"compute.snapshots.useReadOnly"}
		case "roles/pubsub.publisher":
			permissions = []string{"pubsub.topics.publish"}
		case "roles/storage.objectViewer":
			permissions = []string{"storage.objects.get", "storage.objects.list"}
		case "roles/bigquery.dataViewer":
			permissions = []string{"bigquery.tables.getData"}
		case "roles/iap.httpsResourceAccessor":
			permissions = []string{"iap.webServiceVersions.accessViaIAP"}
		case "roles/iam.serviceAccountTokenCreator":
			permissions = []string{"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt"}
		case "roles/spanner.fineGrainedAccessUser":
			permissions = []string{"spanner.databases.useRoleBasedAccess"}
		case "roles/spanner.databaseRoleUser":
			permissions = []string{"spanner.databaseRoles.use"}
		case "roles/run.invoker":
			permissions = []string{"run.routes.invoke"}
		case "roles/healthcare.fhirResourceReader":
			permissions = []string{"healthcare.fhirResources.get"}
		case "roles/cloudscheduler.jobRunner":
			permissions = []string{"cloudscheduler.jobs.run"}
		case "roles/cloudsql.admin":
			permissions = []string{"cloudsql.users.update"}
		case "roles/secretmanager.secretAccessor":
			permissions = []string{"secretmanager.versions.access"}
		default:
			f.t.Fatal("unexpected role", role)
		}
		b, _ := json.Marshal(inventory.Object{"name": role, "includedPermissions": permissions})
		return respond(string(b))
	}
	switch key {
	case "apigee.googleapis.com/v1/organizations/demo/apiproducts":
		return respond(`{"apiProduct":[{"name":"trial","approvalType":"auto","attributes":[{"name":"access","value":"public"},{"name":"private_attribute","value":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}]}`)
	case "sourcerepo.googleapis.com/v1/projects/demo/repos/nested/repo":
		return respond(`{"name":"projects/demo/repos/nested/repo","mirrorConfig":{"url":"https://github.com/example/public-build.git","webhookId":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","deployKeyId":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "modelarmor.googleapis.com/v1/projects/123/locations/global/floorSetting":
		return respond(`{"name":"projects/123/locations/global/floorSetting","enableFloorSettingEnforcement":false}`)
	case "modelarmor.us-central1.rep.googleapis.com/v1/projects/123/locations":
		return respond(`{"locations":[{"name":"projects/123/locations/us-central1","locationId":"us-central1"}]}`)
	case "modelarmor.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/templates":
		return respond(`{"templates":[{"name":"projects/123/locations/us-central1/templates/template","filterConfig":{"piAndJailbreakFilterSettings":{"filterEnforcement":"ENABLED","confidenceLevel":"HIGH"},"sdpSettings":{"basicConfig":{"filterEnforcement":"DISABLED"}},"filterRuleSettings":{"ruleSets":[{"filterTypes":["PROMPT_INJECTION_AND_JAILBREAK"],"rules":[{"exclusionRule":{"matchingScope":"MATCHING_SCOPE_PARTIAL_MATCH","regex":{"pattern":"(?s).*"}}}]}]}},"templateMetadata":{"enforcementType":"INSPECT_ONLY","ignorePartialInvocationFailures":true,"customPromptSafetyErrorMessage":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "apigee.googleapis.com/v1/organizations/demo":
		return respond(`{"name":"demo","projectId":"demo"}`)
	case "apigee.googleapis.com/v1/organizations/demo/envgroups":
		return respond(`{}`)
	case "apigee.googleapis.com/v1/organizations/demo/deployments":
		return respond(`{"deployments":[{"apiProxy":"api","revision":"1","environment":"prod","state":"READY"}]}`)
	case "apigee.googleapis.com/v1/organizations/demo/environments/prod/flowhooks/PreProxyFlowHook", "apigee.googleapis.com/v1/organizations/demo/environments/prod/flowhooks/PostProxyFlowHook", "apigee.googleapis.com/v1/organizations/demo/environments/prod/flowhooks/PreTargetFlowHook", "apigee.googleapis.com/v1/organizations/demo/environments/prod/flowhooks/PostTargetFlowHook":
		return respond(`{}`)
	case "apigee.googleapis.com/v1/organizations/demo/sharedflows/flow/deployments":
		return respond(`{"deployments":[{"apiProxy":"flow","revision":"2","environment":"prod","state":"READY"}]}`)
	case "apigee.googleapis.com/v1/organizations/demo/apis/api/revisions/1", "apigee.googleapis.com/v1/organizations/demo/sharedflows/flow/revisions/2":
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		sources := map[string]string{
			"apiproxy/policies/auth.xml":   `<VerifyAPIKey name="VIEWER_PIPELINE_SECRET_DO_NOT_SAVE" enabled="false"><APIKey ref="VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"/></VerifyAPIKey>`,
			"apiproxy/policies/call.xml":   `<FlowCallout name="callout"><SharedFlowBundle>flow</SharedFlowBundle></FlowCallout>`,
			"apiproxy/proxies/default.xml": `<ProxyEndpoint name="default"><HTTPProxyConnection><BasePath>/v1/weather</BasePath></HTTPProxyConnection><PreFlow><Request><Step><Name>VIEWER_PIPELINE_SECRET_DO_NOT_SAVE</Name></Step><Step><Name>callout</Name></Step></Request></PreFlow></ProxyEndpoint>`,
		}
		if strings.Contains(r.URL.Path, "/sharedflows/") {
			sources = map[string]string{
				"sharedflowbundle/policies/auth.xml":       `<VerifyJWT name="VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"/>`,
				"sharedflowbundle/sharedflows/default.xml": `<SharedFlow name="default"><Step><Name>VIEWER_PIPELINE_SECRET_DO_NOT_SAVE</Name></Step></SharedFlow>`,
			}
		}
		for name, source := range sources {
			w, err := z.Create(name)
			if err != nil {
				f.t.Fatal(err)
			}
			if _, err = w.Write([]byte(source)); err != nil {
				f.t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			f.t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b.Bytes()))}, nil
	case "healthcare.googleapis.com/v1/projects/demo/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`)
	case "healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets":
		return respond(`{"datasets":[{"name":"projects/demo/locations/us-central1/datasets/data","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data/fhirStores":
		return respond(`{"fhirStores":[{"name":"projects/demo/locations/us-central1/datasets/data/fhirStores/store","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data/dicomStores", "healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data/hl7V2Stores":
		return respond(`{}`)
	case "healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data:getIamPolicy":
		return respond(`{"version":3,"bindings":[]}`)
	case "healthcare.googleapis.com/v1/projects/demo/locations/us-central1/datasets/data/fhirStores/store:getIamPolicy":
		return respond(`{"version":3,"bindings":[{"role":"roles/healthcare.fhirResourceReader","members":["allAuthenticatedUsers"]}]}`)
	case "firestore.googleapis.com/v1/projects/demo/databases":
		return respond(`{"databases":[{"name":"projects/demo/databases/(default)","locationId":"us-central1","type":"FIRESTORE_NATIVE","deleteProtectionState":"DELETE_PROTECTION_DISABLED","pointInTimeRecoveryEnablement":"POINT_IN_TIME_RECOVERY_DISABLED","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "firestore.googleapis.com/v1/projects/demo/locations/-/backups":
		return respond(`{}`)
	case "spanner.googleapis.com/v1/projects/demo/instances":
		return respond(`{"instances":[{"name":"projects/demo/instances/db","state":"READY","instanceType":"PROVISIONED","edition":"ENTERPRISE","displayName":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "spanner.googleapis.com/v1/projects/demo/instances/db/databases":
		return respond(`{"databases":[{"name":"projects/demo/instances/db/databases/data","state":"READY","databaseDialect":"GOOGLE_STANDARD_SQL","enableDropProtection":false,"versionRetentionPeriod":"1h","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "spanner.googleapis.com/v1/projects/demo/instances/db/backups":
		return respond(`{"backups":[{"name":"projects/demo/instances/db/backups/backup","database":"projects/demo/instances/db/databases/data","state":"READY","expireTime":"2026-12-01T00:00:00Z","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "spanner.googleapis.com/v1/projects/demo/instances/db/databases/data/ddl":
		return respond("{\"statements\":[\"CREATE CHANGE STREAM VIEWER_PIPELINE_SECRET_DO_NOT_SAVE FOR ALL OPTIONS (exclude_insert = true)\",\"CREATE TABLE private_data (id INT64 NOT NULL) PRIMARY KEY(id)\",\"GRANT SELECT ON TABLE VIEWER_PIPELINE_SECRET_DO_NOT_SAVE TO ROLE public\",\"GRANT INSERT(id), SELECT(VIEWER_PIPELINE_SECRET_DO_NOT_SAVE) ON TABLE reporting.private_data TO ROLE `public`, restricted\",\"GRANT SELECT ON TABLE private_data TO ROLE restricted\"],\"protoDescriptors\":\"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE\"}")
	case "spanner.googleapis.com/v1/projects/demo/instances/db:getIamPolicy", "spanner.googleapis.com/v1/projects/demo/instances/db/databases/data:getIamPolicy", "spanner.googleapis.com/v1/projects/demo/instances/db/backups/backup:getIamPolicy":
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"options":{"requestedPolicyVersion":3}}` {
			f.t.Fatal("invalid Spanner IAM read body")
		}
		if r.URL.Path == "/v1/projects/demo/instances/db/databases/data:getIamPolicy" {
			return respond(`{"version":3,"bindings":[{"role":"roles/spanner.fineGrainedAccessUser","members":["allAuthenticatedUsers"]},{"role":"roles/spanner.databaseRoleUser","members":["allAuthenticatedUsers"]}]}`)
		}
		return respond(`{"version":3,"bindings":[]}`)
	case "bigtableadmin.googleapis.com/v2/projects/demo/instances":
		return respond(`{"instances":[{"name":"projects/demo/instances/db","state":"READY","type":"PRODUCTION","displayName":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "bigtableadmin.googleapis.com/v2/projects/demo/instances/db/tables":
		return respond(`{"tables":[{"name":"projects/demo/instances/db/tables/data"}]}`)
	case "bigtableadmin.googleapis.com/v2/projects/demo/instances/db/tables/data":
		return respond(`{"name":"projects/demo/instances/db/tables/data","deletionProtection":false,"columnFamilies":{"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE":{"gcRule":{}}},"changeStreamConfig":{"retentionPeriod":"86400s"}}`)
	case "bigtableadmin.googleapis.com/v2/projects/demo/instances/db/tables/data/authorizedViews":
		return respond(`{"authorizedViews":[{"name":"projects/demo/instances/db/tables/data/authorizedViews/view","subsetView":{"rowPrefixes":[""],"familySubsets":{"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE":{"qualifierPrefixes":[""]}}}}]}`)
	case "bigtableadmin.googleapis.com/v2/projects/demo/instances/db:getIamPolicy", "bigtableadmin.googleapis.com/v2/projects/demo/instances/db/tables/data:getIamPolicy", "bigtableadmin.googleapis.com/v2/projects/demo/instances/db/tables/data/authorizedViews/view:getIamPolicy":
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"options":{"requestedPolicyVersion":3}}` {
			f.t.Fatal("invalid Bigtable IAM read body")
		}
		return respond(`{"version":3,"bindings":[]}`)
	case "file.googleapis.com/v1/projects/demo/locations/-/instances":
		return respond(`{"instances":[{"name":"projects/demo/locations/us-central1-a/instances/share","state":"READY","tier":"BASIC_HDD","protocol":"NFS_V3","networks":[{"network":"projects/demo/global/networks/default","modes":["MODE_IPV4"],"connectMode":"DIRECT_PEERING"}],"fileShares":[{"name":"data","nfsExportOptions":[{"ipRanges":["0.0.0.0/0"],"accessMode":"READ_WRITE","squashMode":"NO_ROOT_SQUASH"}]}],"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","labels":{"secret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"directoryServices":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "alloydb.googleapis.com/v1/projects/demo/locations/-/clusters":
		return respond(`{"clusters":[{"name":"projects/demo/locations/us-central1/clusters/db","state":"READY","clusterType":"PRIMARY","initialUser":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "alloydb.googleapis.com/v1/projects/demo/locations/-/clusters/-/instances":
		return respond(`{"instances":[{"name":"projects/demo/locations/us-central1/clusters/db/instances/primary","state":"READY","instanceType":"PRIMARY","dataApiAccess":"ENABLED","publicIpAddress":"192.0.2.10","networkConfig":{"enablePublicIp":true,"authorizedExternalNetworks":[{"cidrRange":"0.0.0.0/0"}]},"clientConnectionConfig":{"requireConnectors":false,"sslConfig":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED"}},"databaseFlags":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "alloydb.googleapis.com/v1/projects/demo/locations/us-central1/clusters/db/users":
		return respond(`{"users":[{"name":"projects/demo/locations/us-central1/clusters/db/users/admin","userType":"ALLOYDB_BUILT_IN","databaseRoles":["alloydbsuperuser"],"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "redis.googleapis.com/v1/projects/demo/locations/-/instances":
		return respond(`{"instances":[{"name":"projects/demo/locations/us-central1/instances/cache","state":"READY","authEnabled":false,"transitEncryptionMode":"DISABLED","authorizedNetwork":"projects/demo/global/networks/default","authString":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","labels":{"secret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "redis.googleapis.com/v1/projects/demo/locations/-/clusters":
		return respond(`{"clusters":[{"name":"projects/demo/locations/us-central1/clusters/cache","state":"ACTIVE","authorizationMode":"AUTH_MODE_DISABLED","transitEncryptionMode":"TRANSIT_ENCRYPTION_MODE_DISABLED","pscConfigs":[{"network":"projects/demo/global/networks/default"}],"tokenAuthUsers":[{"token":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}]}`)
	case "memcache.googleapis.com/v1/projects/demo/locations/-/instances":
		return respond(`{"instances":[{"name":"projects/demo/locations/us-central1/instances/cache","state":"READY","nodeCount":2,"memcacheVersion":"MEMCACHE_1_5","authorizedNetwork":"projects/demo/global/networks/default","parameters":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "dns.googleapis.com/dns/v1/projects/demo/managedZones/zone/rrsets", "dns.googleapis.com/dns/v1/projects/demo/managedZones/private/rrsets":
		name := "_credential.example.test."
		if strings.Contains(r.URL.Path, "/private/") {
			name = "_credential.internal.test."
		}
		if !strings.Contains(r.URL.Path, "/private/") {
			return respond(`{"rrsets":[{"name":"` + name + `","type":"TXT","ttl":60,"rrdatas":["password=VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"]},{"name":"gateway.example.test.","type":"CNAME","ttl":60,"rrdatas":["example.gateway.dev."]}]}`)
		}
		return respond(`{"rrsets":[{"name":"` + name + `","type":"TXT","ttl":60,"rrdatas":["password=VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"]}]}`)
	case "dns.googleapis.com/dns/v1/projects/demo/responsePolicies/responses/rules":
		return respond(`{"responsePolicyRules":[{"ruleName":"exception","dnsName":"specific.example.test.","behavior":"bypassResponsePolicy"},{"ruleName":"answer","dnsName":"*.example.test.","localData":{"localDatas":[{"name":"*.example.test.","type":"TXT","ttl":60,"rrdatas":["password=VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"]}]}}]}`)
	case "dns.googleapis.com/dns/v1/projects/demo/policies":
		return respond(`{"policies":[{"id":"11","name":"hybrid","enableLogging":false,"enableInboundForwarding":true,"networks":[{"networkUrl":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"}],"alternativeNameServerConfig":{"targetNameServers":[{"ipv4Address":"192.0.2.53","forwardingPath":"private"}]},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "dns.googleapis.com/dns/v1/projects/demo/responsePolicies":
		return respond(`{"responsePolicies":[{"id":"12","responsePolicyName":"responses","networks":[{"networkUrl":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"}],"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "serviceusage.googleapis.com/v1/projects/123/services":
		if r.URL.Query().Get("filter") != "state:ENABLED" {
			f.t.Fatal("unfiltered enabled API discovery")
		}
		return respond(`{"services":[{"name":"projects/123/services/appengine.googleapis.com","parent":"projects/123","state":"ENABLED","config":{"name":"appengine.googleapis.com","title":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "appengine.googleapis.com/v1/apps/demo":
		return respond(`{"name":"apps/demo","servingStatus":"SERVING","iap":{"enabled":false,"oauth2ClientSecret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "appengine.googleapis.com/v1/apps/demo/services":
		return respond(`{"services":[{"name":"apps/demo/services/default","networkSettings":{"ingressTrafficAllowed":"INGRESS_TRAFFIC_ALLOWED_ALL"},"split":{"shardBy":"COOKIE","allocations":{"current":1}}}]}`)
	case "appengine.googleapis.com/v1/apps/demo/firewall/ingressRules":
		return respond(`{"ingressRules":[{"priority":100,"action":"DENY","sourceRange":"192.0.2.0/24","description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},{"priority":2147483647,"action":"ALLOW","sourceRange":"*"}]}`)
	case "appengine.googleapis.com/v1/apps/demo/services/default/versions":
		return respond(`{"versions":[{"name":"apps/demo/services/default/versions/v1","runtime":"python313"}]}`)
	case "appengine.googleapis.com/v1/apps/demo/services/default/versions/v1":
		if r.URL.Query().Get("view") != "FULL" {
			f.t.Fatal("missing FULL environment inspection")
		}
		return respond(`{"name":"apps/demo/services/default/versions/v1","servingStatus":"SERVING","serviceAccount":"worker@demo.iam.gserviceaccount.com","envVariables":{"PASSWORD":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"buildEnvVariables":{"TOKEN":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"deployment":{"zip":{"sourceUrl":"https://example.test/VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}}`)
	case "logging.googleapis.com/v2/projects/123/metrics":
		return respond(`{"metrics":[{"name":"error_count","resourceName":"projects/123/metrics/error_count","disabled":true,"filter":"PRIVATE_METRIC_FILTER","description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "logging.googleapis.com/v2/projects/123/locations/global/buckets/short/links":
		return respond(`{"links":[{"name":"projects/123/locations/global/buckets/short/links/linked","lifecycleState":"ACTIVE","bigqueryDataset":{"datasetId":"bigquery.googleapis.com/projects/demo/datasets/linked"},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "logging.googleapis.com/v2/projects/123/locations/-/buckets":
		return respond(`{"buckets":[{"name":"projects/123/locations/global/buckets/short","retentionDays":1,"locked":true,"lifecycleState":"ACTIVE","restrictedFields":["jsonPayload.secret"],"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "logging.googleapis.com/v2/projects/123/locations/global/buckets/short/views":
		return respond(`{"views":[{"name":"projects/123/locations/global/buckets/short/views/_AllLogs","filter":"PRIVATE_VIEW_FILTER","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "logging.googleapis.com/v2/projects/123/locations/global/buckets/short/views/_AllLogs:getIamPolicy":
		return respond(`{"version":3,"bindings":[{"role":"roles/logging.viewAccessor","members":["allAuthenticatedUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`)
	case "cloudasset.googleapis.com/v1/projects/123:searchAllIamPolicies":
		return respond(`{"results":[{"resource":"//pubsub.googleapis.com/projects/demo/topics/topic","assetType":"pubsub.googleapis.com/Topic","project":"projects/123","policy":{"bindings":[{"role":"roles/pubsub.publisher","members":["allUsers"]}]}},{"resource":"//artifactregistry.googleapis.com/projects/demo/locations/us-central1/repositories/custom","assetType":"artifactregistry.googleapis.com/Repository","project":"projects/123","policy":{"bindings":[{"role":"roles/artifactregistry.reader","members":["allUsers"]}]}},{"resource":"//storage.googleapis.com/public-bucket","assetType":"storage.googleapis.com/Bucket","project":"projects/123","policy":{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}},{"resource":"//bigquery.googleapis.com/projects/demo/datasets/dataset","assetType":"bigquery.googleapis.com/Dataset","project":"projects/123","policy":{"bindings":[{"role":"roles/bigquery.dataViewer","members":["allAuthenticatedUsers"]}]}}]}`)
	case "cloudresourcemanager.googleapis.com/v3/projects/demo":
		return respond(`{"name":"projects/123","projectId":"demo"}`)
	case "cloudresourcemanager.googleapis.com/v3/projects/123:getIamPolicy":
		return respond(`{"version":3,"auditConfigs":[{"service":"secretmanager.googleapis.com","auditLogConfigs":[{"logType":"ADMIN_READ","exemptedMembers":["user:auditor@example.test"]}]}],"bindings":[{"role":"roles/iap.httpsResourceAccessor","members":["allAuthenticatedUsers"]},{"role":"roles/cloudscheduler.jobRunner","members":["allAuthenticatedUsers"]},{"role":"roles/cloudsql.admin","members":["principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/uid1"],"condition":{"expression":"resource.name.startsWith('projects/demo')"}},{"role":"roles/iam.serviceAccountKeyAdmin","members":["serviceAccount:worker@demo.iam.gserviceaccount.com"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`)
	case "cloudasset.googleapis.com/v1/projects/123:searchAllResources":
		return respond(`{"results":[{"name":"//composer.googleapis.com/projects/demo/locations/us-central1/environments/composer","assetType":"composer.googleapis.com/Environment","project":"projects/123","location":"us-central1"}]}`)
	case "composer.googleapis.com/v1/projects/demo/locations/us-central1/environments/composer":
		return respond(`{"name":"projects/demo/locations/us-central1/environments/composer","state":"RUNNING","config":{"nodeConfig":{"serviceAccount":"worker@demo.iam.gserviceaccount.com"},"softwareConfig":{"envVariables":{"AUTH":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}},"privateEnvironmentConfig":{"networkingType":"PUBLIC"},"webServerNetworkAccessControl":{"allowedIpRanges":[{"value":"0.0.0.0/0"}]}},"unrequestedCredential":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}`)
	case "compute.googleapis.com/compute/v1/projects/demo":
		return respond(`{"name":"demo"}`)
	case "servicemanagement.googleapis.com/v1/services":
		if r.URL.Query().Get("producerProjectId") != "demo" {
			f.t.Fatal("unscoped service discovery")
		}
		return respond(`{"services":[{"serviceName":"api.example.test"}]}`)
	case "servicemanagement.googleapis.com/v1/services/api.example.test":
		return respond(`{"serviceName":"api.example.test","producerProjectId":"demo"}`)
	case "servicemanagement.googleapis.com/v1/services/api.example.test/configs":
		return respond(`{"serviceConfigs":[{"name":"api.example.test","id":"config"}]}`)
	case "servicemanagement.googleapis.com/v1/services/api.example.test/rollouts":
		if r.URL.Query().Get("filter") != "strategy=TrafficPercentStrategy" {
			f.t.Fatal("unreviewed rollout filter")
		}
		return respond(`{"rollouts":[{"rolloutId":"rollout","serviceName":"api.example.test","createTime":"2026-01-01T00:00:00Z","status":"SUCCESS","trafficPercentStrategy":{"percentages":{"config":100}},"createdBy":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "servicemanagement.googleapis.com/v1/services/api.example.test/configs/config":
		if r.URL.Query().Get("view") != "BASIC" {
			f.t.Fatal("unreviewed service config view")
		}
		return respond(`{"name":"api.example.test","id":"config","producerProjectId":"demo","apis":[{"name":"example.API","methods":[{"name":"Read"}]}],"authentication":{"rules":[{"selector":"*"}]},"usage":{"rules":[{"selector":"*","allowUnregisteredCalls":true}]},"backend":{"rules":[{"selector":"*","address":"https://user:VIEWER_PIPELINE_SECRET_DO_NOT_SAVE@example.test","disableAuth":true}]},"sourceInfo":{"sourceFiles":[{"contents":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}}`)
	case "apigateway.googleapis.com/v1/projects/demo/locations/global/apis":
		return respond(`{"apis":[{"name":"projects/demo/locations/global/apis/api","state":"ACTIVE","managedService":"api.example.test"}]}`)
	case "apigateway.googleapis.com/v1/projects/demo/locations/global/apis/api/configs":
		return respond(`{"apiConfigs":[{"name":"projects/demo/locations/global/apis/api/configs/config","state":"ACTIVE"},{"name":"projects/demo/locations/global/apis/api/configs/mcp","state":"ACTIVE"}]}`)
	case "apigateway.googleapis.com/v1/projects/demo/locations/global/apis/api/configs/mcp":
		if r.URL.Query().Get("view") != "FULL" {
			f.t.Fatal("missing FULL MCP config view")
		}
		source := `{"openapi":"3.0.3","info":{"title":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","version":"1"},"x-google-api-management":{"mcp":true,"backends":{"default":{"address":"https://example.test","disableAuth":true}}},"x-google-backend":"default","paths":{"/mcp-open":{"get":{"operationId":"readItem","summary":"Read item","security":[],"responses":{"200":{"description":"ok"}}}}}}`
		return respond(`{"name":"projects/demo/locations/global/apis/api/configs/mcp","state":"ACTIVE","openapiDocuments":[{"document":{"path":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","contents":"` + base64.StdEncoding.EncodeToString([]byte(source)) + `"}}]}`)
	case "apigateway.googleapis.com/v1/projects/demo/locations/global/apis/api/configs/config":
		if r.URL.Query().Get("view") != "FULL" {
			f.t.Fatal("missing FULL config view")
		}
		source := `{"swagger":"2.0","info":{"title":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","version":"1"},"paths":{"/open":{"get":{"security":[],"responses":{"200":{"description":"password: VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}}}}}`
		return respond(`{"name":"projects/demo/locations/global/apis/api/configs/config","state":"ACTIVE","serviceConfigId":"config","gatewayServiceAccount":"projects/demo/accounts/12345","openapiDocuments":[{"document":{"path":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","contents":"` + base64.StdEncoding.EncodeToString([]byte(source)) + `"}}]}`)
	case "apigateway.googleapis.com/v1/projects/demo/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`)
	case "apigateway.googleapis.com/v1/projects/demo/locations/us-central1/gateways":
		return respond(`{"gateways":[{"name":"projects/demo/locations/us-central1/gateways/gateway","state":"ACTIVE","apiConfig":"projects/demo/locations/global/apis/api/configs/config","defaultHostname":"example.gateway.dev"},{"name":"projects/demo/locations/us-central1/gateways/mcp","state":"ACTIVE","apiConfig":"projects/123/locations/global/apis/api/configs/mcp","defaultHostname":"mcp.gateway.dev"}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/firewalls":
		return respond(`{"items":[{"name":"world-web","network":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default","direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"sourceTags":["trusted"],"targetTags":["web"],"allowed":[{"IPProtocol":"tcp","ports":["443"]}]},{"name":"deny-web","network":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default","direction":"INGRESS","priority":500,"sourceRanges":["0.0.0.0/0"],"targetTags":["web"],"denied":[{"IPProtocol":"tcp","ports":["443"]}]}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/routes":
		return respond(`{"items":[{"name":"internet","network":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default","destRange":"0.0.0.0/0","priority":1000,"nextHopGateway":"https://www.googleapis.com/compute/v1/projects/demo/global/gateways/default-internet-gateway","routeType":"STATIC","tags":["web"],"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/networks/default/getEffectiveFirewalls":
		return respond(`{"firewalls":[],"firewallPolicys":[{"type":"HIERARCHY","rules":[{"priority":10,"action":"deny","direction":"INGRESS","disabled":false,"match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["443"]}]}}]}],"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}`)
	case "compute.googleapis.com/compute/v1/projects/demo/regions/us-central1/firewallPolicies/getEffectiveFirewalls":
		if r.URL.Query().Get("network") != "projects/demo/global/networks/default" {
			f.t.Fatal("regional policy query escaped exact observed network", r.URL)
		}
		return respond(`{"firewalls":[],"firewallPolicys":[{"type":"HIERARCHY","rules":[{"priority":10,"action":"deny","direction":"INGRESS","disabled":false,"match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["443"]}]}}]},{"type":"NETWORK_REGIONAL","priority":50,"rules":[{"priority":20,"action":"allow","direction":"INGRESS","disabled":false,"match":{"srcIpRanges":["0.0.0.0/0"],"layer4Configs":[{"ipProtocol":"tcp","ports":["443"]}]}}]}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/aggregated/backendServices":
		return respond(`{"items":{"global":{"backendServices":[{"name":"global-web","protocol":"HTTPS","loadBalancingScheme":"EXTERNAL_MANAGED","iap":{"enabled":false,"oauth2ClientSecret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]},"regions/us-central1":{"backendServices":[{"name":"regional-web","protocol":"HTTP","loadBalancingScheme":"INTERNAL_MANAGED","iap":{"enabled":false,"oauth2ClientSecret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}}}`)
	case "storage.googleapis.com/storage/v1/b":
		return respond(`{"items":[{"name":"public-bucket","projectNumber":"123","iamConfiguration":{"publicAccessPrevention":"enforced","uniformBucketLevelAccess":{"enabled":true}}}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/aggregated/instances":
		return respond(`{"items":{"zones/us-central1-a":{"instances":[{"name":"esp","status":"RUNNING","zone":"https://www.googleapis.com/compute/v1/projects/demo/zones/us-central1-a","tags":{"items":["web"]},"networkInterfaces":[{"name":"nic0","network":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default","subnetwork":"https://www.googleapis.com/compute/v1/projects/demo/regions/us-central1/subnetworks/subnet","networkIP":"10.0.0.2","accessConfigs":[{"type":"ONE_TO_ONE_NAT","natIP":"192.0.2.10"}]}],"metadata":{"items":[{"key":"gce-container-declaration","value":"spec:\n  containers:\n  - image: gcr.io/endpoints-release/endpoints-runtime:2\n    args: [\"--service=api.example.test\", \"--version=config\", \"--rollout_strategy=fixed\"]\n"}]}}]}}}`)
	case "sqladmin.googleapis.com/v1/projects/demo/instances":
		return respond(`{"items":[{"name":"db","project":"demo","region":"us-central1","databaseVersion":"MYSQL_8_0","instanceType":"CLOUD_SQL_INSTANCE","settings":{"availabilityType":"ZONAL","backupConfiguration":{"backupTier":"STANDARD","binaryLogEnabled":false},"deletionProtectionEnabled":false,"passwordValidationPolicy":{"enablePasswordPolicy":false},"ipConfiguration":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED","authorizedNetworks":[{"value":"0.0.0.0/0"}]}},"ipAddresses":[{"type":"PRIMARY","ipAddress":"192.0.2.1"}]},{"name":"policy","project":"demo","databaseVersion":"MYSQL_8_0","settings":{"passwordValidationPolicy":{"enablePasswordPolicy":true,"reuseInterval":0,"disallowUsernameSubstring":false}}}]}`)
	case "sqladmin.googleapis.com/v1/projects/demo/instances/policy/users", "sqladmin.googleapis.com/v1/projects/demo/instances/policy/databases", "sqladmin.googleapis.com/v1/projects/demo/instances/policy/backupRuns":
		return respond(`{}`)
	case "sqladmin.googleapis.com/v1/projects/demo/instances/db/users":
		return respond(`{"items":[{"name":"reader","host":"%","type":"BUILT_IN","project":"demo","instance":"db","password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "sqladmin.googleapis.com/v1/projects/demo/instances/db/databases":
		return respond(`{"items":[{"name":"application","project":"demo","instance":"db","charset":"utf8mb4","collation":"utf8mb4_0900_ai_ci","password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "sqladmin.googleapis.com/v1/projects/demo/instances/db/backupRuns":
		return respond(`{"items":[{"id":"42","instance":"db"}]}`)
	case "sqladmin.googleapis.com/v1/projects/demo/instances/db/backupRuns/42":
		return respond(`{"id":"42","instance":"db","status":"SUCCESSFUL","type":"AUTOMATED","backupKind":"SNAPSHOT","error":{"message":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}`)
	case "container.googleapis.com/v1/projects/demo/locations/-/clusters":
		return respond(`{"clusters":[{"name":"cluster","location":"us-central1","loggingService":"none","monitoringService":"none","legacyAbac":{"enabled":true},"nodePools":[{"name":"pool","config":{"kubeletConfig":{"insecureKubeletReadonlyPortEnabled":true}}}]}]}`)
	case "run.googleapis.com/v1/projects/demo/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`)
	case "run.googleapis.com/v2/projects/demo/locations/us-central1/services":
		return respond(`{"services":[{"name":"projects/demo/locations/us-central1/services/app","invokerIamDisabled":true,"template":{"containers":[{"env":[{"name":"PASSWORD","value":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},{"name":"ordinary","value":"ghp_` + strings.Repeat("A", 36) + `"}]}]}}]}`)
	case "run.googleapis.com/v2/projects/demo/locations/us-central1/services/app:getIamPolicy":
		return respond(`{"version":3,"bindings":[{"role":"roles/run.invoker","members":["allUsers"]}]}`)
	case "run.googleapis.com/v2/projects/demo/locations/us-central1/jobs", "cloudfunctions.googleapis.com/v1/projects/demo/locations/-/functions", "cloudfunctions.googleapis.com/v2/projects/demo/locations/-/functions":
		return respond(`{}`)
	case "dns.googleapis.com/dns/v1/projects/demo/managedZones":
		return respond(`{"managedZones":[{"name":"zone","id":"42","dnsName":"example.test.","visibility":"public","dnssecConfig":{"state":"off"},"cloudLoggingConfig":{"enableLogging":false},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},{"name":"private","id":"43","dnsName":"internal.test.","visibility":"private","privateVisibilityConfig":{"networks":[{"networkUrl":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default"}]},"forwardingConfig":{"targetNameServers":[{"ipv6Address":"2001:db8::53","forwardingPath":"private"}]},"labels":{"secret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "iam.googleapis.com/v1/projects/demo/serviceAccounts":
		return respond(`{"accounts":[{"name":"projects/demo/serviceAccounts/12345","projectId":"demo","uniqueId":"12345","email":"worker@demo.iam.gserviceaccount.com"}]}`)
	case "iam.googleapis.com/v1/projects/demo/serviceAccounts/12345/keys", "iam.googleapis.com/v1/projects/-/serviceAccounts/worker@demo.iam.gserviceaccount.com/keys", "iam.googleapis.com/v1/projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com/keys":
		return respond(`{"keys":[{"name":"projects/demo/serviceAccounts/12345/keys/abcdef","keyType":"USER_MANAGED","validAfterTime":"2020-01-01T00:00:00Z"}]}`)
	case "apikeys.googleapis.com/v2/projects/123/locations/global/keys":
		return respond(`{"keys":[{"name":"projects/123/locations/global/keys/api-key","restrictions":{}},{"name":"projects/123/locations/global/keys/world-server","restrictions":{"serverKeyRestrictions":{"allowedIps":["0.0.0.0/0","::/0"]}}}]}`)
	case "secretmanager.googleapis.com/v1/projects/123/secrets":
		return respond(`{"secrets":[{"name":"projects/123/secrets/db","rotation":{"nextRotationTime":"2020-01-01T00:00:00Z"}}]}`)
	case "secretmanager.googleapis.com/v1/projects/123/secrets/db/versions":
		return respond(`{"versions":[{"name":"projects/123/secrets/db/versions/1","state":"DISABLED","scheduledDestroyTime":"2030-01-01T00:00:00Z"}]}`)
	case "secretmanager.googleapis.com/v1/projects/123/secrets/db":
		return respond(`{"name":"projects/123/secrets/db","versionAliases":{"current":"1"}}`)
	case "secretmanager.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets/regional":
		return respond(`{"name":"projects/123/locations/us-central1/secrets/regional","versionAliases":{"current":"1"}}`)
	case "secretmanager.googleapis.com/v1/projects/123/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/global","locationId":"global"},{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`)
	case "parametermanager.googleapis.com/v1/projects/123/locations", "parametermanager.googleapis.com/v1/projects/123/locations/global/parameters":
		return respond(`{}`)
	case "secretmanager.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets":
		return respond(`{"secrets":[{"name":"projects/123/locations/us-central1/secrets/regional","secretType":"CLOUD_SQL_DB_CREDENTIALS","policyMember":{"iamPolicyUidPrincipal":"principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/uid1"},"expireTime":"2099-01-01T00:00:00Z","versionDestroyTtl":"86400s","annotations":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "secretmanager.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets/regional/versions":
		return respond(`{"versions":[{"name":"projects/123/locations/us-central1/secrets/regional/versions/1","state":"DISABLED","scheduledDestroyTime":"2099-01-01T00:00:00Z"}]}`)
	case "secretmanager.googleapis.com/v1/projects/123/secrets/db:getIamPolicy", "secretmanager.us-central1.rep.googleapis.com/v1/projects/123/locations/us-central1/secrets/regional:getIamPolicy":
		if r.URL.Query().Get("options.requestedPolicyVersion") != "3" {
			f.t.Fatal("missing secret policy version 3")
		}
		return respond(`{"version":3,"bindings":[{"role":"roles/secretmanager.secretAccessor","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`)
	case "cloudkms.googleapis.com/v1/projects/demo/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/global","locationId":"global"}]}`)
	case "cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings":
		return respond(`{"keyRings":[{"name":"projects/demo/locations/global/keyRings/ring"}]}`)
	case "cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring:getIamPolicy":
		if r.URL.Query().Get("options.requestedPolicyVersion") != "3" {
			f.t.Fatal("missing v3 policy request")
		}
		return respond(`{"version":3,"bindings":[]}`)
	case "cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key:getIamPolicy":
		if r.URL.Query().Get("options.requestedPolicyVersion") != "3" {
			f.t.Fatal("missing v3 policy request")
		}
		return respond(`{"version":3,"bindings":[{"role":"roles/cloudkms.cryptoKeyDecrypter","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`)
	case "cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys":
		return respond(`{"cryptoKeys":[{"name":"projects/demo/locations/global/keyRings/ring/cryptoKeys/key","purpose":"ENCRYPT_DECRYPT","createTime":"2020-01-01T00:00:00Z","versionTemplate":{"protectionLevel":"SOFTWARE"}}]}`)
	case "cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions":
		return respond(`{"cryptoKeyVersions":[{"name":"projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1","state":"DESTROY_SCHEDULED","destroyTime":"2030-01-01T00:00:00Z"}]}`)
	case "cloudbuild.googleapis.com/v2/projects/demo/locations":
		return respond(`{}`)
	case "cloudbuild.googleapis.com/v1/projects/demo/locations/global/builds":
		return respond(`{"builds":[{"id":"build-one","projectId":"demo","steps":[{"name":"alpine","env":["DATABASE_URL=VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"]}]}]}`)
	case "cloudbuild.googleapis.com/v1/projects/demo/locations/global/triggers":
		return respond(`{"triggers":[{"id":"trigger-one","serviceAccount":"projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com","substitutions":{"_PASSWORD":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"disabled":false,"github":{"owner":"example","name":"public-build","pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"approvalConfig":{"approvalRequired":false}},{"id":"trigger-two","serviceAccount":"projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com","disabled":false,"repositoryEventConfig":{"repository":"projects/demo/locations/global/connections/source/repositories/build","pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"approvalConfig":{"approvalRequired":false}},{"id":"trigger-mirror","serviceAccount":"projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com","disabled":false,"triggerTemplate":{"repoName":"nested/repo","branchName":".*"},"approvalConfig":{"approvalRequired":false}}]}`)
	case "cloudbuild.googleapis.com/v2/projects/demo/locations/global/connections/source/repositories/build":
		return respond(`{"name":"projects/demo/locations/global/connections/source/repositories/build","remoteUri":"https://github.com/example/public-build.git","readToken":{"secretVersion":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "workflows.googleapis.com/v1/projects/demo/locations", "artifactregistry.googleapis.com/v1/projects/demo/locations", "cloudscheduler.googleapis.com/v1/projects/demo/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/us-central1","locationId":"us-central1"}]}`)
	case "workflows.googleapis.com/v1/projects/demo/locations/us-central1/workflows":
		return respond(`{"workflows":[{"name":"projects/demo/locations/us-central1/workflows/flow"}]}`)
	case "workflows.googleapis.com/v1/projects/demo/locations/us-central1/workflows/flow":
		return respond(`{"name":"projects/demo/locations/us-central1/workflows/flow","sourceContents":"password=VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}`)
	case "artifactregistry.googleapis.com/v1/projects/demo/locations/us-central1/repositories":
		return respond(`{"repositories":[{"name":"projects/demo/locations/us-central1/repositories/custom","mode":"REMOTE_REPOSITORY","remoteRepositoryConfig":{"dockerRepository":{"customRepository":{"uri":"https://registry.example.test"}}}}]}`)
	case "artifactregistry.googleapis.com/v1/projects/demo/locations/us-central1/repositories/custom:getIamPolicy":
		return respond(`{"version":3,"bindings":[{"role":"roles/artifactregistry.reader","members":["allUsers","serviceAccount:worker@other-project.iam.gserviceaccount.com"]}]}`)
	case "cloudscheduler.googleapis.com/v1/projects/demo/locations/us-central1/jobs":
		return respond(`{"jobs":[{"name":"projects/demo/locations/us-central1/jobs/job","httpTarget":{"uri":"https://example.test/handler","oidcToken":{"serviceAccountEmail":"worker@demo.iam.gserviceaccount.com"}}}]}`)
	case "pubsub.googleapis.com/v1/projects/demo/schemas":
		if r.URL.Query().Get("view") != "BASIC" {
			f.t.Fatal("schema view", r.URL)
		}
		return respond(`{"schemas":[{"name":"projects/demo/schemas/schema","type":"AVRO","definition":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "pubsub.googleapis.com/v1/projects/demo/schemas/schema:listRevisions":
		if r.URL.Query().Get("view") != "BASIC" {
			f.t.Fatal("revision view", r.URL)
		}
		return respond(`{"schemas":[{"name":"projects/demo/schemas/schema","revisionId":"abc123","type":"AVRO","definition":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "pubsub.googleapis.com/v1/projects/demo/snapshots":
		return respond(`{"snapshots":[{"name":"projects/demo/snapshots/snapshot","topic":"projects/demo/topics/topic","expireTime":"2026-10-07T00:00:00Z","labels":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "pubsub.googleapis.com/v1/projects/demo/topics":
		return respond(`{"topics":[{"name":"projects/demo/topics/topic","labels":{"password":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "pubsub.googleapis.com/v1/projects/demo/subscriptions":
		return respond(`{"subscriptions":[{"name":"projects/demo/subscriptions/sub","detached":true,"topic":"_deleted-topic_","pushConfig":{"pushEndpoint":"https://example.test/push","oidcToken":{"serviceAccountEmail":"worker@demo.iam.gserviceaccount.com"}}},{"name":"projects/demo/subscriptions/export","topic":"projects/demo/topics/topic","state":"ACTIVE","detached":false,"cloudStorageConfig":{"bucket":"export-bucket","serviceAccountEmail":"writer@source-project.iam.gserviceaccount.com","filenamePrefix":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"messageTransforms":[{"javascriptUdf":{"code":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}]}`)
	case "bigquery.googleapis.com/bigquery/v2/projects/demo/datasets":
		return respond(`{"datasets":[{"datasetReference":{"projectId":"demo","datasetId":"dataset"}}]}`)
	case "bigquery.googleapis.com/bigquery/v2/projects/demo/datasets/dataset":
		return respond(`{"datasetReference":{"projectId":"demo","datasetId":"dataset"},"access":[{"iamMember":"allUsers","role":"READER","condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`)
	case "identitytoolkit.googleapis.com/admin/v2/projects/123/config":
		return respond(`{"name":"projects/123/config","signIn":{"anonymous":{"enabled":true},"email":{"enabled":true,"passwordRequired":true}},"client":{"permissions":{"disabledUserSignup":false}},"blockingFunctions":{"triggers":{"beforeCreate":{"functionUri":"https://private.example.test/VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}},"forwardInboundCredentials":{"refreshToken":true}},"hashConfig":{"signerKey":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "firebaseappcheck.googleapis.com/v1/projects/123/services":
		return respond(`{"services":[{"name":"projects/123/services/firestore.googleapis.com","enforcementMode":"UNENFORCED","replayProtection":"OFF","unexpected":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},{"name":"projects/123/services/oauth2.googleapis.com","enforcementMode":"ENFORCED"}]}`)
	case "firebaseappcheck.googleapis.com/v1/projects/123/services/oauth2.googleapis.com/resourcePolicies":
		return respond(`{"resourcePolicies":[{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/policy-one","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/client-one","enforcementMode":"OFF","description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "identitytoolkit.googleapis.com/v2/projects/123/tenants":
		return respond(`{"tenants":[{"name":"projects/123/tenants/tenant"}]}`)
	case "identitytoolkit.googleapis.com/v2/projects/123/tenants/tenant":
		return respond(`{"name":"projects/123/tenants/tenant","enableAnonymousUser":true,"mfaConfig":{"state":"DISABLED"},"hashConfig":{"signerKey":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "identitytoolkit.googleapis.com/v2/projects/123/oauthIdpConfigs":
		return respond(`{"oauthIdpConfigs":[{"name":"projects/123/oauthIdpConfigs/oidc.example","enabled":true,"responseType":{"idToken":true,"code":false},"clientSecret":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","issuer":"https://VIEWER_PIPELINE_SECRET_DO_NOT_SAVE.example.test"}]}`)
	case "identitytoolkit.googleapis.com/v2/projects/123/inboundSamlConfigs", "identitytoolkit.googleapis.com/v2/projects/123/tenants/tenant/oauthIdpConfigs", "identitytoolkit.googleapis.com/v2/projects/123/tenants/tenant/inboundSamlConfigs":
		return respond(`{}`)
	case "cloudtasks.googleapis.com/v2/projects/demo/locations", "aiplatform.googleapis.com/v1/projects/demo/locations":
		return respond(`{"locations":[{"name":"projects/demo/locations/us-central1"}]}`)
	case "cloudtasks.googleapis.com/v2/projects/demo/locations/us-central1/queues":
		return respond(`{"queues":[{"name":"projects/demo/locations/us-central1/queues/queue","stackdriverLoggingConfig":{"samplingRatio":0}}]}`)
	case "cloudtasks.googleapis.com/v2/projects/123/locations/us-central1/queues/queue/tasks":
		if r.URL.Query().Get("responseView") != "BASIC" {
			f.t.Fatal("unexpected task view", r.URL)
		}
		return respond(`{"tasks":[{"name":"projects/123/locations/us-central1/queues/queue/tasks/task","httpRequest":{"url":"https://example.test/task","oidcToken":{"serviceAccountEmail":"worker@demo.iam.gserviceaccount.com"},"body":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE","headers":{"Authorization":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}}]}`)
	case "us-central1-aiplatform.googleapis.com/v1/projects/demo/locations/us-central1/customJobs":
		return respond(`{"customJobs":[{"name":"projects/123/locations/us-central1/customJobs/1"}]}`)
	case "us-central1-aiplatform.googleapis.com/v1/projects/demo/locations/us-central1/pipelineJobs":
		return respond(`{"pipelineJobs":[{"name":"projects/123/locations/us-central1/pipelineJobs/2"}]}`)
	case "us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/customJobs/1":
		return respond(`{"name":"projects/123/locations/us-central1/customJobs/1","jobSpec":{"workerPoolSpecs":[{"containerSpec":{"env":[{"name":"PASSWORD","value":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}}]},"webAccessUris":{"uri":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "us-central1-aiplatform.googleapis.com/v1/projects/123/locations/us-central1/pipelineJobs/2":
		return respond(`{"name":"projects/123/locations/us-central1/pipelineJobs/2","pipelineSpec":{},"jobDetail":{"value":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}`)
	case "compute.googleapis.com/compute/v1/projects/demo/aggregated/instanceTemplates":
		return respond(`{"items":{"global":{"instanceTemplates":[{"name":"template","properties":{"metadata":{"items":[{"key":"AUTH","value":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}}}]}}}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/networks":
		return respond(`{"items":[{"name":"default","autoCreateSubnetworks":false,"networkFirewallPolicyEnforcementOrder":"AFTER_CLASSIC_FIREWALL","peerings":[{"name":"peer","network":"https://www.googleapis.com/compute/v1/projects/other-project/global/networks/remote","state":"ACTIVE","exportCustomRoutes":true,"stateDetails":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}],"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/aggregated/subnetworks":
		return respond(`{"items":{"regions/us-central1":{"subnetworks":[{"name":"subnet","region":"https://www.googleapis.com/compute/v1/projects/demo/regions/us-central1","network":"https://www.googleapis.com/compute/v1/projects/demo/global/networks/default","privateIpGoogleAccess":true,"logConfig":{"enable":true,"filterExpr":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}}}`)
	case "compute.googleapis.com/compute/v1/projects/demo/regions/us-central1/subnetworks/subnet/getIamPolicy":
		if r.URL.Query().Get("optionsRequestedPolicyVersion") != "3" {
			f.t.Fatal("subnet IAM v3 missing")
		}
		return respond(`{"version":3,"bindings":[]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/images":
		return respond(`{"items":[{"name":"image","status":"READY","imageEncryptionKey":{"kmsKeyName":"projects/demo/locations/global/keyRings/ring/cryptoKeys/key","rawKey":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"rawDisk":{"source":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"},"description":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/snapshots":
		return respond(`{"items":[{"name":"snapshot","status":"READY","snapshotEncryptionKey":{"rawKey":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/regions":
		return respond(`{"items":[{"name":"us-central1"}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/regions/us-central1/snapshots":
		return respond(`{"items":[{"name":"regional","status":"READY","snapshotType":"STANDARD"}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/images/image/getIamPolicy":
		if r.URL.Query().Get("optionsRequestedPolicyVersion") != "3" {
			f.t.Fatal("missing Compute IAM v3")
		}
		return respond(`{"version":3,"bindings":[{"role":"roles/compute.imageUser","members":["allUsers"],"condition":{"expression":"request.time < timestamp('2030-01-01T00:00:00Z')"}}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/snapshots/snapshot/getIamPolicy", "compute.googleapis.com/compute/v1/projects/demo/regions/us-central1/snapshots/regional/getIamPolicy":
		if r.URL.Query().Get("optionsRequestedPolicyVersion") != "3" {
			f.t.Fatal("missing Compute IAM v3")
		}
		return respond(`{"version":3,"bindings":[{"role":"projects/demo/roles/snapshotSource","members":["allAuthenticatedUsers"]}]}`)
	case "compute.googleapis.com/compute/v1/projects/demo/global/machineImages":
		return respond(`{"items":[{"name":"machine","instanceProperties":{"metadata":{"items":[{"key":"ACCESS_KEY","value":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}]}}}]}`)
	case "iam.googleapis.com/v1/projects/123/locations/global/workloadIdentityPools":
		return respond(`{"workloadIdentityPools":[{"name":"projects/123/locations/global/workloadIdentityPools/pool","state":"ACTIVE"}]}`)
	case "iam.googleapis.com/v1/projects/123/locations/global/workloadIdentityPools/pool/providers":
		return respond(`{"workloadIdentityPoolProviders":[{"name":"projects/123/locations/global/workloadIdentityPools/pool/providers/provider","state":"ACTIVE","oidc":{"issuerUri":"https://issuer.example.test"},"attributeMapping":{"google.subject":"assertion.sub"}}]}`)
	case "dataflow.googleapis.com/v1b3/projects/demo/jobs:aggregated":
		return respond(`{"jobs":[{"id":"dataflowjob","projectId":"demo","location":"us-central1"}]}`)
	case "dataflow.googleapis.com/v1b3/projects/demo/locations/us-central1/jobs/dataflowjob":
		return respond(`{"id":"dataflowjob","projectId":"demo","location":"us-central1","environment":{"sdkPipelineOptions":{"AUTH":"VIEWER_PIPELINE_SECRET_DO_NOT_SAVE"}}}`)
	default:
		f.t.Fatalf("unexpected service endpoint: %s", r.URL)
		return nil, nil
	}
}

func TestViewerServiceCollectionToRedactedReport(t *testing.T) {
	t.Setenv("VIEWER_SERVICES_TEST_TOKEN", "VIEWER_PIPELINE_TOKEN_DO_NOT_SAVE")
	c := inventory.Client{TokenEnv: "VIEWER_SERVICES_TEST_TOKEN", HTTP: &http.Client{Transport: viewerServicesTransport{t}}}
	s := c.ViewerCloud(context.Background(), "projects/demo")
	// Supplied offline IAP policy evidence; no live IAP policy GET is authorized.
	iapPolicy := inventory.NewAsset("//iap.googleapis.com/projects/123/iap_web/compute/services/global-web", "iap.googleapis.com/PolicyResource", inventory.Object{})
	iapPolicy.IAM = inventory.Object{"bindings": []any{inventory.Object{"role": "roles/iap.httpsResourceAccessor", "members": []any{"allAuthenticatedUsers"}}}}
	s.Assets = append(s.Assets, iapPolicy)
	// Explicit supplied repository visibility, not a live GitHub lookup.
	s.Assets = append(s.Assets, inventory.NewAsset("//github.com/example/public-build", inventory.GitHubRepositoryMetadataType, inventory.Object{"owner": "example", "name": "public-build", "visibility": "public"}))
	credentialPolicy := inventory.NewAsset("//iam.googleapis.com/projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com", "iam.googleapis.com/ServiceAccount", inventory.Object{})
	credentialPolicy.IAM = inventory.Object{"bindings": []any{inventory.Object{"role": "roles/iam.serviceAccountTokenCreator", "members": []any{"allAuthenticatedUsers"}}}}
	s.Assets = append(s.Assets, credentialPolicy)
	// Explicitly exercise the opt-in logging bucket metadata path.
	c.CollectViewerLogBuckets(context.Background(), &s, []string{"projects/123"})
	c.CollectViewerLogViews(context.Background(), &s, []string{"projects/123"})
	c.CollectViewerLogLinks(context.Background(), &s, []string{"projects/123"})
	c.CollectViewerLogMetrics(context.Background(), &s, []string{"projects/123"})
	c.ResolveRoles(context.Background(), &s)
	domainPermissionGap := false
	for _, coverage := range s.Coverage {
		if coverage.Status == "failed" {
			t.Fatalf("unexpected collection failure: %+v", coverage)
		}
		if strings.HasPrefix(coverage.Source, "viewer-run-domain-mappings:") && coverage.Status == "incomplete" && strings.Contains(coverage.Error, "run.domainmappings.list") {
			domainPermissionGap = true
		}
	}
	if !domainPermissionGap {
		t.Fatal("unverified domain mapping permission must remain an explicit coverage gap")
	}
	s.Assets = mergeAssets(s.Assets)
	inventory.CorrelateDNSServiceTargets(&s)
	dnsServiceJoins := 0
	for _, a := range s.Assets {
		if inventory.Get(a.Resource.Data, "_gcpbusterObservedServiceTarget", "status") == "matched" {
			if inventory.Get(a.Resource.Data, "_gcpbusterObservedServiceTarget", "resource") != "//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/gateway" {
				t.Fatal("wrong exact DNS service join", a)
			}
			dnsServiceJoins++
		}
	}
	if dnsServiceJoins != 1 {
		t.Fatal("missing default metadata-only DNS service correlation", dnsServiceJoins)
	}
	for _, a := range s.Assets {
		if a.Type == "apigateway.googleapis.com/ApiConfig" {
			if len(inventory.List(a.Resource.Data["_gcpbusterGateways"])) != 1 {
				t.Fatal("missing explicit active gateway binding", a.Name)
			}
		}
	}
	networkMetadata := 0
	for _, a := range s.Assets {
		if a.Type == "compute.googleapis.com/Network" || a.Type == "compute.googleapis.com/Subnetwork" {
			networkMetadata++
			raw, _ := json.Marshal(a)
			if bytes.Contains(raw, []byte("VIEWER_PIPELINE_SECRET_DO_NOT_SAVE")) {
				t.Fatal("network metadata projection failed", a.Name)
			}
			if a.Type == "compute.googleapis.com/Subnetwork" && a.IAM == nil {
				t.Fatal("missing subnet IAM", a.Name)
			}
		}
	}
	if networkMetadata != 2 {
		t.Fatal("missing network/subnet metadata", networkMetadata)
	}
	computeDiskMetadata := 0
	for _, a := range s.Assets {
		if a.Type == "compute.googleapis.com/Image" || a.Type == "compute.googleapis.com/Snapshot" {
			computeDiskMetadata++
			raw, _ := json.Marshal(a)
			if bytes.Contains(raw, []byte("VIEWER_PIPELINE_SECRET_DO_NOT_SAVE")) || a.IAM == nil {
				t.Fatal("Compute metadata projection or direct IAM missing", a.Name)
			}
		}
	}
	if computeDiskMetadata != 3 {
		t.Fatal("missing global/regional Compute metadata", computeDiskMetadata)
	}
	pubsubMetadata := map[string]bool{}
	for _, a := range s.Assets {
		switch a.Type {
		case "pubsub.googleapis.com/Schema", inventory.PubSubSchemaRevisionType, "pubsub.googleapis.com/Snapshot":
			pubsubMetadata[a.Type] = true
			raw, _ := json.Marshal(a)
			if bytes.Contains(raw, []byte("VIEWER_PIPELINE_SECRET_DO_NOT_SAVE")) {
				t.Fatal("metadata projection failed", a.Type)
			}
		}
	}
	if len(pubsubMetadata) != 3 {
		t.Fatal("missing Pub/Sub metadata", pubsubMetadata)
	}
	userMetadataFound := false
	for _, a := range s.Assets {
		if a.Type == "sqladmin.googleapis.com/Instance" && inventory.Str(a.Resource.Data["name"]) == "db" {
			users := inventory.Obj(a.Resource.Data["_gcpbusterSQLUsers"])
			if inventory.Str(users["status"]) != "completed" {
				t.Fatal("missing completed SQL user metadata", users)
			}
			rows, ok := users["items"].([]any)
			if !ok || len(rows) != 1 || inventory.Str(inventory.Obj(rows[0])["name"]) != "reader" || inventory.Obj(rows[0])["password"] != nil {
				t.Fatal("SQL user projection failed", users)
			}
			userMetadataFound = true
			for _, field := range []string{"_gcpbusterSQLDatabases", "_gcpbusterSQLBackups"} {
				meta := inventory.Obj(a.Resource.Data[field])
				items, ok := meta["items"].([]any)
				if inventory.Str(meta["status"]) != "completed" || !ok || len(items) != 1 {
					t.Fatal("missing SQL child metadata", field, meta)
				}
				encoded, err := json.Marshal(meta)
				if err != nil || bytes.Contains(encoded, []byte("VIEWER_PIPELINE_SECRET_DO_NOT_SAVE")) {
					t.Fatal("SQL child metadata projection failed", field)
				}
			}
		}
	}
	if !userMetadataFound {
		t.Fatal("missing SQL user collection")
	}
	ids := []string{"service_config_auth", "service_config_secrets", "apigateway_mcp_discovery", "apigateway_route_auth", "apigateway_source_secrets", "firewall_ingress", "sql_hardening", "public_sql", "gke_security", "gke_telemetry", "public_serverless", "configuration_secrets", "dns_security", "service_account_keys", "api_key_restrictions", "secret_manager_lifecycle", "secret_manager_audit", "log_bucket_retention", "log_bucket_visibility", "logging_metrics", "log_bigquery_link", "kms_lifecycle", "automation_identity_delivery", "artifact_registry_upstreams", "public_bigquery", "identity_platform", "task_queue_logging", "vertex_ai_posture", "federation_trust", "public_iam", "public_artifact_access", "public_pubsub_capabilities", "public_compute_disk_capabilities", "pubsub_subscription_state", "pubsub_export_identity", "network_peering_routes", "composer_network", "workload_identity_grants"}
	ids = append(ids, "appengine_protection", "appengine_ingress", "appengine_firewall", "appengine_version_traffic")
	ids = append(ids, "dns_policy_forwarding", "dns_zone_resolution", "dns_query_logging")
	ids = append(ids, "dns_record_secrets", "dns_response_rules")
	ids = append(ids, "memorystore_authentication", "memorystore_transport")
	ids = append(ids, "alloydb_public_configuration", "alloydb_client_protection", "alloydb_data_api", "alloydb_user_roles")
	ids = append(ids, "filestore_root_trust", "filestore_export_sources")
	ids = append(ids, "bigtable_table_protection", "bigtable_authorized_view_scope")
	ids = append(ids, "spanner_database_protection", "spanner_change_stream_scope")
	ids = append(ids, "public_serverless_invocation")
	ids = append(ids, "public_healthcare_capabilities")
	ids = append(ids, "public_automation_capabilities", "public_secret_payload_capability", "cloud_build_pr_comment_control")
	ids = append(ids, "public_service_account_credentials")
	ids = append(ids, "spanner_public_role_read")
	ids = append(ids, "cloud_build_mirrored_source", "apigee_product_self_service")
	ids = append(ids, "public_compute")
	ids = append(ids, "apigee_authentication_policy")
	ids = append(ids, "public_storage_capabilities")
	ids = append(ids, "identity_platform_enrollment")
	ids = append(ids, "apigee_request_authentication")
	ids = append(ids, "firebase_app_check_enforcement")
	ids = append(ids, "firebase_app_check_resource_enforcement")
	ids = append(ids, "public_bigquery_capabilities", "identity_blocking_functions")
	ids = append(ids, "public_iap_capabilities", "iap_backend_protection")
	ids = append(ids, "identity_oidc_response_type", "artifact_cross_project_access")
	ids = append(ids, "model_armor_filter_configuration", "model_armor_exclusion_configuration")
	selected, err := checks.Select(ids, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.Open(filepath.Join(t.TempDir(), "engagement"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err = assess(context.Background(), cmd, e, s, selected, false)
	e.Close()
	if err == nil {
		t.Fatal("unmapped services must leave the overall report incomplete")
	}
	for _, file := range []string{"findings.json", "report.html", "engagement.db"} {
		b, err := os.ReadFile(filepath.Join(e.Dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("VIEWER_PIPELINE_SECRET_DO_NOT_SAVE")) || bytes.Contains(b, []byte("PRIVATE_METRIC_FILTER")) || bytes.Contains(b, []byte("PRIVATE_VIEW_FILTER")) || bytes.Contains(b, []byte("VIEWER_PIPELINE_TOKEN_DO_NOT_SAVE")) || bytes.Contains(b, []byte("ghp_"+strings.Repeat("A", 36))) {
			t.Fatal("sensitive value persisted", file)
		}
		if file == "findings.json" {
			var rows []struct {
				Module, Severity, Detail string
			}
			if err := json.Unmarshal(b, &rows); err != nil {
				t.Fatal(err)
			}
			storageControls, backendFindings, iapJoins, espPins, buildJoins, networkJoins, worldKeys := 0, 0, 0, 0, 0, 0, 0
			for _, row := range rows {
				var parsed inventory.Object
				if err := json.Unmarshal([]byte(row.Detail), &parsed); err != nil {
					t.Fatal(err)
				}
				if row.Module == "public_iap_capabilities" && inventory.Get(parsed, "evidence", "backend_configuration", "status") == "observed" {
					if inventory.Get(parsed, "evidence", "backend_configuration", "iap_enabled") != false {
						t.Fatal("explicit IAP backend configuration lost", parsed)
					}
					iapJoins++
				}
				if pins := inventory.List(inventory.Get(parsed, "evidence", "observed_esp_config_pins")); len(pins) > 0 {
					espPins++
				}
				if row.Module == "cloud_build_pr_comment_control" && inventory.Get(parsed, "evidence", "build_trust_context", "repository_visibility") == "public" && inventory.Get(parsed, "evidence", "build_trust_context", "identity_status") == "explicit_trigger_service_account" {
					if len(inventory.List(inventory.Get(parsed, "evidence", "build_trust_context", "high_impact_direct_grants"))) == 0 {
						t.Fatal("explicit build identity grant context lost", parsed)
					}
					buildJoins++
				}
				if row.Module == "public_compute" && len(inventory.List(inventory.Get(parsed, "evidence", "network_configuration", "matches"))) > 0 && len(inventory.List(inventory.Get(parsed, "evidence", "network_configuration", "internet_gateway_routes"))) > 0 {
					if inventory.Get(parsed, "evidence", "network_configuration", "effective_admission") != "unknown" {
						t.Fatal("configured network candidates became effective admission", parsed)
					}
					matches := inventory.List(inventory.Get(parsed, "evidence", "network_configuration", "matches"))
					if inventory.Get(inventory.Obj(matches[0]), "effective_policy_context", "status") != "observed" || inventory.Get(inventory.Obj(matches[0]), "effective_policy_context", "hierarchical_policy_count") != float64(1) {
						t.Fatal("scoped effective hierarchical policy metadata lost in report", parsed)
					}
					if inventory.Get(inventory.Obj(matches[0]), "effective_policy_context", "regional_policy_count") != float64(1) || inventory.Get(inventory.Obj(matches[0]), "effective_policy_context", "regional_policy_coverage") != "observed_response" {
						t.Fatal("exact NIC regional policy metadata missing", parsed)
					}
					contexts := inventory.List(inventory.Get(parsed, "evidence", "network_configuration", "effective_policy_contexts"))
					if len(contexts) != 1 || len(inventory.List(inventory.Get(inventory.Obj(contexts[0]), "context", "policy_rule_candidates"))) != 2 {
						t.Fatal("independent NIC policy-only world-source context lost", parsed)
					}
					if inventory.Get(inventory.Obj(matches[0]), "classic_deny_context", "status") != "definitely_shadowed_by_observed_classic_deny" {
						t.Fatal("scoped classic deny precedence lost in report", parsed)
					}
					networkJoins++
				}
				if row.Module == "public_compute" && networkJoins == 0 {
					t.Logf("missing expected network context: %#v", parsed)
				}
				if row.Module == "public_pubsub_capabilities" && inventory.Get(parsed, "evidence", "resource_type") == "pubsub.googleapis.com/Topic" {
					if inventory.Get(parsed, "evidence", "observed_subscription_context", "storage") != float64(1) {
						t.Fatal("exact topic/subscription configuration context missing", parsed)
					}
				}
				if row.Module == "api_key_restrictions" && len(inventory.List(inventory.Get(parsed, "evidence", "unrestricted_ip_families"))) == 2 {
					worldKeys++
				}
				if row.Module == "apigee_request_authentication" && inventory.Get(parsed, "evidence", "configured_base_path", "base_path") != "/v1/weather" {
					t.Fatal("configured Apigee path metadata missing", parsed)
				}
				if row.Module == "spanner_public_role_read" && (inventory.Get(parsed, "evidence", "public_table_select_grants") != float64(2) || inventory.Get(parsed, "evidence", "named_role_select_conjunction") != true) {
					t.Fatal("Spanner column/named-role conjunction missing", parsed)
				}
				if row.Module == "cloud_build_mirrored_source" && inventory.Get(parsed, "evidence", "build_trust_context", "repository_visibility") != "public" {
					t.Fatal("CSR mirror exact supplied visibility lost", parsed)
				}
				if row.Module == "public_storage_capabilities" {
					var detail inventory.Object
					if err := json.Unmarshal([]byte(row.Detail), &detail); err != nil || row.Severity != "info" || inventory.Get(detail, "evidence", "public_access_prevention") != "enforced" || inventory.Get(detail, "evidence", "bucket_control_evidence") != "observed" {
						t.Fatal("exact bucket PAP enforcement was not retained in report", row, err)
					}
					storageControls++
				}
				if row.Module == "iap_backend_protection" {
					backendFindings++
				}
			}
			if storageControls != 2 || backendFindings != 2 {
				t.Fatal("missing global/regional backend or exact Storage control correlation", storageControls, backendFindings)
			}
			if iapJoins == 0 || espPins == 0 {
				t.Fatal("missing exact offline IAP or explicit ESP metadata correlation in report", iapJoins, espPins)
			}
			if buildJoins != 2 || networkJoins == 0 {
				t.Fatal("missing supplied repository/explicit build identity or exact NIC/firewall/route report context", buildJoins, networkJoins)
			}
			if worldKeys != 1 {
				t.Fatal("world-wide API-key server range finding missing", worldKeys)
			}
			for _, title := range []string{"Compiled service method has no configured client credential requirement", "Potential plaintext secret in compiled service configuration", "API config enables MCP discovery without configured tools/list authentication", "API config defines an operation without required client authentication", "Potential plaintext secret in API Gateway configuration source", "Firewall configures world-source ingress allowance", "Cloud SQL deletion protection explicitly disabled", "Cloud SQL local-user password policy explicitly disabled", "Public IAM binding with a condition; effective access requires review", "Cloud SQL primary uses zonal availability", "Cloud SQL primary PITR setting explicitly disabled", "Cloud SQL MySQL password policy does not prohibit username substrings", "Cloud SQL MySQL password policy has zero password history", "Composer Airflow webserver admits an internet-wide network", "Composer environment explicitly uses public networking", "Workload identity has high-impact configured IAM capabilities", "Secret has scheduled automatic expiration", "Secret Manager ADMIN_READ audit policy exempts principals", "Logs-based metric is disabled", "Log bucket has an active BigQuery linked dataset", "Log bucket has locked one-day retention", "Log bucket configures field-level read restrictions", "Repository grants artifact-download capability to all users", "Pub/Sub resource grants publish capability to all users", "Compute image grants source-use capability to all users", "Compute snapshot grants source-use capability to any Google-authenticated identity", "VPC peering requests custom-route exchange", "Pub/Sub subscription is detached", "Pub/Sub subscription references a deleted topic", "Pub/Sub export explicitly selects a service account for Cloud Storage"} {
				if !bytes.Contains(b, []byte(title)) {
					t.Errorf("missing pipeline finding %s", title)
				}
			}
			for _, id := range ids {
				if !bytes.Contains(b, []byte(id)) {
					t.Errorf("missing collected finding %s", id)
				}
			}
			for _, resource := range []string{
				"//spanner.googleapis.com/projects/demo/instances/db/databases/data",
				"//bigtable.googleapis.com/projects/demo/instances/db/tables/data",
				"//bigtable.googleapis.com/projects/demo/instances/db/tables/data/authorizedViews/view",
				"//file.googleapis.com/projects/demo/locations/us-central1-a/instances/share",
				"//alloydb.googleapis.com/projects/demo/locations/us-central1/clusters/db/instances/primary",
				"AlloyDB user has the managed superuser group role",
				"//redis.googleapis.com/projects/demo/locations/us-central1/instances/cache",
				"//redis.googleapis.com/projects/demo/locations/us-central1/clusters/cache",
				"Potential plaintext credential in DNS configuration",
				"Cloud DNS response rule configures a policy bypass exception",
				"Cloud DNS response rule configures local answer overrides",
				"Cloud DNS policy enables inbound forwarding",
				"Cloud DNS policy configures alternative outbound resolvers",
				"Cloud DNS query logging is explicitly disabled",
				"Private Cloud DNS zone configures forwarding targets",
				"Serving App Engine version has no observed service traffic allocation",
				"App Engine firewall has broadly permissive source configuration",
				"unmatched_source_fallback",
				"all_sources_in_family",
				"//appengine.googleapis.com/apps/demo/services/default/versions/v1",
				"retained_history_not_current",
				"gatewayServiceAccount",
				"observed_gateway_pins",
				"//servicemanagement.googleapis.com/services/api.example.test/configs/config",
				"//apigateway.googleapis.com/projects/demo/locations/global/apis/api/configs/mcp",
				"//apigateway.googleapis.com/projects/demo/locations/us-central1/gateways/mcp",
				"//logging.googleapis.com/projects/123/metrics/error_count",
				"//logging.googleapis.com/projects/123/locations/global/buckets/short/links/linked",
				"//logging.googleapis.com/projects/123/locations/global/buckets/short/views/_AllLogs",
				"//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/regional",
				"//secretmanager.googleapis.com/projects/123/locations/us-central1/secrets/regional/versions/1",
				"//composer.googleapis.com/projects/demo/locations/us-central1/environments/composer",
				"config.nodeConfig.serviceAccount",
				"policyMember.iamPolicyUidPrincipal",
				"principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/uid1",
				"//cloudbuild.googleapis.com/projects/123/locations/global/builds/build-one",
				"//cloudbuild.googleapis.com/projects/123/locations/global/triggers/trigger-one",
				"//workflows.googleapis.com/projects/demo/locations/us-central1/workflows/flow",
				"//secretmanager.googleapis.com/projects/123/secrets/db/versions/1",
				"//cloudkms.googleapis.com/projects/demo/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
				"//cloudscheduler.googleapis.com/projects/demo/locations/us-central1/jobs/job",
				"//pubsub.googleapis.com/projects/demo/subscriptions/sub",
				"//bigquery.googleapis.com/projects/demo/datasets/dataset",
				"//identitytoolkit.googleapis.com/projects/123/tenants/tenant",
				"//cloudtasks.googleapis.com/projects/123/locations/us-central1/queues/queue/tasks/task",
				"//aiplatform.googleapis.com/projects/123/locations/us-central1/customJobs/1",
				"//aiplatform.googleapis.com/projects/123/locations/us-central1/pipelineJobs/2",
				"//compute.googleapis.com/projects/demo/global/instanceTemplates/template",
				"//compute.googleapis.com/projects/demo/global/machineImages/machine", "//compute.googleapis.com/projects/demo/global/images/image", "//compute.googleapis.com/projects/demo/global/networks/default", "//compute.googleapis.com/projects/demo/global/snapshots/snapshot", "//compute.googleapis.com/projects/demo/regions/us-central1/snapshots/regional",
				"//iam.googleapis.com/projects/demo/locations/global/workloadIdentityPools/pool/providers/provider",
				"//dataflow.googleapis.com/projects/demo/locations/us-central1/jobs/dataflowjob",
				"resource.data.template.containers[0].env[1].value",
			} {
				if !bytes.Contains(b, []byte(resource)) {
					t.Errorf("missing finding from collected resource %s", resource)
				}
			}
		}
	}
}
