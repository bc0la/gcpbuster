package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The baseline is deliberately immutable: neither credentials with extra roles
// nor an API being read-only widens the user's three-role authorization budget.
var viewerRoleNames = [...]string{"roles/viewer", "roles/resourcemanager.folderViewer", "roles/resourcemanager.organizationViewer"}

// Current role definitions can include service-qualified IAM identifiers such
// as iam.googleapis.com/workloadIdentityPools.list. Preserve exact strings;
// accepting the syntax does not alias them to another permission or API.
// Permission identifiers include ordinary dotted names and domain-qualified
// partner services, not just *.googleapis.com. Resource segments may contain
// underscores (for example networkservices.route_views.get). This is syntax
// validation only: names remain verbatim, without aliases or wildcard matching.
var viewerPermissionName = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){2,}|[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+/[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+)$`)

type viewerPolicyCache struct {
	mu          sync.Mutex
	permissions map[string]bool
}

type viewerEndpoint struct {
	host, method, path string
	permissions        []string
}

// Exact API methods, not a general GET allowlist. API-level authorization still
// applies at the requested resource. This does not assert the caller holds any
// role or bypass organization policy, OAuth scopes, VPC-SC or API enablement.
var viewerEndpoints = []viewerEndpoint{
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/aggregated/backendServices`, []string{"compute.backendServices.list"}},
	{"firebaseappcheck.googleapis.com", "GET", `/v1/projects/[0-9]+/services/oauth2\.googleapis\.com/resourcePolicies`, []string{"firebaseappcheck.resourcePolicies.get"}},
	{"firebaseappcheck.googleapis.com", "GET", `/v1/projects/[0-9]+/services`, []string{"firebaseappcheck.services.get"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/environments/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/flowhooks/(PreProxyFlowHook|PostProxyFlowHook|PreTargetFlowHook|PostTargetFlowHook)`, []string{"apigee.flowhooks.getSharedFlow"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/sharedflows/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/deployments`, []string{"apigee.deployments.list"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/sharedflows/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/revisions/[1-9][0-9]{0,18}`, []string{"apigee.sharedflowrevisions.get"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+`, []string{"apigee.organizations.get"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/deployments`, []string{"apigee.deployments.list"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/apiproducts`, []string{"apigee.apiproducts.list"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/envgroups`, []string{"apigee.envgroups.list"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/envgroups/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/attachments`, []string{"apigee.envgroupattachments.list"}},
	{"apigee.googleapis.com", "GET", `/v1/organizations/[A-Za-z0-9_-]+/apis/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/revisions/[1-9][0-9]{0,18}`, []string{"apigee.proxyrevisions.get"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations`, []string{"healthcare.locations.list"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets`, []string{"healthcare.datasets.list"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}/fhirStores`, []string{"healthcare.fhirStores.list"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}/dicomStores`, []string{"healthcare.dicomStores.list"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}/hl7V2Stores`, []string{"healthcare.hl7V2Stores.list"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}:getIamPolicy`, []string{"healthcare.datasets.getIamPolicy"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}/fhirStores/[\p{L}\p{N}_.-]{1,256}:getIamPolicy`, []string{"healthcare.fhirStores.getIamPolicy"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}/dicomStores/[\p{L}\p{N}_.-]{1,256}:getIamPolicy`, []string{"healthcare.dicomStores.getIamPolicy"}},
	{"healthcare.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/datasets/[\p{L}\p{N}_.-]{1,256}/hl7V2Stores/[\p{L}\p{N}_.-]{1,256}:getIamPolicy`, []string{"healthcare.hl7V2Stores.getIamPolicy"}},
	{"firestore.googleapis.com", "GET", `/v1/projects/[^/:]+/databases`, []string{"datastore.databases.list"}},
	{"firestore.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/backups`, []string{"datastore.backups.list"}},
	{"spanner.googleapis.com", "GET", `/v1/projects/[^/:]+/instances`, []string{"spanner.instances.list"}},
	{"spanner.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/databases`, []string{"spanner.databases.list"}},
	{"spanner.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/backups`, []string{"spanner.backups.list"}},
	{"spanner.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/databases/[A-Za-z_][A-Za-z0-9_-]*/ddl`, []string{"spanner.databases.getDdl"}},
	{"spanner.googleapis.com", "POST", `/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*:getIamPolicy`, []string{"spanner.instances.getIamPolicy"}},
	{"spanner.googleapis.com", "POST", `/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/databases/[A-Za-z_][A-Za-z0-9_-]*:getIamPolicy`, []string{"spanner.databases.getIamPolicy"}},
	{"spanner.googleapis.com", "POST", `/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/backups/[A-Za-z_][A-Za-z0-9_-]*:getIamPolicy`, []string{"spanner.backups.getIamPolicy"}},
	{"bigtableadmin.googleapis.com", "GET", `/v2/projects/[^/:]+/instances`, []string{"bigtable.instances.list"}},
	{"bigtableadmin.googleapis.com", "GET", `/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables`, []string{"bigtable.tables.list"}},
	{"bigtableadmin.googleapis.com", "GET", `/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables/[A-Za-z0-9_.-]+`, []string{"bigtable.tables.get"}},
	{"bigtableadmin.googleapis.com", "GET", `/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables/[A-Za-z0-9_.-]+/authorizedViews`, []string{"bigtable.authorizedViews.list"}},
	{"bigtableadmin.googleapis.com", "POST", `/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*:getIamPolicy`, []string{"bigtable.instances.getIamPolicy"}},
	{"bigtableadmin.googleapis.com", "POST", `/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables/[A-Za-z0-9_.-]+:getIamPolicy`, []string{"bigtable.tables.getIamPolicy"}},
	{"bigtableadmin.googleapis.com", "POST", `/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables/[A-Za-z0-9_.-]+/authorizedViews/[A-Za-z0-9_.-]+:getIamPolicy`, []string{"bigtable.authorizedViews.getIamPolicy"}},
	{"file.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/instances`, []string{"file.instances.list"}},
	{"servicemanagement.googleapis.com", "GET", `/v1/services`, []string{"servicemanagement.services.list"}},
	{"serviceusage.googleapis.com", "GET", `/v1/projects/[0-9]+/services`, []string{"serviceusage.services.list"}},
	{"redis.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/instances`, []string{"redis.instances.list"}},
	{"alloydb.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/clusters`, []string{"alloydb.clusters.list"}},
	{"alloydb.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/clusters/-/instances`, []string{"alloydb.instances.list"}},
	{"alloydb.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/clusters/[a-z][a-z0-9-]*/users`, []string{"alloydb.users.list"}},
	{"redis.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/clusters`, []string{"redis.clusters.list"}},
	{"memcache.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/-/instances`, []string{"memcache.instances.list"}},
	{"dns.googleapis.com", "GET", `/dns/v1/projects/[^/:]+/policies`, []string{"dns.policies.list"}},
	{"dns.googleapis.com", "GET", `/dns/v1/projects/[^/:]+/responsePolicies`, []string{"dns.responsePolicies.list"}},
	{"dns.googleapis.com", "GET", `/dns/v1/projects/[^/:]+/responsePolicies/[a-z][a-z0-9-]*/rules`, []string{"dns.responsePolicyRules.list"}},
	{"servicemanagement.googleapis.com", "GET", `/v1/services/[^/:]+`, []string{"servicemanagement.services.get"}},
	{"servicemanagement.googleapis.com", "GET", `/v1/services/[^/:]+/configs`, []string{"servicemanagement.services.get"}},
	{"servicemanagement.googleapis.com", "GET", `/v1/services/[^/:]+/configs/[^/:]+`, []string{"servicemanagement.services.get"}},
	{"servicemanagement.googleapis.com", "GET", `/v1/services/[^/:]+/rollouts`, []string{"servicemanagement.services.get"}},
	{"apigateway.googleapis.com", "GET", `/v1/projects/[^/:]+/locations`, []string{"apigateway.locations.list"}},
	{"apigateway.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/gateways`, []string{"apigateway.gateways.list"}},
	{"apigateway.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/global/apis`, []string{"apigateway.apis.list"}},
	{"apigateway.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/global/apis/[^/:]+/configs`, []string{"apigateway.apiconfigs.list"}},
	{"apigateway.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/global/apis/[^/:]+/configs/[^/:]+`, []string{"apigateway.apiconfigs.get"}},
	{"cloudasset.googleapis.com", "GET", `/v1/(projects|folders|organizations)/[^/:]+:searchAllResources`, []string{"cloudasset.assets.searchAllResources"}},
	{"cloudasset.googleapis.com", "GET", `/v1/(projects|folders|organizations)/[^/:]+:searchAllIamPolicies`, []string{"cloudasset.assets.searchAllIamPolicies"}},
	{"cloudresourcemanager.googleapis.com", "GET", `/v3/(projects|folders|organizations)/[^/]+`, nil},
	{"cloudresourcemanager.googleapis.com", "GET", `/v3/(projects|folders)`, nil},
	{"cloudresourcemanager.googleapis.com", "POST", `/v3/(projects|folders|organizations)/[^/:]+:getIamPolicy`, nil},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+`, []string{"compute.projects.get"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/aggregated/instances`, []string{"compute.instances.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/aggregated/instanceTemplates`, []string{"compute.instanceTemplates.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/global/machineImages`, []string{"compute.machineImages.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/global/images`, []string{"compute.images.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/global/snapshots`, []string{"compute.snapshots.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/regions`, []string{"compute.regions.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/regions/[a-z][a-z0-9-]*/snapshots`, []string{"compute.snapshots.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/global/images/[a-z][a-z0-9-]*/getIamPolicy`, []string{"compute.images.getIamPolicy"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/(global|regions/[a-z][a-z0-9-]*)/snapshots/[a-z][a-z0-9-]*/getIamPolicy`, []string{"compute.snapshots.getIamPolicy"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/zones/[^/]+/instances/[^/]+`, []string{"compute.instances.get"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/global/firewalls`, []string{"compute.firewalls.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/global/networks`, []string{"compute.networks.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/aggregated/subnetworks`, []string{"compute.subnetworks.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/:]+/regions/[a-z][a-z0-9-]*/subnetworks/[a-z][a-z0-9-]*/getIamPolicy`, []string{"compute.subnetworks.getIamPolicy"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/global/backendServices`, []string{"compute.backendServices.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/global/instanceTemplates/[^/]+`, []string{"compute.instanceTemplates.get"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/regions/[^/]+/instanceTemplates/[^/]+`, []string{"compute.instanceTemplates.get"}},
	{"sqladmin.googleapis.com", "GET", `/v1/projects/[^/]+/instances`, []string{"cloudsql.instances.list"}},
	{"composer.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[^/:]+/environments/[^/:]+`, []string{"composer.environments.get"}},
	{"sqladmin.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[^/:]+/databases`, []string{"cloudsql.databases.list"}},
	{"sqladmin.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[^/:]+/backupRuns`, []string{"cloudsql.backupRuns.list"}},
	{"sqladmin.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[^/:]+/backupRuns/[0-9]+`, []string{"cloudsql.backupRuns.get"}},
	{"container.googleapis.com", "GET", `/v1/projects/[^/]+/locations/-/clusters`, []string{"container.clusters.list"}},
	{"run.googleapis.com", "GET", `/v1/projects/[^/]+/locations`, []string{"run.locations.list"}},
	{"run.googleapis.com", "GET", `/v2/projects/[^/]+/locations/[a-z0-9-]+/services`, []string{"run.services.list"}},
	{"run.googleapis.com", "GET", `/v2/projects/[^/:]+/locations/[a-z][a-z0-9-]*/services/[A-Za-z0-9][A-Za-z0-9_-]*:getIamPolicy`, []string{"run.services.getIamPolicy"}},
	{"cloudfunctions.googleapis.com", "GET", `/v[12]/projects/[^/:]+/locations/[a-z][a-z0-9-]*/functions/[A-Za-z0-9][A-Za-z0-9_-]*:getIamPolicy`, []string{"cloudfunctions.functions.getIamPolicy"}},
	{"run.googleapis.com", "GET", `/v2/projects/[^/]+/locations/[a-z0-9-]+/jobs`, []string{"run.jobs.list"}},
	{"cloudfunctions.googleapis.com", "GET", `/v1/projects/[^/]+/locations/-/functions`, []string{"cloudfunctions.functions.list"}},
	{"cloudfunctions.googleapis.com", "GET", `/v2/projects/[^/]+/locations/-/functions`, []string{"cloudfunctions.functions.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[^/]+/global/machineImages/[^/]+`, []string{"compute.machineImages.get"}},
	{"storage.googleapis.com", "GET", `/storage/v1/b`, []string{"storage.buckets.list"}},
	{"storage.googleapis.com", "GET", `/storage/v1/b/[^/]+`, []string{"storage.buckets.get"}},
	{"storage.googleapis.com", "GET", `/storage/v1/b/[^/]+/o`, []string{"storage.objects.list"}},
	{"storage.googleapis.com", "GET", `/storage/v1/b/[^/]+/o/[^/]+`, []string{"storage.objects.get"}},
	{"iam.googleapis.com", "GET", `/v1/(roles/[^/]+|(projects|organizations)/[^/]+/roles/[^/]+)`, []string{"iam.roles.get"}},
	{"iam.googleapis.com", "GET", `/v1/projects/[^/]+/serviceAccounts/[^/]+/keys`, []string{"iam.serviceAccountKeys.list"}},
	{"iam.googleapis.com", "GET", `/v1/projects/[^/]+/serviceAccounts`, []string{"iam.serviceAccounts.list"}},
	{"iam.googleapis.com", "GET", `/v1/projects/[^/]+/locations/global/workloadIdentityPools`, []string{"iam.workloadIdentityPools.list"}},
	{"iam.googleapis.com", "GET", `/v1/projects/[^/]+/locations/global/workloadIdentityPools/[^/:]+/providers`, []string{"iam.workloadIdentityPoolProviders.list"}},
	{"dataflow.googleapis.com", "GET", `/v1b3/projects/[^/:]+/jobs:aggregated`, []string{"dataflow.jobs.list"}},
	{"dataflow.googleapis.com", "GET", `/v1b3/projects/[^/]+/locations/[^/]+/jobs/[^/:]+`, []string{"dataflow.jobs.get"}},
	{"dns.googleapis.com", "GET", `/dns/v1/projects/[^/]+/managedZones`, []string{"dns.managedZones.list"}},
	{"apikeys.googleapis.com", "GET", `/v2/projects/[0-9]+/locations/global/keys`, []string{"apikeys.keys.list"}},
	{"cloudbuild.googleapis.com", "GET", `/v2/projects/[^/]+/locations`, []string{"cloudbuild.locations.list"}},
	{"cloudbuild.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/builds`, []string{"cloudbuild.builds.list"}},
	{"cloudbuild.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/triggers`, []string{"cloudbuild.builds.list"}},
	{"sourcerepo.googleapis.com", "GET", `/v1/projects/[A-Za-z0-9_-]+/repos/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*`, []string{"source.repos.get"}},
	{"cloudbuild.googleapis.com", "GET", `/v2/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/connections/[A-Za-z0-9_-]+/repositories/[A-Za-z0-9_-]+`, []string{"cloudbuild.repositories.get"}},
	{"developerconnect.googleapis.com", "GET", `/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/connections/[A-Za-z0-9_-]+/gitRepositoryLinks/[A-Za-z0-9_-]+`, []string{"developerconnect.gitRepositoryLinks.get"}},
	{"cloudbuild.googleapis.com", "GET", `/v1/projects/[A-Za-z0-9_-]+/(?:locations/[a-z][a-z0-9-]*/)?githubEnterpriseConfigs/[A-Za-z0-9_-]+`, []string{"cloudbuild.integrations.get"}},
	{"cloudbuild.googleapis.com", "GET", `/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/bitbucketServerConfigs/[A-Za-z0-9_-]+`, []string{"cloudbuild.integrations.get"}},
	{"workflows.googleapis.com", "GET", `/v1/projects/[^/]+/locations`, []string{"workflows.locations.list"}},
	{"workflows.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/workflows`, []string{"workflows.workflows.list"}},
	{"workflows.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/workflows/[^/:]+`, []string{"workflows.workflows.get"}},
	{"artifactregistry.googleapis.com", "GET", `/v1/projects/[^/]+/locations`, []string{"artifactregistry.locations.list"}},
	{"artifactregistry.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/repositories`, []string{"artifactregistry.repositories.list"}},
	{"artifactregistry.googleapis.com", "GET", `/v1/projects/[^/:]+/locations/[a-z][a-z0-9-]*/repositories/[A-Za-z0-9][A-Za-z0-9_.-]*:getIamPolicy`, []string{"artifactregistry.repositories.getIamPolicy"}},
	{"cloudscheduler.googleapis.com", "GET", `/v1/projects/[^/]+/locations`, []string{"cloudscheduler.locations.list"}},
	{"cloudscheduler.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/jobs`, []string{"cloudscheduler.jobs.list"}},
	{"pubsub.googleapis.com", "GET", `/v1/projects/[^/]+/subscriptions`, []string{"pubsub.subscriptions.list"}},
	{"pubsub.googleapis.com", "GET", `/v1/projects/[^/:]+/topics`, []string{"pubsub.topics.list"}},
	{"pubsub.googleapis.com", "GET", `/v1/projects/[^/:]+/snapshots`, []string{"pubsub.snapshots.list"}},
	{"bigquery.googleapis.com", "GET", `/bigquery/v2/projects/[^/]+/datasets`, []string{"bigquery.datasets.get"}},
	{"bigquery.googleapis.com", "GET", `/bigquery/v2/projects/[^/]+/datasets/[^/:]+`, []string{"bigquery.datasets.get", "bigquery.datasets.getIamPolicy"}},
	{"identitytoolkit.googleapis.com", "GET", `/admin/v2/projects/[^/]+/config`, []string{"firebaseauth.configs.get"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[A-Za-z0-9_-]+/global/routes`, []string{"compute.routes.list"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[A-Za-z0-9_-]+/global/networks/[a-z][-a-z0-9]*/getEffectiveFirewalls`, []string{"compute.networks.getEffectiveFirewalls"}},
	{"compute.googleapis.com", "GET", `/compute/v1/projects/[A-Za-z0-9_-]+/regions/[a-z][-a-z0-9]*/firewallPolicies/getEffectiveFirewalls`, []string{"compute.networks.getRegionEffectiveFirewalls"}},
	{"modelarmor.googleapis.com", "GET", `/v1/projects/[0-9]+/locations/global/floorSetting`, []string{"modelarmor.floorSettings.get"}},
	{"modelarmor.us-central1.rep.googleapis.com", "GET", `/v1/projects/[0-9]+/locations`, []string{"modelarmor.locations.list"}},
	{"modelarmor.us-central1.rep.googleapis.com", "GET", `/v1/projects/[0-9]+/locations/us-central1/templates`, []string{"modelarmor.templates.list"}},
	{"identitytoolkit.googleapis.com", "GET", `/v2/projects/[0-9]+(/tenants/[A-Za-z0-9_-]+)?/(oauthIdpConfigs|inboundSamlConfigs)`, []string{"firebaseauth.configs.get"}},
	{"identitytoolkit.googleapis.com", "GET", `/v2/projects/[^/]+/tenants`, []string{"identitytoolkit.tenants.list"}},
	{"identitytoolkit.googleapis.com", "GET", `/v2/projects/[^/]+/tenants/[^/:]+`, []string{"identitytoolkit.tenants.get"}},
	{"cloudtasks.googleapis.com", "GET", `/v2/projects/[^/]+/locations`, []string{"cloudtasks.locations.list"}},
	{"cloudtasks.googleapis.com", "GET", `/v2/projects/[^/]+/locations/[^/]+/queues`, []string{"cloudtasks.queues.list"}},
	{"aiplatform.googleapis.com", "GET", `/v1/projects/[^/]+/locations`, []string{"aiplatform.locations.list"}},
	{"secretmanager.googleapis.com", "GET", `/v1/projects/[^/]+/secrets`, []string{"secretmanager.secrets.list"}},
	{"secretmanager.googleapis.com", "GET", `/v1/projects/[0-9]+/secrets/[^/:]+:getIamPolicy`, []string{"secretmanager.secrets.getIamPolicy"}},
	{"secretmanager.googleapis.com", "GET", `/v1/projects/[^/:]+/locations`, []string{"secretmanager.locations.list"}},
	{"secretmanager.googleapis.com", "GET", `/v1/projects/[^/]+/secrets/[^/:]+/versions`, []string{"secretmanager.versions.list"}},
	{"cloudkms.googleapis.com", "GET", `/v1/projects/[^/]+/locations`, []string{"cloudkms.locations.list"}},
	{"cloudkms.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/keyRings`, []string{"cloudkms.keyRings.list"}},
	{"cloudkms.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/keyRings/[^/:]+:getIamPolicy`, []string{"cloudkms.keyRings.getIamPolicy"}},
	{"sqladmin.googleapis.com", "GET", `/v1/projects/[^/:]+/instances/[^/:]+/users`, []string{"cloudsql.users.list"}},
	{"cloudkms.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/keyRings/[^/:]+/cryptoKeys/[^/:]+:getIamPolicy`, []string{"cloudkms.cryptoKeys.getIamPolicy"}},
	{"cloudkms.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys`, []string{"cloudkms.cryptoKeys.list"}},
	{"cloudkms.googleapis.com", "GET", `/v1/projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions`, []string{"cloudkms.cryptoKeyVersions.list"}},
	{"dns.googleapis.com", "GET", `/dns/v1/projects/[^/]+/managedZones/[^/]+/rrsets`, []string{"dns.resourceRecordSets.list"}},
	{"logging.googleapis.com", "GET", `/v2/(projects|folders|organizations)/[^/]+/sinks`, []string{"logging.sinks.list"}},
	{"logging.googleapis.com", "GET", `/v2/(projects|folders|organizations)/[^/:]+/locations/-/buckets`, []string{"logging.buckets.list"}},
	{"logging.googleapis.com", "GET", `/v2/projects/[^/:]+/metrics`, []string{"logging.logMetrics.list"}},
	{"logging.googleapis.com", "GET", `/v2/(projects|folders|organizations)/[^/:]+/locations/[a-z][a-z0-9-]*/buckets/[A-Za-z0-9_][A-Za-z0-9_.-]*/links`, []string{"logging.links.list"}},
	{"logging.googleapis.com", "GET", `/v2/(projects|folders|organizations)/[^/:]+/locations/[a-z][a-z0-9-]*/buckets/[A-Za-z0-9_][A-Za-z0-9_.-]*/views`, []string{"logging.views.list"}},
	{"logging.googleapis.com", "POST", `/v2/(projects|folders|organizations)/[^/:]+/locations/[a-z][a-z0-9-]*/buckets/[A-Za-z0-9_][A-Za-z0-9_.-]*/views/[A-Za-z0-9_][A-Za-z0-9_.-]*:getIamPolicy`, []string{"logging.views.getIamPolicy"}},
	{"logging.googleapis.com", "GET", `/v2/(projects|folders|organizations)/[^/]+/exclusions`, []string{"logging.exclusions.list"}},
	{"logging.googleapis.com", "POST", `/v2/entries:list`, []string{"logging.logEntries.list"}},
	{"orgpolicy.googleapis.com", "GET", `/v2/(projects|folders|organizations)/[^/]+/policies/[^/:]+:getEffectivePolicy`, []string{"orgpolicy.policy.get"}},
	{"appengine.googleapis.com", "GET", `/v1/apps/[^/]+`, []string{"appengine.applications.get"}},
	{"appengine.googleapis.com", "GET", `/v1/apps/[a-z0-9][a-z0-9-]*/firewall/ingressRules`, []string{"appengine.applications.get"}},
	{"appengine.googleapis.com", "GET", `/v1/apps/[^/]+/services`, []string{"appengine.services.list"}},
	{"appengine.googleapis.com", "GET", `/v1/apps/[^/]+/services/[^/]+/versions`, []string{"appengine.versions.list"}},
	{"appengine.googleapis.com", "GET", `/v1/apps/[^/]+/services/[^/]+/versions/[^/]+`, []string{"appengine.versions.get"}},
}

// ViewerRequestPermissions exposes the reviewed request classifier for manual
// report commands. It does not issue a request or prove role membership; live
// collection additionally checks the freshly resolved three-role union.
func ViewerRequestPermissions(method, endpoint string, q url.Values) ([]string, error) {
	permissions, err := viewerRequestPermissions(method, endpoint, q)
	return append([]string(nil), permissions...), err
}

func viewerRequestPermissions(method, endpoint string, q url.Values) ([]string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || strings.Contains(u.Path, "/../") || strings.Contains(u.Path, "/./") || strings.Contains(u.Path, "\\") {
		return nil, fmt.Errorf("viewer-only policy: invalid API endpoint")
	}
	// Query in the endpoint is supported by the bounded Storage reader. Never
	// allow conflicting query sources to change the classified request.
	query := u.Query()
	for k, values := range q {
		if _, exists := query[k]; exists {
			return nil, fmt.Errorf("viewer-only policy: duplicate query source")
		}
		query[k] = values
	}
	if query.Has("userProject") || query.Has("quotaUser") || query.Has("$xgafv") {
		return nil, fmt.Errorf("viewer-only policy: unreviewed billing or API override")
	}
	if (u.Host == "workflows.googleapis.com" && (strings.HasSuffix(u.Path, ":listRevisions") || query.Has("revisionId"))) || (u.Host == "run.googleapis.com" && strings.Contains(u.Path, "/services/") && (strings.HasSuffix(u.Path, "/revisions") || strings.Contains(u.Path, "/revisions/"))) {
		return historicalSecretPermissions(method, u, query)
	}
	if err := secretCaptureQueryMask(u, query); err != nil {
		return nil, err
	}
	if u.Host == "parametermanager.googleapis.com" || strings.HasPrefix(u.Host, "parametermanager.") {
		return parameterManagerPermission(method, u, query)
	}
	if u.Host == "workflowexecutions.googleapis.com" {
		return workflowExecutionPermissions(method, u, query)
	}
	if u.Host == "dataproc.googleapis.com" {
		return dataprocSecretPermissions(method, u, query)
	}
	if u.Host == "notebooks.googleapis.com" {
		return notebookSecretsPermission(method, u, query)
	}
	if u.Host == "clouddeploy.googleapis.com" {
		return cloudDeployPermission(method, u, query)
	}
	if u.Host == "firebaseapphosting.googleapis.com" {
		return appHostingPermission(method, u, query)
	}
	if u.Host == "datafusion.googleapis.com" {
		return dataFusionSecretPermission(method, u, query)
	}
	if (u.Host == "secretmanager.googleapis.com" || strings.HasPrefix(u.Host, "secretmanager.")) && query.Get("fields") == secretAliasFields {
		return secretAliasesPermission(method, u, query)
	}
	if u.Host == "apikeys.googleapis.com" && strings.HasSuffix(u.Path, "/keyString") {
		if method != "GET" || u.RawPath != "" || !regexp.MustCompile(`^/v2/projects/[0-9]+/locations/global/keys/[A-Za-z0-9_-]+/keyString$`).MatchString(u.Path) || len(query) != 1 || len(query["fields"]) != 1 || query.Get("fields") != "keyString" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed API key string request")
		}
		return []string{"apikeys.keys.getKeyString"}, nil
	}
	if u.Host == "www.googleapis.com" && strings.HasPrefix(u.Path, "/deploymentmanager/v2/") {
		return deploymentManagerPermission(method, u, query)
	}
	if u.Host == "compute.googleapis.com" && strings.HasSuffix(u.Path, "/getEffectiveFirewalls") {
		wantQueries := 1
		if strings.Contains(u.Path, "/regions/") {
			wantQueries = 2
			p := strings.Split(u.Path, "/")
			if len(p) != 9 || len(query["network"]) != 1 || !strings.HasPrefix(query.Get("network"), "projects/"+p[4]+"/global/networks/") || ingressNetwork(query.Get("network")) != query.Get("network") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed regional effective firewall network")
			}
		}
		if method != "GET" || len(query) != wantQueries || len(query["fields"]) != 1 || query.Get("fields") != viewerEffectiveFirewallFields {
			return nil, fmt.Errorf("viewer-only policy: unreviewed effective firewall query")
		}
	}
	if fields := viewerBuildRepositoryFields(u.Host, u.Path); fields != "" {
		if method != "GET" || u.RawPath != "" || len(query) != 1 || len(query["fields"]) != 1 || query.Get("fields") != fields {
			return nil, fmt.Errorf("viewer-only policy: unreviewed repository reference metadata query")
		}
	} else if u.Host == "sourcerepo.googleapis.com" {
		return nil, fmt.Errorf("viewer-only policy: unreviewed source repository endpoint")
	}
	if u.Host == "compute.googleapis.com" && strings.HasSuffix(u.Path, "/global/routes") {
		if method != "GET" || query.Get("fields") != viewerRouteFields || query.Get("maxResults") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed route request")
		}
		for k, v := range query {
			if len(v) != 1 || (k != "fields" && k != "maxResults" && k != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed route query")
			}
		}
	}
	if u.Host == "modelarmor.googleapis.com" || viewerModelArmorRegionalHost.MatchString(u.Host) {
		return viewerModelArmorPermission(method, u, query)
	}
	if u.Host == "compute.googleapis.com" && strings.HasSuffix(u.Path, "/aggregated/backendServices") {
		if method != "GET" || query.Get("fields") != viewerBackendServiceFields || query.Get("maxResults") != "100" || query.Get("returnPartialSuccess") != "true" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed backend service request")
		}
		for k, v := range query {
			if len(v) != 1 || (k != "fields" && k != "maxResults" && k != "returnPartialSuccess" && k != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed backend service query")
			}
		}
	}
	if u.Host == "identitytoolkit.googleapis.com" && (strings.Contains(u.Path, "oauthIdpConfigs") || strings.Contains(u.Path, "inboundSamlConfigs")) {
		fields := viewerOIDCFields
		if strings.HasSuffix(u.Path, "/inboundSamlConfigs") {
			fields = viewerSAMLFields
		}
		if method != "GET" || query.Get("fields") != fields || query.Get("pageSize") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed identity provider request")
		}
		for k, v := range query {
			if len(v) != 1 || (k != "fields" && k != "pageSize" && k != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed identity provider query")
			}
		}
	}
	if u.Host == "firebaseappcheck.googleapis.com" {
		fields := ""
		if regexp.MustCompile(`^/v1/projects/[0-9]+/services$`).MatchString(u.Path) {
			fields = viewerAppCheckFields
		}
		if regexp.MustCompile(`^/v1/projects/[0-9]+/services/oauth2\.googleapis\.com/resourcePolicies$`).MatchString(u.Path) {
			fields = viewerAppCheckResourcePolicyFields
		}
		if method != "GET" || fields == "" || query.Get("fields") != fields || query.Get("pageSize") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed App Check method")
		}
		for k, v := range query {
			if len(v) != 1 || (k != "fields" && k != "pageSize" && k != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed App Check query")
			}
		}
	}
	if viewerRunRegionalHost.MatchString(u.Host) {
		if !viewerRunDomainQueryValid(method, u.Path, query) {
			return nil, fmt.Errorf("viewer-only policy: unreviewed regional Run request")
		}
		return []string{"run.domainmappings.list"}, nil
	}
	if u.Host == "serviceusage.googleapis.com" {
		if method != "GET" || !regexp.MustCompile(`^/v1/projects/[0-9]+/services$`).MatchString(u.Path) || query.Get("filter") != "state:ENABLED" || query.Get("fields") != viewerServiceUsageFields || query.Get("pageSize") != "200" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Service Usage request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "filter" && key != "fields" && key != "pageSize" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed Service Usage query")
			}
		}
	}
	if u.Host == "healthcare.googleapis.com" {
		for _, segment := range strings.Split(strings.TrimSuffix(u.Path, ":getIamPolicy"), "/") {
			if segment == "." || segment == ".." {
				return nil, fmt.Errorf("viewer-only policy: invalid Healthcare resource segment")
			}
		}
		valid := false
		allowed := map[string]bool{"fields": true}
		if strings.HasSuffix(u.Path, ":getIamPolicy") {
			allowed["options.requestedPolicyVersion"] = true
			valid = query.Get("options.requestedPolicyVersion") == "3" && query.Get("fields") == "version,bindings,etag"
		} else {
			allowed["pageSize"] = true
			allowed["pageToken"] = true
			parts := strings.Split(u.Path, "/")
			collection := parts[len(parts)-1]
			fields := ""
			switch collection {
			case "locations":
				fields = "locations(name,locationId),nextPageToken"
			case "datasets", "fhirStores", "dicomStores", "hl7V2Stores":
				fields = collection + "(name),nextPageToken"
			}
			valid = fields != "" && query.Get("fields") == fields && query.Get("pageSize") == "100"
		}
		if method != "GET" || !valid {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Healthcare request")
		}
		for key, values := range query {
			if !allowed[key] || len(values) != 1 {
				return nil, fmt.Errorf("viewer-only policy: unreviewed Healthcare query")
			}
		}
	}
	if u.Host == "apigee.googleapis.com" && !viewerApigeeQueryValid(method, u.Path, query) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed Apigee request")
	}
	if (u.Host == "run.googleapis.com" || u.Host == "cloudfunctions.googleapis.com" || u.Host == "artifactregistry.googleapis.com") && strings.HasSuffix(u.Path, ":getIamPolicy") {
		if method != "GET" || len(query) != 2 || len(query["fields"]) != 1 || len(query["options.requestedPolicyVersion"]) != 1 || query.Get("fields") != "version,bindings,etag" || query.Get("options.requestedPolicyVersion") != "3" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed serverless IAM read")
		}
	}
	if u.Host == "firestore.googleapis.com" {
		fields := ""
		if regexp.MustCompile(`^/v1/projects/[^/:]+/databases$`).MatchString(u.Path) {
			fields = viewerFirestoreDatabaseFields
		}
		if regexp.MustCompile(`^/v1/projects/[^/:]+/locations/-/backups$`).MatchString(u.Path) {
			fields = viewerFirestoreBackupFields
		}
		if method != "GET" || fields == "" || len(query) != 1 || len(query["fields"]) != 1 || query.Get("fields") != fields {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Firestore request")
		}
	}
	if u.Host == "spanner.googleapis.com" {
		valid := false
		allowed := map[string]bool{}
		if method == "POST" && strings.HasSuffix(u.Path, ":getIamPolicy") {
			valid = len(query) == 0
		} else if method == "GET" {
			allowed["fields"] = true
			if regexp.MustCompile(`^/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/databases/[A-Za-z_][A-Za-z0-9_-]*/ddl$`).MatchString(u.Path) {
				valid = query.Get("fields") == "statements"
			} else {
				fields := ""
				switch {
				case regexp.MustCompile(`^/v1/projects/[^/:]+/instances$`).MatchString(u.Path):
					fields = viewerSpannerInstanceFields
				case regexp.MustCompile(`^/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/databases$`).MatchString(u.Path):
					fields = viewerSpannerDatabaseFields
				case regexp.MustCompile(`^/v1/projects/[^/:]+/instances/[a-z][a-z0-9-]*/backups$`).MatchString(u.Path):
					fields = viewerSpannerBackupFields
				}
				valid = fields != "" && query.Get("fields") == fields && query.Get("pageSize") == "100"
				allowed["pageSize"] = true
				allowed["pageToken"] = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Spanner request")
		}
		for key, values := range query {
			if !allowed[key] || len(values) != 1 {
				return nil, fmt.Errorf("viewer-only policy: unreviewed Spanner query")
			}
		}
	}
	if u.Host == "bigtableadmin.googleapis.com" {
		allowed := map[string]bool{}
		valid := false
		if method == "POST" && strings.HasSuffix(u.Path, ":getIamPolicy") {
			valid = len(query) == 0
		} else if method == "GET" {
			allowed["fields"] = true
			switch {
			case regexp.MustCompile(`^/v2/projects/[^/:]+/instances$`).MatchString(u.Path):
				valid = query.Get("fields") == viewerBigtableInstanceFields
			case regexp.MustCompile(`^/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables$`).MatchString(u.Path):
				valid = query.Get("fields") == viewerBigtableTableListFields && query.Get("view") == "NAME_ONLY" && query.Get("pageSize") == "100"
				allowed["view"] = true
				allowed["pageSize"] = true
				allowed["pageToken"] = true
			case regexp.MustCompile(`^/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables/[A-Za-z0-9_.-]+/authorizedViews$`).MatchString(u.Path):
				valid = query.Get("fields") == viewerBigtableAuthorizedViewFields && query.Get("view") == "FULL" && query.Get("pageSize") == "100"
				allowed["view"] = true
				allowed["pageSize"] = true
				allowed["pageToken"] = true
			case regexp.MustCompile(`^/v2/projects/[^/:]+/instances/[a-z][a-z0-9-]*/tables/[A-Za-z0-9_.-]+$`).MatchString(u.Path):
				valid = query.Get("fields") == viewerBigtableTableFields && query.Get("view") == "FULL"
				allowed["view"] = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Bigtable request")
		}
		for key, values := range query {
			if !allowed[key] || len(values) != 1 {
				return nil, fmt.Errorf("viewer-only policy: unreviewed Bigtable query")
			}
		}
	}
	if u.Host == "file.googleapis.com" {
		if method != "GET" || query.Get("fields") != viewerFilestoreFields || query.Get("pageSize") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Filestore request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "fields" && key != "pageSize" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed Filestore query")
			}
		}
	}
	if u.Host == "alloydb.googleapis.com" {
		fields := viewerAlloyDBClusterFields
		if strings.HasSuffix(u.Path, "/instances") {
			fields = viewerAlloyDBInstanceFields
		} else if strings.HasSuffix(u.Path, "/users") {
			fields = viewerAlloyDBUserFields
		}
		if method != "GET" || query.Get("fields") != fields || query.Get("pageSize") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed AlloyDB request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "fields" && key != "pageSize" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed AlloyDB query")
			}
		}
	}
	if u.Host == "redis.googleapis.com" || u.Host == "memcache.googleapis.com" {
		fields := viewerRedisInstanceFields
		if u.Host == "memcache.googleapis.com" {
			fields = viewerMemcacheFields
		} else if strings.HasSuffix(u.Path, "/clusters") {
			fields = viewerRedisClusterFields
		}
		if method != "GET" || query.Get("fields") != fields || query.Get("pageSize") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Memorystore request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "fields" && key != "pageSize" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed Memorystore query")
			}
		}
	}
	if u.Host == "dns.googleapis.com" && strings.Contains(u.Path, "/responsePolicies/") {
		if method != "GET" || query.Get("fields") != viewerDNSResponseRuleFields || query.Get("maxResults") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed DNS response rule request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "fields" && key != "maxResults" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed DNS response rule query")
			}
		}
	}
	if u.Host == "dns.googleapis.com" && regexp.MustCompile(`^/dns/v1/projects/[^/:]+/(policies|responsePolicies)$`).MatchString(u.Path) {
		fields := viewerDNSPolicyFields
		if strings.HasSuffix(u.Path, "/responsePolicies") {
			fields = viewerDNSResponsePolicyFields
		}
		if method != "GET" || query.Get("fields") != fields || query.Get("maxResults") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed DNS policy request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "fields" && key != "maxResults" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed DNS policy query")
			}
		}
	}
	if u.Host == "appengine.googleapis.com" && strings.Contains(u.Path, "/firewall/") {
		if method != "GET" || query.Get("fields") != viewerAppEngineFirewallFields || query.Get("pageSize") != "100" {
			return nil, fmt.Errorf("viewer-only policy: unreviewed App Engine firewall request")
		}
		for key, values := range query {
			if len(values) != 1 || (key != "fields" && key != "pageSize" && key != "pageToken") {
				return nil, fmt.Errorf("viewer-only policy: unreviewed App Engine firewall query")
			}
		}
	}
	if method == "GET" && u.Host == "pubsub.googleapis.com" && regexp.MustCompile(`^/v1/projects/[^/:]+/schemas(/[A-Za-z][A-Za-z0-9._~+%-]*:listRevisions)?$`).MatchString(u.Path) {
		if query.Get("view") != "BASIC" || len(query["view"]) != 1 || query.Has("responseView") || query.Has("response_view") {
			return nil, fmt.Errorf("viewer-only policy: schema collection requires explicit BASIC view")
		}
		permission := "pubsub.schemas.list"
		if strings.HasSuffix(u.Path, ":listRevisions") {
			permission = "pubsub.schemas.listRevisions"
		}
		return []string{permission}, nil
	}
	if method == "GET" && u.Host == "cloudtasks.googleapis.com" && regexp.MustCompile(`^/v2/projects/[^/]+/locations/[^/]+/queues/[^/:]+/tasks$`).MatchString(u.Path) {
		if query.Get("responseView") != "BASIC" || len(query["responseView"]) != 1 || query.Has("response_view") {
			return nil, fmt.Errorf("viewer-only policy: task collection requires explicit BASIC view")
		}
		return []string{"cloudtasks.tasks.list"}, nil
	}
	// Vertex requests use regional API hosts. Bind host and path locations;
	// never grant a general *.googleapis.com or arbitrary-endpoint exception.
	if method == "GET" {
		regionalPolicy := regexp.MustCompile(`^/v1/projects/[0-9]+/locations/([a-z][a-z0-9-]*)/secrets/[A-Za-z0-9_-]+:getIamPolicy$`).FindStringSubmatch(u.Path)
		if len(regionalPolicy) > 0 && regionalPolicy[1] != "global" && u.Host == "secretmanager."+regionalPolicy[1]+".rep.googleapis.com" {
			return []string{"secretmanager.secrets.getIamPolicy"}, nil
		}
		regionalSecret := regexp.MustCompile(`^/v1/projects/[^/:]+/locations/([a-z][a-z0-9-]*)/secrets(/[A-Za-z0-9_-]+/versions)?$`).FindStringSubmatch(u.Path)
		if len(regionalSecret) > 0 && regionalSecret[1] != "global" && u.Host == "secretmanager."+regionalSecret[1]+".rep.googleapis.com" {
			permission := "secretmanager.secrets.list"
			if regionalSecret[2] != "" {
				permission = "secretmanager.versions.list"
			}
			return []string{permission}, nil
		}
		parts := regexp.MustCompile(`^/v1/projects/[^/]+/locations/([a-z][a-z0-9-]*)/(customJobs|pipelineJobs)(/[A-Za-z0-9_-]+)?$`).FindStringSubmatch(u.Path)
		if len(parts) > 0 && u.Host == parts[1]+"-aiplatform.googleapis.com" {
			action := "list"
			if parts[3] != "" {
				action = "get"
			}
			return []string{"aiplatform." + parts[2] + "." + action}, nil
		}
	}
	if u.Host == "cloudasset.googleapis.com" && method == "GET" && regexp.MustCompile(`^/v1/(projects|folders|organizations)/[^/]+/assets$`).MatchString(u.Path) {
		switch query.Get("contentType") {
		case "RESOURCE":
			return []string{"cloudasset.assets.listResource"}, nil
		case "IAM_POLICY":
			return []string{"cloudasset.assets.listIamPolicy"}, nil
		default:
			return nil, fmt.Errorf("viewer-only policy: unreviewed asset content type")
		}
	}
	if u.Host == "iap.googleapis.com" {
		return viewerIAPPermissions(method, u.Path)
	}
	for _, entry := range viewerEndpoints {
		path := u.Path
		// Object names may contain escaped slashes. An unescaped /acl suffix,
		// however, is a different API method and must not inherit objects.get.
		if u.Host == "storage.googleapis.com" {
			path = u.EscapedPath()
		}
		if u.Host != entry.host || method != entry.method || !regexp.MustCompile("^"+entry.path+"$").MatchString(path) {
			continue
		}
		permissions := append([]string(nil), entry.permissions...)
		if entry.host == "cloudresourcemanager.googleapis.com" {
			parts := strings.Split(strings.TrimPrefix(u.Path, "/v3/"), "/")
			action := "get"
			if len(parts) == 1 {
				action = "list"
			}
			if method == "POST" {
				action = "getIamPolicy"
			}
			permissions = []string{"resourcemanager." + parts[0] + "." + action}
		}
		if entry.host == "storage.googleapis.com" && query.Get("projection") == "full" {
			permission := "storage.buckets.getIamPolicy"
			if regexp.MustCompile(`^/storage/v1/b/[^/]+/o(/|$)`).MatchString(u.Path) {
				permission = "storage.objects.getIamPolicy"
			}
			permissions = append(permissions, permission)
		}
		return permissions, nil
	}
	return nil, fmt.Errorf("viewer-only policy: unreviewed API method or resource")
}

func viewerIAPPermissions(method, path string) ([]string, error) {
	action := ""
	if method == "POST" && strings.HasSuffix(path, ":getIamPolicy") {
		action = "getIamPolicy"
	}
	if method == "GET" && strings.HasSuffix(path, ":iapSettings") {
		action = "getSettings"
	}
	if action == "" {
		return nil, fmt.Errorf("viewer-only policy: unreviewed IAP action")
	}
	path = strings.Split(path, ":")[0]
	patterns := []struct{ pattern, resource string }{
		{`/v1/organizations/[0-9]+`, "organizations"}, {`/v1/folders/[0-9]+`, "folders"}, {`/v1/projects/[0-9]+`, "projects"},
		{`/v1/projects/[0-9]+/iap_web`, "web"},
		{`/v1/projects/[0-9]+/iap_web/[^/]+`, "webTypes"},
		{`/v1/projects/[0-9]+/iap_web/[^/]+/services/[^/]+`, "webServices"},
		{`/v1/projects/[0-9]+/iap_web/[^/]+/services/[^/]+/versions/[^/]+`, "webServiceVersions"},
		{`/v1/projects/[0-9]+/iap_tunnel`, "tunnel"},
		{`/v1/projects/[0-9]+/iap_tunnel/zones/[^/]+`, "tunnelZones"},
		{`/v1/projects/[0-9]+/iap_tunnel/zones/[^/]+/instances/[^/]+`, "tunnelInstances"},
	}
	for _, p := range patterns {
		if regexp.MustCompile("^" + p.pattern + "$").MatchString(path) {
			return []string{"iap." + p.resource + "." + action}, nil
		}
	}
	return nil, fmt.Errorf("viewer-only policy: unreviewed IAP resource")
}

func (c *Client) requireViewerPermissions(ctx context.Context, method, endpoint string, q url.Values) error {
	permissions, err := viewerRequestPermissions(method, endpoint, q)
	if err != nil {
		return err
	}
	return c.requireViewerPermissionSet(ctx, permissions)
}

// Only reviewed request classifiers and instance-bound read transports may
// call this gate. It verifies authority, not endpoint shape or scope.
func (c *Client) requireViewerPermissionSet(ctx context.Context, permissions []string) error {
	c.viewerPolicy.mu.Lock()
	defer c.viewerPolicy.mu.Unlock()
	if c.viewerPolicy.permissions == nil {
		union := map[string]bool{}
		for _, role := range viewerRoleNames {
			p, err := c.loadViewerRole(ctx, role)
			if err != nil {
				return fmt.Errorf("viewer-only policy: cannot verify %s: %w", role, err)
			}
			for _, permission := range p {
				union[permission] = true
			}
		}
		c.viewerPolicy.permissions = union
	}
	for _, permission := range permissions {
		if !c.viewerPolicy.permissions[permission] {
			return fmt.Errorf("viewer-only policy: %s is not included in the three allowed roles", permission)
		}
	}
	return nil
}

// The sole bootstrap exception is a GET of an exact predefined role definition.
// It cannot be reached with a caller-chosen role or endpoint.
func (c *Client) loadViewerRole(ctx context.Context, role string) ([]string, error) {
	allowed := false
	for _, fixed := range viewerRoleNames {
		if role == fixed {
			allowed = true
		}
	}
	if !allowed {
		return nil, fmt.Errorf("unapproved baseline role")
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	h := &http.Client{Timeout: 60 * time.Second}
	if c.HTTP != nil {
		copy := *c.HTTP
		h = &copy
	}
	h.Jar = nil
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, "GET", "https://iam.googleapis.com/v1/"+role, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.Do(req)
	if err != nil {
		return nil, fmt.Errorf("role definition request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("role definition HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return nil, fmt.Errorf("role definition unreadable or oversized")
	}
	var definition struct {
		Name                string   `json:"name"`
		IncludedPermissions []string `json:"includedPermissions"`
		Deleted             bool     `json:"deleted"`
	}
	if json.Unmarshal(data, &definition) != nil || definition.Name != role || definition.Deleted || len(definition.IncludedPermissions) == 0 {
		return nil, fmt.Errorf("invalid role definition")
	}
	for _, permission := range definition.IncludedPermissions {
		if !viewerPermissionName.MatchString(permission) {
			return nil, fmt.Errorf("invalid role permission")
		}
	}
	return definition.IncludedPermissions, nil
}
