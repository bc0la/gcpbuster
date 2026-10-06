package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

type Category struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

func CategoryOf(id string) string {
	if id == "scoutsuite" {
		return "best_practices"
	}
	for _, c := range All {
		if c.ID == id {
			return c.Category
		}
	}
	return ""
}

var Categories = []Category{{"best_practices", "Best Practices"}, {"secrets", "Secrets Management"}, {"iam", "IAM & Access"}, {"exposure", "Public Exposure"}}

type Result struct {
	Severity    string           `json:"severity"`
	Title       string           `json:"title"`
	Evidence    inventory.Object `json:"evidence"`
	Remediation string           `json:"remediation"`
}
type Check struct {
	ID          string                                    `json:"id"`
	Category    string                                    `json:"category"`
	Description string                                    `json:"description"`
	Types       []string                                  `json:"asset_types"`
	Source      string                                    `json:"source"`
	Eval        func(inventory.Asset, time.Time) []Result `json:"-"`
}

func (c Check) Applies(a inventory.Asset) bool {
	if c.ID == "audit_logging" && a.Type != "cloudresourcemanager.googleapis.com/Project" && a.Type != "cloudresourcemanager.googleapis.com/Folder" && a.Type != "cloudresourcemanager.googleapis.com/Organization" {
		return false
	}
	for _, t := range c.Types {
		if t == "*IAM" && a.IAM != nil {
			return true
		}
		if t == a.Type && a.Resource.Data != nil {
			return true
		}
	}
	return false
}
func result(sev, title, fix string, evidence inventory.Object) []Result {
	return []Result{{sev, title, evidence, fix}}
}
func val(a inventory.Asset, path ...string) any { return inventory.Get(a.Resource.Data, path...) }
func s(v any) string                            { return inventory.Str(v) }
func b(v any) bool                              { return inventory.Bool(v) }
func obj(v any) inventory.Object                { return inventory.Obj(v) }
func arr(v any) []any                           { return inventory.List(v) }
func has(v any, value string) bool {
	for _, x := range arr(v) {
		if s(x) == value {
			return true
		}
	}
	return false
}
func isFalse(v any) bool        { x, ok := v.(bool); return ok && !x }
func public(member string) bool { return member == "allUsers" || member == "allAuthenticatedUsers" }

const cloudSource = "https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/"
const workspaceSource = "https://cloud.hacktricks.wiki/en/pentesting-cloud/workspace-security/"

var All = []Check{
	{"secrets_scan", "secrets", "Kingfisher detection with actual-value evidence for manual validation", []string{SecretScanFindingType}, "https://github.com/mongodb/kingfisher", kingfisherSecrets},
	{"configuration_plaintext", "secrets", "Actual plaintext configuration values and native secret heuristics", []string{CapturedConfigurationValueType}, cloudSource + "gcp-post-exploitation/gcp-cloud-build-post-exploitation.html", capturedConfigurationValue},
	{"run_domain_mapping_status", "exposure", "Observed not-ready Cloud Run domain mappings without takeover inference", []string{"gcpbuster.googleapis.com/RunDomainMapping"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-cloud-run-unauthenticated-enum.html", runDomainMappingStatus},
	{"public_storage_capabilities", "exposure", "Broad Storage object read/list/create/delete permissions distinguished by action", []string{inventory.PermissionGrantType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-storage-unauthenticated-enum/", publicStorageCapabilities},
	{"apigee_authentication_policy", "exposure", "Attached Apigee authentication policies explicitly disabled or non-blocking", []string{"gcpbuster.googleapis.com/ApigeeProxyRevision"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-apigee-unauthenticated-enum.html", apigeeAuthenticationPolicy},
	{"apigee_request_authentication", "exposure", "Apigee request flows without a selected unconditional enforcing authenticator", []string{inventory.ApigeeProxyRevisionType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-apigee-unauthenticated-enum.html", apigeeRequestAuthentication},
	{"looker_studio_public_sharing", "exposure", "Offline supplied Looker Studio public-sharing and credential-delegation review", []string{"workspace.googleapis.com/LookerStudioReport"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-looker-studio-unauthenticated-enum.html", lookerStudioSharing},
	{"public_secret_payload_capability", "exposure", "Broad secret-scoped grants with exact payload-access permission", []string{inventory.PermissionGrantType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-secret-manager-unauthenticated-enum.html", publicSecretPayloadCapability},
	{"public_service_account_credentials", "iam", "Broad scoped service-account token issuance and signing capabilities", []string{inventory.PermissionGrantType}, "https://docs.cloud.google.com/iam/docs/service-account-permissions", publicServiceAccountCredentials},
	{"spanner_public_role_read", "exposure", "Broad Spanner FGAC grants coinciding with table SELECT for the SQL public role", []string{inventory.PermissionGrantType}, "https://docs.cloud.google.com/spanner/docs/fgac-system-roles", spannerPublicRoleRead},
	{"cloud_build_mirrored_source", "exposure", "Configured external mirror provenance of a Cloud Build source trigger", []string{"cloudbuild.googleapis.com/BuildTrigger"}, "https://docs.cloud.google.com/source-repositories/docs/mirroring-a-github-repository", cloudBuildMirroredSource},
	{"apigee_product_self_service", "exposure", "Explicit public API products with automatic consumer-key approval", []string{inventory.ApigeeAPIProductType}, "https://docs.cloud.google.com/apigee/docs/api-platform/publish/create-api-products", apigeeProductSelfService},
	{"public_automation_capabilities", "exposure", "Broad scoped Cloud Tasks enqueue or Scheduler run permissions", []string{inventory.PermissionGrantType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-cloud-tasks-unauthenticated-enum.html", publicAutomationCapabilities},
	{"public_healthcare_capabilities", "exposure", "Broad Healthcare IAM grants with exact clinical-read permissions", []string{inventory.PermissionGrantType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-healthcare-unauthenticated-enum.html", publicHealthcareCapabilities},
	{"cloud_build_pr_comment_control", "exposure", "Pull-request build triggers explicitly omit the trusted-writer comment gate", []string{"cloudbuild.googleapis.com/BuildTrigger"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-cloud-build-unauthenticated-enum.html", cloudBuildPRCommentControl},
	{"public_serverless_invocation", "exposure", "Broad direct serverless grants with resolved invocation permission", []string{inventory.PermissionGrantType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-cloud-run-unauthenticated-enum.html", publicServerlessInvocation},
	{"firestore_database_protection", "best_practices", "Explicitly disabled Firestore database deletion protection", []string{"firestore.googleapis.com/Database"}, cloudSource + "gcp-post-exploitation/gcp-firestore-post-exploitation.html", firestoreDatabaseProtection},
	{"firestore_pitr", "best_practices", "Explicitly disabled extended Firestore point-in-time recovery", []string{"firestore.googleapis.com/Database"}, cloudSource + "gcp-post-exploitation/gcp-firestore-post-exploitation.html", firestorePITR},
	{"spanner_database_protection", "best_practices", "Explicitly disabled Spanner database deletion protection", []string{"spanner.googleapis.com/Database"}, cloudSource + "gcp-services/gcp-spanner-enum.html", spannerDatabaseProtection},
	{"spanner_change_stream_scope", "exposure", "Explicit all-table Spanner change-stream configuration", []string{"spanner.googleapis.com/Database"}, cloudSource + "gcp-persistence/gcp-spanner-persistence.html", spannerChangeStreamScope},
	{"bigtable_table_protection", "best_practices", "Explicitly disabled Bigtable table deletion protection", []string{"bigtableadmin.googleapis.com/Table"}, cloudSource + "gcp-post-exploitation/gcp-bigtable-post-exploitation.html", bigtableTableProtection},
	{"bigtable_authorized_view_scope", "exposure", "Authorized view configured for all rows and all qualifiers in selected families", []string{inventory.BigtableAuthorizedViewType}, cloudSource + "gcp-persistence/gcp-bigtable-persistence.html", bigtableAuthorizedViewScope},
	{"filestore_root_trust", "best_practices", "Explicit Filestore read-write exports without root squashing", []string{"file.googleapis.com/Instance"}, cloudSource + "gcp-persistence/gcp-filestore-persistence.html", filestoreRootTrust},
	{"filestore_export_sources", "exposure", "Explicit Filestore unrestricted IPv4 export source configuration", []string{"file.googleapis.com/Instance"}, cloudSource + "gcp-post-exploitation/gcp-filestore-post-exploitation.html", filestoreExportSources},
	{"alloydb_user_roles", "iam", "Observed AlloyDB-managed database administrative role memberships", []string{inventory.AlloyDBUserType}, cloudSource + "gcp-persistence/gcp-alloydb-persistence.html", alloyDBUserRoles},
	{"alloydb_public_configuration", "exposure", "AlloyDB explicit public-IP and world-source authorized-network configuration", []string{"alloydb.googleapis.com/Instance"}, cloudSource + "gcp-services/gcp-alloydb-enum.html", alloyDBPublicConfiguration},
	{"alloydb_client_protection", "best_practices", "AlloyDB explicit optional TLS and connector-only enforcement settings", []string{"alloydb.googleapis.com/Instance"}, cloudSource + "gcp-services/gcp-alloydb-enum.html", alloyDBClientProtection},
	{"alloydb_data_api", "exposure", "AlloyDB explicitly enabled authorized Data API access", []string{"alloydb.googleapis.com/Instance"}, cloudSource + "gcp-post-exploitation/gcp-alloydb-post-exploitation.html", alloyDBDataAPI},
	{"memorystore_authentication", "best_practices", "Explicitly disabled Memorystore Redis instance or cluster authentication", []string{"redis.googleapis.com/Instance", "redis.googleapis.com/Cluster"}, cloudSource + "gcp-post-exploitation/gcp-memorystore-post-exploitation.html", memorystoreAuthentication},
	{"memorystore_transport", "best_practices", "Explicitly disabled Memorystore Redis instance or cluster transport encryption", []string{"redis.googleapis.com/Instance", "redis.googleapis.com/Cluster"}, cloudSource + "gcp-post-exploitation/gcp-memorystore-post-exploitation.html", memorystoreTransport},
	{"dns_record_secrets", "secrets", "Redacted DNS record and response-policy credential candidates", []string{inventory.DNSRecordSetType, inventory.DNSResponsePolicyRuleType}, cloudSource + "gcp-post-exploitation/gcp-cloud-dns-post-exploitation.html", dnsRecordSecrets},
	{"dns_response_rules", "exposure", "Configured bound DNS response-policy overrides and bypass exceptions", []string{inventory.DNSResponsePolicyRuleType}, cloudSource + "gcp-post-exploitation/gcp-cloud-dns-post-exploitation.html", dnsResponseRule},
	{"service_config_auth", "exposure", "Compiled service method authentication and consumer-identity requirements", []string{inventory.ServiceConfigType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-cloud-endpoints-unauthenticated-enum.html", serviceManagementAuth},
	{"service_config_secrets", "secrets", "Redacted credential candidates in compiled Service Management configuration", []string{inventory.ServiceConfigType}, cloudSource + "gcp-services/gcp-api-gateway-enum.html", serviceConfigSecrets},
	{"apigateway_mcp_discovery", "exposure", "API Gateway MCP tool-discovery authentication configuration", []string{"apigateway.googleapis.com/ApiConfig"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-api-gateway-unauthenticated-enum.html", apiGatewayMCPDiscovery},
	{"apigateway_route_auth", "exposure", "OpenAPI operation authentication requirements from transient API Gateway config source", []string{"apigateway.googleapis.com/ApiConfig"}, cloudSource + "gcp-post-exploitation/gcp-api-gateway-post-exploitation.html", apiGatewayAuth},
	{"apigateway_source_secrets", "secrets", "Redacted credential candidates in Viewer-readable API Gateway OpenAPI source", []string{"apigateway.googleapis.com/ApiConfig"}, cloudSource + "gcp-services/gcp-api-gateway-enum.html", apiGatewaySecrets},
	{"iap_access_grants", "iam", "Review standing and public IAP web/tunnel accessor bindings", []string{"*IAM"}, cloudSource + "gcp-persistence/gcp-iap-persistence.html", iapAccessGrants},
	{"public_iap_capabilities", "exposure", "Broad IAP grants with exact web or tunnel access permissions", []string{inventory.PermissionGrantType}, "https://docs.cloud.google.com/iap/docs/managing-access", publicIAPCapabilities},
	{"iap_settings", "best_practices", "Review explicit IAP CORS, programmatic-client and authentication settings", []string{"iap.googleapis.com/IapSettings"}, cloudSource + "gcp-privilege-escalation/gcp-iap-privesc.html", iapSettings},
	{"appengine_protection", "best_practices", "Review explicitly disabled application-level IAP", []string{"appengine.googleapis.com/Application"}, cloudSource + "gcp-privilege-escalation/gcp-iap-privesc.html", appEngineProtection},
	{"appengine_ingress", "exposure", "Review App Engine service ingress permitting public sources", []string{"appengine.googleapis.com/Service"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-app-engine-unauthenticated-enum.html", appEngineIngress},
	{"appengine_firewall", "exposure", "Review complete App Engine first-match firewall broad source allowances", []string{"gcpbuster.googleapis.com/AppEngineFirewall"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-app-engine-unauthenticated-enum.html", appEngineFirewall},
	{"appengine_version_traffic", "best_practices", "Review serving App Engine versions absent from observed service traffic splits", []string{"appengine.googleapis.com/Version"}, cloudSource + "gcp-persistence/gcp-app-engine-persistence.html", appEngineVersionTraffic},
	{"iap_backend_protection", "best_practices", "Review explicitly disabled IAP on HTTP backend services", []string{"compute.googleapis.com/BackendService", "compute.googleapis.com/RegionBackendService"}, cloudSource + "gcp-privilege-escalation/gcp-iap-privesc.html", iapBackendProtection},
	{"logging_routes", "best_practices", "Review export destinations and aggregated/intercepting log sink configuration", []string{"logging.googleapis.com/LogSink"}, cloudSource + "gcp-persistence/gcp-logging-persistence.html", loggingRoutes},
	{"log_bucket_retention", "best_practices", "Explicit Cloud Logging minimum retention and retention-lock review", []string{"logging.googleapis.com/LogBucket"}, cloudSource + "gcp-persistence/gcp-logging-persistence.html", loggingBucketRetention},
	{"log_bucket_visibility", "best_practices", "Explicit pending bucket deletion and field-level read restrictions", []string{"logging.googleapis.com/LogBucket"}, cloudSource + "gcp-post-exploitation/gcp-logging-post-exploitation.html", loggingBucketVisibility},
	{"logging_metrics", "best_practices", "Explicitly disabled log-based metric configuration", []string{"logging.googleapis.com/LogMetric"}, cloudSource + "gcp-post-exploitation/gcp-logging-post-exploitation.html", loggingMetrics},
	{"log_bigquery_link", "best_practices", "Active configured Logging-to-BigQuery dataset links", []string{"logging.googleapis.com/Link"}, cloudSource + "gcp-post-exploitation/gcp-logging-post-exploitation.html", loggingBigQueryLink},
	{"secret_manager_audit", "best_practices", "Secret Manager metadata/payload Data Access audit classes and exemptions", []string{inventory.AuditConfigType}, cloudSource + "gcp-services/gcp-secrets-manager-enum.html", secretManagerAudit},
	{"parameter_manager_audit", "best_practices", "Parameter Manager version-read/render Data Access audit policy and exemptions", []string{inventory.AuditConfigType}, cloudSource + "gcp-post-exploitation/gcp-parameter-manager-post-exploitation.html", parameterManagerAudit},
	{"cloud_sql_user_update_audit", "best_practices", "Cloud SQL user-password update DATA_WRITE audit policy and exemptions, including managed-secret rotation downstream activity", []string{inventory.AuditConfigType}, cloudSource + "gcp-privilege-escalation/gcp-secretmanager-privesc.html", cloudSQLUserUpdateAudit},
	{"parameter_reference_delegation", "secrets", "Stored Parameter Manager secret references and supplied exact-resource delegation prerequisites", []string{ParameterReferenceType}, cloudSource + "gcp-post-exploitation/gcp-parameter-manager-post-exploitation.html", parameterReferenceDelegation},
	{"inherited_audit_logging", "best_practices", "Union supplied ancestor/local Data Access audit settings and exemptions", []string{inventory.AuditConfigType}, cloudSource + "gcp-persistence/gcp-logging-persistence.html", inheritedAuditConfig},
	{"workload_identity_grants", "iam", "Correlate explicit workload or built-in resource identities with high-impact direct IAM grants", []string{inventory.WorkloadGrantType}, cloudSource + "gcp-privilege-escalation/gcp-run-privesc.html", workloadIdentityGrants},
	{"gke_kubelet_exposure", "exposure", "Detect explicitly enabled insecure kubelet read-only port configuration", []string{"container.googleapis.com/Cluster"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-gke-kubelet-unauthenticated-access.html", gkeKubelet},
	{"gke_telemetry", "best_practices", "Review disabled operational telemetry and omitted workload logging", []string{"container.googleapis.com/Cluster"}, cloudSource + "gcp-post-exploitation/gcp-gke-post-exploitation.html", gkeTelemetry},
	{"workspace_group_iam_paths", "iam", "Correlate IAM-bound groups with join settings and direct owners/managers", []string{inventory.GroupIAMType}, cloudSource + "gcp-persistence/gcp-cloud-identity-persistence.html", groupIAMPaths},
	{"secret_manager_lifecycle", "secrets", "Review Secret Manager rotation notifications, delegated rotation prerequisites, alias metadata and recoverable scheduled destruction", []string{"secretmanager.googleapis.com/Secret", "secretmanager.googleapis.com/SecretVersion", SecretAliasMetadataType, ManagedRotationPrerequisiteType}, cloudSource + "gcp-persistence/gcp-secret-manager-persistence.html", secretManagerLifecycle},
	{"kms_lifecycle", "best_practices", "Review eligible KMS rotation schedules and pending key-version destruction", []string{"cloudkms.googleapis.com/CryptoKey", "cloudkms.googleapis.com/CryptoKeyVersion"}, cloudSource + "gcp-services/gcp-kms-enum.html", kmsLifecycle},
	{"org_policy_guardrails", "best_practices", "Review selected effective organization-policy guardrails without inferring runtime access", []string{inventory.EffectiveOrgPolicyType}, cloudSource + "gcp-privilege-escalation/gcp-orgpolicy-privesc.html", orgPolicyGuardrails},
	{"log_content_secrets", "secrets", "Scan time-bounded Cloud Logging payloads without persisting their contents", []string{inventory.LogScanType}, cloudSource + "gcp-post-exploitation/gcp-logging-post-exploitation.html", logContentSecrets},
	{"gcs_anonymous_access", "exposure", "Validate anonymous listing and object reads on discovered Cloud Storage buckets", []string{inventory.StorageProbeType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-storage-unauthenticated-enum/README.html", storageAnonymousAccess},
	{"gcs_content_secrets", "secrets", "Scan bounded Cloud Storage text/source/ZIP contents with value-redacted findings", []string{inventory.ContentScanType}, cloudSource + "gcp-services/gcp-storage-enum.html", storageContentSecrets},
	{"artifact_registry_upstreams", "best_practices", "Compare virtual-repository public/private upstream priorities and review custom remotes", []string{"artifactregistry.googleapis.com/Repository", inventory.ArtifactUpstreamsType}, cloudSource + "gcp-persistence/gcp-artifact-registry-persistence.html", artifactUpstreams},
	{"automation_identity_delivery", "iam", "Review durable service-account token delivery in Scheduler, Tasks and Pub/Sub", []string{"cloudscheduler.googleapis.com/Job", "cloudtasks.googleapis.com/Queue", "cloudtasks.googleapis.com/Task", "pubsub.googleapis.com/Subscription"}, cloudSource + "gcp-persistence/gcp-cloud-scheduler-persistence.html", automationIdentityDelivery},
	{"task_queue_logging", "best_practices", "Cloud Tasks dispatch logging configuration", []string{"cloudtasks.googleapis.com/Queue"}, cloudSource + "gcp-persistence/gcp-cloud-tasks-persistence.html", taskQueueLogging},
	{"iam_permission_risks", "iam", "Correlate assigned role permissions with the HackTricks permission risk catalog", []string{inventory.PermissionGrantType}, permissionSource, permissionRisks},
	{"iam_permission_combinations", "iam", "Match documented permission combinations for the same scope, principal and condition", []string{inventory.PermissionGrantType}, permissionSource, permissionCombinations},
	{"public_permission_capabilities", "exposure", "Resolve high-impact capabilities in public principals' assigned roles", []string{inventory.PermissionGrantType}, permissionSource, publicPermissionCapabilities},
	{"public_artifact_access", "exposure", "Public repository grants with resolved artifact-download capability", []string{inventory.PermissionGrantType}, "https://docs.cloud.google.com/artifact-registry/docs/protect-artifacts", publicArtifactAccess},
	{"artifact_cross_project_access", "iam", "Repository download grants to explicitly cross-project service accounts", []string{inventory.PermissionGrantType}, "https://docs.cloud.google.com/artifact-registry/docs/access-control", artifactCrossProjectAccess},
	{"public_pubsub_capabilities", "exposure", "Public Pub/Sub grants with exact resolved messaging capabilities", []string{inventory.PermissionGrantType}, cloudSource + "gcp-services/gcp-pub-sub.html", publicPubSubCapabilities},
	{"public_compute_disk_capabilities", "exposure", "Broad source-use grants on Compute images and snapshots", []string{inventory.PermissionGrantType}, cloudSource + "gcp-services/gcp-compute-instances-enum/", publicComputeDiskCapabilities},
	{"pubsub_subscription_state", "best_practices", "Explicit detached or deleted-topic Pub/Sub subscription state", []string{"pubsub.googleapis.com/Subscription"}, cloudSource + "gcp-post-exploitation/gcp-pub-sub-post-exploitation.html", pubsubSubscriptionState},
	{"pubsub_export_identity", "iam", "Review explicit Pub/Sub export writers and destinations", []string{"pubsub.googleapis.com/Subscription"}, cloudSource + "gcp-privilege-escalation/gcp-pubsub-privesc.html", pubsubExportIdentity},
	{"dns_dangling", "exposure", "Public-zone CNAME targets that did not resolve; takeover requires confirmation", []string{"dns.googleapis.com/ResourceRecordSet"}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-dns-unauthenticated-enum.html", dnsDangling},
	{"identity_platform", "iam", "Identity Platform anonymous sign-in and MFA settings", []string{"identitytoolkit.googleapis.com/Config", "identitytoolkit.googleapis.com/Tenant"}, "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/projects/getConfig", identityPlatform},
	{"identity_platform_enrollment", "exposure", "Explicit local-provider signup configuration", []string{"identitytoolkit.googleapis.com/Config", "identitytoolkit.googleapis.com/Tenant"}, "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/Config", identityPlatformEnrollment},
	{"identity_blocking_functions", "iam", "Configured Identity Platform blocking hooks and credential forwarding", []string{"identitytoolkit.googleapis.com/Config"}, "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/Config", identityBlockingFunctions},
	{"identity_oidc_response_type", "iam", "Enabled Identity Platform OIDC front-channel ID-token response configuration", []string{"gcpbuster.googleapis.com/IdentityPlatformOIDCProvider"}, "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/projects.oauthIdpConfigs", identityOIDCResponseType},
	{"model_armor_filter_configuration", "best_practices", "Explicit Model Armor template filter and inspection configuration", []string{"gcpbuster.googleapis.com/ModelArmorTemplate"}, "https://docs.cloud.google.com/model-armor/reference/rest/v1/projects.locations.templates", modelArmorFilterConfiguration},
	{"model_armor_exclusion_configuration", "best_practices", "Recognized catch-all exclusions on enabled Model Armor template filters", []string{"gcpbuster.googleapis.com/ModelArmorTemplate"}, "https://docs.cloud.google.com/model-armor/configure-exclusion-rules", modelArmorExclusionConfiguration},
	{"firebase_app_check_enforcement", "exposure", "Explicit Firebase App Check service baseline non-enforcement", []string{"gcpbuster.googleapis.com/FirebaseAppCheckService"}, "https://firebase.google.com/docs/reference/appcheck/rest/v1/EnforcementMode", firebaseAppCheckEnforcement},
	{"firebase_app_check_resource_enforcement", "exposure", "Explicit Firebase App Check resource baseline non-enforcement", []string{"gcpbuster.googleapis.com/FirebaseAppCheckResourcePolicy"}, "https://firebase.google.com/docs/reference/appcheck/rest/v1/projects.services.resourcePolicies", firebaseAppCheckResourceEnforcement},
	{"dns_security", "best_practices", "Public Cloud DNS DNSSEC configuration", []string{"dns.googleapis.com/ManagedZone"}, cloudSource + "gcp-services/gcp-dns-enum.html", dnsSecurity},
	{"dns_policy_forwarding", "exposure", "Cloud DNS inbound forwarding and alternative resolver configuration", []string{"dns.googleapis.com/Policy"}, cloudSource + "gcp-post-exploitation/gcp-cloud-dns-post-exploitation.html", dnsPolicyForwarding},
	{"dns_zone_resolution", "exposure", "Private Cloud DNS forwarding and DNS peering configuration", []string{"dns.googleapis.com/ManagedZone"}, cloudSource + "gcp-post-exploitation/gcp-cloud-dns-post-exploitation.html", dnsZoneResolution},
	{"dns_query_logging", "best_practices", "Explicitly disabled public-zone or bound-network DNS query logging", []string{"dns.googleapis.com/ManagedZone", "dns.googleapis.com/Policy"}, cloudSource + "gcp-post-exploitation/gcp-cloud-dns-post-exploitation.html", dnsQueryLogging},
	{"vertex_ai_posture", "best_practices", "Vertex AI training and pipeline private-network configuration review", []string{"aiplatform.googleapis.com/CustomJob", "aiplatform.googleapis.com/PipelineJob"}, cloudSource + "gcp-post-exploitation/gcp-vertex-ai-post-exploitation.html", vertexPosture},
	{"compute_metadata", "best_practices", "VM metadata, OS Login, project SSH keys, serial console and scopes", []string{"compute.googleapis.com/Instance"}, cloudSource + "gcp-post-exploitation/gcp-compute-post-exploitation.html", computeMetadata},
	{"gke_security", "best_practices", "Legacy credentials, workload identity and node metadata", []string{"container.googleapis.com/Cluster"}, cloudSource + "gcp-post-exploitation/gcp-gke-post-exploitation.html", gkeSecurity},
	{"storage_hardening", "best_practices", "Uniform bucket access and public access prevention", []string{"storage.googleapis.com/Bucket"}, cloudSource + "gcp-post-exploitation/gcp-storage-post-exploitation.html", storageHardening},
	{"sql_hardening", "best_practices", "SQL transport, backups/PITR, availability, deletion protection and local password-policy configuration", []string{"sqladmin.googleapis.com/Instance"}, cloudSource + "gcp-post-exploitation/gcp-cloud-sql-post-exploitation.html", sqlHardening},
	{"composer_network", "exposure", "Explicit Composer webserver network admission and environment networking", []string{"composer.googleapis.com/Environment"}, cloudSource + "gcp-services/gcp-composer-enum.html", composerNetwork},
	{"audit_logging", "best_practices", "Direct Data Access audit policy and exemptions (inheritance needs review)", []string{"*IAM"}, cloudSource + "gcp-persistence/gcp-logging-persistence.html", auditLogging},
	{"logging_sinks", "best_practices", "Disabled sinks and log exclusions", []string{"logging.googleapis.com/LogSink", "logging.googleapis.com/LogExclusion"}, cloudSource + "gcp-persistence/gcp-logging-persistence.html", loggingSinks},
	{"workspace_2sv", "best_practices", "Workspace user/admin 2-Step Verification enrollment and enforcement", []string{"workspace.googleapis.com/User"}, workspaceSource + "gws-admin-privesc.html", workspace2SV},
	{"configuration_secrets", "secrets", "Redacted secret candidates in workload, build, metadata and orchestration configuration", []string{"compute.googleapis.com/Instance", "compute.googleapis.com/Project", "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/MachineImage", "cloudfunctions.googleapis.com/CloudFunction", "cloudfunctions.googleapis.com/Function", "run.googleapis.com/Service", "run.googleapis.com/Job", "cloudbuild.googleapis.com/Build", "cloudbuild.googleapis.com/BuildTrigger", "appengine.googleapis.com/Version", "workflows.googleapis.com/Workflow", "cloudscheduler.googleapis.com/Job", "dataflow.googleapis.com/Job", "composer.googleapis.com/Environment", "aiplatform.googleapis.com/CustomJob", "aiplatform.googleapis.com/PipelineJob"}, cloudSource + "gcp-post-exploitation/gcp-cloud-build-post-exploitation.html", configurationSecrets},
	{"service_account_keys", "secrets", "Active user-managed service-account keys and key age", []string{"iam.googleapis.com/ServiceAccountKey"}, cloudSource + "gcp-privilege-escalation/gcp-iam-privesc.html", serviceAccountKeys},
	{"api_key_restrictions", "secrets", "API key application and API restrictions without reading key strings", []string{"apikeys.googleapis.com/Key"}, cloudSource + "gcp-services/gcp-api-keys-enum.html", apiKeys},
	{"iam_privileges", "iam", "Broad basic roles, impersonation, service-account attachment and custom escalation permissions", []string{"*IAM", "iam.googleapis.com/Role"}, cloudSource + "gcp-privilege-escalation/gcp-iam-privesc.html", iamPrivileges},
	{"federation_trust", "iam", "Unconstrained federation providers and whole-pool IAM grants", []string{"*IAM", "iam.googleapis.com/WorkloadIdentityPoolProvider", "iam.googleapis.com/WorkforcePoolProvider"}, cloudSource + "gcp-persistence/gcp-workload-identity-federation-persistence.html", federationTrust},
	{"workspace_oauth", "iam", "High-impact Workspace OAuth grants", []string{"workspace.googleapis.com/OAuthGrant"}, workspaceSource + "gws-persistence.html", workspaceOAuth},
	{"workspace_admin_roles", "iam", "Super admins, delegated admins and sensitive custom administrator roles", []string{"workspace.googleapis.com/User", "workspace.googleapis.com/Role", "workspace.googleapis.com/RoleAssignment"}, workspaceSource + "gws-admin-privesc.html", workspaceAdmins},
	{"workspace_dwd", "iam", "Operator-supplied domain-wide delegation grants (not inferred from OAuth client IDs)", []string{"workspace.googleapis.com/DomainWideDelegation"}, cloudSource + "gcp-to-workspace-pivoting/gcp-understanding-domain-wide-delegation.html", workspaceDWD},
	{"workspace_mail_persistence", "iam", "Operator-supplied Gmail delegation and forwarding metadata", []string{"workspace.googleapis.com/GmailSettings"}, workspaceSource + "gws-persistence.html", workspaceMail},
	{"public_iam", "exposure", "Public IAM grants on buckets, data, workloads, images, snapshots, messaging, repositories and keys", []string{"*IAM"}, cloudSource + "gcp-persistence/gcp-resource-iam-persistence.html", publicIAM},
	{"storage_acl", "exposure", "Public legacy bucket/default object ACLs", []string{"storage.googleapis.com/Bucket"}, cloudSource + "gcp-post-exploitation/gcp-storage-post-exploitation.html", storageACL},
	{"firewall_ingress", "exposure", "Internet-wide ingress firewall allows", []string{"compute.googleapis.com/Firewall"}, cloudSource + "gcp-post-exploitation/gcp-vpc-network-post-exploitation.html", firewallIngress},
	{"network_peering_routes", "best_practices", "Explicit custom-route exchange configuration on active VPC peerings", []string{"compute.googleapis.com/Network"}, cloudSource + "gcp-services/gcp-compute-instances-enum/gcp-vpc-and-networking.html", networkPeeringRoutes},
	{"public_compute", "exposure", "VM external addresses (inventory, not proof of reachability)", []string{"compute.googleapis.com/Instance"}, cloudSource + "gcp-post-exploitation/gcp-compute-post-exploitation.html", publicCompute},
	{"public_sql", "exposure", "Cloud SQL public addresses and internet-wide authorized networks", []string{"sqladmin.googleapis.com/Instance"}, cloudSource + "gcp-post-exploitation/gcp-cloud-sql-post-exploitation.html", publicSQL},
	{"public_gke", "exposure", "GKE public control-plane endpoint and authorized networks", []string{"container.googleapis.com/Cluster"}, cloudSource + "gcp-post-exploitation/gcp-gke-post-exploitation.html", publicGKE},
	{"public_bigquery", "exposure", "BigQuery dataset public access entries", []string{"bigquery.googleapis.com/Dataset"}, cloudSource + "gcp-post-exploitation/gcp-bigquery-post-exploitation.html", publicBigQuery},
	{"public_bigquery_capabilities", "exposure", "BigQuery authenticated broad-reader grants with exact table data permission", []string{inventory.PermissionGrantType}, cloudSource + "gcp-unauthenticated-enum-and-access/gcp-bigquery-unauthenticated-enum.html", publicBigQueryCapabilities},
	{"public_serverless", "exposure", "Cloud Run invoker IAM checks disabled", []string{"run.googleapis.com/Service"}, cloudSource + "gcp-post-exploitation/gcp-cloud-run-post-exploitation.html", publicServerless},
	{"workspace_groups", "exposure", "Public group archives, public joining and external membership", []string{"workspace.googleapis.com/GroupSettings"}, workspaceSource + "gws-admin-privesc.html", workspaceGroups},
	{"workspace_drive_sharing", "exposure", "Operator-supplied Drive permissions with anyone access", []string{"workspace.googleapis.com/DriveFile"}, workspaceSource + "gws-admin-data-exfil.html", workspaceDrive},
}

func Select(ids, categories, excluded []string) ([]Check, error) {
	known := map[string]bool{}
	for _, c := range All {
		known[c.ID] = true
	}
	for _, id := range append(append([]string{}, ids...), excluded...) {
		if !known[id] {
			return nil, fmt.Errorf("unknown module %q", id)
		}
	}
	valid := map[string]bool{}
	for _, c := range Categories {
		valid[c.Key] = true
	}
	for _, c := range categories {
		if !valid[c] {
			return nil, fmt.Errorf("unknown category %q", c)
		}
	}
	contains := func(xs []string, x string) bool {
		for _, s := range xs {
			if s == x {
				return true
			}
		}
		return false
	}
	var out []Check
	for _, c := range All {
		if (len(ids) == 0 || contains(ids, c.ID)) && (len(categories) == 0 || contains(categories, c.Category)) && !contains(excluded, c.ID) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no modules selected")
	}
	return out, nil
}

func sortedKeys(m inventory.Object) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func truth(v any) bool { return b(v) || strings.EqualFold(s(v), "true") }
