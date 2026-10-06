# GCPBuster

GCP and Google Workspace evaluators adapted from local `~/BezosBuster`, preserving four report categories. The source repositories remain unchanged.

| Category | Example evaluators |
| --- | --- |
| Best Practices | Compute metadata, GKE configuration, bucket controls, audit logging, SQL hardening, IAP settings |
| Secrets Management | Kingfisher matches, plaintext configuration, service-account key metadata, API key restrictions |
| IAM & Access | IAM grants and permission combinations, federation trust, workload identities, supplied Workspace evidence |
| Public Exposure | Public IAM, firewall ingress, VM addresses, service endpoint configuration, supplied Workspace sharing evidence |

There are **120 native evaluators, not 120 verified live Viewer-compatible checks**. Many require offline evidence or service configuration discovery not yet rebuilt for this profile. Public/unauthenticated coverage and explicit role/workflow boundaries are tracked in [PUBLIC_SURFACE.md](PUBLIC_SURFACE.md). Full applicable HackTricks GCP and BezosBuster equivalence remains unfinished; see [COVERAGE.md](COVERAGE.md) and [GOAL_PROGRESS.md](GOAL_PROGRESS.md).

## Secrets reporting

Like BezosBuster, secret scanning uses Kingfisher with `--no-validate`: matches and approved native configuration values are reported in full by default for manual validation. No credential is tested. Keep engagement directories private; JSON, HTML and SQLite can contain sensitive values. Matched source files are stored privately and served only through finding-bound download links.

Use `--redact-secrets` with a fresh engagement to suppress new secret values and source artifacts. An engagement previously used for actual values cannot be reused as redacted. `--no-secrets` skips Kingfisher only; native `configuration_plaintext` reporting remains independently selectable. Legacy configuration-candidate checks still redact their own evidence.

The pinned Linux Kingfisher binary is installed beside the executable under `.tools/kingfisher-v1.112.0/`; a PATH installation takes precedence. Build `gcpbuster` in this directory to use the pinned fallback. Source capture is bounded and transient, excludes protected secret payloads, and uses only reviewed Viewer-permitted requests. Parameter Manager raw version configuration is readable; rendering Secret Manager references is not attempted. Remaining source-family gaps are tracked in [SECRETS_SOURCE_COVERAGE.json](SECRETS_SOURCE_COVERAGE.json).

Reports include full matches, rule/confidence/validation metadata, source fields and revisions, safe manual refetch commands where available, and private `saved_file` downloads for matched sources. Refetch commands are never executed by the tool; collection commands may require following pagination, and later configuration can differ from the saved source. Native configuration inventory includes benign values and reference strings as INFO without resolving references. Historical Workflow definitions and retained Cloud Run revisions are included through separate bounded reads.

Additional sources include raw Parameter Manager template versions and reviewed Apigee proxy/sharedflow configuration XML from already-authorized bundle reads. Parameter reference checks report stored targets, parameter UID metadata and observed delegation grants without rendering or retrieving the target secret. Parameter DATA_READ and Cloud SQL password-update DATA_WRITE checks assess supplied audit-policy configuration, not private audit logs or successful delivery. Managed-rotation findings correlate configured caller and built-in identity grants without resetting a password or proving effective access.

## Exact Viewer-only authorization profile

All live native requests are constrained to permissions present in these three roles:

- `roles/viewer`
- `roles/resourcemanager.folderViewer`
- `roles/resourcemanager.organizationViewer`

Read-only is not sufficient: many GET/read APIs require permissions absent from these roles. A runtime guard loads the three exact predefined role definitions through fixed IAM GET endpoints, checks their permission union, and rejects unreviewed API methods or nonbaseline permissions before sending the resource request. Failed role-definition loading fails closed. A token with extra privileges does not enlarge the guard's API-method allowlist, but the guard **does not downscope credentials or prove their assigned roles**. Stronger credentials can reveal extra fields on an otherwise allowed method. Use an assessment identity with only the three permitted roles and appropriate existing OAuth scopes, not additional role grants. Resource authorization, deny policies, API enablement and provider controls still apply.

Role placement matters: service reads need Viewer on the project or valid inherited access; hierarchy Viewer roles do not provide general service access. This tool does not grant roles or enable APIs. Supplied/default credentials must already represent the intended allowed-role identity. Explicit and detected gcloud impersonation settings are refused, but the tool cannot fully establish stored credential provenance or downscope externally issued tokens. `--token-env` accepts an already-issued token subject to those same limits.

These legacy entry points now reject before collection: service-account impersonation; live Workspace and its token/membership flags; `--iap-policies`; GCS content/source scans; list-backed anonymous-storage probes; and external ScoutSuite `collect`. Their evaluator/source code may remain for offline evidence and historical tests, not supported live execution.

See Google's [Cloud Asset](https://docs.cloud.google.com/iam/docs/roles-permissions/cloudasset), [Resource Manager](https://docs.cloud.google.com/iam/docs/roles-permissions/resourcemanager), [IAP](https://docs.cloud.google.com/iam/docs/roles-permissions/iap), and [Storage basic-role](https://docs.cloud.google.com/storage/docs/access-control/iam-roles#intrinsic-permissions) permissions. Removable Storage convenience-value grants are not intrinsic Viewer access.

## Build and run

Requires Go 1.25 or later. The supplied Linux executable is `./gcpbuster`.

### Install from GitHub

Install from the public repository (Go 1.25 or later):

```bash
go install github.com/bc0la/gcpbuster/cmd/gcpbuster@latest
```

The executable installs into `GOBIN`, or `$(go env GOPATH)/bin` when `GOBIN` is unset. `go install` installs GCPBuster only: install Kingfisher on PATH separately to use `secrets_scan`, or download the Linux release bundle containing the pinned scanner. Scanning uses `--no-validate` regardless of installation method.

Download the Linux amd64 bundle (GCPBuster plus pinned Kingfisher):

```bash
gh release download --repo bc0la/gcpbuster --pattern 'gcpbuster-linux-amd64.tar.gz' --pattern 'SHA256SUMS'
sha256sum --ignore-missing --check SHA256SUMS
tar -xzf gcpbuster-linux-amd64.tar.gz
./gcpbuster --help
```

Keep `.tools/` beside `gcpbuster` so the pinned scanner can be found. The standalone `gcpbuster-linux-amd64` release asset is also available if you already have Kingfisher on PATH.

The GitHub Actions build workflow runs tests and vet, builds Linux artifacts, and publishes release assets for version tags. Manual runs also provide downloadable workflow artifacts. Local engagement reports and scanner downloads are not committed.

```bash
cd ~/gcpbuster
go build -o gcpbuster ./cmd/gcpbuster
./gcpbuster modules

# Offline demonstration: no credentials or cloud access.
./gcpbuster scan --inventory examples/inventory.json --engagement ./engagements/demo

# Authenticate gcloud separately with the existing intended Viewer identity.
./gcpbuster scan --project YOUR_PROJECT --engagement ./engagements/project

# Explicit hierarchy traversal; reads still require Viewer on each project.
./gcpbuster scan --scope organizations/123456789 --engagement ./engagements/org

# Interactive Progress/Logs tabs; 8 global workers, at most 4 per project.
./gcpbuster scan --scope organizations/123456789 --ui \
  --concurrency 8 --per-project-concurrency 4 --engagement ./engagements/org-ui

# Plain request-level logs, useful when redirecting output or troubleshooting.
./gcpbuster scan --scope organizations/123456789 --no-ui --verbose \
  --engagement ./engagements/org-verbose

# Multiple projects, selected categories.
./gcpbuster scan --project PROJECT_A,PROJECT_B --category iam,exposure \
  --engagement ./engagements/iam

# Existing token, without token minting/impersonation by this tool.
./gcpbuster scan --project YOUR_PROJECT --token-env GCP_ACCESS_TOKEN

# Optional role-gated supplemental collection.
./gcpbuster scan --project YOUR_PROJECT --iap-settings --logging-config \
  --org-policy-checks --engagement ./engagements/settings
./gcpbuster scan --project YOUR_PROJECT --scan-logs \
  --engagement ./engagements/log-review
```

On an interactive terminal, live scans automatically use a Bubble Tea interface with separate **Progress** and **Logs** tabs. Progress shows stage totals, queued/running/completed work, resource counts and failure counts; Logs keeps request-level activity separate from the overview. Press Tab or left/right arrows to switch tabs, up/down or Page Up/Page Down to scroll logs, End to follow new entries, and Ctrl+C to cancel collection. `q` does not quit or cancel. `--ui` explicitly enables the interface; `--no-ui` disables it. Non-terminal output uses plain stderr progress automatically. In plain mode, `--verbose` adds HTTP method/service/status/attempt timings; a 15-second heartbeat makes long waits visible. Neither interface logs tokens, request paths/queries, response bodies or secret values.

The parallel scheduler follows BezosBuster's global and per-target limits: `--concurrency` defaults to **8** collection workers globally, and `--per-project-concurrency` defaults to **4** jobs per project within that global budget. Both accept 1–64; `--concurrency 1` makes collection serial. Fair dispatch mixes projects and independent service families without reserving workers for a busy project's queue. Dependent reads stay ordered, partial failures remain in coverage, and output merging is deterministic. Optional post-discovery enrichments remain separately ordered. HTTP 429 responses share a service-level cooldown across workers, honor bounded `Retry-After` delays and use bounded retries; cancellation interrupts waits. Lower concurrency if your organization's quotas require it. These settings do not add permissions, enable APIs or turn denied/disabled service reads into successful coverage.

The **Accounts** tab groups scheduled collection work by verified GCP project ID (the GCP counterpart of an AWS account). It shows each project's planned collector-group total, queued/running/completed/failed/cancelled counts, progress percentage and restored checkpoint count. These groups cover the direct collector families, followed by indexed IAM search; totals grow as stages are discovered. Hierarchy/project discovery and optional enrichments remain in Progress/Logs rather than being represented as a fixed per-project denominator. Use Tab/right and Shift+Tab/left to cycle tabs, up/down or Page Up/Page Down to select a project, and Enter to expand its collector-group statuses; scroll the expanded list and press Enter to return. Ctrl+C cancels; `q` does nothing.

Live collection excludes project IDs starting with `sys-` by default. This is a name-prefix heuristic, not confirmation of Apps Script ownership or safety. Excluded projects are recorded as skipped coverage and do not run project collectors. Use `--include-system-projects` to include them. Offline inventories are not filtered. The selection policy is part of the resume configuration; changing it, or resuming pre-policy checkpoints, requires a new engagement directory.

Collection completion is not scan completion: the Progress tab separately shows local secret analysis, assessment preparation, running checks (scanned inventory records and finding counts), and report export. In-check updates are emitted approximately every two seconds as evaluation proceeds; a single blocking operation may take longer. Findings are committed in transactions of at most 256 rows without disabling SQLite durability. Interrupted/failed checks are not marked completed; resume deletes their partial findings before rerunning them against the same inventory.

Each run writes `engagement.db`, `report.html`, and `findings.json`. For large engagements, use the database-backed report server instead of opening the static HTML:

```bash
./gcpbuster report --engagement ./engagements/project
# http://127.0.0.1:8080
```

This uses the existing `engagement.db` directly in read-only mode: no rescan, schema migration or regenerated export is required. Point `--engagement` at the directory containing the database. The server has the same four category tabs, module/project/severity filters and literal metadata search. Findings default to 50 per page (maximum 200); evidence and protected source downloads are loaded on demand. Coverage and module runs are separately paginated. Static `report.html`/`findings.json` exports remain available but contain all findings and can be large. The `/api/findings` endpoint now returns a paginated envelope rather than a full array.

Reports can contain actual secret values. The server binds only to loopback (`--addr 127.0.0.1:8080` by default), rejects cross-origin access and never exposes the engagement directory/database as static files. Use an SSH tunnel for remote viewing rather than exposing it on the network. Ctrl+C stops the server.

The report keeps four sections, filters, module status, evidence/remediation, and collection coverage. Failed/incomplete collection produces a saved partial report **and a nonzero exit status**. Current live discovery deliberately reports incomplete service coverage even when all attempted reads succeed. `skipped` means no applicable records were supplied, not that a control passed. Findings alone do not change the exit status.

Use `--engagement DIR` from the start of a live scan, then repeat the same command with `--resume` after interruption. Successful reviewed metadata collector families are checkpointed in the private engagement SQLite database. Resume reuses eligible successful families, retries failed/unfinished work, and rereads hierarchy, project metadata, IAM searches, optional enrichments and secret-bearing families. Cached metadata reflects the original read time, not a fresh complete scan; use a new engagement for fresh collection. Scopes and collection options must match. Older engagements without collection checkpoints require a new directory.

```bash
gcpbuster scan --scope organizations/123456789 --engagement ./engagements/org
# After interruption:
gcpbuster scan --scope organizations/123456789 --engagement ./engagements/org --resume
```

Offline assessment resume remains supported with matching input. Completed checks skip only when the analysis fingerprint matches. If a prior assessment exists and reread inventory changes, use a new engagement; resume never silently combines findings from different inventories. Reuse without `--resume` is rejected. Input ordering can affect fingerprints; the current evaluator fingerprint is `v44-viewer`.

Resume using the same identity as the original collection. Checkpoints are historical local records, not proof that the current identity still has access to those resources; authentication tokens are never stored in them.

## Current live discovery and its limits

Default discovery reads Resource Manager hierarchy/container metadata and project IAM, Compute project configuration/instances/VPC firewalls, Storage bucket listing with `projection=noAcl`, and project-scoped Cloud Asset **IAM search**. It no longer relies on `assets.list` RESOURCE/IAM_POLICY: those permissions are absent from the allowed roles. Search supplies indexed direct bindings, not full service configuration or complete audit-policy evidence. Direct project policies are retained instead of overwritten by the eventually consistent search index. See [IAM search semantics](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies).

Default discovery also lists Cloud SQL instances, all-location GKE cluster configurations, Cloud Run services/jobs across API-discovered regions, Functions v1/v2 configurations, DNS managed zones and service-account/user-managed-key metadata. These are control-plane configuration reads, not database/Kubernetes access, workload invocation, source/image download or secret-payload retrieval. Pagination, denied reads and unreachable locations are recorded; successful subsets do not establish completeness. DNS resolution remains opt-in through `--dns-checks`.

Service-account email and numeric-ID aliases can remain separate across API and IAM-search records; complete metadata/policy correlation is not asserted. Functions v1/v2 retain their distinct CAI types, so first-generation configuration may appear in both representations and produce duplicate findings.

SQL instances also receive [user metadata](https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users/list), with passwords/hash fields excluded by field selection and a local whitelist. Database and paginated BackupRun listings retain reviewed metadata directly from list responses, avoiding redundant detail GETs; backup collection is capped at 1000 records per instance, with explicit failure on truncation. No database/backup contents or restore operations are accessed. Deleted-instance retained backups and Backup and DR vault inventories remain gaps. User/database presence is not a vulnerability or evidence of an empty password.

`sql_hardening` flags explicitly disabled deletion protection and local password policy (known MySQL/PostgreSQL engines). Informational findings review zonal primaries, disabled engine-specific PITR on standard-backup primaries, and enabled MySQL policies with username-substring exclusion disabled or zero history on MySQL 8+. Missing/malformed settings are unknown; no universal password length or workload availability requirement is invented. SQL exposure checks suppress expired authorized-network entries and networks disabled by required connectors; malformed expiration is labeled unverified. Credential strength, effective reachability, failover and restoration remain untested.

KMS key rings and keys receive [direct IAM policy reads](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/getIamPolicy) requesting version 3. Conditions are preserved, not evaluated. Direct policies—including empty ones—take precedence over eventually consistent IAM-search bindings. Failed policy reads retain metadata and report incomplete collection; inherited access, deny policies and cryptographic usability remain unresolved.

Default collection also includes API-key restrictions, global/regional Secret Manager secret/version lifecycle metadata, KMS key-ring/key/version metadata, stored Build/BuildTrigger configuration, current Workflow definitions, Artifact Registry repositories, Scheduler jobs and Pub/Sub subscriptions. With secrets collection selected, API key strings are read transiently through the Viewer-permitted `getKeyString` method; they are not tested or retained in inventory metadata. Workflows use a detail GET because listing can omit source definitions. Regional services use their location APIs; Cloud Build additionally includes its documented global collection. No execution, message consumption, artifact download or cryptographic operation is performed.

Regional Secret Manager uses project service-location discovery and regional endpoints with strict host/path location matching. Denied, malformed or unavailable locations are reported, not interpreted as empty. Global and regional secrets receive direct version-3 IAM policy reads; conditions are preserved without testing payload access. Regional metadata retains managed-rotation type, IAM principal identifiers and state, but excludes credentials and unstructured errors; Exact returned built-in UID/name principals correlate independently with supplied direct IAM grants and conditions; no UID/name alias or service account is invented. SQL targets, active rotation and effective authorization remain unassessed. Expiration findings distinguish scheduled expiration from past-due metadata without claiming deletion or external credential revocation; see [expiration semantics](https://docs.cloud.google.com/secret-manager/docs/creating-and-managing-expiring-secrets). Secret Manager ADMIN_READ/DATA_READ audit checks union supplied ancestor and service settings/exemptions. Missing-class findings require a complete valid policy chain; inaccessible parent policies remain unknown. These checks do not test log delivery, retention or payload access; see [audit classes](https://docs.cloud.google.com/secret-manager/docs/audit-logging).

BigQuery dataset metadata/ACLs, Identity Platform project/tenant anonymous-sign-in and MFA posture, Tasks queue/BASIC task configuration, and Vertex custom/pipeline job configuration are also collected. Conditional BigQuery grants are not treated as unconditional access. Identity hash/provider secrets and task bodies/headers are excluded by response field selection and local projection. Vertex lists discover identities before configuration GETs, binding the regional API host to the resource location; execution outputs and artifact downloads are excluded. None of these reads queries table rows, exports users, dispatches tasks or starts ML jobs.

Compute global/regional instance templates and machine-image metadata are listed without downloading images. Dataflow uses [all-region job summaries](https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.jobs/aggregated) followed by configuration detail reads; failed regions, missing configuration and external step definitions remain incomplete. No jobs are run and external definitions are not fetched. Global workload identity pool/provider metadata is permission-gated; only known active federation pools/providers feed trust findings. Workforce, trust-domain admission and effective token acceptance remain outside this collection. The federation API's exact documented legacy permission names must appear in the runtime role union: service-qualified lookalikes are not silently aliased, and their presence alone results in denied collection/incomplete coverage.

Configuration secret candidates include the source Lambda name/value patterns (AWS keys, PEM, Slack, JWT, GitHub and GitLab), alongside Google-specific patterns. These are redacted heuristics, not credential validation; exact secret references and placeholders are excluded.

Federation posture collection currently supports AWS/OIDC provider metadata only. Missing/malformed provider type or trust fields fail coverage without producing posture findings. SAML/X.509 trust specifics remain unassessed; their certificates/key material are not fetched.

Composer uses project-scoped Asset Inventory resource search to discover environment names, then guarded configuration GETs. Composer has no documented location-list endpoint; search-index incompleteness remains explicit, including on empty results. Configuration feeds redacted secret candidates, explicit webserver network-admission/public-environment indicators, and worker-service-account grant correlation. The worker identity is not inferred from the Composer service agent. No Airflow URL, DAG bucket, GKE cluster, runtime output or exported object is accessed; configured admission and grants do not prove authentication bypass or execution. See the [Composer environment schema](https://docs.cloud.google.com/composer/docs/reference/rest/v1/projects.locations.environments).

Other service-configuration discovery remains incomplete; settings are not guaranteed merely because search returns their IAM policies. Missing records remain unknown. Current service reads are documented by Google's [SQL API](https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances/list), [GKE API](https://docs.cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters/list), [Run API](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/list), and [Functions API](https://docs.cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/list). Run service listing does not accept a wildcard region; region enumeration is not a hard-coded region list. API-key metadata listing explicitly [omits the key string](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list); the key-string endpoint remains outside this tool's allowlist even if present in Viewer.

`--resolve-roles` defaults to enabled and uses `iam.roles.get`. Disabling it requires supplied complete definitions for permission analysis; missing definitions are incomplete coverage. IAM modules use the local HackTricks catalog of 10,238 classified permissions, preserving resource, principal and condition. Permission matches are not effective authorization: deny policies, access boundaries, inherited/group grants, conditions and service prerequisites remain unresolved.

`--ancestor-iam` follows container parents. Project `getIamPolicy` is permitted; folder/organization `getIamPolicy` is outside the three-role union and denied by the guard. It does not establish complete inherited IAM or audit logging. Missing topology/policies and search-only bindings are not evidence of disabled inherited audit controls.

`--iap-settings` discovers global Compute backends and App Engine applications/services/version identities, then reads local settings using distinct `getSettings` permissions. Project/web/type/service/version reads are Viewer-permitted; ancestor settings need their own permission and may be denied. IAP IAM-policy reads are disabled. Findings review explicit OPTIONS exceptions, programmatic clients, disabled reauthentication/domain restrictions, application/backend IAP, and service ingress. Missing fields are unknown; findings are configuration review, not verified unauthenticated access. Effective settings inheritance and alternate backend paths remain incomplete. See [settings authorization](https://docs.cloud.google.com/iap/docs/reference/rest/v1/TopLevel/getIapSettings).

`--org-policy-checks` reads 11 selected effective guardrails using `orgpolicy.policy.get`, subject to the guard and scope authorization. These cover service-account keys/default grants, storage controls, OS Login, serial ports, App Engine code download, member domains and VM external IPs. Provider effective-policy responses drive findings; unsupported/missing/denied responses are failures, not disabled-control findings. Managed/custom constraints, compensating controls and existing-resource compliance remain incomplete.

`--logging-config` reads sinks/exclusions with `logging.sinks.list`/`logging.exclusions.list` and all-location bucket metadata with `logging.buckets.list`. Denied scopes remain explicit failures. Informational bucket checks review explicit one-day retention and locked retention; no arbitrary retention baseline, malicious intent or historical data loss is inferred. The collector also lists views under discovered, in-scope buckets and reads their direct version-3 IAM policies. View metadata and conditions are retained; filters and effective access are not evaluated. Pending deletion and configured field restrictions are separate indicators, not proof of maliciousness or actual data loss. It also lists project log-based metrics and links under discovered in-scope buckets. Explicitly disabled metrics and ACTIVE linked datasets yield configuration indicators only; filters/extractors, time series, dependent alerts and effective BigQuery access are not evaluated. No log entries, view contents, analytics or destination contents are read by this collector. See [bucket listing](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/list). Sink requests include ancestor intercepting routes using the ALL filter, not every ancestor sink. Findings do not establish destination ownership, readership, writer authorization or delivery. Intercepting sinks preserve descendant `_Required` routing; see [LogSink](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks).

`--scan-logs` uses read-only `entries.list` POST with `logging.logEntries.list`, fixed time bounds and pagination limits. Defaults: 24 hours, 1,000 entries and 100 pages per container; configure `--logs-lookback`, `--logs-max-entries`, `--logs-max-pages`, `--log-filter`. Private Data Access/Access Transparency logs are excluded; special views and restricted fields requiring additional authority are outside the coverage claim. With stronger credentials, method-level guarding cannot downscope every returned field. The legacy eight-pattern detector persists redacted candidate metadata; approved project-scoped ordinary text also feeds Kingfisher when secrets scanning is selected. Kingfisher findings follow the actual-value default or `--redact-secrets` policy. Hierarchy traversal remains explicit and log visibility scope-dependent. See [Logging permissions](https://docs.cloud.google.com/iam/docs/roles-permissions/logging).

Default discovery enumerates DNS zones, public/private record metadata, selected server/response-policy metadata and response-policy rules without querying resolver targets. Raw record values feed transient secret capture before inventory redaction. Native/Kingfisher findings and matched source artifacts follow the actual-value default or `--redact-secrets` policy. `--dns-checks` separately opts into address lookups for validated CNAME targets in explicitly public zones. Applicable record listing passes the same role guard. An address-not-found result is neither authoritative NXDOMAIN evidence nor proof of claimability. No deployment or takeover is attempted.

No cloud resources are modified. Findings contain resource identifiers and policy metadata: keep engagement directories private. Secret scan and native plaintext findings retain actual values unless `--redact-secrets` is selected; missing, encoded or unsupported content may be missed.

## Offline evidence and Workspace

All native evaluators remain available for supplied inventory. This does not mean all required evidence can be acquired with the three roles. Workspace users, groups, membership, admins, OAuth grants, DWD, Gmail and Drive are offline-only under this profile. Cloud IAM grants no Workspace Directory authority; see [Directory scopes](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing). A service-account OAuth client ID does not prove DWD, and SSO/IdP MFA matters when reviewing 2SV indicators.

Opt-in log scanning also supplies approved, project-scoped ordinary log text to Kingfisher when secrets scanning is selected. The legacy log heuristic remains redacted, but Kingfisher matches/source artifacts follow the actual-value default or `--redact-secrets` policy described above.

Engagements must use a real private `0700` directory and private `0600` SQLite files. Unsafe existing directories, symlinks and broadly readable database/sidecar files are rejected; choose a new private directory rather than assuming a previously public report has become private.

Public-surface discovery now reads direct Run/Functions and Artifact Registry IAM. A second-generation function can supply its explicit, project-scoped backing Run service reference even if service listing is denied. Healthcare collection reads dataset/store names and version-3 IAM; clinical resources are excluded. Resolved public permissions distinguish invocation, artifact downloads, clinical reads, secret payload access, task creation and scheduled job execution. Project-level observations retain their parent scope. Pull-request comment gates and independent build approval settings have a separate check. These observations retain conditions and do not establish effective access.

Apigee discovery verifies the organization's project binding before reading deployment and routing metadata. Only explicitly observed revision bundles are inspected transiently, with compressed/inflated byte, entry and aggregate XML-token bounds. Attached VerifyAPIKey/VerifyJWT/OAuthV2 VerifyAccessToken policies that explicitly disable enforcement or continue on error produce configuration findings. Native inbound-request analysis distinguishes unconditional, conditional and non-enforcing verification steps from response/fault attachments. Environment hooks are read only for observed deployment environments; referenced shared flows are inspected only at revisions observed in that same environment. Policy names are digested; source, credentials and option values are omitted. Conditions, dynamic shared-flow calls, custom code and backend authentication remain unresolved, so neither missing findings nor selected verifiers prove effective route authentication.

Public Storage grants are classified separately as object read, list, create and delete, without accessing objects. Exact bucket metadata can qualify those observations: explicitly enforced PAP overrides broad-principal grants and lowers residual-binding review to informational; inherited/missing/conflicting PAP remains unresolved. UBLA does not disable IAM bindings. Project grants are not expanded into child buckets. Cloud Run native domain-mapping metadata is conditional: listing requires the exact `run.domainmappings.list` in the freshly loaded three-role union. Current published role evidence does not establish that permission; it is skipped with incomplete coverage rather than substituted with another permission. A not-ready mapping is configuration review, not DNS, takeover or released custom-URL proof.

Default Compute backend discovery uses a strictly selected aggregated metadata read for global and regional HTTP backend services, feeding explicit IAP-disabled configuration review without OAuth client secrets or backend probes. `public_iap_capabilities` classifies resolved custom/predefined role permissions separately for web versions, tunnel instances and destination groups; parent/project scopes remain unexpanded. IAP public conditional bindings are unsupported/unknown, not valid conditional-access claims. Direct IAP policy reads remain outside the baseline.

Configuration-secret candidate heuristics include the CodeBuild `database_url`, `connection_string` and `jdbc` name families, including native Cloud Build `NAME=value` entries. Protected references, placeholders, empty and boolean values are excluded from candidate heuristics; legacy projected candidate evidence remains redacted. The separate `configuration_plaintext` evaluator retains approved native values unless `--redact-secrets` is selected. Candidates are not validated credentials.

Identity Platform enrollment review uses typed local-provider enablement and explicit `client.permissions.disabledUserSignup=false`, with tenant `disableAuth=false` required separately. Missing controls stay unknown. No signup, token issuance, users, Firebase ruleset source or application-data access is performed or inferred.

Default Identity Platform provider discovery reads selected OIDC/SAML names and enabled/response-type flags for the project and observed tenants. Client secrets, issuer/client identifiers, certificates and provider/token/login requests are excluded. An enabled explicit front-channel ID-token response produces informational implicit-flow review, not a universally unsafe-flow, token-leak or missing-secret claim. The Google discovery document's `/v2` paths are used; rendered project REST references currently show a different `/admin/v2` prefix, tracked in the ledger.

Artifact repository download grants to canonical service accounts in different named projects produce informational cross-project review. Numeric project aliases, known service agents and users/groups are not classified by this indicator; different projects can share an organization. Federation trust review additionally recognizes whitespace/parentheses around literal CEL `true`, without evaluating arbitrary conditions or assuming nonempty expressions are restrictive.

Identity Platform Config metadata also projects blocking-hook presence and explicit inbound credential-forwarding switches, without retaining hook URIs or credential values. Hook registration is informational review, not auth-bypass or enrollment-blocking proof; anonymous/custom authentication does not support these hooks. No hook, source or user endpoint is contacted. See [blocking functions](https://docs.cloud.google.com/identity-platform/docs/blocking-functions).

`public_bigquery_capabilities` resolves exact `bigquery.tables.getData` grants to `allAuthenticatedUsers` at dataset, table or project scope. Metadata get/list and query-job permissions alone are not data-read grants. Tokenless `allUsers` access is not asserted; authentication, query execution-project permissions, row/policy-tag/masking controls and perimeters remain separate. No table data, query or export is requested.

Firebase App Check lists explicitly configured service-level enforcement metadata through `firebaseappcheck.services.get` and resource-policy metadata under the documented OAuth2 service through `firebaseappcheck.resourcePolicies.get`. Explicit `OFF`/`UNENFORCED` settings produce informational protection review, not anonymous-access findings. Resource policies override the service baseline but do not prove their targets exist or that enforcement has propagated. Missing services/modes remain unknown; independent authentication/rules and effective access remain unresolved. No attestation, debug/provider configuration, tokens or protected data are requested.

Offline group/IAM correlation can consume native `cloudidentity.googleapis.com/Group` records with `groupKey.id` and selected empty-valued type labels. Security, locked and dynamic groups are distinguished from ordinary discussion groups when reviewing self-join and OWNER/MANAGER settings; those settings alone do not establish membership-change authority. Conflicting type evidence or group aliases remain unknown. Native group input grants no live Workspace authority. See [Cloud Identity group types](https://docs.cloud.google.com/identity/docs/groups).

`looker_studio_public_sharing` accepts operator-normalized offline evidence, not native Looker API responses: asset type `workspace.googleapis.com/LookerStudioReport`, name `workspace/lookerStudioReports/REPORT_ID` (1–128 ASCII letters, digits, `_` or `-`), and `resource.data` containing `schemaVersion: 1`, `sharing: "PUBLIC_ON_WEB" | "ANYONE_WITH_LINK" | "RESTRICTED"`, plus optional `dataSources: [{"credentialMode":"OWNER" | "SERVICE_ACCOUNT" | "VIEWER"}]`. No report or data-source contents are fetched. Groups checks separate public message visibility from enabled conversation history; disabling history does not prove older archives were erased.

`--inventory` accepts JSON arrays, CAI `{"assets":[...]}` responses, CAI JSONL, or snapshots with `assets` and optional `coverage`. Existing formats remain importable; the tool does not acquire privileged exports for you. Repeat inputs to merge by `(assetType, name)`:

```bash
./gcpbuster scan --inventory resources.jsonl --inventory policies.jsonl \
  --inventory workspace.json --engagement ./engagements/export-review
```

Assets need `name` and `assetType`; metadata belongs in `resource.data`, bindings in `iamPolicy`. Incomplete pagination is not accepted as complete inventory. Wrap raw objects, for example:

```json
{
  "name": "workspace/dwd/CLIENT_ID",
  "assetType": "workspace.googleapis.com/DomainWideDelegation",
  "resource": {"data": {
    "clientId": "CLIENT_ID",
    "scopes": ["https://www.googleapis.com/auth/drive.readonly"]
  }}
}
```

Workspace types include `User`, `Group`, `GroupMemberships`, `GroupSettings`, `Role`, `RoleAssignment`, `OAuthGrant`, `DomainWideDelegation`, `GmailSettings`, and `DriveFile`, prefixed with `workspace.googleapis.com/`. Gmail evidence may include forwarding/delegates/filters; Drive permission arrays must be complete before interpreting absence. See [examples/inventory.json](examples/inventory.json).

Historical bounded GCS/archive scanners and anonymous probes are not enabled live. Their fixtures preserve behavioral/redaction tests, not Viewer compatibility. External ScoutSuite collection is disabled: its [GCP setup](https://github.com/nccgroup/ScoutSuite/wiki/Google-Cloud-Platform) includes additional roles and arbitrary installed external code is not protected by the native guard.

Public Artifact Registry download grants are distinguished from public metadata-only grants using resolved role permissions. Anonymous and Google-authenticated audiences remain distinct; conditions, deny rules and service perimeters can affect actual access. No package or image is downloaded.

## Development and source audit

```bash
./gcpbuster coverage --hacktricks-root ~/hacktricks-cloud \
  --bezosbuster-root ~/BezosBuster --summary
./gcpbuster coverage --hacktricks-root ~/hacktricks-cloud \
  --bezosbuster-root ~/BezosBuster --output source-audit.json
go test ./...
go test -race ./...
go vet ./...
```

Source hashes, headings, citations and catalog overlap do not prove behavioral coverage. The full applicable backlog remains open. Permission-incompatible techniques need a Viewer-observable equivalent or explicit unsupported boundary, not additional roles.

Tests use fake HTTP and never access a tenant. Historical collector/report fixtures may deliberately supply **synthetic privileged permission sets** to test inaccessible paths and redaction; those are not actual Viewer compatibility evidence. Separate request-policy and CLI tests check denial boundaries. Passing tests do not prove full cloud coverage.

New live collectors need reviewed method-to-permission mappings, membership in the exact role union, scoped discovery, partial-failure reporting, and tests. A new GET endpoint is not automatically approved. Keep every evaluator in one of the four categories and distinguish offline evidence, live settings and verified probes.

Pub/Sub increment: paginated topic metadata and existing subscription metadata stay within Viewer permissions. `public_pubsub_capabilities` distinguishes exact publish, attach-subscription and consume permissions in resource-scoped broad-principal grants. Live grant evidence comes from indexed CAI IAM search and resolved roles; direct topic/subscription IAM reads are unavailable under the three-role boundary. Conditions, index completeness and effective authorization remain unresolved. No messages are published, pulled, acknowledged or replayed, and attachment alone does not prove subscription creation or consumption.

Further Pub/Sub coverage: schema and revision lists require explicit `view=BASIC` and locally omit definitions; snapshots retain only name, topic reference and expiration. Subscription projection now omits transforms, labels, filter contents and unknown fields. Best Practices flags only explicit `detached: true` or the exact `_deleted-topic_` marker. IAM & Access reports explicitly configured export writers/destinations for BigQuery, Cloud Storage and Bigtable, without inferring a default identity or effective write access. Conservative identifier validation can omit unusual export identities/names. No mutation, message access or replay is permitted. Historical changes, destination ownership, import-source configuration, service-specific audit coverage and full technique correlation remain gaps. The allowed list permissions are documented in [Pub/Sub roles](https://docs.cloud.google.com/iam/docs/roles-permissions/pubsub), and state/export fields in the [Subscription API](https://docs.cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions).

Compute image/snapshot coverage: global custom images and global/regional snapshots are enumerated with direct version-3 IAM policies. Regions come from `regions.list`, not a hardcoded list. Strict response projection omits raw encryption keys, disk content, labels and descriptions. `public_compute_disk_capabilities` distinguishes exact `compute.images.useReadOnly` / `compute.snapshots.useReadOnly` grants from metadata-only access and preserves conditions/audiences. Source use alone does not establish destination creation, decryption, restore, download or filesystem access. Instant/recoverable snapshots, recycle-bin policies, database-backup sharing and effective inherited authorization remain gaps. Allowed direct policy permissions are documented in [Compute IAM](https://docs.cloud.google.com/iam/docs/roles-permissions/compute); source-use prerequisites are documented in [disk creation](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/insert). No creation or restore request is sent.
