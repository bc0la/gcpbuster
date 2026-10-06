package checks

import (
	"fmt"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net"
	"strconv"
	"strings"
	"time"
)

func publicIAM(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, v := range arr(a.IAM["bindings"]) {
		bind := obj(v)
		for _, m := range arr(bind["members"]) {
			if public(s(m)) {
				sev := "high"
				title := "Public IAM binding"
				if s(m) == "allAuthenticatedUsers" {
					title = "IAM binding admits any Google-authenticated identity"
				}
				if bind["condition"] != nil {
					sev = "medium"
					title += " with a condition; effective access requires review"
				}
				out = append(out, Result{sev, title, inventory.Object{"role": bind["role"], "member": m, "condition": bind["condition"], "assessment": "configured grant; IAM deny, conditions, public access prevention and other controls may restrict effective access"}, "Remove broad members or document intentional public access; validate effective permissions."})
			}
		}
	}
	return out
}

func iamPrivileges(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	if a.Type == "iam.googleapis.com/Role" {
		roleName := s(val(a, "name"))
		if roleName == "" {
			roleName = inventory.RoleName(a.Name)
		}
		if strings.HasPrefix(roleName, "roles/") {
			return nil
		} // predefined roles are evaluated through their actual bindings
		if truth(val(a, "deleted")) {
			return nil
		}
		for _, p := range arr(val(a, "includedPermissions")) {
			x := strings.ToLower(s(p))
			if strings.HasSuffix(x, ".setiampolicy") || strings.HasSuffix(x, ".actas") || strings.HasSuffix(x, ".getaccesstoken") || strings.HasSuffix(x, ".signblob") || strings.HasSuffix(x, ".signjwt") || x == "iam.serviceaccountkeys.create" || x == "iam.roles.update" || x == "compute.instances.setmetadata" || x == "compute.projects.setcommoninstancemetadata" || x == "cloudbuild.builds.create" || x == "osconfig.patchjobs.exec" {
				out = append(out, Result{"medium", "Custom role contains an escalation-relevant permission", inventory.Object{"permission": p, "assessment": "role definition only; assigned principal, scope and prerequisites must be verified"}, "Review role bindings and remove unnecessary privilege-changing permissions."})
			}
		}
		return out
	}
	for _, v := range arr(a.IAM["bindings"]) {
		bind := obj(v)
		role := s(bind["role"])
		sev := ""
		title := ""
		switch role {
		case "roles/owner", "roles/editor":
			sev = "high"
			title = "Broad basic IAM role assigned"
		case "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin", "roles/iam.roleAdmin":
			sev = "high"
			title = "Privilege-changing IAM role assigned"
		case "roles/iam.serviceAccountUser", "roles/iam.workloadIdentityUser":
			sev = "medium"
			title = "Service-account use or impersonation grant requires review"
		}
		if sev != "" {
			out = append(out, Result{sev, title, inventory.Object{"role": role, "members": bind["members"], "condition": bind["condition"], "assessment": "potential privilege path; not an exploitability assertion"}, "Limit the role, resource scope and principals; review IAM conditions and inherited access."})
		}
	}
	return out
}

func federationTrust(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	if strings.HasSuffix(a.Type, "PoolProvider") {
		if b(val(a, "disabled")) || s(val(a, "state")) == "DELETED" {
			return nil
		}
		condition, conditionKnown := val(a, "attributeCondition").(string)
		_, conditionPresent := a.Resource.Data["attributeCondition"]
		if !conditionPresent || (conditionKnown && strings.TrimSpace(condition) == "") {
			out = result("medium", "Federation provider has no attribute condition", "Restrict the issuer's permitted tenants, subjects or repositories; verify mappings and IAM principal selectors.", inventory.Object{"issuer": val(a, "oidc", "issuerUri"), "assessment": "missing condition alone does not establish an exploitable trust"})
		} else if conditionKnown && literalTrueFederationCondition(condition) {
			out = result("medium", "Federation provider attribute condition is a literal true value", "Use a meaningful tenant, subject or repository restriction and separately review mappings, audiences and IAM selectors.", inventory.Object{"condition_assessment": "literal_true", "assessment": "A literal true attribute condition adds no admission restriction. Issuer token validation, mapped identities, IAM grants and other provider controls remain independent; no credential exchange or effective trust exploitation was tested."})
		}
	}
	for _, v := range arr(a.IAM["bindings"]) {
		bind := obj(v)
		for _, m := range arr(bind["members"]) {
			if strings.HasPrefix(s(m), "principalSet://") && strings.HasSuffix(s(m), "/*") {
				out = append(out, Result{"high", "IAM grant covers an entire federation pool", inventory.Object{"member": m, "role": bind["role"], "condition": bind["condition"]}, "Bind selected subjects or attributes and constrain provider admission."})
			}
		}
	}
	return out
}

// Recognize only the CEL boolean literal with whitespace/outer parentheses.
// Arbitrary expressions, comments, quoted strings and issuer policy are not
// evaluated; a nonempty expression is not assumed to be a sufficient guard.
func literalTrueFederationCondition(condition string) bool {
	condition = strings.TrimSpace(condition)
	for len(condition) >= 2 && condition[0] == '(' && condition[len(condition)-1] == ')' {
		condition = strings.TrimSpace(condition[1 : len(condition)-1])
	}
	return condition == "true"
}

func metadata(a inventory.Asset) inventory.Object {
	m := inventory.Object{}
	for _, v := range arr(val(a, "metadata", "items")) {
		x := obj(v)
		m[s(x["key"])] = x["value"]
	}
	return m
}
func computeMetadata(a inventory.Asset, _ time.Time) []Result {
	m := metadata(a)
	var out []Result
	// GCE's v0.1/v1beta1 metadata endpoints were shut down in 2020.
	// A custom legacy-endpoint key cannot establish a live IMDSv1-like
	// exposure; do not mechanically translate AWS HttpTokens findings.
	for _, k := range []string{"serial-port-enable"} {
		if truth(m[k]) {
			out = append(out, Result{"medium", "VM metadata enables " + k, inventory.Object{"metadata_key": k}, "Disable this metadata option unless explicitly required."})
		}
	}
	for _, k := range []string{"enable-oslogin", "block-project-ssh-keys"} {
		if strings.EqualFold(s(m[k]), "false") {
			out = append(out, Result{"medium", "VM explicitly disables " + k, inventory.Object{"metadata_key": k}, "Use OS Login and limit project-wide SSH keys."})
		}
	}
	if isFalse(val(a, "shieldedInstanceConfig", "enableVtpm")) || isFalse(val(a, "shieldedInstanceConfig", "enableIntegrityMonitoring")) {
		out = append(out, Result{"low", "Shielded VM integrity controls explicitly disabled", nil, "Enable vTPM and integrity monitoring where supported."})
	}
	for _, sa := range arr(val(a, "serviceAccounts")) {
		x := obj(sa)
		if has(x["scopes"], "https://www.googleapis.com/auth/cloud-platform") {
			out = append(out, Result{"info", "VM service account has cloud-platform OAuth scope", inventory.Object{"service_account": x["email"], "assessment": "scope is recommended with least-privilege IAM; not itself a vulnerability"}, "Validate the attached service account's IAM grants and workload isolation."})
		}
	}
	return out
}
func gkeSecurity(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	if s(val(a, "masterAuth", "username")) != "" || s(val(a, "masterAuth", "password")) != "" {
		out = append(out, Result{"high", "GKE legacy basic authentication configured", nil, "Disable basic authentication and use IAM/RBAC."})
	}
	if b(val(a, "legacyAbac", "enabled")) {
		out = append(out, Result{"high", "GKE legacy ABAC enabled", nil, "Disable ABAC and use scoped RBAC."})
	}
	if !b(val(a, "autopilot", "enabled")) && s(val(a, "workloadIdentityConfig", "workloadPool")) == "" {
		out = append(out, Result{"medium", "GKE workload identity pool not configured", nil, "Enable Workload Identity Federation for GKE and scope workload access."})
	}
	for _, v := range arr(val(a, "nodePools")) {
		p := obj(v)
		mode := s(inventory.Get(p, "config", "workloadMetadataConfig", "mode"))
		if mode == "GCE_METADATA" {
			out = append(out, Result{"high", "GKE node pool exposes Compute Engine metadata", inventory.Object{"node_pool": p["name"]}, "Use GKE_METADATA and workload identities."})
		}
	}
	return out
}
func storageHardening(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	if !b(val(a, "iamConfiguration", "uniformBucketLevelAccess", "enabled")) {
		out = append(out, Result{"medium", "Uniform bucket-level access is not enabled", nil, "Enable uniform bucket-level access after migrating ACLs."})
	}
	if s(val(a, "iamConfiguration", "publicAccessPrevention")) != "enforced" {
		out = append(out, Result{"info", "Bucket does not locally enforce public access prevention", inventory.Object{"assessment": "organization policy inheritance may enforce this control"}, "Confirm effective organization policy or enforce public access prevention on the bucket."})
	}
	return out
}
func sqlHardening(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	mode := s(val(a, "settings", "ipConfiguration", "sslMode"))
	if mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED" || (mode == "" && isFalse(val(a, "settings", "ipConfiguration", "requireSsl"))) {
		out = append(out, Result{"medium", "Cloud SQL allows unencrypted connections", nil, "Require encrypted connections with the supported SSL mode."})
	}
	if isFalse(val(a, "settings", "backupConfiguration", "enabled")) {
		out = append(out, Result{"medium", "Cloud SQL automated backups explicitly disabled", nil, "Enable backups and appropriate point-in-time recovery."})
	}
	// Explicit booleans only: omitted/malformed fields do not establish that
	// a control is disabled. These configuration indicators do not test users
	// or infer the password of a default root account.
	if disabled, ok := val(a, "settings", "deletionProtectionEnabled").(bool); ok && !disabled {
		out = append(out, Result{"low", "Cloud SQL deletion protection explicitly disabled", inventory.Object{"assessment": "Accidental-deletion safeguard only; other IAM or recovery controls may apply."}, "Enable deletion protection for instances that should be protected against accidental deletion."})
	}
	engine := s(val(a, "databaseVersion"))
	if strings.HasPrefix(engine, "MYSQL_") || strings.HasPrefix(engine, "POSTGRES_") {
		if enabled, ok := val(a, "settings", "passwordValidationPolicy", "enablePasswordPolicy").(bool); ok && !enabled {
			out = append(out, Result{"medium", "Cloud SQL local-user password policy explicitly disabled", inventory.Object{"database_version": engine, "assessment": "Instance-local password policy only; existing password strength, IAM authentication and external controls are not tested."}, "Review local-user requirements and enable an engine-supported password policy. Do not assume any current user has a weak or empty password."})
		}
	}
	out = append(out, sqlConfigurationPosture(a)...)
	return out
}
func auditLogging(a inventory.Asset, _ time.Time) []Result {
	if inventory.Bool(a.IAM["_gcpbusterBindingsOnly"]) {
		return nil
	}
	if a.Type != "cloudresourcemanager.googleapis.com/Project" && a.Type != "cloudresourcemanager.googleapis.com/Folder" && a.Type != "cloudresourcemanager.googleapis.com/Organization" {
		return nil
	}
	var out []Result
	read, write := false, false
	for _, v := range arr(a.IAM["auditConfigs"]) {
		c := obj(v)
		for _, x := range arr(c["auditLogConfigs"]) {
			l := obj(x)
			if s(c["service"]) == "allServices" {
				read = read || s(l["logType"]) == "DATA_READ"
				write = write || s(l["logType"]) == "DATA_WRITE"
			}
			if len(arr(l["exemptedMembers"])) > 0 {
				out = append(out, Result{"medium", "Data Access audit configuration exempts principals", inventory.Object{"service": c["service"], "log_type": l["logType"], "members": l["exemptedMembers"]}, "Review exemptions against effective inherited audit policy."})
			}
		}
	}
	if !read || !write {
		out = append(out, Result{"info", "No complete all-services Data Access configuration in this direct policy", inventory.Object{"assessment": "inherited and service-specific configuration not resolved; BigQuery Data Access has separate defaults"}, "Review effective DATA_READ/DATA_WRITE coverage across ancestors and individual services."})
	}
	return out
}
func loggingSinks(a inventory.Asset, _ time.Time) []Result {
	if a.Type == "logging.googleapis.com/LogSink" && b(val(a, "disabled")) {
		return result("medium", "Logging sink is disabled", "Confirm another enabled route preserves required audit records.", nil)
	}
	if a.Type == "logging.googleapis.com/LogExclusion" && !b(val(a, "disabled")) {
		return result("medium", "Active log exclusion requires review", "Review excluded log classes and retain security-relevant records.", inventory.Object{"assessment": "active exclusion; scope and impact need review"})
	}
	for _, v := range arr(val(a, "exclusions")) {
		if !b(obj(v)["disabled"]) {
			return result("medium", "Logging sink has an active exclusion", "Review exclusions against required security logging; other sinks may preserve the same records.", nil)
		}
	}
	return nil
}

func identityPlatform(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	anonymous := b(val(a, "signIn", "anonymous", "enabled")) || b(val(a, "allowAnonymousSignup"))
	mfa := s(val(a, "mfa", "state"))
	if a.Type == "identitytoolkit.googleapis.com/Tenant" {
		if b(val(a, "disableAuth")) {
			return nil
		}
		if value, exists := a.Resource.Data["enableAnonymousUser"]; exists {
			anonymous = b(value)
		}
		if value, exists := a.Resource.Data["mfaConfig"]; exists {
			mfa = s(obj(value)["state"])
		}
	}
	if anonymous {
		out = append(out, Result{"medium", "Identity Platform anonymous sign-in enabled", nil, "Confirm anonymous access is intended and Firebase/application authorization rules limit its capabilities."})
	}
	if mfa == "DISABLED" {
		out = append(out, Result{"medium", "Identity Platform MFA explicitly disabled", nil, "Enable appropriate MFA for sensitive application accounts."})
	}
	return out
}
func dnsSecurity(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "dns.googleapis.com/ManagedZone" || s(val(a, "visibility")) != "public" {
		return nil
	}
	if s(val(a, "dnssecConfig", "state")) == "off" {
		return result("low", "Public Cloud DNS zone has DNSSEC disabled", "Enable DNSSEC and publish the matching DS record at the registrar.", nil)
	}
	return nil
}

func dnsDangling(a inventory.Asset, _ time.Time) []Result {
	status := s(val(a, "targetStatus"))
	target, valid := inventory.DNSLookupName(s(val(a, "target")))
	visibility := s(val(a, "zoneVisibility"))
	if a.Type == "dns.googleapis.com/ResourceRecordSet" && valid && s(val(a, "type")) == "CNAME" && ((status == "address_not_found" && visibility == "public") || (status == "NXDOMAIN" && (visibility == "public" || visibility == ""))) {
		return result("medium", "DNS CNAME target did not resolve", "Validate authoritative DNS and service ownership; remove stale aliases. Nonresolution alone does not prove the target can be claimed.", inventory.Object{"target": target, "resolution_status": status, "observed_service_context": dnsObservedServiceEvidence(a, target), "assessment": "Address lookup found no record; NXDOMAIN versus no-address data is not established by LookupHost. Historical offline NXDOMAIN labels are accepted but not independently verified. Dangling-record candidate only; takeover and domain ownership not confirmed."})
	}
	return nil
}
func vertexPosture(a inventory.Asset, _ time.Time) []Result {
	network := s(val(a, "network"))
	if a.Type == "aiplatform.googleapis.com/CustomJob" {
		network = s(val(a, "jobSpec", "network"))
	}
	if network == "" {
		return result("info", "Vertex AI job has no customer VPC network configured", "Review training/pipeline data access and egress requirements, service-account IAM and perimeter controls.", inventory.Object{"assessment": "absence of VPC peering is a review item, not evidence of a public endpoint"})
	}
	return nil
}
func storageACL(a inventory.Asset, _ time.Time) []Result {
	if b(val(a, "iamConfiguration", "uniformBucketLevelAccess", "enabled")) {
		return nil
	}
	var out []Result
	for _, field := range []string{"acl", "defaultObjectAcl"} {
		for _, v := range arr(val(a, field)) {
			x := obj(v)
			if public(s(x["entity"])) {
				out = append(out, Result{"high", "Public legacy storage ACL", inventory.Object{"acl_type": field, "entity": x["entity"], "role": x["role"], "assessment": "default ACL applies to newly created objects; public access prevention may block access"}, "Remove public ACL entries and enable uniform bucket-level access."})
			}
		}
	}
	return out
}
func firewallIngress(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "compute.googleapis.com/Firewall" {
		return nil
	}
	d := a.Resource.Data
	if raw, exists := d["disabled"]; exists {
		v, ok := raw.(bool)
		if !ok || v {
			return nil
		}
	}
	if raw, exists := d["direction"]; exists {
		if direction, ok := raw.(string); !ok || direction != "INGRESS" {
			return nil
		}
	}
	// API defaults apply only to omitted/valid empty fields, not malformed
	// values. In particular, malformed source filters must not become /0.
	stringsField := func(field string) ([]any, bool) {
		raw, exists := d[field]
		if !exists {
			return nil, true
		}
		rows, ok := raw.([]any)
		if !ok {
			return nil, false
		}
		for _, raw := range rows {
			v, ok := raw.(string)
			if !ok || v == "" || strings.TrimSpace(v) != v {
				return nil, false
			}
		}
		return rows, true
	}
	selectors := map[string][]any{}
	for _, field := range []string{"sourceRanges", "destinationRanges", "sourceTags", "sourceServiceAccounts", "targetTags", "targetServiceAccounts"} {
		rows, ok := stringsField(field)
		if !ok {
			return nil
		}
		selectors[field] = rows
	}
	if (len(selectors["sourceTags"])+len(selectors["targetTags"]) > 0) && (len(selectors["sourceServiceAccounts"])+len(selectors["targetServiceAccounts"]) > 0) {
		return nil
	}
	if raw, exists := d["priority"]; exists {
		p, ok := raw.(float64)
		if !ok || p < 0 || p > 65535 || p != float64(int(p)) {
			return nil
		}
	}
	if raw, exists := d["denied"]; exists {
		denied, ok := raw.([]any)
		if !ok || len(denied) != 0 {
			return nil
		}
	}
	ranges := selectors["sourceRanges"]
	worldRanges := []string{}
	ipBits := 0
	for _, field := range []string{"sourceRanges", "destinationRanges"} {
		for _, raw := range selectors[field] {
			_, cidr, err := net.ParseCIDR(s(raw))
			if err != nil {
				return nil
			}
			ones, bits := cidr.Mask.Size()
			if ipBits != 0 && bits != ipBits {
				return nil
			}
			ipBits = bits
			if field == "sourceRanges" && ones == 0 {
				worldRanges = append(worldRanges, cidr.String())
			}
		}
	}
	defaultSources := len(ranges) == 0 && len(selectors["sourceTags"]) == 0 && len(selectors["sourceServiceAccounts"]) == 0
	if defaultSources {
		// Omitted ingress sources default to IPv4, not IPv6.
		if ipBits == 128 {
			return nil
		}
		worldRanges = []string{"0.0.0.0/0"}
	}
	if len(worldRanges) == 0 {
		return nil
	}
	allowed, ok := d["allowed"].([]any)
	if !ok || len(allowed) == 0 {
		return nil
	}
	cleanAllowed := []any{}
	decimal := func(v string, max int) (int, bool) {
		if v == "" {
			return 0, false
		}
		for _, ch := range v {
			if ch < '0' || ch > '9' {
				return 0, false
			}
		}
		n, err := strconv.Atoi(v)
		return n, err == nil && n >= 0 && n <= max
	}
	for _, raw := range allowed {
		row := obj(raw)
		protocol, ok := row["IPProtocol"].(string)
		if !ok {
			return nil
		}
		named := map[string]bool{"all": true, "tcp": true, "udp": true, "icmp": true, "esp": true, "ah": true, "ipip": true, "sctp": true}
		protocolNumber, numeric := decimal(protocol, 255)
		if !named[protocol] && !numeric {
			return nil
		}
		// IPv6 Hop-by-Hop (protocol 0) is explicitly unsupported by VPC rules.
		if numeric && protocolNumber == 0 {
			return nil
		}
		clean := inventory.Object{"IPProtocol": protocol}
		if raw, exists := row["ports"]; exists {
			ports, ok := raw.([]any)
			if !ok {
				return nil
			}
			if len(ports) > 0 && protocol != "tcp" && protocol != "udp" && !(numeric && (protocolNumber == 6 || protocolNumber == 17)) {
				return nil
			}
			for _, raw := range ports {
				port, ok := raw.(string)
				if !ok {
					return nil
				}
				parts := strings.Split(port, "-")
				if len(parts) > 2 {
					return nil
				}
				lo, valid := decimal(parts[0], 65535)
				if !valid {
					return nil
				}
				if len(parts) == 2 {
					hi, valid := decimal(parts[1], 65535)
					if !valid || hi < lo {
						return nil
					}
				}
			}
			clean["ports"] = ports
		}
		cleanAllowed = append(cleanAllowed, clean)
	}
	// Source ranges and source tags/service accounts are ORed, not ANDed.
	// https://docs.cloud.google.com/firewall/docs/firewalls
	return result("high", "Firewall configures world-source ingress allowance", "Review whether these source networks and protocols/ports are intended. Evaluate effective policy priority, matching targets, destination restrictions and routing before concluding that an endpoint is exposed.", inventory.Object{"allowed": cleanAllowed, "source_ranges": ranges, "world_source_ranges": worldRanges, "default_source_range": defaultSources, "source_tags": selectors["sourceTags"], "source_service_accounts": selectors["sourceServiceAccounts"], "destination_ranges": selectors["destinationRanges"], "target_tags": selectors["targetTags"], "target_service_accounts": selectors["targetServiceAccounts"], "priority": val(a, "priority"), "assessment": "Configured enabled ingress allow rule only; not a reachability test. Source ranges and source tags/service accounts are alternatives (OR): source identity filters do not narrow an explicit world range. Targets and destinations can still restrict applicability. Higher-priority rules, hierarchical/network firewall policies, matching interfaces, routes, external addresses, listening services and actual traffic are not evaluated."})
}
func publicCompute(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, v := range arr(val(a, "networkInterfaces")) {
		n := obj(v)
		for _, f := range []string{"accessConfigs", "ipv6AccessConfigs"} {
			for _, c := range arr(n[f]) {
				x := obj(c)
				ip := s(x["natIP"])
				if ip == "" {
					ip = s(x["externalIpv6"])
				}
				if ip != "" {
					out = append(out, Result{"info", "VM has an external address", inventory.Object{"address": ip, "network_configuration": computeIngressContextEvidence(a), "assessment": "routing/firewall/service reachability not tested"}, "Confirm the external address is required and restrict ingress."})
				}
			}
		}
	}
	return out
}
func publicSQL(a inventory.Asset, now time.Time) []Result {
	var out []Result
	for _, v := range arr(val(a, "ipAddresses")) {
		x := obj(v)
		if s(x["type"]) == "PRIMARY" && net.ParseIP(s(x["ipAddress"])) != nil {
			out = append(out, Result{"medium", "Cloud SQL has a public address", inventory.Object{"address": x["ipAddress"], "assessment": "authentication and network authorization remain applicable"}, "Prefer private connectivity or restrict authorized networks and enforce TLS."})
		}
	}
	return append(out, sqlAuthorizedNetworks(a, now)...)
}
func gkeIPEndpoint(a inventory.Asset) []Result {
	private := b(val(a, "privateClusterConfig", "enablePrivateEndpoint"))
	ipConfig := obj(val(a, "controlPlaneEndpointsConfig", "ipEndpointsConfig"))
	if isFalse(ipConfig["enabled"]) {
		return nil
	}
	publicConfig := val(a, "controlPlaneEndpointsConfig", "ipEndpointsConfig", "enablePublicEndpoint")
	if private || isFalse(publicConfig) {
		return nil
	}
	if s(val(a, "privateClusterConfig", "publicEndpoint")) == "" && s(ipConfig["publicEndpoint"]) == "" && !b(publicConfig) && s(val(a, "endpoint")) == "" {
		return nil
	}
	networks := obj(val(a, "masterAuthorizedNetworksConfig"))
	if newer := obj(ipConfig["authorizedNetworksConfig"]); newer != nil {
		networks = newer
	}
	if b(networks["enabled"]) && !hasCIDR(networks["cidrBlocks"], "0.0.0.0/0") && !hasCIDR(networks["cidrBlocks"], "::/0") {
		return nil
	}
	return result("medium", "GKE IP control-plane endpoint may accept broad network access", "Use private endpoints or restrictive authorized networks; check newer endpoint controls and IAM/RBAC.", inventory.Object{"assessment": "configuration review; endpoint reachability and authentication not tested"})
}
func hasCIDR(v any, cidr string) bool {
	for _, x := range arr(v) {
		if s(obj(x)["cidrBlock"]) == cidr {
			return true
		}
	}
	return false
}
func publicBigQuery(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, v := range arr(val(a, "access")) {
		x := obj(v)
		if s(x["specialGroup"]) == "allAuthenticatedUsers" || public(s(x["iamMember"])) {
			severity, title := "high", "BigQuery dataset grants public access"
			assessment := "Configured public-principal access; not a table-data or effective-access probe."
			if x["condition"] != nil {
				severity, title = "medium", "BigQuery dataset has a conditional public-principal grant"
				assessment = "Condition is preserved but not evaluated; unconditional access is not established."
				if strings.TrimSpace(s(inventory.Get(x, "condition", "expression"))) == "" {
					title = "BigQuery public-principal grant has unverified condition metadata"
					assessment = "Malformed or incomplete condition metadata; neither valid conditionality nor unconditional access is established. Refresh the dataset policy."
				}
			}
			out = append(out, Result{severity, title, inventory.Object{"access": x, "assessment": assessment}, "Remove unintended public dataset grants; review conditions and effective dataset/table authorization."})
		}
	}
	return out
}
func publicServerless(a inventory.Asset, _ time.Time) []Result {
	if b(val(a, "invokerIamDisabled")) || truth(val(a, "metadata", "annotations", "run.googleapis.com/invoker-iam-disabled")) {
		return result("high", "Cloud Run invoker IAM check disabled", "Enable the invoker IAM check or document alternative authentication and intended exposure.", inventory.Object{"assessment": "ingress controls and application authentication can still restrict access"})
	}
	return nil
}
func serviceAccountKeys(a inventory.Asset, now time.Time) []Result {
	if s(val(a, "keyType")) != "USER_MANAGED" || b(val(a, "disabled")) {
		return nil
	}
	if exp, err := time.Parse(time.RFC3339, s(val(a, "validBeforeTime"))); err == nil && !exp.After(now) {
		return nil
	}
	sev := "medium"
	title := "Active user-managed service-account key"
	e := inventory.Object{}
	if created, err := time.Parse(time.RFC3339, s(val(a, "validAfterTime"))); err == nil {
		days := int(now.Sub(created).Hours() / 24)
		e["age_days"] = days
		if days > 90 {
			sev = "high"
			title = "User-managed service-account key older than 90 days"
		}
	}
	return result(sev, title, "Prefer short-lived federation credentials; rotate and remove unused keys.", e)
}
func apiKeys(a inventory.Asset, _ time.Time) []Result {
	r, valid := apiKeyRestrictionMetadata(a)
	if !valid {
		return nil
	}
	var missing []string
	var out []Result
	if len(arr(r["apiTargets"])) == 0 {
		missing = append(missing, "API targets")
	}
	if r["browserKeyRestrictions"] == nil && r["serverKeyRestrictions"] == nil && r["androidKeyRestrictions"] == nil && r["iosKeyRestrictions"] == nil {
		missing = append(missing, "application restrictions")
	}
	if len(missing) > 0 {
		out = append(out, result("medium", fmt.Sprintf("API key lacks %s", strings.Join(missing, " and ")), "Restrict the API key to required APIs and applications; do not use API keys as user authorization.", nil)...)
	}
	return append(out, apiKeyUnrestrictedServerSources(a)...)
}
