package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var publicIAPRoot = regexp.MustCompile(`^//iap\.googleapis\.com/projects/[0-9]+/(iap_web|iap_tunnel)(/.*)?$`)
var publicIAPWeb = regexp.MustCompile(`^/(?:compute(?:-[a-z][a-z0-9-]*)?|forwarding_rule(?:-[a-z][a-z0-9-]*)?|cloud_run-[a-z][a-z0-9-]*)(?:/services/[A-Za-z0-9_-]+)?$`)
var publicIAPAppEngine = regexp.MustCompile(`^/appengine-[A-Za-z0-9_-]+(?:/services/[A-Za-z0-9_-]+(?:/versions/[A-Za-z0-9_-]+)?)?$`)
var publicIAPInstances = regexp.MustCompile(`^/zones/[a-z][a-z0-9-]*(?:/instances/[A-Za-z0-9_-]+)?$`)
var publicIAPDestinations = regexp.MustCompile(`^/locations/[a-z][a-z0-9-]*(?:/destGroups/[A-Za-z0-9_-]+)?$`)

func publicIAPCapabilities(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType || !public(s(val(a, "principal"))) {
		return nil
	}
	typ, resource := s(val(a, "resourceType")), s(val(a, "resource"))
	permissions := []string{}
	scope := "iap_resource"
	if typ == "cloudresourcemanager.googleapis.com/Project" {
		if !projectCapabilityResource.MatchString(resource) {
			return nil
		}
		scope = "project"
		permissions = []string{"iap.webServiceVersions.accessViaIAP", "iap.tunnelInstances.accessViaIAP", "iap.tunnelDestGroups.accessViaIAP"}
	} else {
		if typ != "iap.googleapis.com/PolicyResource" {
			return nil
		}
		m := publicIAPRoot.FindStringSubmatch(resource)
		if m == nil {
			return nil
		}
		suffix := m[2]
		if m[1] == "iap_web" && (suffix == "" || publicIAPWeb.MatchString(suffix) || publicIAPAppEngine.MatchString(suffix)) {
			permissions = []string{"iap.webServiceVersions.accessViaIAP"}
		}
		if m[1] == "iap_tunnel" {
			if suffix == "" || publicIAPInstances.MatchString(suffix) {
				permissions = append(permissions, "iap.tunnelInstances.accessViaIAP")
			}
			if suffix == "" || publicIAPDestinations.MatchString(suffix) {
				permissions = append(permissions, "iap.tunnelDestGroups.accessViaIAP")
			}
		}
	}
	var out []Result
	for _, permission := range permissions {
		if !has(arr(val(a, "permissions")), permission) {
			continue
		}
		kind, detail := "web", "The allUsers web binding can permit access without Google sign-in where IAP's public-access mode applies; allAuthenticatedUsers requires an accepted Google identity. OAuth/Identity Platform (GCIP) mode, IAP enablement, ingress and independent backend authentication are not verified."
		if strings.HasPrefix(permission, "iap.tunnel") {
			kind = "tunnel"
			detail = "Tunnel access requires authentication and is not a tokenless network path. VM/destination reachability, firewall, OS Login or SSH/RDP credentials and any additional client permissions remain independent; tunnel permission is not OS authentication."
		}
		severity, status := "high", "no condition supplied on this binding"
		title := "IAP " + kind + " access permission is granted to a broad principal"
		if val(a, "condition") != nil {
			severity, status = "info", "public IAP bindings do not support conditions; supplied policy validity and applicability unknown"
			title = "IAP broad-principal permission has unsupported condition metadata"
		}
		out = append(out, result(severity, title, "Review exact IAP permission bindings separately from Compute or Cloud Run IAM; remove unintended broad access and verify configured authentication modes without invoking applications or opening tunnels.", inventory.Object{"resource": resource, "resource_type": typ, "binding_scope": scope, "principal": val(a, "principal"), "roles": val(a, "roles"), "permission": permission, "condition": val(a, "condition"), "condition_status": status, "backend_configuration": iapBackendContextEvidence(a, resource), "assessment": "Resolved allow-policy permission observation only, including custom roles. Project and parent bindings are not expanded into child resources. Optional exact backend context is configuration only, not effective ingress, active IAP enforcement or application authentication. Policy provenance, IAM deny and effective authorization remain unverified; indexed/supplied observations may be incomplete and direct IAP policy reads are not added to the exact Viewer baseline. No protected request or tunnel was opened. " + detail})...)
	}
	return out
}
