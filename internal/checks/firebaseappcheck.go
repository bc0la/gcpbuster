package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var appCheckServiceName = regexp.MustCompile(`^//firebaseappcheck\.googleapis\.com/projects/[0-9]+/services/(identitytoolkit|firebasedataconnect|firestore|firebasedatabase|firebasestorage|firebaseml|maps-backend|places|oauth2)\.googleapis\.com$`)
var appCheckResourcePolicyName = regexp.MustCompile(`^//firebaseappcheck\.googleapis\.com/projects/([0-9]+)/services/oauth2\.googleapis\.com/resourcePolicies/[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$`)
var appCheckOAuthTarget = regexp.MustCompile(`^//oauth2\.googleapis\.com/projects/([0-9]+)/oauthClients/[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$`)

func firebaseAppCheckResourceEnforcement(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/FirebaseAppCheckResourcePolicy" {
		return nil
	}
	policy := appCheckResourcePolicyName.FindStringSubmatch(a.Name)
	target, ok := val(a, "targetResource").(string)
	bound := appCheckOAuthTarget.FindStringSubmatch(target)
	if !ok || policy == nil || bound == nil || policy[1] != bound[1] {
		return nil
	}
	name, ok := val(a, "name").(string)
	if !ok || "//firebaseappcheck.googleapis.com/"+name != a.Name {
		return nil
	}
	mode, ok := val(a, "enforcementMode").(string)
	if !ok || (mode != "OFF" && mode != "UNENFORCED") {
		return nil
	}
	return result("info", "Firebase App Check resource policy configures non-enforcement", "Review whether this resource-specific exception is intended; its baseline mode overrides the service baseline. Verify resource existence and client compatibility independently before changing policy.", inventory.Object{
		"service_id": "oauth2.googleapis.com", "enforcement_mode": mode, "target_resource": target, "scope": "resource_specific_baseline_override",
		"assessment": "Explicit same-project iOS OAuth client policy configuration only. This baseline mode overrides the service-level baseline, but the target may not yet exist and runtime policy effect was not verified. OFF does not apply this App Check protection; UNENFORCED is monitoring-only. Independent authentication and authorization remain applicable. This is not evidence of anonymous access, data disclosure or authentication bypass. No OAuth token, login or application requests were performed.",
	})
}

func firebaseAppCheckEnforcement(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "gcpbuster.googleapis.com/FirebaseAppCheckService" || !appCheckServiceName.MatchString(a.Name) {
		return nil
	}
	if raw, exists := a.Resource.Data["name"]; exists {
		name, ok := raw.(string)
		if !ok || "//firebaseappcheck.googleapis.com/"+name != a.Name {
			return nil
		}
	}
	mode, ok := val(a, "enforcementMode").(string)
	if !ok || (mode != "OFF" && mode != "UNENFORCED") {
		return nil
	}
	metrics := "not_collected"
	if mode == "UNENFORCED" {
		metrics = "monitoring_only"
	}
	service := a.Name[strings.LastIndex(a.Name, "/")+1:]
	return result("info", "Firebase App Check service baseline protection is explicitly not enforced", "Review whether App Check enforcement is intended for this service, validate client compatibility and review resource-specific policies before changing enforcement.", inventory.Object{
		"service_id": service, "enforcement_mode": mode, "app_check_metrics": metrics,
		"assessment": "Observed service-level baseline configuration only; resource-specific policies and service eligibility are not evaluated. Other authentication, authorization and Firebase Security Rules remain independent. This does not establish anonymous access, readable data, an authentication bypass or the absence of other protections. Missing configuration is not treated as OFF; no application requests, token operations or data reads were performed.",
	})
}
