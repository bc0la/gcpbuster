package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

const WorkloadGrantType = "gcpbuster.googleapis.com/WorkloadIdentityGrant"

var serviceAccountEmail = regexp.MustCompile(`^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com$`)
var secretBuiltInPrincipal = regexp.MustCompile(`^principal://secretmanager\.googleapis\.com/projects/([0-9]+)/(uid|name)/locations/([a-z][a-z0-9-]*)/secrets/([A-Za-z0-9_-]+)$`)

type attachedIdentity struct {
	email, field    string
	principal, kind string
	scopes          any
}

func workloadIdentities(a Asset) ([]attachedIdentity, bool) {
	var out []attachedIdentity
	add := func(field string, value any, scopes any) {
		email := Str(value)
		if strings.HasPrefix(email, "projects/") && strings.Contains(email, "/serviceAccounts/") {
			email = strings.SplitN(email, "/serviceAccounts/", 2)[1]
		}
		if serviceAccountEmail.MatchString(email) {
			out = append(out, attachedIdentity{email: email, field: field, scopes: scopes, principal: "serviceAccount:" + email, kind: "service_account"})
		}
	}
	d := a.Resource.Data
	switch a.Type {
	case "appengine.googleapis.com/Version":
		// The explicit version identity is not inferred from an application's
		// default service account or from the Appspot naming convention.
		if email := Str(d["serviceAccount"]); serviceAccountEmail.MatchString(email) {
			add("serviceAccount", email, nil)
		}
	case "apigateway.googleapis.com/ApiConfig":
		// Only the documented bare email form can be resolved locally; UID
		// references are joined to observed account records by the correlator.
		if email := Str(d["gatewayServiceAccount"]); serviceAccountEmail.MatchString(email) {
			add("gatewayServiceAccount", email, nil)
		}
	case "compute.googleapis.com/Instance", "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/MachineImage":
		path := "serviceAccounts"
		config := d
		if a.Type == "compute.googleapis.com/InstanceTemplate" {
			config = Obj(d["properties"])
			path = "properties.serviceAccounts"
		}
		if a.Type == "compute.googleapis.com/MachineImage" {
			config = Obj(d["instanceProperties"])
			path = "instanceProperties.serviceAccounts"
		}
		for _, v := range List(config["serviceAccounts"]) {
			x := Obj(v)
			add(path, x["email"], x["scopes"])
		}
	case "run.googleapis.com/Service":
		add("template.serviceAccount", Get(d, "template", "serviceAccount"), nil)
		add("spec.template.spec.serviceAccountName", Get(d, "spec", "template", "spec", "serviceAccountName"), nil)
	case "run.googleapis.com/Job":
		add("template.template.serviceAccount", Get(d, "template", "template", "serviceAccount"), nil)
		add("spec.template.spec.template.spec.serviceAccountName", Get(d, "spec", "template", "spec", "template", "spec", "serviceAccountName"), nil)
	case "cloudfunctions.googleapis.com/CloudFunction":
		add("serviceAccountEmail", d["serviceAccountEmail"], nil)
	case "cloudfunctions.googleapis.com/Function":
		add("serviceConfig.serviceAccountEmail", Get(d, "serviceConfig", "serviceAccountEmail"), nil)
	case "cloudbuild.googleapis.com/Build":
		add("serviceAccount", d["serviceAccount"], nil)
	case "workflows.googleapis.com/Workflow":
		add("serviceAccount", d["serviceAccount"], nil)
	case "composer.googleapis.com/Environment":
		// The environment worker identity is distinct from the Google-managed
		// Composer service agent. Never infer either from the project number.
		add("config.nodeConfig.serviceAccount", Get(d, "config", "nodeConfig", "serviceAccount"), Get(d, "config", "nodeConfig", "oauthScopes"))
	case "secretmanager.googleapis.com/Secret":
		// Only the reviewed regional typed-secret identity is supported. The
		// identity itself is not proof that rotation is enabled or functional.
		if Str(d["secretType"]) != "CLOUD_SQL_DB_CREDENTIALS" {
			return nil, false
		}
		name := strings.TrimPrefix(a.Name, "//secretmanager.googleapis.com/")
		parts := strings.Split(name, "/")
		if !strings.HasPrefix(a.Name, "//secretmanager.googleapis.com/") || len(parts) != 6 || parts[0] != "projects" || !projectNumberPattern.MatchString("projects/"+parts[1]) || parts[2] != "locations" || !viewerLocation.MatchString(parts[3]) || parts[3] == "global" || parts[4] != "secrets" || !viewerKeyResourceID.MatchString(parts[5]) || Str(d["name"]) != name {
			return nil, true
		}
		if a.Resource.Location != "" && a.Resource.Location != parts[3] {
			return nil, true
		}
		for _, field := range []string{"iamPolicyUidPrincipal", "iamPolicyNamePrincipal"} {
			principal := Str(Get(d, "policyMember", field))
			p := secretBuiltInPrincipal.FindStringSubmatch(principal)
			mode := "uid"
			if field == "iamPolicyNamePrincipal" {
				mode = "name"
			}
			if len(p) != 5 || p[1] != parts[1] || p[2] != mode || p[3] != parts[3] || (mode == "name" && p[4] != parts[5]) {
				continue
			}
			out = append(out, attachedIdentity{field: "policyMember." + field, principal: principal, kind: "resource_" + mode})
		}
	case "container.googleapis.com/Cluster":
		for _, v := range List(d["nodePools"]) {
			p := Obj(v)
			add("nodePools."+Str(p["name"])+".config.serviceAccount", Get(p, "config", "serviceAccount"), Get(p, "config", "oauthScopes"))
		}
	default:
		return nil, false
	}
	return out, true
}

// CorrelateWorkloadGrants joins explicit workload identities to direct grants.
// It does not infer default service accounts, merge grant conditions, expand
// inherited/group permissions, or claim a workload can exercise every grant.
func CorrelateWorkloadGrants(snap *Snapshot) {
	grants := map[string][]Asset{}
	for _, a := range snap.Assets {
		if a.Type != PermissionGrantType {
			continue
		}
		principal := Str(a.Resource.Data["principal"])
		if (strings.HasPrefix(principal, "serviceAccount:") && serviceAccountEmail.MatchString(strings.TrimPrefix(principal, "serviceAccount:"))) || secretBuiltInPrincipal.MatchString(principal) {
			grants[principal] = append(grants[principal], a)
		}
	}
	assets := append([]Asset(nil), snap.Assets...)
	missingIdentity, missingGrants := 0, 0
	for _, a := range assets {
		if a.Resource.Data == nil {
			continue
		}
		identities, supported := workloadIdentities(a)
		if a.Type == "apigateway.googleapis.com/ApiConfig" && len(identities) == 0 {
			if email := resolveGatewayAccountUID(a, assets); email != "" {
				identities = []attachedIdentity{{email: email, field: "gatewayServiceAccount", principal: "serviceAccount:" + email, kind: "service_account"}}
			}
		}
		if !supported {
			continue
		}
		if len(identities) == 0 {
			missingIdentity++
			continue
		}
		for ii, id := range identities {
			if len(grants[id.principal]) == 0 {
				missingGrants++
				continue
			}
			for gi, grant := range grants[id.principal] {
				d := grant.Resource.Data
				data := Object{"workload": a.Name, "workloadType": a.Type, "principal": id.principal, "identityKind": id.kind, "identityField": id.field, "oauthScopes": id.scopes, "grantResource": d["resource"], "roles": d["roles"], "permissions": d["permissions"], "condition": d["condition"]}
				if id.email != "" {
					data["serviceAccount"] = id.email
				}
				x := NewAsset(fmt.Sprintf("%s/workload-grants/%d/%d", a.Name, ii, gi), WorkloadGrantType, data)
				x.Ancestors = a.Ancestors
				snap.Assets = append(snap.Assets, x)
			}
		}
	}
	if missingIdentity > 0 {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "workload-identities:unresolved", Status: "notice", Count: missingIdentity, Error: "Supported records lack a validated explicit service-account email or regional typed-secret policyMember principal. Defaults, malformed/missing identities and intentionally identity-free workloads need separate review; no identity or UID/name alias was guessed."})
	}
	if missingGrants > 0 {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "workload-identities:grants", Status: "notice", Count: missingGrants, Error: "Attached identities have no resolved direct grants in supplied inventory. Cross-project, ancestor, group and missing-role evidence may be absent; this is not proof of least privilege."})
	}
}
