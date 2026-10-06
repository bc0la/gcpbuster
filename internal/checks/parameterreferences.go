package checks

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const ParameterReferenceType = "gcpbuster.googleapis.com/ParameterReferenceDelegation"

var parameterVersionName = regexp.MustCompile(`^//parametermanager\.googleapis\.com/projects/([A-Za-z0-9_-]+)/locations/([a-z][a-z0-9-]*)/parameters/([A-Za-z0-9_-]+)/versions/[A-Za-z0-9_-]+$`)
var parameterUID = regexp.MustCompile(`^principal://parametermanager\.googleapis\.com/projects/([0-9]+)/uid/locations/([a-z][a-z0-9-]*)/parameters/[A-Za-z0-9_-]+$`)
var parameterREF = regexp.MustCompile(`__REF__\(\s*(?:"(//secretmanager\.googleapis\.com/projects/[A-Za-z0-9_-]+/(?:locations/[a-z][a-z0-9-]*/)?secrets/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+)"|'(//secretmanager\.googleapis\.com/projects/[A-Za-z0-9_-]+/(?:locations/[a-z][a-z0-9-]*/)?secrets/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+)'|(//secretmanager\.googleapis\.com/projects/[A-Za-z0-9_-]+/(?:locations/[a-z][a-z0-9-]*/)?secrets/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+))\s*\)`)

// An entire canonical stored REF expression is reference metadata, not a
// recovered credential. Mixed configuration retains normal candidate checks.
func parameterReferenceExpression(value string) bool {
	match := parameterREF.FindStringSubmatch(value)
	if len(match) != 4 || match[0] != value {
		return false
	}
	target := ""
	for _, part := range match[1:] {
		if part != "" {
			target = part
		}
	}
	version := target[strings.LastIndex(target, "/")+1:]
	return validParameterReferenceVersion(version)
}

func validParameterReferenceVersion(version string) bool {
	return len(version) <= 63 && !strings.EqualFold(version, "new") && !strings.HasPrefix(version, "-") && (version == "latest" || regexp.MustCompile(`^(?:[1-9][0-9]*|[A-Za-z][A-Za-z0-9_-]*)$`).MatchString(version))
}

// ParameterReferenceAssets retains only canonical stored references and static
// prerequisite evidence. It does not render, fetch referenced versions, infer
// inaccessible grants, or retain arbitrary surrounding configuration bytes.
func ParameterReferenceAssets(samples []inventory.SecretSample, assets []inventory.Asset, redact bool) []inventory.Asset {
	// Expand into a private slice so reference-only selection has the same
	// observed grant evidence without duplicating rows in the caller snapshot.
	derived := inventory.Snapshot{Assets: append([]inventory.Asset(nil), assets...)}
	inventory.ExpandBindings(&derived)
	assets = derived.Assets
	out := []inventory.Asset{}
	for _, sample := range samples {
		parts := parameterVersionName.FindStringSubmatch(sample.Resource)
		if sample.SourceType != "parameter_manager_raw" || sample.Path != "payload.data" || len(parts) != 4 || len(sample.Data) > 4<<20 || !utf8.Valid(sample.Data) || !strings.Contains(string(sample.Data), "__REF__") {
			continue
		}
		parameter := sample.Resource[:strings.LastIndex(sample.Resource, "/versions/")]
		identity, identityState, format := "", "UNKNOWN", "UNKNOWN"
		seenParameter := false
		for _, a := range assets {
			if a.Type != "parametermanager.googleapis.com/Parameter" || a.Name != parameter {
				continue
			}
			principal := inventory.Str(inventory.Get(a.Resource.Data, "policyMember", "iamPolicyUidPrincipal"))
			p := parameterUID.FindStringSubmatch(principal)
			valid := len(p) == 3 && p[1] == parts[1] && p[2] == parts[2] && inventory.Str(a.Resource.Data["name"]) == strings.TrimPrefix(parameter, "//parametermanager.googleapis.com/") && (a.Resource.Location == "" || a.Resource.Location == parts[2])
			if !valid || seenParameter && principal != identity {
				identityState = "CONFLICT_OR_MALFORMED"
				identity = ""
				break
			}
			seenParameter = true
			identity, identityState = principal, "OBSERVED_UID"
			if value := inventory.Str(a.Resource.Data["format"]); value == "JSON" || value == "YAML" || value == "UNFORMATTED" {
				format = value
			}
		}
		text := parameterReferenceText(sample.Data)
		matches := parameterREF.FindAllStringSubmatch(text, 16)
		status := "STORED_REFERENCE"
		if len(matches) == 0 || len(matches) > 15 || strings.Count(text, "__REF__") != len(matches) {
			status = "MALFORMED_OR_BOUNDED_REFERENCES"
		}
		targets := map[string]bool{}
		for _, match := range matches {
			target := ""
			for _, part := range match[1:] {
				if part != "" {
					target = part
				}
			}
			version := target[strings.LastIndex(target, "/")+1:]
			if !validParameterReferenceVersion(version) {
				status = "MALFORMED_OR_BOUNDED_REFERENCES"
				continue
			}
			targets[target] = true
		}
		ordered := []string{}
		for target := range targets {
			ordered = append(ordered, target)
		}
		sort.Strings(ordered)
		if len(ordered) == 0 {
			ordered = []string{""}
		}
		for index, target := range ordered {
			secret := ""
			if target != "" {
				secret = target[:strings.LastIndex(target, "/versions/")]
			}
			identityGrants, callerGrants := []any{}, []any{}
			for _, a := range assets {
				if a.Type != inventory.PermissionGrantType {
					continue
				}
				d := a.Resource.Data
				resource := inventory.Str(d["resource"])
				if parameterReferenceGrantScope(d, secret) && secret != "" && identity != "" && inventory.Str(d["principal"]) == identity && has(d["permissions"], "secretmanager.versions.access") {
					identityGrants = append(identityGrants, inventory.Object{"resource": resource, "principal": identity, "condition": d["condition"], "roles": d["roles"], "permission": "secretmanager.versions.access"})
				}
				if parameterReferenceGrantScope(d, parameter) && inventory.Str(d["principal"]) != "" && has(d["permissions"], "parametermanager.parameterVersions.render") {
					callerGrants = append(callerGrants, inventory.Object{"resource": resource, "principal": d["principal"], "condition": d["condition"], "roles": d["roles"], "permission": "parametermanager.parameterVersions.render"})
				}
			}
			state := "UNKNOWN"
			for _, a := range assets {
				if a.Type != "secretmanager.googleapis.com/SecretVersion" || a.Name != target {
					continue
				}
				observed := inventory.Str(a.Resource.Data["state"])
				if observed != "ENABLED" && observed != "DISABLED" && observed != "DESTROYED" {
					state = "UNKNOWN"
					break
				}
				if state != "UNKNOWN" && state != observed {
					state = "UNKNOWN"
					break
				}
				state = observed
			}
			d := inventory.Object{"parameter_version": sample.Resource, "parameter": parameter, "parameter_format": format, "target_version": target, "identity": identity, "identity_state": identityState, "reference_status": status, "observed_target_state": state, "identity_payload_grants": identityGrants, "caller_render_grants": callerGrants, "render_performed": false, "payload_read_performed": false, "redacted": redact}
			if redact {
				for _, key := range []string{"parameter_version", "parameter", "target_version", "identity"} {
					d[key] = "[REDACTED]"
				}
				d["identity_payload_grants"], d["caller_render_grants"] = []any{}, []any{}
			}
			locator := sample.ID + "\x00" + sample.Resource + "\x00" + target
			if redact {
				locator = fmt.Sprintf("%s:reference:%d", sample.ID, index)
			}
			name := fmt.Sprintf("//gcpbuster.googleapis.com/parameter-reference/%x", sha256.Sum256([]byte(locator)))
			a := inventory.NewAsset(name, ParameterReferenceType, d)
			out = append(out, a)
		}
	}
	return out
}

// Decode JSON string escaping without persisting surrounding values. YAML's
// plain reference syntax is scanned literally; malformed/unsupported forms are
// explicitly unknown, never treated as permission denial or a rendered value.
func parameterReferenceText(data []byte) string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return string(data)
	}
	stringsFound := []string{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			stringsFound = append(stringsFound, x)
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			keys := []string{}
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(x[key])
			}
		}
	}
	walk(value)
	return strings.Join(stringsFound, "\n")
}

func parameterReferenceGrantScope(d inventory.Object, target string) bool {
	if target == "" {
		return false
	}
	resource := inventory.Str(d["resource"])
	if resource == target {
		return true
	}
	if inventory.Str(d["resourceType"]) != "cloudresourcemanager.googleapis.com/Project" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(target, "//"), "/")
	return len(parts) > 2 && parts[1] == "projects" && resource == "//cloudresourcemanager.googleapis.com/projects/"+parts[2]
}

func parameterReferenceDelegation(a inventory.Asset, _ time.Time) []Result {
	d := a.Resource.Data
	if a.Type != ParameterReferenceType || d["render_performed"] != false || d["payload_read_performed"] != false {
		return nil
	}
	if d["reference_status"] != "STORED_REFERENCE" && d["reference_status"] != "MALFORMED_OR_BOUNDED_REFERENCES" {
		return nil
	}
	e := inventory.Object{}
	for _, key := range []string{"parameter_version", "parameter", "parameter_format", "target_version", "identity", "identity_state", "reference_status", "observed_target_state", "identity_payload_grants", "caller_render_grants", "render_performed", "payload_read_performed", "redacted"} {
		e[key] = d[key]
	}
	e["assessment"] = "Stored canonical reference text and supplied exact-resource or explicit matching-project prerequisites only. References are documented for structured JSON/YAML; missing format or UNFORMATTED does not establish a server-renderable reference. Missing metadata/grants or malformed/conflicting evidence is UNKNOWN, not denied access. Caller and identity conditions, deny policies, service perimeters, folder/organization inheritance, group grants, project-ID/number equivalence, alias resolution, consumer use and effective authorization remain unverified. No parameter was rendered or referenced secret payload read."
	return result("info", "Parameter configuration contains delegated secret references", "Review the per-parameter UID identity, referenced secret grants and principals able to render this parameter; audit Parameter Manager reads independently of Secret Manager delegation. Validate effective authorization through normal review, not payload access.", e)
}
