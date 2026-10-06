package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func parameterReferenceFixture() (inventory.SecretSample, []inventory.Asset) {
	version := "//parametermanager.googleapis.com/projects/123/locations/global/parameters/p/versions/v1"
	parameter := "//parametermanager.googleapis.com/projects/123/locations/global/parameters/p"
	identity := "principal://parametermanager.googleapis.com/projects/123/uid/locations/global/parameters/uid123"
	target := "//secretmanager.googleapis.com/projects/456/secrets/s/versions/1"
	sample := inventory.SecretSample{ID: strings.Repeat("a", 64), SourceType: "parameter_manager_raw", Resource: version, Path: "payload.data", Data: []byte(`db_password: __REF__("` + target + `")`)}
	metadata := inventory.NewAsset(parameter, "parametermanager.googleapis.com/Parameter", inventory.Object{"name": strings.TrimPrefix(parameter, "//parametermanager.googleapis.com/"), "format": "YAML", "policyMember": inventory.Object{"iamPolicyUidPrincipal": identity}})
	secretVersion := inventory.NewAsset(target, "secretmanager.googleapis.com/SecretVersion", inventory.Object{"state": "ENABLED"})
	grant := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": target[:strings.LastIndex(target, "/versions/")], "principal": identity, "permissions": []any{"secretmanager.versions.access"}, "condition": inventory.Object{"expression": "false"}})
	caller := inventory.NewAsset("caller", inventory.PermissionGrantType, inventory.Object{"resource": parameter, "principal": "user:reader@example.invalid", "permissions": []any{"parametermanager.parameterVersions.render"}})
	return sample, []inventory.Asset{metadata, secretVersion, grant, caller}
}

func TestParameterStoredReferencesExactPrerequisitesNoRender(t *testing.T) {
	sample, assets := parameterReferenceFixture()
	rows := ParameterReferenceAssets([]inventory.SecretSample{sample}, assets, false)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	d := rows[0].Resource.Data
	if d["identity_state"] != "OBSERVED_UID" || d["observed_target_state"] != "ENABLED" || len(inventory.List(d["identity_payload_grants"])) != 1 || len(inventory.List(d["caller_render_grants"])) != 1 {
		t.Fatal(d)
	}
	got := parameterReferenceDelegation(rows[0], time.Time{})
	if len(got) != 1 || got[0].Severity != "info" || got[0].Evidence["render_performed"] != false || got[0].Evidence["payload_read_performed"] != false {
		t.Fatal(got)
	}
	if inventory.Get(inventory.Obj(inventory.List(d["identity_payload_grants"])[0]), "condition", "expression") != "false" {
		t.Fatal("condition lost")
	}
}

func TestParameterReferencesSyntaxUnknownAndRedaction(t *testing.T) {
	sample, assets := parameterReferenceFixture()
	target := "//secretmanager.googleapis.com/projects/456/secrets/s/versions/1"
	for _, value := range []string{`__REF__("` + target + `")`, `__REF__('` + target + `')`, `__REF__(` + target + `)`, `{"password":"__REF__(\"` + target + `\")"}`} {
		sample.Data = []byte(value)
		rows := ParameterReferenceAssets([]inventory.SecretSample{sample}, assets, false)
		if len(rows) != 1 || rows[0].Resource.Data["target_version"] != target || rows[0].Resource.Data["reference_status"] != "STORED_REFERENCE" {
			t.Fatal(value, rows)
		}
	}
	sample.Data = []byte(`__REF__("https://evil.invalid/path?SECRET_SENTINEL")`)
	rows := ParameterReferenceAssets([]inventory.SecretSample{sample}, nil, false)
	if len(rows) != 1 || rows[0].Resource.Data["reference_status"] != "MALFORMED_OR_BOUNDED_REFERENCES" || rows[0].Resource.Data["identity_state"] != "UNKNOWN" {
		t.Fatal(rows)
	}
	b, _ := json.Marshal(rows)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("malformed source retained")
	}
	sample.Data = []byte(`__REF__("` + target + `")`)
	rows = ParameterReferenceAssets([]inventory.SecretSample{sample}, assets, true)
	b, _ = json.Marshal(rows)
	if strings.Contains(string(b), target) || strings.Contains(string(b), "uid123") || !strings.Contains(string(b), "[REDACTED]") {
		t.Fatal("redacted reference context retained", string(b))
	}
	other := sample
	other.Data = []byte(`__REF__("//secretmanager.googleapis.com/projects/999/secrets/other/versions/2")`)
	otherRows := ParameterReferenceAssets([]inventory.SecretSample{other}, nil, true)
	if rows[0].Name != otherRows[0].Name {
		t.Fatal("redacted ID depends on stored target")
	}
}

func TestParameterReferenceMissingConflictingForeignIdentity(t *testing.T) {
	sample, assets := parameterReferenceFixture()
	for _, principal := range []string{"", "principal://parametermanager.googleapis.com/projects/999/uid/locations/global/parameters/u", "principal://parametermanager.googleapis.com/projects/123/name/locations/global/parameters/p"} {
		metadata := assets[0]
		metadata.Resource.Data = inventory.Object{"name": strings.TrimPrefix(metadata.Name, "//parametermanager.googleapis.com/"), "policyMember": inventory.Object{"iamPolicyUidPrincipal": principal}}
		rows := ParameterReferenceAssets([]inventory.SecretSample{sample}, []inventory.Asset{metadata}, false)
		if len(rows) != 1 || rows[0].Resource.Data["identity_state"] != "CONFLICT_OR_MALFORMED" || rows[0].Resource.Data["identity"] != "" {
			t.Fatal(principal, rows)
		}
	}
	conflict := assets[1]
	conflict.Resource.Data = inventory.Object{"state": "DISABLED"}
	rows := ParameterReferenceAssets([]inventory.SecretSample{sample}, append(assets, conflict), false)
	if rows[0].Resource.Data["observed_target_state"] != "UNKNOWN" {
		t.Fatal("conflicting target state assumed", rows)
	}
}

func TestParameterReferencePrivateBindingExpansionProjectScopes(t *testing.T) {
	sample, assets := parameterReferenceFixture()
	identity := inventory.Str(inventory.Get(assets[0].Resource.Data, "policyMember", "iamPolicyUidPrincipal"))
	project := inventory.NewAsset("//cloudresourcemanager.googleapis.com/projects/456", "cloudresourcemanager.googleapis.com/Project", inventory.Object{})
	project.IAM = inventory.Object{"bindings": []any{inventory.Object{"role": "roles/secretmanager.secretAccessor", "members": []any{identity}}}}
	role := inventory.NewAsset("//iam.googleapis.com/roles/secretmanager.secretAccessor", "iam.googleapis.com/Role", inventory.Object{"name": "roles/secretmanager.secretAccessor", "includedPermissions": []any{"secretmanager.versions.access"}})
	input := []inventory.Asset{assets[0], project, role}
	rows := ParameterReferenceAssets([]inventory.SecretSample{sample}, input, false)
	if len(rows) != 1 || len(inventory.List(rows[0].Resource.Data["identity_payload_grants"])) != 1 || len(input) != 3 {
		t.Fatal(rows)
	}
}
