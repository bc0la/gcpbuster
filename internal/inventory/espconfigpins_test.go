package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const espDeclaration = `spec:
  containers:
  - image: gcr.io/endpoints-release/endpoints-runtime:2
    args: ["--service=example.com", "--version=compiled", "--rollout_strategy=fixed", "--backend=PRIVATE_BACKEND:8080"]
`

func espPinFixture() Snapshot {
	return Snapshot{Assets: []Asset{
		NewAsset("//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/esp", "compute.googleapis.com/Instance", Object{"name": "esp", "status": "RUNNING", "metadata": Object{"items": []any{Object{"key": "gce-container-declaration", "value": espDeclaration}}}}),
		NewAsset("//servicemanagement.googleapis.com/services/example.com/configs/compiled", ServiceConfigType, Object{"name": "example.com", "id": "compiled", "producerProjectId": "demo"}),
	}}
}

func TestESPConfigPinsExplicitFixedDeclaration(t *testing.T) {
	s := espPinFixture()
	CorrelateESPConfigPins(&s)
	rows := List(s.Assets[1].Resource.Data["_gcpbusterESPConfigPins"])
	if len(rows) != 1 || Str(Obj(rows[0])["workload"]) != s.Assets[0].Name || Obj(rows[0])["selection"] != "explicit_fixed_container_declaration" {
		t.Fatal(rows)
	}
	b, _ := json.Marshal(rows)
	if strings.Contains(string(b), "PRIVATE_BACKEND") || strings.Contains(string(b), "endpoints-runtime") {
		t.Fatal("raw declaration persisted", string(b))
	}
	s.Assets[0].Resource.Data["status"] = "TERMINATED"
	CorrelateESPConfigPins(&s)
	if s.Assets[1].Resource.Data["_gcpbusterESPConfigPins"] != nil {
		t.Fatal("stale pin")
	}
}

func TestESPConfigPinsScopeConflictsAndNoServerlessGuess(t *testing.T) {
	for _, mode := range []string{"foreign", "config", "service", "producer", "vm-name", "run", "numeric", "conflict", "invalid-duplicate"} {
		s := espPinFixture()
		switch mode {
		case "foreign":
			s.Assets[0].Name = strings.Replace(s.Assets[0].Name, "/demo/", "/foreign/", 1)
		case "config":
			s.Assets[1].Resource.Data["id"] = "other"
		case "service":
			s.Assets[1].Resource.Data["name"] = "other.com"
		case "producer":
			s.Assets[1].Resource.Data["producerProjectId"] = "other"
		case "vm-name":
			s.Assets[0].Resource.Data["name"] = "different"
		case "run":
			s.Assets[0].Type = "run.googleapis.com/Service"
		case "numeric":
			s.Assets[0].Name = strings.Replace(s.Assets[0].Name, "/demo/", "/123/", 1)
		case "conflict", "invalid-duplicate":
			other := espPinFixture().Assets[0]
			other.Resource.Data["status"] = "STOPPING"
			s.Assets = append(s.Assets, other, s.Assets[0])
		}
		CorrelateESPConfigPins(&s)
		if s.Assets[1].Resource.Data["_gcpbusterESPConfigPins"] != nil {
			t.Fatal(mode)
		}
	}
}

func TestESPDeclarationRejectsAmbiguousAndManaged(t *testing.T) {
	for _, body := range []string{
		strings.Replace(espDeclaration, "fixed", "managed", 1),
		strings.Replace(espDeclaration, "--version=compiled", "--service_json_path=/tmp/config", 1),
		strings.Replace(espDeclaration, "--version=compiled", "--version=${SECRET}", 1),
		strings.Replace(espDeclaration, "--version=compiled", "--service=other.com", 1),
		strings.Replace(espDeclaration, "endpoints-release", "attacker", 1),
		espDeclaration + "---\nanything: true\n",
		strings.Replace(espDeclaration, "  containers:", "  containers: []\n  containers:", 1),
		strings.Replace(espDeclaration, "    args:", "    command: [sh]\n    args:", 1),
		strings.Replace(espDeclaration, "    args:", "    env: [{name: ESPv2_ARGS, value: never}]\n    args:", 1),
		"spec: &x {containers: []}\nother: *x",
		strings.Repeat("x", 65537),
	} {
		if _, _, ok := espDeclaredFixedConfig(body); ok {
			t.Fatal("unsupported declaration accepted", body)
		}
	}
	for _, body := range []string{espDeclaration, strings.Replace(espDeclaration, `"--rollout_strategy=fixed", `, "", 1), strings.Replace(espDeclaration, `"--version=compiled"`, `"--version", "compiled"`, 1)} {
		service, config, ok := espDeclaredFixedConfig(body)
		if !ok || service != "example.com" || config != "compiled" {
			t.Fatal(service, config, ok)
		}
	}
}

func TestESPConfigPinsBounds(t *testing.T) {
	s := espPinFixture()
	for i := 0; i < 100; i++ {
		a := espPinFixture().Assets[0]
		name := fmt.Sprintf("esp%d", i)
		a.Name = "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/" + name
		a.Resource.Data["name"] = name
		s.Assets = append(s.Assets, a)
	}
	CorrelateESPConfigPins(&s)
	if len(List(s.Assets[1].Resource.Data["_gcpbusterESPConfigPins"])) != 100 || len(s.Coverage) != 1 || s.Coverage[0].Status != "incomplete" {
		t.Fatal("pin bound")
	}
	s.Assets = append(s.Assets, make([]Asset, 100001)...)
	CorrelateESPConfigPins(&s)
	if s.Assets[1].Resource.Data["_gcpbusterESPConfigPins"] != nil {
		t.Fatal("snapshot bound left stale pins")
	}
}
