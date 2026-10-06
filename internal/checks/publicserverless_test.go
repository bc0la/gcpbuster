package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestPublicServerlessInvocationExactResourcePermission(t *testing.T) {
	base := func() inventory.Asset {
		return inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//run.googleapis.com/projects/demo/locations/us-central1/services/api", "resourceType": "run.googleapis.com/Service", "principal": "allUsers", "roles": []any{"projects/demo/roles/custom"}, "permissions": []any{"run.routes.invoke"}})
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"resource", "https://evil.test/api"}, {"resource", "//run.googleapis.com/projects/demo/locations/us-central1/jobs/api"},
		{"resource", "//run.googleapis.com/projects/demo/locations/us-central1/services/../api"}, {"resourceType", "run.googleapis.com/Job"},
		{"principal", "user:a@example.com"}, {"permissions", []any{"run.services.get"}}, {"permissions", []any{"run.jobs.run"}},
	} {
		a := base()
		a.Resource.Data[tc.key] = tc.value
		if got := publicServerlessInvocation(a, time.Now()); len(got) != 0 {
			t.Fatal(tc, got)
		}
	}
	a := base()
	if got := publicServerlessInvocation(a, time.Now()); len(got) != 1 || got[0].Severity != "high" {
		t.Fatal(got)
	}
	a.Resource.Data["principal"] = "allAuthenticatedUsers"
	a.Resource.Data["condition"] = inventory.Object{"expression": "false"}
	got := publicServerlessInvocation(a, time.Now())
	if len(got) != 1 || got[0].Severity != "medium" || !strings.Contains(got[0].Title, "Google-authenticated") {
		t.Fatal(got)
	}
	a.Resource.Data["condition"] = inventory.Object{}
	got = publicServerlessInvocation(a, time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Evidence["condition_status"].(string), "malformed") {
		t.Fatal(got)
	}
	a.Type = "run.googleapis.com/Service"
	if len(publicServerlessInvocation(a, time.Now())) != 0 {
		t.Fatal("wrong analysis type")
	}
}

func TestPublicServerlessInvocationFunctionGenerationBoundary(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/api", "resourceType": "cloudfunctions.googleapis.com/CloudFunction", "principal": "allUsers", "permissions": []any{"cloudfunctions.functions.invoke"}})
	got := publicServerlessInvocation(a, time.Now())
	if len(got) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), "HTTP-trigger presence is not established") {
		t.Fatal(string(b))
	}
	a.Resource.Data["resourceType"] = "cloudfunctions.googleapis.com/Function"
	if len(publicServerlessInvocation(a, time.Now())) != 0 {
		t.Fatal("gen2 is underlying Run")
	}
	a.Resource.Data["permissions"] = []any{"run.routes.invoke"}
	if len(publicServerlessInvocation(a, time.Now())) != 0 {
		t.Fatal("wrong resource for Run")
	}
}
