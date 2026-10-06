package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestPublicAutomationCapabilitiesExactScope(t *testing.T) {
	for _, tc := range []struct{ host, collection, typ, permission string }{
		{"cloudtasks", "queues", "Queue", "cloudtasks.tasks.create"}, {"cloudscheduler", "jobs", "Job", "cloudscheduler.jobs.run"},
	} {
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//" + tc.host + ".googleapis.com/projects/demo/locations/us-central1/" + tc.collection + "/target", "resourceType": tc.host + ".googleapis.com/" + tc.typ, "principal": "allUsers", "permissions": []any{tc.permission}})
		got := publicAutomationCapabilities(a, time.Now())
		if len(got) != 1 || !strings.Contains(got[0].Evidence["assessment"].(string), "OAuth") {
			t.Fatal(tc, got)
		}
		if tc.host == "cloudtasks" && !strings.Contains(got[0].Evidence["assessment"].(string), "actAs") {
			t.Fatal(got)
		}
		a.Resource.Data["principal"] = "allAuthenticatedUsers"
		a.Resource.Data["condition"] = inventory.Object{"expression": "false"}
		got = publicAutomationCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Severity != "medium" {
			t.Fatal(got)
		}
		a.Resource.Data["principal"] = "user:a@example.com"
		if len(publicAutomationCapabilities(a, time.Now())) != 0 {
			t.Fatal("nonpublic")
		}
		a.Resource.Data["principal"] = "allUsers"
		a.Resource.Data["permissions"] = []any{"cloudtasks.tasks.get", "cloudscheduler.jobs.get"}
		if len(publicAutomationCapabilities(a, time.Now())) != 0 {
			t.Fatal("metadata permission")
		}
		a.Resource.Data["permissions"] = []any{tc.permission}
		a.Resource.Data["resource"] = "//" + tc.host + ".googleapis.com/projects/demo/locations/us-central1/" + tc.collection + "/target/tasks/child"
		if len(publicAutomationCapabilities(a, time.Now())) != 0 {
			t.Fatal("child scope")
		}
	}
}

func TestPublicAutomationMalformedAndCrossProduct(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//cloudtasks.googleapis.com/projects/demo/locations/us-central1/queues/q", "resourceType": "cloudtasks.googleapis.com/Queue", "principal": "allUsers", "permissions": []any{"cloudscheduler.jobs.run"}})
	if len(publicAutomationCapabilities(a, time.Now())) != 0 {
		t.Fatal("cross-product")
	}
	a.Resource.Data["permissions"] = []any{"cloudtasks.tasks.create"}
	a.Resource.Data["condition"] = inventory.Object{}
	got := publicAutomationCapabilities(a, time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Evidence["condition_status"].(string), "malformed") {
		t.Fatal(got)
	}
	for _, resource := range []string{"https://evil.test/q", "//cloudtasks.googleapis.com/projects/demo/locations/us-central1/queues/../q", "//cloudtasks.googleapis.com/projects/demo/locations/us-central1/queues/q%2f"} {
		a.Resource.Data["resource"] = resource
		if len(publicAutomationCapabilities(a, time.Now())) != 0 {
			t.Fatal(resource)
		}
	}
}

func TestPublicAutomationAndServerlessProjectScope(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//cloudresourcemanager.googleapis.com/projects/123", "resourceType": "cloudresourcemanager.googleapis.com/Project", "principal": "allAuthenticatedUsers", "permissions": []any{"cloudtasks.tasks.create", "cloudscheduler.jobs.run", "run.routes.invoke", "cloudfunctions.functions.invoke"}})
	for _, eval := range []func(inventory.Asset, time.Time) []Result{publicAutomationCapabilities, publicServerlessInvocation} {
		got := eval(a, time.Now())
		if len(got) != 2 {
			t.Fatal(got)
		}
		for _, r := range got {
			if r.Evidence["binding_scope"] != "project" || r.Evidence["resource"] != a.Resource.Data["resource"] || !strings.Contains(r.Evidence["assessment"].(string), "No child bindings") {
				t.Fatal(r)
			}
		}
	}
	a.Resource.Data["condition"] = inventory.Object{"expression": "resource.name.endsWith('/jobs/job')"}
	if got := publicAutomationCapabilities(a, time.Now()); len(got) != 2 || got[0].Severity != "medium" {
		t.Fatal(got)
	}
	a.Resource.Data["resource"] = "//cloudresourcemanager.googleapis.com/projects/123/jobs/job"
	if len(publicAutomationCapabilities(a, time.Now())) != 0 || len(publicServerlessInvocation(a, time.Now())) != 0 {
		t.Fatal("invented descendant")
	}
}
