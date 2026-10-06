package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicServerlessInvocationExactContextNotReachability(t *testing.T) {
	resource := "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/app"
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": resource, "resourceType": "cloudfunctions.googleapis.com/CloudFunction", "principal": "allUsers", "permissions": []any{"cloudfunctions.functions.invoke"}})
	for _, tc := range []struct{ trigger, severity string }{{"http_configuration", "high"}, {"event_driven_configuration", "info"}, {"unknown", "high"}} {
		a.Resource.Data["_gcpbusterServerlessContext"] = inventory.Object{"resource": resource, "resource_type": "cloudfunctions.googleapis.com/CloudFunction", "status": "observed", "http_trigger": tc.trigger, "ingress": "ALLOW_INTERNAL_AND_GCLB"}
		got := publicServerlessInvocation(a, time.Now())
		if len(got) != 1 || got[0].Severity != tc.severity || inventory.Get(got[0].Evidence, "invocation_context", "http_trigger") != tc.trigger {
			t.Fatal(tc, got)
		}
	}
	for _, context := range []inventory.Object{{"resource": resource, "resource_type": "cloudfunctions.googleapis.com/CloudFunction", "status": "conflicting", "http_trigger": "event_driven_configuration"}, {"resource": "foreign", "resource_type": "cloudfunctions.googleapis.com/CloudFunction", "status": "observed", "http_trigger": "event_driven_configuration"}} {
		a.Resource.Data["_gcpbusterServerlessContext"] = context
		if got := publicServerlessInvocation(a, time.Now()); got[0].Severity != "high" || inventory.Get(got[0].Evidence, "invocation_context", "status") != "not_correlated" {
			t.Fatal("unknown/foreign context qualified permission", got)
		}
	}
	resource = "//run.googleapis.com/projects/demo/locations/us-central1/services/app"
	a.Resource.Data = inventory.Object{"resource": resource, "resourceType": "run.googleapis.com/Service", "principal": "allUsers", "permissions": []any{"run.routes.invoke"}, "_gcpbusterServerlessContext": inventory.Object{"resource": resource, "resource_type": "run.googleapis.com/Service", "status": "observed", "http_trigger": "event_driven_configuration"}}
	if got := publicServerlessInvocation(a, time.Now()); got[0].Severity != "high" || inventory.Get(got[0].Evidence, "invocation_context", "http_trigger") != "unknown" {
		t.Fatal("cross-kind supplied context became a gen1 trigger", got)
	}
}
