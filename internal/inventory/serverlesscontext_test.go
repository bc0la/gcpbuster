package inventory

import "testing"

func TestServerlessContextExactResourceScopeAndConflicts(t *testing.T) {
	name := "projects/demo/locations/us-central1/services/app"
	service := NewAsset("//run.googleapis.com/"+name, "run.googleapis.com/Service", Object{"name": name, "ingress": "INGRESS_TRAFFIC_ALL", "invokerIamDisabled": false, "iapEnabled": true, "uri": "PRIVATE_ENDPOINT"})
	grant := NewAsset("grant", PermissionGrantType, Object{"resource": service.Name, "resourceType": service.Type})
	project := NewAsset("project", PermissionGrantType, Object{"resource": "//cloudresourcemanager.googleapis.com/projects/demo", "resourceType": "cloudresourcemanager.googleapis.com/Project"})
	s := Snapshot{Assets: []Asset{service, grant, project}}
	CorrelateServerlessContext(&s)
	c := Obj(s.Assets[1].Resource.Data["_gcpbusterServerlessContext"])
	if c["ingress"] != "INGRESS_TRAFFIC_ALL" || c["invokerIamDisabled"] != false || c["iapEnabled"] != true || c["uri"] != nil || s.Assets[2].Resource.Data["_gcpbusterServerlessContext"] != nil {
		t.Fatal(s)
	}
	other := NewAsset(service.Name, service.Type, Object{"name": name, "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"})
	s.Assets = append(s.Assets, other, service)
	CorrelateServerlessContext(&s)
	if Get(s.Assets[1].Resource.Data, "_gcpbusterServerlessContext", "status") != "conflicting" {
		t.Fatal("repetition cleared conflict", s)
	}
}

func TestServerlessFunctionTriggersAndUnknownSchemas(t *testing.T) {
	name := "projects/demo/locations/us-central1/functions/app"
	for _, tc := range []struct {
		data Object
		want string
	}{
		{Object{"httpsTrigger": Object{}, "ingressSettings": "ALLOW_ALL"}, "http_configuration"},
		{Object{"eventTrigger": Object{"eventType": "google.pubsub.topic.publish"}}, "event_driven_configuration"},
		{Object{"httpsTrigger": Object{}, "eventTrigger": Object{"eventType": "google.pubsub.topic.publish"}}, "unknown"},
		{Object{"httpsTrigger": true}, "unknown"},
		{Object{"eventTrigger": Object{}}, "unknown"},
	} {
		tc.data["name"] = name
		function := NewAsset("//cloudfunctions.googleapis.com/"+name, "cloudfunctions.googleapis.com/CloudFunction", tc.data)
		grant := NewAsset("grant", PermissionGrantType, Object{"resource": function.Name, "resourceType": function.Type})
		s := Snapshot{Assets: []Asset{function, grant}}
		CorrelateServerlessContext(&s)
		if Get(s.Assets[1].Resource.Data, "_gcpbusterServerlessContext", "http_trigger") != tc.want {
			t.Fatal(tc, s)
		}
		function.Resource.Data["name"] = "projects/foreign/locations/us-central1/functions/app"
		s.Assets[0] = function
		CorrelateServerlessContext(&s)
		if s.Assets[1].Resource.Data["_gcpbusterServerlessContext"] != nil {
			t.Fatal("foreign metadata bound", s)
		}
	}
}
