package inventory

import "testing"

func TestAPIGatewayExplicitDeploymentBindings(t *testing.T) {
	config := "projects/demo/locations/global/apis/api/configs/config"
	config2 := "projects/demo/locations/global/apis/api/configs/other"
	makeConfig := func(name string) Asset {
		return NewAsset("//apigateway.googleapis.com/"+name, "apigateway.googleapis.com/ApiConfig", Object{"name": name})
	}
	gateway := func(name, state, ref string) Asset {
		name = "projects/demo/locations/us-central1/gateways/" + name
		return NewAsset("//apigateway.googleapis.com/"+name, "apigateway.googleapis.com/Gateway", Object{"name": name, "state": state, "apiConfig": ref})
	}
	s := Snapshot{Assets: []Asset{makeConfig(config), makeConfig(config2), gateway("one", "ACTIVE", config), gateway("two", "ACTIVE", "projects/123/locations/global/apis/api/configs/config"), gateway("three", "CREATING", config2), gateway("four", "ACTIVE", "projects/foreign/locations/global/apis/api/configs/other"), gateway("five", "ACTIVE", config+"?secret=value")}}
	correlateAPIGatewayDeployments(&s, "demo", "projects/123")
	if len(List(s.Assets[0].Resource.Data["_gcpbusterGateways"])) != 2 || s.Assets[1].Resource.Data["_gcpbusterGateways"] != nil {
		t.Fatal(s.Assets[:2])
	}
	s.Assets = s.Assets[:2]
	correlateAPIGatewayDeployments(&s, "demo", "projects/123")
	if s.Assets[0].Resource.Data["_gcpbusterGateways"] != nil {
		t.Fatal("stale derived binding")
	}
}
