package inventory

import "testing"

func servicePinsFixture() Snapshot {
	api := "projects/demo/locations/global/apis/api"
	config := api + "/configs/config"
	gateway := "projects/demo/locations/us-central1/gateways/gateway"
	return Snapshot{Assets: []Asset{
		NewAsset("//apigateway.googleapis.com/"+api, "apigateway.googleapis.com/Api", Object{"name": api, "managedService": "example.com"}),
		NewAsset("//apigateway.googleapis.com/"+config, "apigateway.googleapis.com/ApiConfig", Object{"name": config, "serviceConfigId": "compiled", "_gcpbusterGateways": []any{"//apigateway.googleapis.com/" + gateway}}),
		NewAsset("//apigateway.googleapis.com/"+gateway, "apigateway.googleapis.com/Gateway", Object{"name": gateway, "state": "ACTIVE", "apiConfig": config}),
		NewAsset("//servicemanagement.googleapis.com/services/example.com/configs/compiled", ServiceConfigType, Object{"name": "example.com", "id": "compiled", "producerProjectId": "demo"}),
	}}
}

func TestServiceGatewayPinsExactObservedJoin(t *testing.T) {
	s := servicePinsFixture()
	correlateServiceGatewayPins(&s, "demo", "projects/123")
	pins := List(s.Assets[3].Resource.Data["_gcpbusterGatewayPins"])
	if len(pins) != 1 || Str(Obj(pins[0])["apiConfig"]) != s.Assets[1].Name || len(List(Obj(pins[0])["gateways"])) != 1 {
		t.Fatal(s)
	}
	s.Assets[2].Resource.Data["state"] = "DELETING"
	correlateServiceGatewayPins(&s, "demo", "projects/123")
	if s.Assets[3].Resource.Data["_gcpbusterGatewayPins"] != nil {
		t.Fatal("stale pin", s)
	}
}

func TestServiceGatewayPinsRejectForeignMalformedAndMissing(t *testing.T) {
	for _, mode := range []string{"producer", "service", "config-id", "derived-only", "foreign-gateway", "wrong-api", "missing-api", "api-conflict"} {
		t.Run(mode, func(t *testing.T) {
			s := servicePinsFixture()
			switch mode {
			case "producer":
				s.Assets[3].Resource.Data["producerProjectId"] = "other"
			case "service":
				s.Assets[0].Resource.Data["managedService"] = "other.com"
			case "config-id":
				s.Assets[1].Resource.Data["serviceConfigId"] = "other"
			case "derived-only":
				s.Assets[2].Type = "unknown"
			case "foreign-gateway":
				s.Assets[1].Resource.Data["_gcpbusterGateways"] = []any{"//apigateway.googleapis.com/projects/other/locations/us-central1/gateways/gateway"}
			case "wrong-api":
				s.Assets[0].Name = "//apigateway.googleapis.com/projects/demo/locations/global/apis/wrong"
			case "missing-api":
				s.Assets[0].Type = "unknown"
			case "api-conflict":
				a := NewAsset(s.Assets[0].Name, s.Assets[0].Type, Object{"name": s.Assets[0].Resource.Data["name"], "managedService": "other.com"})
				s.Assets = append(s.Assets, a)
			}
			correlateServiceGatewayPins(&s, "demo", "projects/123")
			if s.Assets[3].Resource.Data["_gcpbusterGatewayPins"] != nil {
				t.Fatal(mode, s)
			}
		})
	}
}

func TestServiceGatewayPinsRejectConflictingObservations(t *testing.T) {
	for _, kind := range []string{"gateway-config", "gateway-state", "compiled-config"} {
		s := servicePinsFixture()
		var duplicate Asset
		if kind == "compiled-config" {
			duplicate = NewAsset(s.Assets[1].Name, s.Assets[1].Type, Object{"name": s.Assets[1].Resource.Data["name"], "serviceConfigId": "other", "_gcpbusterGateways": s.Assets[1].Resource.Data["_gcpbusterGateways"]})
		} else {
			data := Object{"name": s.Assets[2].Resource.Data["name"], "state": "ACTIVE", "apiConfig": s.Assets[2].Resource.Data["apiConfig"]}
			if kind == "gateway-config" {
				data["apiConfig"] = "projects/demo/locations/global/apis/api/configs/other"
			} else {
				data["state"] = "DELETING"
			}
			duplicate = NewAsset(s.Assets[2].Name, s.Assets[2].Type, data)
		}
		s.Assets = append(s.Assets, duplicate)
		correlateServiceGatewayPins(&s, "demo", "projects/123")
		if s.Assets[3].Resource.Data["_gcpbusterGatewayPins"] != nil {
			t.Fatal(kind, s)
		}
	}
}
