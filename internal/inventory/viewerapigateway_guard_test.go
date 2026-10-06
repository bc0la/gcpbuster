package inventory

import (
	"net/url"
	"reflect"
	"testing"
)

func TestViewerAPIGatewayReadGuard(t *testing.T) {
	base := "https://apigateway.googleapis.com/v1/projects/demo/"
	for path, permission := range map[string]string{
		"locations":                                "apigateway.locations.list",
		"locations/us-central1/gateways":           "apigateway.gateways.list",
		"locations/global/apis":                    "apigateway.apis.list",
		"locations/global/apis/api/configs":        "apigateway.apiconfigs.list",
		"locations/global/apis/api/configs/config": "apigateway.apiconfigs.get",
	} {
		got, err := viewerRequestPermissions("GET", base+path, url.Values{"view": {"FULL"}})
		if err != nil || !reflect.DeepEqual(got, []string{permission}) {
			t.Fatal(path, got, err)
		}
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, base+path, nil); err == nil {
				t.Fatal("mutation allowed", method, path)
			}
		}
	}
	for _, path := range []string{"locations/global/apis/api/configs/config:setIamPolicy", "locations/global/apis/api/configs/config:getIamPolicy", "locations/global/apis/api/configs/config:delete", "locations/us-central1/apis/api/configs/config", "locations/global/operations/op:cancel"} {
		if _, err := viewerRequestPermissions("GET", base+path, nil); err == nil {
			t.Fatal("unreviewed method", path)
		}
	}
	for _, endpoint := range []string{"https://example.gateway.dev/mcp", "https://example.gateway.dev/open", "https://apigateway.googleapis.com/mcp"} {
		for _, method := range []string{"GET", "POST"} {
			if _, err := viewerRequestPermissions(method, endpoint, nil); err == nil {
				t.Fatal("gateway data-plane request allowed", method, endpoint)
			}
		}
	}
}
