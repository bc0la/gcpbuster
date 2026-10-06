package inventory

import (
	"reflect"
	"testing"
)

func TestViewerServiceManagementReadGuard(t *testing.T) {
	base := "https://servicemanagement.googleapis.com/v1/"
	for path, permission := range map[string]string{"services/api.example.test/rollouts": "servicemanagement.services.get", "services": "servicemanagement.services.list", "services/api.example.test": "servicemanagement.services.get", "services/api.example.test/configs": "servicemanagement.services.get", "services/api.example.test/configs/config-id": "servicemanagement.services.get"} {
		got, err := viewerRequestPermissions("GET", base+path, nil)
		if err != nil || !reflect.DeepEqual(got, []string{permission}) {
			t.Fatal(path, got, err)
		}
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, base+path, nil); err == nil {
				t.Fatal(method, path)
			}
		}
	}
	for _, path := range []string{"services/api.example.test:getIamPolicy", "services/api.example.test:setIamPolicy", "services/api.example.test:enable", "services/api.example.test:generateConfigReport", "services/api.example.test/configs:submit", "services/api.example.test/rollouts/r1"} {
		for _, method := range []string{"GET", "POST"} {
			if _, err := viewerRequestPermissions(method, base+path, nil); err == nil {
				t.Fatal(method, path)
			}
		}
	}
}
