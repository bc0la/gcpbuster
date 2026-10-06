package permissioncatalog

import "testing"

func TestCanonicalCatalog(t *testing.T) {
	if Count() < 10000 {
		t.Fatalf("truncated catalog: %d", Count())
	}
	for _, p := range []string{"iam.serviceAccounts.getAccessToken", "secretmanager.versions.access", "storage.objects.get", "cloudtasks.tasks.create", "managedkafka.connectors.create"} {
		if _, ok := Severity(p); !ok {
			t.Errorf("missing %s", p)
		}
	}
	for _, p := range Data.NonPermissions {
		if _, ok := Severity(p); ok {
			t.Errorf("non-permission retained: %s", p)
		}
	}
	if _, ok := Severity("invented.service.exploit"); ok {
		t.Fatal("invented permission classified")
	}
	if !Match("*.setIamPolicy", "run.services.setIamPolicy") || Match("*.setIamPolicy", "run.services.getIamPolicy") {
		t.Fatal("incorrect wildcard matching")
	}
}
