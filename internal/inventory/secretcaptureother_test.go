package inventory

import (
	"net/url"
	"strings"
	"testing"
)

func TestSecretCaptureInventoryStrictFamilies(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	good := NewAsset("//composer.googleapis.com/projects/demo/locations/us-central1/environments/a", "composer.googleapis.com/Environment", Object{"config": Object{"softwareConfig": Object{"envVariables": Object{"PASSWORD": "exact-value"}, "unknown": "DO_NOT_CAPTURE"}}})
	bad := good
	bad.Name = "//composer.googleapis.com/projects/demo/locations/us-central1/jobs/a"
	c.CaptureInventory([]Asset{good, bad})
	if len(c.Samples()) != 1 || strings.Contains(string(c.Samples()[0].Data), "DO_NOT_CAPTURE") {
		t.Fatal(c.Samples())
	}
	scheduler := NewAsset("//cloudscheduler.googleapis.com/projects/demo/locations/us-central1/jobs/a", "cloudscheduler.googleapis.com/Job", Object{"httpTarget": Object{"uri": "https://example.test/?token=exact-value", "headers": Object{"Authorization": "Bearer exact-value"}, "body": "DO_NOT_CAPTURE"}, "pubsubTarget": Object{"data": "DO_NOT_CAPTURE"}})
	c.CaptureInventory([]Asset{scheduler})
	if len(c.Samples()) != 3 {
		t.Fatal(c.Samples())
	}
	for _, s := range c.Samples() {
		if strings.Contains(string(s.Data), "DO_NOT_CAPTURE") {
			t.Fatal("body captured")
		}
	}
}

func TestSecretCaptureExactQueryMasks(t *testing.T) {
	endpoint := "https://run.googleapis.com/v2/projects/demo/locations/us-central1/services"
	for _, mask := range []string{"*", "services(template),nextPageToken", "services(" + secretCaptureRunServiceFields + "),nextPageToken,unreachable"} {
		_, err := viewerRequestPermissions("GET", endpoint, url.Values{"fields": {mask}})
		want := strings.HasPrefix(mask, "services(name,")
		if (err == nil) != want {
			t.Fatalf("mask %q err %v", mask, err)
		}
	}
	if _, err := viewerRequestPermissions("GET", endpoint, nil); err != nil {
		t.Fatal("legacy nil rejected", err)
	}
}
