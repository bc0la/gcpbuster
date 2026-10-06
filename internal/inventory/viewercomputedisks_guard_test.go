package inventory

import (
	"reflect"
	"testing"
)

func TestViewerComputeDiskReadOnlyGuard(t *testing.T) {
	base := "https://compute.googleapis.com/compute/v1/projects/demo/"
	for path, permission := range map[string]string{
		"global/images":                                       "compute.images.list",
		"global/snapshots":                                    "compute.snapshots.list",
		"regions":                                             "compute.regions.list",
		"regions/us-central1/snapshots":                       "compute.snapshots.list",
		"global/images/image/getIamPolicy":                    "compute.images.getIamPolicy",
		"global/snapshots/snapshot/getIamPolicy":              "compute.snapshots.getIamPolicy",
		"regions/us-central1/snapshots/snapshot/getIamPolicy": "compute.snapshots.getIamPolicy",
	} {
		got, err := viewerRequestPermissions("GET", base+path, nil)
		if err != nil || !reflect.DeepEqual(got, []string{permission}) {
			t.Fatal(path, got, err)
		}
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, base+path, nil); err == nil {
				t.Fatal("mutation allowed", method, path)
			}
		}
	}
	for _, path := range []string{"global/images/image/setIamPolicy", "global/images/image/export", "global/snapshots/snapshot/setIamPolicy", "zones/us-central1-a/disks", "zones/us-central1-a/instances", "regions/us-central1/snapshots/snapshot/setIamPolicy", "global/snapshots/snapshot", "aggregated/snapshots", "global/recoverableSnapshots"} {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, base+path, nil); err == nil {
				t.Fatal("unreviewed route", method, path)
			}
		}
	}
}
