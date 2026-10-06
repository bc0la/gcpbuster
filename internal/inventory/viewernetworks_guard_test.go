package inventory

import (
	"reflect"
	"testing"
)

func TestViewerNetworkMetadataReadGuard(t *testing.T) {
	base := "https://compute.googleapis.com/compute/v1/projects/demo/"
	for path, permission := range map[string]string{
		"global/networks":        "compute.networks.list",
		"aggregated/subnetworks": "compute.subnetworks.list",
		"regions/us-central1/subnetworks/subnet/getIamPolicy": "compute.subnetworks.getIamPolicy",
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
	for _, path := range []string{"global/networks/net/addPeering", "global/networks/net/removePeering", "global/networks/net/updatePeering", "regions/us-central1/subnetworks/subnet/setIamPolicy", "global/networks/net/getEffectiveFirewalls", "global/networks/net/getIamPolicy"} {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, base+path, nil); err == nil {
				t.Fatal("unreviewed action", method, path)
			}
		}
	}
}
