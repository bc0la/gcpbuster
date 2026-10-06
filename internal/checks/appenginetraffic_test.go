package checks

import (
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestAppEngineVersionTrafficBoundaries(t *testing.T) {
	for _, tc := range []struct {
		status, service string
		fraction        any
		want            int
	}{
		{"SERVING", "apps/demo/services/default", float64(0), 1},
		{"STOPPED", "apps/demo/services/default", float64(0), 0},
		{"UNKNOWN", "apps/demo/services/default", float64(0), 0},
		{"SERVING", "apps/foreign/services/default", float64(0), 0},
		{"SERVING", "apps/demo/services/default", float64(0.1), 0},
		{"SERVING", "apps/demo/services/default", "0", 0},
		{"SERVING", "apps/demo/services/default", nil, 0},
	} {
		a := inventory.NewAsset("//appengine.googleapis.com/apps/demo/services/default/versions/old", "appengine.googleapis.com/Version", inventory.Object{"name": "apps/demo/services/default/versions/old", "servingStatus": tc.status, "_gcpbusterTrafficAllocation": inventory.Object{"service": tc.service, "fraction": tc.fraction}})
		if got := appEngineVersionTraffic(a, time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
		a.Name = "//appengine.googleapis.com/apps/foreign/services/default/versions/old"
		if got := appEngineVersionTraffic(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
