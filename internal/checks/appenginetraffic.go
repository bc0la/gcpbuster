package checks

import (
	"regexp"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

var appEngineTrafficName = regexp.MustCompile(`^apps/[a-z][a-z0-9-]*/services/[a-z0-9][a-z0-9-]{0,99}/versions/[a-z0-9][a-z0-9-]{0,99}$`)

func appEngineVersionTraffic(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "appengine.googleapis.com/Version" || s(a.Resource.Data["servingStatus"]) != "SERVING" {
		return nil
	}
	name := s(a.Resource.Data["name"])
	if !appEngineTrafficName.MatchString(name) || a.Name != "//appengine.googleapis.com/"+name {
		return nil
	}
	marker := obj(a.Resource.Data["_gcpbusterTrafficAllocation"])
	service := name[:strings.LastIndex(name, "/versions/")]
	fraction, known := marker["fraction"].(float64)
	if !known || fraction != 0 || s(marker["service"]) != service {
		return nil
	}
	return []Result{{"info", "Serving App Engine version has no observed service traffic allocation", inventory.Object{"service": service, "service_traffic_fraction": 0, "serving_status": "SERVING", "assessment": "Point-in-time configuration only. No allocation does not prove inactivity: version-specific routing may still be possible. This is not evidence of a backdoor, unauthorized deployment or public reachability."}, "Review whether this version is intentionally retained; inspect its ownership and access controls before considering retirement. No version endpoint was requested."}}
}
