package inventory

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
)

const viewerMemcacheFields = "instances(name,state,nodeCount,memcacheVersion,authorizedNetwork,zones),nextPageToken,unreachable"

var viewerMemcacheID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// CollectViewerMemcache uses the documented aggregate '-' list. It never
// connects to Memcached, applies parameters, or reads cached values.
func (c *Client) CollectViewerMemcache(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-memcache:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	partial := false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://memcache.googleapis.com/v1/projects/"+projectID+"/locations/-/instances", url.Values{"pageSize": {"100"}, "fields": {viewerMemcacheFields}}, func(page Object) error {
		rows, err := viewerRows(page, "instances")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			clean, e := projectViewerMemcache(Obj(raw), projectID, number)
			if e != nil {
				partial = true
			}
			if clean == nil {
				continue
			}
			name := Str(clean["name"])
			if seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			a := NewAsset("//memcache.googleapis.com/"+name, "memcache.googleapis.com/Instance", clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("Memcached inventory includes malformed, duplicate or unreachable resources")
	}
	out.record("viewer-memcache:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-memcache:limitations:" + projectID, Status: "notice", Error: "Selected instance identity, lifecycle, version, network and node-count metadata only. Parameters, node endpoints, maintenance history, cached values, connectivity and effective access are unassessed. No Memcached requests or mutations occur."})
}

func projectViewerMemcache(d Object, projectID, number string) (Object, error) {
	name := Str(d["name"])
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && parts[1] != strings.TrimPrefix(number, "projects/")) || parts[2] != "locations" || !viewerLocation.MatchString(parts[3]) || parts[3] == "global" || parts[4] != "instances" || !viewerMemcacheID.MatchString(parts[5]) {
		return nil, fmt.Errorf("invalid or out-of-scope Memcached identity")
	}
	clean := Object{"name": "projects/" + projectID + "/locations/" + parts[3] + "/instances/" + parts[5]}
	partial := false
	enums := map[string]map[string]bool{
		"state":           {"STATE_UNSPECIFIED": true, "CREATING": true, "READY": true, "UPDATING": true, "DELETING": true, "PERFORMING_MAINTENANCE": true, "MEMCACHE_VERSION_UPGRADING": true},
		"memcacheVersion": {"MEMCACHE_VERSION_UNSPECIFIED": true, "MEMCACHE_1_5": true, "MEMCACHE_1_6_15": true},
	}
	for field, valid := range enums {
		if raw, exists := d[field]; exists {
			text, ok := raw.(string)
			if ok && valid[text] {
				clean[field] = text
			} else {
				partial = true
			}
		}
	}
	if raw, exists := d["nodeCount"]; exists {
		n, ok := raw.(float64)
		if ok && !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 1 && n <= 2147483647 && math.Trunc(n) == n {
			clean["nodeCount"] = n
		} else {
			partial = true
		}
	}
	if raw, exists := d["authorizedNetwork"]; exists {
		ref, ok := raw.(string)
		ref = strings.TrimPrefix(ref, "https://www.googleapis.com/compute/v1/")
		if ok && viewerDNSNetworkRef.MatchString(ref) {
			clean["authorizedNetwork"] = ref
		} else {
			partial = true
		}
	}
	if raw, exists := d["zones"]; exists {
		rows, ok := raw.([]any)
		valid := ok
		zones := []any{}
		for _, row := range rows {
			zone, ok := row.(string)
			if !ok || !strings.HasPrefix(zone, parts[3]+"-") || !viewerLocation.MatchString(zone) {
				valid = false
				continue
			}
			zones = append(zones, zone)
		}
		if valid {
			clean["zones"] = zones
		} else {
			partial = true
		}
	}
	if partial {
		return clean, fmt.Errorf("some Memcached configuration fields were malformed or unsupported")
	}
	return clean, nil
}
