package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

const viewerRouteFields = "items(name,selfLink,network,destRange,priority,nextHopGateway,routeType,tags),nextPageToken,warning(code)"

// CollectViewerRoutes reads configured routes only, not effective forwarding,
// learned BGP paths, health checks or connectivity-test resources.
func (c *Client) CollectViewerRoutes(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-routes:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	count := 0
	partial := false
	seen := map[string]int{}
	e := c.viewerPages(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/global/routes", url.Values{"fields": {viewerRouteFields}, "maxResults": {"100"}}, func(page Object) error {
		rows, e := viewerRows(page, "items")
		if e != nil {
			return e
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !backendID.MatchString(name) || len(name) > 63 {
				partial = true
				continue
			}
			if index, exists := seen[name]; exists {
				partial = true
				if index >= 0 {
					out.Assets[index].Resource.Data["projection_complete"] = false
				}
				continue
			}
			seen[name] = -1
			if raw, exists := d["selfLink"]; exists && !viewerComputeDiskLink(Str(raw), projectID, number, "global/routes/"+name) {
				partial = true
				continue
			}
			network := ingressNetwork(d["network"])
			if !strings.HasPrefix(network, "projects/"+projectID+"/") && !strings.HasPrefix(network, number+"/") {
				partial = true
				continue
			}
			prefix, e := netip.ParsePrefix(Str(d["destRange"]))
			if e != nil || prefix.Addr().Is4In6() {
				partial = true
				continue
			}
			clean := Object{"name": name, "network": network, "destRange": prefix.Masked().String()}
			rowPartial := false
			if v, exists := d["priority"]; exists {
				n, ok := v.(float64)
				if !ok || n < 0 || n > 65535 || float64(int(n)) != n {
					partial = true
					rowPartial = true
				} else {
					clean["priority"] = n
				}
			}
			if v, exists := d["routeType"]; exists {
				switch v {
				case "BGP", "STATIC", "SUBNET", "TRANSIT":
					clean["routeType"] = v
				default:
					partial = true
					rowPartial = true
				}
			}
			if v, exists := d["nextHopGateway"]; exists {
				if viewerComputeDiskLink(Str(v), projectID, number, "global/gateways/default-internet-gateway") || v == "projects/"+projectID+"/global/gateways/default-internet-gateway" || v == number+"/global/gateways/default-internet-gateway" {
					clean["nextHopGateway"] = "projects/" + projectID + "/global/gateways/default-internet-gateway"
				} else {
					partial = true
					rowPartial = true
				}
			}
			tags, ok := ingressStrings(d, "tags")
			if !ok {
				partial = true
				rowPartial = true
			} else {
				safe := []any{}
				valid := true
				for _, tag := range tags {
					if !ingressTag.MatchString(tag) {
						valid = false
					}
					safe = append(safe, tag)
				}
				if valid {
					clean["tags"] = safe
				} else {
					partial = true
					rowPartial = true
				}
			}
			if rowPartial {
				clean["projection_complete"] = false
			}
			a := NewAsset("//compute.googleapis.com/projects/"+projectID+"/global/routes/"+name, "compute.googleapis.com/Route", clean)
			a.Ancestors = []string{number}
			seen[name] = len(out.Assets)
			out.Assets = append(out.Assets, a)
			count++
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if e == nil && partial {
		e = fmt.Errorf("some route metadata malformed or unavailable")
	}
	out.record("viewer-routes:"+projectID, count, e)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-routes:limitations:" + projectID, Status: "notice", Error: "Selected configured route metadata only. Presence does not establish effective selected routes or ingress/return reachability. Learned, policy-based and peering routes, overlapping prefixes, route priority, forwarding health and packet traffic are not evaluated. Other next-hop details are omitted, not interpreted as an internet gateway. No probes or connectivity tests are performed."})
}
