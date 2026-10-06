package inventory

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const viewerBackendServiceFields = "items(backendServices(name,id,selfLink,region,protocol,loadBalancingScheme,iap(enabled)),warning),nextPageToken,warning,unreachables"

func viewerComputeUint64(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	n, e := strconv.ParseUint(s, 10, 64)
	return s, e == nil && strconv.FormatUint(n, 10) == s
}

// aggregatedList explicitly includes global and regional backend services.
// No frontend/backend references, OAuth clients/secrets or policy reads are
// needed to retain this selected configured IAP indicator.
func (c *Client) CollectViewerBackendServices(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-backend-services:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	count := 0
	partial := false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/aggregated/backendServices", url.Values{"fields": {viewerBackendServiceFields}, "maxResults": {"100"}, "returnPartialSuccess": {"true"}}, func(page Object) error {
		items := Object{}
		if raw, exists := page["items"]; exists {
			var ok bool
			items, ok = raw.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid aggregated backend service map")
			}
		}
		scopes := []string{}
		for scope := range items {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		for _, scope := range scopes {
			kind, location := "BackendService", "global"
			if scope != "global" {
				p := strings.Split(scope, "/")
				if len(p) != 2 || p[0] != "regions" || !viewerLocation.MatchString(p[1]) || p[1] == "global" {
					partial = true
					continue
				}
				kind, location = "RegionBackendService", p[1]
			}
			group, ok := items[scope].(map[string]any)
			if !ok {
				partial = true
				continue
			}
			rows, e := viewerRows(group, "backendServices")
			if e != nil {
				partial = true
				continue
			}
			if e := viewerComputeExtraWarnings(group, &partial); e != nil {
				partial = true
			}
			for _, raw := range rows {
				d := Obj(raw)
				id := Str(d["name"])
				tail := scope + "/backendServices/" + id
				if !backendID.MatchString(id) || len(id) > 63 {
					partial = true
					continue
				}
				if link, exists := d["selfLink"]; exists && !viewerComputeDiskLink(Str(link), projectID, number, tail) {
					partial = true
					continue
				}
				if region, exists := d["region"]; exists {
					if location == "global" || !viewerComputeDiskLink(Str(region), projectID, number, "regions/"+location) {
						partial = true
						continue
					}
				}
				path := "projects/" + projectID + "/" + tail
				if seen[path] {
					partial = true
					continue
				}
				seen[path] = true
				safe := Object{"name": id}
				if raw, exists := d["id"]; exists {
					if id, ok := viewerComputeUint64(raw); ok {
						safe["id"] = id
					} else {
						partial = true
					}
				}
				if v, exists := d["protocol"]; exists {
					switch v {
					case "GRPC", "H2C", "HTTP", "HTTP2", "HTTPS", "SSL", "TCP", "UDP", "UNSPECIFIED":
						safe["protocol"] = v
					default:
						partial = true
					}
				}
				if v, exists := d["loadBalancingScheme"]; exists {
					switch v {
					case "EXTERNAL", "EXTERNAL_MANAGED", "INTERNAL", "INTERNAL_MANAGED", "INTERNAL_SELF_MANAGED", "INVALID_LOAD_BALANCING_SCHEME":
						safe["loadBalancingScheme"] = v
					default:
						partial = true
					}
				}
				if raw, exists := d["iap"]; exists {
					iap, ok := raw.(map[string]any)
					if !ok {
						partial = true
					} else if enabled, exists := iap["enabled"]; exists {
						if enabled, ok := enabled.(bool); ok {
							safe["iap"] = Object{"enabled": enabled}
						} else {
							partial = true
						}
					}
				}
				a := NewAsset("//compute.googleapis.com/"+path, "compute.googleapis.com/"+kind, safe)
				a.Ancestors = []string{number}
				a.Resource.Location = location
				out.Assets = append(out.Assets, a)
				count++
			}
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some backend service scopes, identities, selected fields or regional results were incomplete")
	}
	out.record("viewer-backend-services:"+projectID, count, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-backend-services:limitations:" + projectID, Status: "notice", Error: "Selected global/regional backend service configuration only. Explicit IAP enablement is not frontend reachability, effective IAP authorization or proof of absent application authentication. Missing flags remain unknown. No IAP policies, OAuth client secrets, health probes, frontend/backend traversal or endpoint requests."})
}
