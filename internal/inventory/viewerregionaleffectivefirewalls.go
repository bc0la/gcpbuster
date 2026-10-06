package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Regions come only from scoped observed subnetworks and their explicit network
// links. No policy names or region guesses are used to expand collection.
func (c *Client) CollectViewerRegionalEffectiveFirewalls(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-regional-effective-firewalls:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	re := regexp.MustCompile(`^//compute\.googleapis\.com/projects/([A-Za-z0-9_-]+)/regions/([a-z][a-z0-9-]*)/subnetworks/([a-z][-a-z0-9]*)$`)
	pairs := map[string]string{}
	identities := map[string]string{}
	conflicts := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "compute.googleapis.com/Subnetwork" {
			continue
		}
		m := re.FindStringSubmatch(a.Name)
		if m == nil || (m[1] != projectID && "projects/"+m[1] != number) || Str(a.Resource.Data["name"]) != m[3] {
			continue
		}
		network := ingressNetwork(a.Resource.Data["network"])
		if strings.HasPrefix(network, number+"/") {
			network = "projects/" + projectID + strings.TrimPrefix(network, number)
		}
		if !strings.HasPrefix(network, "projects/"+projectID+"/global/networks/") {
			continue
		}
		identity := "regions/" + m[2] + "/subnetworks/" + m[3]
		pair := m[2] + "|" + network
		if prior, exists := identities[identity]; exists && prior != pair {
			conflicts[prior] = true
			conflicts[pair] = true
		}
		identities[identity] = pair
		pairs[pair] = network
	}
	keys := []string{}
	for key := range pairs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if i >= 1024 {
			out.Coverage = append(out.Coverage, Coverage{Source: "viewer-regional-effective-firewalls:bounds:" + projectID, Status: "incomplete", Error: "Observed network/region pairs exceed bounded collection"})
			break
		}
		if conflicts[key] {
			out.record("viewer-regional-effective-firewalls:ambiguous:"+key, 0, fmt.Errorf("conflicting observed subnetwork network identity"))
			continue
		}
		region := strings.SplitN(key, "|", 2)[0]
		network := pairs[key]
		d, e := c.get(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/regions/"+region+"/firewallPolicies/getEffectiveFirewalls", url.Values{"fields": {viewerEffectiveFirewallFields}, "network": {network}})
		count := 0
		if e == nil {
			safe, pe := projectEffectiveFirewallScope(d, network, true)
			e = pe
			safe["region"] = region
			a := NewAsset("//compute.googleapis.com/"+network+"/effectiveFirewalls/"+region, EffectiveRegionalNetworkFirewallsType, safe)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			out.Assets = append(out.Assets, a)
			count = 1
		}
		out.record("viewer-regional-effective-firewalls:"+key, count, e)
	}
}
