package inventory

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const viewerNetworkFields = "items(name,selfLink,autoCreateSubnetworks,enableUlaInternalIpv6,internalIpv6Range,firewallPolicy,networkFirewallPolicyEnforcementOrder,routingConfig(routingMode,bgpBestPathSelectionMode,bgpAlwaysCompareMed,bgpInterRegionCost),peerings(name,network,state,exportCustomRoutes,importCustomRoutes,exportSubnetRoutesWithPublicIp,importSubnetRoutesWithPublicIp,exchangeSubnetRoutes,stackType,updateStrategy,connectionStatus(updateStrategy,trafficConfiguration(exportCustomRoutesToPeer,exportSubnetRoutesWithPublicIpToPeer,importCustomRoutesFromPeer,importSubnetRoutesWithPublicIpFromPeer,stackType)))),nextPageToken,warning(code)"
const viewerSubnetworkFields = "items/*(subnetworks(name,selfLink,region,network,purpose,role,privateIpGoogleAccess,privateIpv6GoogleAccess,ipv6AccessType,stackType,state,ipCidrRange,ipv6CidrRange,internalIpv6Prefix,externalIpv6Prefix,enableFlowLogs,logConfig(enable,aggregationInterval,flowSampling,metadata)),warning(code)),nextPageToken,warning(code),unreachables"

var viewerNetworkReference = regexp.MustCompile(`^(https://(www|compute)\.googleapis\.com/compute/v1/)?projects/[A-Za-z0-9][A-Za-z0-9:._-]*/global/networks/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

func (c *Client) CollectViewerNetworks(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-networks:identity", 0, fmt.Errorf("invalid network project identity"))
		return
	}
	base := "https://compute.googleapis.com/compute/v1/projects/" + projectID
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, base+"/global/networks", url.Values{"maxResults": {"100"}, "fields": {viewerNetworkFields}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			a, err := viewerNetworkAsset(d, projectID, number, "global", "networks", "Network")
			if err != nil {
				partial = true
				continue
			}
			if seen[a.Name] {
				continue
			}
			seen[a.Name] = true
			out.Assets = append(out.Assets, a)
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some network metadata was malformed or unavailable")
	}
	out.record("viewer-networks:list:"+projectID, len(out.Assets)-start, err)
	start, partial = len(out.Assets), false
	seen = map[string]bool{}
	err = c.viewerPages(ctx, base+"/aggregated/subnetworks", url.Values{"maxResults": {"100"}, "returnPartialSuccess": {"true"}, "fields": {viewerSubnetworkFields}}, func(page Object) error {
		if err := viewerComputeExtraWarnings(page, &partial); err != nil {
			return err
		}
		raw, exists := page["items"]
		if !exists {
			return nil
		}
		scoped := Obj(raw)
		if scoped == nil {
			return fmt.Errorf("malformed subnetworks scope map")
		}
		scopes := []string{}
		for scope := range scoped {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		for _, scope := range scopes {
			p := strings.Split(scope, "/")
			if len(p) != 2 || p[0] != "regions" || !viewerComputeDiskID.MatchString(p[1]) {
				partial = true
				continue
			}
			group := Obj(scoped[scope])
			if group == nil {
				partial = true
				continue
			}
			if err := viewerComputeExtraWarnings(group, &partial); err != nil {
				partial = true
				continue
			}
			rows, err := viewerRows(group, "subnetworks")
			if err != nil {
				partial = true
				continue
			}
			for _, raw := range rows {
				d := Obj(raw)
				a, err := viewerNetworkAsset(d, projectID, number, scope, "subnetworks", "Subnetwork")
				if err != nil {
					partial = true
					continue
				}
				if seen[a.Name] {
					continue
				}
				seen[a.Name] = true
				endpoint := base + "/" + scope + "/subnetworks/" + Str(d["name"]) + "/getIamPolicy"
				policy, policyErr := c.get(ctx, endpoint, url.Values{"optionsRequestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag"}})
				if policyErr == nil {
					policy, policyErr = viewerLogViewPolicy(policy)
					if policyErr != nil {
						policyErr = fmt.Errorf("malformed subnetwork IAM policy")
					}
				}
				count := 0
				if policyErr == nil {
					a.IAM = policy
					count = 1
				}
				out.record("viewer-subnetwork-iam:"+a.Name, count, policyErr)
				out.Assets = append(out.Assets, a)
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some subnetwork scopes or metadata were malformed or unavailable")
	}
	out.record("viewer-networks:subnetworks:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-networks:limitations:" + projectID, Status: "notice", Error: "Selected VPC network/subnetwork control-plane metadata and direct subnetwork IAM only. References are not followed, peering connectivity and effective route/firewall behavior are not established. Flow-log filters, labels and descriptions are excluded; selected log flags do not establish effective logging or delivery. No packet probes, connectivity tests, network changes or IAM mutations are performed."})
}

func viewerNetworkAsset(d Object, projectID, number, scope, collection, kind string) (Asset, error) {
	bad := func() (Asset, error) { return Asset{}, fmt.Errorf("invalid network metadata or identity") }
	name := Str(d["name"])
	if !viewerComputeDiskID.MatchString(name) {
		return bad()
	}
	if _, exists := d["selfLink"]; exists {
		if !viewerComputeDiskLink(Str(d["selfLink"]), projectID, number, scope+"/"+collection+"/"+name) {
			return bad()
		}
	}
	stringsFields := []string{"name", "internalIpv6Range", "firewallPolicy", "networkFirewallPolicyEnforcementOrder"}
	boolFields := []string{"autoCreateSubnetworks", "enableUlaInternalIpv6"}
	if kind == "Subnetwork" {
		stringsFields = []string{"name", "network", "purpose", "role", "privateIpv6GoogleAccess", "ipv6AccessType", "stackType", "state", "ipCidrRange", "ipv6CidrRange", "internalIpv6Prefix", "externalIpv6Prefix"}
		boolFields = []string{"privateIpGoogleAccess", "enableFlowLogs"}
		if _, exists := d["region"]; exists {
			if !viewerComputeDiskLink(Str(d["region"]), projectID, number, scope) {
				return bad()
			}
		}
	}
	clean, err := viewerNetworkProjection(d, stringsFields, boolFields)
	if err != nil {
		return bad()
	}
	if raw, exists := d["network"]; exists && kind == "Subnetwork" {
		if !viewerNetworkReference.MatchString(Str(raw)) {
			return bad()
		}
	}
	nested := "routingConfig"
	sf := []string{"routingMode", "bgpBestPathSelectionMode", "bgpInterRegionCost"}
	bf := []string{"bgpAlwaysCompareMed"}
	if kind == "Subnetwork" {
		nested = "logConfig"
		sf = []string{"aggregationInterval", "metadata"}
		bf = []string{"enable"}
	}
	if raw, exists := d[nested]; exists {
		row := Obj(raw)
		if row == nil {
			return bad()
		}
		projected, err := viewerNetworkProjection(row, sf, bf)
		if err != nil {
			return bad()
		}
		if nested == "logConfig" {
			if raw, exists := row["flowSampling"]; exists {
				v, ok := raw.(float64)
				if !ok || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
					return bad()
				}
				projected["flowSampling"] = v
			}
		}
		clean[nested] = projected
	}
	if raw, exists := d["peerings"]; exists && kind == "Network" {
		rows, ok := raw.([]any)
		if !ok {
			return bad()
		}
		peers := []any{}
		for _, raw := range rows {
			row := Obj(raw)
			if row == nil {
				return bad()
			}
			peer, err := viewerNetworkProjection(row, []string{"name", "network", "state", "stackType", "updateStrategy"}, []string{"exportCustomRoutes", "importCustomRoutes", "exportSubnetRoutesWithPublicIp", "importSubnetRoutesWithPublicIp", "exchangeSubnetRoutes"})
			// Compute documents global/networks/NAME as a same-project
			// peering reference. Expand only that exact relative form; do not
			// resolve arbitrary paths, bare names or resource-provided URLs.
			ref := Str(peer["network"])
			if strings.HasPrefix(ref, "global/networks/") && viewerResourceName.MatchString(projectID) && viewerComputeDiskID.MatchString(strings.TrimPrefix(ref, "global/networks/")) {
				peer["network"] = "projects/" + projectID + "/" + ref
			}
			if err != nil || !viewerComputeDiskID.MatchString(Str(peer["name"])) || !viewerNetworkReference.MatchString(Str(peer["network"])) {
				return bad()
			}
			if raw, exists := row["connectionStatus"]; exists {
				connection := Obj(raw)
				if connection == nil {
					return bad()
				}
				projected, err := viewerNetworkProjection(connection, []string{"updateStrategy"}, nil)
				if err != nil {
					return bad()
				}
				if raw, exists := connection["trafficConfiguration"]; exists {
					traffic := Obj(raw)
					if traffic == nil {
						return bad()
					}
					cleanTraffic, err := viewerNetworkProjection(traffic, []string{"stackType"}, []string{"exportCustomRoutesToPeer", "exportSubnetRoutesWithPublicIpToPeer", "importCustomRoutesFromPeer", "importSubnetRoutesWithPublicIpFromPeer"})
					if err != nil {
						return bad()
					}
					projected["trafficConfiguration"] = cleanTraffic
				}
				peer["connectionStatus"] = projected
			}
			peers = append(peers, peer)
		}
		clean["peerings"] = peers
	}
	a := NewAsset("//compute.googleapis.com/projects/"+projectID+"/"+scope+"/"+collection+"/"+name, "compute.googleapis.com/"+kind, clean)
	a.Ancestors = []string{number}
	a.Resource.Location = strings.TrimPrefix(scope, "regions/")
	return a, nil
}

func viewerNetworkProjection(d Object, stringsFields, boolFields []string) (Object, error) {
	clean := Object{}
	for _, field := range stringsFields {
		if raw, exists := d[field]; exists {
			if _, ok := raw.(string); !ok {
				return nil, fmt.Errorf("malformed network string")
			}
			clean[field] = raw
		}
	}
	for _, field := range boolFields {
		if raw, exists := d[field]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, fmt.Errorf("malformed network flag")
			}
			clean[field] = raw
		}
	}
	return clean, nil
}
