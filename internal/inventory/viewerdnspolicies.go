package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const viewerDNSPolicyFields = "policies(id,name,enableLogging,enableInboundForwarding,networks(networkUrl),alternativeNameServerConfig(targetNameServers(ipv4Address,ipv6Address,forwardingPath)),dns64Config(scope(allQueries))),nextPageToken"
const viewerDNSResponsePolicyFields = "responsePolicies(id,responsePolicyName,networks(networkUrl),gkeClusters(gkeClusterName)),nextPageToken"

var viewerDNSNetworkRef = regexp.MustCompile(`^projects/[A-Za-z0-9][A-Za-z0-9_-]*/global/networks/[a-z][a-z0-9-]{0,62}$`)
var viewerDNSClusterRef = regexp.MustCompile(`^projects/[A-Za-z0-9][A-Za-z0-9_-]*/locations/[a-z][a-z0-9-]*/clusters/[a-z][a-z0-9-]{0,62}$`)

// These are configured policy observations, not DNS resolution probes or
// evidence that any bound network/cluster or forwarding target is reachable.
func (c *Client) CollectViewerDNSPolicies(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-dns-policies:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	for _, spec := range []struct{ collection, kind, fields string }{{"policies", "Policy", viewerDNSPolicyFields}, {"responsePolicies", "ResponsePolicy", viewerDNSResponsePolicyFields}} {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://dns.googleapis.com/dns/v1/projects/"+projectID+"/"+spec.collection, url.Values{"maxResults": {"100"}, "fields": {spec.fields}}, func(page Object) error {
			rows, err := viewerRows(page, spec.collection)
			if err != nil {
				return err
			}
			for _, raw := range rows {
				clean, valid := viewerDNSPolicyProjection(Obj(raw), spec.kind)
				if !valid {
					partial = true
					continue
				}
				id := Str(clean["id"])
				if seen[id] {
					partial = true
					continue
				}
				seen[id] = true
				a := NewAsset("//dns.googleapis.com/projects/"+projectID+"/"+spec.collection+"/"+id, "dns.googleapis.com/"+spec.kind, clean)
				a.Ancestors = []string{number}
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some DNS policy metadata was malformed or duplicated")
		}
		out.record("viewer-dns-"+spec.collection+":"+projectID, len(out.Assets)-start, err)
	}
}

func viewerDNSPolicyProjection(d Object, kind string) (Object, bool) {
	nameField := "name"
	if kind == "ResponsePolicy" {
		nameField = "responsePolicyName"
	}
	id, name := Str(d["id"]), Str(d[nameField])
	if !viewerNumericID.MatchString(id) || !viewerDNSZoneName.MatchString(name) {
		return nil, false
	}
	clean := Object{"id": id, nameField: name}
	for _, spec := range []struct{ field, key string }{{"networks", "networkUrl"}, {"gkeClusters", "gkeClusterName"}} {
		if spec.field == "gkeClusters" && kind != "ResponsePolicy" {
			continue
		}
		v, exists := d[spec.field]
		if !exists {
			continue
		}
		rows, ok := v.([]any)
		if !ok {
			return nil, false
		}
		list := []any{}
		for _, r := range rows {
			ref := Str(Obj(r)[spec.key])
			if spec.field == "networks" {
				ref = strings.TrimPrefix(ref, "https://www.googleapis.com/compute/v1/")
				if !viewerDNSNetworkRef.MatchString(ref) {
					return nil, false
				}
			} else if !viewerDNSClusterRef.MatchString(ref) {
				return nil, false
			}
			list = append(list, Object{spec.key: ref})
		}
		clean[spec.field] = list
	}
	if kind == "ResponsePolicy" {
		return clean, true
	}
	for _, field := range []string{"enableLogging", "enableInboundForwarding"} {
		if v, exists := d[field]; exists {
			b, ok := v.(bool)
			if !ok {
				return nil, false
			}
			clean[field] = b
		}
	}
	if v, exists := d["dns64Config"]; exists {
		cfg := Obj(v)
		if cfg == nil {
			return nil, false
		}
		scope := Obj(cfg["scope"])
		if scope == nil {
			return nil, false
		}
		b, ok := scope["allQueries"].(bool)
		if !ok {
			return nil, false
		}
		clean["dns64Config"] = Object{"scope": Object{"allQueries": b}}
	}
	if v, exists := d["alternativeNameServerConfig"]; exists {
		cfg := Obj(v)
		if cfg == nil {
			return nil, false
		}
		targets, ok := cfg["targetNameServers"].([]any)
		if !ok {
			return nil, false
		}
		list := []any{}
		for _, target := range targets {
			t := Obj(target)
			for _, key := range []string{"ipv4Address", "ipv6Address"} {
				if raw, exists := t[key]; exists {
					if value, ok := raw.(string); !ok || value == "" {
						return nil, false
					}
				}
			}
			v4, v6 := Str(t["ipv4Address"]), Str(t["ipv6Address"])
			if (v4 == "") == (v6 == "") {
				return nil, false
			}
			field, address := "ipv4Address", v4
			if v6 != "" {
				field, address = "ipv6Address", v6
			}
			ip, e := netip.ParseAddr(address)
			if e != nil || ip.Zone() != "" || ip.Is4In6() || (field == "ipv4Address") != ip.Is4() {
				return nil, false
			}
			path := "default"
			if v, exists := t["forwardingPath"]; exists {
				var ok bool
				path, ok = v.(string)
				if !ok || (path != "default" && path != "private") {
					return nil, false
				}
			}
			list = append(list, Object{field: ip.String(), "forwardingPath": path})
		}
		clean["alternativeNameServerConfig"] = Object{"targetNameServers": list}
	}
	return clean, true
}
