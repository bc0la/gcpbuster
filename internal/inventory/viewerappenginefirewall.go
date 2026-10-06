package inventory

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"sort"
)

const AppEngineFirewallType = "gcpbuster.googleapis.com/AppEngineFirewall"
const viewerAppEngineFirewallFields = "ingressRules(priority,action,sourceRange),nextPageToken"

func (c *Client) CollectViewerAppEngineFirewall(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerAppEngineID.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-appengine-firewall:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	rules := []any{}
	priorities := map[int]bool{}
	partial := false
	defaultFound := false
	err := c.viewerPages(ctx, "https://appengine.googleapis.com/v1/apps/"+projectID+"/firewall/ingressRules", url.Values{"pageSize": {"100"}, "fields": {viewerAppEngineFirewallFields}}, func(page Object) error {
		rows, err := viewerRows(page, "ingressRules")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			p, ok := d["priority"].(float64)
			action := Str(d["action"])
			source := Str(d["sourceRange"])
			if !ok || math.IsNaN(p) || math.IsInf(p, 0) || math.Trunc(p) != p || p < 1 || p > 2147483647 || (action != "ALLOW" && action != "DENY") {
				partial = true
				continue
			}
			if priorities[int(p)] {
				partial = true
				continue
			}
			priorities[int(p)] = true
			if source == "0/0" {
				source = "0.0.0.0/0"
			}
			if source != "*" {
				if prefix, e := netip.ParsePrefix(source); e == nil && !prefix.Addr().Is4In6() {
					source = prefix.Masked().String()
				} else if addr, e := netip.ParseAddr(source); e == nil && addr.Zone() == "" && !addr.Is4In6() {
					source = netip.PrefixFrom(addr, addr.BitLen()).String()
				} else {
					partial = true
					continue
				}
			}
			if int(p) == 2147483647 {
				if source != "*" {
					partial = true
					continue
				}
				defaultFound = true
			}
			rules = append(rules, Object{"priority": int(p), "action": action, "sourceRange": source})
		}
		return nil
	})
	if err == nil && (partial || !defaultFound) {
		err = fmt.Errorf("App Engine firewall rules are malformed, duplicate, or missing the mandatory default rule")
	}
	sort.Slice(rules, func(i, j int) bool { return Obj(rules[i])["priority"].(int) < Obj(rules[j])["priority"].(int) })
	a := NewAsset("//appengine.googleapis.com/apps/"+projectID+"/firewall", AppEngineFirewallType, Object{"rules": rules, "complete": err == nil})
	a.Ancestors = []string{number}
	out.Assets = append(out.Assets, a)
	out.record("viewer-appengine-firewall:"+projectID, len(rules), err)
}
