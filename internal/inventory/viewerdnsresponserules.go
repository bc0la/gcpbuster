package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const DNSResponsePolicyRuleType = "gcpbuster.googleapis.com/DNSResponsePolicyRule"
const viewerDNSResponseRuleFields = "responsePolicyRules(ruleName,dnsName,behavior,localData(localDatas(name,type,ttl,rrdatas))),nextPageToken"

var viewerDNSResponseRuleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,255}$`)

// CollectViewerDNSResponseRules follows only validated same-project policy
// observations. API rule data is configuration, not live DNS query traffic.
func (c *Client) CollectViewerDNSResponseRules(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-dns-response-rules:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	policies := map[string]Object{}
	conflicts := map[string]bool{}
	idNames := map[string]string{}
	for _, a := range out.Assets {
		if a.Type != "dns.googleapis.com/ResponsePolicy" {
			continue
		}
		d, ok := viewerDNSPolicyProjection(a.Resource.Data, "ResponsePolicy")
		if !ok || a.Name != "//dns.googleapis.com/projects/"+projectID+"/responsePolicies/"+Str(d["id"]) {
			continue
		}
		name := Str(d["responsePolicyName"])
		if _, exists := policies[name]; exists {
			conflicts[name] = true
		}
		if prior, exists := idNames[Str(d["id"])]; exists {
			conflicts[name] = true
			conflicts[prior] = true
		}
		idNames[Str(d["id"])] = name
		policies[name] = d
	}
	names := []string{}
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, policyName := range names {
		if conflicts[policyName] {
			out.record("viewer-dns-response-rules:"+policyName, 0, fmt.Errorf("ambiguous response policy identity"))
			continue
		}
		policy := policies[policyName]
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://dns.googleapis.com/dns/v1/projects/"+projectID+"/responsePolicies/"+policyName+"/rules", url.Values{"maxResults": {"100"}, "fields": {viewerDNSResponseRuleFields}}, func(page Object) error {
			rows, e := viewerRows(page, "responsePolicyRules")
			if e != nil {
				return e
			}
			for _, raw := range rows {
				clean, e := viewerDNSResponseRuleProjection(Obj(raw))
				if e != nil {
					partial = true
				}
				if clean == nil {
					continue
				}
				name := Str(clean["ruleName"])
				if seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				clean["responsePolicyName"] = policyName
				clean["responsePolicyId"] = policy["id"]
				bindings := Object{}
				for _, field := range []string{"networks", "gkeClusters"} {
					if v, ok := policy[field]; ok {
						bindings[field] = v
					}
				}
				clean["_gcpbusterPolicyBindings"] = bindings
				a := NewAsset("//dns.googleapis.com/projects/"+projectID+"/responsePolicies/"+Str(policy["id"])+"/rules/"+name, DNSResponsePolicyRuleType, clean)
				a.Ancestors = []string{number}
				c.SecretCapture.captureDNSResponseRule(a.Name, Obj(raw))
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some response policy rule metadata was malformed or duplicated")
		}
		out.record("viewer-dns-response-rules:"+policyName, len(out.Assets)-start, err)
	}
}

func viewerDNSResponseRuleProjection(d Object) (Object, error) {
	bad := func() (Object, error) { return nil, fmt.Errorf("invalid DNS response policy rule metadata") }
	name, domain := Str(d["ruleName"]), Str(d["dnsName"])
	if !viewerDNSResponseRuleName.MatchString(name) || !validDNSZoneName(strings.TrimPrefix(domain, "*.")) {
		return bad()
	}
	clean := Object{"ruleName": name, "dnsName": domain}
	local, hasLocal := d["localData"]
	behavior, hasBehavior := d["behavior"]
	if hasLocal == hasBehavior {
		return bad()
	}
	if hasBehavior {
		if behavior != "bypassResponsePolicy" {
			return bad()
		}
		clean["behavior"] = behavior
		clean["complete"] = true
		return clean, nil
	}
	rows, ok := Obj(local)["localDatas"].([]any)
	if !ok || len(rows) == 0 {
		return bad()
	}
	records := []any{}
	partial := false
	seen := map[string]bool{}
	for _, raw := range rows {
		record := Obj(raw)
		kind := Str(record["type"])
		if !strings.EqualFold(Str(record["name"]), domain) || kind == "NS" || kind == "SOA" || seen[kind] {
			partial = true
			continue
		}
		seen[kind] = true
		projected, e := projectDNSRecordSet(record)
		if e != nil {
			partial = true
		}
		if projected != nil {
			records = append(records, projected)
		}
	}
	clean["localData"] = Object{"localDatas": records}
	clean["complete"] = !partial
	if partial {
		return clean, fmt.Errorf("some response policy local record data was malformed")
	}
	return clean, nil
}
