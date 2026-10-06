package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

// Offline assets carry no live authorization assertion. Only the established
// synthetic record/rule identities and validated RR schema are accepted.
func (c *SecretCapture) captureOfflineDNS(a Asset) bool {
	if a.Type == DNSRecordSetType {
		if regexp.MustCompile(`^//dns\.googleapis\.com/projects/[A-Za-z0-9_-]+/managedZones/[0-9]+/record-metadata/[a-f0-9]{64}$`).MatchString(a.Name) {
			if clean, _ := projectDNSRecordSet(a.Resource.Data); clean != nil {
				c.captureDNSRecord(a.Name, "", a.Resource.Data)
			}
		}
		return true
	}
	if a.Type == DNSResponsePolicyRuleType {
		if regexp.MustCompile(`^//dns\.googleapis\.com/projects/[A-Za-z0-9_-]+/responsePolicies/[0-9]+/rules/[A-Za-z0-9_-]+$`).MatchString(a.Name) {
			if clean, _ := viewerDNSResponseRuleProjection(a.Resource.Data); clean != nil {
				c.captureDNSResponseRule(a.Name, a.Resource.Data)
			}
		}
		return true
	}
	return false
}

// Only reviewed ResourceRecordSet data/routing leaves enter transient capture.
// This never resolves names or follows health-check/network URLs.
func (c *SecretCapture) captureDNSRecord(resource, prefix string, raw Object) {
	if c == nil {
		return
	}
	remaining := 4 << 20
	nodes := 0
	add := func(path, text string) {
		nodes++
		if nodes > 10000 || len(text) > remaining {
			c.Add(SecretSample{})
			return
		}
		remaining -= len(text)
		if text != "" && text != "[REDACTED]" {
			c.Add(SecretSample{SourceType: "dns_record_config", Resource: resource, Path: prefix + path, Data: []byte(text)})
		}
	}
	stringsAt := func(path string, value any, txt bool) {
		rows, ok := value.([]any)
		if !ok {
			if value != nil {
				c.Add(SecretSample{})
			}
			return
		}
		if len(rows) > 10000 {
			c.Add(SecretSample{})
			return
		}
		for i, row := range rows {
			v, ok := row.(string)
			if !ok {
				c.Add(SecretSample{})
				continue
			}
			p := fmt.Sprintf("%s[%d]", path, i)
			add(p, v)
			if txt {
				if decoded, ok := dnsTXTCharacters(v); ok && decoded != v {
					add(p+".decoded", decoded)
				}
			}
		}
	}
	stringsAt("rrdatas", raw["rrdatas"], Str(raw["type"]) == "TXT")
	targets := func(path string, d Object) {
		stringsAt(path+".externalEndpoints", d["externalEndpoints"], false)
		rows, _ := d["internalLoadBalancers"].([]any)
		if len(rows) > 10000 {
			c.Add(SecretSample{})
			return
		}
		for i, row := range rows {
			for _, field := range []string{"ipAddress", "port", "networkUrl"} {
				if v, ok := Obj(row)[field].(string); ok {
					add(fmt.Sprintf("%s.internalLoadBalancers[%d].%s", path, i, field), v)
				}
			}
		}
	}
	items := func(path string, d Object) {
		rows, _ := d["items"].([]any)
		if len(rows) > 10000 {
			c.Add(SecretSample{})
			return
		}
		for i, row := range rows {
			if nodes > 10000 {
				break
			}
			item := Obj(row)
			p := fmt.Sprintf("%s.items[%d]", path, i)
			stringsAt(p+".rrdatas", item["rrdatas"], false)
			targets(p+".healthCheckedTargets", Obj(item["healthCheckedTargets"]))
		}
	}
	policy := Obj(raw["routingPolicy"])
	if v, ok := policy["healthCheck"].(string); ok {
		add("routingPolicy.healthCheck", v)
	}
	items("routingPolicy.geo", Obj(policy["geo"]))
	items("routingPolicy.wrr", Obj(policy["wrr"]))
	backup := Obj(policy["primaryBackup"])
	items("routingPolicy.primaryBackup.backupGeo", Obj(backup["backupGeo"]))
	targets("routingPolicy.primaryBackup.primaryTargets", Obj(backup["primaryTargets"]))
}

func (c *SecretCapture) captureDNSResponseRule(resource string, raw Object) {
	if c == nil {
		return
	}
	rows, _ := Get(raw, "localData", "localDatas").([]any)
	if len(rows) > 10000 {
		c.Add(SecretSample{})
		return
	}
	seen := map[string]bool{}
	for i, row := range rows {
		record := Obj(row)
		kind := Str(record["type"])
		if !strings.EqualFold(Str(record["name"]), Str(raw["dnsName"])) || kind == "NS" || kind == "SOA" || seen[kind] {
			continue
		}
		seen[kind] = true
		if clean, _ := projectDNSRecordSet(record); clean != nil {
			c.captureDNSRecord(resource, fmt.Sprintf("localData.localDatas[%d].", i), record)
		}
	}
}
