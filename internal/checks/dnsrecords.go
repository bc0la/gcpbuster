package checks

import (
	"crypto/sha256"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

func dnsRecordSecrets(a inventory.Asset, _ time.Time) []Result {
	records := []any{}
	switch a.Type {
	case inventory.DNSRecordSetType:
		records = append(records, a.Resource.Data)
	case inventory.DNSResponsePolicyRuleType:
		records = arr(val(a, "localData", "localDatas"))
	default:
		return nil
	}
	rules := map[string]bool{"private_key": true, "google_api_key": true, "google_oauth_access_token": true, "github_token": true, "aws_access_key_id": true, "slack_token": true, "credential_assignment": true, "url_credentials": true}
	var out []Result
	seen := map[string]bool{}
	for recordIndex, raw := range records {
		for _, candidate := range arr(obj(raw)["_gcpbusterSecretCandidates"]) {
			c := obj(candidate)
			field, rule := s(c["field"]), s(c["rule"])
			index, known := gatewaySecretInteger(c["record_index"])
			if !known || index < 0 || index >= 10000 || !rules[rule] || (field != "rrdatas" && field != "routingPolicy") {
				continue
			}
			if field == "routingPolicy" && index != 0 {
				continue
			}
			key := fmt.Sprintf("%d:%s:%d:%s", recordIndex, field, index, rule)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Result{"high", "Potential plaintext credential in DNS configuration", inventory.Object{"local_record_index": recordIndex, "field": field, "record_index": index, "rule": rule, "value": "[REDACTED]", "assessment": "Heuristic metadata-content candidate only; credential validity, publication and access are unverified. No credential was used."}, "Review this record securely, rotate confirmed exposed credentials and remove plaintext credentials from DNS configuration."})
		}
	}
	return out
}

var dnsResponseSelectorLabel = regexp.MustCompile(`^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
var dnsResponseCluster = regexp.MustCompile(`^projects/[A-Za-z0-9][A-Za-z0-9_-]*/locations/[a-z][a-z0-9-]*/clusters/[a-z][a-z0-9-]{0,62}$`)
var dnsEvidenceRecordType = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}$`)

func dnsResponseRule(a inventory.Asset, _ time.Time) []Result {
	complete, known := val(a, "complete").(bool)
	if a.Type != inventory.DNSResponsePolicyRuleType || !known || !complete {
		return nil
	}
	selector := s(val(a, "dnsName"))
	base := strings.TrimPrefix(selector, "*.")
	if len(base) > 254 || !strings.HasSuffix(base, ".") {
		return nil
	}
	if base != "." {
		for _, label := range strings.Split(strings.TrimSuffix(base, "."), ".") {
			if !dnsResponseSelectorLabel.MatchString(label) {
				return nil
			}
		}
	}
	bindings := obj(val(a, "_gcpbusterPolicyBindings"))
	networks := dnsBoundNetworks(bindings["networks"])
	clusters := map[string]bool{}
	for _, raw := range arr(bindings["gkeClusters"]) {
		name := s(obj(raw)["gkeClusterName"])
		if !dnsResponseCluster.MatchString(name) {
			return nil
		}
		clusters[name] = true
	}
	if len(networks)+len(clusters) == 0 {
		return nil
	}
	_, local := a.Resource.Data["localData"]
	_, behavior := a.Resource.Data["behavior"]
	if local == behavior {
		return nil
	}
	mode, title := "", ""
	if behavior && s(val(a, "behavior")) == "bypassResponsePolicy" {
		mode = "bypassResponsePolicy"
		title = "Cloud DNS response rule configures a policy bypass exception"
	}
	if local {
		rows, valid := val(a, "localData", "localDatas").([]any)
		if !valid || len(rows) == 0 {
			return nil
		}
		seen := map[string]bool{}
		for _, row := range rows {
			d := obj(row)
			kind := s(d["type"])
			if !strings.EqualFold(s(d["name"]), selector) || kind == "NS" || kind == "SOA" || !dnsEvidenceRecordType.MatchString(kind) || seen[kind] {
				return nil
			}
			seen[kind] = true
		}
		mode = "localData"
		title = "Cloud DNS response rule configures local answer overrides"
	}
	if mode == "" {
		return nil
	}
	return []Result{{"info", title, inventory.Object{"action": mode, "selector_digest": fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(selector)))), "wildcard": strings.HasPrefix(selector, "*."), "bound_network_count": len(networks), "bound_cluster_count": len(clusters), "assessment": "Configured response-policy rule only. Longest-suffix selection, other policy precedence, actual query scope and successful resolution remain unverified. Bypass continues normal resolution; it does not prove public resolution or malicious interception. No DNS query was sent."}, "Review whether the configured answer override or bypass exception is intended for the policy's bound networks and clusters."}}
}
