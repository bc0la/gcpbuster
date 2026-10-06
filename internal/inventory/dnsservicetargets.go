package inventory

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var dnsObservedService = regexp.MustCompile(`^//(run|apigateway)\.googleapis\.com/projects/([A-Za-z0-9_-]+)/locations/[a-z][a-z0-9-]*/(services|gateways)/[A-Za-z0-9_-]+$`)
var dnsObservedApplication = regexp.MustCompile(`^//appengine\.googleapis\.com/apps/([A-Za-z0-9_-]+)$`)
var dnsObservedZone = regexp.MustCompile(`^//dns\.googleapis\.com/projects/([A-Za-z0-9_-]+)/managedZones/[A-Za-z0-9_-]+$`)
var dnsObservedRecordSuffix = regexp.MustCompile(`^/record-metadata/[a-f0-9]{64}$`)
var dnsObservedResolvedRecord = regexp.MustCompile(`^(//dns\.googleapis\.com/projects/[A-Za-z0-9_-]+/managedZones/[A-Za-z0-9_-]+)/rrsets/([^/]+)/([^/]+)$`)

// CorrelateDNSServiceTargets performs a bounded exact-host metadata join only.
// Missing matches never mean deletion, nonresolution or name reclaimability.
// Different project aliases are not merged without authoritative identity data.
func CorrelateDNSServiceTargets(out *Snapshot) {
	for i := range out.Assets {
		if out.Assets[i].Type == DNSRecordSetType || out.Assets[i].Type == "dns.googleapis.com/ResourceRecordSet" {
			delete(out.Assets[i].Resource.Data, "_gcpbusterObservedServiceTarget")
		}
	}
	if len(out.Assets) > 100000 {
		out.Coverage = append(out.Coverage, Coverage{Source: "dns-observed-service-targets", Status: "incomplete", Error: "Snapshot exceeds bounded exact-host metadata correlation limit"})
		return
	}
	type endpoint struct{ host, project, kind, name string }
	byName := map[string]endpoint{}
	conflicted := map[string]bool{}
	zonePublic := map[string]bool{}
	zoneSeen := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type == "dns.googleapis.com/ManagedZone" && dnsObservedZone.MatchString(a.Name) {
			valid := Str(a.Resource.Data["visibility"]) == "public"
			if zoneSeen[a.Name] && zonePublic[a.Name] != valid {
				conflicted[a.Name] = true
			}
			zoneSeen[a.Name] = true
			zonePublic[a.Name] = valid
		}
		project, host := dnsServiceEndpoint(a)
		if project == "" {
			if dnsObservedService.MatchString(a.Name) || dnsObservedApplication.MatchString(a.Name) {
				conflicted[a.Name] = true
			}
			continue
		}
		entry := endpoint{host, project, a.Type, a.Name}
		if old, ok := byName[a.Name]; ok && old != entry {
			conflicted[a.Name] = true
		}
		byName[a.Name] = entry
	}
	byHost := map[string][]endpoint{}
	for _, entry := range byName {
		if !conflicted[entry.name] {
			key := entry.project + "\x00" + entry.host
			byHost[key] = append(byHost[key], entry)
		}
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		if (a.Type != DNSRecordSetType && a.Type != "dns.googleapis.com/ResourceRecordSet") || Str(a.Resource.Data["type"]) != "CNAME" || Str(a.Resource.Data["zoneVisibility"]) != "public" {
			continue
		}
		zone := Str(a.Resource.Data["managedZone"])
		resolvedHost := ""
		if a.Type == "dns.googleapis.com/ResourceRecordSet" {
			m := dnsObservedResolvedRecord.FindStringSubmatch(a.Name)
			if m == nil || m[2] != Str(a.Resource.Data["name"]) {
				continue
			}
			var valid bool
			resolvedHost, valid = DNSLookupName(Str(a.Resource.Data["target"]))
			namedHost, namedValid := DNSLookupName(m[3])
			if !valid || !namedValid || resolvedHost != namedHost {
				continue
			}
			zone = m[1]
		}
		z := dnsObservedZone.FindStringSubmatch(zone)
		if z == nil || !zonePublic[zone] || conflicted[zone] || !strings.HasPrefix(a.Name, zone) || (resolvedHost == "" && !dnsObservedRecordSuffix.MatchString(strings.TrimPrefix(a.Name, zone))) {
			continue
		}
		marker := Object{"status": "unknown", "basis": "exact_same_project_observed_hostname_metadata"}
		a.Resource.Data["_gcpbusterObservedServiceTarget"] = marker
		// A CNAME must have exactly one simple target; routing and incomplete rows
		// cannot supply a deterministic ownership observation.
		targets, ok := a.Resource.Data["_gcpbusterRecordTargets"].([]any)
		if resolvedHost != "" {
			targets = []any{Object{"kind": "CNAME", "host": resolvedHost}}
			ok = true
		}
		if !ok || len(targets) != 1 || a.Resource.Data["routing_policy_present"] == true {
			continue
		}
		if resolvedHost == "" && !dnsExactlyOne(a.Resource.Data["data_count"]) {
			continue
		}
		target := Obj(targets[0])
		if Str(target["kind"]) != "CNAME" {
			continue
		}
		host, ok := DNSLookupName(Str(target["host"]))
		if !ok {
			continue
		}
		entries := byHost[z[1]+"\x00"+host]
		if len(entries) > 1 {
			marker["status"] = "ambiguous"
			continue
		}
		if len(entries) != 1 {
			continue
		}
		marker["status"] = "matched"
		marker["host"] = host
		marker["resource"] = entries[0].name
		marker["resource_type"] = entries[0].kind
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "dns-observed-service-targets", Status: "notice", Error: "Exact same-project public CNAME to observed Run URI, API Gateway default hostname or supplied App Engine default hostname only. No DNS queries, URL requests, suffix inference, cross-project alias assumptions or compiled API-name-as-endpoint inference. Missing or conflicting inventory remains unknown; matches do not prove reachability, public authentication, deletion or takeover."})
}

func dnsExactlyOne(v any) bool {
	switch n := v.(type) {
	case int:
		return n == 1
	case float64:
		return n == 1
	case json.Number:
		return n.String() == "1"
	}
	return false
}

func dnsServiceEndpoint(a Asset) (string, string) {
	project, host, relative := "", "", ""
	if m := dnsObservedService.FindStringSubmatch(a.Name); m != nil {
		project = m[2]
		relative = strings.TrimPrefix(a.Name, "//"+m[1]+".googleapis.com/")
		switch {
		case m[1] == "run" && m[3] == "services" && a.Type == "run.googleapis.com/Service":
			raw, ok := a.Resource.Data["uri"].(string)
			if !ok || len(raw) > 2048 {
				return "", ""
			}
			u, e := url.Parse(raw)
			if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				return "", ""
			}
			host = u.Hostname()
		case m[1] == "apigateway" && m[3] == "gateways" && a.Type == "apigateway.googleapis.com/Gateway":
			host = Str(a.Resource.Data["defaultHostname"])
		default:
			return "", ""
		}
	} else if m := dnsObservedApplication.FindStringSubmatch(a.Name); m != nil && a.Type == "appengine.googleapis.com/Application" {
		project = m[1]
		relative = "apps/" + project
		host = Str(a.Resource.Data["defaultHostname"])
	} else {
		return "", ""
	}
	if Str(a.Resource.Data["name"]) != relative {
		return "", ""
	}
	normalized, ok := DNSLookupName(host)
	if !ok {
		return "", ""
	}
	return project, normalized
}
