package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const viewerRunDomainFields = "items(metadata(name,namespace,generation),spec(routeName),status(conditions(type,status),observedGeneration,mappedRouteName,resourceRecords(name,type,rrdata))),metadata(continue),unreachable"
const RunDomainMappingType = "gcpbuster.googleapis.com/RunDomainMapping"

var viewerRunRegionalHost = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]-run\.googleapis\.com$`)

// This is conditional, NOT verified basic-Viewer coverage. REST and audit
// documentation specify run.domainmappings.list, but current published role
// catalogs do not establish its inclusion in Viewer. Never alias routes.list
// or a service-qualified spelling: only the freshly loaded exact three-role
// union can authorize a request. Regions come from Run's locations response.
func (c *Client) CollectViewerRunDomains(ctx context.Context, out *Snapshot, projectID, number, region string) {
	source := "viewer-run-domain-mappings:" + projectID + ":" + region
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) || !viewerServerlessRegion.MatchString(region) || region == "global" {
		out.record(source, 0, fmt.Errorf("invalid scoped Run domain mapping identity"))
		return
	}
	endpoint := "https://" + region + "-run.googleapis.com/apis/domains.cloudrun.com/v1/namespaces/" + projectID + "/domainmappings"
	q := url.Values{"fields": {viewerRunDomainFields}, "limit": {"100"}}
	if err := c.requireViewerPermissions(ctx, "GET", endpoint, q); err != nil {
		out.Coverage = append(out.Coverage, Coverage{Source: source, Status: "incomplete", Error: "Domain mappings were not requested: exact run.domainmappings.list permission could not be verified in the three allowed roles; no routes.list or service-qualified alias is substituted."})
		return
	}
	count := 0
	partial := false
	seen := map[string]bool{}
	tokens := map[string]bool{}
	var err error
	for pageNumber := 0; pageNumber < 10000; pageNumber++ {
		var page Object
		page, err = c.get(ctx, endpoint, q)
		if err != nil {
			break
		}
		var rows []any
		rows, err = viewerRows(page, "items")
		if err != nil {
			break
		}
		for _, raw := range rows {
			safe, e := projectViewerRunDomain(Obj(raw), projectID, number, region)
			if safe == nil {
				partial = true
				continue
			}
			if e != nil {
				partial = true
			}
			name := Str(safe["name"])
			if seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			a := NewAsset("//run.googleapis.com/"+name, RunDomainMappingType, safe)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			out.Assets = append(out.Assets, a)
			count++
		}
		if u, exists := page["unreachable"]; exists {
			rows, ok := u.([]any)
			if !ok || len(rows) > 0 {
				partial = true
			}
		}
		meta := Object{}
		if raw, exists := page["metadata"]; exists {
			var ok bool
			meta, ok = raw.(map[string]any)
			if !ok {
				err = fmt.Errorf("invalid Run domain mapping pagination metadata")
				break
			}
		}
		token := ""
		if raw, exists := meta["continue"]; exists {
			var ok bool
			token, ok = raw.(string)
			if !ok {
				err = fmt.Errorf("invalid Run domain mapping continuation")
				break
			}
		}
		if token == "" {
			break
		}
		if tokens[token] {
			err = fmt.Errorf("repeated Run domain mapping continuation")
			break
		}
		tokens[token] = true
		q.Set("continue", token)
		if pageNumber == 9999 {
			err = fmt.Errorf("Run domain mapping pagination limit reached")
		}
	}
	if err == nil && partial {
		err = fmt.Errorf("some Run domain mapping metadata malformed, duplicated, foreign or unreachable")
	}
	out.record(source, count, err)
	out.Coverage = append(out.Coverage, Coverage{Source: source + ":limitations", Status: "notice", Error: "Observed custom-domain mapping configuration only; suggested resource records are not observed DNS records. No DNS queries, endpoint probes, ownership verification, provisioning or takeover attempts. A surviving mapping does not establish domain reclaimability or default Run URL takeover."})
}

func projectViewerRunDomain(raw Object, projectID, number, region string) (Object, error) {
	m := Obj(raw["metadata"])
	namespace := Str(m["namespace"])
	host, valid := DNSLookupName(Str(m["name"]))
	if !valid || (namespace != projectID && "projects/"+namespace != number) {
		return nil, fmt.Errorf("invalid domain mapping identity")
	}
	d := Object{"name": "projects/" + projectID + "/locations/" + region + "/domainMappings/" + host, "metadata": Object{"name": host, "namespace": projectID}}
	partial := false
	meta := Obj(d["metadata"])
	for _, pair := range []struct {
		from Object
		key  string
		to   Object
	}{{m, "generation", meta}} {
		if value, exists := pair.from[pair.key]; exists {
			if n, ok := viewerRunGeneration(value); ok {
				pair.to[pair.key] = n
			} else {
				partial = true
			}
		}
	}
	spec, status := Object{}, Object{}
	d["spec"] = spec
	d["status"] = status
	if value, exists := raw["spec"]; exists {
		s, ok := value.(map[string]any)
		if !ok {
			partial = true
		} else if value, exists := s["routeName"]; exists {
			route := Str(value)
			if viewerResourceName.MatchString(route) {
				spec["routeName"] = route
				d["_gcpbusterServiceReference"] = "//run.googleapis.com/projects/" + projectID + "/locations/" + region + "/services/" + route
			} else {
				partial = true
			}
		}
	}
	s := Obj(raw["status"])
	if value, exists := raw["status"]; exists {
		if _, ok := value.(map[string]any); !ok {
			partial = true
		}
	}
	if value, exists := s["mappedRouteName"]; exists {
		if route := Str(value); viewerResourceName.MatchString(route) {
			status["mappedRouteName"] = route
		} else {
			partial = true
		}
	}
	if value, exists := s["observedGeneration"]; exists {
		if n, ok := viewerRunGeneration(value); ok {
			status["observedGeneration"] = n
		} else {
			partial = true
		}
	}
	conditions, e := viewerRows(s, "conditions")
	if e != nil {
		partial = true
	} else {
		selected := []any{}
		for _, row := range conditions {
			condition := Obj(row)
			kind, state := Str(condition["type"]), Str(condition["status"])
			if (kind != "Ready" && kind != "CertificateProvisioned" && kind != "DomainRoutable") || (state != "True" && state != "False" && state != "Unknown") {
				partial = true
				continue
			}
			selected = append(selected, Object{"type": kind, "status": state})
		}
		status["conditions"] = selected
	}
	records, e := viewerRows(s, "resourceRecords")
	if e != nil {
		partial = true
	} else {
		selected := []any{}
		for _, row := range records {
			r := Obj(row)
			kind, value := Str(r["type"]), Str(r["rrdata"])
			good := false
			switch kind {
			case "A", "AAAA":
				ip, e := netip.ParseAddr(value)
				good = e == nil && ip.Zone() == "" && ((kind == "A" && ip.Is4()) || (kind == "AAAA" && ip.Is6() && !ip.Is4In6()))
				if good {
					value = ip.String()
				}
			case "CNAME":
				value, good = DNSLookupName(value)
			}
			if !good {
				partial = true
				continue
			}
			record := Object{"type": kind, "rrdata": value}
			if name, exists := r["name"]; exists {
				n, ok := name.(string)
				if !ok || n != "" && !validDNSZoneName(n+".") {
					partial = true
					continue
				}
				record["name"] = n
			}
			selected = append(selected, record)
		}
		status["resourceRecords"] = selected
	}
	if partial {
		return d, fmt.Errorf("some domain mapping fields invalid")
	}
	return d, nil
}

func viewerRunGeneration(v any) (string, bool) {
	switch n := v.(type) {
	case string:
		if regexp.MustCompile(`^[0-9]{1,18}$`).MatchString(n) {
			return n, true
		}
	case float64:
		if n >= 0 && n < 1e15 && n == float64(int64(n)) {
			return fmt.Sprintf("%.0f", n), true
		}
	case int:
		if n >= 0 {
			return fmt.Sprint(n), true
		}
	case int64:
		if n >= 0 {
			return fmt.Sprint(n), true
		}
	}
	return "", false
}

func viewerRunDomainQueryValid(method, path string, q url.Values) bool {
	if method != "GET" || !regexp.MustCompile(`^/apis/domains\.cloudrun\.com/v1/namespaces/[A-Za-z0-9_-]+/domainmappings$`).MatchString(path) || q.Get("fields") != viewerRunDomainFields || q.Get("limit") != "100" {
		return false
	}
	for k, v := range q {
		if len(v) != 1 || (k != "fields" && k != "limit" && k != "continue") {
			return false
		}
	}
	return !strings.Contains(path, "..")
}
