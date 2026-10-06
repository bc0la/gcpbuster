package inventory

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const BigtableAuthorizedViewType = "gcpbuster.googleapis.com/BigtableAuthorizedView"
const viewerBigtableAuthorizedViewFields = "authorizedViews(name,deletionProtection,subsetView),nextPageToken"

// Only known table parents are followed. Selector bytes and family names are
// transient: persisted scope summaries cannot reconstruct table contents.
func (c *Client) CollectViewerBigtableAuthorizedViews(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-bigtable-views:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "bigtableadmin.googleapis.com/Table" {
			continue
		}
		name := Str(a.Resource.Data["name"])
		parent, ok := canonicalBigtableViewResource(name, projectID, number, false)
		if ok && a.Name == "//bigtable.googleapis.com/"+name {
			parents[parent] = true
		}
	}
	names := []string{}
	for parent := range parents {
		names = append(names, parent)
	}
	sort.Strings(names)
	for _, parent := range names {
		start, partial := len(out.Assets), false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://bigtableadmin.googleapis.com/v2/"+parent+"/authorizedViews", url.Values{"pageSize": {"100"}, "view": {"FULL"}, "fields": {viewerBigtableAuthorizedViewFields}}, func(page Object) error {
			rows, err := viewerRows(page, "authorizedViews")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				d := Obj(raw)
				name, ok := canonicalBigtableViewResource(Str(d["name"]), projectID, number, true)
				if !ok || !strings.HasPrefix(name, parent+"/authorizedViews/") || seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				clean := Object{"name": name}
				if v, exists := d["deletionProtection"]; exists {
					if b, ok := v.(bool); ok {
						clean["deletionProtection"] = b
					} else {
						partial = true
					}
				}
				scope, ok := projectBigtableSubsetScope(d["subsetView"])
				clean["subset_scope"] = scope
				if !ok {
					partial = true
				}
				a := NewAsset("//bigtable.googleapis.com/"+name, BigtableAuthorizedViewType, clean)
				a.Ancestors = []string{number}
				policy, policyErr := c.readIAMPolicy(ctx, "https://bigtableadmin.googleapis.com/v2/"+name+":getIamPolicy")
				if policyErr == nil {
					a.IAM, policyErr = viewerLogViewPolicy(policy)
				}
				count := 0
				if policyErr == nil {
					count = 1
				}
				out.record("viewer-bigtable-view-iam:"+name, count, policyErr)
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some authorized-view metadata was malformed, duplicated or out of scope")
		}
		out.record("viewer-bigtable-views:"+parent, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-bigtable-views:limitations:" + projectID, Status: "notice", Error: "Selected authorized-view configuration and direct IAM only. Row/qualifier selectors and family names are omitted. No rows, samples, SQL queries, effective authorization or data-plane calls are collected."})
}

func canonicalBigtableViewResource(name, projectID, number string, view bool) (string, bool) {
	p := strings.Split(name, "/")
	want := 6
	if view {
		want = 8
	}
	if len(p) != want {
		return "", false
	}
	parent := canonicalViewerBigtableName(strings.Join(p[:6], "/"), projectID, number, "Table")
	if parent == "" {
		return "", false
	}
	if view && (p[6] != "authorizedViews" || !viewerBigtableTableID.MatchString(p[7]) || p[7] == "." || p[7] == "..") {
		return "", false
	}
	p[1] = projectID
	return strings.Join(p, "/"), true
}

func projectBigtableSubsetScope(raw any) (Object, bool) {
	out := Object{"complete": false}
	d := Obj(raw)
	if d == nil {
		return out, false
	}
	remaining, entries := 4<<20, 10000
	// A byte field accepts standard/URL-safe padded or unpadded protobuf JSON.
	countPrefixes := func(raw any) (int, bool, bool) {
		if raw == nil {
			return 0, false, true
		}
		rows, ok := raw.([]any)
		if !ok || len(rows) > entries {
			return 0, false, false
		}
		entries -= len(rows)
		empty := false
		for _, v := range rows {
			s, ok := v.(string)
			if !ok || len(s) > remaining || strings.ContainsAny(s, "\r\n") {
				return 0, false, false
			}
			remaining -= len(s)
			valid := false
			for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(), base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict()} {
				if _, err := encoding.DecodeString(s); err == nil {
					valid = true
					break
				}
			}
			if !valid {
				return 0, false, false
			}
			if s == "" {
				empty = true
			}
		}
		return len(rows), empty, true
	}
	rows, allRows, ok := countPrefixes(d["rowPrefixes"])
	if !ok {
		return out, false
	}
	families := Object{}
	if raw, exists := d["familySubsets"]; exists {
		families = Obj(raw)
		if families == nil || len(families) > entries {
			return out, false
		}
	}
	entries -= len(families)
	allQualifiers := 0
	for name, raw := range families {
		if name == "" || len(name) > 1024 || len(name) > remaining {
			return out, false
		}
		remaining -= len(name)
		f := Obj(raw)
		if f == nil {
			return out, false
		}
		if _, _, ok := countPrefixes(f["qualifiers"]); !ok {
			return out, false
		}
		_, all, ok := countPrefixes(f["qualifierPrefixes"])
		if !ok {
			return out, false
		}
		if all {
			allQualifiers++
		}
	}
	return Object{"complete": true, "all_rows": allRows, "row_prefix_count": rows, "family_count": len(families), "all_qualifiers_family_count": allQualifiers}, true
}
