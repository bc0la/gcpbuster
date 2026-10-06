package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerBigtableInstanceFields = "instances(name,state,type,edition),failedLocations"
const viewerBigtableTableListFields = "tables(name),nextPageToken"
const viewerBigtableTableFields = "name,deletionProtection,changeStreamConfig(retentionPeriod),automatedBackupPolicy(retentionPeriod,frequency)"

var viewerBigtableTableID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,50}$`)
var viewerBigtableDuration = regexp.MustCompile(`^[0-9]+(\.[0-9]{1,9})?s$`)

func canonicalViewerBigtableName(raw, projectID, number, kind string) string {
	p := strings.Split(raw, "/")
	size := 4
	if kind == "Table" {
		size = 6
	}
	if len(p) != size || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "instances" || !viewerDNSZoneName.MatchString(p[3]) {
		return ""
	}
	if size == 6 && (p[4] != "tables" || !viewerBigtableTableID.MatchString(p[5]) || p[5] == "." || p[5] == "..") {
		return ""
	}
	p[1] = projectID
	return strings.Join(p, "/")
}

// Lists metadata and reads explicitly selected FULL table metadata. No data
// plane calls are made even when the baseline role contains data permissions.
func (c *Client) CollectViewerBigtable(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-bigtable:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	partial := false
	// ListInstances is deliberately unpaginated: its pageToken is deprecated
	// and ignored by the documented API, and it accepts no pageSize.
	page, err := c.get(ctx, "https://bigtableadmin.googleapis.com/v2/projects/"+projectID+"/instances", url.Values{"fields": {viewerBigtableInstanceFields}})
	parents := []string{}
	seen := map[string]bool{}
	if err == nil {
		var rows []any
		rows, err = viewerRows(page, "instances")
		for _, raw := range rows {
			d := Obj(raw)
			name := canonicalViewerBigtableName(Str(d["name"]), projectID, number, "Instance")
			if name == "" || seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			clean := Object{"name": name}
			for field, values := range map[string]string{"state": "STATE_NOT_KNOWN|READY|CREATING", "type": "TYPE_UNSPECIFIED|PRODUCTION|DEVELOPMENT", "edition": "EDITION_UNSPECIFIED|ENTERPRISE|ENTERPRISE_PLUS"} {
				if v, exists := d[field]; exists {
					s, ok := v.(string)
					match := false
					for _, allowed := range strings.Split(values, "|") {
						if s == allowed {
							match = true
						}
					}
					if ok && match {
						clean[field] = s
					} else {
						partial = true
					}
				}
			}
			a := NewAsset("//bigtable.googleapis.com/"+name, "bigtableadmin.googleapis.com/Instance", clean)
			a.Ancestors = []string{number}
			c.viewerBigtableIAM(ctx, out, &a, name)
			out.Assets = append(out.Assets, a)
			parents = append(parents, name)
		}
		if v, exists := page["failedLocations"]; exists {
			r, ok := v.([]any)
			if !ok || len(r) > 0 {
				partial = true
			}
		}
	}
	if err == nil && partial {
		err = fmt.Errorf("some Bigtable instance metadata was malformed, duplicate, foreign or unavailable")
	}
	out.record("viewer-bigtable-instances:"+projectID, len(out.Assets)-start, err)
	for _, parent := range parents {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://bigtableadmin.googleapis.com/v2/"+parent+"/tables", url.Values{"fields": {viewerBigtableTableListFields}, "view": {"NAME_ONLY"}, "pageSize": {"100"}}, func(page Object) error {
			rows, e := viewerRows(page, "tables")
			if e != nil {
				return e
			}
			for _, raw := range rows {
				name := canonicalViewerBigtableName(Str(Obj(raw)["name"]), projectID, number, "Table")
				if name == "" || !strings.HasPrefix(name, parent+"/tables/") || seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				clean := Object{"name": name}
				full, getErr := c.get(ctx, "https://bigtableadmin.googleapis.com/v2/"+name, url.Values{"view": {"FULL"}, "fields": {viewerBigtableTableFields}})
				if getErr == nil {
					var valid bool
					clean, valid = projectViewerBigtableTable(full, name, projectID, number)
					if !valid {
						getErr = fmt.Errorf("malformed or foreign Bigtable table metadata")
					}
					if clean == nil {
						clean = Object{"name": name}
					}
				}
				n := 0
				if getErr == nil {
					n = 1
				} else {
					partial = true
				}
				out.record("viewer-bigtable-table:"+name, n, getErr)
				a := NewAsset("//bigtable.googleapis.com/"+name, "bigtableadmin.googleapis.com/Table", clean)
				a.Ancestors = []string{number}
				c.viewerBigtableIAM(ctx, out, &a, name)
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some Bigtable table metadata was malformed, duplicate, foreign or unavailable")
		}
		out.record("viewer-bigtable-tables:"+parent, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-bigtable:limitations:" + projectID, Status: "notice", Error: "Selected instance and FULL table configuration plus direct IAM only. No row reads, sampled keys, queries, schema contents, change-stream consumption, backup contents, restores or writes. Configuration and direct IAM do not establish effective access or historical abuse. Public principal grants are not supported by Bigtable."})
}

func (c *Client) viewerBigtableIAM(ctx context.Context, out *Snapshot, a *Asset, name string) {
	policy, err := c.readIAMPolicy(ctx, "https://bigtableadmin.googleapis.com/v2/"+name+":getIamPolicy")
	if err == nil {
		a.IAM, err = viewerLogViewPolicy(policy)
	}
	n := 0
	if err == nil {
		n = 1
	}
	out.record("viewer-bigtable-iam:"+name, n, err)
}

func projectViewerBigtableTable(d Object, name, projectID, number string) (Object, bool) {
	if canonicalViewerBigtableName(Str(d["name"]), projectID, number, "Table") != name {
		return nil, false
	}
	out := Object{"name": name}
	valid := true
	if v, exists := d["deletionProtection"]; exists {
		b, ok := v.(bool)
		if ok {
			out["deletionProtection"] = b
		} else {
			valid = false
		}
	}
	for _, key := range []string{"changeStreamConfig", "automatedBackupPolicy"} {
		if v, exists := d[key]; exists {
			cfg := Obj(v)
			if cfg == nil {
				valid = false
				continue
			}
			safe := Object{}
			good := true
			for _, field := range []string{"retentionPeriod", "frequency"} {
				if key == "changeStreamConfig" && field == "frequency" {
					continue
				}
				if v, exists := cfg[field]; exists {
					s, ok := v.(string)
					duration, e := time.ParseDuration(s)
					min, max := 24*time.Hour, 7*24*time.Hour
					if key == "automatedBackupPolicy" {
						min, max = 3*24*time.Hour, 90*24*time.Hour
					}
					if field == "frequency" {
						min, max = 24*time.Hour, 24*time.Hour
					}
					if !ok || !viewerBigtableDuration.MatchString(s) || e != nil || duration < min || duration > max {
						good = false
					} else {
						safe[field] = s
					}
				}
			}
			if good {
				out[key] = safe
			} else {
				valid = false
			}
		}
	}
	return out, valid
}
