package inventory

import (
	"context"
	"fmt"
	"net/url"
	"sort"
)

const viewerSpannerDDLFields = "statements"

// getDdl is schema metadata, never an ExecuteSql/session call. Raw schema and
// proto descriptors are not stored; the parser returns fixed scope markers.
func (c *Client) CollectViewerSpannerDDL(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-spanner-ddl:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := map[string][]int{}
	dialects := map[string]string{}
	ambiguous := map[string]bool{}
	for i, a := range out.Assets {
		if a.Type != "spanner.googleapis.com/Database" {
			continue
		}
		raw := Str(a.Resource.Data["name"])
		name := canonicalViewerSpannerName(raw, projectID, number, "Database")
		if name == "" || a.Name != "//spanner.googleapis.com/"+raw {
			continue
		}
		delete(out.Assets[i].Resource.Data, "_gcpbusterSpannerPublicRoleDDL")
		dialect := Str(a.Resource.Data["databaseDialect"])
		if previous, exists := dialects[name]; exists && previous != dialect {
			ambiguous[name] = true
		}
		dialects[name] = dialect
		parents[name] = append(parents[name], i)
	}
	names := []string{}
	for name := range parents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ambiguous[name] || dialects[name] != "GOOGLE_STANDARD_SQL" {
			out.record("viewer-spanner-ddl:"+name, 0, fmt.Errorf("unsupported, missing or conflicting Spanner schema dialect"))
			continue
		}
		page, err := c.get(ctx, "https://spanner.googleapis.com/v1/"+name+"/ddl", url.Values{"fields": {viewerSpannerDDLFields}})
		var candidates []any
		if err == nil {
			publicRole, publicErr := projectSpannerPublicRole(page, dialects[name])
			for _, i := range parents[name] {
				delete(out.Assets[i].Resource.Data, "_gcpbusterSpannerPublicRoleDDL")
				if publicRole != nil {
					out.Assets[i].Resource.Data["_gcpbusterSpannerPublicRoleDDL"] = publicRole
				}
			}
			out.record("viewer-spanner-public-role:"+name, 0, publicErr)
			candidates, err = projectSpannerDDL(page, dialects[name])
		}
		if len(candidates) > 0 {
			for _, i := range parents[name] {
				out.Assets[i].Resource.Data["_gcpbusterChangeStreams"] = candidates
			}
		}
		out.record("viewer-spanner-ddl:"+name, len(candidates), err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-spanner-ddl:limitations:" + projectID, Status: "notice", Error: "Transient GoogleSQL schema metadata inspection for supported CREATE CHANGE STREAM FOR ALL and table/column SELECT grants to SQL public or named roles, including mixed privileges, quoted ordinary grantees and qualified tables. Raw DDL, identifiers, option values and proto descriptors omitted. No sessions, SQL execution, rows, stream consumption or schema mutation; other dialects, pending schema changes, unsupported FGAC syntax and effective access remain unassessed."})
}
