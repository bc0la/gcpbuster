package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerPubSubSchemaFields = "schemas(name,type,revisionId,revisionCreateTime),nextPageToken"
const PubSubSchemaRevisionType = "gcpbuster.googleapis.com/PubSubSchemaRevision"

var viewerPubSubRevisionID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// CollectViewerPubSubSchemas requests BASIC metadata only. Resource-provided
// names are validated against the selected project before deriving fixed URLs.
func (c *Client) CollectViewerPubSubSchemas(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-pubsub-schemas:identity", 0, fmt.Errorf("invalid schema project identity"))
		return
	}
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	parents := []string{}
	query := func() url.Values {
		return url.Values{"view": {"BASIC"}, "pageSize": {"100"}, "fields": {viewerPubSubSchemaFields}}
	}
	err := c.viewerPages(ctx, "https://pubsub.googleapis.com/v1/projects/"+projectID+"/schemas", query(), func(page Object) error {
		rows, err := viewerRows(page, "schemas")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			clean, name, err := viewerPubSubSchemaProjection(Obj(raw), projectID, number, false)
			if err != nil {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			parents = append(parents, name)
			a := NewAsset("//pubsub.googleapis.com/"+name, "pubsub.googleapis.com/Schema", clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some schema BASIC metadata was malformed or unavailable")
	}
	out.record("viewer-pubsub-schemas:list:"+projectID, len(out.Assets)-start, err)
	for _, parent := range parents {
		start, partial = len(out.Assets), false
		seenRevisions := map[string]bool{}
		pieces := strings.Split(parent, "/")
		endpoint := "https://pubsub.googleapis.com/v1/projects/" + projectID + "/schemas/" + url.PathEscape(pieces[3]) + ":listRevisions"
		err = c.viewerPages(ctx, endpoint, query(), func(page Object) error {
			rows, err := viewerRows(page, "schemas")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				clean, name, err := viewerPubSubSchemaProjection(Obj(raw), projectID, number, true)
				if err != nil || name != parent {
					partial = true
					continue
				}
				revision := Str(clean["revisionId"])
				if seenRevisions[revision] {
					continue
				}
				seenRevisions[revision] = true
				a := NewAsset("//pubsub.googleapis.com/"+parent+"@"+revision, PubSubSchemaRevisionType, clean)
				a.Ancestors = []string{number}
				out.Assets = append(out.Assets, a)
			}
			return viewerAutomationPartial(page, &partial)
		})
		if err == nil && partial {
			err = fmt.Errorf("some schema revisions lacked valid BASIC identity or metadata")
		}
		out.record("viewer-pubsub-schemas:revisions:"+parent, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-pubsub-schemas:limitations:" + projectID, Status: "notice", Error: "BASIC metadata for listed schemas and revisions only. Missing revision IDs are unknown rather than invented. Definitions, message data, direct schema IAM and effective validation behavior are not collected; schemas are never committed, rolled back, validated or modified."})
}

func viewerPubSubSchemaProjection(d Object, projectID, number string, revision bool) (Object, string, error) {
	bad := func() (Object, string, error) { return nil, "", fmt.Errorf("invalid or out-of-scope schema metadata") }
	p := strings.Split(Str(d["name"]), "/")
	if len(p) != 4 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "schemas" {
		return bad()
	}
	id, suffix, hasSuffix := strings.Cut(p[3], "@")
	if !viewerPubSubID.MatchString(id) || strings.HasPrefix(id, "goog") || (hasSuffix && !revision) {
		return bad()
	}
	rev := Str(d["revisionId"])
	if raw, exists := d["revisionId"]; exists {
		if _, ok := raw.(string); !ok || !viewerPubSubRevisionID.MatchString(rev) {
			return bad()
		}
	}
	if revision && !viewerPubSubRevisionID.MatchString(rev) {
		return bad()
	}
	if hasSuffix && suffix != rev {
		return bad()
	}
	name := "projects/" + projectID + "/schemas/" + id
	clean := Object{"name": name}
	if rev != "" {
		clean["revisionId"] = rev
	}
	if raw, exists := d["type"]; exists {
		kind, ok := raw.(string)
		if !ok || (kind != "TYPE_UNSPECIFIED" && kind != "AVRO" && kind != "PROTOCOL_BUFFER") {
			return bad()
		}
		clean["type"] = kind
	}
	if raw, exists := d["revisionCreateTime"]; exists {
		v, ok := raw.(string)
		if _, err := time.Parse(time.RFC3339Nano, v); !ok || err != nil {
			return bad()
		}
		clean["revisionCreateTime"] = v
	}
	return clean, name, nil
}
