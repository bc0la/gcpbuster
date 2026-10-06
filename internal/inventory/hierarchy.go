package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ExpandResourceScopes traverses only children of explicitly selected containers.
// Parent validation prevents malformed responses from expanding the assessment
// outside that hierarchy. Partial discovery remains usable but never looks complete.
func (c *Client) ExpandResourceScopes(ctx context.Context, snap *Snapshot, scopes []string) []string {
	queue := append([]string(nil), scopes...)
	seen := map[string]bool{}
	projectIDs := map[string]string{}
	var out []string
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if seen[parent] {
			continue
		}
		seen[parent] = true
		if !logScopePattern.MatchString(parent) {
			snap.record("resource-hierarchy:scope", 0, fmt.Errorf("invalid resource container"))
			continue
		}
		if strings.HasPrefix(parent, "projects/") {
			id := strings.TrimPrefix(parent, "projects/")
			if !c.IncludeSystemProjects {
				if known := projectIDs[parent]; known != "" {
					id = known
				} else if projectNumberPattern.MatchString(parent) {
					metadata, err := c.get(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+parent, url.Values{"fields": {"name,projectId"}})
					if err != nil || Str(metadata["name"]) != parent || !viewerResourceName.MatchString(Str(metadata["projectId"])) {
						if err == nil {
							err = fmt.Errorf("invalid project identity for exclusion check")
						}
						snap.record("project-exclusion-identity:"+parent, 0, err)
						continue
					}
					id = Str(metadata["projectId"])
				}
				if strings.HasPrefix(id, "sys-") {
					c.recordSystemProjectExclusion(snap, parent)
					continue
				}
			}
			out = append(out, parent)
			continue
		}
		out = append(out, parent)
		if err := ctx.Err(); err != nil {
			snap.record("resource-hierarchy:"+parent, 0, err)
			break
		}
		for _, kind := range []string{"projects", "folders"} {
			start := time.Now()
			c.ReportProgress(ProgressEvent{Phase: "hierarchy", Scope: parent, Collector: kind, Status: "started"})
			children, err := c.hierarchyChildrenWithProjects(ctx, parent, kind, projectIDs, snap)
			status := "completed"
			if err != nil {
				status = "failed"
			}
			c.ReportProgress(ProgressEvent{Phase: "hierarchy", Scope: parent, Collector: kind, Status: status, Count: len(children), Duration: time.Since(start)})
			snap.record("resource-hierarchy:"+parent+":"+kind, len(children), err)
			queue = append(queue, children...)
		}
	}
	return out
}

func (c *Client) hierarchyChildren(ctx context.Context, parent, kind string) ([]string, error) {
	return c.hierarchyChildrenWithProjects(ctx, parent, kind, nil, nil)
}

func (c *Client) hierarchyChildrenWithProjects(ctx context.Context, parent, kind string, projectIDs map[string]string, snap *Snapshot) ([]string, error) {
	q := url.Values{"parent": {parent}, "pageSize": {"100"}, "showDeleted": {"false"}}
	var out []string
	seen := map[string]bool{}
	for {
		page, err := c.get(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+kind, q)
		if err != nil {
			return out, err
		}
		if page == nil {
			return out, fmt.Errorf("invalid hierarchy response")
		}
		if raw, exists := page[kind]; exists {
			if _, ok := raw.([]any); !ok {
				return out, fmt.Errorf("invalid hierarchy children")
			}
		}
		for _, raw := range List(page[kind]) {
			child := Obj(raw)
			name := Str(child["name"])
			if !strings.HasPrefix(name, kind+"/") || !logScopePattern.MatchString(name) || Str(child["parent"]) != parent || name == parent {
				return out, fmt.Errorf("invalid or out-of-scope hierarchy child")
			}
			switch Str(child["state"]) {
			case "ACTIVE":
				if kind == "projects" {
					id := Str(child["projectId"])
					if projectIDs != nil && viewerResourceName.MatchString(id) {
						projectIDs[name] = id
					}
					if !c.IncludeSystemProjects && strings.HasPrefix(id, "sys-") {
						c.recordSystemProjectExclusion(snap, name)
						continue
					}
				}
				out = append(out, name)
			case "DELETE_REQUESTED": // Not a currently active assessment target.
			default:
				return out, fmt.Errorf("hierarchy child has unknown lifecycle state")
			}
		}
		if raw, exists := page["nextPageToken"]; exists {
			if _, ok := raw.(string); !ok {
				return out, fmt.Errorf("invalid hierarchy pagination token")
			}
		}
		c.ReportProgress(ProgressEvent{Phase: "hierarchy-page", Scope: parent, Collector: kind, Status: "completed", Count: len(out)})
		next := Str(page["nextPageToken"])
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return out, fmt.Errorf("repeated hierarchy pagination token")
		}
		seen[next] = true
		q.Set("pageToken", next)
	}
}

func (c *Client) recordSystemProjectExclusion(snap *Snapshot, scope string) {
	if snap != nil {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "project-exclusion:" + scope, Status: "skipped", Error: "Project ID starts with sys- and is excluded by default. This naming heuristic is not proof of an Apps Script project; use --include-system-projects to include it."})
	}
	c.ReportProgress(ProgressEvent{Phase: "project", Scope: scope, Status: "excluded", Reason: "sys- project ID prefix; include-system-projects overrides"})
}
