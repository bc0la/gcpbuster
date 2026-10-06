package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const workflowExecutionFields = "executions(name,argument,result,error(payload)),nextPageToken"

var workflowExecutionParent = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/workflows/[A-Za-z0-9_-]+$`)
var workflowExecutionID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// CollectViewerWorkflowExecutions inspects retained execution text, never runs
// a workflow or follows callback URLs. FULL list needs only executions.list.
func (c *Client) CollectViewerWorkflowExecutions(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("workflow-executions:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := map[string]bool{}
	for _, asset := range out.Assets {
		if asset.Type != "workflows.googleapis.com/Workflow" {
			continue
		}
		parent := strings.TrimPrefix(asset.Name, "//workflows.googleapis.com/")
		if !workflowExecutionParent.MatchString(parent) || !(strings.HasPrefix(parent, "projects/"+projectID+"/") || strings.HasPrefix(parent, number+"/")) {
			continue
		}
		parents[parent] = true
	}
	count := 0
	for _, parent := range orderedViewerRegions(parents) {
		err := c.viewerPages(ctx, "https://workflowexecutions.googleapis.com/v1/"+parent+"/executions", url.Values{"view": {"FULL"}, "pageSize": {"100"}, "fields": {workflowExecutionFields}}, func(page Object) error {
			rows, err := viewerRows(page, "executions")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				count++
				if count > 10000 {
					return fmt.Errorf("workflow execution read limit reached")
				}
				d := Obj(raw)
				name := Str(d["name"])
				canonical := parameterCanonicalName(name, projectID, number)
				expected := parameterCanonicalName(parent, projectID, number) + "/executions/"
				if !strings.HasPrefix(canonical, expected) || !workflowExecutionID.MatchString(strings.TrimPrefix(canonical, expected)) {
					return fmt.Errorf("workflow execution identity mismatch")
				}
				region := strings.Split(parent, "/")[3]
				for _, field := range []string{"argument", "result", "error.payload"} {
					var value any
					if field == "error.payload" {
						value = Obj(d["error"])["payload"]
					} else {
						value = d[field]
					}
					if value == nil {
						continue
					}
					text, ok := value.(string)
					if !ok {
						return fmt.Errorf("invalid workflow execution text")
					}
					if text != "" {
						c.SecretCapture.Add(SecretSample{SourceType: "workflow_execution", Resource: "//workflowexecutions.googleapis.com/" + canonical, Location: region, Path: field, Data: []byte(text)})
					}
				}
			}
			return nil
		})
		out.record("workflow-executions:"+parent, count, err)
		if count > 10000 {
			break
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "workflow-executions:retention:" + projectID, Status: "notice", Error: "Retained execution arguments, results and error payloads only; history retention and pagination on dynamic data limit completeness. No execution, cancellation, callback or credential validation."})
}

func workflowExecutionPermissions(method string, u *url.URL, q url.Values) ([]string, error) {
	parent := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/v1/"), "/executions")
	if method != "GET" || u.RawPath != "" || !strings.HasSuffix(u.Path, "/executions") || !workflowExecutionParent.MatchString(parent) || q.Get("view") != "FULL" || q.Get("pageSize") != "100" || q.Get("fields") != workflowExecutionFields {
		return nil, fmt.Errorf("viewer-only policy: unreviewed workflow execution request")
	}
	for key, values := range q {
		if (key != "view" && key != "pageSize" && key != "fields" && key != "pageToken") || len(values) != 1 {
			return nil, fmt.Errorf("viewer-only policy: unreviewed workflow execution query")
		}
	}
	return []string{"workflows.executions.list"}, nil
}
