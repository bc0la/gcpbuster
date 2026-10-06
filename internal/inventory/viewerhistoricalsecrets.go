package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const workflowRevisionNamesFields = "workflows(name,revisionId),nextPageToken"
const workflowRevisionConfigFields = "name,revisionId,sourceContents,userEnvVars"
const runRevisionConfigFields = "revisions(name,service,serviceAccount,containers(image,command,args,env(name,value,valueSource))),nextPageToken"
const runRevisionDetailFields = "name,service,serviceAccount,containers(image,command,args,env(name,value,valueSource))"

var workflowRevisionID = regexp.MustCompile(`^[0-9]{6}-[a-f0-9]{3}$`)
var runServiceParent = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/services/[A-Za-z0-9_-]+$`)

func (c *Client) CollectViewerHistoricalSecrets(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("historical-secrets:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := map[string]string{}
	for _, a := range out.Assets {
		if a.Type != "workflows.googleapis.com/Workflow" && a.Type != "run.googleapis.com/Service" {
			continue
		}
		name := strings.TrimPrefix(a.Name, "//"+strings.SplitN(a.Type, "/", 2)[0]+"/")
		if !(strings.HasPrefix(name, "projects/"+projectID+"/") || strings.HasPrefix(name, number+"/")) {
			continue
		}
		if a.Type == "workflows.googleapis.com/Workflow" && workflowExecutionParent.MatchString(name) {
			parents[name] = "workflow"
		}
		if a.Type == "run.googleapis.com/Service" && runServiceParent.MatchString(name) {
			parents[name] = "run"
		}
	}
	count := 0
	keys := map[string]bool{}
	for name := range parents {
		keys[name] = true
	}
	for _, parent := range orderedViewerRegions(keys) {
		region := strings.Split(parent, "/")[3]
		canonical := parameterCanonicalName(parent, projectID, number)
		if parents[parent] == "workflow" {
			err := c.viewerPages(ctx, "https://workflows.googleapis.com/v1/"+parent+":listRevisions", url.Values{"pageSize": {"100"}, "fields": {workflowRevisionNamesFields}}, func(page Object) error {
				rows, e := viewerRows(page, "workflows")
				if e != nil {
					return e
				}
				seen := map[string]bool{}
				for _, raw := range rows {
					count++
					if count > 10000 {
						return fmt.Errorf("historical configuration read limit reached")
					}
					d := Obj(raw)
					revision := Str(d["revisionId"])
					if parameterCanonicalName(Str(d["name"]), projectID, number) != canonical || !workflowRevisionID.MatchString(revision) {
						return fmt.Errorf("workflow revision identity mismatch")
					}
					if seen[revision] {
						continue
					}
					seen[revision] = true
					full, e := c.get(ctx, "https://workflows.googleapis.com/v1/"+parent, url.Values{"revisionId": {revision}, "fields": {workflowRevisionConfigFields}})
					if e != nil {
						out.record("historical-secrets:workflow-detail:"+parent+":"+revision, 0, e)
						continue
					}
					if parameterCanonicalName(Str(full["name"]), projectID, number) != canonical || Str(full["revisionId"]) != revision {
						return fmt.Errorf("workflow revision detail identity mismatch")
					}
					text, ok := full["sourceContents"].(string)
					if !ok || text == "" {
						out.record("historical-secrets:workflow-source:"+parent+":"+revision, 0, fmt.Errorf("workflow revision source omitted"))
						continue
					}
					root := "revisions[" + revision + "]."
					resource := "//workflows.googleapis.com/" + canonical
					c.SecretCapture.Add(SecretSample{SourceType: "workflow_revision_definition", Resource: resource, Location: region, Path: root + "sourceContents", Data: []byte(text)})
					c.SecretCapture.CaptureStringMap("workflow_revision_env", resource, region, root+"userEnvVars", full["userEnvVars"])
				}
				return nil
			})
			out.record("historical-secrets:workflow:"+parent, count, err)
		} else {
			err := c.viewerPages(ctx, "https://run.googleapis.com/v2/"+parent+"/revisions", url.Values{"pageSize": {"100"}, "showDeleted": {"true"}, "fields": {runRevisionConfigFields}}, func(page Object) error {
				rows, e := viewerRows(page, "revisions")
				if e != nil {
					return e
				}
				for _, raw := range rows {
					count++
					if count > 10000 {
						return fmt.Errorf("historical configuration read limit reached")
					}
					d := Obj(raw)
					name := parameterCanonicalName(Str(d["name"]), projectID, number)
					prefix := canonical + "/revisions/"
					if !strings.HasPrefix(name, prefix) || !viewerKeyResourceID.MatchString(strings.TrimPrefix(name, prefix)) {
						return fmt.Errorf("run revision identity mismatch")
					}
					if d["service"] != nil && parameterCanonicalName(Str(d["service"]), projectID, number) != canonical {
						return fmt.Errorf("run revision service mismatch")
					}
					c.SecretCapture.captureContainers("run_revision_config", "//run.googleapis.com/"+name, region, "containers", d["containers"])
					c.SecretCapture.captureRunRevisionContext("//run.googleapis.com/"+name, region, d)
				}
				return nil
			})
			out.record("historical-secrets:run:"+parent, count, err)
		}
		if count > 10000 {
			break
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "historical-secrets:retention:" + projectID, Status: "notice", Error: "Retained workflow revisions and Cloud Run service revisions, including API-visible deleted but unexpired revisions, only. Historical retention and discovered parent visibility limit completeness; no deployment, execution, restore, callbacks, image/source download or credential validation."})
}

func historicalSecretPermissions(method string, u *url.URL, q url.Values) ([]string, error) {
	if method != "GET" || u.RawPath != "" {
		return nil, fmt.Errorf("viewer-only policy: unreviewed historical configuration request")
	}
	permissions := []string{}
	want := workflowRevisionNamesFields
	if u.Host == "workflows.googleapis.com" {
		parent := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/v1/"), ":listRevisions")
		if !workflowExecutionParent.MatchString(parent) {
			return nil, fmt.Errorf("viewer-only policy: invalid workflow revision parent")
		}
		if strings.HasSuffix(u.Path, ":listRevisions") {
			permissions = []string{"workflows.workflows.listRevision"}
			if q.Get("pageSize") != "100" {
				return nil, fmt.Errorf("viewer-only policy: invalid revision page size")
			}
		} else {
			permissions = []string{"workflows.workflows.get"}
			want = workflowRevisionConfigFields
			if !workflowRevisionID.MatchString(q.Get("revisionId")) {
				return nil, fmt.Errorf("viewer-only policy: invalid workflow revision")
			}
		}
	} else if u.Host == "run.googleapis.com" {
		if regexp.MustCompile(`^/v2/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/services/[A-Za-z0-9_-]+/revisions/[A-Za-z0-9_-]+$`).MatchString(u.Path) {
			if len(q) != 1 || len(q["fields"]) != 1 || q.Get("fields") != runRevisionDetailFields {
				return nil, fmt.Errorf("viewer-only policy: unreviewed run revision detail query")
			}
			return []string{"run.revisions.get"}, nil
		}
		parent := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/v2/"), "/revisions")
		if !strings.HasSuffix(u.Path, "/revisions") || !runServiceParent.MatchString(parent) || q.Get("pageSize") != "100" || q.Get("showDeleted") != "true" {
			return nil, fmt.Errorf("viewer-only policy: invalid run revision request")
		}
		permissions = []string{"run.revisions.list"}
		want = runRevisionConfigFields
	} else {
		return nil, fmt.Errorf("viewer-only policy: invalid historical host")
	}
	if q.Get("fields") != want {
		return nil, fmt.Errorf("viewer-only policy: unreviewed revision fields")
	}
	for key, values := range q {
		allowed := key == "fields"
		if permissions[0] == "workflows.workflows.get" {
			allowed = allowed || key == "revisionId"
		} else {
			allowed = allowed || key == "pageSize" || key == "pageToken" || (permissions[0] == "run.revisions.list" && key == "showDeleted")
		}
		if !allowed || len(values) != 1 {
			return nil, fmt.Errorf("viewer-only policy: unreviewed revision query")
		}
	}
	return permissions, nil
}
