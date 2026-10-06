package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const notebookListFields = "instances(name),nextPageToken,unreachable"
const notebookGetFields = "name,gceSetup(metadata)"

var notebookListPath = regexp.MustCompile(`^/v2/projects/[A-Za-z0-9_-]+/locations/-/instances$`)
var notebookGetPath = regexp.MustCompile(`^/v2/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/instances/[A-Za-z0-9_-]+$`)

// Modern Workbench v2 supports all-location discovery and exposes custom VM
// metadata, including inline lifecycle configuration. Neither notebook content
// nor referenced startup-script objects are read.
// https://docs.cloud.google.com/gemini-enterprise-agent-platform/notebooks/workbench/reference/rest/v2/projects.locations.instances/list
func (c *Client) CollectViewerNotebookSecrets(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("notebooks:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	names := []string{}
	seen := map[string]bool{}
	partial := false
	pages := 0
	err := c.viewerPages(ctx, "https://notebooks.googleapis.com/v2/"+number+"/locations/-/instances", url.Values{"pageSize": {"100"}, "fields": {notebookListFields}}, func(page Object) error {
		pages++
		if pages > 100 {
			return fmt.Errorf("notebook discovery page limit reached")
		}
		rows, e := viewerRows(page, "instances")
		if e != nil {
			return e
		}
		for _, row := range rows {
			name := parameterCanonicalName(Str(Obj(row)["name"]), projectID, number)
			if !strings.HasPrefix(name, number+"/locations/") || !notebookGetPath.MatchString("/v2/"+name) {
				partial = true
				continue
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
			if len(names) >= 10000 {
				return fmt.Errorf("notebook discovery limit reached")
			}
		}
		inaccessible, e := viewerBuildWorkflowUnreachable(page)
		partial = partial || inaccessible
		return e
	})
	if err == nil && partial {
		err = fmt.Errorf("notebook discovery malformed or incomplete")
	}
	out.record("notebooks:list:"+number, len(names), err)
	for _, name := range names {
		raw, e := c.get(ctx, "https://notebooks.googleapis.com/v2/"+name, url.Values{"fields": {notebookGetFields}})
		n := 0
		if e == nil {
			e = c.captureNotebookMetadata(raw, name, projectID, number)
			if e == nil {
				n = 1
			}
		}
		out.record("notebooks:get:"+name, n, e)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "notebooks:boundary:" + projectID, Status: "notice", Error: "Workbench v2 custom VM metadata only. No notebook files, proxy endpoints, runtime credentials, script URI downloads or execution. Legacy v1 managed/user-managed notebooks reached end of life March 30, 2026; underlying Compute metadata is collected separately."})
}

func (c *Client) captureNotebookMetadata(raw Object, name, projectID, number string) error {
	if parameterCanonicalName(Str(raw["name"]), projectID, number) != name {
		return fmt.Errorf("notebook instance identity mismatch")
	}
	if setup, exists := raw["gceSetup"]; exists {
		d := Obj(setup)
		if d == nil {
			return fmt.Errorf("invalid notebook setup")
		}
		if metadata, exists := d["metadata"]; exists {
			m := Obj(metadata)
			if m == nil || len(m) > 10000 {
				return fmt.Errorf("invalid notebook metadata")
			}
			for _, v := range m {
				s, ok := v.(string)
				if !ok || len(s) > 4<<20 {
					return fmt.Errorf("invalid or oversized notebook metadata value")
				}
			}
			location := strings.Split(name, "/")[3]
			c.SecretCapture.CaptureStringMap("workbench_metadata", "//notebooks.googleapis.com/"+name, location, "gceSetup.metadata", metadata)
		}
	}
	return nil
}

func notebookSecretsPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) { return nil, fmt.Errorf("viewer-only policy: unreviewed Notebooks request") }
	if method != "GET" || u.Host != "notebooks.googleapis.com" || u.RawPath != "" {
		return fail()
	}
	permission, fields := "notebooks.instances.get", notebookGetFields
	if notebookListPath.MatchString(u.Path) {
		permission, fields = "notebooks.instances.list", notebookListFields
	} else if !notebookGetPath.MatchString(u.Path) {
		return fail()
	}
	if q.Get("fields") != fields {
		return fail()
	}
	for k, v := range q {
		if len(v) != 1 {
			return fail()
		}
		if k == "fields" {
			continue
		}
		if permission == "notebooks.instances.get" || (k != "pageToken" && (k != "pageSize" || v[0] != "100")) {
			return fail()
		}
	}
	if permission == "notebooks.instances.list" && q.Get("pageSize") != "100" {
		return fail()
	}
	return []string{permission}, nil
}
