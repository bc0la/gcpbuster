package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const deploymentNamesFields = "deployments(name,selfLink),nextPageToken"
const manifestNamesFields = "manifests(name,selfLink),nextPageToken"
const manifestContentFields = "name,selfLink,config(content),imports(content),expandedConfig,layout"

var deploymentRequestPath = regexp.MustCompile(`^/deploymentmanager/v2/projects/[A-Za-z0-9_-]+/global/deployments(?:/[A-Za-z0-9_-]+/manifests(?:/[A-Za-z0-9_-]+)?)?$`)

// Existing Deployment Manager customers retain V2 API access through June 30,
// 2027. Immutable manifest configuration is readable with roles/viewer.
// https://docs.cloud.google.com/deployment-manager/docs/deprecations
// https://docs.cloud.google.com/deployment-manager/docs/reference/latest/manifests
func (c *Client) CollectViewerDeploymentManager(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("deployment-manager:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parent := "/deploymentmanager/v2/" + number + "/global/deployments"
	count := 0
	listPages := 0
	for _, deployment := range c.deploymentNames(ctx, out, parent, "deployments", deploymentNamesFields, projectID, number, &listPages) {
		if listPages >= 10000 {
			out.record("deployment-manager:list-limit", listPages, fmt.Errorf("manifest total discovery page limit reached"))
			return
		}
		path := parent + "/" + deployment + "/manifests"
		for _, manifest := range c.deploymentNames(ctx, out, path, "manifests", manifestNamesFields, projectID, number, &listPages) {
			count++
			if count > 10000 {
				out.record("deployment-manager:limit", count-1, fmt.Errorf("manifest read limit reached"))
				return
			}
			resource := path + "/" + manifest
			raw, err := c.get(ctx, "https://www.googleapis.com"+resource, url.Values{"fields": {manifestContentFields}})
			n := 0
			if err == nil {
				err = c.captureDeploymentManifest(raw, resource, manifest, projectID, number)
				if err == nil {
					n = 1
				}
			}
			out.record("deployment-manager:manifest:"+number+"/"+deployment+"/"+manifest, n, err)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "deployment-manager:boundary:" + projectID, Status: "notice", Error: "Immutable manifest config, imports, expandedConfig and layout only; no template execution, reference downloads or mutations. Support ended April 1, 2026; existing-customer API ends June 30, 2027."})
}

func deploymentIdentity(raw Object, path, name, projectID, number string) bool {
	if Str(raw["name"]) != name {
		return false
	}
	if link, exists := raw["selfLink"]; exists {
		s, ok := link.(string)
		if !ok {
			return false
		}
		canonical := strings.Replace(path, "/"+number+"/", "/projects/"+projectID+"/", 1)
		if s != "https://www.googleapis.com"+path && s != "https://www.googleapis.com"+canonical {
			return false
		}
	}
	return true
}

func (c *Client) deploymentNames(ctx context.Context, out *Snapshot, path, key, fields, projectID, number string, totalPages *int) []string {
	names := []string{}
	seen := map[string]bool{}
	partial := false
	pages := 0
	err := c.viewerPages(ctx, "https://www.googleapis.com"+path, url.Values{"maxResults": {"100"}, "fields": {fields}}, func(page Object) error {
		pages++
		*totalPages++
		if pages > 100 {
			return fmt.Errorf("manifest discovery page limit reached")
		}
		if *totalPages >= 10000 && Str(page["nextPageToken"]) != "" {
			return fmt.Errorf("manifest total discovery page limit reached")
		}
		rows, err := viewerRows(page, key)
		if err != nil {
			return err
		}
		for _, row := range rows {
			d := Obj(row)
			name := Str(d["name"])
			if !viewerKeyResourceID.MatchString(name) || !deploymentIdentity(d, path+"/"+name, name, projectID, number) {
				partial = true
				continue
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
			if len(names) >= 10000 {
				return fmt.Errorf("manifest discovery limit reached")
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("malformed or foreign manifest discovery identity")
	}
	out.record("deployment-manager:list:"+strings.TrimPrefix(path, "/deploymentmanager/v2/"), len(names), err)
	return names
}

func (c *Client) captureDeploymentManifest(raw Object, path, name, projectID, number string) error {
	if !deploymentIdentity(raw, path, name, projectID, number) {
		return fmt.Errorf("manifest identity mismatch")
	}
	type field struct {
		path  string
		value any
	}
	fields := []field{{"expandedConfig", raw["expandedConfig"]}, {"layout", raw["layout"]}}
	if config, exists := raw["config"]; exists {
		d, ok := config.(map[string]any)
		if !ok {
			if o, yes := config.(Object); yes {
				d = map[string]any(o)
			} else {
				return fmt.Errorf("invalid manifest config")
			}
		}
		fields = append(fields, field{"config.content", d["content"]})
	}
	if imports, exists := raw["imports"]; exists {
		rows, ok := imports.([]any)
		if !ok || len(rows) > 10000 {
			return fmt.Errorf("invalid manifest imports")
		}
		for i, row := range rows {
			d := Obj(row)
			if d == nil {
				return fmt.Errorf("invalid manifest import")
			}
			fields = append(fields, field{fmt.Sprintf("imports[%d].content", i), d["content"]})
		}
	}
	// Validate the complete response before admitting any samples.
	for _, f := range fields {
		if f.value != nil {
			s, ok := f.value.(string)
			if !ok || len(s) > 4<<20 {
				return fmt.Errorf("invalid or oversized manifest content")
			}
		}
	}
	for _, f := range fields {
		s, _ := f.value.(string)
		if s != "" && !c.SecretCapture.Add(SecretSample{SourceType: "deployment_manager_manifest", Resource: "//deploymentmanager.googleapis.com/" + strings.TrimPrefix(path, "/deploymentmanager/v2/"), Location: "global", Path: f.path, Data: []byte(s)}) {
			return fmt.Errorf("manifest capture limit or conflict")
		}
	}
	return nil
}

func deploymentManagerPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed Deployment Manager request")
	}
	if method != "GET" || u.Host != "www.googleapis.com" || u.RawPath != "" || !deploymentRequestPath.MatchString(u.Path) {
		return fail()
	}
	permission, fields := "deploymentmanager.manifests.get", manifestContentFields
	if strings.HasSuffix(u.Path, "/deployments") {
		permission, fields = "deploymentmanager.deployments.list", deploymentNamesFields
	} else if strings.HasSuffix(u.Path, "/manifests") {
		permission, fields = "deploymentmanager.manifests.list", manifestNamesFields
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
		if strings.HasSuffix(permission, ".get") || (k != "pageToken" && (k != "maxResults" || v[0] != "100")) {
			return fail()
		}
	}
	if strings.HasSuffix(permission, ".list") && q.Get("maxResults") != "100" {
		return fail()
	}
	return []string{permission}, nil
}
