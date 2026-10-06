package inventory

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const parameterTemplateListFields = "templates(name),nextPageToken,unreachable"
const parameterTemplateVersionListFields = "templateVersions(name),nextPageToken,unreachable"
const parameterTemplateVersionFields = "name,payload(data)"

// Template versions expose raw YAML/JSON blueprints through documented GET.
// Reading is not rendering: no substitution or Secret Manager dereference.
func (c *Client) collectParameterTemplates(ctx context.Context, out *Snapshot, parent, region, projectID, number string, budget *secretCollectionBudget) {
	defer func() {
		if budget.exhausted {
			out.Coverage = append(out.Coverage, Coverage{Source: "parameter-templates:limit:" + number, Status: "incomplete", Error: "Shared template discovery/read budget exhausted; remaining payloads were not read."})
		}
	}()
	for _, template := range c.parameterTemplateNames(ctx, out, parent, "templates", "templates", parameterTemplateListFields, region, projectID, number, budget) {
		if budget.exhausted {
			return
		}
		for _, version := range c.parameterTemplateNames(ctx, out, template, "versions", "templateVersions", parameterTemplateVersionListFields, region, projectID, number, budget) {
			if budget.exhausted || budget.pages >= 1000 {
				budget.exhausted = true
				return
			}
			budget.pages++
			d, err := c.get(ctx, "https://parametermanager.googleapis.com/v1/"+version, url.Values{"fields": {parameterTemplateVersionFields}})
			count := 0
			if err == nil {
				err = c.captureParameterTemplateVersion(d, version, region, projectID, number)
				if err == nil {
					count = 1
					a := NewAsset("//parametermanager.googleapis.com/"+version, "parametermanager.googleapis.com/TemplateVersion", Object{"name": version})
					a.Ancestors = []string{number}
					a.Resource.Location = region
					out.Assets = append(out.Assets, a)
				}
			}
			out.record("parameter-templates:version:"+version, count, err)
		}
	}
}

func (c *Client) parameterTemplateNames(ctx context.Context, out *Snapshot, parent, collection, key, fields, region, projectID, number string, budget *secretCollectionBudget) []string {
	names := []string{}
	seen := map[string]bool{}
	err := c.secretCollectionPages(ctx, "https://parametermanager.googleapis.com/v1/"+parent+"/"+collection, url.Values{"pageSize": {"100"}, "fields": {fields}}, budget, func(page Object) error {
		rows, err := viewerRows(page, key)
		if err != nil {
			return err
		}
		for _, r := range rows {
			name := parameterCanonicalName(Str(Obj(r)["name"]), projectID, number)
			prefix := parent + "/" + collection + "/"
			id := strings.TrimPrefix(name, prefix)
			if !strings.HasPrefix(name, prefix) || !viewerKeyResourceID.MatchString(id) {
				return fmt.Errorf("invalid or foreign parameter template identity")
			}
			if seen[name] {
				return fmt.Errorf("duplicate parameter template identity")
			}
			if err := budget.takeResource(); err != nil {
				return err
			}
			seen[name] = true
			names = append(names, name)
			if collection == "templates" {
				a := NewAsset("//parametermanager.googleapis.com/"+name, "parametermanager.googleapis.com/Template", Object{"name": name})
				a.Resource.Location = region
				a.Ancestors = []string{number}
				out.Assets = append(out.Assets, a)
			}
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		if err != nil {
			return err
		}
		if unreachable {
			return fmt.Errorf("parameter templates returned unreachable resources")
		}
		return nil
	})
	out.record("parameter-templates:list:"+parent+"/"+collection, len(names), err)
	return names
}

func (c *Client) captureParameterTemplateVersion(d Object, expected, region, projectID, number string) error {
	if parameterCanonicalName(Str(d["name"]), projectID, number) != expected {
		return fmt.Errorf("mismatched parameter template version identity")
	}
	text, ok := Get(d, "payload", "data").(string)
	if !ok || text == "" || len(text) > base64.StdEncoding.EncodedLen(4<<20) {
		return fmt.Errorf("missing or oversized parameter template raw payload")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(data) == 0 || len(data) > 4<<20 {
		return fmt.Errorf("invalid or oversized parameter template raw payload")
	}
	if !c.SecretCapture.Add(SecretSample{SourceType: "parameter_template_raw", Resource: "//parametermanager.googleapis.com/" + expected, Location: region, Path: "payload.data", Data: data}) {
		return fmt.Errorf("parameter template capture limit or conflict")
	}
	return nil
}

func parameterTemplatePermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed parameter template request")
	}
	if method != "GET" || u.Host != "parametermanager.googleapis.com" || u.RawPath != "" {
		return fail()
	}
	base := `^/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/templates`
	permission, fields := "", ""
	switch {
	case regexp.MustCompile(base + `$`).MatchString(u.Path):
		permission = "templates.list"
		fields = parameterTemplateListFields
	case regexp.MustCompile(base + `/[A-Za-z0-9_-]+/versions$`).MatchString(u.Path):
		permission = "templateVersions.list"
		fields = parameterTemplateVersionListFields
	case regexp.MustCompile(base + `/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+$`).MatchString(u.Path):
		permission = "templateVersions.get"
		fields = parameterTemplateVersionFields
	default:
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
		if strings.HasSuffix(permission, ".get") || k != "pageToken" && (k != "pageSize" || v[0] != "100") {
			return fail()
		}
	}
	if !strings.HasSuffix(permission, ".get") && q.Get("pageSize") != "100" {
		return fail()
	}
	return []string{"parametermanager." + permission}, nil
}
