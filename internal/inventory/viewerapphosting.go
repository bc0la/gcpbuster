package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const appHostingLocationFields = "locations(name,locationId),nextPageToken"
const appHostingBackendFields = "backends(name),nextPageToken,unreachable"
const appHostingBuildFields = "builds(name,config(effectiveEnv(variable,value,secret))),nextPageToken,unreachable"

// CollectViewerAppHosting captures project-reader-visible plaintext env values;
// secret version references, source archives, images and logs are never read.
func (c *Client) CollectViewerAppHosting(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-apphosting:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	budget := &secretCollectionBudget{}
	defer func() {
		if budget.exhausted {
			out.Coverage = append(out.Coverage, Coverage{Source: "viewer-apphosting:limits:" + projectID, Status: "incomplete", Error: "Shared discovery limit reached across all locations/backends/builds: at most 1000 pages and 10000 resources. Remaining configuration was not read."})
		}
	}()
	for _, location := range c.appHostingNames(ctx, out, number, "locations", "locations", appHostingLocationFields, projectID, number, budget) {
		if budget.exhausted {
			break
		}
		for _, backend := range c.appHostingNames(ctx, out, location, "backends", "backends", appHostingBackendFields, projectID, number, budget) {
			if budget.exhausted {
				break
			}
			count := 0
			seen := map[string]bool{}
			err := c.secretCollectionPages(ctx, "https://firebaseapphosting.googleapis.com/v1/"+backend+"/builds", url.Values{"pageSize": {"100"}, "fields": {appHostingBuildFields}}, budget, func(page Object) error {
				rows, err := viewerRows(page, "builds")
				if err != nil {
					return err
				}
				for _, r := range rows {
					d := Obj(r)
					name, err := appHostingChild(Str(d["name"]), backend, "builds", projectID, number)
					if err != nil {
						return err
					}
					if seen[name] {
						continue
					}
					seen[name] = true
					if err := budget.takeResource(); err != nil {
						return err
					}
					a := NewAsset("//firebaseapphosting.googleapis.com/"+name, "firebaseapphosting.googleapis.com/Build", d)
					a.Ancestors = []string{number}
					a.Resource.Location = strings.Split(location, "/")[3]
					c.SecretCapture.captureAppHosting(a)
					a.Resource.Data = Object{"name": name}
					out.Assets = append(out.Assets, a)
					count++
				}
				unreachable, err := viewerBuildWorkflowUnreachable(page)
				if err != nil {
					return err
				}
				if unreachable {
					return fmt.Errorf("App Hosting builds returned unreachable resources")
				}
				return nil
			})
			out.record("viewer-apphosting:builds:"+backend, count, err)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-apphosting:boundary:" + projectID, Status: "notice", Error: "Stored Build.config.effectiveEnv plaintext values only. Secret references are not resolved. No application invocation, source/archive/image/log downloads, rollout, traffic changes or credential validation."})
}

func appHostingChild(name, parent, collection, projectID, number string) (string, error) {
	if strings.HasPrefix(name, "projects/"+projectID+"/") {
		name = number + strings.TrimPrefix(name, "projects/"+projectID)
	}
	prefix := parent + "/" + collection + "/"
	id := strings.TrimPrefix(name, prefix)
	if !strings.HasPrefix(name, prefix) || !viewerResourceName.MatchString(id) || (collection == "locations" && !viewerLocation.MatchString(id)) {
		return "", fmt.Errorf("invalid App Hosting child identity")
	}
	return name, nil
}

func (c *Client) appHostingNames(ctx context.Context, out *Snapshot, parent, collection, key, fields, projectID, number string, budget *secretCollectionBudget) []string {
	names := []string{}
	seen := map[string]bool{}
	err := c.secretCollectionPages(ctx, "https://firebaseapphosting.googleapis.com/v1/"+parent+"/"+collection, url.Values{"pageSize": {"100"}, "fields": {fields}}, budget, func(page Object) error {
		rows, err := viewerRows(page, key)
		if err != nil {
			return err
		}
		for _, r := range rows {
			d := Obj(r)
			name, err := appHostingChild(Str(d["name"]), parent, collection, projectID, number)
			if err != nil {
				return err
			}
			if collection == "locations" && Str(d["locationId"]) != "" && Str(d["locationId"]) != strings.Split(name, "/")[3] {
				return fmt.Errorf("mismatched App Hosting location")
			}
			if !seen[name] {
				if err := budget.takeResource(); err != nil {
					return err
				}
				seen[name] = true
				names = append(names, name)
			}
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		if err != nil {
			return err
		}
		if unreachable {
			return fmt.Errorf("App Hosting returned unreachable resources")
		}
		return nil
	})
	out.record("viewer-apphosting:"+parent+":"+collection, len(names), err)
	return names
}

func (c *SecretCapture) captureAppHosting(a Asset) {
	if c == nil {
		return
	}
	rows, _ := Get(a.Resource.Data, "config", "effectiveEnv").([]any)
	for i, r := range rows {
		d := Obj(r)
		name, nok := d["variable"].(string)
		value, vok := d["value"].(string)
		if nok && vok && name != "" && value != "[REDACTED]" && d["secret"] == nil {
			c.Add(SecretSample{SourceType: "apphosting_env", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("config.effectiveEnv[%d].value", i), Data: []byte(name + "=" + value)})
		}
	}
}

func appHostingPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed App Hosting configuration request")
	}
	if method != "GET" || u.Host != "firebaseapphosting.googleapis.com" || u.RawPath != "" {
		return fail()
	}
	permission, fields := "", ""
	base := `^/v1/projects/[A-Za-z0-9_-]+/locations`
	switch {
	case regexp.MustCompile(base + `$`).MatchString(u.Path):
		permission = "locations.list"
		fields = appHostingLocationFields
	case regexp.MustCompile(base + `/[a-z][a-z0-9-]*/backends$`).MatchString(u.Path):
		permission = "backends.list"
		fields = appHostingBackendFields
	case regexp.MustCompile(base + `/[a-z][a-z0-9-]*/backends/[A-Za-z0-9_-]+/builds$`).MatchString(u.Path):
		permission = "builds.list"
		fields = appHostingBuildFields
	default:
		return fail()
	}
	if q.Get("fields") != fields || q.Get("pageSize") != "100" {
		return fail()
	}
	for k, v := range q {
		if len(v) != 1 || (k != "fields" && k != "pageSize" && k != "pageToken") {
			return fail()
		}
	}
	return []string{"firebaseapphosting." + permission}, nil
}
