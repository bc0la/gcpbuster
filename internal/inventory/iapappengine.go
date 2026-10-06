package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var appEnginePart = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// CollectAppEngineIAP refreshes app/service configuration and version identities.
// BASIC version responses must not replace richer CAI deployment configuration.
func (c *Client) CollectAppEngineIAP(ctx context.Context, snap *Snapshot) {
	seen := map[string]bool{}
	known := map[string]Asset{}
	for _, a := range snap.Assets {
		known[a.Type+"|"+a.Name] = a
	}
	appendIdentities := func(assets ...Asset) {
		for _, a := range assets {
			old := known[a.Type+"|"+a.Name]
			if len(old.Ancestors) > len(a.Ancestors) && len(a.Ancestors) > 0 && old.Ancestors[0] == a.Ancestors[0] {
				a.Ancestors = old.Ancestors
			}
			snap.Assets = append(snap.Assets, a)
		}
	}
	for _, project := range snap.Assets {
		if project.Type != "cloudresourcemanager.googleapis.com/Project" {
			continue
		}
		number := strings.TrimPrefix(project.Name, "//cloudresourcemanager.googleapis.com/")
		id := Str(project.Resource.Data["projectId"])
		if !projectNumberPattern.MatchString(number) || !computeProjectID.MatchString(id) {
			snap.record("iap-appengine:project", 0, fmt.Errorf("App Engine discovery requires numeric project identity and projectId"))
			continue
		}
		if seen[number] {
			continue
		}
		seen[number] = true
		if err := ctx.Err(); err != nil {
			snap.record("iap-appengine:"+number, 0, err)
			return
		}
		app := "apps/" + id
		appData, appErr := c.get(ctx, "https://appengine.googleapis.com/v1/"+app, nil)
		if appErr == nil && (Str(appData["name"]) != app || Str(appData["id"]) != id) {
			appErr = fmt.Errorf("mismatched App Engine application identity")
		}
		if appErr == nil {
			a := NewAsset("//appengine.googleapis.com/"+app, "appengine.googleapis.com/Application", appData)
			a.Ancestors = []string{number}
			appendIdentities(a)
		}
		snap.record("iap-appengine:"+app+":configuration", 1, appErr)
		services, err := c.appEngineIAPChildren(ctx, app, "services", number)
		snap.record("iap-appengine:"+app+":services", len(services), err)
		if appErr != nil && (err == nil || len(services) > 0) {
			a := NewAsset("//appengine.googleapis.com/"+app, "appengine.googleapis.com/Application", nil)
			a.Ancestors = []string{number}
			appendIdentities(a)
		}
		appendIdentities(services...)
		for _, service := range services {
			parent := strings.TrimPrefix(service.Name, "//appengine.googleapis.com/")
			versions, err := c.appEngineIAPChildren(ctx, parent, "versions", number)
			snap.record("iap-appengine:"+parent+":versions", len(versions), err)
			appendIdentities(versions...)
		}
	}
	snap.Coverage = append(snap.Coverage, Coverage{Source: "iap-appengine:limitations", Status: "notice", Error: "App Engine app/service configuration and version identities. Failed API reads are not proof of application absence. Full version configuration, effective firewall/authentication, traffic attribution and runtime reachability require further assessment."})
}

func (c *Client) appEngineIAPChildren(ctx context.Context, parent, kind, number string) ([]Asset, error) {
	q := url.Values{"pageSize": {"100"}}
	typ := "appengine.googleapis.com/Service"
	if kind == "versions" {
		q.Set("view", "BASIC")
		typ = "appengine.googleapis.com/Version"
	}
	var out []Asset
	seenPages, seenAssets := map[string]bool{}, map[string]bool{}
	for {
		page, err := c.get(ctx, "https://appengine.googleapis.com/v1/"+parent+"/"+kind, q)
		if err != nil {
			return out, err
		}
		if page == nil {
			return out, fmt.Errorf("invalid App Engine list response")
		}
		if raw, exists := page[kind]; exists {
			if _, ok := raw.([]any); !ok {
				return out, fmt.Errorf("invalid App Engine child list")
			}
		}
		for _, raw := range List(page[kind]) {
			d := Obj(raw)
			id := Str(d["id"])
			name := parent + "/" + kind + "/" + id
			if !appEnginePart.MatchString(id) || Str(d["name"]) != name {
				return out, fmt.Errorf("mismatched App Engine child identity")
			}
			if seenAssets[name] {
				continue
			}
			seenAssets[name] = true
			a := NewAsset("//appengine.googleapis.com/"+name, typ, nil)
			if kind == "services" {
				a.Resource.Data = d
			}
			a.Ancestors = []string{number}
			out = append(out, a)
		}
		if raw, exists := page["nextPageToken"]; exists {
			if _, ok := raw.(string); !ok {
				return out, fmt.Errorf("invalid App Engine pagination token")
			}
		}
		next := Str(page["nextPageToken"])
		if next == "" {
			return out, nil
		}
		if seenPages[next] {
			return out, fmt.Errorf("repeated App Engine pagination token")
		}
		seenPages[next] = true
		q.Set("pageToken", next)
	}
}
