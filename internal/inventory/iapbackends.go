package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var computeProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)
var backendID = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)

// CollectIAPBackends supplements CAI with global backend services from explicitly
// selected/discovered projects. Metadata resolves project IDs to IAP's numbers.
// Returned selfLinks are checked for identity, never followed as URLs.
func (c *Client) CollectIAPBackends(ctx context.Context, snap *Snapshot, scopes []string) {
	seenScopes, seenProjects := map[string]bool{}, map[string]bool{}
	for _, scope := range scopes {
		if !strings.HasPrefix(scope, "projects/") || seenScopes[scope] {
			continue
		}
		seenScopes[scope] = true
		id := strings.TrimPrefix(scope, "projects/")
		if !projectNumberPattern.MatchString(scope) && !computeProjectID.MatchString(id) {
			snap.record("iap-backends:scope", 0, fmt.Errorf("invalid project scope"))
			continue
		}
		if err := ctx.Err(); err != nil {
			snap.record("iap-backends:"+scope, 0, err)
			return
		}
		d, err := c.get(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+scope, nil)
		if err != nil {
			snap.record("iap-backends:project:"+scope, 0, err)
			continue
		}
		number, projectID := Str(d["name"]), Str(d["projectId"])
		if !projectNumberPattern.MatchString(number) || !computeProjectID.MatchString(projectID) || (number != scope && projectID != id) {
			snap.record("iap-backends:project:"+scope, 0, fmt.Errorf("invalid or mismatched project metadata"))
			continue
		}
		if seenProjects[number] {
			continue
		}
		seenProjects[number] = true
		snap.record("iap-backends:project:"+scope, 1, nil)
		project := NewAsset("//cloudresourcemanager.googleapis.com/"+number, "cloudresourcemanager.googleapis.com/Project", d)
		snap.Assets = append(snap.Assets, project)
		assets, err := c.globalIAPBackends(ctx, projectID, number)
		snap.Assets = append(snap.Assets, assets...)
		snap.record("iap-backends:"+number, len(assets), err)
	}
}

func (c *Client) globalIAPBackends(ctx context.Context, projectID, number string) ([]Asset, error) {
	endpoint := "https://compute.googleapis.com/compute/v1/projects/" + projectID + "/global/backendServices"
	q := url.Values{"maxResults": {"500"}}
	var out []Asset
	seenPages, seenAssets := map[string]bool{}, map[string]bool{}
	for {
		page, err := c.get(ctx, endpoint, q)
		if err != nil {
			return out, err
		}
		if page == nil {
			return out, fmt.Errorf("invalid backend service response")
		}
		if raw, exists := page["items"]; exists {
			if _, ok := raw.([]any); !ok {
				return out, fmt.Errorf("invalid backend service list")
			}
		}
		for _, raw := range List(page["items"]) {
			d := Obj(raw)
			id := Str(d["name"])
			if !backendID.MatchString(id) || len(id) > 63 || Str(d["region"]) != "" {
				return out, fmt.Errorf("invalid global backend identity")
			}
			path := "projects/" + projectID + "/global/backendServices/" + id
			if link := Str(d["selfLink"]); link != "" && link != "https://www.googleapis.com/compute/v1/"+path && link != "https://compute.googleapis.com/compute/v1/"+path {
				return out, fmt.Errorf("mismatched global backend identity")
			}
			if seenAssets[path] {
				continue
			}
			seenAssets[path] = true
			a := NewAsset("//compute.googleapis.com/"+path, "compute.googleapis.com/BackendService", d)
			a.Ancestors = []string{number}
			out = append(out, a)
		}
		if raw, exists := page["warning"]; exists {
			if Str(Obj(raw)["code"]) != "NO_RESULTS_ON_PAGE" {
				return out, fmt.Errorf("backend listing returned a warning; completeness unverified")
			}
		}
		if raw, exists := page["nextPageToken"]; exists {
			if _, ok := raw.(string); !ok {
				return out, fmt.Errorf("invalid backend pagination token")
			}
		}
		next := Str(page["nextPageToken"])
		if next == "" {
			return out, nil
		}
		if seenPages[next] {
			return out, fmt.Errorf("repeated backend pagination token")
		}
		seenPages[next] = true
		q.Set("pageToken", next)
	}
}
