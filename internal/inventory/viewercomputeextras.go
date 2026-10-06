package inventory

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// CollectViewerComputeExtras collects API-visible configuration only. Disk
// contents, guest filesystems, exports, downloads and VM creation are excluded.
func (c *Client) CollectViewerComputeExtras(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-compute-extras:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	c.viewerInstanceTemplates(ctx, out, projectID, number)
	c.viewerMachineImages(ctx, out, projectID, number)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-compute-extras:limitations:" + projectID, Status: "notice", Error: "Instance template and machine image control-plane configuration only. Referenced startup-script URLs, disk contents, guest filesystems, images and snapshots were not downloaded or instantiated."})
}

func viewerComputeExtraAsset(d Object, projectID, number, scope, collection, kind, properties string) (Asset, error) {
	name := Str(d["name"])
	if !viewerResourceName.MatchString(name) {
		return Asset{}, fmt.Errorf("invalid Compute configuration resource name")
	}
	if link := Str(d["selfLink"]); link != "" {
		valid := false
		for _, project := range []string{projectID, strings.TrimPrefix(number, "projects/")} {
			path := "/compute/v1/projects/" + project + "/" + scope + "/" + collection + "/" + name
			if link == "https://www.googleapis.com"+path || link == "https://compute.googleapis.com"+path {
				valid = true
			}
		}
		if !valid {
			return Asset{}, fmt.Errorf("mismatched or out-of-project Compute configuration self link")
		}
	}
	if raw, exists := d[properties]; exists && Obj(raw) == nil {
		return Asset{}, fmt.Errorf("invalid Compute configuration properties")
	}
	a := NewAsset("//compute.googleapis.com/projects/"+projectID+"/"+scope+"/"+collection+"/"+name, "compute.googleapis.com/"+kind, d)
	a.Ancestors = []string{number}
	a.Resource.Location = strings.TrimPrefix(scope, "regions/")
	return a, nil
}

func viewerComputeExtraWarnings(page Object, partial *bool) error {
	if raw, exists := page["warning"]; exists {
		warning := Obj(raw)
		if warning == nil {
			return fmt.Errorf("invalid Compute collection warning")
		}
		if Str(warning["code"]) != "NO_RESULTS_ON_PAGE" {
			*partial = true
		}
	}
	if page["error"] != nil {
		*partial = true
	}
	for _, field := range []string{"unreachables", "unreachable"} {
		rows, err := viewerRows(page, field)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			if Str(raw) == "" {
				return fmt.Errorf("invalid Compute unreachable location")
			}
		}
		if len(rows) > 0 {
			*partial = true
		}
	}
	return nil
}

func (c *Client) viewerInstanceTemplates(ctx context.Context, out *Snapshot, projectID, number string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	query := url.Values{"maxResults": {"500"}, "returnPartialSuccess": {"true"}, "includeAllScopes": {"true"}}
	if c.SecretCapture != nil {
		query.Set("fields", "items/*/instanceTemplates("+secretCaptureTemplateFields+"),items/*/warning,items/*/error,nextPageToken,warning,unreachables")
	}
	err := c.viewerPages(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/aggregated/instanceTemplates", query, func(page Object) error {
		items := Obj(page["items"])
		if _, exists := page["items"]; exists && items == nil {
			return fmt.Errorf("invalid aggregated template inventory")
		}
		scopes := make([]string, 0, len(items))
		for scope := range items {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		for _, scope := range scopes {
			if scope != "global" && (!strings.HasPrefix(scope, "regions/") || !viewerLocation.MatchString(strings.TrimPrefix(scope, "regions/"))) {
				return fmt.Errorf("invalid instance template scope")
			}
			group := Obj(items[scope])
			if group == nil {
				return fmt.Errorf("invalid template scope result")
			}
			rows, err := viewerRows(group, "instanceTemplates")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				a, err := viewerComputeExtraAsset(Obj(raw), projectID, number, scope, "instanceTemplates", "InstanceTemplate", "properties")
				if err != nil {
					return err
				}
				if seen[a.Name] {
					continue
				}
				seen[a.Name] = true
				c.SecretCapture.captureOther(a)
				out.Assets = append(out.Assets, a)
				if a.Resource.Data["properties"] == nil {
					out.Coverage = append(out.Coverage, Coverage{Source: "viewer-template-config:" + a.Name, Status: "incomplete", Error: "Instance template response omitted properties; embedded configuration was not inspected."})
				}
			}
			if err := viewerComputeExtraWarnings(group, &partial); err != nil {
				return err
			}
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("instance template inventory contains partial scopes or warnings")
	}
	out.record("viewer-instance-templates:"+projectID, len(out.Assets)-start, err)
}

func (c *Client) viewerMachineImages(ctx context.Context, out *Snapshot, projectID, number string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	query := url.Values{"maxResults": {"500"}}
	if c.SecretCapture != nil {
		query.Set("fields", "items("+secretCaptureMachineImageFields+"),nextPageToken,warning")
	}
	err := c.viewerPages(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/global/machineImages", query, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			a, err := viewerComputeExtraAsset(Obj(raw), projectID, number, "global", "machineImages", "MachineImage", "instanceProperties")
			if err != nil {
				return err
			}
			if seen[a.Name] {
				continue
			}
			seen[a.Name] = true
			c.SecretCapture.captureOther(a)
			out.Assets = append(out.Assets, a)
			if a.Resource.Data["instanceProperties"] == nil {
				out.Coverage = append(out.Coverage, Coverage{Source: "viewer-machine-image-config:" + a.Name, Status: "incomplete", Error: "Machine image response omitted instanceProperties; embedded configuration was not inspected."})
			}
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("machine image inventory contains warnings or unreachable scopes")
	}
	out.record("viewer-machine-images:"+projectID, len(out.Assets)-start, err)
}
