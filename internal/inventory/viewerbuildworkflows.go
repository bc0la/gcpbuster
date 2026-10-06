package inventory

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// CollectViewerBuildWorkflows reads stored build/trigger configuration and the
// latest workflow definitions. It never starts builds or workflow executions,
// generates source URLs, fetches repositories, or reads execution/log payloads.
func (c *Client) CollectViewerBuildWorkflows(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-build-workflows:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	// Cloud Build exposes locations.list in v2, while builds/triggers use v1.
	// The documented global collection exists independently of regional
	// discovery; 'global' is not a guessed regional fallback.
	buildRegions := c.viewerBuildWorkflowLocations(ctx, out, projectID, number, "cloudbuild.googleapis.com", "v2")
	buildRegions["global"] = true
	for _, region := range orderedViewerRegions(buildRegions) {
		for _, collection := range []string{"builds", "triggers"} {
			if ctx.Err() != nil {
				out.record("viewer-build-workflows:"+projectID, 0, ctx.Err())
				return
			}
			c.viewerBuildConfig(ctx, out, projectID, number, region, collection)
		}
	}
	workflowRegions := c.viewerBuildWorkflowLocations(ctx, out, projectID, number, "workflows.googleapis.com", "v1")
	for _, region := range orderedViewerRegions(workflowRegions) {
		if ctx.Err() != nil {
			out.record("viewer-build-workflows:"+projectID, 0, ctx.Err())
			return
		}
		c.viewerWorkflowConfig(ctx, out, projectID, number, region)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-build-workflows:limitations:" + projectID, Status: "notice", Error: "Only API-visible stored Build/BuildTrigger configuration and latest Workflow definitions were inspected. Referenced source/repositories/images, historical workflow revisions, execution arguments/results and build logs were not fetched. Build history retention and API visibility limit completeness."})
}

func orderedViewerRegions(regions map[string]bool) []string {
	out := make([]string, 0, len(regions))
	for region := range regions {
		out = append(out, region)
	}
	sort.Strings(out)
	return out
}

func (c *Client) viewerBuildWorkflowLocations(ctx context.Context, out *Snapshot, projectID, number, host, version string) map[string]bool {
	regions := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://"+host+"/"+version+"/projects/"+projectID+"/locations", url.Values{"pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 4 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || !viewerServerlessRegion.MatchString(parts[3]) {
				return fmt.Errorf("invalid or out-of-project build/workflow location")
			}
			if id := Str(d["locationId"]); id != "" && id != parts[3] {
				return fmt.Errorf("mismatched build/workflow location")
			}
			regions[parts[3]] = true
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("build/workflow location discovery has unreachable resources")
	}
	out.record("viewer-locations:"+host+":"+projectID, len(regions), err)
	return regions
}

func viewerBuildWorkflowName(name, projectID, number, region, collection string) (string, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || parts[3] != region || parts[4] != collection || !viewerResourceName.MatchString(parts[5]) {
		return "", fmt.Errorf("invalid or out-of-scope build/workflow resource identity")
	}
	return parts[5], nil
}

func (c *Client) viewerBuildConfig(ctx context.Context, out *Snapshot, projectID, number, region, collection string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	kind, nameField := "Build", "name"
	if collection == "triggers" {
		kind, nameField = "BuildTrigger", "resourceName"
	}
	query := url.Values{"pageSize": {"100"}, "projectId": {projectID}}
	if c.SecretCapture != nil {
		fields := secretCaptureBuildFields
		if collection == "triggers" {
			fields = secretCaptureTriggerFields
		}
		query.Set("fields", collection+"("+fields+"),nextPageToken")
	}
	err := c.viewerPages(ctx, "https://cloudbuild.googleapis.com/v1/projects/"+projectID+"/locations/"+region+"/"+collection, query, func(page Object) error {
		rows, err := viewerRows(page, collection)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id := Str(d["id"])
			if !viewerResourceName.MatchString(id) {
				partial = true
				continue
			}
			if collection == "builds" && Str(d["projectId"]) != projectID && "projects/"+Str(d["projectId"]) != number {
				partial = true
				continue
			}
			if name := Str(d[nameField]); name != "" {
				parsed, err := viewerBuildWorkflowName(name, projectID, number, region, collection)
				if err != nil {
					partial = true
					continue
				}
				if parsed != id {
					partial = true
					continue
				}
			}
			// Legacy global records can omit the modern resourceName/name. The
			// validated ID and requested collection establish their identity.
			name := "//cloudbuild.googleapis.com/" + number + "/locations/" + region + "/" + collection + "/" + id
			if seen[name] {
				continue
			}
			seen[name] = true
			a := NewAsset(name, "cloudbuild.googleapis.com/"+kind, d)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			c.SecretCapture.captureBuild(a)
			out.Assets = append(out.Assets, a)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("Cloud Build inventory has unreachable locations")
	}
	out.record("viewer-cloudbuild:"+projectID+":"+region+":"+collection, len(out.Assets)-start, err)
}

func viewerBuildWorkflowUnreachable(page Object) (bool, error) {
	partial := false
	for _, field := range []string{"unreachable", "unreachableLocations"} {
		rows, err := viewerRows(page, field)
		if err != nil {
			return partial, err
		}
		if len(rows) > 0 {
			partial = true
		}
		for _, row := range rows {
			if strings.TrimSpace(Str(row)) == "" {
				return partial, fmt.Errorf("invalid build/workflow unreachable resource")
			}
		}
	}
	return partial, nil
}

func (c *Client) viewerWorkflowConfig(ctx context.Context, out *Snapshot, projectID, number, region string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://workflows.googleapis.com/v1/projects/"+projectID+"/locations/"+region+"/workflows", url.Values{"pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "workflows")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id, err := viewerBuildWorkflowName(Str(d["name"]), projectID, number, region, "workflows")
			if err != nil {
				return err
			}
			name := "projects/" + projectID + "/locations/" + region + "/workflows/" + id
			if seen[name] {
				continue
			}
			seen[name] = true
			query := url.Values{}
			if c.SecretCapture != nil {
				query.Set("fields", secretCaptureWorkflowFields)
			}
			full, getErr := c.get(ctx, "https://workflows.googleapis.com/v1/"+name, query)
			if getErr == nil {
				fullID, identityErr := viewerBuildWorkflowName(Str(full["name"]), projectID, number, region, "workflows")
				getErr = identityErr
				if getErr == nil && fullID != id {
					getErr = fmt.Errorf("mismatched Workflow detail identity")
				}
			}
			out.record("viewer-workflow-detail:"+name, 1, getErr)
			if getErr == nil {
				d = full
				if value, ok := full["sourceContents"].(string); ok && value != "" {
					c.SecretCapture.Add(SecretSample{SourceType: "workflow_definition", Resource: "//workflows.googleapis.com/" + name, Location: region, Path: "sourceContents", Data: []byte(value)})
				}
				c.SecretCapture.CaptureStringMap("workflow_env", "//workflows.googleapis.com/"+name, region, "userEnvVars", full["userEnvVars"])
				if strings.TrimSpace(Str(d["sourceContents"])) == "" {
					out.Coverage = append(out.Coverage, Coverage{Source: "viewer-workflow-source:" + name, Status: "incomplete", Error: "Workflow detail omitted or returned empty sourceContents; definition content was not inspected."})
				}
			}
			a := NewAsset("//workflows.googleapis.com/"+name, "workflows.googleapis.com/Workflow", d)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			out.Assets = append(out.Assets, a)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("Workflow inventory has unreachable resources")
	}
	out.record("viewer-workflows:"+projectID+":"+region, len(out.Assets)-start, err)
}
