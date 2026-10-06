package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const cloudDeployLocationsFields = "locations(name,locationId),nextPageToken"
const cloudDeployPipelineFields = "deliveryPipelines(name,serialPipeline(stages(deployParameters(values)))),nextPageToken,unreachable"
const cloudDeployTargetFields = "targets(name,deployParameters),nextPageToken,unreachable"

// CollectViewerCloudDeploy inspects selected plaintext deployment parameters.
// Rendered manifests are not followed through storage/artifact references.
func (c *Client) CollectViewerCloudDeploy(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-clouddeploy:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	regions := map[string]bool{}
	budget := &secretCollectionBudget{}
	defer func() {
		if budget.exhausted {
			out.Coverage = append(out.Coverage, Coverage{Source: "viewer-clouddeploy:limits:" + projectID, Status: "incomplete", Error: "Shared discovery limit reached across all locations/pipelines/targets/releases: at most 1000 pages and 10000 resources. Remaining configuration was not read."})
		}
	}()
	err := c.secretCollectionPages(ctx, "https://clouddeploy.googleapis.com/v1/"+number+"/locations", url.Values{"pageSize": {"100"}, "fields": {cloudDeployLocationsFields}}, budget, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, r := range rows {
			d := Obj(r)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 4 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || !viewerLocation.MatchString(parts[3]) || (Str(d["locationId"]) != "" && Str(d["locationId"]) != parts[3]) {
				return fmt.Errorf("invalid Cloud Deploy location identity")
			}
			if !regions[parts[3]] {
				if err := budget.takeResource(); err != nil {
					return err
				}
				regions[parts[3]] = true
			}
		}
		return nil
	})
	out.record("viewer-clouddeploy:locations:"+projectID, len(regions), err)
	for _, region := range orderedViewerRegions(regions) {
		if budget.exhausted {
			break
		}
		pipelines := []string{}
		for _, collection := range []string{"deliveryPipelines", "targets"} {
			if budget.exhausted {
				break
			}
			fields := cloudDeployPipelineFields
			if collection == "targets" {
				fields = cloudDeployTargetFields
			}
			count := 0
			seen := map[string]bool{}
			err := c.secretCollectionPages(ctx, "https://clouddeploy.googleapis.com/v1/"+number+"/locations/"+region+"/"+collection, url.Values{"pageSize": {"100"}, "fields": {fields}}, budget, func(page Object) error {
				rows, err := viewerRows(page, collection)
				if err != nil {
					return err
				}
				for _, r := range rows {
					d := Obj(r)
					id, err := viewerBuildWorkflowName(Str(d["name"]), projectID, number, region, collection)
					if err != nil {
						return err
					}
					name := "//clouddeploy.googleapis.com/" + number + "/locations/" + region + "/" + collection + "/" + id
					if seen[name] {
						continue
					}
					seen[name] = true
					if err := budget.takeResource(); err != nil {
						return err
					}
					if collection == "deliveryPipelines" {
						pipelines = append(pipelines, strings.TrimPrefix(name, "//clouddeploy.googleapis.com/"))
					}
					a := NewAsset(name, "clouddeploy.googleapis.com/DeliveryPipeline", Object{})
					if collection == "targets" {
						a.Type = "clouddeploy.googleapis.com/Target"
					}
					a.Resource.Location = region
					a.Ancestors = []string{number}
					a.Resource.Data = d
					c.SecretCapture.captureCloudDeploy(a)
					// The full selected parameter values remain transient, not inventory.
					a.Resource.Data = Object{"name": strings.TrimPrefix(name, "//clouddeploy.googleapis.com/")}
					out.Assets = append(out.Assets, a)
					count++
				}
				unreachable, err := viewerBuildWorkflowUnreachable(page)
				if err != nil {
					return err
				}
				if unreachable {
					return fmt.Errorf("Cloud Deploy returned unreachable resources")
				}
				return nil
			})
			out.record("viewer-clouddeploy:"+projectID+":"+region+":"+collection, count, err)
		}
		for _, pipeline := range pipelines {
			if budget.exhausted {
				break
			}
			c.viewerCloudDeployReleases(ctx, out, pipeline, region, projectID, number, budget)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-clouddeploy:boundary:" + projectID, Status: "notice", Error: "Stored pipeline stage, target and release snapshot deployParameters only. No rendered manifests, Skaffold/source archives, artifacts, rollout execution, secret-reference resolution or credential validation."})
}

func (c *SecretCapture) captureCloudDeploy(a Asset) {
	if c == nil {
		return
	}
	if a.Type == "clouddeploy.googleapis.com/Target" {
		c.CaptureStringMap("clouddeploy_parameters", a.Name, a.Resource.Location, "deployParameters", a.Resource.Data["deployParameters"])
		return
	}
	stages, _ := Get(a.Resource.Data, "serialPipeline", "stages").([]any)
	for i, stage := range stages {
		params, _ := Get(Obj(stage), "deployParameters").([]any)
		for j, param := range params {
			c.CaptureStringMap("clouddeploy_parameters", a.Name, a.Resource.Location, fmt.Sprintf("serialPipeline.stages[%d].deployParameters[%d].values", i, j), Get(Obj(param), "values"))
		}
	}
}

func cloudDeployPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed Cloud Deploy configuration request")
	}
	if method != "GET" || u.Host != "clouddeploy.googleapis.com" || u.RawPath != "" {
		return fail()
	}
	permission, fields := "", ""
	if regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations$`).MatchString(u.Path) {
		permission = "locations.list"
		fields = cloudDeployLocationsFields
	} else if regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/deliveryPipelines/[A-Za-z0-9_-]+/releases$`).MatchString(u.Path) {
		permission = "releases.list"
		fields = cloudDeployReleaseFields
	} else {
		m := regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/(deliveryPipelines|targets)$`).FindStringSubmatch(u.Path)
		if m == nil {
			return fail()
		}
		permission = m[1] + ".list"
		fields = cloudDeployPipelineFields
		if m[1] == "targets" {
			fields = cloudDeployTargetFields
		}
	}
	if q.Get("fields") != fields || q.Get("pageSize") != "100" {
		return fail()
	}
	for k, v := range q {
		if len(v) != 1 || (k != "fields" && k != "pageSize" && k != "pageToken") {
			return fail()
		}
	}
	return []string{"clouddeploy." + permission}, nil
}
