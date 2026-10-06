package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

const cloudDeployReleaseFields = "releases(name,deployParameters,deliveryPipelineSnapshot(serialPipeline(stages(deployParameters(values)))),targetSnapshots(deployParameters)),nextPageToken,unreachable"

func (c *Client) viewerCloudDeployReleases(ctx context.Context, out *Snapshot, parent, region, projectID, number string, budget *secretCollectionBudget) {
	count := 0
	seen := map[string]bool{}
	err := c.secretCollectionPages(ctx, "https://clouddeploy.googleapis.com/v1/"+parent+"/releases", url.Values{"fields": {cloudDeployReleaseFields}, "pageSize": {"100"}}, budget, func(page Object) error {
		rows, err := viewerRows(page, "releases")
		if err != nil {
			return err
		}
		for _, r := range rows {
			d := Obj(r)
			name := Str(d["name"])
			if strings.HasPrefix(name, "projects/"+projectID+"/") {
				name = number + strings.TrimPrefix(name, "projects/"+projectID)
			}
			prefix := parent + "/releases/"
			id := strings.TrimPrefix(name, prefix)
			if !strings.HasPrefix(name, prefix) || !viewerResourceName.MatchString(id) {
				return fmt.Errorf("invalid Cloud Deploy release identity")
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			if err := budget.takeResource(); err != nil {
				return err
			}
			a := NewAsset("//clouddeploy.googleapis.com/"+name, "clouddeploy.googleapis.com/Release", d)
			a.Resource.Location = region
			a.Ancestors = []string{number}
			c.SecretCapture.captureCloudDeployRelease(a)
			a.Resource.Data = Object{"name": name}
			out.Assets = append(out.Assets, a)
			count++
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		if err != nil {
			return err
		}
		if unreachable {
			return fmt.Errorf("Cloud Deploy releases returned unreachable resources")
		}
		return nil
	})
	out.record("viewer-clouddeploy:releases:"+parent, count, err)
}

func (c *SecretCapture) captureCloudDeployRelease(a Asset) {
	if c == nil {
		return
	}
	c.CaptureStringMap("clouddeploy_parameters", a.Name, a.Resource.Location, "deployParameters", a.Resource.Data["deployParameters"])
	stages, _ := Get(a.Resource.Data, "deliveryPipelineSnapshot", "serialPipeline", "stages").([]any)
	for i, stage := range stages {
		params, _ := Get(Obj(stage), "deployParameters").([]any)
		for j, param := range params {
			c.CaptureStringMap("clouddeploy_parameters", a.Name, a.Resource.Location, fmt.Sprintf("deliveryPipelineSnapshot.serialPipeline.stages[%d].deployParameters[%d].values", i, j), Get(Obj(param), "values"))
		}
	}
	targets, _ := a.Resource.Data["targetSnapshots"].([]any)
	for i, target := range targets {
		c.CaptureStringMap("clouddeploy_parameters", a.Name, a.Resource.Location, fmt.Sprintf("targetSnapshots[%d].deployParameters", i), Get(Obj(target), "deployParameters"))
	}
}
