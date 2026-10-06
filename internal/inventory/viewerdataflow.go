package inventory

import (
	"context"
	"fmt"
	"net/url"
)

const viewerDataflowFields = "id,name,projectId,location,type,currentState,environment,steps,stepsLocation,pipelineDescription,labels"

func viewerDataflowIdentity(d Object, projectID, number string) (string, string, error) {
	id, location, project := Str(d["id"]), Str(d["location"]), Str(d["projectId"])
	if !viewerResourceName.MatchString(id) || !viewerLocation.MatchString(location) || (project != projectID && "projects/"+project != number) {
		return "", "", fmt.Errorf("invalid or out-of-project Dataflow job identity")
	}
	return id, location, nil
}

// CollectViewerDataflow lists all regions, then requests configuration detail;
// aggregated jobs.list always returns summaries regardless of requested view.
// No job creation/update, messages, metrics, storage objects or worker endpoints.
// https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.jobs/aggregated
func (c *Client) CollectViewerDataflow(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-dataflow:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://dataflow.googleapis.com/v1b3/projects/"+projectID+"/jobs:aggregated", url.Values{"filter": {"ALL"}, "pageSize": {"100"}, "fields": {"jobs(id,projectId,location),nextPageToken,failedLocation"}}, func(page Object) error {
		rows, err := viewerRows(page, "jobs")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			id, location, err := viewerDataflowIdentity(Obj(raw), projectID, number)
			if err != nil {
				return err
			}
			name := "projects/" + projectID + "/locations/" + location + "/jobs/" + id
			if seen[name] {
				continue
			}
			seen[name] = true
			full, getErr := c.get(ctx, "https://dataflow.googleapis.com/v1b3/"+name, url.Values{"view": {"JOB_VIEW_ALL"}, "fields": {viewerDataflowFields}})
			if getErr == nil {
				gotID, gotLocation, identityErr := viewerDataflowIdentity(full, projectID, number)
				getErr = identityErr
				if getErr == nil && (gotID != id || gotLocation != location) {
					getErr = fmt.Errorf("mismatched Dataflow detail identity")
				}
			}
			out.record("viewer-dataflow-detail:"+name, 1, getErr)
			if getErr != nil {
				continue
			}
			metadata := viewerConfigProjection(full, "id", "name", "projectId", "location", "type", "currentState", "environment", "steps", "stepsLocation", "pipelineDescription", "labels")
			if Obj(full["environment"]) == nil {
				out.Coverage = append(out.Coverage, Coverage{Source: "viewer-dataflow-environment:" + name, Status: "incomplete", Error: "Job detail omitted environment configuration; environment-secret absence was not established."})
			}
			if Str(full["stepsLocation"]) != "" {
				out.Coverage = append(out.Coverage, Coverage{Source: "viewer-dataflow-steps:" + name, Status: "incomplete", Error: "Steps are referenced through a separate location; referenced storage content was not fetched."})
			}
			a := NewAsset("//dataflow.googleapis.com/"+name, "dataflow.googleapis.com/Job", metadata)
			a.Resource.Location, a.Ancestors = location, []string{number}
			c.SecretCapture.captureOther(a)
			out.Assets = append(out.Assets, a)
		}
		failed, err := viewerRows(page, "failedLocation")
		if err != nil {
			return err
		}
		for _, raw := range failed {
			if Str(Obj(raw)["name"]) == "" {
				return fmt.Errorf("malformed Dataflow failed-location indicator")
			}
		}
		partial = partial || len(failed) > 0
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("Dataflow aggregated inventory has failed regional endpoints")
	}
	out.record("viewer-dataflow-jobs:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-dataflow:limitations:" + projectID, Status: "notice", Error: "Only API-visible job configuration was inspected. Job retention, encoded pipeline objects and separately stored steps limit evidence; no job messages, logs, metrics, worker data or referenced storage content was fetched."})
}
