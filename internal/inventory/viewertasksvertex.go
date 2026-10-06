package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var viewerTaskID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Standard REST partial-response fields excludes payloads at the API as well
// as in the local projection. Keep both protections even with privileged ADC.
const viewerTaskFields = "tasks(name,scheduleTime,createTime,dispatchDeadline,dispatchCount,responseCount,httpRequest(url,httpMethod,oidcToken(serviceAccountEmail,audience),oauthToken(serviceAccountEmail,scope)),appEngineHttpRequest(relativeUri,httpMethod,appEngineRouting)),nextPageToken"

func viewerQueueID(name, projectID, number, region string) (string, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || parts[3] != region || parts[4] != "queues" || !viewerTaskID.MatchString(parts[5]) {
		return "", fmt.Errorf("invalid or out-of-project queue identity")
	}
	return parts[5], nil
}

// CollectViewerTasksVertex never dispatches tasks, starts training/pipelines or
// obtains payloads, model artifacts, container images, or execution results.
func (c *Client) CollectViewerTasksVertex(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-tasks-vertex:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	for _, region := range orderedViewerRegions(c.viewerBuildWorkflowLocations(ctx, out, projectID, number, "cloudtasks.googleapis.com", "v2")) {
		if ctx.Err() != nil {
			out.record("viewer-tasks-vertex:"+projectID, 0, ctx.Err())
			return
		}
		c.viewerTaskQueues(ctx, out, projectID, number, region)
	}
	for _, region := range orderedViewerRegions(c.viewerBuildWorkflowLocations(ctx, out, projectID, number, "aiplatform.googleapis.com", "v1")) {
		if region == "global" {
			out.Coverage = append(out.Coverage, Coverage{Source: "viewer-vertex:" + number + ":global", Status: "incomplete", Error: "Global Vertex location is not mapped to a reviewed training/pipeline regional endpoint; no job configuration was inferred."})
			continue
		}
		for _, collection := range []string{"customJobs", "pipelineJobs"} {
			if ctx.Err() != nil {
				out.record("viewer-tasks-vertex:"+projectID, 0, ctx.Err())
				return
			}
			c.viewerVertexJobs(ctx, out, projectID, number, region, collection)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-tasks-vertex:limitations:" + projectID, Status: "notice", Error: "Tasks were listed only in BASIC view, with request bodies/headers excluded locally. Queue/task membership can change during pagination. Vertex reads inspect API-visible stored job configuration only; artifacts, training data, execution outputs and logs were not read. No dispatch, token generation, training, pipeline execution or inference was performed."})
}

func (c *Client) viewerTaskQueues(ctx context.Context, out *Snapshot, projectID, number, region string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	queues := []string{}
	err := c.viewerPages(ctx, "https://cloudtasks.googleapis.com/v2/projects/"+projectID+"/locations/"+region+"/queues", url.Values{"pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "queues")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id, err := viewerQueueID(Str(d["name"]), projectID, number, region)
			if err != nil {
				return err
			}
			name := number + "/locations/" + region + "/queues/" + id
			if seen[name] {
				continue
			}
			seen[name] = true
			metadata := viewerConfigProjection(d, "name", "state", "rateLimits", "retryConfig", "stackdriverLoggingConfig", "httpTarget", "appEngineRoutingOverride")
			a := NewAsset("//cloudtasks.googleapis.com/"+name, "cloudtasks.googleapis.com/Queue", metadata)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			out.Assets = append(out.Assets, a)
			queues = append(queues, name)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("Cloud Tasks queue inventory has unreachable resources")
	}
	out.record("viewer-task-queues:"+projectID+":"+region, len(out.Assets)-start, err)
	for _, queue := range queues {
		if ctx.Err() != nil {
			out.record("viewer-tasks:"+queue, 0, ctx.Err())
			return
		}
		c.viewerTasks(ctx, out, queue, projectID, number)
	}
}

func viewerConfigProjection(d Object, fields ...string) Object {
	out := Object{}
	for _, field := range fields {
		if value, ok := d[field]; ok {
			out[field] = value
		}
	}
	return out
}

func (c *Client) viewerTasks(ctx context.Context, out *Snapshot, queue, projectID, number string) {
	queueParts := strings.Split(queue, "/")
	if len(queueParts) != 6 {
		out.record("viewer-tasks:identity", 0, fmt.Errorf("invalid queue identity"))
		return
	}
	if _, err := viewerQueueID(queue, projectID, number, queueParts[3]); err != nil {
		out.record("viewer-tasks:identity", 0, err)
		return
	}
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://cloudtasks.googleapis.com/v2/"+queue+"/tasks", url.Values{"pageSize": {"100"}, "responseView": {"BASIC"}, "fields": {viewerTaskFields}}, func(page Object) error {
		rows, err := viewerRows(page, "tasks")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 8 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || parts[3] != queueParts[3] || parts[4] != "queues" || parts[5] != queueParts[5] || parts[6] != "tasks" || !viewerTaskID.MatchString(parts[7]) {
				return fmt.Errorf("invalid or out-of-queue task identity")
			}
			name := queue + "/tasks/" + parts[7]
			if seen[name] {
				continue
			}
			seen[name] = true
			metadata := viewerConfigProjection(d, "name", "scheduleTime", "createTime", "dispatchDeadline", "dispatchCount", "responseCount")
			for _, field := range []string{"httpRequest", "appEngineHttpRequest"} {
				if raw, exists := d[field]; exists {
					request := Obj(raw)
					if request == nil {
						return fmt.Errorf("invalid task HTTP configuration")
					}
					projected := viewerConfigProjection(request, "url", "httpMethod", "relativeUri", "appEngineRouting")
					for _, tokenField := range []string{"oidcToken", "oauthToken"} {
						if raw, exists := request[tokenField]; exists {
							token := Obj(raw)
							if token == nil {
								return fmt.Errorf("invalid task identity configuration")
							}
							projected[tokenField] = viewerConfigProjection(token, "serviceAccountEmail", "audience", "scope")
						}
					}
					metadata[field] = projected
				}
			}
			a := NewAsset("//cloudtasks.googleapis.com/"+name, "cloudtasks.googleapis.com/Task", metadata)
			a.Ancestors = []string{number}
			a.Resource.Location = parts[3]
			out.Assets = append(out.Assets, a)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("Cloud Tasks task inventory has unreachable resources")
	}
	out.record("viewer-tasks-basic:"+queue, len(out.Assets)-start, err)
}

func (c *Client) viewerVertexJobs(ctx context.Context, out *Snapshot, projectID, number, region, collection string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	host := region + "-aiplatform.googleapis.com"
	specField, kind := "jobSpec", "CustomJob"
	fields := "name,displayName,labels,state,createTime,startTime,endTime,updateTime,encryptionSpec,jobSpec"
	if collection == "pipelineJobs" {
		specField, kind = "pipelineSpec", "PipelineJob"
		fields = "name,displayName,labels,state,createTime,startTime,endTime,updateTime,encryptionSpec,pipelineSpec,serviceAccount,network,reservedIpRanges,runtimeConfig,templateUri,templateMetadata"
	}
	err := c.viewerPages(ctx, "https://"+host+"/v1/projects/"+projectID+"/locations/"+region+"/"+collection, url.Values{"pageSize": {"100"}, "readMask": {"name"}}, func(page Object) error {
		rows, err := viewerRows(page, collection)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id, err := viewerBuildWorkflowName(Str(d["name"]), projectID, number, region, collection)
			if err != nil {
				return err
			}
			name := number + "/locations/" + region + "/" + collection + "/" + id
			if seen[name] {
				continue
			}
			seen[name] = true
			full, getErr := c.get(ctx, "https://"+host+"/v1/"+name, url.Values{"fields": {fields}})
			if getErr == nil {
				fullID, identityErr := viewerBuildWorkflowName(Str(full["name"]), projectID, number, region, collection)
				getErr = identityErr
				if getErr == nil && fullID != id {
					getErr = fmt.Errorf("mismatched Vertex job detail identity")
				}
			}
			out.record("viewer-vertex-detail:"+name, 1, getErr)
			if getErr != nil {
				continue
			}
			if Obj(full[specField]) == nil {
				out.Coverage = append(out.Coverage, Coverage{Source: "viewer-vertex-config:" + name, Status: "incomplete", Error: "Vertex detail omitted the job configuration object; no absence-based network posture was inferred."})
				continue
			}
			metadata := viewerConfigProjection(full, strings.Split(fields, ",")...)
			a := NewAsset("//aiplatform.googleapis.com/"+name, "aiplatform.googleapis.com/"+kind, metadata)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			c.SecretCapture.captureOther(a)
			out.Assets = append(out.Assets, a)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("Vertex job inventory has unreachable resources")
	}
	out.record("viewer-vertex-jobs:"+projectID+":"+region+":"+collection, len(out.Assets)-start, err)
}
