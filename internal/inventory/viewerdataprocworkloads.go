package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const dataprocJobConfigFields = "hadoopJob(args,properties),sparkJob(args,properties),pysparkJob(args,properties),sparkRJob(args,properties),flinkJob(args,properties),hiveJob(properties,scriptVariables,queryList(queries)),pigJob(properties,scriptVariables,queryList(queries)),sparkSqlJob(properties,scriptVariables,queryList(queries)),prestoJob(properties,queryList(queries)),trinoJob(properties,queryList(queries))"
const dataprocJobSecretFields = "jobs(reference(projectId,jobId)," + dataprocJobConfigFields + "),nextPageToken,unreachable"
const dataprocBatchSecretFields = "batches(name,runtimeConfig(properties),pysparkBatch(args),sparkBatch(args),sparkRBatch(args),sparkSqlBatch(queryVariables)),nextPageToken,unreachable"
const dataprocTemplateSecretFields = "templates(name,jobs(stepId," + dataprocJobConfigFields + "),placement(managedCluster(config(gceClusterConfig(metadata),softwareConfig(properties))))),nextPageToken,unreachable"

var dataprocWorkloadPath = regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/(regions|locations)/[a-z][a-z0-9-]*/(jobs|batches|workflowTemplates)$`)

func (c *Client) viewerDataprocWorkloads(ctx context.Context, out *Snapshot, projectID, number, region string) {
	for _, kind := range []string{"jobs", "batches", "workflowTemplates"} {
		scope, key, fields := "regions", kind, dataprocJobSecretFields
		if kind == "batches" {
			scope = "locations"
			fields = dataprocBatchSecretFields
		}
		if kind == "workflowTemplates" {
			key = "templates"
			fields = dataprocTemplateSecretFields
		}
		parent := "projects/" + projectID + "/" + scope + "/" + region
		count := 0
		err := c.viewerPages(ctx, "https://dataproc.googleapis.com/v1/"+parent+"/"+kind, url.Values{"pageSize": {"100"}, "fields": {fields}}, func(page Object) error {
			rows, e := viewerRows(page, key)
			if e != nil {
				return e
			}
			for _, raw := range rows {
				count++
				if count > 10000 {
					return fmt.Errorf("dataproc workload read limit reached")
				}
				d := Obj(raw)
				resource := ""
				if kind == "jobs" {
					ref := Obj(d["reference"])
					project := Str(ref["projectId"])
					id := Str(ref["jobId"])
					if !viewerKeyResourceID.MatchString(id) || project != projectID && "projects/"+project != number {
						return fmt.Errorf("dataproc job identity mismatch")
					}
					resource = "//dataproc.googleapis.com/" + number + "/regions/" + region + "/jobs/" + id
				} else {
					name := parameterCanonicalName(Str(d["name"]), projectID, number)
					prefix := number + "/" + scope + "/" + region + "/" + kind + "/"
					if !strings.HasPrefix(name, prefix) || !viewerKeyResourceID.MatchString(strings.TrimPrefix(name, prefix)) {
						return fmt.Errorf("dataproc workload identity mismatch")
					}
					resource = "//dataproc.googleapis.com/" + name
				}
				switch kind {
				case "jobs":
					if e := c.captureDataprocJob(d, resource, region, ""); e != nil {
						return e
					}
				case "batches":
					c.SecretCapture.CaptureStringMap("dataproc_properties", resource, region, "runtimeConfig.properties", Obj(d["runtimeConfig"])["properties"])
					c.SecretCapture.CaptureStringMap("dataproc_properties", resource, region, "sparkSqlBatch.queryVariables", Obj(d["sparkSqlBatch"])["queryVariables"])
					for _, job := range []string{"pysparkBatch", "sparkBatch", "sparkRBatch"} {
						if e := c.captureDataprocTexts(Obj(d[job])["args"], resource, region, job+".args", "dataproc_args"); e != nil {
							return e
						}
					}
				case "workflowTemplates":
					jobs, e := viewerRows(d, "jobs")
					if e != nil {
						return e
					}
					for i, rawJob := range jobs {
						if e := c.captureDataprocJob(Obj(rawJob), resource, region, "jobs["+strconv.Itoa(i)+"]."); e != nil {
							return e
						}
					}
					cfg := Obj(Obj(Obj(d["placement"])["managedCluster"])["config"])
					c.SecretCapture.CaptureStringMap("dataproc_metadata", resource, region, "placement.managedCluster.config.gceClusterConfig.metadata", Obj(cfg["gceClusterConfig"])["metadata"])
					c.SecretCapture.CaptureStringMap("dataproc_properties", resource, region, "placement.managedCluster.config.softwareConfig.properties", Obj(cfg["softwareConfig"])["properties"])
				}
			}
			partial, e := viewerBuildWorkflowUnreachable(page)
			if e != nil {
				return e
			}
			if partial {
				return fmt.Errorf("dataproc workload list has unreachable resources")
			}
			return nil
		})
		out.record("dataproc-secrets:"+kind+":"+parent, count, err)
	}
}

func (c *Client) captureDataprocJob(d Object, resource, region, prefix string) error {
	for _, job := range []string{"hadoopJob", "sparkJob", "pysparkJob", "sparkRJob", "flinkJob", "hiveJob", "pigJob", "sparkSqlJob", "prestoJob", "trinoJob"} {
		cfg := Obj(d[job])
		root := prefix + job
		c.SecretCapture.CaptureStringMap("dataproc_properties", resource, region, root+".properties", cfg["properties"])
		c.SecretCapture.CaptureStringMap("dataproc_properties", resource, region, root+".scriptVariables", cfg["scriptVariables"])
		if e := c.captureDataprocTexts(cfg["args"], resource, region, root+".args", "dataproc_args"); e != nil {
			return e
		}
		if e := c.captureDataprocTexts(Obj(cfg["queryList"])["queries"], resource, region, root+".queryList.queries", "dataproc_query"); e != nil {
			return e
		}
	}
	return nil
}
func (c *Client) captureDataprocTexts(value any, resource, region, path, source string) error {
	if value == nil {
		return nil
	}
	values, ok := value.([]any)
	if !ok {
		return fmt.Errorf("invalid dataproc text list")
	}
	if len(values) > 10000 {
		return fmt.Errorf("dataproc text list limit reached")
	}
	for i, value := range values {
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid dataproc text value")
		}
		if text != "" {
			c.SecretCapture.Add(SecretSample{SourceType: source, Resource: resource, Location: region, Path: path + "[" + strconv.Itoa(i) + "]", Data: []byte(text)})
		}
	}
	return nil
}

func dataprocWorkloadSecretPermissions(method string, u *url.URL, q url.Values) ([]string, error) {
	parts := dataprocWorkloadPath.FindStringSubmatch(u.Path)
	if method != "GET" || u.RawPath != "" || len(parts) != 3 || q.Get("pageSize") != "100" {
		return nil, fmt.Errorf("viewer-only policy: unreviewed dataproc workload request")
	}
	kind, fields, permission := parts[2], dataprocJobSecretFields, "dataproc.jobs.list"
	switch kind {
	case "batches":
		if parts[1] != "locations" {
			return nil, fmt.Errorf("viewer-only policy: invalid batch scope")
		}
		fields = dataprocBatchSecretFields
		permission = "dataproc.batches.list"
	case "workflowTemplates":
		fields = dataprocTemplateSecretFields
		permission = "dataproc.workflowTemplates.list"
	case "jobs":
		if parts[1] != "regions" {
			return nil, fmt.Errorf("viewer-only policy: invalid job scope")
		}
	}
	if q.Get("fields") != fields {
		return nil, fmt.Errorf("viewer-only policy: unreviewed dataproc workload fields")
	}
	for key, values := range q {
		if key != "pageSize" && key != "fields" && key != "pageToken" || len(values) != 1 {
			return nil, fmt.Errorf("viewer-only policy: unreviewed dataproc workload query")
		}
	}
	return []string{permission}, nil
}
