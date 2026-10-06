package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const dataprocClusterSecretFields = "clusters(projectId,clusterName,config(gceClusterConfig(metadata),softwareConfig(properties))),nextPageToken"

var dataprocClusterSecretPath = regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/regions/[a-z][a-z0-9-]*/clusters$`)

// CollectViewerDataprocSecrets inspects stored cluster configuration, never
// bootstrap artifacts, job execution, guest files or data-plane content.
func (c *Client) CollectViewerDataprocSecrets(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("dataproc-secrets:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	regions := map[string]bool{}
	err := c.viewerPages(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/regions", url.Values{"maxResults": {"100"}, "fields": {"items(name,selfLink),nextPageToken,warning(code)"}}, func(page Object) error {
		rows, e := viewerRows(page, "items")
		if e != nil {
			return e
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !viewerLocation.MatchString(name) || d["selfLink"] != nil && !viewerComputeDiskLink(Str(d["selfLink"]), projectID, number, "regions/"+name) {
				return fmt.Errorf("invalid dataproc region discovery")
			}
			regions[name] = true
		}
		if page["warning"] != nil {
			return fmt.Errorf("region discovery warning")
		}
		return nil
	})
	out.record("dataproc-secrets:regions:"+projectID, len(regions), err)
	count := 0
	for _, region := range orderedViewerRegions(regions) {
		err := c.viewerPages(ctx, "https://dataproc.googleapis.com/v1/projects/"+projectID+"/regions/"+region+"/clusters", url.Values{"pageSize": {"100"}, "fields": {dataprocClusterSecretFields}}, func(page Object) error {
			rows, e := viewerRows(page, "clusters")
			if e != nil {
				return e
			}
			for _, raw := range rows {
				count++
				if count > 10000 {
					return fmt.Errorf("dataproc cluster limit reached")
				}
				d := Obj(raw)
				id := Str(d["clusterName"])
				project := Str(d["projectId"])
				if !viewerResourceName.MatchString(id) || project != projectID && "projects/"+project != number {
					return fmt.Errorf("dataproc cluster identity mismatch")
				}
				resource := "//dataproc.googleapis.com/" + number + "/regions/" + region + "/clusters/" + id
				config := Obj(d["config"])
				c.SecretCapture.CaptureStringMap("dataproc_metadata", resource, region, "config.gceClusterConfig.metadata", Obj(config["gceClusterConfig"])["metadata"])
				c.SecretCapture.CaptureStringMap("dataproc_properties", resource, region, "config.softwareConfig.properties", Obj(config["softwareConfig"])["properties"])
			}
			return nil
		})
		out.record("dataproc-secrets:clusters:"+projectID+":"+region, count, err)
		if count > 10000 {
			break
		}
		c.viewerDataprocWorkloads(ctx, out, projectID, number, region)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "dataproc-secrets:boundary:" + projectID, Status: "notice", Error: "Stored cluster metadata/software properties, retained job arguments/properties/inline queries, serverless batch arguments/runtime properties and workflow template configuration in discovered Compute regions only. Job history retention and encrypted/unreachable resources limit completeness. Referenced scripts, notebooks, initialization objects, guest files and data-plane contents are not downloaded. No execution or credential validation."})
}

func dataprocSecretPermissions(method string, u *url.URL, q url.Values) ([]string, error) {
	if dataprocWorkloadPath.MatchString(u.Path) {
		return dataprocWorkloadSecretPermissions(method, u, q)
	}
	if method != "GET" || u.RawPath != "" || !dataprocClusterSecretPath.MatchString(u.Path) || q.Get("fields") != dataprocClusterSecretFields || q.Get("pageSize") != "100" {
		return nil, fmt.Errorf("viewer-only policy: unreviewed dataproc secret request")
	}
	for key, values := range q {
		if key != "fields" && key != "pageSize" && key != "pageToken" || len(values) != 1 {
			return nil, fmt.Errorf("viewer-only policy: unreviewed dataproc secret query")
		}
	}
	if strings.Contains(u.Path, ":") {
		return nil, fmt.Errorf("viewer-only policy: forbidden dataproc action")
	}
	return []string{"dataproc.clusters.list"}, nil
}
