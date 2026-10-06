package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const dataFusionLocationsFields = "locations(name,locationId),nextPageToken"
const dataFusionInstancesFields = "instances(name,options),nextPageToken,unreachable"

// Data Fusion control-plane options only. CDAP/runtime endpoint access is a
// separate permission and is never inferred from Viewer instance access.
func (c *Client) CollectViewerDataFusionSecrets(ctx context.Context, out *Snapshot, projectID, number string) {
	if c.SecretCapture == nil {
		return
	}
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-datafusion:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	budget := &secretCollectionBudget{}
	regions := map[string]bool{}
	defer func() {
		if budget.exhausted {
			out.Coverage = append(out.Coverage, Coverage{Source: "viewer-datafusion:limits:" + projectID, Status: "incomplete", Error: "Shared per-project discovery limit reached: at most 1000 pages and 10000 resources. Remaining instance options were not read."})
		}
	}()
	err := c.secretCollectionPages(ctx, "https://datafusion.googleapis.com/v1/"+number+"/locations", url.Values{"pageSize": {"100"}, "fields": {dataFusionLocationsFields}}, budget, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, r := range rows {
			d := Obj(r)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 4 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || !viewerLocation.MatchString(parts[3]) || (Str(d["locationId"]) != "" && Str(d["locationId"]) != parts[3]) {
				return fmt.Errorf("invalid Data Fusion location identity")
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
	out.record("viewer-datafusion:locations:"+projectID, len(regions), err)
	for _, region := range orderedViewerRegions(regions) {
		if budget.exhausted {
			break
		}
		count := 0
		seen := map[string]bool{}
		err := c.secretCollectionPages(ctx, "https://datafusion.googleapis.com/v1/"+number+"/locations/"+region+"/instances", url.Values{"pageSize": {"100"}, "fields": {dataFusionInstancesFields}}, budget, func(page Object) error {
			rows, err := viewerRows(page, "instances")
			if err != nil {
				return err
			}
			for _, r := range rows {
				d := Obj(r)
				id, err := viewerBuildWorkflowName(Str(d["name"]), projectID, number, region, "instances")
				if err != nil {
					return err
				}
				name := "//datafusion.googleapis.com/" + number + "/locations/" + region + "/instances/" + id
				if seen[name] {
					continue
				}
				if err := budget.takeResource(); err != nil {
					return err
				}
				seen[name] = true
				c.SecretCapture.CaptureStringMap("datafusion_options", name, region, "options", d["options"])
				a := NewAsset(name, "datafusion.googleapis.com/Instance", Object{"name": strings.TrimPrefix(name, "//datafusion.googleapis.com/")})
				a.Resource.Location = region
				a.Ancestors = []string{number}
				out.Assets = append(out.Assets, a)
				count++
				c.viewerDataFusionCDAP(ctx, out, projectID, number, number+"/locations/"+region+"/instances/"+id, region, budget)
			}
			unreachable, err := viewerBuildWorkflowUnreachable(page)
			if err != nil {
				return err
			}
			if unreachable {
				return fmt.Errorf("Data Fusion returned unreachable resources")
			}
			return nil
		})
		out.record("viewer-datafusion:instances:"+projectID+":"+region, count, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-datafusion:boundary:" + projectID, Status: "notice", Error: "Instance.options and stored CDAP connection/pipeline property strings in discovered namespaces, using a fresh validated output-only apiEndpoint. Unpaginated CDAP lists/detail responses are bounded at 4 MiB and 10000 resources, shared at most 1000 reads per project. Latest application configuration only; retained version history is not enumerated. No connection test/browse/sample/specification, pipeline execution/preview, secureKeys.getSecret, runtime credential provisioning, database contents or credential validation."})
}

func dataFusionSecretPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed Data Fusion configuration request")
	}
	if method != "GET" || u.Host != "datafusion.googleapis.com" || u.RawPath != "" {
		return fail()
	}
	permission, fields := "", ""
	if regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations$`).MatchString(u.Path) {
		permission = "locations.list"
		fields = dataFusionLocationsFields
	} else if regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/instances$`).MatchString(u.Path) {
		permission = "instances.list"
		fields = dataFusionInstancesFields
	} else if regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/instances/[A-Za-z0-9_-]+$`).MatchString(u.Path) {
		if q.Get("fields") != dataFusionEndpointFields || len(q) != 1 || len(q["fields"]) != 1 {
			return fail()
		}
		return []string{"datafusion.instances.get"}, nil
	} else {
		return fail()
	}
	if q.Get("fields") != fields || q.Get("pageSize") != "100" {
		return fail()
	}
	for k, v := range q {
		if len(v) != 1 || (k != "fields" && k != "pageSize" && k != "pageToken") {
			return fail()
		}
	}
	return []string{"datafusion." + permission}, nil
}
