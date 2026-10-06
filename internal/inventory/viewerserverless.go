package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var viewerServerlessRegion = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

// CollectViewerServerless reads configuration only. Run v2 services.list does
// not support a wildcard region, so the region set comes from the paginated
// project-specific locations API. Functions v1/v2 expressly support '-'.
// https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/list
// https://docs.cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/list
func (c *Client) CollectViewerServerless(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-serverless:identity", 0, fmt.Errorf("invalid project ID or project number"))
		return
	}
	regions := map[string]bool{}
	partialLocations := false
	err := c.viewerPages(ctx, "https://run.googleapis.com/v1/projects/"+projectID+"/locations", url.Values{"pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 4 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || !viewerServerlessRegion.MatchString(parts[3]) {
				partialLocations = true
				continue
			}
			if id := Str(d["locationId"]); id != "" && id != parts[3] {
				partialLocations = true
				continue
			}
			regions[parts[3]] = true
		}
		return nil
	})
	if err == nil && partialLocations {
		err = fmt.Errorf("some Run locations were malformed or out of scope")
	}
	out.record("viewer-run-locations:"+projectID, len(regions), err)
	ordered := make([]string, 0, len(regions))
	for region := range regions {
		ordered = append(ordered, region)
	}
	sort.Strings(ordered)
	for _, region := range ordered {
		c.CollectViewerRunDomains(ctx, out, projectID, number, region)
		for _, spec := range []struct{ collection, kind string }{{"services", "Service"}, {"jobs", "Job"}} {
			if ctx.Err() != nil {
				out.record("viewer-serverless:"+projectID, 0, ctx.Err())
				return
			}
			c.viewerServerlessList(ctx, out, projectID, number, "run.googleapis.com", "v2", region, spec.collection, spec.kind)
		}
	}
	// Keep native schemas under their corresponding CAI types. In particular,
	// Functions v2 serviceConfig/buildConfig and Run v2 nested task templates
	// must not be flattened into the v1 service-account/environment shape.
	for _, spec := range []struct{ version, kind string }{{"v1", "CloudFunction"}, {"v2", "Function"}} {
		if ctx.Err() != nil {
			out.record("viewer-serverless:"+projectID, 0, ctx.Err())
			return
		}
		c.viewerServerlessList(ctx, out, projectID, number, "cloudfunctions.googleapis.com", spec.version, "-", "functions", spec.kind)
	}
	c.viewerFunctionRunPolicies(ctx, out, projectID, number)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-serverless:limitations", Status: "notice", Error: "Only current Run service/job and Functions API configuration was read. Historical revisions, job executions, source archives, container images and secret payloads were not fetched. Public configuration is not a live reachability or effective-access proof."})
}

// A v2 function supplies its exact underlying Run service resource. It can
// safely seed an IAM read when Run list discovery was denied, without guessing
// names, invoking URLs, or following cross-project references.
func (c *Client) viewerFunctionRunPolicies(ctx context.Context, out *Snapshot, projectID, number string) {
	seen := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type == "run.googleapis.com/Service" {
			seen[a.Name] = true
		}
	}
	refs := map[string]string{}
	conflicts := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "cloudfunctions.googleapis.com/Function" {
			continue
		}
		p := strings.Split(Str(a.Resource.Data["name"]), "/")
		if len(p) != 6 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerServerlessRegion.MatchString(p[3]) || p[4] != "functions" || !viewerResourceName.MatchString(p[5]) {
			continue
		}
		p[1] = projectID
		function := strings.Join(p, "/")
		if a.Name != "//cloudfunctions.googleapis.com/"+function {
			continue
		}
		raw, exists := Obj(a.Resource.Data["serviceConfig"])["service"]
		if !exists {
			continue
		}
		r := strings.Split(Str(raw), "/")
		if len(r) != 6 || r[0] != "projects" || (r[1] != projectID && "projects/"+r[1] != number) || r[2] != "locations" || r[3] != p[3] || r[4] != "services" || !viewerResourceName.MatchString(r[5]) {
			conflicts[function] = true
			out.record("viewer-function-run-iam:"+function, 0, fmt.Errorf("invalid or out-of-scope underlying Run service reference"))
			continue
		}
		r[1] = projectID
		ref := strings.Join(r, "/")
		if old, exists := refs[function]; exists && old != ref {
			conflicts[function] = true
		}
		refs[function] = ref
	}
	functions := []string{}
	for function := range refs {
		functions = append(functions, function)
	}
	sort.Strings(functions)
	for _, function := range functions {
		if conflicts[function] {
			out.record("viewer-function-run-iam:"+function, 0, fmt.Errorf("ambiguous underlying Run service reference"))
			continue
		}
		ref := refs[function]
		name := "//run.googleapis.com/" + ref
		if seen[name] {
			continue
		}
		seen[name] = true
		a := NewAsset(name, "run.googleapis.com/Service", Object{"name": ref, "_gcpbusterFunctionReference": function})
		a.Ancestors = []string{number}
		a.Resource.Location = strings.Split(ref, "/")[3]
		policy, err := c.get(ctx, "https://run.googleapis.com/v2/"+ref+":getIamPolicy", url.Values{"options.requestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag"}})
		if err == nil {
			a.IAM, err = viewerLogViewPolicy(policy)
		}
		n := 0
		if err == nil {
			n = 1
		}
		out.record("viewer-function-run-iam:"+function, n, err)
		out.Assets = append(out.Assets, a)
	}
}

func (c *Client) viewerServerlessList(ctx context.Context, out *Snapshot, projectID, number, host, version, region, collection, kind string) {
	start := len(out.Assets)
	partial := false
	seen := map[string]bool{}
	query := url.Values{"pageSize": {"100"}}
	if c.SecretCapture != nil {
		fields := secretCaptureRunServiceFields
		if collection == "jobs" {
			fields = secretCaptureRunJobFields
		}
		if host == "cloudfunctions.googleapis.com" {
			fields = secretCaptureFunctionV1Fields
			if version == "v2" {
				fields = secretCaptureFunctionV2Fields
			}
		}
		query.Set("fields", collection+"("+fields+"),nextPageToken,unreachable")
	}
	err := c.viewerPages(ctx, "https://"+host+"/"+version+"/projects/"+projectID+"/locations/"+region+"/"+collection, query, func(page Object) error {
		rows, err := viewerRows(page, collection)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || !viewerServerlessRegion.MatchString(parts[3]) || (region != "-" && parts[3] != region) || parts[4] != collection || !viewerResourceName.MatchString(parts[5]) {
				partial = true
				continue
			}
			// CAI names use the project ID even when the API returns a number.
			parts[1] = projectID
			name := "//" + host + "/" + strings.Join(parts, "/")
			if seen[name] {
				continue
			}
			seen[name] = true
			a := NewAsset(name, host+"/"+kind, d)
			a.Ancestors = []string{number}
			a.Resource.Location = parts[3]
			c.SecretCapture.captureServerless(a)
			if collection == "services" || collection == "functions" {
				policy, policyErr := c.get(ctx, "https://"+host+"/"+version+"/"+strings.Join(parts, "/")+":getIamPolicy", url.Values{"options.requestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag"}})
				if policyErr == nil {
					a.IAM, policyErr = viewerLogViewPolicy(policy)
				}
				n := 0
				if policyErr == nil {
					n = 1
				}
				out.record("viewer-serverless-iam:"+host+":"+version+":"+strings.Join(parts, "/"), n, policyErr)
			}
			out.Assets = append(out.Assets, a)
		}
		for _, key := range []string{"unreachable", "unreachableLocations"} {
			unreachable, err := viewerRows(page, key)
			if err != nil {
				return err
			}
			if len(unreachable) > 0 {
				partial = true
			}
			for _, raw := range unreachable {
				if Str(raw) == "" {
					return fmt.Errorf("invalid serverless unreachable location")
				}
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("serverless inventory includes unreachable locations")
	}
	out.record("viewer-serverless:"+host+":"+version+":"+projectID+":"+region+":"+collection, len(out.Assets)-start, err)
}
