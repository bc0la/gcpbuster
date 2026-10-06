package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var viewerResourceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
var viewerZone = regexp.MustCompile(`^zones/[a-z0-9-]+$`)
var viewerAssetType = regexp.MustCompile(`^[a-z][a-z0-9.]*\.googleapis\.com/[A-Za-z][A-Za-z0-9]*$`)

// ViewerCloud replaces Cloud Asset Inventory with direct, viewer-permitted
// resource reads. A successful subset never implies complete service coverage.
func (c *Client) ViewerCloud(ctx context.Context, scope string) Snapshot {
	var out Snapshot
	scopes := c.ExpandResourceScopes(ctx, &out, []string{scope})
	metadata := make([]Snapshot, len(scopes))
	projects := make([]viewerProject, len(scopes))
	jobs := make([]viewerTask, 0, len(scopes))
	for i, container := range scopes {
		i, container := i, container
		jobs = append(jobs, viewerTask{scope: container, family: "metadata", out: &metadata[i], run: func() {
			projects[i] = c.viewerContainer(ctx, &metadata[i], container)
		}})
	}
	c.runViewerTasks(ctx, jobs)
	for i := range metadata {
		out.Assets = append(out.Assets, metadata[i].Assets...)
		out.Coverage = append(out.Coverage, metadata[i].Coverage...)
	}
	groups := c.viewerFamilies()
	results := make([][]Snapshot, len(projects))
	for i := range projects {
		results[i] = make([]Snapshot, len(groups))
	}
	jobs = nil
	// Round-robin projects rather than exhausting one project's families first.
	// A single pool bounds all projects and independent service families together.
	for j, family := range groups {
		for i, project := range projects {
			if project.id == "" {
				continue
			}
			i, j, project, family := i, j, project, family
			jobs = append(jobs, viewerTask{scope: project.number + " (" + project.id + ")", family: family.name, out: &results[i][j], run: func() {
				for _, collect := range family.collect {
					if ctx.Err() != nil {
						break
					}
					collect(ctx, &results[i][j], project.id, project.number)
				}
			}})
		}
	}
	c.runViewerTasks(ctx, jobs)
	// Merge in source order, not completion order. IAM search needs the combined
	// direct policies and therefore runs only after every family has finished.
	combined := make([]Snapshot, len(projects))
	for i := range projects {
		combined[i].Assets = append(combined[i].Assets, metadata[i].Assets...)
		for j := range groups {
			combined[i].Assets = append(combined[i].Assets, results[i][j].Assets...)
			out.Coverage = append(out.Coverage, results[i][j].Coverage...)
		}
	}
	jobs = nil
	for i, project := range projects {
		if project.id == "" {
			continue
		}
		i, project := i, project
		jobs = append(jobs, viewerTask{scope: project.number + " (" + project.id + ")", family: "iam-search", out: &combined[i], run: func() {
			c.viewerSearchIAM(ctx, &combined[i], project.number)
		}})
	}
	c.runViewerTasks(ctx, jobs)
	for i := range projects {
		out.Assets = append(out.Assets, combined[i].Assets[len(metadata[i].Assets):]...)
		out.Coverage = append(out.Coverage, combined[i].Coverage...)
	}
	if ctx.Err() != nil {
		out.record("viewer-inventory:"+scope, 0, ctx.Err())
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-inventory:unmapped-services", Status: "incomplete", Error: "Direct viewer inventory covers selected service configuration and metadata, not every GCP service or historical version. Viewer-permitted IAM search adds indexed direct policies, not unindexed policies or effective permissions. Workforce identity and Workspace remain outside this discovery path. Composer discovery depends on indexed resource identities. Individual collector failures and permission denials further limit coverage. Missing resources are not evidence of safety; no additional roles are requested."})
	return out
}

// viewerContainer owns its snapshot; metadata reads may overlap across projects.
func (c *Client) viewerContainer(ctx context.Context, out *Snapshot, container string) viewerProject {
	if ctx.Err() != nil {
		out.record("viewer-inventory:"+container, 0, ctx.Err())
		return viewerProject{}
	}
	d, err := c.get(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+container, nil)
	name := Str(d["name"])
	project := strings.HasPrefix(container, "projects/")
	if err == nil && (!logScopePattern.MatchString(name) || (name != container && !(project && projectNumberPattern.MatchString(name) && Str(d["projectId"]) == strings.TrimPrefix(container, "projects/")))) {
		err = fmt.Errorf("mismatched container metadata")
	}
	parent := Str(d["parent"])
	if err == nil && parent != "" && (!logScopePattern.MatchString(parent) || strings.HasPrefix(parent, "projects/") || parent == name) {
		err = fmt.Errorf("invalid container parent")
	}
	if err == nil && ((strings.HasPrefix(container, "organizations/") && parent != "") || (strings.HasPrefix(container, "folders/") && parent == "")) {
		err = fmt.Errorf("invalid container hierarchy")
	}
	out.record("viewer-metadata:"+container, 1, err)
	if err != nil {
		return viewerProject{}
	}
	kind := "Project"
	if strings.HasPrefix(container, "folders/") {
		kind = "Folder"
	}
	if strings.HasPrefix(container, "organizations/") {
		kind = "Organization"
	}
	a := NewAsset("//cloudresourcemanager.googleapis.com/"+name, "cloudresourcemanager.googleapis.com/"+kind, d)
	// Do not advertise a partial parent chain as complete CAI ancestors.
	if project {
		policy, policyErr := c.getContainerPolicy(ctx, name)
		out.record("viewer-project-iam:"+name, 1, policyErr)
		if policyErr == nil {
			a.IAM = policy
		}
	}
	out.Assets = append(out.Assets, a)
	if !project {
		return viewerProject{}
	}
	projectID := Str(d["projectId"])
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(name) {
		out.record("viewer-project-identity:"+name, 0, fmt.Errorf("project ID or numeric project name missing or invalid"))
		return viewerProject{}
	}
	return viewerProject{id: projectID, number: name}
}

// viewerSearchIAM intentionally sends no query: role/permission filters would
// drop nonmatching bindings and must not be mistaken for complete policies.
func (c *Client) viewerSearchIAM(ctx context.Context, out *Snapshot, scope string) {
	start := len(out.Assets)
	err := c.viewerPages(ctx, "https://cloudasset.googleapis.com/v1/"+scope+":searchAllIamPolicies", url.Values{"pageSize": {"500"}}, func(page Object) error {
		rows, err := viewerRows(page, "results")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			r := Obj(raw)
			name, kind, project := Str(r["resource"]), Str(r["assetType"]), Str(r["project"])
			u, parseErr := url.Parse(name)
			if parseErr != nil || u.Scheme != "" || !strings.HasSuffix(u.Host, ".googleapis.com") || u.Path == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || !viewerAssetType.MatchString(kind) {
				return fmt.Errorf("invalid IAM search resource identity")
			}
			if project != "" && !projectNumberPattern.MatchString(project) {
				return fmt.Errorf("invalid IAM search project")
			}
			inScope := name == "//cloudresourcemanager.googleapis.com/"+scope
			if strings.HasPrefix(scope, "projects/") {
				inScope = inScope || project == scope
			}
			if strings.HasPrefix(scope, "organizations/") {
				inScope = inScope || Str(r["organization"]) == scope
			}
			if strings.HasPrefix(scope, "folders/") {
				folders, err := viewerRows(r, "folders")
				if err != nil {
					return err
				}
				for _, folder := range folders {
					if folder == scope {
						inScope = true
					}
				}
			}
			if !inScope {
				return fmt.Errorf("out-of-scope IAM search result")
			}
			policy := Obj(r["policy"])
			if policy == nil {
				return fmt.Errorf("missing IAM search policy")
			}
			bindings, err := viewerRows(policy, "bindings")
			if err != nil {
				return err
			}
			for _, rawBinding := range bindings {
				b := Obj(rawBinding)
				members, ok := b["members"].([]any)
				if !rolePattern.MatchString(Str(b["role"])) || !ok {
					return fmt.Errorf("invalid IAM search binding")
				}
				for _, member := range members {
					if Str(member) == "" {
						return fmt.Errorf("invalid IAM search member")
					}
				}
				if b["condition"] != nil && Str(Get(b, "condition", "expression")) == "" {
					return fmt.Errorf("invalid IAM search condition")
				}
			}
			// Search guarantees matching bindings, not complete auditConfigs.
			// Downstream absence checks must not treat this as a full policy.
			policy["_gcpbusterBindingsOnly"] = true
			a := NewAsset(name, kind, nil)
			a.IAM = policy
			if project != "" {
				a.Ancestors = []string{project}
			}
			// A direct project policy collected during this scan is fresher than
			// the eventual-consistency search index; do not overwrite it.
			direct := false
			for _, existing := range out.Assets[:start] {
				if existing.Name == name && existing.Type == kind && existing.IAM != nil {
					direct = true
					break
				}
			}
			if !direct {
				out.Assets = append(out.Assets, a)
			}
		}
		return nil
	})
	out.record("viewer-iam-search:"+scope, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-iam-search:limitations", Status: "notice", Error: "Unfiltered project-scoped IAM search preserves indexed direct bindings and conditions, but is eventually consistent, limited to IAM-search-supported asset types, and is not an effective-access or complete-policy absence proof. Folder and organization policies are not collected: folderViewer and organizationViewer do not grant their getIamPolicy or IAM-search permissions."})
}

// viewerPages validates pagination instead of accepting malformed lists as empty.
// Callbacks retain already-validated rows when a later row/page fails.
func (c *Client) viewerPages(ctx context.Context, endpoint string, q url.Values, pageFn func(Object) error) error {
	if q == nil {
		q = url.Values{}
	}
	seen := map[string]bool{}
	for {
		page, err := c.get(ctx, endpoint, q)
		if err != nil {
			return err
		}
		if page == nil {
			return fmt.Errorf("invalid viewer inventory page")
		}
		if err := pageFn(page); err != nil {
			return err
		}
		if raw, exists := page["nextPageToken"]; exists {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("invalid viewer inventory pagination token")
			}
		}
		next := Str(page["nextPageToken"])
		if next == "" {
			return nil
		}
		if seen[next] {
			return fmt.Errorf("repeated viewer inventory pagination token")
		}
		seen[next] = true
		q.Set("pageToken", next)
	}
}

func viewerRows(page Object, key string) ([]any, error) {
	raw, exists := page[key]
	if !exists {
		return nil, nil
	}
	rows, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("invalid viewer inventory list")
	}
	return rows, nil
}

func viewerComputeAsset(row Object, projectID, number, suffix, kind string) (Asset, error) {
	name := Str(row["name"])
	if !viewerResourceName.MatchString(name) {
		return Asset{}, fmt.Errorf("invalid Compute resource name")
	}
	path := "projects/" + projectID + "/" + suffix + "/" + name
	if link := Str(row["selfLink"]); link != "" && link != "https://www.googleapis.com/compute/v1/"+path && link != "https://compute.googleapis.com/compute/v1/"+path {
		return Asset{}, fmt.Errorf("mismatched Compute resource identity")
	}
	a := NewAsset("//compute.googleapis.com/"+path, "compute.googleapis.com/"+kind, row)
	// Only the known project is included; this is not a complete ancestor chain.
	a.Ancestors = []string{number}
	return a, nil
}

func (c *Client) viewerCompute(ctx context.Context, out *Snapshot, projectID, number string) {
	base := "https://compute.googleapis.com/compute/v1/projects/" + projectID
	projectQuery := url.Values{}
	if c.SecretCapture != nil {
		projectQuery.Set("fields", secretCaptureComputeProjectFields)
	}
	d, err := c.get(ctx, base, projectQuery)
	if err == nil && Str(d["name"]) != projectID {
		err = fmt.Errorf("mismatched Compute project identity")
	}
	out.record("viewer-compute-project:"+projectID, 1, err)
	if err == nil {
		a := NewAsset("//compute.googleapis.com/projects/"+projectID, "compute.googleapis.com/Project", d)
		c.SecretCapture.captureMetadata("compute_project_metadata", a.Name, "", "commonInstanceMetadata", d["commonInstanceMetadata"])
		a.Ancestors = []string{number}
		out.Assets = append(out.Assets, a)
	}
	start := len(out.Assets)
	err = c.viewerPages(ctx, base+"/global/firewalls", url.Values{"maxResults": {"500"}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			a, err := viewerComputeAsset(Obj(raw), projectID, number, "global/firewalls", "Firewall")
			if err != nil {
				return err
			}
			out.Assets = append(out.Assets, a)
		}
		return nil
	})
	out.record("viewer-compute-firewalls:"+projectID, len(out.Assets)-start, err)
	start = len(out.Assets)
	partial := false
	instanceQuery := url.Values{"maxResults": {"500"}, "returnPartialSuccess": {"true"}}
	if c.SecretCapture != nil {
		instanceQuery.Set("fields", "items/*/instances("+secretCaptureComputeInstanceFields+"),items/*/warning,items/*/error,nextPageToken,warning,unreachables")
	}
	err = c.viewerPages(ctx, base+"/aggregated/instances", instanceQuery, func(page Object) error {
		items := Obj(page["items"])
		if _, exists := page["items"]; exists && items == nil {
			return fmt.Errorf("invalid aggregated Compute inventory")
		}
		keys := make([]string, 0, len(items))
		for key := range items {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, zone := range keys {
			if !viewerZone.MatchString(zone) {
				return fmt.Errorf("invalid Compute inventory zone")
			}
			group := Obj(items[zone])
			if group == nil {
				return fmt.Errorf("invalid Compute inventory zone result")
			}
			if group["warning"] != nil && Str(Get(group, "warning", "code")) != "NO_RESULTS_ON_PAGE" {
				partial = true
			}
			if group["error"] != nil {
				partial = true
			}
			rows, err := viewerRows(group, "instances")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				a, err := viewerComputeAsset(Obj(raw), projectID, number, zone+"/instances", "Instance")
				if err != nil {
					return err
				}
				c.SecretCapture.captureMetadata("compute_instance_metadata", a.Name, strings.TrimPrefix(zone, "zones/"), "metadata", a.Resource.Data["metadata"])
				out.Assets = append(out.Assets, a)
			}
		}
		unreachables, err := viewerRows(page, "unreachables")
		if err != nil {
			return err
		}
		if (page["warning"] != nil && Str(Get(page, "warning", "code")) != "NO_RESULTS_ON_PAGE") || len(unreachables) > 0 {
			partial = true
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("partial or unreachable Compute instance inventory")
	}
	out.record("viewer-compute-instances:"+projectID, len(out.Assets)-start, err)
}

func (c *Client) viewerBuckets(ctx context.Context, out *Snapshot, projectID, number string) {
	start := len(out.Assets)
	err := c.viewerPages(ctx, "https://storage.googleapis.com/storage/v1/b", url.Values{"project": {projectID}, "projection": {"noAcl"}, "maxResults": {"1000"}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !bucketNamePattern.MatchString(name) || Str(d["projectNumber"]) != strings.TrimPrefix(number, "projects/") {
				return fmt.Errorf("invalid or out-of-project bucket identity")
			}
			a := NewAsset("//storage.googleapis.com/"+name, "storage.googleapis.com/Bucket", d)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return nil
	})
	out.record("viewer-storage-buckets:"+projectID, len(out.Assets)-start, err)
}
