package inventory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const viewerApigeeOrgFields = "name,projectId"
const viewerApigeeDeploymentFields = "deployments(apiProxy,revision,environment,state)"
const viewerApigeeGroupFields = "environmentGroups(name,hostnames,state),nextPageToken"
const viewerApigeeAttachmentFields = "environmentGroupAttachments(name,environment,environmentGroupId),nextPageToken"
const viewerApigeeHookFields = "flowHookPoint,sharedFlow,continueOnError"
const ApigeeProxyRevisionType = "gcpbuster.googleapis.com/ApigeeProxyRevision"
const viewerApigeeBundleLimit = 16 << 20

var viewerApigeeID = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$`)
var viewerApigeeRevision = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

func viewerApigeeQueryValid(method, path string, q url.Values) bool {
	if method != "GET" {
		return false
	}
	p := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fields := ""
	paged := false
	switch {
	case len(p) == 4 && p[3] == "apiproducts":
		return viewerApigeeProductsQuery(q)
	case len(p) == 3:
		fields = viewerApigeeOrgFields
	case len(p) == 4 && p[3] == "deployments":
		fields = viewerApigeeDeploymentFields
	case len(p) == 6 && p[3] == "sharedflows" && p[5] == "deployments":
		fields = viewerApigeeDeploymentFields
	case len(p) == 7 && p[3] == "environments" && p[5] == "flowhooks":
		fields = viewerApigeeHookFields
	case len(p) == 4 && p[3] == "envgroups":
		fields = viewerApigeeGroupFields
		paged = true
	case len(p) == 6 && p[3] == "envgroups" && p[5] == "attachments":
		fields = viewerApigeeAttachmentFields
		paged = true
	case len(p) == 7 && (p[3] == "apis" || p[3] == "sharedflows") && p[5] == "revisions":
		return len(q) == 1 && len(q["format"]) == 1 && q.Get("format") == "bundle"
	}
	if fields == "" || q.Get("fields") != fields {
		return false
	}
	if paged && q.Get("pageSize") != "100" {
		return false
	}
	for k, v := range q {
		if len(v) != 1 || (k != "fields" && (!paged || (k != "pageSize" && k != "pageToken"))) {
			return false
		}
	}
	return true
}

// Apigee X/hybrid organization names equal the associated project ID. Verify
// the returned binding before collecting any descendants; never list all orgs.
func (c *Client) CollectViewerApigee(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-apigee:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parent := "organizations/" + projectID
	org, err := c.get(ctx, "https://apigee.googleapis.com/v1/"+parent, url.Values{"fields": {viewerApigeeOrgFields}})
	if err == nil && (Str(org["name"]) != projectID || Str(org["projectId"]) != projectID) {
		err = fmt.Errorf("Apigee organization project binding missing or mismatched")
	}
	if err != nil {
		out.record("viewer-apigee:organization:"+projectID, 0, err)
		return
	}
	out.record("viewer-apigee:organization:"+projectID, 1, nil)
	c.collectViewerApigeeProducts(ctx, out, parent, number)
	c.viewerApigeeRouting(ctx, out, parent, number)
	page, err := c.get(ctx, "https://apigee.googleapis.com/v1/"+parent+"/deployments", url.Values{"fields": {viewerApigeeDeploymentFields}})
	deployments := map[string][]any{}
	partial := false
	if err == nil {
		var rows []any
		rows, err = viewerRows(page, "deployments")
		for _, raw := range rows {
			d := Obj(raw)
			api, rev, env := Str(d["apiProxy"]), Str(d["revision"]), Str(d["environment"])
			if !viewerApigeeID.MatchString(api) || !viewerApigeeRevision.MatchString(rev) || !viewerApigeeID.MatchString(env) {
				partial = true
				continue
			}
			name := parent + "/apis/" + api + "/revisions/" + rev
			binding := Object{"environment": env}
			if state, exists := d["state"]; exists {
				switch state {
				case "RUNTIME_STATE_UNSPECIFIED", "READY", "PROGRESSING", "ERROR":
					binding["state"] = state
				default:
					partial = true
				}
			}
			deployments[name] = append(deployments[name], binding)
		}
	}
	if err == nil && partial {
		err = fmt.Errorf("some deployment identities or states malformed")
	}
	out.record("viewer-apigee:deployments:"+projectID, len(deployments), err)
	names := []string{}
	for name := range deployments {
		names = append(names, name)
	}
	sort.Strings(names)
	callouts := newApigeeCalloutResolver(c, out, parent)
	dependencies := c.viewerApigeeDependencies(ctx, out, parent, deployments, callouts)
	for _, name := range names {
		d := Object{"name": name, "deployments": deployments[name]}
		environments := []any{}
		seenEnvironments := map[string]bool{}
		for _, binding := range deployments[name] {
			env := Str(Obj(binding)["environment"])
			if !seenEnvironments[env] {
				environments = append(environments, dependencies[env])
				seenEnvironments[env] = true
			}
		}
		d["_gcpbusterApigeeDependencies"] = Object{"environments": environments}
		bundle, e := c.viewerApigeeBundle(ctx, name)
		if e == nil {
			var projected Object
			var references []ApigeeFlowReference
			projected, references, e = c.projectApigeeBundleCapture(bundle, name)
			if projected != nil {
				d["_gcpbusterApigeeAuth"] = projected
			}
			if e == nil {
				resolved := []any{}
				for _, environment := range environments {
					env := Str(Obj(environment)["environment"])
					graph := callouts.resolve(ctx, env, references, 0, map[string]bool{})
					graph["environment"] = env
					resolved = append(resolved, graph)
				}
				d["_gcpbusterApigeeFlowCallouts"] = Object{"environments": resolved}
			}
		}
		count := 0
		if e == nil {
			count = 1
		}
		out.record("viewer-apigee:bundle:"+name, count, e)
		a := NewAsset("//apigee.googleapis.com/"+name, ApigeeProxyRevisionType, d)
		a.Ancestors = []string{number}
		out.Assets = append(out.Assets, a)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-apigee:limitations:" + projectID, Status: "notice", Error: "Selected deployment/routing, fixed environment flow hooks and bounded static native-request FlowCallout dependencies at observed same-environment revisions only. Dynamic references, conditional reachability, custom code, backend authentication and runtime anonymous access are not fully evaluated. Graph completeness means only static-reference traversal, not complete authorization. Optional secrets capture scans reviewed configuration XML in already-read revision bundles; resources/code/images are excluded. Actual configuration matches can be retained for manual review unless redacted. No protected payloads, credential testing, traces or endpoint requests."})
}

// Only this exact revision-bundle GET may use the binary response path. No
// redirects or response error bodies are followed/persisted. ZIPs are transient;
// optional secret reporting retains only matched reviewed configuration members.
func (c *Client) viewerApigeeBundle(ctx context.Context, name string) ([]byte, error) {
	if !regexp.MustCompile(`^organizations/[A-Za-z0-9_-]+/(apis|sharedflows)/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/revisions/[1-9][0-9]{0,18}$`).MatchString(name) {
		return nil, fmt.Errorf("invalid Apigee revision identity")
	}
	endpoint := "https://apigee.googleapis.com/v1/" + name
	q := url.Values{"format": {"bundle"}}
	if e := c.requireViewerPermissions(ctx, "GET", endpoint, q); e != nil {
		return nil, e
	}
	token, e := c.accessToken(ctx)
	if e != nil {
		return nil, e
	}
	h := &http.Client{Timeout: 60 * time.Second}
	if c.HTTP != nil {
		copy := *c.HTTP
		h = &copy
		if h.Timeout <= 0 {
			h.Timeout = 60 * time.Second
		}
	}
	h.Jar = nil
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+q.Encode(), nil)
	if e != nil {
		return nil, fmt.Errorf("could not construct Apigee bundle request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, e := c.doRequest(h, req, 1)
	if e != nil {
		return nil, fmt.Errorf("Apigee bundle transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Apigee bundle GET HTTP %d", resp.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, viewerApigeeBundleLimit+1))
	if e != nil {
		return nil, fmt.Errorf("Apigee bundle read failed")
	}
	if len(data) > viewerApigeeBundleLimit {
		return nil, fmt.Errorf("Apigee bundle exceeds compressed size limit")
	}
	return data, nil
}

// Dependencies are observational, not a merged effective authorization graph.
// A failed hook read is never converted into an absent hook. A referenced flow
// is only read at revisions explicitly deployed in the same environment.
func (c *Client) viewerApigeeDependencies(ctx context.Context, out *Snapshot, parent string, deployments map[string][]any, resolvers ...*apigeeCalloutResolver) map[string]Object {
	resolver := newApigeeCalloutResolver(c, out, parent)
	if len(resolvers) > 0 {
		resolver = resolvers[0]
	}
	result := map[string]Object{}
	envs := map[string]bool{}
	for _, bindings := range deployments {
		for _, b := range bindings {
			envs[Str(Obj(b)["environment"])] = true
		}
	}
	ordered := []string{}
	for env := range envs {
		ordered = append(ordered, env)
	}
	sort.Strings(ordered)
	type deploymentResult struct {
		rows []any
		err  error
	}
	flows := map[string]deploymentResult{}
	type bundleResult struct {
		auth Object
		refs []ApigeeFlowReference
		err  error
	}
	bundles := map[string]bundleResult{}
	for _, env := range ordered {
		hooks := []any{}
		for _, point := range []string{"PreProxyFlowHook", "PostProxyFlowHook", "PreTargetFlowHook", "PostTargetFlowHook"} {
			hook := Object{"point": point, "status": "error"}
			hooks = append(hooks, hook)
			name := parent + "/environments/" + env + "/flowhooks/" + point
			raw, e := c.get(ctx, "https://apigee.googleapis.com/v1/"+name, url.Values{"fields": {viewerApigeeHookFields}})
			if e == nil && raw == nil {
				e = fmt.Errorf("invalid flow hook response")
			}
			if e == nil {
				if p, exists := raw["flowHookPoint"]; exists && p != point {
					e = fmt.Errorf("flow hook point mismatch")
				}
			}
			if e == nil {
				if v, exists := raw["continueOnError"]; exists {
					if b, ok := v.(bool); ok {
						hook["continue_on_error"] = b
					} else {
						e = fmt.Errorf("invalid flow hook continuation flag")
					}
				}
			}
			shared := ""
			if e == nil {
				if value, exists := raw["sharedFlow"]; exists {
					var ok bool
					shared, ok = value.(string)
					if !ok || (shared != "" && !viewerApigeeID.MatchString(shared)) {
						e = fmt.Errorf("invalid flow hook shared-flow reference")
					}
				}
			}
			if e != nil {
				out.record("viewer-apigee:flowhook:"+name, 0, e)
				continue
			}
			out.record("viewer-apigee:flowhook:"+name, 1, nil)
			if shared == "" {
				hook["status"] = "absent"
				continue
			}
			hook["status"] = "present"
			flow := parent + "/sharedflows/" + shared
			hook["shared_flow"] = flow
			listed, exists := flows[flow]
			if !exists {
				page, e := c.get(ctx, "https://apigee.googleapis.com/v1/"+flow+"/deployments", url.Values{"fields": {viewerApigeeDeploymentFields}})
				var rows []any
				if e == nil {
					rows, e = viewerRows(page, "deployments")
				}
				listed = deploymentResult{rows, e}
				flows[flow] = listed
			}
			revisions := []any{}
			hook["revisions"] = revisions
			complete := listed.err == nil
			hook["complete"] = false
			if listed.err != nil {
				out.record("viewer-apigee:sharedflow-deployments:"+flow+":"+env, 0, listed.err)
				continue
			}
			seen := map[string]bool{}
			for _, row := range listed.rows {
				r := Obj(row)
				rEnv, rev := Str(r["environment"]), Str(r["revision"])
				if !viewerApigeeID.MatchString(rEnv) || !viewerApigeeRevision.MatchString(rev) {
					complete = false
					continue
				}
				if rEnv != env {
					continue
				}
				if api, exists := r["apiProxy"]; exists && api != shared {
					complete = false
					continue
				}
				if seen[rev] {
					complete = false
					continue
				}
				seen[rev] = true
				revisionName := flow + "/revisions/" + rev
				entry := Object{"name": revisionName}
				if state, exists := r["state"]; exists {
					switch state {
					case "READY", "PROGRESSING", "ERROR", "RUNTIME_STATE_UNSPECIFIED":
						entry["state"] = state
					default:
						complete = false
					}
				}
				parsed, exists := bundles[revisionName]
				if !exists {
					body, e := c.viewerApigeeBundle(ctx, revisionName)
					var auth Object
					var refs []ApigeeFlowReference
					if e == nil {
						auth, refs, e = c.projectApigeeBundleCapture(body, revisionName)
					}
					parsed = bundleResult{auth, refs, e}
					bundles[revisionName] = parsed
					count := 0
					if e == nil {
						count = 1
					}
					out.record("viewer-apigee:sharedflow-bundle:"+revisionName, count, e)
				}
				if parsed.auth != nil {
					entry["auth"] = parsed.auth
				}
				if parsed.err != nil {
					complete = false
				}
				if parsed.err == nil {
					entry["flow_callouts"] = resolver.resolve(ctx, env, parsed.refs, 0, map[string]bool{env + ":" + flow: true})
				}
				revisions = append(revisions, entry)
			}
			hook["revisions"] = revisions
			hook["complete"] = complete && len(revisions) == 1
			e = nil
			if !complete || len(revisions) != 1 {
				e = fmt.Errorf("hook shared-flow revision missing, ambiguous or incompletely read in the same environment")
			}
			out.record("viewer-apigee:sharedflow-deployments:"+flow+":"+env, len(revisions), e)
		}
		result[env] = Object{"environment": env, "hooks": hooks}
	}
	return result
}

func (c *Client) viewerApigeeRouting(ctx context.Context, out *Snapshot, parent, number string) {
	groups := []string{}
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://apigee.googleapis.com/v1/"+parent+"/envgroups", url.Values{"fields": {viewerApigeeGroupFields}, "pageSize": {"100"}}, func(page Object) error {
		rows, e := viewerRows(page, "environmentGroups")
		if e != nil {
			return e
		}
		for _, raw := range rows {
			d := Obj(raw)
			id := Str(d["name"])
			if !viewerApigeeID.MatchString(id) || seen[id] {
				partial = true
				continue
			}
			seen[id] = true
			groups = append(groups, id)
			safe := Object{"name": parent + "/envgroups/" + id}
			if state, ok := d["state"]; ok {
				switch state {
				case "STATE_UNSPECIFIED", "CREATING", "ACTIVE", "DELETING", "UPDATING":
					safe["state"] = state
				default:
					partial = true
				}
			}
			hosts, e := viewerRows(d, "hostnames")
			if e != nil {
				partial = true
			} else {
				selected := []any{}
				for _, host := range hosts {
					h, ok := host.(string)
					normalized, valid := DNSLookupName(h)
					if !ok || !valid || strings.Contains(h, "*") {
						partial = true
						continue
					}
					selected = append(selected, normalized)
				}
				safe["hostnames"] = selected
			}
			a := NewAsset("//apigee.googleapis.com/"+Str(safe["name"]), "gcpbuster.googleapis.com/ApigeeEnvironmentGroup", safe)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some environment group metadata malformed")
	}
	out.record("viewer-apigee:envgroups:"+parent, len(groups), err)
	for _, group := range groups {
		groupName := parent + "/envgroups/" + group
		count := 0
		partial := false
		seenAttachments := map[string]bool{}
		err := c.viewerPages(ctx, "https://apigee.googleapis.com/v1/"+groupName+"/attachments", url.Values{"fields": {viewerApigeeAttachmentFields}, "pageSize": {"100"}}, func(page Object) error {
			rows, e := viewerRows(page, "environmentGroupAttachments")
			if e != nil {
				return e
			}
			for _, raw := range rows {
				d := Obj(raw)
				id, env := Str(d["name"]), Str(d["environment"])
				if !viewerApigeeID.MatchString(id) || !viewerApigeeID.MatchString(env) || seenAttachments[id] {
					partial = true
					continue
				}
				if v, ok := d["environmentGroupId"]; ok && v != group {
					partial = true
					continue
				}
				seenAttachments[id] = true
				name := groupName + "/attachments/" + id
				a := NewAsset("//apigee.googleapis.com/"+name, "gcpbuster.googleapis.com/ApigeeEnvironmentGroupAttachment", Object{"name": name, "environment": env, "environmentGroupId": group})
				a.Ancestors = []string{number}
				out.Assets = append(out.Assets, a)
				count++
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some environment group attachments malformed")
		}
		out.record("viewer-apigee:attachments:"+groupName, count, err)
	}
}
