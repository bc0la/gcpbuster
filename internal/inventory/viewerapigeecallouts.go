package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
)

const viewerApigeeCalloutDepth = 8
const viewerApigeeCalloutNodes = 64
const viewerApigeeCalloutDownloads = 32

type apigeeCalloutList struct {
	rows []any
	err  error
}
type apigeeCalloutBundle struct {
	auth Object
	refs []ApigeeFlowReference
	err  error
}
type apigeeCalloutResolver struct {
	c                *Client
	out              *Snapshot
	parent           string
	nodes, downloads int
	lists            map[string]apigeeCalloutList
	bundles          map[string]apigeeCalloutBundle
}

func newApigeeCalloutResolver(c *Client, out *Snapshot, parent string) *apigeeCalloutResolver {
	return &apigeeCalloutResolver{c: c, out: out, parent: parent, lists: map[string]apigeeCalloutList{}, bundles: map[string]apigeeCalloutBundle{}}
}

// Resolve source references only. Neither conditional expressions nor custom
// code execute here. A resolved source edge is not effective authorization.
func (r *apigeeCalloutResolver) resolve(ctx context.Context, env string, refs []ApigeeFlowReference, depth int, active map[string]bool) Object {
	edges := []any{}
	result := Object{"complete": true, "scope": "observed_static_request_references", "edges": edges}
	if !viewerApigeeID.MatchString(env) {
		result["complete"] = false
		return result
	}
	for _, ref := range refs {
		if depth >= viewerApigeeCalloutDepth || r.nodes >= viewerApigeeCalloutNodes {
			result["complete"] = false
			edges = append(edges, Object{"status": "limit"})
			break
		}
		r.nodes++
		edge := Object{"conditional": ref.Conditional, "enabled": ref.Enabled, "continue_on_error": ref.ContinueOnError, "status": "error"}
		edges = append(edges, edge)
		if !viewerApigeeID.MatchString(ref.SharedFlow) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(ref.EndpointDigest) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(ref.PolicyDigest) || (ref.EndpointKind != "ProxyEndpoint" && ref.EndpointKind != "SharedFlow") {
			result["complete"] = false
			continue
		}
		edge["endpoint_digest"] = ref.EndpointDigest
		edge["endpoint_kind"] = ref.EndpointKind
		edge["policy_digest"] = ref.PolicyDigest
		flow := r.parent + "/sharedflows/" + ref.SharedFlow
		edge["shared_flow"] = flow
		if !ref.Enabled {
			edge["status"] = "disabled"
			continue
		}
		activeKey := env + ":" + flow
		if active[activeKey] {
			edge["status"] = "cycle"
			result["complete"] = false
			continue
		}
		listed, exists := r.lists[flow]
		if !exists {
			page, e := r.c.get(ctx, "https://apigee.googleapis.com/v1/"+flow+"/deployments", url.Values{"fields": {viewerApigeeDeploymentFields}})
			var rows []any
			if e == nil {
				rows, e = viewerRows(page, "deployments")
			}
			listed = apigeeCalloutList{rows, e}
			r.lists[flow] = listed
			r.out.record("viewer-apigee:callout-deployments:"+flow, len(rows), e)
		}
		if listed.err != nil {
			result["complete"] = false
			continue
		}
		valid := true
		revisions := map[string]Object{}
		for _, raw := range listed.rows {
			d := Obj(raw)
			observedEnv, rev := Str(d["environment"]), Str(d["revision"])
			if !viewerApigeeID.MatchString(observedEnv) || !viewerApigeeRevision.MatchString(rev) {
				valid = false
				continue
			}
			if observedEnv != env {
				continue
			}
			if name, exists := d["apiProxy"]; exists && name != ref.SharedFlow {
				valid = false
				continue
			}
			if _, exists := revisions[rev]; exists {
				valid = false
				continue
			}
			entry := Object{"name": flow + "/revisions/" + rev}
			if state, exists := d["state"]; exists {
				switch state {
				case "READY", "PROGRESSING", "ERROR", "RUNTIME_STATE_UNSPECIFIED":
					entry["state"] = state
				default:
					valid = false
				}
			}
			revisions[rev] = entry
		}
		revs := []string{}
		for rev := range revisions {
			revs = append(revs, rev)
		}
		sort.Strings(revs)
		rows := []any{}
		for _, rev := range revs {
			rows = append(rows, revisions[rev])
		}
		edge["revisions"] = rows
		if !valid {
			result["complete"] = false
			continue
		}
		if len(revs) == 0 {
			edge["status"] = "missing"
			result["complete"] = false
			continue
		}
		if len(revs) != 1 {
			edge["status"] = "ambiguous"
			result["complete"] = false
			continue
		}
		entry := revisions[revs[0]]
		name := Str(entry["name"])
		parsed, exists := r.bundles[name]
		if !exists {
			if r.downloads >= viewerApigeeCalloutDownloads {
				edge["status"] = "limit"
				result["complete"] = false
				continue
			}
			r.downloads++
			body, e := r.c.viewerApigeeBundle(ctx, name)
			var auth Object
			var nested []ApigeeFlowReference
			if e == nil {
				auth, nested, e = r.c.projectApigeeBundleCapture(body, name)
			}
			parsed = apigeeCalloutBundle{auth, nested, e}
			r.bundles[name] = parsed
			count := 0
			if e == nil {
				count = 1
			}
			r.out.record("viewer-apigee:callout-bundle:"+name, count, e)
		}
		if parsed.auth != nil {
			entry["auth"] = parsed.auth
		}
		if parsed.err != nil {
			result["complete"] = false
			continue
		}
		edge["status"] = "resolved"
		active[activeKey] = true
		nested := r.resolve(ctx, env, parsed.refs, depth+1, active)
		delete(active, activeKey)
		entry["flow_callouts"] = nested
		if nested["complete"] != true {
			result["complete"] = false
		}
	}
	result["edges"] = edges
	if result["complete"] != true {
		r.out.Coverage = append(r.out.Coverage, Coverage{Source: "viewer-apigee:callout-resolution:" + r.parent + ":" + env, Status: "incomplete", Error: fmt.Sprintf("Static request callout resolution incomplete: missing/ambiguous revision, malformed/dynamic dependency, permission failure, cycle or limit (depth %d, edges %d, downloads %d). No condition or code execution.", viewerApigeeCalloutDepth, viewerApigeeCalloutNodes, viewerApigeeCalloutDownloads)})
	}
	return result
}
