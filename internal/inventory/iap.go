package inventory

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

var projectNumberPattern = regexp.MustCompile(`^projects/[0-9]+$`)
var computeIAPSource = regexp.MustCompile(`^//compute.googleapis.com/projects/[^/]+/(global|zones/([a-z0-9-]+)|regions/([a-z0-9-]+))/(instances|backendServices)/([A-Za-z0-9_-]+)$`)
var runIAPSource = regexp.MustCompile(`^//run.googleapis.com/projects/[^/]+/locations/([a-z0-9-]+)/services/([A-Za-z0-9_-]+)$`)
var appEngineIAPSource = regexp.MustCompile(`^//appengine.googleapis.com/apps/([a-z0-9-]+)(?:/services/([a-z0-9-]+))?(?:/versions/([a-z0-9-]+))?$`)

func iapTargets(a Asset) ([]string, bool) {
	project := ""
	for _, ancestor := range a.Ancestors {
		if projectNumberPattern.MatchString(ancestor) {
			project = ancestor
			break
		}
	}
	name := strings.TrimPrefix(a.Name, "//cloudresourcemanager.googleapis.com/")
	if projectNumberPattern.MatchString(name) {
		project = name
	}
	if project == "" {
		return nil, false
	}
	out := []string{project + "/iap_web", project + "/iap_tunnel"}
	if strings.HasPrefix(a.Type, "appengine.googleapis.com/") {
		m := appEngineIAPSource.FindStringSubmatch(a.Name)
		if m == nil || (m[3] != "" && m[2] == "") || (a.Type == "appengine.googleapis.com/Version" && m[3] == "") || (a.Type == "appengine.googleapis.com/Service" && (m[2] == "" || m[3] != "")) || (a.Type == "appengine.googleapis.com/Application" && m[2] != "") {
			return out, false
		}
		parent := project + "/iap_web/appengine-" + m[1]
		out = append(out, parent)
		if m[2] != "" {
			parent += "/services/" + m[2]
			out = append(out, parent)
		}
		if m[3] != "" {
			out = append(out, parent+"/versions/"+m[3])
		}
	}
	if a.Type == "compute.googleapis.com/Instance" || a.Type == "compute.googleapis.com/BackendService" || a.Type == "compute.googleapis.com/RegionBackendService" {
		m := computeIAPSource.FindStringSubmatch(a.Name)
		if m == nil {
			return out, false
		}
		if a.Type == "compute.googleapis.com/Instance" {
			if m[2] == "" || m[4] != "instances" {
				return out, false
			}
			parent := project + "/iap_tunnel/zones/" + m[2]
			out = append(out, parent, parent+"/instances/"+m[5])
		} else {
			if m[4] != "backendServices" || m[2] != "" {
				return out, false
			}
			kind := "compute"
			if m[3] != "" {
				kind += "-" + m[3]
			}
			parent := project + "/iap_web/" + kind
			out = append(out, parent, parent+"/services/"+m[5])
		}
	}
	if a.Type == "run.googleapis.com/Service" {
		m := runIAPSource.FindStringSubmatch(a.Name)
		if m == nil {
			return out, false
		}
		parent := project + "/iap_web/cloud_run-" + m[1]
		out = append(out, parent, parent+"/services/"+m[2])
	}
	return out, true
}

// CollectIAPPolicies keeps IAP IAM resources distinct from Compute/Run policies.
// It neither opens tunnels nor invokes protected applications.
func (c *Client) CollectIAPPolicies(ctx context.Context, snap *Snapshot) {
	targets := map[string]bool{}
	unresolved := 0
	for _, a := range snap.Assets {
		switch a.Type {
		case "appengine.googleapis.com/Application", "appengine.googleapis.com/Service", "appengine.googleapis.com/Version", "compute.googleapis.com/Instance", "compute.googleapis.com/BackendService", "compute.googleapis.com/RegionBackendService", "run.googleapis.com/Service", "cloudresourcemanager.googleapis.com/Project":
		default:
			continue
		}
		paths, ok := iapTargets(a)
		if !ok {
			unresolved++
		}
		for _, path := range paths {
			targets[path] = true
		}
	}
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		policy, err := c.readIAMPolicy(ctx, "https://iap.googleapis.com/v1/"+name+":getIamPolicy")
		snap.record("iap-policy:"+name, 1, err)
		if err != nil {
			continue
		}
		a := NewAsset("//iap.googleapis.com/"+name, "iap.googleapis.com/PolicyResource", Object{"name": name, "basis": "IAP IAM policy only; enforcement, reachability and backend authentication unverified"})
		a.IAM = policy
		a.Ancestors = []string{strings.Join(strings.Split(name, "/")[:2], "/")}
		snap.Assets = append(snap.Assets, a)
	}
	if unresolved > 0 {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "iap-policy:unresolved", Status: "incomplete", Count: unresolved, Error: "IAP targets require a numeric project ancestor and supported resource name; some discovered resources could not be resolved."})
	}
	snap.Coverage = append(snap.Coverage, Coverage{Source: "iap-policy:limitations", Status: "notice", Error: "Policies for discovered Compute instances/backends, Cloud Run services, App Engine apps/services/versions and their IAP parents only. CLI global backend and App Engine discovery supplement CAI; failed discovery remains failed coverage. Forwarding-rule authorization, hybrid destination groups and Agent Gateway resources require additional collection. IAM policies do not prove IAP enablement or end-to-end access."})
}
