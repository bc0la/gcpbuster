package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// CollectViewerSecretIAM reads policies on already discovered global/regional
// Secret resources. It never accesses a SecretVersion payload or follows a
// resource-provided URL. Conditions remain evidence, not evaluated grants.
func (c *Client) CollectViewerSecretIAM(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-secret-iam:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	const prefix = "//secretmanager.googleapis.com/"
	policies := map[string]Object{}
	seen := map[string]bool{}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != "secretmanager.googleapis.com/Secret" {
			continue
		}
		// Other projects coexist in organization/folder snapshots. Only the
		// requested canonical project is eligible for this collection pass.
		if !strings.HasPrefix(a.Name, prefix+number+"/") {
			continue
		}
		name := strings.TrimPrefix(a.Name, prefix)
		host, err := viewerSecretIAMHost(name, number)
		if err == nil && Str(a.Resource.Data["name"]) != name {
			err = fmt.Errorf("mismatched Secret Manager metadata identity")
		}
		if err == nil && strings.Contains(name, "/locations/") && a.Resource.Location != "" && a.Resource.Location != strings.Split(name, "/")[3] {
			err = fmt.Errorf("mismatched Secret Manager location")
		}
		if err != nil {
			out.record("viewer-secret-iam:identity", 0, err)
			continue
		}
		if seen[name] {
			if policy := policies[name]; policy != nil {
				a.IAM = policy
			}
			continue
		}
		seen[name] = true
		policy, err := c.get(ctx, "https://"+host+"/v1/"+name+":getIamPolicy", url.Values{"options.requestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag,auditConfigs"}})
		if err == nil && viewerValidateKeyPolicy(policy) != nil {
			err = fmt.Errorf("malformed Secret Manager IAM policy or missing conditional-policy version 3")
		}
		count := 0
		if err == nil {
			// Retain the complete policy schema, not arbitrary unknown fields
			// or upstream internal markers. Empty direct policies stay non-nil.
			policy = viewerConfigProjection(policy, "version", "bindings", "etag", "auditConfigs")
			a.IAM = policy
			policies[name] = policy
			count = 1
		}
		out.record("viewer-secret-iam:"+name, count, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-secret-iam:limitations:" + projectID, Status: "notice", Error: "Direct IAM policies on discovered global/regional Secret resources only. Conditions are preserved, not evaluated; inherited grants, deny policies and effective payload access are not proven. Policy failures retain metadata and prior policy evidence. No secret version payload or credential is accessed."})
}

func viewerSecretIAMHost(name, number string) (string, error) {
	p := strings.Split(name, "/")
	if len(p) != 4 && len(p) != 6 {
		return "", fmt.Errorf("invalid Secret Manager IAM resource")
	}
	if p[0] != "projects" || "projects/"+p[1] != number || !projectNumberPattern.MatchString(number) {
		return "", fmt.Errorf("out-of-project Secret Manager IAM resource")
	}
	if len(p) == 4 && p[2] == "secrets" && viewerKeyResourceID.MatchString(p[3]) {
		return "secretmanager.googleapis.com", nil
	}
	if len(p) == 6 && p[2] == "locations" && viewerLocation.MatchString(p[3]) && p[3] != "global" && p[4] == "secrets" && viewerKeyResourceID.MatchString(p[5]) {
		return "secretmanager." + p[3] + ".rep.googleapis.com", nil
	}
	return "", fmt.Errorf("invalid Secret Manager IAM resource or region")
}
