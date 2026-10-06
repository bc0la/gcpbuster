package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var viewerDatasetID = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

const viewerIdentityConfigFields = "name,signIn(anonymous(enabled),email(enabled,passwordRequired),phoneNumber(enabled)),client(permissions(disabledUserSignup)),mfa(state),blockingFunctions(triggers,forwardInboundCredentials(idToken,accessToken,refreshToken))"
const viewerIdentityTenantFields = "name,enableAnonymousUser,allowPasswordSignup,enableEmailLinkSignin,client(permissions(disabledUserSignup)),mfaConfig(state),disableAuth"

// CollectViewerDataConfig reads dataset metadata/ACLs and Identity Platform
// sign-in/MFA settings. It never queries table rows, launches jobs, exports
// users, retrieves hash configuration, or uses application authentication APIs.
func (c *Client) CollectViewerDataConfig(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-data-config:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	c.viewerDatasets(ctx, out, projectID, number)
	c.viewerIdentityConfig(ctx, out, projectID, number)
	c.CollectViewerIdentityProviders(ctx, out, projectID, number)
	c.CollectViewerAppCheck(ctx, out, projectID, number)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-data-config:limitations:" + projectID, Status: "notice", Error: "BigQuery dataset visibility follows the caller's dataset-get permissions; dataset ACLs are not effective table/row/column authorization. Identity Platform collection retains selected typed local provider, signup restriction and MFA posture fields; provider secrets, password hash configuration, users and application login testing are not collected. Enrollment configuration does not establish Firebase Rules or application data access."})
}

func viewerDatasetIdentity(d Object, projectID, number string) (string, error) {
	ref := Obj(d["datasetReference"])
	id := Str(ref["datasetId"])
	project := Str(ref["projectId"])
	if len(id) > 1024 || !viewerDatasetID.MatchString(id) || (project != projectID && "projects/"+project != number) {
		return "", fmt.Errorf("invalid or out-of-project BigQuery dataset")
	}
	return id, nil
}

func (c *Client) viewerDatasets(ctx context.Context, out *Snapshot, projectID, number string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	base := "https://bigquery.googleapis.com/bigquery/v2/projects/" + projectID + "/datasets"
	err := c.viewerPages(ctx, base, url.Values{"all": {"true"}, "maxResults": {"1000"}}, func(page Object) error {
		rows, err := viewerRows(page, "datasets")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id, err := viewerDatasetIdentity(d, projectID, number)
			if err != nil {
				return err
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			full, getErr := c.get(ctx, base+"/"+id, url.Values{"datasetView": {"FULL"}, "accessPolicyVersion": {"3"}})
			if getErr == nil {
				fullID, identityErr := viewerDatasetIdentity(full, projectID, number)
				getErr = identityErr
				if getErr == nil && fullID != id {
					getErr = fmt.Errorf("mismatched BigQuery dataset detail")
				}
			}
			if getErr == nil {
				access, accessErr := viewerRows(full, "access")
				getErr = accessErr
				validated := []any{}
				for _, entry := range access {
					acl := Obj(entry)
					if acl == nil {
						getErr = fmt.Errorf("malformed BigQuery access entry")
						continue
					}
					if acl["condition"] != nil && strings.TrimSpace(Str(Get(acl, "condition", "expression"))) == "" {
						getErr = fmt.Errorf("malformed BigQuery access condition")
						continue
					}
					validated = append(validated, entry)
				}
				// Retain valid entries even when another ACL entry is malformed.
				// Never convert an unreadable condition into unconditional access.
				d = full
				if _, exists := full["access"]; exists {
					d["access"] = validated
				}
			}
			out.record("viewer-bigquery-detail:"+projectID+":"+id, 1, getErr)
			if getErr == nil {
				d = full
				if _, exists := d["access"]; !exists {
					out.Coverage = append(out.Coverage, Coverage{Source: "viewer-bigquery-acl:" + projectID + ":" + id, Status: "incomplete", Error: "FULL dataset detail omitted access entries; absence of public grants was not verified."})
				}
			}
			a := NewAsset("//bigquery.googleapis.com/projects/"+projectID+"/datasets/"+id, "bigquery.googleapis.com/Dataset", d)
			a.Ancestors = []string{number}
			a.Resource.Location = Str(d["location"])
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("BigQuery dataset inventory has unreachable locations")
	}
	out.record("viewer-bigquery-datasets:"+projectID, len(out.Assets)-start, err)
}

func viewerIdentityName(raw, projectID, number, kind string) (string, error) {
	parts := strings.Split(raw, "/")
	if len(parts) < 3 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) {
		return "", fmt.Errorf("invalid or out-of-project Identity Platform resource")
	}
	if kind == "Config" {
		if len(parts) != 3 || parts[2] != "config" {
			return "", fmt.Errorf("invalid Identity Platform config identity")
		}
		return number + "/config", nil
	}
	if len(parts) != 4 || parts[2] != "tenants" || !viewerResourceName.MatchString(parts[3]) {
		return "", fmt.Errorf("invalid Identity Platform tenant identity")
	}
	return number + "/tenants/" + parts[3], nil
}

// Only posture fields needed by existing checks are retained. A credential with
// extra privileges must not accidentally retain provider secrets/hash settings
// embedded in a broader configuration response.
func viewerIdentityPosture(d Object) (Object, error) {
	clean := Object{"name": d["name"]}
	var malformed bool
	paths := [][]string{{"signIn", "anonymous", "enabled"}, {"signIn", "email", "enabled"}, {"signIn", "email", "passwordRequired"}, {"signIn", "phoneNumber", "enabled"}, {"client", "permissions", "disabledUserSignup"}, {"enableAnonymousUser"}, {"allowPasswordSignup"}, {"enableEmailLinkSignin"}, {"disableAuth"}, {"mfa", "state"}, {"mfaConfig", "state"}}
	for _, path := range paths {
		src, dst := d, clean
		for i, key := range path {
			raw, present := src[key]
			if !present {
				break
			}
			if i == len(path)-1 {
				valid := false
				if key == "state" {
					state, ok := raw.(string)
					valid = ok && (state == "STATE_UNSPECIFIED" || state == "DISABLED" || state == "ENABLED" || state == "MANDATORY")
				} else {
					_, valid = raw.(bool)
				}
				if valid {
					dst[key] = raw
				} else {
					malformed = true
				}
				break
			}
			next := Obj(raw)
			if next == nil {
				malformed = true
				break
			}
			if dst[key] == nil {
				dst[key] = Object{}
			}
			src, dst = next, Obj(dst[key])
		}
	}
	if raw, present := d["blockingFunctions"]; present {
		marker, err := viewerIdentityBlockingFunctions(raw)
		clean["_gcpbusterIdentityHooks"] = marker
		if err != nil {
			malformed = true
		}
	}
	if malformed {
		return clean, fmt.Errorf("malformed selected Identity Platform posture fields")
	}
	return clean, nil
}

func (c *Client) viewerIdentityConfig(ctx context.Context, out *Snapshot, projectID, number string) {
	base := "https://identitytoolkit.googleapis.com/v2/" + number
	d, err := c.get(ctx, "https://identitytoolkit.googleapis.com/admin/v2/"+number+"/config", url.Values{"fields": {viewerIdentityConfigFields}})
	name := ""
	if err == nil {
		name, err = viewerIdentityName(Str(d["name"]), projectID, number, "Config")
	}
	out.record("viewer-identity-config:"+projectID, 1, err)
	if err == nil {
		clean, projectionErr := viewerIdentityPosture(d)
		if projectionErr != nil {
			out.record("viewer-identity-config-projection:"+projectID, 1, projectionErr)
		}
		a := NewAsset("//identitytoolkit.googleapis.com/"+name, "identitytoolkit.googleapis.com/Config", clean)
		a.Ancestors = []string{number}
		out.Assets = append(out.Assets, a)
	}
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	err = c.viewerPages(ctx, base+"/tenants", url.Values{"pageSize": {"1000"}, "fields": {"tenants(" + viewerIdentityTenantFields + "),nextPageToken"}}, func(page Object) error {
		rows, err := viewerRows(page, "tenants")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name, err := viewerIdentityName(Str(d["name"]), projectID, number, "Tenant")
			if err != nil {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			full, getErr := c.get(ctx, "https://identitytoolkit.googleapis.com/v2/"+name, url.Values{"fields": {viewerIdentityTenantFields}})
			if getErr == nil {
				fullName, identityErr := viewerIdentityName(Str(full["name"]), projectID, number, "Tenant")
				getErr = identityErr
				if getErr == nil && fullName != name {
					getErr = fmt.Errorf("mismatched Identity Platform tenant detail")
				}
			}
			out.record("viewer-identity-tenant-detail:"+name, 1, getErr)
			if getErr == nil {
				d = full
			}
			clean, projectionErr := viewerIdentityPosture(d)
			if projectionErr != nil {
				partial = true
			}
			a := NewAsset("//identitytoolkit.googleapis.com/"+name, "identitytoolkit.googleapis.com/Tenant", clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("Identity Platform tenant inventory has malformed fields or unreachable locations")
	}
	out.record("viewer-identity-tenants:"+projectID, len(out.Assets)-start, err)
}
