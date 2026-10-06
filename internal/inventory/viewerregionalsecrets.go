package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const viewerRegionalSecretFields = "secrets(name,createTime,expireTime,ttl,versionDestroyTtl,versionAliases,secretType,policyMember(iamPolicyUidPrincipal,iamPolicyNamePrincipal),rotation(nextRotationTime,rotationPeriod,managedRotationStatus(state)),topics(name),customerManagedEncryption(kmsKeyName)),nextPageToken"
const viewerRegionalVersionFields = "versions(name,state,createTime,destroyTime,scheduledDestroyTime,customerManagedEncryption(kmsKeyVersionName)),nextPageToken"

// CollectViewerRegionalSecrets enumerates visible service locations through
// the location API, then uses the corresponding residency endpoint for metadata.
// No payload, access, managed-rotation, cryptographic or credential API is used.
func (c *Client) CollectViewerRegionalSecrets(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-regional-secrets:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	regions := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://secretmanager.googleapis.com/v1/"+number+"/locations", url.Values{"pageSize": {"100"}, "fields": {"locations(name,locationId),nextPageToken"}}, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			p := strings.Split(Str(d["name"]), "/")
			if len(p) != 4 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) {
				partial = true
				continue
			}
			if raw, exists := d["locationId"]; exists {
				id, ok := raw.(string)
				if !ok || (id != "" && id != p[3]) {
					partial = true
					continue
				}
			}
			if p[3] == "global" {
				continue
			} // Global secrets use their separate collector.
			regions[p[3]] = true
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("Secret Manager location discovery was partial or malformed")
	}
	out.record("viewer-regional-secret-locations:"+projectID, len(regions), err)
	for _, region := range orderedViewerRegions(regions) {
		parent := number + "/locations/" + region
		secrets := c.viewerRegionalSecretList(ctx, out, projectID, number, region, parent, false)
		for _, secret := range secrets {
			c.viewerRegionalSecretList(ctx, out, projectID, number, region, secret, true)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-regional-secrets:limitations:" + projectID, Status: "notice", Error: "Regional Secret Manager lifecycle metadata only, across locations returned by the project's service location API. The location API may also list locations where regional endpoints are unavailable; those reads are reported as failures, not empty inventories. Secret type, built-in policy identity and managed-rotation state are metadata; configured Cloud SQL target instance/user are not exposed by the Secret metadata schema and are not inferred. No secret data, labels/annotations, managed-rotation credentials, error details, payload checksums or secret access operations are read. Global secrets are inventoried separately."})
}

func (c *Client) viewerRegionalSecretList(ctx context.Context, out *Snapshot, projectID, number, region, parent string, versions bool) []string {
	collection, kind, fields := "secrets", "Secret", viewerRegionalSecretFields
	if versions {
		collection, kind, fields = "versions", "SecretVersion", viewerRegionalVersionFields
	}
	if !versions && c.SecretCapture != nil {
		fields = secretCaptureRegionalSecretFields
	}
	host := "secretmanager." + region + ".rep.googleapis.com"
	seen := map[string]bool{}
	names := []string{}
	partial := false
	err := c.viewerPages(ctx, "https://"+host+"/v1/"+parent+"/"+collection, url.Values{"pageSize": {"1000"}, "fields": {fields}}, func(page Object) error {
		rows, err := viewerRows(page, collection)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if strings.HasPrefix(name, "projects/"+projectID+"/") {
				name = number + strings.TrimPrefix(name, "projects/"+projectID)
			}
			prefix := parent + "/" + collection + "/"
			id := strings.TrimPrefix(name, prefix)
			if !strings.HasPrefix(name, prefix) || !viewerKeyResourceID.MatchString(id) || (versions && !viewerKeyVersionID.MatchString(id)) {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			clean, err := viewerRegionalSecretProjection(d, versions)
			if err != nil {
				partial = true
				continue
			}
			clean["name"] = name
			a := NewAsset("//secretmanager.googleapis.com/"+name, "secretmanager.googleapis.com/"+kind, clean)
			a.Ancestors = []string{number}
			a.Resource.Location = region
			if !versions {
				c.SecretCapture.CaptureStringMap("secret_manager_annotations", a.Name, region, "annotations", d["annotations"])
			}
			out.Assets = append(out.Assets, a)
			seen[name] = true
			names = append(names, name)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("regional secret metadata contains malformed, out-of-scope or unreachable resources")
	}
	out.record("viewer-regional-secret-metadata:"+parent+"/"+collection, len(names), err)
	return names
}

func viewerRegionalSecretProjection(d Object, version bool) (Object, error) {
	clean := Object{}
	fields := []string{"name", "createTime", "expireTime", "ttl", "versionDestroyTtl", "secretType"}
	if version {
		fields = []string{"name", "state", "createTime", "destroyTime", "scheduledDestroyTime"}
	}
	for _, field := range fields {
		if raw, exists := d[field]; exists {
			value, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("malformed regional secret metadata")
			}
			if strings.HasSuffix(field, "Time") && value != "" {
				if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
					return nil, fmt.Errorf("malformed regional secret timestamp")
				}
			}
			clean[field] = value
		}
	}
	if version && Str(clean["state"]) == "" {
		return nil, fmt.Errorf("missing regional secret version state")
	}
	for section, subfields := range map[string][]string{"rotation": {"nextRotationTime", "rotationPeriod"}, "customerManagedEncryption": {"kmsKeyName"}, "policyMember": {"iamPolicyUidPrincipal", "iamPolicyNamePrincipal"}} {
		if version {
			if section == "rotation" || section == "policyMember" {
				continue
			}
			subfields = []string{"kmsKeyVersionName"}
		}
		if raw, exists := d[section]; exists {
			sub := Obj(raw)
			if sub == nil {
				return nil, fmt.Errorf("malformed regional secret metadata section")
			}
			projected := Object{}
			for _, field := range subfields {
				if raw, exists := sub[field]; exists {
					value, ok := raw.(string)
					if !ok {
						return nil, fmt.Errorf("malformed regional secret metadata value")
					}
					if field == "nextRotationTime" && value != "" {
						if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
							return nil, fmt.Errorf("malformed regional secret rotation time")
						}
					}
					projected[field] = value
				}
			}
			if section == "rotation" {
				if raw, exists := sub["managedRotationStatus"]; exists {
					status := Obj(raw)
					if status == nil {
						return nil, fmt.Errorf("malformed regional secret managed rotation status")
					}
					// Status.error can carry unstructured service messages/details;
					// only the documented state is requested and retained.
					retained := Object{}
					if raw, exists := status["state"]; exists {
						state, ok := raw.(string)
						if !ok {
							return nil, fmt.Errorf("malformed regional secret managed rotation state")
						}
						retained["state"] = state
					}
					projected["managedRotationStatus"] = retained
				}
			}
			clean[section] = projected
		}
	}
	if !version {
		if raw, exists := d["versionAliases"]; exists {
			aliases := Obj(raw)
			if aliases == nil || len(aliases) > 50 {
				return nil, fmt.Errorf("malformed regional secret aliases")
			}
			retained := Object{}
			for alias, value := range aliases {
				text, ok := value.(string)
				id, err := strconv.ParseInt(text, 10, 64)
				if !ok || err != nil || id <= 0 || strconv.FormatInt(id, 10) != text || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,62}$`).MatchString(alias) || strings.EqualFold(alias, "latest") || strings.EqualFold(alias, "new") {
					return nil, fmt.Errorf("malformed regional secret alias mapping")
				}
				retained[alias] = text
			}
			clean["versionAliases"] = retained
		}
		if _, exists := d["topics"]; exists {
			rows, err := viewerRows(d, "topics")
			if err != nil {
				return nil, err
			}
			topics := []any{}
			for _, raw := range rows {
				topic := Obj(raw)
				if Str(topic["name"]) == "" {
					return nil, fmt.Errorf("malformed regional secret notification topic")
				}
				topics = append(topics, Object{"name": topic["name"]})
			}
			clean["topics"] = topics
		}
	}
	return clean, nil
}
