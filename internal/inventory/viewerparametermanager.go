package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const parameterLocationsFields = "locations(name,locationId),nextPageToken"
const parameterListFields = "parameters(name,format,policyMember(iamPolicyUidPrincipal,iamPolicyNamePrincipal),kmsKey),nextPageToken,unreachable"
const parameterVersionsFields = "parameterVersions(name,disabled),nextPageToken,unreachable"
const parameterFullFields = "name,disabled,payload(data)"

var parameterPath = regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/([a-z][a-z0-9-]*)/parameters(?:/[A-Za-z0-9_-]+/versions(?:/[A-Za-z0-9_-]+)?)?$`)

// Raw parameter configuration is Viewer-readable. Rendering references to
// Secret Manager is a different permission and is deliberately never invoked.
func (c *Client) CollectViewerParameterManager(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("parameter-manager:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	regions := map[string]bool{"global": true}
	locations := c.parameterNames(ctx, out, "parametermanager.googleapis.com", number, "locations", "locations", parameterLocationsFields, projectID, number)
	for _, name := range locations {
		p := strings.Split(name, "/")
		if len(p) == 4 && viewerLocation.MatchString(p[3]) {
			regions[p[3]] = true
		}
	}
	requests := 0
	templateBudget := &secretCollectionBudget{}
	for _, region := range orderedViewerRegions(regions) {
		host := "parametermanager.googleapis.com"
		if region != "global" {
			host = "parametermanager." + region + ".rep.googleapis.com"
		}
		parent := number + "/locations/" + region
		if c.SecretCapture != nil {
			c.collectParameterTemplates(ctx, out, parent, region, projectID, number, templateBudget)
		}
		for _, parameter := range c.parameterNames(ctx, out, host, parent, "parameters", "parameters", parameterListFields, projectID, number) {
			if c.SecretCapture == nil {
				continue // Built-in identity metadata does not require raw capture.
			}
			for _, version := range c.parameterNames(ctx, out, host, parameter, "versions", "parameterVersions", parameterVersionsFields, projectID, number) {
				requests++
				if requests > 10000 {
					out.record("parameter-manager:limit", requests-1, fmt.Errorf("parameter version read limit reached"))
					return
				}
				raw, err := c.get(ctx, "https://"+host+"/v1/"+version, url.Values{"view": {"FULL"}, "fields": {parameterFullFields}})
				count := 0
				if err == nil {
					err = c.captureParameterVersion(raw, version, region, projectID, number)
					if err == nil {
						count = 1
					}
				}
				out.record("parameter-manager:version:"+version, count, err)
			}
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "parameter-manager:boundary:" + projectID, Status: "notice", Error: "Raw parameter version configuration only; disabled versions do not expose payloads. No render, Secret Manager dereference, template versions, mutations or credential validation. Regional inventory uses discovered locations; unavailable endpoints remain incomplete."})
}

func (c *Client) parameterNames(ctx context.Context, out *Snapshot, host, parent, collection, key, fields, projectID, number string) []string {
	names := []string{}
	seen := map[string]bool{}
	metadataIndices := map[string]int{}
	partial := false
	err := c.viewerPages(ctx, "https://"+host+"/v1/"+parent+"/"+collection, url.Values{"pageSize": {"100"}, "fields": {fields}}, func(page Object) error {
		rows, err := viewerRows(page, key)
		if err != nil {
			return err
		}
		for _, row := range rows {
			d := Obj(row)
			name := parameterCanonicalName(Str(d["name"]), projectID, number)
			prefix := parent + "/" + collection + "/"
			id := strings.TrimPrefix(name, prefix)
			if !strings.HasPrefix(name, prefix) || !viewerKeyResourceID.MatchString(id) {
				partial = true
				continue
			}
			if collection == "locations" && (!viewerLocation.MatchString(id) || (d["locationId"] != nil && Str(d["locationId"]) != id)) {
				partial = true
				continue
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
				if collection == "parameters" {
					metadata := parameterMetadataProjection(d, name)
					asset := NewAsset("//parametermanager.googleapis.com/"+name, "parametermanager.googleapis.com/Parameter", metadata)
					asset.Ancestors = []string{number}
					asset.Resource.Location = strings.Split(name, "/")[3]
					out.Assets = append(out.Assets, asset)
					metadataIndices[name] = len(out.Assets) - 1
				}
			} else if collection == "parameters" {
				index := metadataIndices[name]
				previous, _ := json.Marshal(out.Assets[index].Resource.Data)
				current, _ := json.Marshal(parameterMetadataProjection(d, name))
				if string(previous) != string(current) {
					partial = true
					out.Assets[index].Resource.Data["policyMember"] = Object{}
					out.Assets[index].Resource.Data["identityMetadataConflict"] = true
				}
			}
			if len(names) >= 10000 {
				return fmt.Errorf("parameter discovery limit reached")
			}
		}
		inaccessible, e := viewerBuildWorkflowUnreachable(page)
		partial = partial || inaccessible
		return e
	})
	if err == nil && partial {
		err = fmt.Errorf("parameter discovery malformed or incomplete")
	}
	out.record("parameter-manager:list:"+parent+"/"+collection, len(names), err)
	return names
}

func parameterMetadataProjection(d Object, name string) Object {
	metadata := Object{"name": name}
	if format := Str(d["format"]); format == "JSON" || format == "YAML" || format == "UNFORMATTED" || format == "PARAMETER_FORMAT_UNSPECIFIED" {
		metadata["format"] = format
	}
	parts := strings.Split(name, "/")
	member := Object{}
	for _, field := range []string{"iamPolicyUidPrincipal", "iamPolicyNamePrincipal"} {
		principal := Str(Get(d, "policyMember", field))
		mode := "uid"
		if field == "iamPolicyNamePrincipal" {
			mode = "name"
		}
		prefix := "principal://parametermanager.googleapis.com/projects/" + parts[1] + "/" + mode + "/locations/" + parts[3] + "/parameters/"
		if strings.HasPrefix(principal, prefix) && viewerKeyResourceID.MatchString(strings.TrimPrefix(principal, prefix)) && (mode == "uid" || strings.TrimPrefix(principal, prefix) == parts[5]) {
			member[field] = principal
		}
	}
	metadata["policyMember"] = member
	if key := Str(d["kmsKey"]); regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`).MatchString(key) {
		metadata["kmsKey"] = key
	}
	return metadata
}
func parameterCanonicalName(name, projectID, number string) string {
	if strings.HasPrefix(name, "projects/"+projectID+"/") {
		return number + strings.TrimPrefix(name, "projects/"+projectID)
	}
	return name
}
func (c *Client) captureParameterVersion(raw Object, version, region, projectID, number string) error {
	if parameterCanonicalName(Str(raw["name"]), projectID, number) != version {
		return fmt.Errorf("parameter version identity mismatch")
	}
	if v, exists := raw["disabled"]; exists {
		disabled, ok := v.(bool)
		if !ok {
			return fmt.Errorf("invalid parameter disabled state")
		}
		if disabled {
			return nil
		}
	}
	encoded, ok := Get(raw, "payload", "data").(string)
	if !ok || len(encoded) > 6<<20 {
		return fmt.Errorf("parameter payload missing or oversized")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) > 4<<20 {
		return fmt.Errorf("invalid or oversized parameter payload")
	}
	if len(data) == 0 {
		return nil
	}
	if !c.SecretCapture.Add(SecretSample{SourceType: "parameter_manager_raw", Resource: "//parametermanager.googleapis.com/" + version, Location: region, Path: "payload.data", Data: data}) {
		return fmt.Errorf("parameter capture limit or conflict")
	}
	return nil
}

func parameterManagerPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	if regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/templates(?:/|$)`).MatchString(u.Path) {
		return parameterTemplatePermission(method, u, q)
	}
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed Parameter Manager request")
	}
	if method != "GET" || u.RawPath != "" {
		return fail()
	}
	permission, fields := "", ""
	if u.Host == "parametermanager.googleapis.com" && regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations$`).MatchString(u.Path) {
		permission = "locations.list"
		fields = parameterLocationsFields
	} else {
		m := parameterPath.FindStringSubmatch(u.Path)
		if m == nil {
			return fail()
		}
		host := "parametermanager.googleapis.com"
		if m[1] != "global" {
			host = "parametermanager." + m[1] + ".rep.googleapis.com"
		}
		if u.Host != host {
			return fail()
		}
		switch {
		case strings.HasSuffix(u.Path, "/parameters"):
			permission = "parameters.list"
			fields = parameterListFields
		case strings.HasSuffix(u.Path, "/versions"):
			permission = "parameterVersions.list"
			fields = parameterVersionsFields
		default:
			permission = "parameterVersions.get"
			fields = parameterFullFields
		}
	}
	if q.Get("fields") != fields {
		return fail()
	}
	for k, v := range q {
		if len(v) != 1 {
			return fail()
		}
		if k == "fields" {
			continue
		}
		if strings.HasSuffix(permission, ".get") {
			if k != "view" || v[0] != "FULL" {
				return fail()
			}
		} else if k != "pageToken" && (k != "pageSize" || v[0] != "100") {
			return fail()
		}
	}
	if strings.HasSuffix(permission, ".get") {
		if q.Get("view") != "FULL" {
			return fail()
		}
	} else if q.Get("pageSize") != "100" {
		return fail()
	}
	return []string{"parametermanager." + permission}, nil
}
