package inventory

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

const viewerAPIGatewayConfigFields = "name,createTime,updateTime,state,gatewayServiceAccount,serviceConfigId"
const viewerAPIGatewayFullFields = viewerAPIGatewayConfigFields + ",openapiDocuments(document(contents,path)),grpcServices(fileDescriptorSet(path),source(path)),managedServiceConfigs(path)"

// CollectViewerAPIGateway reads control-plane configuration. OpenAPI source is
// parsed transiently into a safe auth summary; no source bytes are persisted.
func (c *Client) CollectViewerAPIGateway(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-apigateway:identity", 0, fmt.Errorf("invalid API Gateway project identity"))
		return
	}
	base := "projects/" + projectID
	apis := c.viewerAPIGatewayList(ctx, out, projectID, number, base+"/locations/global", "apis", "Api", "name,createTime,updateTime,state,managedService")
	for _, api := range apis {
		configs := c.viewerAPIGatewayList(ctx, out, projectID, number, api, "configs", "ApiConfig", viewerAPIGatewayConfigFields)
		for _, config := range configs {
			raw, err := c.get(ctx, "https://apigateway.googleapis.com/v1/"+config, url.Values{"view": {"FULL"}, "fields": {viewerAPIGatewayFullFields}})
			var clean Object
			if err == nil {
				var name string
				clean, name, err = viewerAPIGatewayProjection(raw, projectID, number, "ApiConfig")
				if err == nil && name != config {
					err = fmt.Errorf("mismatched API Gateway config detail identity")
				}
			}
			if err == nil {
				derived, parseErr := projectAPIGatewayAuth(raw)
				c.SecretCapture.captureOpenAPI("//apigateway.googleapis.com/"+config, raw)
				if derived != nil {
					clean["_gcpbusterAuth"] = derived
				}
				candidates, secretErr := projectAPIGatewaySecrets(raw)
				if len(candidates) > 0 {
					clean["_gcpbusterSecretCandidates"] = candidates
				}
				for i := range out.Assets {
					if out.Assets[i].Type == "apigateway.googleapis.com/ApiConfig" && out.Assets[i].Name == "//apigateway.googleapis.com/"+config {
						out.Assets[i].Resource.Data = clean
						break
					}
				}
				err = errors.Join(parseErr, secretErr)
			}
			count := 0
			if err == nil {
				count = 1
			}
			out.record("viewer-apigateway:config-auth:"+config, count, err)
		}
	}
	locations := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://apigateway.googleapis.com/v1/"+base+"/locations", url.Values{"pageSize": {"100"}, "fields": {"locations(name,locationId),nextPageToken"}}, func(page Object) error {
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
			if v, exists := d["locationId"]; exists && Str(v) != p[3] {
				partial = true
				continue
			}
			if p[3] != "global" {
				locations[p[3]] = true
			}
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some API Gateway locations were malformed or unavailable")
	}
	out.record("viewer-apigateway:locations:"+projectID, len(locations), err)
	names := []string{}
	for name := range locations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, location := range names {
		c.viewerAPIGatewayList(ctx, out, projectID, number, base+"/locations/"+location, "gateways", "Gateway", "name,createTime,updateTime,state,apiConfig,defaultHostname")
	}
	correlateAPIGatewayDeployments(out, projectID, number)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-apigateway:limitations:" + projectID, Status: "notice", Error: "API/config metadata and gateways in discovered locations only. OpenAPI config source is parsed transiently into safe auth evidence; raw source and document paths are discarded. Unsupported source forms or denied config reads are explicit failures. No backend invocation, URL following, compiled Service Management reads, payload operations or credential-value API calls occur; no gateway/config mutation is performed. Direct IAM and effective deployed backend authorization are not resolved."})
}

func (c *Client) viewerAPIGatewayList(ctx context.Context, out *Snapshot, projectID, number, parent, collection, kind, fields string) []string {
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	names := []string{}
	responseKey := collection
	if collection == "configs" {
		responseKey = "apiConfigs"
	}
	err := c.viewerPages(ctx, "https://apigateway.googleapis.com/v1/"+parent+"/"+collection, url.Values{"pageSize": {"100"}, "fields": {responseKey + "(" + fields + "),nextPageToken,unreachableLocations"}}, func(page Object) error {
		rows, err := viewerRows(page, responseKey)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			clean, name, err := viewerAPIGatewayProjection(Obj(raw), projectID, number, kind)
			if err != nil || !strings.HasPrefix(name, parent+"/"+collection+"/") {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
			a := NewAsset("//apigateway.googleapis.com/"+name, "apigateway.googleapis.com/"+kind, clean)
			a.Ancestors = []string{number}
			a.Resource.Location = strings.Split(name, "/")[3]
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some API Gateway metadata was malformed or unavailable")
	}
	out.record("viewer-apigateway:"+collection+":"+parent, len(out.Assets)-start, err)
	return names
}

func viewerAPIGatewayProjection(d Object, projectID, number, kind string) (Object, string, error) {
	bad := func() (Object, string, error) { return nil, "", fmt.Errorf("invalid API Gateway metadata or scope") }
	p := strings.Split(Str(d["name"]), "/")
	want := 6
	if kind == "ApiConfig" {
		want = 8
	}
	if len(p) != want || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) {
		return bad()
	}
	if kind == "Gateway" {
		if p[3] == "global" || p[4] != "gateways" {
			return bad()
		}
	} else {
		if p[3] != "global" || p[4] != "apis" {
			return bad()
		}
	}
	if !viewerComputeDiskID.MatchString(p[5]) {
		return bad()
	}
	if kind == "ApiConfig" && (p[6] != "configs" || !viewerComputeDiskID.MatchString(p[7])) {
		return bad()
	}
	p[1] = projectID
	name := strings.Join(p, "/")
	clean := Object{"name": name}
	fields := []string{"state", "createTime", "updateTime"}
	switch kind {
	case "Api":
		fields = append(fields, "managedService")
	case "ApiConfig":
		fields = append(fields, "gatewayServiceAccount", "serviceConfigId")
	case "Gateway":
		fields = append(fields, "apiConfig", "defaultHostname")
	}
	for _, field := range fields {
		if raw, exists := d[field]; exists {
			v, ok := raw.(string)
			if !ok {
				return bad()
			}
			if strings.HasSuffix(field, "Time") {
				if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
					return bad()
				}
			}
			clean[field] = v
		}
	}
	return clean, name, nil
}
