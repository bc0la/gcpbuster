package inventory

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

const ServiceConfigType = "gcpbuster.googleapis.com/ServiceConfig"
const viewerServiceConfigFields = "name,id,producerProjectId,apis(name,methods(name)),authentication(rules(selector,oauth,allowWithoutCredential,requirements(providerId)),providers(id,issuer)),usage(rules(selector,allowUnregisteredCalls,skipServiceControl)),backend(rules(selector,address,jwtAudience,disableAuth))"

var viewerManagedServiceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
var viewerManagedConfigID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

// CollectViewerServiceManagement limits discovery to producer-owned services.
// Compiled config bodies are transient inputs to safe projections; original
// SourceInfo files, backend URLs and arbitrary config values are not persisted.
func (c *Client) CollectViewerServiceManagement(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-service-management:identity", 0, fmt.Errorf("invalid producer project identity"))
		return
	}
	partial := false
	services := []string{}
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://servicemanagement.googleapis.com/v1/services", url.Values{"producerProjectId": {projectID}, "pageSize": {"100"}, "fields": {"services(serviceName,producerProjectId),nextPageToken"}}, func(page Object) error {
		rows, err := viewerRows(page, "services")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["serviceName"])
			if len(name) > 253 || !viewerManagedServiceName.MatchString(name) {
				partial = true
				continue
			}
			if p, exists := d["producerProjectId"]; exists && p != projectID {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			services = append(services, name)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some producer service names were malformed or out of scope")
	}
	out.record("viewer-service-management:list:"+projectID, len(services), err)
	for _, service := range services {
		endpoint := "https://servicemanagement.googleapis.com/v1/services/" + service
		d, err := c.get(ctx, endpoint, url.Values{"fields": {"serviceName,producerProjectId"}})
		if err == nil && (Str(d["serviceName"]) != service || Str(d["producerProjectId"]) != projectID) {
			err = fmt.Errorf("service producer identity was not confirmed")
		}
		count := 0
		if err == nil {
			count = 1
		}
		out.record("viewer-service-management:producer:"+service, count, err)
		if err != nil {
			continue
		}
		a := NewAsset("//servicemanagement.googleapis.com/services/"+service, "servicemanagement.googleapis.com/ManagedService", Object{"serviceName": service, "producerProjectId": projectID})
		a.Ancestors = []string{number}
		out.Assets = append(out.Assets, a)
		c.viewerManagedServiceConfigs(ctx, out, projectID, number, service)
		c.viewerManagedServiceRollouts(ctx, out, projectID, number, service)
	}
	correlateServiceGatewayPins(out, projectID, number)
	correlateServiceRolloutHistory(out, projectID)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-service-management:limitations:" + projectID, Status: "notice", Error: "Configuration history for services with confirmed producer ownership only. BASIC includes compiled configuration, but excludes original SourceInfo files. Only selected API method, authentication, usage and backend fields are inspected; HTTP annotations, original source files and other unselected fields are outside secret-scan coverage. Safe derived auth and secret-candidate metadata only is retained; backend URLs, provider values, method names and raw config source are discarded. Config versions may be historical or undeployed; no rollout/deployment, backend access or effective authorization is established. No service checks, reports, token generation, mutations or URL following occurs."})
}

func (c *Client) viewerManagedServiceConfigs(ctx context.Context, out *Snapshot, projectID, number, service string) {
	endpoint := "https://servicemanagement.googleapis.com/v1/services/" + service + "/configs"
	ids := []string{}
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, endpoint, url.Values{"pageSize": {"100"}, "fields": {"serviceConfigs(name,id,producerProjectId),nextPageToken"}}, func(page Object) error {
		rows, err := viewerRows(page, "serviceConfigs")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id := Str(d["id"])
			if !viewerManagedConfigID.MatchString(id) {
				partial = true
				continue
			}
			if name, exists := d["name"]; exists && name != service {
				partial = true
				continue
			}
			if producer, exists := d["producerProjectId"]; exists && producer != projectID {
				partial = true
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some service config identities were malformed or out of scope")
	}
	out.record("viewer-service-management:configs:"+service, len(ids), err)
	for _, id := range ids {
		clean := Object{"name": service, "id": id, "producerProjectId": projectID}
		raw, err := c.get(ctx, endpoint+"/"+id, url.Values{"view": {"BASIC"}, "fields": {viewerServiceConfigFields}})
		if err == nil {
			if Str(raw["name"]) != service || Str(raw["id"]) != id {
				err = fmt.Errorf("mismatched compiled service config identity")
			}
			if producer, exists := raw["producerProjectId"]; exists && producer != projectID {
				err = fmt.Errorf("mismatched compiled config producer")
			}
		}
		if err == nil {
			auth, authErr := projectServiceManagementAuth(raw)
			c.SecretCapture.captureServiceConfig("//servicemanagement.googleapis.com/services/"+service+"/configs/"+id, raw)
			if auth != nil {
				clean["_gcpbusterServiceAuth"] = auth
			}
			candidates, secretErr := projectServiceManagementSecrets(raw)
			if len(candidates) > 0 {
				clean["_gcpbusterSecretCandidates"] = candidates
			}
			err = errors.Join(authErr, secretErr)
		}
		a := NewAsset("//servicemanagement.googleapis.com/services/"+service+"/configs/"+id, ServiceConfigType, clean)
		a.Ancestors = []string{number}
		out.Assets = append(out.Assets, a)
		count := 0
		if err == nil {
			count = 1
		}
		out.record("viewer-service-management:config:"+service+":"+id, count, err)
	}
}
