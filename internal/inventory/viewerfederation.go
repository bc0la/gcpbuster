package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// CollectViewerFederation reads project-scoped workload federation metadata.
// The IAM API documents global as the only supported pool location. It does
// not contact issuers, retrieve provider keys, exchange tokens, or inspect
// organization-scoped workforce pools.
func (c *Client) CollectViewerFederation(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-federation:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	pools := []string{}
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://iam.googleapis.com/v1/"+number+"/locations/global/workloadIdentityPools", url.Values{"pageSize": {"100"}, "fields": {"workloadIdentityPools(name,state,disabled,mode,displayName,description),nextPageToken"}}, func(page Object) error {
		rows, err := viewerRows(page, "workloadIdentityPools")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id, err := viewerBuildWorkflowName(Str(d["name"]), projectID, number, "global", "workloadIdentityPools")
			if err != nil {
				return err
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			a := NewAsset("//iam.googleapis.com/projects/"+projectID+"/locations/global/workloadIdentityPools/"+id, "iam.googleapis.com/WorkloadIdentityPool", viewerConfigProjection(d, "name", "state", "disabled", "mode", "displayName", "description"))
			a.Ancestors = []string{number}
			a.Resource.Location = "global"
			out.Assets = append(out.Assets, a)
			active, valid := viewerFederationState(d)
			if !valid {
				partial = true
				continue
			}
			mode, ok := d["mode"].(string)
			if _, exists := d["mode"]; exists && !ok {
				partial = true
				continue
			}
			switch mode {
			case "", "MODE_UNSPECIFIED", "FEDERATION_ONLY":
			case "TRUST_DOMAIN", "SYSTEM_TRUST_DOMAIN":
				active = false
			default:
				partial = true
				continue
			}
			if active {
				pools = append(pools, id)
			} else {
				out.Coverage = append(out.Coverage, Coverage{Source: "viewer-federation:providers:" + id, Status: "notice", Error: "Inactive or managed-identity-only parent pool: active federation provider posture was not assessed."})
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("pool state or mode is missing, malformed, or unknown; affected provider posture was not assessed")
	}
	out.record("viewer-federation:pools:"+projectID, len(out.Assets)-start, err)
	for _, pool := range pools {
		c.viewerFederationProviders(ctx, out, projectID, number, pool)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-federation:limitations:" + projectID, Status: "notice", Error: "Project workload federation only; workforce pools, provider keys/certificates, external issuers and token exchange were not inspected. SAML and X.509 trust details are unassessed; these provider types are omitted from posture evaluation without fetching key material. Exact API-documented permission names must occur in the three allowed role definitions; service-qualified spellings are not assumed aliases."})
}

// Proto3 omission of disabled means false, but omission of the state enum does
// not prove ACTIVE. Never feed unknown-state providers to posture evaluators.
func viewerFederationState(d Object) (active, valid bool) {
	disabled := false
	if raw, exists := d["disabled"]; exists {
		var ok bool
		disabled, ok = raw.(bool)
		if !ok {
			return false, false
		}
	}
	switch Str(d["state"]) {
	case "ACTIVE":
		return !disabled, true
	case "DELETED":
		return false, true
	default:
		return false, false
	}
}

func (c *Client) viewerFederationProviders(ctx context.Context, out *Snapshot, projectID, number, pool string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	parent := number + "/locations/global/workloadIdentityPools/" + pool
	err := c.viewerPages(ctx, "https://iam.googleapis.com/v1/"+parent+"/providers", url.Values{"pageSize": {"100"}, "fields": {"workloadIdentityPoolProviders(name,state,disabled,displayName,description,attributeCondition,attributeMapping,aws(accountId),oidc(issuerUri,allowedAudiences)),nextPageToken"}}, func(page Object) error {
		rows, err := viewerRows(page, "workloadIdentityPoolProviders")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 8 || parts[6] != "providers" || !viewerResourceName.MatchString(parts[7]) {
				return fmt.Errorf("invalid federation provider identity")
			}
			id, err := viewerBuildWorkflowName(strings.Join(parts[:6], "/"), projectID, number, "global", "workloadIdentityPools")
			if err != nil || id != pool {
				return fmt.Errorf("out-of-scope federation provider")
			}
			if seen[parts[7]] {
				continue
			}
			seen[parts[7]] = true
			if _, valid := viewerFederationState(d); !valid {
				partial = true
				continue
			}
			if condition, exists := d["attributeCondition"]; exists {
				if _, ok := condition.(string); !ok {
					partial = true
					continue
				}
			}
			if mapping, exists := d["attributeMapping"]; exists {
				m := Obj(mapping)
				valid := m != nil
				for _, v := range m {
					if _, ok := v.(string); !ok {
						valid = false
					}
				}
				if !valid {
					partial = true
					continue
				}
			}
			clean := viewerConfigProjection(d, "name", "state", "disabled", "displayName", "description", "attributeCondition", "attributeMapping")
			kind, config, valid := viewerFederationProviderConfig(d)
			if !valid {
				partial = true
				continue
			}
			clean[kind] = config
			a := NewAsset("//iam.googleapis.com/projects/"+projectID+"/locations/global/workloadIdentityPools/"+pool+"/providers/"+parts[7], "iam.googleapis.com/WorkloadIdentityPoolProvider", clean)
			a.Ancestors = []string{number}
			a.Resource.Location = "global"
			out.Assets = append(out.Assets, a)
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("provider state or configuration is missing, malformed, or unknown; affected provider posture was not assessed")
	}
	out.record("viewer-federation:providers:"+parent, len(out.Assets)-start, err)
}

// Only the AWS/OIDC union alternatives have sufficient non-key metadata in
// this collector's field mask. Unsupported, missing, or conflicting types must
// not become generic missing-condition findings.
func viewerFederationProviderConfig(d Object) (string, Object, bool) {
	kind, count := "", 0
	for _, candidate := range []string{"aws", "oidc", "saml", "x509"} {
		if _, exists := d[candidate]; exists {
			kind = candidate
			count++
		}
	}
	if count != 1 || (kind != "aws" && kind != "oidc") {
		return "", nil, false
	}
	config := Obj(d[kind])
	field := "accountId"
	if kind == "oidc" {
		field = "issuerUri"
	}
	if strings.TrimSpace(Str(config[field])) == "" {
		return "", nil, false
	}
	fields := []string{field}
	if kind == "oidc" {
		fields = append(fields, "allowedAudiences")
		if raw, exists := config["allowedAudiences"]; exists {
			audiences, ok := raw.([]any)
			if !ok {
				return "", nil, false
			}
			for _, audience := range audiences {
				if strings.TrimSpace(Str(audience)) == "" {
					return "", nil, false
				}
			}
		}
	}
	return kind, viewerConfigProjection(config, fields...), true
}
