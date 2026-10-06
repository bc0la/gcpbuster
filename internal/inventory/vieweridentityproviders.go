package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const IdentityPlatformOIDCProviderType = "gcpbuster.googleapis.com/IdentityPlatformOIDCProvider"
const IdentityPlatformSAMLProviderType = "gcpbuster.googleapis.com/IdentityPlatformSAMLProvider"
const viewerOIDCFields = "oauthIdpConfigs(name,enabled,responseType(code,idToken,token)),nextPageToken"
const viewerSAMLFields = "inboundSamlConfigs(name,enabled),nextPageToken"

var viewerIdentityProviderID = regexp.MustCompile(`^(oidc|saml)\.[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$`)

// CollectViewerIdentityProviders selects non-secret configuration only. The
// documented getSecret permission is conditional on requesting secret data;
// it is neither needed nor granted here. Issuers and credentials are not read.
func (c *Client) CollectViewerIdentityProviders(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-identity-providers:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := map[string]bool{number: true}
	for _, a := range out.Assets {
		if a.Type != "identitytoolkit.googleapis.com/Tenant" {
			continue
		}
		n, e := viewerIdentityName(strings.TrimPrefix(a.Name, "//identitytoolkit.googleapis.com/"), projectID, number, "Tenant")
		if e == nil && strings.HasPrefix(a.Name, "//identitytoolkit.googleapis.com/") {
			parents[n] = true
		}
	}
	ordered := []string{}
	for p := range parents {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	for _, p := range ordered {
		for _, kind := range []string{"oauthIdpConfigs", "inboundSamlConfigs"} {
			c.viewerIdentityProviders(ctx, out, projectID, number, p, kind)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-identity-providers:limitations:" + number, Status: "notice", Error: "Only selected provider configuration for the project and observed tenants is read. Missing flags/providers are unknown, not disabled. Issuers, client IDs, secrets, certificates, users and application authentication are not accessed; configuration does not establish application or data access."})
}

func (c *Client) viewerIdentityProviders(ctx context.Context, out *Snapshot, projectID, number, parent, kind string) {
	fields, typ, prefix := viewerOIDCFields, IdentityPlatformOIDCProviderType, "oidc."
	if kind == "inboundSamlConfigs" {
		fields, typ, prefix = viewerSAMLFields, IdentityPlatformSAMLProviderType, "saml."
	}
	count, partial := 0, false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://identitytoolkit.googleapis.com/v2/"+parent+"/"+kind, url.Values{"fields": {fields}, "pageSize": {"100"}}, func(page Object) error {
		rows, e := viewerRows(page, kind)
		if e != nil {
			return e
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if strings.HasPrefix(name, "projects/"+projectID+"/") {
				name = number + strings.TrimPrefix(name, "projects/"+projectID)
			}
			id := strings.TrimPrefix(name, parent+"/"+kind+"/")
			if !strings.HasPrefix(name, parent+"/"+kind+"/") || !viewerIdentityProviderID.MatchString(id) || !strings.HasPrefix(id, prefix) || seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			clean := Object{"name": name}
			valid := true
			if v, ok := d["enabled"]; ok {
				if b, ok := v.(bool); ok {
					clean["enabled"] = b
				} else {
					valid = false
				}
			}
			if kind == "oauthIdpConfigs" {
				if v, ok := d["responseType"]; ok {
					r, ok := v.(map[string]any)
					if !ok {
						valid = false
					} else {
						safe := Object{}
						for _, k := range []string{"code", "idToken", "token"} {
							if v, exists := r[k]; exists {
								if b, ok := v.(bool); ok {
									safe[k] = b
								} else {
									valid = false
								}
							}
						}
						if Bool(safe["code"]) && Bool(safe["idToken"]) || Bool(safe["token"]) {
							valid = false
						}
						if valid {
							clean["responseType"] = safe
						}
					}
				}
			}
			if !valid {
				clean["projection_complete"] = false
				partial = true
			}
			a := NewAsset("//identitytoolkit.googleapis.com/"+name, typ, clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
			count++
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some provider identities or typed configuration fields were malformed or duplicated")
	}
	out.record("viewer-identity-providers:"+parent+":"+kind, count, err)
}
