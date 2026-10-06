package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const secretAliasFields = "name,versionAliases"

var secretAliasGlobalPath = regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$`)
var secretAliasRegionalPath = regexp.MustCompile(`^/v1/projects/[A-Za-z0-9_-]+/locations/([a-z][a-z0-9-]*)/secrets/[A-Za-z0-9_-]+$`)

// Aliases are explicitly documented as GetSecret metadata. List responses may
// omit them; never infer absence from a list alone.
// https://github.com/googleapis/googleapis/blob/master/google/cloud/secretmanager/v1/resources.proto
func (c *Client) CollectViewerSecretAliases(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("secret-aliases:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	seen := map[string]bool{}
	count := 0
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != "secretmanager.googleapis.com/Secret" {
			continue
		}
		name := strings.TrimPrefix(a.Name, "//secretmanager.googleapis.com/")
		if name == a.Name || !strings.HasPrefix(name, number+"/") {
			continue
		}
		path := "/v1/" + name
		host := "secretmanager.googleapis.com"
		if m := secretAliasRegionalPath.FindStringSubmatch(path); m != nil {
			if m[1] == "global" {
				continue
			}
			host = "secretmanager." + m[1] + ".rep.googleapis.com"
		} else if !secretAliasGlobalPath.MatchString(path) {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		count++
		if count > 10000 {
			out.record("secret-aliases:limit", count-1, fmt.Errorf("secret alias detail limit reached"))
			return
		}
		raw, e := c.get(ctx, "https://"+host+path, url.Values{"fields": {secretAliasFields}})
		n := 0
		if e == nil {
			if parameterCanonicalName(Str(raw["name"]), projectID, number) != name {
				e = fmt.Errorf("secret alias response identity mismatch")
			} else {
				clean, err := viewerRegionalSecretProjection(Object{"versionAliases": raw["versionAliases"]}, false)
				if _, exists := raw["versionAliases"]; !exists {
					clean = Object{"versionAliases": Object{}}
					err = nil
				}
				e = err
				if e == nil {
					if a.Resource.Data == nil {
						a.Resource.Data = Object{}
					}
					a.Resource.Data["versionAliases"] = clean["versionAliases"]
					a.Resource.Data["gcpbusterAliasesObserved"] = true
					n = 1
				}
			}
		}
		out.record("secret-aliases:get:"+name, n, e)
	}
}

func secretAliasesPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed secret alias request")
	}
	if method != "GET" || u.RawPath != "" || q.Get("fields") != secretAliasFields || len(q) != 1 || len(q["fields"]) != 1 {
		return fail()
	}
	if secretAliasGlobalPath.MatchString(u.Path) && u.Host == "secretmanager.googleapis.com" {
		return []string{"secretmanager.secrets.get"}, nil
	}
	if m := secretAliasRegionalPath.FindStringSubmatch(u.Path); m != nil && m[1] != "global" && u.Host == "secretmanager."+m[1]+".rep.googleapis.com" {
		return []string{"secretmanager.secrets.get"}, nil
	}
	return fail()
}
