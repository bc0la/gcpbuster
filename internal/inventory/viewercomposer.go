package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const viewerComposerType = "composer.googleapis.com/Environment"
const viewerComposerFields = "name,state,config(dagGcsPrefix,airflowUri,gkeCluster,softwareConfig(imageVersion,envVariables,airflowConfigOverrides,pypiPackages),nodeConfig(serviceAccount,network,subnetwork,oauthScopes),privateEnvironmentConfig(enablePrivateEnvironment,enablePrivateBuildsOnly,networkingType),webServerNetworkAccessControl(allowedIpRanges(value,description)))"

var viewerComposerID = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,62}[a-z0-9])?$`)

// CollectViewerComposer discovers names/locations from project-scoped CAI
// search, then reads current environment configuration. Composer v1 exposes no
// locations.list method or documented all-locations environments.list wildcard.
// Indexed discovery is explicitly incomplete, never an exhaustive region scan.
func (c *Client) CollectViewerComposer(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-composer:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://cloudasset.googleapis.com/v1/"+number+":searchAllResources", url.Values{"assetTypes": {viewerComposerType}, "pageSize": {"500"}, "readMask": {"name,assetType,project,location"}}, func(page Object) error {
		rows, err := viewerRows(page, "results")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			fullName := Str(d["name"])
			name, region, err := viewerComposerName(strings.TrimPrefix(fullName, "//composer.googleapis.com/"), projectID, number)
			locationOK := true
			if raw, exists := d["location"]; exists {
				location, ok := raw.(string)
				locationOK = ok && (location == "" || location == region)
			}
			if err != nil || !strings.HasPrefix(fullName, "//composer.googleapis.com/") || Str(d["assetType"]) != viewerComposerType || Str(d["project"]) != number || !locationOK {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			metadata, readErr := c.get(ctx, "https://composer.googleapis.com/v1/"+name, url.Values{"fields": {viewerComposerFields}})
			var clean Object
			if readErr == nil {
				var actual string
				actual, _, readErr = viewerComposerName(Str(metadata["name"]), projectID, number)
				if readErr == nil && actual != name {
					readErr = fmt.Errorf("mismatched Composer environment identity")
				}
				if readErr == nil {
					clean, readErr = viewerComposerProjection(metadata)
				}
			}
			count := 0
			if readErr == nil {
				clean["name"] = name
				a := NewAsset("//composer.googleapis.com/"+name, viewerComposerType, clean)
				a.Ancestors = []string{number}
				a.Resource.Location = region
				c.SecretCapture.captureOther(a)
				out.Assets = append(out.Assets, a)
				count = 1
				if Obj(clean["config"]) == nil || Obj(Get(clean, "config", "softwareConfig")) == nil {
					out.Coverage = append(out.Coverage, Coverage{Source: "viewer-composer-config:" + name, Status: "incomplete", Error: "Environment configuration/software configuration omitted; plaintext configuration absence cannot be assessed."})
				}
			} else {
				partial = true
			}
			out.record("viewer-composer:"+name, count, readErr)
		}
		unreachable, err := viewerBuildWorkflowUnreachable(page)
		partial = partial || unreachable
		return err
	})
	if err == nil && partial {
		err = fmt.Errorf("some indexed Composer identities or detail reads were unavailable or malformed")
	}
	out.record("viewer-composer-discovery:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-composer-index:" + projectID, Status: "incomplete", Error: "Composer environments/locations are discovered only through eventually consistent Cloud Asset Inventory search, not an exhaustive region enumeration. Missing or recently changed environments may be absent; an empty index is not proof of no environments."}, Coverage{Source: "viewer-composer:limitations:" + projectID, Status: "notice", Error: "Selected environment metadata and software environment/Airflow overrides only. Airflow endpoints, commands, DAGs, storage objects, task outputs, user-workload secrets and effective runtime authorization are not accessed. Referenced buckets, clusters, URLs and identities are not followed."})
}

func viewerComposerName(name, projectID, number string) (string, string, error) {
	p := strings.Split(name, "/")
	if len(p) != 6 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[4] != "environments" || !viewerComposerID.MatchString(p[5]) {
		return "", "", fmt.Errorf("invalid or out-of-scope Composer environment identity")
	}
	p[1] = projectID
	return strings.Join(p, "/"), p[3], nil
}

func viewerComposerProjection(d Object) (Object, error) {
	clean := viewerConfigProjection(d, "name", "state")
	if state, exists := d["state"]; exists {
		if _, ok := state.(string); !ok {
			return nil, fmt.Errorf("malformed Composer environment state")
		}
	}
	if _, exists := d["config"]; !exists {
		return clean, nil
	}
	config := Obj(d["config"])
	if config == nil {
		return nil, fmt.Errorf("malformed Composer environment config")
	}
	cfg := Object{}
	for _, field := range []string{"dagGcsPrefix", "airflowUri", "gkeCluster"} {
		if value, exists := config[field]; exists {
			if _, ok := value.(string); !ok {
				return nil, fmt.Errorf("malformed Composer config reference")
			}
			cfg[field] = value
		}
	}
	for section, fields := range map[string][]string{
		"softwareConfig":                {"imageVersion", "envVariables", "airflowConfigOverrides", "pypiPackages"},
		"nodeConfig":                    {"serviceAccount", "network", "subnetwork", "oauthScopes"},
		"privateEnvironmentConfig":      {"enablePrivateEnvironment", "enablePrivateBuildsOnly", "networkingType"},
		"webServerNetworkAccessControl": {"allowedIpRanges"},
	} {
		if _, exists := config[section]; !exists {
			continue
		}
		sub := Obj(config[section])
		if sub == nil {
			return nil, fmt.Errorf("malformed Composer config section")
		}
		projected := Object{}
		for _, field := range fields {
			value, exists := sub[field]
			if !exists {
				continue
			}
			switch field {
			case "envVariables", "airflowConfigOverrides", "pypiPackages":
				values := Obj(value)
				if values == nil {
					return nil, fmt.Errorf("malformed Composer software configuration map")
				}
				for _, v := range values {
					if _, ok := v.(string); !ok {
						return nil, fmt.Errorf("malformed Composer software configuration value")
					}
				}
			case "oauthScopes":
				values, err := viewerRows(sub, field)
				if err != nil {
					return nil, err
				}
				for _, v := range values {
					if _, ok := v.(string); !ok {
						return nil, fmt.Errorf("malformed Composer OAuth scope")
					}
				}
			case "enablePrivateEnvironment", "enablePrivateBuildsOnly":
				if _, ok := value.(bool); !ok {
					return nil, fmt.Errorf("malformed Composer private environment setting")
				}
			case "allowedIpRanges":
				values, err := viewerRows(sub, field)
				if err != nil {
					return nil, err
				}
				ranges := []any{}
				for _, raw := range values {
					r := Obj(raw)
					if r == nil || Str(r["value"]) == "" {
						return nil, fmt.Errorf("malformed Composer network range")
					}
					if description, exists := r["description"]; exists {
						if _, ok := description.(string); !ok {
							return nil, fmt.Errorf("malformed Composer network description")
						}
					}
					ranges = append(ranges, viewerConfigProjection(r, "value", "description"))
				}
				value = ranges
			default:
				if _, ok := value.(string); !ok {
					return nil, fmt.Errorf("malformed Composer configuration value")
				}
			}
			projected[field] = value
		}
		cfg[section] = projected
	}
	clean["config"] = cfg
	return clean, nil
}
