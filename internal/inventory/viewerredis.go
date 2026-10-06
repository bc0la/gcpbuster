package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

const viewerRedisInstanceFields = "instances(name,state,authEnabled,transitEncryptionMode,authorizedNetwork,connectMode,tier,persistenceConfig(persistenceMode)),nextPageToken,unreachable"
const viewerRedisClusterFields = "clusters(name,state,authorizationMode,transitEncryptionMode,pscConfigs(network),persistenceConfig(mode)),nextPageToken,unreachable"

// Both v1 list methods document '-' as all project regions. No endpoints are
// contacted and no auth strings, ACL tokens or Redis commands are requested.
func (c *Client) CollectViewerRedis(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-redis:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-redis:limitations:" + projectID, Status: "notice", Error: "Selected current configuration only. Auth strings, token-auth users, ACL contents, backup contents, history, Redis commands and network access are not read or tested. Referenced networks are not followed; omitted metadata is not proof of security."})
	for _, spec := range []struct{ collection, kind, fields string }{{"instances", "Instance", viewerRedisInstanceFields}, {"clusters", "Cluster", viewerRedisClusterFields}} {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://redis.googleapis.com/v1/projects/"+projectID+"/locations/-/"+spec.collection, url.Values{"pageSize": {"100"}, "fields": {spec.fields}}, func(page Object) error {
			if v, exists := page["unreachable"]; exists {
				rows, ok := v.([]any)
				if !ok || len(rows) > 0 {
					partial = true
				}
			}
			rows, err := viewerRows(page, spec.collection)
			if err != nil {
				return err
			}
			for _, r := range rows {
				clean, valid := viewerRedisProjection(Obj(r), projectID, number, spec.collection)
				if !valid {
					partial = true
				}
				if clean == nil {
					continue
				}
				name := Str(clean["name"])
				if seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				a := NewAsset("//redis.googleapis.com/"+name, "redis.googleapis.com/"+spec.kind, clean)
				a.Ancestors = []string{number}
				a.Resource.Location = strings.Split(name, "/")[3]
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some Redis metadata was malformed, duplicated, foreign or in unreachable locations")
		}
		out.record("viewer-redis-"+spec.collection+":"+projectID, len(out.Assets)-start, err)
	}
}

func viewerRedisProjection(d Object, projectID, number, collection string) (Object, bool) {
	parts := strings.Split(Str(d["name"]), "/")
	if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && "projects/"+parts[1] != number) || parts[2] != "locations" || !viewerLocation.MatchString(parts[3]) || parts[3] == "global" || parts[4] != collection || !viewerDNSZoneName.MatchString(parts[5]) {
		return nil, false
	}
	parts[1] = projectID
	clean := Object{"name": strings.Join(parts, "/")}
	valid := true
	enums := map[string][]string{}
	persistenceField := "persistenceMode"
	persistenceEnums := []string{"PERSISTENCE_MODE_UNSPECIFIED", "DISABLED", "RDB"}
	if collection == "instances" {
		enums["state"] = []string{"STATE_UNSPECIFIED", "CREATING", "READY", "UPDATING", "DELETING", "REPAIRING", "MAINTENANCE", "IMPORTING", "FAILING_OVER"}
		enums["transitEncryptionMode"] = []string{"TRANSIT_ENCRYPTION_MODE_UNSPECIFIED", "SERVER_AUTHENTICATION", "DISABLED"}
		enums["tier"] = []string{"TIER_UNSPECIFIED", "BASIC", "STANDARD_HA"}
		enums["connectMode"] = []string{"CONNECT_MODE_UNSPECIFIED", "DIRECT_PEERING", "PRIVATE_SERVICE_ACCESS"}
		if v, exists := d["authEnabled"]; exists {
			b, ok := v.(bool)
			if ok {
				clean["authEnabled"] = b
			} else {
				valid = false
			}
		}
	} else {
		enums["state"] = []string{"STATE_UNSPECIFIED", "CREATING", "ACTIVE", "UPDATING", "DELETING"}
		enums["authorizationMode"] = []string{"AUTH_MODE_UNSPECIFIED", "AUTH_MODE_IAM_AUTH", "AUTH_MODE_DISABLED", "AUTH_MODE_TOKEN_AUTH"}
		enums["transitEncryptionMode"] = []string{"TRANSIT_ENCRYPTION_MODE_UNSPECIFIED", "TRANSIT_ENCRYPTION_MODE_DISABLED", "TRANSIT_ENCRYPTION_MODE_SERVER_AUTHENTICATION"}
		persistenceField = "mode"
		persistenceEnums = append(persistenceEnums, "AOF")
	}
	enum := func(value any, allowed []string) (string, bool) {
		s, ok := value.(string)
		if !ok {
			return "", false
		}
		for _, candidate := range allowed {
			if s == candidate {
				return s, true
			}
		}
		return "", false
	}
	for field, allowed := range enums {
		if v, exists := d[field]; exists {
			s, ok := enum(v, allowed)
			if ok {
				clean[field] = s
			} else {
				valid = false
			}
		}
	}
	if v, exists := d["persistenceConfig"]; exists {
		cfg := Obj(v)
		if cfg == nil {
			valid = false
		} else if value, exists := cfg[persistenceField]; exists {
			s, ok := enum(value, persistenceEnums)
			if ok {
				clean["persistenceConfig"] = Object{persistenceField: s}
			} else {
				valid = false
			}
		} else {
			clean["persistenceConfig"] = Object{}
		}
	}
	network := func(v any) (string, bool) {
		s, ok := v.(string)
		if !ok {
			return "", false
		}
		s = strings.TrimPrefix(s, "https://www.googleapis.com/compute/v1/")
		return s, viewerDNSNetworkRef.MatchString(s)
	}
	if collection == "instances" {
		if v, exists := d["authorizedNetwork"]; exists {
			s, ok := network(v)
			if ok {
				clean["authorizedNetwork"] = s
			} else {
				valid = false
			}
		}
	} else if v, exists := d["pscConfigs"]; exists {
		rows, ok := v.([]any)
		if !ok {
			valid = false
		} else {
			nets := []any{}
			for _, r := range rows {
				s, ok := network(Obj(r)["network"])
				if !ok {
					valid = false
					continue
				}
				nets = append(nets, Object{"network": s})
			}
			clean["pscConfigs"] = nets
		}
	}
	return clean, valid
}
