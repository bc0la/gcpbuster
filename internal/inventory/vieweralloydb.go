package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

const viewerAlloyDBClusterFields = "clusters(name,state,clusterType,networkConfig(network),pscConfig(pscEnabled)),nextPageToken,unreachable"
const viewerAlloyDBInstanceFields = "instances(name,state,instanceType,dataApiAccess,publicIpAddress,networkConfig(network,enablePublicIp,authorizedExternalNetworks(cidrRange)),clientConnectionConfig(requireConnectors,sslConfig(sslMode))),nextPageToken,unreachable"

// Documented wildcard list parents enumerate all project locations. Neither
// initialUser nor database flags/credentials/queries/node contents are read.
func (c *Client) CollectViewerAlloyDB(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-alloydb:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	for _, spec := range []struct{ path, collection, kind, fields string }{{"locations/-/clusters", "clusters", "Cluster", viewerAlloyDBClusterFields}, {"locations/-/clusters/-/instances", "instances", "Instance", viewerAlloyDBInstanceFields}} {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://alloydb.googleapis.com/v1/projects/"+projectID+"/"+spec.path, url.Values{"pageSize": {"100"}, "fields": {spec.fields}}, func(page Object) error {
			if v, exists := page["unreachable"]; exists {
				rows, ok := v.([]any)
				if !ok || len(rows) > 0 {
					partial = true
				}
			}
			rows, e := viewerRows(page, spec.collection)
			if e != nil {
				return e
			}
			for _, raw := range rows {
				clean, valid := viewerAlloyDBProjection(Obj(raw), projectID, number, spec.kind)
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
				a := NewAsset("//alloydb.googleapis.com/"+name, "alloydb.googleapis.com/"+spec.kind, clean)
				a.Ancestors = []string{number}
				a.Resource.Location = strings.Split(name, "/")[3]
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some AlloyDB metadata was malformed, duplicate, foreign or unreachable")
		}
		out.record("viewer-alloydb-"+spec.collection+":"+projectID, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-alloydb:limitations:" + projectID, Status: "notice", Error: "Selected current cluster and instance configuration only. No initial-user passwords, database queries, exports/imports, connection attempts, generated credentials, backup contents or node data. Public IP/Data API metadata does not establish effective reachability or database authorization."})
}

func viewerAlloyDBProjection(d Object, projectID, number, kind string) (Object, bool) {
	p := strings.Split(Str(d["name"]), "/")
	size := 6
	if kind == "Instance" {
		size = 8
	}
	if len(p) != size || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[3] == "global" || p[4] != "clusters" || !viewerDNSZoneName.MatchString(p[5]) {
		return nil, false
	}
	if size == 8 && (p[6] != "instances" || !viewerDNSZoneName.MatchString(p[7])) {
		return nil, false
	}
	p[1] = projectID
	clean := Object{"name": strings.Join(p, "/")}
	valid := true
	enum := func(source, target Object, field string, allowed string) {
		v, exists := source[field]
		if !exists {
			return
		}
		s, ok := v.(string)
		matched := false
		for _, candidate := range strings.Split(allowed, "|") {
			if s == candidate {
				matched = true
			}
		}
		if !ok || !matched || s == "" {
			valid = false
			return
		}
		target[field] = s
	}
	boolean := func(source, target Object, field string) {
		if v, exists := source[field]; exists {
			b, ok := v.(bool)
			if ok {
				target[field] = b
			} else {
				valid = false
			}
		}
	}
	states := "STATE_UNSPECIFIED|READY|STOPPED|CREATING|DELETING|FAILED|BOOTSTRAPPING|MAINTENANCE|PROMOTING|SWITCHOVER"
	if kind == "Cluster" {
		states += "|EMPTY"
	} else {
		states += "|STOPPING|STARTING"
	}
	enum(d, clean, "state", states)
	if kind == "Cluster" {
		enum(d, clean, "clusterType", "CLUSTER_TYPE_UNSPECIFIED|PRIMARY|SECONDARY")
		if v, exists := d["pscConfig"]; exists {
			cfg := Obj(v)
			if cfg == nil {
				valid = false
			} else {
				out := Object{}
				boolean(cfg, out, "pscEnabled")
				clean["pscConfig"] = out
			}
		}
	} else {
		enum(d, clean, "instanceType", "INSTANCE_TYPE_UNSPECIFIED|PRIMARY|READ_POOL|SECONDARY")
		enum(d, clean, "dataApiAccess", "DEFAULT_DATA_API_ENABLED_FOR_GOOGLE_CLOUD_SERVICES|DISABLED|ENABLED")
		if v, exists := d["publicIpAddress"]; exists {
			s, ok := v.(string)
			ip, e := netip.ParseAddr(s)
			if !ok || e != nil || ip.Zone() != "" || ip.Is4In6() {
				valid = false
			} else {
				clean["publicIpAddress"] = ip.String()
			}
		}
		if v, exists := d["clientConnectionConfig"]; exists {
			cfg := Obj(v)
			if cfg == nil {
				valid = false
			} else {
				out := Object{}
				boolean(cfg, out, "requireConnectors")
				if ssl, exists := cfg["sslConfig"]; exists {
					s := Obj(ssl)
					if s == nil {
						valid = false
					} else {
						o := Object{}
						enum(s, o, "sslMode", "SSL_MODE_UNSPECIFIED|SSL_MODE_ALLOW|SSL_MODE_REQUIRE|SSL_MODE_VERIFY_CA|ALLOW_UNENCRYPTED_AND_ENCRYPTED|ENCRYPTED_ONLY")
						out["sslConfig"] = o
					}
				}
				clean["clientConnectionConfig"] = out
			}
		}
	}
	if v, exists := d["networkConfig"]; exists {
		cfg := Obj(v)
		if cfg == nil {
			valid = false
		} else {
			out := Object{}
			if v, exists := cfg["network"]; exists {
				s, ok := v.(string)
				if !ok || !viewerDNSNetworkRef.MatchString(s) {
					valid = false
				} else {
					out["network"] = s
				}
			}
			if kind == "Instance" {
				boolean(cfg, out, "enablePublicIp")
				if v, exists := cfg["authorizedExternalNetworks"]; exists {
					rows, ok := v.([]any)
					if !ok {
						valid = false
					} else {
						nets := []any{}
						for _, r := range rows {
							cidr, e := netip.ParsePrefix(Str(Obj(r)["cidrRange"]))
							if e != nil || cidr.Addr().Is4In6() {
								valid = false
								continue
							}
							nets = append(nets, Object{"cidrRange": cidr.Masked().String()})
						}
						out["authorizedExternalNetworks"] = nets
					}
				}
			}
			clean["networkConfig"] = out
		}
	}
	return clean, valid
}
