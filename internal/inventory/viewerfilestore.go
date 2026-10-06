package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const viewerFilestoreFields = "instances(name,state,tier,protocol,networks(network,connectMode),fileShares(nfsExportOptions(ipRanges,accessMode,squashMode,network,anonUid,anonGid))),nextPageToken,unreachable"

func (c *Client) CollectViewerFilestore(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-filestore:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	partial := false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://file.googleapis.com/v1/projects/"+projectID+"/locations/-/instances", url.Values{"pageSize": {"100"}, "fields": {viewerFilestoreFields}}, func(page Object) error {
		rows, e := viewerRows(page, "instances")
		if e != nil {
			return e
		}
		for _, raw := range rows {
			clean, ok := projectViewerFilestore(Obj(raw), projectID, number)
			if !ok {
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
			a := NewAsset("//file.googleapis.com/"+name, "file.googleapis.com/Instance", clean)
			a.Ancestors = []string{number}
			a.Resource.Location = strings.Split(name, "/")[3]
			out.Assets = append(out.Assets, a)
		}
		if v, exists := page["unreachable"]; exists {
			rows, ok := v.([]any)
			if !ok || len(rows) > 0 {
				partial = true
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some Filestore metadata was malformed, duplicate, foreign or unreachable")
	}
	out.record("viewer-filestore:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-filestore:limitations:" + projectID, Status: "notice", Error: "Selected instance and export configuration only; no mounts, probes, file contents, backups, directory-service credentials or writes. Configured source ranges and root handling do not establish network reachability or effective file access."})
}

func projectViewerFilestore(d Object, projectID, number string) (Object, bool) {
	p := strings.Split(Str(d["name"]), "/")
	if len(p) != 6 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[3] == "global" || p[4] != "instances" || !viewerDNSZoneName.MatchString(p[5]) {
		return nil, false
	}
	p[1] = projectID
	out := Object{"name": strings.Join(p, "/")}
	valid := true
	enum := func(src, dst Object, key, allowed string) bool {
		v, exists := src[key]
		if !exists {
			return true
		}
		s, ok := v.(string)
		matched := false
		for _, candidate := range strings.Split(allowed, "|") {
			if s == candidate {
				matched = true
			}
		}
		if !ok || !matched || s == "" {
			return false
		}
		dst[key] = s
		return true
	}
	for key, allowed := range map[string]string{"state": "STATE_UNSPECIFIED|CREATING|READY|REPAIRING|DELETING|ERROR|RESTORING|SUSPENDED|SUSPENDING|RESUMING|REVERTING|PROMOTING", "tier": "TIER_UNSPECIFIED|STANDARD|PREMIUM|BASIC_HDD|BASIC_SSD|HIGH_SCALE_SSD|ENTERPRISE|ZONAL|REGIONAL", "protocol": "FILE_PROTOCOL_UNSPECIFIED|NFS_V3|NFS_V4_1"} {
		if !enum(d, out, key, allowed) {
			valid = false
		}
	}
	network := func(v any) (string, bool) {
		s, ok := v.(string)
		return s, ok && (viewerDNSNetworkRef.MatchString(s) || viewerDNSZoneName.MatchString(s))
	}
	if v, exists := d["networks"]; exists {
		rows, ok := v.([]any)
		if !ok {
			valid = false
		} else {
			nets := []any{}
			for _, row := range rows {
				r := Obj(row)
				n, ok := network(r["network"])
				o := Object{"network": n}
				if !ok || !enum(r, o, "connectMode", "CONNECT_MODE_UNSPECIFIED|DIRECT_PEERING|PRIVATE_SERVICE_ACCESS|PRIVATE_SERVICE_CONNECT") {
					valid = false
					continue
				}
				nets = append(nets, o)
			}
			out["networks"] = nets
		}
	}
	if v, exists := d["fileShares"]; exists {
		shares, ok := v.([]any)
		if !ok {
			valid = false
		} else {
			safe := []any{}
			for _, raw := range shares {
				share := Obj(raw)
				if share == nil {
					valid = false
					safe = append(safe, Object{})
					continue
				}
				s := Object{}
				if v, exists := share["nfsExportOptions"]; exists {
					rows, ok := v.([]any)
					if !ok {
						valid = false
						safe = append(safe, s)
						continue
					}
					opts := []any{}
					for _, raw := range rows {
						r := Obj(raw)
						o := Object{}
						good := r != nil
						if !enum(r, o, "accessMode", "ACCESS_MODE_UNSPECIFIED|READ_ONLY|READ_WRITE") || !enum(r, o, "squashMode", "SQUASH_MODE_UNSPECIFIED|NO_ROOT_SQUASH|ROOT_SQUASH") {
							good = false
						}
						if v, exists := r["network"]; exists {
							n, ok := network(v)
							if !ok {
								good = false
							} else {
								o["network"] = n
							}
						}
						if v, exists := r["ipRanges"]; exists {
							ranges, ok := v.([]any)
							if !ok {
								good = false
							} else {
								clean := []any{}
								for _, v := range ranges {
									s, ok := v.(string)
									ip, e := netip.ParseAddr(s)
									if ok && e == nil && ip.Is4() {
										clean = append(clean, ip.String())
										continue
									}
									cidr, e := netip.ParsePrefix(s)
									if !ok || e != nil || !cidr.Addr().Is4() {
										good = false
										continue
									}
									clean = append(clean, cidr.Masked().String())
								}
								o["ipRanges"] = clean
							}
						}
						for _, key := range []string{"anonUid", "anonGid"} {
							if v, exists := r[key]; exists {
								s, ok := v.(string)
								n, e := strconv.ParseInt(s, 10, 64)
								if !ok || e != nil || n < 0 || Str(o["squashMode"]) != "ROOT_SQUASH" {
									good = false
								} else {
									o[key] = strconv.FormatInt(n, 10)
								}
							}
						}
						if !good {
							valid = false
							opts = append(opts, Object{})
							continue
						}
						opts = append(opts, o)
					}
					s["nfsExportOptions"] = opts
				}
				safe = append(safe, s)
			}
			out["fileShares"] = safe
		}
	}
	return out, valid
}
