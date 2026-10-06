package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const viewerAppEngineApplicationFields = "name,id,locationId,servingStatus,serviceAccount,sslPolicy,iap(enabled)"
const viewerAppEngineServiceFields = "name,id,networkSettings(ingressTrafficAllowed),split(shardBy,allocations)"
const viewerAppEngineVersionFields = "name,id,runtime,env,servingStatus,serviceAccount,createTime,vm,threadsafe,appEngineApis,network(name,subnetworkName,instanceIpMode,sessionAffinity),vpcAccessConnector(name,egressSetting)"
const viewerAppEngineFullFields = viewerAppEngineVersionFields + ",envVariables,buildEnvVariables"

var viewerAppEngineID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)

// CollectViewerAppEngine reads configuration only. FULL version environment
// maps are transient secret-scanner inputs, never persisted in the snapshot.
func (c *Client) CollectViewerAppEngine(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-appengine:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	base := "apps/" + projectID
	appendAsset := func(kind string, d Object) {
		a := NewAsset("//appengine.googleapis.com/"+Str(d["name"]), "appengine.googleapis.com/"+kind, d)
		a.Ancestors = []string{number}
		out.Assets = append(out.Assets, a)
	}
	raw, err := c.get(ctx, "https://appengine.googleapis.com/v1/"+base, url.Values{"fields": {viewerAppEngineApplicationFields}})
	count := 0
	if err == nil {
		var clean Object
		clean, err = viewerAppEngineProjection(raw, base, "Application")
		if clean != nil {
			appendAsset("Application", clean)
			count = 1
		}
	}
	out.record("viewer-appengine:application:"+projectID, count, err)
	services := []Object{}
	partial := false
	err = c.viewerPages(ctx, "https://appengine.googleapis.com/v1/"+base+"/services", url.Values{"pageSize": {"100"}, "fields": {"services(" + viewerAppEngineServiceFields + "),nextPageToken"}}, func(page Object) error {
		rows, e := viewerRows(page, "services")
		if e != nil {
			return e
		}
		for _, r := range rows {
			d := Obj(r)
			name := Str(d["name"])
			id := strings.TrimPrefix(name, base+"/services/")
			if name != base+"/services/"+id || !viewerAppEngineID.MatchString(id) {
				partial = true
				continue
			}
			clean, e := viewerAppEngineProjection(d, name, "Service")
			if e != nil {
				partial = true
			}
			if clean != nil {
				services = append(services, clean)
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some App Engine service metadata was malformed")
	}
	out.record("viewer-appengine:services:"+projectID, len(services), err)
	serviceCounts := map[string]int{}
	for _, service := range services {
		serviceCounts[Str(service["name"])]++
	}
	seen := map[string]bool{}
	for _, service := range services {
		name := Str(service["name"])
		if seen[name] {
			continue
		}
		seen[name] = true
		appendAsset("Service", service)
		versions := []Object{}
		partial = false
		err = c.viewerPages(ctx, "https://appengine.googleapis.com/v1/"+name+"/versions", url.Values{"pageSize": {"100"}, "view": {"BASIC"}, "fields": {"versions(" + viewerAppEngineVersionFields + "),nextPageToken"}}, func(page Object) error {
			rows, e := viewerRows(page, "versions")
			if e != nil {
				return e
			}
			for _, r := range rows {
				d := Obj(r)
				vn := Str(d["name"])
				id := strings.TrimPrefix(vn, name+"/versions/")
				if vn != name+"/versions/"+id || !viewerAppEngineID.MatchString(id) {
					partial = true
					continue
				}
				clean, e := viewerAppEngineProjection(d, vn, "Version")
				if e != nil {
					partial = true
				}
				if clean != nil {
					versions = append(versions, clean)
				}
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some App Engine version metadata was malformed")
		}
		out.record("viewer-appengine:versions:"+name, len(versions), err)
		vs := map[string]bool{}
		for _, version := range versions {
			vn := Str(version["name"])
			if vs[vn] {
				continue
			}
			vs[vn] = true
			full, e := c.get(ctx, "https://appengine.googleapis.com/v1/"+vn, url.Values{"view": {"FULL"}, "fields": {viewerAppEngineFullFields}})
			if e == nil {
				var projected Object
				projected, e = viewerAppEngineProjection(full, vn, "Version")
				if projected != nil {
					if e == nil {
						c.SecretCapture.CaptureStringMap("appengine_env", "//appengine.googleapis.com/"+vn, "", "envVariables", full["envVariables"])
						c.SecretCapture.CaptureStringMap("appengine_build_env", "//appengine.googleapis.com/"+vn, "", "buildEnvVariables", full["buildEnvVariables"])
					}
					for k, v := range projected {
						version[k] = v
					}
					candidates, secretErr := projectAppEngineSecrets(full)
					if len(candidates) > 0 {
						version["_gcpbusterSecretCandidates"] = candidates
					}
					if e == nil {
						e = secretErr
					}
				}
			}
			n := 0
			if e == nil {
				n = 1
			}
			out.record("viewer-appengine:version:"+vn, n, e)
			// Repeated service observations may straddle a traffic update. Do
			// not select an arbitrary split for a negative-allocation finding.
			if split := Obj(service["split"]); split != nil && serviceCounts[name] == 1 {
				allocations := Obj(split["allocations"])
				fraction := float64(0)
				if value, exists := allocations[Str(version["id"])]; exists {
					fraction = value.(float64) // validated by projectAppEngineSplit
				}
				version["_gcpbusterTrafficAllocation"] = Object{"service": name, "fraction": fraction}
			}
			appendAsset("Version", version)
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-appengine:limitations:" + projectID, Status: "notice", Error: "Application/service configuration and BASIC version metadata with selected FULL environment configuration. Only redacted environment secret candidates are retained. IAP client secrets/hashes, deployment artifacts, source files, arbitrary generated metadata and raw environment values are excluded. No source downloads, application requests, URL following, deployment or mutation occurs; serving status alone does not establish reachability."})
}

func viewerAppEngineProjection(d Object, name, kind string) (Object, error) {
	if d == nil || Str(d["name"]) != name {
		return nil, fmt.Errorf("invalid App Engine resource identity")
	}
	id := name[strings.LastIndex(name, "/")+1:]
	if raw, exists := d["id"]; exists && raw != id {
		return nil, fmt.Errorf("mismatched App Engine resource id")
	}
	clean := Object{"name": name, "id": id}
	partial := false
	fields := []string{}
	bools := []string{}
	nested := map[string]struct{ s, b []string }{}
	switch kind {
	case "Application":
		fields = []string{"locationId", "servingStatus", "serviceAccount", "sslPolicy"}
		nested["iap"] = struct{ s, b []string }{b: []string{"enabled"}}
	case "Service":
		nested["networkSettings"] = struct{ s, b []string }{s: []string{"ingressTrafficAllowed"}}
		if value, exists := d["split"]; exists {
			if split, valid := projectAppEngineSplit(value); valid {
				clean["split"] = split
			} else {
				partial = true
			}
		}
	case "Version":
		fields = []string{"runtime", "env", "servingStatus", "serviceAccount", "createTime"}
		bools = []string{"vm", "threadsafe", "appEngineApis"}
		nested["network"] = struct{ s, b []string }{s: []string{"name", "subnetworkName", "instanceIpMode"}, b: []string{"sessionAffinity"}}
		nested["vpcAccessConnector"] = struct{ s, b []string }{s: []string{"name", "egressSetting"}}
	default:
		return nil, fmt.Errorf("unknown App Engine resource type")
	}
	for _, k := range fields {
		if v, ok := d[k]; ok {
			if _, valid := v.(string); valid {
				clean[k] = v
			} else {
				partial = true
			}
		}
	}
	for _, k := range bools {
		if v, ok := d[k]; ok {
			if _, valid := v.(bool); valid {
				clean[k] = v
			} else {
				partial = true
			}
		}
	}
	for k, f := range nested {
		if v, ok := d[k]; ok {
			if Obj(v) == nil {
				partial = true
				continue
			}
			p, e := viewerNetworkProjection(Obj(v), f.s, f.b)
			if e != nil {
				partial = true
			} else {
				clean[k] = p
			}
		}
	}
	if partial {
		return clean, fmt.Errorf("some App Engine configuration fields were malformed")
	}
	return clean, nil
}
