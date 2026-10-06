package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type sourceObject struct{ bucket, name, generation string }

func sourceReference(a Asset) (sourceObject, bool) {
	var ref Object
	switch a.Type {
	case "cloudfunctions.googleapis.com/CloudFunction":
		archive := Str(a.Resource.Data["sourceArchiveUrl"])
		u, err := url.Parse(archive)
		if err == nil && u.Scheme == "gs" && u.Host != "" && u.User == nil && u.RawQuery == "" {
			return sourceObject{u.Host, strings.TrimPrefix(u.Path, "/"), u.Fragment}, true
		}
	case "cloudfunctions.googleapis.com/Function":
		ref = Obj(Get(a.Resource.Data, "buildConfig", "source", "storageSource"))
	case "cloudbuild.googleapis.com/Build":
		ref = Obj(Get(a.Resource.Data, "sourceProvenance", "resolvedStorageSource"))
		if ref == nil {
			ref = Obj(Get(a.Resource.Data, "source", "storageSource"))
		}
	case "cloudbuild.googleapis.com/BuildTrigger":
		ref = Obj(Get(a.Resource.Data, "build", "source", "storageSource"))
	}
	if ref == nil {
		return sourceObject{}, false
	}
	return sourceObject{Str(ref["bucket"]), Str(ref["object"]), Str(ref["generation"])}, true
}

// CollectSources reads GCS source references directly, without object listing.
// A missing generation is resolved through object metadata and then pinned.
func (c *Client) CollectSources(ctx context.Context, snap *Snapshot, opts StorageOptions) {
	if err := opts.Validate(); err != nil {
		snap.record("source-options", 0, err)
		return
	}
	assets := append([]Asset(nil), snap.Assets...)
	for _, a := range assets {
		switch a.Type {
		case "appengine.googleapis.com/Version", "cloudfunctions.googleapis.com/CloudFunction", "cloudfunctions.googleapis.com/Function", "cloudbuild.googleapis.com/Build", "cloudbuild.googleapis.com/BuildTrigger":
		default:
			continue
		}
		if a.Resource.Data == nil {
			snap.Coverage = append(snap.Coverage, Coverage{Source: "source:" + a.Name, Status: "incomplete", Error: "Workload configuration is missing; source references cannot be assessed."})
			continue
		}
		var refs []sourceObject
		if a.Type == "appengine.googleapis.com/Version" {
			var incomplete bool
			refs, incomplete = appEngineSourceReferences(a, opts.MaxObjects)
			if incomplete {
				snap.Coverage = append(snap.Coverage, Coverage{Source: "source:" + a.Name, Status: "incomplete", Error: "App Engine deployment references include unsupported/malformed entries or exceed the source object limit; valid bounded references are still scanned."})
			}
		} else if ref, ok := sourceReference(a); ok {
			refs = append(refs, ref)
		}
		if len(refs) == 0 {
			snap.Coverage = append(snap.Coverage, Coverage{Source: "source:" + a.Name, Status: "incomplete", Error: "No directly readable GCS source reference supplied. Repository sources, manifests, signed download URLs and omitted source fields require additional collection."})
			continue
		}
		for _, ref := range refs {
			if !bucketNamePattern.MatchString(ref.bucket) || ref.name == "" {
				snap.record("source:"+a.Name, 0, fmt.Errorf("invalid GCS source reference"))
				continue
			}
			base := "https://storage.googleapis.com/storage/v1/b/" + url.PathEscape(ref.bucket) + "/o/" + url.PathEscape(ref.name)
			q := url.Values{"fields": {"name,generation,size,contentType"}}
			if ref.generation != "" && ref.generation != "0" {
				if _, err := strconv.ParseUint(ref.generation, 10, 64); err != nil {
					snap.record("source:"+a.Name, 0, fmt.Errorf("invalid source generation"))
					continue
				}
				q.Set("generation", ref.generation)
			}
			r, err := c.storageGET(ctx, base+"?"+q.Encode(), true, 1<<20, "")
			if err != nil {
				snap.record("source:"+a.Name, 0, err)
				continue
			}
			var metadata Object
			if r.Status != 200 || r.Truncated || json.Unmarshal(r.Body, &metadata) != nil || Str(metadata["name"]) != ref.name || Str(metadata["generation"]) == "" {
				snap.record("source:"+a.Name, 0, fmt.Errorf("source metadata unavailable or malformed (HTTP %d)", r.Status))
				continue
			}
			if expected := q.Get("generation"); expected != "" && Str(metadata["generation"]) != expected {
				snap.record("source:"+a.Name, 0, fmt.Errorf("source generation mismatch"))
				continue
			}
			size, err := strconv.ParseInt(Str(metadata["size"]), 10, 64)
			if err != nil || size < 0 {
				snap.record("source:"+a.Name, 0, fmt.Errorf("source metadata omitted valid content size"))
				continue
			}
			if size > opts.MaxObjectBytes {
				snap.Coverage = append(snap.Coverage, Coverage{Source: "source:" + a.Name, Status: "incomplete", Error: "Source object exceeds configured content byte limit."})
				continue
			}
			generation := Str(metadata["generation"])
			uri := base + "?" + url.Values{"alt": {"media"}, "generation": {generation}}.Encode()
			resource := "//storage.googleapis.com/" + ref.bucket + "/objects/" + url.PathEscape(ref.name) + "#" + generation
			before := len(snap.Assets)
			c.scanObject(ctx, snap, a, resource, ref.name, uri, opts)
			for i := before; i < len(snap.Assets); i++ {
				snap.Assets[i].Name = a.Name + "/source-scan"
				if a.Type == "appengine.googleapis.com/Version" {
					snap.Assets[i].Name += fmt.Sprintf("/%x", sha256.Sum256([]byte(resource)))
				}
				snap.Assets[i].Resource.Data["originResource"] = a.Name
				snap.Assets[i].Resource.Data["sourceKind"] = "workload_source"
			}
		}
	}
}
