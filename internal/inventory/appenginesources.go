package inventory

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Manifest URLs are parsed into GCS identities, never fetched directly. Even
// documented HTTP source URLs are read through the authenticated HTTPS GCS API.
func appEngineSourceURL(raw string) (sourceObject, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host != "storage.googleapis.com" || (u.Scheme != "https" && u.Scheme != "http") {
		return sourceObject{}, false
	}
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if len(parts) != 2 || !bucketNamePattern.MatchString(parts[0]) || parts[1] == "" {
		return sourceObject{}, false
	}
	return sourceObject{bucket: parts[0], name: parts[1]}, true
}

func appEngineSourceReferences(a Asset, limit int) ([]sourceObject, bool) {
	var refs []sourceObject
	incomplete := false
	seen := map[sourceObject]bool{}
	add := func(raw string) {
		ref, ok := appEngineSourceURL(raw)
		if !ok {
			incomplete = true
			return
		}
		if seen[ref] {
			return
		}
		seen[ref] = true
		if len(refs) >= limit {
			incomplete = true
			return
		}
		refs = append(refs, ref)
	}
	deployment := Obj(a.Resource.Data["deployment"])
	if raw, exists := deployment["zip"]; exists {
		add(Str(Obj(raw)["sourceUrl"]))
	}
	if raw, exists := deployment["files"]; exists {
		files, ok := raw.(map[string]any)
		if !ok {
			incomplete = true
		} else {
			keys := make([]string, 0, len(files))
			for key := range files {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				add(Str(Obj(files[key])["sourceUrl"]))
			}
		}
	}
	if deployment["container"] != nil {
		incomplete = true
	}
	return refs, incomplete
}

// RefreshAppEngineSources uses versions.get FULL on known identities. It does
// not require list permission or guess version names. Failed reads preserve the
// prior inventory but mark collection failed; stale references are not clean.
func (c *Client) RefreshAppEngineSources(ctx context.Context, snap *Snapshot) {
	seen := map[string]bool{}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != "appengine.googleapis.com/Version" || seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		m := appEngineIAPSource.FindStringSubmatch(a.Name)
		if m == nil || m[2] == "" || m[3] == "" {
			snap.record("appengine-full:"+a.Name, 0, fmt.Errorf("invalid App Engine version name"))
			continue
		}
		name := strings.TrimPrefix(a.Name, "//appengine.googleapis.com/")
		d, err := c.get(ctx, "https://appengine.googleapis.com/v1/"+name, url.Values{"view": {"FULL"}})
		if err == nil && (Str(d["name"]) != name || Str(d["id"]) != m[3]) {
			err = fmt.Errorf("mismatched App Engine full version identity")
		}
		if err != nil {
			snap.record("appengine-full:"+a.Name, 0, err)
			continue
		}
		a.Resource.Data = d
		snap.record("appengine-full:"+a.Name, 1, nil)
	}
}
