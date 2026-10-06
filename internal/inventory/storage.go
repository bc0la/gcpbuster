package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

const StorageProbeType = "gcpbuster.googleapis.com/StorageAnonymousProbe"
const ContentScanType = "gcpbuster.googleapis.com/ContentScan"

type StorageOptions struct {
	Anonymous         bool
	ScanContent       bool
	MaxObjects        int
	MaxObjectBytes    int64
	MaxArchiveBytes   int64
	MaxArchiveEntries int
	Prefix            string
}

func (o StorageOptions) Validate() error {
	if o.MaxObjects < 1 || o.MaxObjectBytes < 1 || o.MaxArchiveBytes < 1 || o.MaxArchiveEntries < 1 {
		return fmt.Errorf("storage object, byte and archive limits must be positive")
	}
	if o.MaxObjectBytes > 64<<20 || o.MaxArchiveBytes > 256<<20 {
		return fmt.Errorf("storage limits exceed 64 MiB per object or 256 MiB expanded archive")
	}
	return nil
}

type storageResponse struct {
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
}

// Uses an isolated client without a cookie jar or redirects. Anonymous requests
// do not call accessToken, so they cannot accidentally reuse authenticated state.
func (c *Client) storageGET(ctx context.Context, endpoint string, authenticated bool, limit int64, byteRange string) (storageResponse, error) {
	if authenticated {
		if err := c.requireViewerPermissions(ctx, "GET", endpoint, nil); err != nil {
			return storageResponse{}, err
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host != "storage.googleapis.com" || u.User != nil {
		return storageResponse{}, fmt.Errorf("invalid storage API endpoint")
	}
	h := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.HTTP != nil {
		h.Transport = c.HTTP.Transport
		if c.HTTP.Timeout > 0 {
			h.Timeout = c.HTTP.Timeout
		}
	}
	ctx = withRequestAttemptCounter(ctx)
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return storageResponse{}, fmt.Errorf("invalid storage request")
		}
		if authenticated {
			token, err := c.accessToken(ctx)
			if err != nil {
				return storageResponse{}, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if byteRange != "" {
			req.Header.Set("Range", byteRange)
		}
		resp, err := c.doRequest(h, req, attempt+1)
		if err != nil {
			return storageResponse{}, fmt.Errorf("storage request failed (transport or cancellation)")
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < 3 {
				select {
				case <-time.After(time.Duration(1<<attempt) * time.Second):
					continue
				case <-ctx.Done():
					return storageResponse{}, ctx.Err()
				}
			}
			return storageResponse{Status: resp.StatusCode}, fmt.Errorf("storage request exhausted retries: HTTP %d", resp.StatusCode)
		}
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if readErr != nil {
			return storageResponse{}, fmt.Errorf("storage response read failed")
		}
		truncated := int64(len(b)) > limit
		if truncated {
			b = b[:limit]
		}
		return storageResponse{resp.StatusCode, resp.Header, b, truncated}, nil
	}
	return storageResponse{}, fmt.Errorf("storage retry budget exhausted")
}

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)

func bucketName(a Asset) string {
	name := Str(a.Resource.Data["name"])
	if name == "" {
		name = strings.TrimPrefix(a.Name, "//storage.googleapis.com/")
	}
	if !bucketNamePattern.MatchString(name) {
		return ""
	}
	return name
}

// CollectStorage inspects discovered buckets only. It is opt-in and never
// creates/deletes objects, validates recovered credentials, or retains bodies.
func (c *Client) CollectStorage(ctx context.Context, snap *Snapshot, opts StorageOptions) {
	if err := opts.Validate(); err != nil {
		snap.record("storage-options", 0, err)
		return
	}
	seen := map[string]bool{}
	assets := append([]Asset(nil), snap.Assets...)
	for _, a := range assets {
		if a.Type != "storage.googleapis.com/Bucket" {
			continue
		}
		bucket := bucketName(a)
		if bucket == "" {
			snap.record("storage:"+a.Name, 0, fmt.Errorf("invalid or missing bucket name"))
			continue
		}
		if seen[bucket] {
			continue
		}
		seen[bucket] = true
		if err := ctx.Err(); err != nil {
			snap.record("storage:"+bucket, 0, err)
			return
		}
		base := "https://storage.googleapis.com/storage/v1/b/" + url.PathEscape(bucket) + "/o"
		if opts.Anonymous {
			c.probeBucketList(ctx, snap, a, bucket, base, opts.Prefix)
		}
		if !opts.ScanContent && !opts.Anonymous {
			continue
		}
		q := url.Values{"maxResults": {strconv.Itoa(min(opts.MaxObjects, 1000))}, "fields": {"kind,items(name,generation,size,contentType),nextPageToken"}}
		if opts.Prefix != "" {
			q.Set("prefix", opts.Prefix)
		}
		pages := map[string]bool{}
		examined, skipped := 0, 0
		for {
			resp, err := c.storageGET(ctx, base+"?"+q.Encode(), true, 8<<20, "")
			if err != nil {
				snap.record("storage-list:"+bucket, examined, err)
				break
			}
			if resp.Status != 200 || resp.Truncated {
				snap.record("storage-list:"+bucket, examined, fmt.Errorf("object list unavailable or oversized (HTTP %d)", resp.Status))
				break
			}
			var page Object
			if err := json.Unmarshal(resp.Body, &page); err != nil || Str(page["kind"]) != "storage#objects" {
				snap.record("storage-list:"+bucket, examined, fmt.Errorf("invalid object-list response"))
				break
			}
			items := List(page["items"])
			limited := false
			for _, v := range items {
				if examined >= opts.MaxObjects {
					limited = true
					break
				}
				examined++
				x := Obj(v)
				name, generation := Str(x["name"]), Str(x["generation"])
				if name == "" || generation == "" {
					snap.record("storage-object:"+bucket, 0, fmt.Errorf("object list omitted name or generation"))
					continue
				}
				uri := base + "/" + url.PathEscape(name) + "?" + url.Values{"alt": {"media"}, "generation": {generation}}.Encode()
				resource := "//storage.googleapis.com/" + bucket + "/objects/" + url.PathEscape(name) + "#" + generation
				if opts.Anonymous {
					c.probeObject(ctx, snap, a, resource, uri)
				}
				if opts.ScanContent {
					if !secretmatch.Supported(name, Str(x["contentType"])) {
						skipped++
						continue
					}
					if size, e := strconv.ParseInt(Str(x["size"]), 10, 64); e == nil && size > opts.MaxObjectBytes {
						snap.Coverage = append(snap.Coverage, Coverage{Source: "content:" + resource, Status: "incomplete", Error: "Object exceeds configured content byte limit and was not scanned."})
						continue
					}
					c.scanObject(ctx, snap, a, resource, name, uri, opts)
				}
			}
			next := Str(page["nextPageToken"])
			if limited || (examined >= opts.MaxObjects && next != "") {
				snap.Coverage = append(snap.Coverage, Coverage{Source: "storage-list:" + bucket, Status: "incomplete", Count: examined, Error: "Object sampling limit reached; remaining objects were not inspected."})
				break
			}
			if next == "" {
				snap.record("storage-list:"+bucket, examined, nil)
				break
			}
			if pages[next] {
				snap.record("storage-list:"+bucket, examined, fmt.Errorf("repeated object-list pagination token"))
				break
			}
			pages[next] = true
			q.Set("pageToken", next)
		}
		if opts.ScanContent {
			snap.Coverage = append(snap.Coverage, Coverage{Source: "content-format-filter:" + bucket, Status: "notice", Count: skipped, Error: "Only supported text/code/config and ZIP artifacts were scanned; other formats were excluded."})
		}
		if opts.Prefix != "" {
			snap.Coverage = append(snap.Coverage, Coverage{Source: "storage-prefix:" + bucket, Status: "notice", Error: "Collection was restricted to the explicitly selected object prefix."})
		}
	}
}

func probeAsset(parent Asset, name, operation string, resp storageResponse, allowed bool) Asset {
	a := NewAsset(name, StorageProbeType, Object{"operation": operation, "httpStatus": resp.Status, "anonymous": true, "accessConfirmed": allowed, "requestAuthentication": "none"})
	a.Ancestors = parent.Ancestors
	return a
}
func (c *Client) probeBucketList(ctx context.Context, snap *Snapshot, parent Asset, bucket, base, prefix string) {
	q := url.Values{"maxResults": {"1"}, "fields": {"kind,items(name),nextPageToken"}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	r, err := c.storageGET(ctx, base+"?"+q.Encode(), false, 1<<20, "")
	if err != nil {
		snap.record("anonymous-list:"+bucket, 0, err)
		return
	}
	allowed := false
	if r.Status == 200 {
		var page Object
		if json.Unmarshal(r.Body, &page) != nil || Str(page["kind"]) != "storage#objects" || r.Truncated {
			snap.record("anonymous-list:"+bucket, 0, fmt.Errorf("invalid anonymous list response"))
			return
		}
		allowed = true
	} else if r.Status != 401 && r.Status != 403 {
		snap.record("anonymous-list:"+bucket, 0, fmt.Errorf("inconclusive anonymous list HTTP %d", r.Status))
		return
	}
	a := probeAsset(parent, parent.Name+"/anonymous-list", "list", r, allowed)
	a.Resource.Data["prefixRestricted"] = prefix != ""
	snap.Assets = append(snap.Assets, a)
	snap.record("anonymous-list:"+bucket, 1, nil)
}
func (c *Client) probeObject(ctx context.Context, snap *Snapshot, parent Asset, resource, uri string) {
	r, err := c.storageGET(ctx, uri, false, 1, "bytes=0-0")
	if err != nil {
		snap.record("anonymous-object:"+resource, 0, err)
		return
	}
	allowed := r.Status == 200 || r.Status == 206
	if !allowed && r.Status != 401 && r.Status != 403 {
		snap.record("anonymous-object:"+resource, 0, fmt.Errorf("inconclusive anonymous object HTTP %d", r.Status))
		return
	}
	snap.Assets = append(snap.Assets, probeAsset(parent, resource+"/anonymous-read", "object_read", r, allowed))
	snap.record("anonymous-object:"+resource, 1, nil)
}
func (c *Client) scanObject(ctx context.Context, snap *Snapshot, parent Asset, resource, name, uri string, opts StorageOptions) {
	r, err := c.storageGET(ctx, uri, true, opts.MaxObjectBytes, "")
	if err != nil {
		snap.record("content:"+resource, 0, err)
		return
	}
	if r.Status != 200 {
		snap.record("content:"+resource, 0, fmt.Errorf("content unavailable: HTTP %d", r.Status))
		return
	}
	if r.Truncated {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "content:" + resource, Status: "incomplete", Error: "Content response exceeds byte limit; no complete-content assessment was made."})
		return
	}
	matches, err := secretmatch.Scan(ctx, name, r.Body, opts.MaxArchiveBytes, opts.MaxArchiveEntries)
	var values []any
	for _, m := range matches {
		values = append(values, Object{"rule": m.Rule, "line": m.Line, "file": m.File})
	}
	a := NewAsset(resource+"/content-scan", ContentScanType, Object{"resource": resource, "matches": values, "bytesInspected": len(r.Body), "complete": err == nil, "redacted": true})
	a.Ancestors = parent.Ancestors
	snap.Assets = append(snap.Assets, a)
	if err != nil {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "content:" + resource, Status: "incomplete", Error: err.Error()})
	} else {
		snap.record("content:"+resource, 1, nil)
	}
}
