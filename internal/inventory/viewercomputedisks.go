package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var viewerComputeDiskID = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

const viewerComputeImageFields = "items(name,selfLink,id,creationTimestamp,status,family,sourceDisk,sourceDiskId,sourceImage,sourceImageId,sourceSnapshot,sourceSnapshotId,storageLocations,imageEncryptionKey(kmsKeyName,kmsKeyServiceAccount),deprecated(state,replacement,deprecated,obsolete,deleted)),nextPageToken,warning(code)"
const viewerComputeSnapshotFields = "items(name,selfLink,id,creationTimestamp,status,snapshotType,sourceDisk,sourceDiskId,sourceInstantSnapshot,sourceInstantSnapshotId,storageLocations,snapshotEncryptionKey(kmsKeyName,kmsKeyServiceAccount)),nextPageToken,warning(code)"

// CollectViewerComputeDisks reads image/snapshot control-plane metadata and
// direct policies only. It does not create disks, restore, mount or export data.
func (c *Client) CollectViewerComputeDisks(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-compute-disks:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	c.viewerComputeDiskList(ctx, out, projectID, number, "global", "images", "Image")
	c.viewerComputeDiskList(ctx, out, projectID, number, "global", "snapshots", "Snapshot")
	regions := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://compute.googleapis.com/compute/v1/projects/"+projectID+"/regions", url.Values{"maxResults": {"100"}, "fields": {"items(name,selfLink),nextPageToken,warning(code)"}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !viewerComputeDiskID.MatchString(name) {
				partial = true
				continue
			}
			if _, exists := d["selfLink"]; exists {
				if !viewerComputeDiskLink(Str(d["selfLink"]), projectID, number, "regions/"+name) {
					partial = true
					continue
				}
			}
			regions[name] = true
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some Compute regions were malformed or unavailable")
	}
	out.record("viewer-compute-disks:regions:"+projectID, len(regions), err)
	names := []string{}
	for name := range regions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, region := range names {
		c.viewerComputeDiskList(ctx, out, projectID, number, "regions/"+region, "snapshots", "Snapshot")
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-compute-disks:limitations:" + projectID, Status: "notice", Error: "Custom images and global/regional standard or archive snapshots in the selected project only. Instant snapshots, recycle-bin/recoverable snapshots, disk data, guest files, licenses, raw encryption keys, exports and restores are excluded. Direct IAM conditions are retained, not evaluated; inherited grants, deny policies, KMS authorization and effective data access are not established. References are not followed."})
}

func (c *Client) viewerComputeDiskList(ctx context.Context, out *Snapshot, projectID, number, scope, collection, kind string) {
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	fields := viewerComputeSnapshotFields
	if collection == "images" {
		fields = viewerComputeImageFields
	}
	endpoint := "https://compute.googleapis.com/compute/v1/projects/" + projectID + "/" + scope + "/" + collection
	err := c.viewerPages(ctx, endpoint, url.Values{"maxResults": {"100"}, "fields": {fields}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !viewerComputeDiskID.MatchString(name) {
				partial = true
				continue
			}
			if _, exists := d["selfLink"]; exists {
				if !viewerComputeDiskLink(Str(d["selfLink"]), projectID, number, scope+"/"+collection+"/"+name) {
					partial = true
					continue
				}
			}
			clean, err := viewerComputeDiskProjection(d, collection)
			if err != nil {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			canonical := "projects/" + projectID + "/" + scope + "/" + collection + "/" + name
			a := NewAsset("//compute.googleapis.com/"+canonical, "compute.googleapis.com/"+kind, clean)
			a.Ancestors = []string{number}
			a.Resource.Location = strings.TrimPrefix(scope, "regions/")
			policy, policyErr := c.get(ctx, endpoint+"/"+name+"/getIamPolicy", url.Values{"optionsRequestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag"}})
			if policyErr == nil {
				policy, policyErr = viewerLogViewPolicy(policy)
				if policyErr != nil {
					policyErr = fmt.Errorf("malformed Compute image/snapshot IAM policy")
				}
			}
			count := 0
			if policyErr == nil {
				a.IAM = policy
				count = 1
			}
			out.record("viewer-compute-disk-iam:"+canonical, count, policyErr)
			out.Assets = append(out.Assets, a)
		}
		return viewerComputeExtraWarnings(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some Compute image/snapshot metadata was malformed or unavailable")
	}
	out.record("viewer-compute-disks:"+projectID+":"+scope+":"+collection, len(out.Assets)-start, err)
}

func viewerComputeDiskLink(link, projectID, number, tail string) bool {
	for _, host := range []string{"https://www.googleapis.com", "https://compute.googleapis.com"} {
		for _, project := range []string{projectID, strings.TrimPrefix(number, "projects/")} {
			if link == host+"/compute/v1/projects/"+project+"/"+tail {
				return true
			}
		}
	}
	return false
}

func viewerComputeDiskProjection(d Object, collection string) (Object, error) {
	clean := Object{}
	fields := []string{"name", "id", "creationTimestamp", "status", "sourceDisk", "sourceDiskId"}
	key := "snapshotEncryptionKey"
	if collection == "images" {
		fields = append(fields, "family", "sourceImage", "sourceImageId", "sourceSnapshot", "sourceSnapshotId")
		key = "imageEncryptionKey"
	} else {
		fields = append(fields, "snapshotType", "sourceInstantSnapshot", "sourceInstantSnapshotId")
	}
	for _, field := range fields {
		if raw, exists := d[field]; exists {
			v, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("malformed Compute image/snapshot string")
			}
			if field == "creationTimestamp" {
				if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
					return nil, err
				}
			}
			clean[field] = v
		}
	}
	if raw, exists := d["storageLocations"]; exists {
		rows, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("malformed storage locations")
		}
		for _, r := range rows {
			if !viewerLocation.MatchString(Str(r)) {
				return nil, fmt.Errorf("malformed storage location")
			}
		}
		clean["storageLocations"] = rows
	}
	if raw, exists := d[key]; exists {
		row := Obj(raw)
		if row == nil {
			return nil, fmt.Errorf("malformed encryption reference")
		}
		projected := Object{}
		for _, field := range []string{"kmsKeyName", "kmsKeyServiceAccount"} {
			if value, exists := row[field]; exists {
				if _, ok := value.(string); !ok {
					return nil, fmt.Errorf("malformed KMS reference")
				}
				projected[field] = value
			}
		}
		clean[key] = projected
	}
	if raw, exists := d["deprecated"]; exists && collection == "images" {
		row := Obj(raw)
		if row == nil {
			return nil, fmt.Errorf("malformed image deprecation")
		}
		projected := Object{}
		for _, field := range []string{"state", "replacement", "deprecated", "obsolete", "deleted"} {
			if raw, exists := row[field]; exists {
				v, ok := raw.(string)
				if !ok {
					return nil, fmt.Errorf("malformed image deprecation field")
				}
				if field != "state" && field != "replacement" {
					if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
						return nil, err
					}
				}
				projected[field] = v
			}
		}
		clean["deprecated"] = projected
	}
	return clean, nil
}
