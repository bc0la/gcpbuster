package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const viewerSQLBackupLimit = 1000
const viewerSQLBackupFields = "id,instance,status,type,backupKind,databaseVersion,location,windowStartTime,enqueuedTime,startTime,endTime"
const viewerSQLBackupListFields = "items(" + viewerSQLBackupFields + "),nextPageToken"

// CollectViewerSQLBackups reads bounded backup-record metadata, not backup
// contents. No create/export/download/restore endpoint or selfLink is followed.
func (c *Client) CollectViewerSQLBackups(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-sql-backups:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	prefix := "//cloudsql.googleapis.com/projects/" + projectID + "/instances/"
	seen := map[string]Object{}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != "sqladmin.googleapis.com/Instance" || !strings.HasPrefix(a.Name, prefix) {
			continue
		}
		instance := strings.TrimPrefix(a.Name, prefix)
		if !viewerResourceName.MatchString(instance) || Str(a.Resource.Data["name"]) != instance || Str(a.Resource.Data["project"]) != projectID {
			out.record("viewer-sql-backups:identity:"+projectID, 0, fmt.Errorf("mismatched Cloud SQL parent identity"))
			continue
		}
		if evidence, exists := seen[instance]; exists {
			a.Resource.Data["_gcpbusterSQLBackups"] = evidence
			continue
		}
		evidence := c.viewerSQLBackupRecords(ctx, out, projectID, instance)
		a.Resource.Data["_gcpbusterSQLBackups"] = evidence
		seen[instance] = evidence
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-sql-backups:limitations:" + projectID, Status: "notice", Error: "BackupRun metadata for discovered current instances only, limited to 1000 records per instance. Deleted-instance/retained backups and Backup and DR vault inventories are not enumerated. A successful backup status does not prove restore usability or data completeness; backup contents, exports and restore operations were not accessed."})
}

func (c *Client) viewerSQLBackupRecords(ctx context.Context, out *Snapshot, projectID, instance string) Object {
	items := []any{}
	seen := map[string]bool{}
	partial := false
	endpoint := "https://sqladmin.googleapis.com/v1/projects/" + projectID + "/instances/" + instance + "/backupRuns"
	// The documented list response already contains BackupRun resources. Read
	// their reviewed metadata directly instead of issuing up to 1000 redundant
	// detail GETs per instance. No backup contents are requested.
	err := c.viewerPages(ctx, endpoint, url.Values{"maxResults": {"100"}, "fields": {viewerSQLBackupListFields}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			id := Str(d["id"])
			if !viewerSQLBackupIdentity(d, instance, id) {
				partial = true
				continue
			}
			if seen[id] {
				continue
			}
			if len(seen) >= viewerSQLBackupLimit {
				return fmt.Errorf("backup metadata record limit reached; remaining inventory unassessed")
			}
			seen[id] = true
			clean, readErr := viewerSQLBackupProjection(d, instance, id)
			count := 0
			if readErr != nil {
				partial = true
				clean = Object{"id": id, "instance": instance, "metadataStatus": "failed"}
			} else {
				count = 1
				clean["metadataStatus"] = "completed"
			}
			items = append(items, clean)
			out.record("viewer-sql-backup:"+projectID+"/"+instance+"/"+id, count, readErr)
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some backup identities or metadata were malformed")
	}
	status := "completed"
	if err != nil {
		status = "failed"
	}
	out.record("viewer-sql-backups:"+projectID+"/"+instance, len(items), err)
	return Object{"items": items, "status": status, "recordLimit": viewerSQLBackupLimit}
}

func viewerSQLBackupIdentity(d Object, instance, id string) bool {
	n, err := strconv.ParseInt(id, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == id && Str(d["id"]) == id && Str(d["instance"]) == instance
}

func viewerSQLBackupProjection(d Object, instance, id string) (Object, error) {
	if !viewerSQLBackupIdentity(d, instance, id) {
		return nil, fmt.Errorf("mismatched Cloud SQL backup identity")
	}
	if strings.TrimSpace(Str(d["status"])) == "" {
		return nil, fmt.Errorf("missing Cloud SQL backup status")
	}
	clean := Object{}
	for _, field := range strings.Split(viewerSQLBackupFields, ",") {
		if raw, exists := d[field]; exists {
			value, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("malformed Cloud SQL backup metadata")
			}
			if strings.HasSuffix(field, "Time") && value != "" {
				if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
					return nil, fmt.Errorf("malformed Cloud SQL backup timestamp")
				}
			}
			clean[field] = value
		}
	}
	return clean, nil
}
