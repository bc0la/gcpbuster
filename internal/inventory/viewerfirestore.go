package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerFirestoreDatabaseFields = "databases(name,locationId,type,databaseEdition,deleteProtectionState,pointInTimeRecoveryEnablement,versionRetentionPeriod,firestoreDataAccessMode,mongodbCompatibleDataAccessMode,createTime,updateTime,earliestVersionTime),unreachable"
const viewerFirestoreBackupFields = "backups(name,database,state,snapshotTime,expireTime),unreachable"

var viewerFirestoreID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func canonicalViewerFirestoreName(raw, projectID, number, kind string) string {
	p := strings.Split(raw, "/")
	if len(p) < 4 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) {
		return ""
	}
	if kind == "Database" {
		if len(p) != 4 || p[2] != "databases" || (p[3] != "(default)" && !viewerFirestoreID.MatchString(p[3])) {
			return ""
		}
	} else {
		if len(p) != 6 || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[3] == "global" || p[4] != "backups" || !viewerFirestoreID.MatchString(p[5]) {
			return ""
		}
	}
	p[1] = projectID
	return strings.Join(p, "/")
}

func (c *Client) CollectViewerFirestore(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-firestore:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	// Both documented list methods are unpaginated. Do not invent page tokens,
	// filters, deleted-resource views, or database document collection requests.
	for _, spec := range []struct{ path, collection, kind, fields string }{{"databases", "databases", "Database", viewerFirestoreDatabaseFields}, {"locations/-/backups", "backups", "Backup", viewerFirestoreBackupFields}} {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		page, err := c.get(ctx, "https://firestore.googleapis.com/v1/projects/"+projectID+"/"+spec.path, url.Values{"fields": {spec.fields}})
		if err == nil {
			rows, e := viewerRows(page, spec.collection)
			err = e
			for _, raw := range rows {
				d := Obj(raw)
				name := canonicalViewerFirestoreName(Str(d["name"]), projectID, number, spec.kind)
				if name == "" || seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				clean, valid := projectViewerFirestore(d, name, spec.kind, projectID, number)
				if !valid {
					partial = true
				}
				a := NewAsset("//firestore.googleapis.com/"+name, "firestore.googleapis.com/"+spec.kind, clean)
				a.Ancestors = []string{number}
				if spec.kind == "Database" {
					a.Resource.Location = Str(clean["locationId"])
				} else {
					a.Resource.Location = strings.Split(name, "/")[3]
				}
				out.Assets = append(out.Assets, a)
			}
			if v, exists := page["unreachable"]; exists {
				r, ok := v.([]any)
				if !ok || len(r) > 0 {
					partial = true
				}
			}
		}
		if err == nil && partial {
			err = fmt.Errorf("some Firestore metadata was malformed, duplicate, foreign or unreachable")
		}
		out.record("viewer-firestore-"+spec.collection+":"+projectID, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-firestore:limitations:" + projectID, Status: "notice", Error: "Selected current database and backup metadata only. No document/entity reads, queries, exports/imports, clones/restores, credential access or writes. No direct database IAM policy endpoint is assumed. Recovery configuration and backup presence do not establish effective access, Firebase Security Rules behavior or historical abuse."})
}

func projectViewerFirestore(d Object, name, kind, projectID, number string) (Object, bool) {
	out := Object{"name": name}
	valid := true
	enums := map[string]string{"state": "STATE_UNSPECIFIED|CREATING|READY|NOT_AVAILABLE"}
	times := []string{"snapshotTime", "expireTime"}
	if kind == "Database" {
		enums = map[string]string{"type": "DATABASE_TYPE_UNSPECIFIED|FIRESTORE_NATIVE|DATASTORE_MODE", "databaseEdition": "DATABASE_EDITION_UNSPECIFIED|STANDARD|ENTERPRISE", "deleteProtectionState": "DELETE_PROTECTION_STATE_UNSPECIFIED|DELETE_PROTECTION_DISABLED|DELETE_PROTECTION_ENABLED", "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_ENABLEMENT_UNSPECIFIED|POINT_IN_TIME_RECOVERY_ENABLED|POINT_IN_TIME_RECOVERY_DISABLED", "firestoreDataAccessMode": "DATA_ACCESS_MODE_UNSPECIFIED|DATA_ACCESS_MODE_ENABLED|DATA_ACCESS_MODE_DISABLED", "mongodbCompatibleDataAccessMode": "DATA_ACCESS_MODE_UNSPECIFIED|DATA_ACCESS_MODE_ENABLED|DATA_ACCESS_MODE_DISABLED"}
		times = []string{"createTime", "updateTime", "earliestVersionTime"}
	}
	for key, values := range enums {
		if v, exists := d[key]; exists {
			s, ok := v.(string)
			match := false
			for _, value := range strings.Split(values, "|") {
				if s == value {
					match = true
				}
			}
			if ok && match {
				out[key] = s
			} else {
				valid = false
			}
		}
	}
	for _, key := range times {
		if raw, exists := d[key]; exists {
			stamp, e := time.Parse(time.RFC3339Nano, Str(raw))
			if e != nil {
				valid = false
			} else {
				out[key] = stamp.Format(time.RFC3339Nano)
			}
		}
	}
	if kind == "Database" {
		if raw, exists := d["locationId"]; exists {
			s, ok := raw.(string)
			if !ok || !viewerLocation.MatchString(s) || s == "global" {
				valid = false
			} else {
				out["locationId"] = s
			}
		}
		if raw, exists := d["versionRetentionPeriod"]; exists {
			s, ok := raw.(string)
			duration, e := time.ParseDuration(s)
			if !ok || !viewerBigtableDuration.MatchString(s) || e != nil || duration < 0 || duration > 7*24*time.Hour {
				valid = false
			} else {
				out["versionRetentionPeriod"] = s
			}
		}
	} else {
		if raw, exists := d["database"]; exists {
			s := Str(raw)
			ref := canonicalViewerFirestoreName(s, projectID, number, "Database")
			if ref == "" {
				p := strings.Split(s, "/")
				if len(p) == 4 && viewerResourceName.MatchString(p[1]) {
					ref = canonicalViewerFirestoreName(s, p[1], "projects/"+p[1], "Database")
				}
			}
			if ref == "" {
				valid = false
			} else {
				out["database"] = ref
			}
		}
	}
	return out, valid
}
