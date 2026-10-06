package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerSpannerInstanceFields = "instances(name,state,instanceType,edition,defaultBackupScheduleType),nextPageToken,unreachable"
const viewerSpannerDatabaseFields = "databases(name,state,databaseDialect,enableDropProtection,versionRetentionPeriod,restoreInfo(sourceType,backupInfo(backup,sourceDatabase,createTime,versionTime))),nextPageToken"
const viewerSpannerBackupFields = "backups(name,state,database,databaseDialect,createTime,versionTime,expireTime),nextPageToken"

var viewerSpannerInstanceID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`)
var viewerSpannerChildID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,127}$`)
var viewerSpannerRetention = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(s|m|h|d)$`)

func canonicalViewerSpannerName(raw, projectID, number, kind string) string {
	p := strings.Split(raw, "/")
	size := 4
	if kind != "Instance" {
		size = 6
	}
	if len(p) != size || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "instances" || !viewerSpannerInstanceID.MatchString(p[3]) {
		return ""
	}
	if size == 6 {
		collection := "databases"
		if kind == "Backup" {
			collection = "backups"
		}
		if p[4] != collection || !viewerSpannerChildID.MatchString(p[5]) {
			return ""
		}
	}
	p[1] = projectID
	return strings.Join(p, "/")
}

// Lineage references may cross the selected project. Validate syntax only;
// these references are never followed or used as collection parents.
func viewerSpannerReference(raw, projectID, number, kind string) string {
	if name := canonicalViewerSpannerName(raw, projectID, number, kind); name != "" {
		return name
	}
	p := strings.Split(raw, "/")
	if len(p) != 6 || !viewerResourceName.MatchString(p[1]) {
		return ""
	}
	return canonicalViewerSpannerName(raw, p[1], "projects/"+p[1], kind)
}

func (c *Client) CollectViewerSpanner(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-spanner:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := []string{}
	collect := func(parent, collection, kind, fields string) {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://spanner.googleapis.com/v1/"+parent+"/"+collection, url.Values{"pageSize": {"100"}, "fields": {fields}}, func(page Object) error {
			rows, e := viewerRows(page, collection)
			if e != nil {
				return e
			}
			for _, raw := range rows {
				d := Obj(raw)
				name := canonicalViewerSpannerName(Str(d["name"]), projectID, number, kind)
				if name == "" || !strings.HasPrefix(name, parent+"/"+collection+"/") || seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				clean, valid := projectViewerSpanner(d, name, kind, projectID, number)
				if !valid {
					partial = true
				}
				a := NewAsset("//spanner.googleapis.com/"+name, "spanner.googleapis.com/"+kind, clean)
				a.Ancestors = []string{number}
				policy, policyErr := c.readIAMPolicy(ctx, "https://spanner.googleapis.com/v1/"+name+":getIamPolicy")
				if policyErr == nil {
					a.IAM, policyErr = viewerLogViewPolicy(policy)
				}
				n := 0
				if policyErr == nil {
					n = 1
				}
				out.record("viewer-spanner-iam:"+name, n, policyErr)
				out.Assets = append(out.Assets, a)
				if kind == "Instance" {
					parents = append(parents, name)
				}
			}
			if v, exists := page["unreachable"]; exists {
				r, ok := v.([]any)
				if !ok || len(r) > 0 {
					partial = true
				}
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some Spanner metadata was malformed, duplicate, foreign or unreachable")
		}
		out.record("viewer-spanner-"+collection+":"+parent, len(out.Assets)-start, err)
	}
	collect("projects/"+projectID, "instances", "Instance", viewerSpannerInstanceFields)
	for _, parent := range parents {
		collect(parent, "databases", "Database", viewerSpannerDatabaseFields)
		collect(parent, "backups", "Backup", viewerSpannerBackupFields)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-spanner:limitations:" + projectID, Status: "notice", Error: "Selected instance, database and backup metadata plus direct IAM only. No sessions, SQL execution, rows, database contents, backup copies/restores or writes. Metadata and direct IAM do not establish effective access, database-role SQL privileges or historical abuse; backup presence is not a vulnerability."})
}

func projectViewerSpanner(d Object, name, kind, projectID, number string) (Object, bool) {
	out := Object{"name": name}
	valid := true
	enums := map[string]string{"state": "STATE_UNSPECIFIED|CREATING|READY"}
	if kind == "Instance" {
		enums["instanceType"] = "INSTANCE_TYPE_UNSPECIFIED|PROVISIONED|FREE_INSTANCE"
		enums["edition"] = "EDITION_UNSPECIFIED|STANDARD|ENTERPRISE|ENTERPRISE_PLUS"
		enums["defaultBackupScheduleType"] = "DEFAULT_BACKUP_SCHEDULE_TYPE_UNSPECIFIED|NONE|AUTOMATIC"
	} else {
		enums["databaseDialect"] = "DATABASE_DIALECT_UNSPECIFIED|GOOGLE_STANDARD_SQL|POSTGRESQL"
	}
	if kind == "Database" {
		if raw, exists := d["restoreInfo"]; exists {
			ri := Obj(raw)
			clean := Object{}
			if ri == nil {
				valid = false
			} else {
				if value, exists := ri["sourceType"]; exists {
					s, ok := value.(string)
					if !ok || (s != "TYPE_UNSPECIFIED" && s != "BACKUP") {
						valid = false
					} else {
						clean["sourceType"] = s
					}
				}
				if raw, exists := ri["backupInfo"]; exists {
					bi := Obj(raw)
					safe := Object{}
					if bi == nil {
						valid = false
					} else {
						for key, kind := range map[string]string{"backup": "Backup", "sourceDatabase": "Database"} {
							if raw, exists := bi[key]; exists {
								ref := viewerSpannerReference(Str(raw), projectID, number, kind)
								if ref == "" {
									valid = false
								} else {
									safe[key] = ref
								}
							}
						}
						for _, key := range []string{"createTime", "versionTime"} {
							if raw, exists := bi[key]; exists {
								ts, e := time.Parse(time.RFC3339Nano, Str(raw))
								if e != nil {
									valid = false
								} else {
									safe[key] = ts.Format(time.RFC3339Nano)
								}
							}
						}
						clean["backupInfo"] = safe
					}
				}
				out["restoreInfo"] = clean
			}
		}
		enums["state"] += "|READY_OPTIMIZING"
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
	if kind == "Database" {
		if v, exists := d["enableDropProtection"]; exists {
			b, ok := v.(bool)
			if ok {
				out["enableDropProtection"] = b
			} else {
				valid = false
			}
		}
		if v, exists := d["versionRetentionPeriod"]; exists {
			s, ok := v.(string)
			if !ok || len(s) > 32 || !viewerSpannerRetention.MatchString(s) {
				valid = false
			} else {
				out["versionRetentionPeriod"] = s
			}
		}
	}
	if kind == "Backup" {
		if v, exists := d["database"]; exists {
			s, ok := v.(string)
			ref := viewerSpannerReference(s, projectID, number, "Database")
			if !ok || ref == "" {
				valid = false
			} else {
				out["database"] = ref
			}
		}
		for _, key := range []string{"createTime", "versionTime", "expireTime"} {
			if v, exists := d[key]; exists {
				s, ok := v.(string)
				stamp, e := time.Parse(time.RFC3339Nano, s)
				if !ok || e != nil {
					valid = false
				} else {
					out[key] = stamp.Format(time.RFC3339Nano)
				}
			}
		}
	}
	return out, valid
}
