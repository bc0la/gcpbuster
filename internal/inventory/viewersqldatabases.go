package inventory

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
)

const viewerSQLDatabaseFields = "items(name,project,instance,charset,collation,selfLink,sqlserverDatabaseDetails(compatibilityLevel,recoveryModel))"

// CollectViewerSQLDatabases reads control-plane database metadata, never SQL
// queries or table contents. The list API returns the same Database resource as
// databases.get; no redundant describe requests are necessary. Nested evidence
// does not invent a CAI asset type or a vulnerability from a database's presence.
func (c *Client) CollectViewerSQLDatabases(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-sql-databases:identity", 0, fmt.Errorf("invalid project identity"))
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
			out.record("viewer-sql-databases:identity:"+projectID, 0, fmt.Errorf("mismatched Cloud SQL parent identity"))
			continue
		}
		if evidence, exists := seen[instance]; exists {
			a.Resource.Data["_gcpbusterSQLDatabases"] = evidence
			continue
		}
		page, err := c.get(ctx, "https://sqladmin.googleapis.com/v1/projects/"+projectID+"/instances/"+instance+"/databases", url.Values{"fields": {viewerSQLDatabaseFields}})
		rows := []any{}
		if err == nil {
			rows, err = viewerSQLDatabasePage(page, projectID, instance)
		}
		status := "completed"
		if err != nil {
			status = "failed"
		}
		evidence := Object{"items": rows, "status": status}
		a.Resource.Data["_gcpbusterSQLDatabases"] = evidence
		seen[instance] = evidence
		out.record("viewer-sql-databases:"+projectID+"/"+instance, len(rows), err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-sql-databases:limitations:" + projectID, Status: "notice", Error: "Database names, charset/collation and returned SQL Server recovery/compatibility metadata only. The unpaginated list returns Database resources also used by describe. Table contents, database connections, credential tests and effective database authorization are not assessed."})
}

func viewerSQLDatabasePage(page Object, projectID, instance string) ([]any, error) {
	result := []any{}
	if page == nil {
		return result, fmt.Errorf("invalid Cloud SQL databases response")
	}
	rows, err := viewerRows(page, "items")
	if err != nil {
		return result, err
	}
	var partial error
	seen := map[string]bool{}
	for _, raw := range rows {
		d := Obj(raw)
		name := Str(d["name"])
		if strings.TrimSpace(name) == "" || Str(d["project"]) != projectID || Str(d["instance"]) != instance {
			partial = fmt.Errorf("invalid or out-of-scope Cloud SQL database identity")
			continue
		}
		database := Object{}
		valid := true
		for _, field := range []string{"name", "project", "instance", "charset", "collation", "selfLink"} {
			if value, exists := d[field]; exists {
				if _, ok := value.(string); !ok {
					valid = false
				} else {
					database[field] = value
				}
			}
		}
		if link := Str(d["selfLink"]); link != "" && !viewerSQLDatabaseLink(link, projectID, instance, name) {
			valid = false
		}
		if raw, exists := d["sqlserverDatabaseDetails"]; exists {
			details := Obj(raw)
			if details == nil {
				valid = false
			} else {
				clean := Object{}
				if value, exists := details["recoveryModel"]; exists {
					if _, ok := value.(string); !ok {
						valid = false
					} else {
						clean["recoveryModel"] = value
					}
				}
				if value, exists := details["compatibilityLevel"]; exists {
					n, ok := value.(float64)
					if !ok || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < -2147483648 || n > 2147483647 {
						valid = false
					} else {
						clean["compatibilityLevel"] = n
					}
				}
				database["sqlserverDatabaseDetails"] = clean
			}
		}
		if !valid {
			partial = fmt.Errorf("malformed or mismatched Cloud SQL database metadata")
			continue
		}
		if !seen[name] {
			result = append(result, database)
			seen[name] = true
		}
	}
	// No continuation parameter exists in the databases.list API.
	if raw, exists := page["nextPageToken"]; exists && raw != "" {
		partial = fmt.Errorf("unexpected Cloud SQL databases continuation; pagination is unsupported")
	}
	return result, partial
}

func viewerSQLDatabaseLink(link, projectID, instance, database string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host != "sqladmin.googleapis.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	for _, prefix := range []string{"/v1/", "/sql/v1/", "/sql/v1beta4/"} {
		if u.Path == prefix+"projects/"+projectID+"/instances/"+instance+"/databases/"+database {
			return true
		}
	}
	return false
}
