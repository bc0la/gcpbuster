package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Explicit projection excludes password and any future credential/hash fields,
// both on the wire and in retained evidence. User presence is not a finding.
const viewerSQLUserFields = "items(name,host,type,project,instance,iamEmail,iamStatus,databaseRoles,serverRoles),nextPageToken"

// CollectViewerSQLUsers enriches already discovered SQL instances with
// control-plane user metadata. It does not connect to the database or test
// credentials. Users are nested evidence, not invented CAI resource types.
func (c *Client) CollectViewerSQLUsers(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-sql-users:identity", 0, fmt.Errorf("invalid project identity"))
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
			out.record("viewer-sql-users:identity:"+projectID, 0, fmt.Errorf("mismatched Cloud SQL parent identity"))
			continue
		}
		if evidence, exists := seen[instance]; exists {
			a.Resource.Data["_gcpbusterSQLUsers"] = evidence
			continue
		}
		page, err := c.get(ctx, "https://sqladmin.googleapis.com/v1/projects/"+projectID+"/instances/"+instance+"/users", url.Values{"fields": {viewerSQLUserFields}})
		users := []any{}
		if err == nil {
			users, err = viewerSQLUserPage(page, projectID, instance)
		}
		status := "completed"
		if err != nil {
			status = "failed"
		}
		evidence := Object{"items": users, "status": status}
		a.Resource.Data["_gcpbusterSQLUsers"] = evidence
		seen[instance] = evidence
		out.record("viewer-sql-users:"+projectID+"/"+instance, len(users), err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-sql-users:limitations:" + projectID, Status: "notice", Error: "User names, host restrictions, authentication types and returned role metadata only; no password strength, credential validity or effective database authorization assessment. users.list is unpaginated and documented to support responses up to 4 MB (roughly 13,000 users); oversized inventories may fail. Database contents and backup contents are not read."})
}

func viewerSQLUserPage(page Object, projectID, instance string) ([]any, error) {
	users := []any{}
	if page == nil {
		return users, fmt.Errorf("invalid Cloud SQL users response")
	}
	rows, err := viewerRows(page, "items")
	if err != nil {
		return users, err
	}
	var partial error
	for _, raw := range rows {
		d := Obj(raw)
		// Empty names can represent anonymous MySQL users. Names and hosts
		// never become URL components; they are metadata only.
		_, nameOK := d["name"].(string)
		if !nameOK || Str(d["project"]) != projectID || Str(d["instance"]) != instance {
			partial = fmt.Errorf("invalid or out-of-scope Cloud SQL user identity")
			continue
		}
		user := Object{}
		valid := true
		for _, field := range []string{"name", "host", "type", "project", "instance", "iamEmail", "iamStatus"} {
			if value, exists := d[field]; exists {
				if _, ok := value.(string); !ok {
					valid = false
				} else {
					user[field] = value
				}
			}
		}
		for _, field := range []string{"databaseRoles", "serverRoles"} {
			if _, exists := d[field]; !exists {
				continue
			}
			roles, err := viewerRows(d, field)
			if err != nil {
				valid = false
				continue
			}
			for _, role := range roles {
				if _, ok := role.(string); !ok {
					valid = false
				}
			}
			user[field] = roles
		}
		if !valid {
			partial = fmt.Errorf("malformed Cloud SQL user metadata")
			continue
		}
		users = append(users, user)
	}
	// The API has no pageToken request parameter; nextPageToken is unused.
	if raw, exists := page["nextPageToken"]; exists && raw != "" {
		partial = fmt.Errorf("unexpected Cloud SQL users continuation; pagination is unsupported")
	}
	return users, partial
}
