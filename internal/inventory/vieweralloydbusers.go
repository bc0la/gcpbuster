package inventory

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const AlloyDBUserType = "gcpbuster.googleapis.com/AlloyDBUser"
const viewerAlloyDBUserFields = "users(name,userType,databaseRoles),nextPageToken,unreachable"

// Database principals are not Cloud IAM principals. Only explicit selected
// built-in role names are retained; arbitrary role/user strings are digested.
func (c *Client) CollectViewerAlloyDBUsers(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-alloydb-users:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parents := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "alloydb.googleapis.com/Cluster" {
			continue
		}
		clean, _ := viewerAlloyDBProjection(a.Resource.Data, projectID, number, "Cluster")
		if clean == nil {
			continue
		}
		original := Str(a.Resource.Data["name"])
		if a.Name != "//alloydb.googleapis.com/"+original {
			continue
		}
		parents[Str(clean["name"])] = true
	}
	names := []string{}
	for name := range parents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, parent := range names {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://alloydb.googleapis.com/v1/"+parent+"/users", url.Values{"pageSize": {"100"}, "fields": {viewerAlloyDBUserFields}}, func(page Object) error {
			rows, e := viewerRows(page, "users")
			if e != nil {
				return e
			}
			for _, raw := range rows {
				clean, e := projectViewerAlloyDBUser(Obj(raw), parent, projectID, number)
				if e != nil {
					partial = true
				}
				if clean == nil {
					continue
				}
				digest := Str(clean["user_name_digest"])
				if seen[digest] {
					partial = true
					continue
				}
				seen[digest] = true
				a := NewAsset("//alloydb.googleapis.com/"+parent+"/user-metadata/"+digest, AlloyDBUserType, clean)
				a.Ancestors = []string{number}
				out.Assets = append(out.Assets, a)
			}
			return viewerAutomationPartial(page, &partial)
		})
		if err == nil && partial {
			err = fmt.Errorf("some AlloyDB user metadata was malformed, duplicated or unreachable")
		}
		out.record("viewer-alloydb-users:"+parent, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-alloydb-users:limitations:" + projectID, Status: "notice", Error: "Known-cluster user metadata only. User names and arbitrary role names are digested; only selected known database roles are named. No passwords, SQL queries, login attempts, effective role inheritance, group memberships or PostgreSQL superuser attribute are collected."})
}

func projectViewerAlloyDBUser(d Object, parent, projectID, number string) (Object, error) {
	name := Str(d["name"])
	// User schema describes singular 'cluster'; REST collection paths use
	// 'clusters'. Accept only either spelling of the same known scoped parent.
	canonical := strings.Replace(name, "/cluster/", "/clusters/", 1)
	numericPrefix := number + "/"
	if strings.HasPrefix(canonical, numericPrefix) {
		canonical = "projects/" + projectID + "/" + strings.TrimPrefix(canonical, numericPrefix)
	}
	prefix := parent + "/users/"
	user := strings.TrimPrefix(canonical, prefix)
	if canonical != prefix+user || user == "" || len(user) > 256 || strings.Contains(user, "/") || strings.IndexFunc(user, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("invalid or out-of-scope AlloyDB user")
	}
	out := Object{"cluster": parent, "user_name_digest": fmt.Sprintf("%x", sha256.Sum256([]byte(user)))}
	partial := false
	if raw, exists := d["userType"]; exists {
		kind, ok := raw.(string)
		allowed := map[string]bool{"USER_TYPE_UNSPECIFIED": true, "ALLOYDB_BUILT_IN": true, "ALLOYDB_IAM_USER": true, "ALLOYDB_IAM_GROUP": true, "ALLOYDB_IAM_GROUP_USER": true, "ALLOYDB_IAM_GROUP_SERVICE_ACCOUNT": true}
		if ok && allowed[kind] {
			out["userType"] = kind
		} else {
			partial = true
		}
	}
	if raw, exists := d["databaseRoles"]; exists {
		roles, ok := raw.([]any)
		if !ok || len(roles) > 10000 {
			partial = true
		} else {
			known := map[string]bool{"alloydbsuperuser": true, "alloydbiamuser": true, "alloydbimportexport": true, "alloydbreplica": true}
			names := []any{}
			digests := []any{}
			seen := map[string]bool{}
			for _, raw := range roles {
				role, ok := raw.(string)
				if !ok || role == "" || len(role) > 256 || strings.IndexFunc(role, unicode.IsControl) >= 0 {
					partial = true
					continue
				}
				if seen[role] {
					continue
				}
				seen[role] = true
				if known[role] {
					names = append(names, role)
				} else {
					digests = append(digests, fmt.Sprintf("%x", sha256.Sum256([]byte(role))))
				}
			}
			out["databaseRoles"] = names
			out["other_role_digests"] = digests
		}
	}
	if partial {
		return out, fmt.Errorf("some AlloyDB user fields were malformed")
	}
	return out, nil
}
