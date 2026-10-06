package inventory

import (
	"fmt"
	"net/url"
	"regexp"
)

var viewerSQLMetadataPath = regexp.MustCompile(`^/v1/projects/[^/:]+/instances/[^/:]+/(users|databases|backupRuns)(/[0-9]+)?$`)

// Enrichment reads retain only reviewed control-plane metadata, not passwords,
// backup descriptions/error bodies or arbitrary fields. Instance configuration
// collection has its own projection and does not enter this guard.
func viewerSQLMetadataQuery(method string, u *url.URL, query url.Values) error {
	parts := viewerSQLMetadataPath.FindStringSubmatch(u.Path)
	if len(parts) == 0 {
		return nil
	}
	fields := ""
	paginated := false
	switch parts[1] {
	case "users":
		fields = viewerSQLUserFields
	case "databases":
		fields = viewerSQLDatabaseFields
	case "backupRuns":
		fields = viewerSQLBackupListFields
		paginated = parts[2] == ""
		if !paginated {
			fields = viewerSQLBackupFields
		}
	}
	if method != "GET" || u.RawPath != "" || query.Get("fields") != fields || len(query["fields"]) != 1 || (parts[1] != "backupRuns" && parts[2] != "") {
		return fmt.Errorf("viewer-only policy: unreviewed Cloud SQL metadata projection")
	}
	if paginated && query.Get("maxResults") != "100" {
		return fmt.Errorf("viewer-only policy: unreviewed Cloud SQL backup pagination")
	}
	for key, values := range query {
		if len(values) != 1 || (key != "fields" && !(paginated && (key == "maxResults" || key == "pageToken"))) {
			return fmt.Errorf("viewer-only policy: unreviewed Cloud SQL metadata query")
		}
	}
	return nil
}
