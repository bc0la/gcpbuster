package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var viewerLocation = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

// CollectViewerSQLGKE reads control-plane configurations only. It never connects
// to a SQL database, Kubernetes endpoint, kubelet, or obtains cluster credentials.
func (c *Client) CollectViewerSQLGKE(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-sql-gke:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	c.viewerSQL(ctx, out, projectID, number)
	c.CollectViewerSQLUsers(ctx, out, projectID, number)
	c.CollectViewerSQLDatabases(ctx, out, projectID, number)
	c.CollectViewerSQLBackups(ctx, out, projectID, number)
	c.viewerGKE(ctx, out, projectID, number)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-sql-gke:limitations:" + projectID, Status: "notice", Error: "Cloud SQL and GKE control-plane configuration only. Database contents/passwords, Kubernetes workloads/RBAC/secrets, kubelet reachability and effective runtime authorization are not assessed by these reads."})
}

func (c *Client) viewerSQL(ctx context.Context, out *Snapshot, projectID, number string) {
	start := len(out.Assets)
	partial := false
	err := c.viewerPages(ctx, "https://sqladmin.googleapis.com/v1/projects/"+projectID+"/instances", url.Values{"maxResults": {"1000"}}, func(page Object) error {
		rows, err := viewerRows(page, "items")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !viewerResourceName.MatchString(name) || Str(d["project"]) != projectID {
				partial = true
				continue
			}
			path := "projects/" + projectID + "/instances/" + name
			if link := Str(d["selfLink"]); link != "" && link != "https://sqladmin.googleapis.com/v1/"+path && link != "https://sqladmin.googleapis.com/sql/v1beta4/"+path && link != "https://sqladmin.googleapis.com/sql/v1/"+path {
				partial = true
				continue
			}
			// Cloud SQL's CAI resource hostname differs from its API/type name.
			a := NewAsset("//cloudsql.googleapis.com/"+path, "sqladmin.googleapis.com/Instance", d)
			a.Ancestors = []string{number}
			a.Resource.Location = Str(d["region"])
			c.SecretCapture.captureSQLFlags(a)
			out.Assets = append(out.Assets, a)
		}
		warnings, err := viewerRows(page, "warnings")
		if err != nil {
			return err
		}
		if len(warnings) > 0 {
			partial = true
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("Cloud SQL returned warnings or invalid identities; instance inventory may be incomplete")
	}
	out.record("viewer-sql-instances:"+projectID, len(out.Assets)-start, err)
}

func (c *Client) viewerGKE(ctx context.Context, out *Snapshot, projectID, number string) {
	start := len(out.Assets)
	page, err := c.get(ctx, "https://container.googleapis.com/v1/projects/"+projectID+"/locations/-/clusters", nil)
	if err == nil {
		err = viewerGKEPage(out, page, projectID, number)
	}
	out.record("viewer-gke-clusters:"+projectID, len(out.Assets)-start, err)
}

func viewerGKEPage(out *Snapshot, page Object, projectID, number string) error {
	if page == nil {
		return fmt.Errorf("invalid GKE cluster list response")
	}
	rows, err := viewerRows(page, "clusters")
	if err != nil {
		return err
	}
	partial := false
	for _, raw := range rows {
		d := Obj(raw)
		name := Str(d["name"])
		location := Str(d["location"])
		if location == "" {
			location = Str(d["zone"])
		}
		if !viewerResourceName.MatchString(name) || !viewerLocation.MatchString(location) {
			partial = true
			continue
		}
		if link := Str(d["selfLink"]); link != "" {
			u, err := url.Parse(link)
			if err != nil || u.Scheme != "https" || u.Host != "container.googleapis.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				partial = true
				continue
			}
			valid := false
			for _, project := range []string{projectID, strings.TrimPrefix(number, "projects/")} {
				for _, segment := range []string{"locations", "zones"} {
					if u.Path == "/v1/projects/"+project+"/"+segment+"/"+location+"/clusters/"+name {
						valid = true
					}
				}
			}
			if !valid {
				partial = true
				continue
			}
		}
		a := NewAsset("//container.googleapis.com/projects/"+projectID+"/locations/"+location+"/clusters/"+name, "container.googleapis.com/Cluster", d)
		a.Ancestors = []string{number}
		a.Resource.Location = location
		out.Assets = append(out.Assets, a)
	}
	// This API is not paginated; an unexpected continuation must never be
	// interpreted as a complete result or sent as an unsupported pageToken.
	if raw, exists := page["nextPageToken"]; exists && raw != "" {
		return fmt.Errorf("unexpected GKE pagination response")
	}
	for _, field := range []string{"missingZones", "unreachable"} {
		missing, err := viewerRows(page, field)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			return fmt.Errorf("GKE inventory contains unreachable or missing locations")
		}
	}
	if partial {
		return fmt.Errorf("some GKE cluster identities were malformed or out of scope")
	}
	return nil
}
