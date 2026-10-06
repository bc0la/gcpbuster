package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerLogLinkFields = "links(name,createTime,lifecycleState,bigqueryDataset(datasetId)),nextPageToken"

var viewerLogLinkID = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var viewerLogLinkDataset = regexp.MustCompile(`^bigquery\.googleapis\.com/projects/([A-Za-z0-9][A-Za-z0-9._:-]*)/datasets/([A-Za-z0-9_]+)$`)

// CollectViewerLogLinks inventories configuration only. It never queries the
// dataset or follows the returned BigQuery reference.
func (c *Client) CollectViewerLogLinks(ctx context.Context, out *Snapshot, scopes []string) {
	aliases := map[string]string{}
	for _, scope := range scopes {
		if !logScopePattern.MatchString(scope) {
			out.record("viewer-log-links:scope", 0, fmt.Errorf("invalid Logging scope"))
			continue
		}
		canonical, known, err := c.viewerLogBucketScope(ctx, out, scope)
		if err != nil {
			out.record("viewer-log-links:scope:"+scope, 0, err)
			continue
		}
		for alias := range known {
			aliases[alias] = canonical
		}
	}
	assets := append([]Asset(nil), out.Assets...)
	seenBuckets, seenLinks := map[string]bool{}, map[string]bool{}
	for _, bucket := range assets {
		if bucket.Type != "logging.googleapis.com/LogBucket" {
			continue
		}
		const prefix = "//logging.googleapis.com/"
		name := strings.TrimPrefix(bucket.Name, prefix)
		p := strings.Split(name, "/")
		if len(p) < 2 || aliases[strings.Join(p[:2], "/")] == "" {
			continue
		}
		canonical, err := viewerLogViewResource(name, aliases, false)
		dataName, dataErr := viewerLogViewResource(Str(bucket.Resource.Data["name"]), aliases, false)
		if !strings.HasPrefix(bucket.Name, prefix) || err != nil || dataErr != nil || canonical != dataName || (bucket.Resource.Location != "" && bucket.Resource.Location != strings.Split(canonical, "/")[3]) {
			out.record("viewer-log-links:bucket-identity", 0, fmt.Errorf("invalid or mismatched Logging bucket identity"))
			continue
		}
		if seenBuckets[canonical] {
			continue
		}
		seenBuckets[canonical] = true
		start, partial := len(out.Assets), false
		err = c.viewerPages(ctx, "https://logging.googleapis.com/v2/"+canonical+"/links", url.Values{"pageSize": {"100"}, "fields": {viewerLogLinkFields}}, func(page Object) error {
			rows, err := viewerRows(page, "links")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				d := Obj(raw)
				parts := strings.Split(Str(d["name"]), "/")
				if len(parts) != 8 || parts[6] != "links" || !viewerLogLinkID.MatchString(parts[7]) {
					partial = true
					continue
				}
				parent, err := viewerLogViewResource(strings.Join(parts[:6], "/"), aliases, false)
				if err != nil || parent != canonical {
					partial = true
					continue
				}
				link := canonical + "/links/" + parts[7]
				clean := Object{"name": link}
				valid := true
				for _, field := range []string{"createTime", "lifecycleState"} {
					if value, exists := d[field]; exists {
						str, ok := value.(string)
						if !ok {
							valid = false
							continue
						}
						if field == "createTime" {
							if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
								valid = false
							}
						}
						if field == "lifecycleState" && str != "LIFECYCLE_STATE_UNSPECIFIED" && str != "ACTIVE" && str != "DELETE_REQUESTED" && str != "UPDATING" && str != "CREATING" && str != "FAILED" {
							valid = false
						}
						clean[field] = str
					}
				}
				if value, exists := d["bigqueryDataset"]; exists {
					dataset := Obj(value)
					id := Str(dataset["datasetId"])
					matches := viewerLogLinkDataset.FindStringSubmatch(id)
					if matches == nil || matches[2] != parts[7] {
						valid = false
					} else {
						// The API promises the same project; accept only already-resolved aliases.
						if strings.HasPrefix(canonical, "projects/") && aliases["projects/"+matches[1]] != strings.Join(strings.Split(canonical, "/")[:2], "/") {
							valid = false
						}
						clean["bigqueryDataset"] = Object{"datasetId": id}
					}
				}
				if !valid {
					partial = true
					continue
				}
				if seenLinks[link] {
					continue
				}
				seenLinks[link] = true
				a := NewAsset("//logging.googleapis.com/"+link, "logging.googleapis.com/Link", clean)
				a.Ancestors = []string{strings.Join(strings.Split(canonical, "/")[:2], "/")}
				a.Resource.Location = strings.Split(canonical, "/")[3]
				out.Assets = append(out.Assets, a)
			}
			unreachable, err := viewerBuildWorkflowUnreachable(page)
			partial = partial || unreachable
			return err
		})
		if err == nil && partial {
			err = fmt.Errorf("some Logging link metadata was unavailable or malformed")
		}
		out.record("viewer-log-links:"+canonical, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-log-links:limitations", Status: "notice", Error: "Links on discovered buckets in explicitly selected scopes only; missing bucket inventory limits coverage. Dataset references are configuration, not proof of effective access or data exposure. No BigQuery queries, rows, log contents, exports or link mutations are performed."})
}
