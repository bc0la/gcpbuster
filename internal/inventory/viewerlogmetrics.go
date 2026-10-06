package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerLogMetricFields = "metrics(name,resourceName,disabled,createTime,updateTime),nextPageToken"

var viewerLogMetricID = regexp.MustCompile(`^[A-Za-z0-9_.,+!*'()%\-][A-Za-z0-9_.,+!*'()%/\-]{0,99}$`)

// CollectViewerLogMetrics lists configuration only. It never reads time series,
// log entries, extractor expressions, or follows metric identifiers as URLs.
func (c *Client) CollectViewerLogMetrics(ctx context.Context, out *Snapshot, scopes []string) {
	seenScopes, seenMetrics := map[string]bool{}, map[string]bool{}
	for _, scope := range scopes {
		if !logScopePattern.MatchString(scope) {
			out.record("viewer-log-metrics:scope", 0, fmt.Errorf("invalid Logging scope"))
			continue
		}
		if !strings.HasPrefix(scope, "projects/") {
			continue
		}
		canonical, aliases, err := c.viewerLogBucketScope(ctx, out, scope)
		if err != nil {
			out.record("viewer-log-metrics:"+scope, 0, err)
			continue
		}
		if seenScopes[canonical] {
			continue
		}
		seenScopes[canonical] = true
		start, partial := len(out.Assets), false
		err = c.viewerPages(ctx, "https://logging.googleapis.com/v2/"+canonical+"/metrics", url.Values{"pageSize": {"100"}, "fields": {viewerLogMetricFields}}, func(page Object) error {
			rows, err := viewerRows(page, "metrics")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				d := Obj(raw)
				id := Str(d["name"])
				if !viewerLogMetricID.MatchString(id) {
					partial = true
					continue
				}
				clean := Object{"name": id}
				valid := true
				if r, exists := d["resourceName"]; exists {
					p := strings.SplitN(Str(r), "/", 4)
					if len(p) != 4 || !aliases[p[0]+"/"+p[1]] || p[2] != "metrics" {
						valid = false
					} else {
						decoded, e := url.PathUnescape(p[3])
						if e != nil || decoded != id {
							valid = false
						}
					}
				}
				if v, exists := d["disabled"]; exists {
					if _, ok := v.(bool); !ok {
						valid = false
					} else {
						clean["disabled"] = v
					}
				}
				for _, field := range []string{"createTime", "updateTime"} {
					if v, exists := d[field]; exists {
						str, ok := v.(string)
						if _, e := time.Parse(time.RFC3339Nano, str); !ok || e != nil {
							valid = false
						} else {
							clean[field] = str
						}
					}
				}
				if !valid {
					partial = true
					continue
				}
				name := canonical + "/metrics/" + url.PathEscape(id)
				if seenMetrics[name] {
					continue
				}
				seenMetrics[name] = true
				clean["resourceName"] = name
				a := NewAsset("//logging.googleapis.com/"+name, "logging.googleapis.com/LogMetric", clean)
				a.Ancestors = []string{canonical}
				out.Assets = append(out.Assets, a)
			}
			unreachable, e := viewerBuildWorkflowUnreachable(page)
			partial = partial || unreachable
			return e
		})
		if err == nil && partial {
			err = fmt.Errorf("some LogMetric metadata was malformed or unavailable")
		}
		out.record("viewer-log-metrics:"+canonical, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-log-metrics:limitations", Status: "notice", Error: "Project user-defined metric configuration only. Disabled metadata does not establish missing alerts, log loss, historical activity or malicious intent. No log entries, time series, queries, extractors or metric updates are accessed."})
}
