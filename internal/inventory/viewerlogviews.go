package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const viewerLogViewFields = "views(name,description,createTime,updateTime,filter),nextPageToken"

var viewerLogViewID = regexp.MustCompile(`^(_AllLogs|_Default|[A-Za-z0-9][A-Za-z0-9_.-]*)$`)

// CollectViewerLogViews reads metadata and direct IAM policies only, on buckets
// already discovered within explicitly selected scopes. No view entries are read.
func (c *Client) CollectViewerLogViews(ctx context.Context, out *Snapshot, scopes []string) {
	aliases := map[string]string{}
	for _, scope := range scopes {
		if !logScopePattern.MatchString(scope) {
			out.record("viewer-log-views:scope", 0, fmt.Errorf("invalid Logging scope"))
			continue
		}
		canonical, known, err := c.viewerLogBucketScope(ctx, out, scope)
		if err != nil {
			out.record("viewer-log-views:scope:"+scope, 0, err)
			continue
		}
		for alias := range known {
			aliases[alias] = canonical
		}
	}
	assets := append([]Asset(nil), out.Assets...)
	seenBuckets, seenViews := map[string]bool{}, map[string]bool{}
	for _, bucket := range assets {
		if bucket.Type != "logging.googleapis.com/LogBucket" {
			continue
		}
		const prefix = "//logging.googleapis.com/"
		name := strings.TrimPrefix(bucket.Name, prefix)
		parts := strings.Split(name, "/")
		if len(parts) < 2 || aliases[strings.Join(parts[:2], "/")] == "" {
			continue
		}
		canonical, err := viewerLogViewResource(name, aliases, false)
		dataName, dataErr := viewerLogViewResource(Str(bucket.Resource.Data["name"]), aliases, false)
		if !strings.HasPrefix(bucket.Name, prefix) || err != nil || dataErr != nil || canonical != dataName || (bucket.Resource.Location != "" && bucket.Resource.Location != strings.Split(canonical, "/")[3]) {
			out.record("viewer-log-views:bucket-identity", 0, fmt.Errorf("invalid or mismatched Logging bucket identity"))
			continue
		}
		if seenBuckets[canonical] {
			continue
		}
		seenBuckets[canonical] = true
		start, partial := len(out.Assets), false
		err = c.viewerPages(ctx, "https://logging.googleapis.com/v2/"+canonical+"/views", url.Values{"pageSize": {"100"}, "fields": {viewerLogViewFields}}, func(page Object) error {
			rows, err := viewerRows(page, "views")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				d := Obj(raw)
				view, err := viewerLogViewResource(Str(d["name"]), aliases, true)
				if err != nil || !strings.HasPrefix(view, canonical+"/views/") {
					partial = true
					continue
				}
				clean := Object{"name": view}
				valid := true
				for _, field := range []string{"description", "createTime", "updateTime", "filter"} {
					if value, exists := d[field]; exists {
						if _, ok := value.(string); !ok {
							valid = false
						} else {
							if field == "createTime" || field == "updateTime" {
								if _, err := time.Parse(time.RFC3339Nano, value.(string)); err != nil {
									valid = false
								}
							}
							clean[field] = value
						}
					}
				}
				if !valid {
					partial = true
					continue
				}
				if seenViews[view] {
					continue
				}
				seenViews[view] = true
				a := NewAsset("//logging.googleapis.com/"+view, "logging.googleapis.com/LogView", clean)
				a.Ancestors = []string{strings.Join(strings.Split(view, "/")[:2], "/")}
				a.Resource.Location = strings.Split(view, "/")[3]
				policy, policyErr := c.readIAMPolicy(ctx, "https://logging.googleapis.com/v2/"+view+":getIamPolicy")
				if policyErr == nil {
					a.IAM, policyErr = viewerLogViewPolicy(policy)
				}
				count := 0
				if policyErr == nil {
					count = 1
				} else {
					partial = true
				}
				out.record("viewer-log-view-iam:"+view, count, policyErr)
				out.Assets = append(out.Assets, a)
			}
			unreachable, err := viewerBuildWorkflowUnreachable(page)
			partial = partial || unreachable
			return err
		})
		if err == nil && partial {
			err = fmt.Errorf("some LogView metadata or direct policies were unavailable or malformed")
		}
		out.record("viewer-log-views:"+canonical, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-log-views:limitations", Status: "notice", Error: "Views on discovered buckets within selected scopes only; missing or denied bucket inventory limits coverage. View filters and conditional direct IAM grants are retained but not evaluated. Inherited access, deny, private-log access, field restrictions and effective authorization are not resolved. No log entries, queries, exports or analytics are read."})
}

func viewerLogViewResource(name string, aliases map[string]string, view bool) (string, error) {
	p := strings.Split(name, "/")
	want := 6
	if view {
		want = 8
	}
	if len(p) != want {
		return "", fmt.Errorf("invalid Logging resource name")
	}
	canonical := aliases[p[0]+"/"+p[1]]
	if canonical == "" || !logScopePattern.MatchString(canonical) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[4] != "buckets" || !logConfigIDPattern.MatchString(p[5]) {
		return "", fmt.Errorf("invalid or out-of-scope Logging resource")
	}
	if view && (p[6] != "views" || !viewerLogViewID.MatchString(p[7])) {
		return "", fmt.Errorf("invalid LogView identity")
	}
	return canonical + "/" + strings.Join(p[2:], "/"), nil
}

func viewerLogViewPolicy(policy Object) (Object, error) {
	if err := viewerValidateKeyPolicy(policy); err != nil {
		return nil, fmt.Errorf("invalid LogView IAM policy")
	}
	clean := Object{}
	for _, field := range []string{"version", "etag"} {
		if value, exists := policy[field]; exists {
			if field == "etag" {
				if _, ok := value.(string); !ok {
					return nil, fmt.Errorf("malformed LogView IAM etag")
				}
			}
			clean[field] = value
		}
	}
	if _, exists := policy["bindings"]; exists {
		bindings := []any{}
		for _, raw := range List(policy["bindings"]) {
			bind := Obj(raw)
			row := viewerConfigProjection(bind, "role", "members")
			if rawCondition, exists := bind["condition"]; exists {
				condition := Obj(rawCondition)
				projected := Object{}
				for _, field := range []string{"expression", "title", "description", "location"} {
					if value, exists := condition[field]; exists {
						if _, ok := value.(string); !ok {
							return nil, fmt.Errorf("malformed LogView IAM condition")
						}
						projected[field] = value
					}
				}
				row["condition"] = projected
			}
			bindings = append(bindings, row)
		}
		clean["bindings"] = bindings
	}
	return clean, nil
}
