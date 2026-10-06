package inventory

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const viewerLogBucketFields = "buckets(name,retentionDays,locked,lifecycleState,analyticsEnabled,createTime,updateTime,restrictedFields,cmekSettings(kmsKeyName,kmsKeyVersionName,serviceAccountId)),nextPageToken"

// CollectViewerLogBuckets complements the opt-in sink/exclusion collector.
// The documented locations/- wildcard lists buckets across all locations.
// This reads configuration only: never entries, views, analytics or exports.
func (c *Client) CollectViewerLogBuckets(ctx context.Context, out *Snapshot, scopes []string) {
	seenScopes := map[string]bool{}
	for _, scope := range scopes {
		if !logScopePattern.MatchString(scope) {
			out.record("viewer-log-buckets:identity", 0, fmt.Errorf("invalid Logging container"))
			continue
		}
		canonical, aliases, err := c.viewerLogBucketScope(ctx, out, scope)
		if err != nil {
			out.record("viewer-log-buckets:"+scope, 0, err)
			continue
		}
		if seenScopes[canonical] {
			continue
		}
		seenScopes[canonical] = true
		start := len(out.Assets)
		seen := map[string]bool{}
		partial := false
		err = c.viewerPages(ctx, "https://logging.googleapis.com/v2/"+canonical+"/locations/-/buckets", url.Values{"pageSize": {"100"}, "fields": {viewerLogBucketFields}}, func(page Object) error {
			rows, err := viewerRows(page, "buckets")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				d := Obj(raw)
				p := strings.Split(Str(d["name"]), "/")
				if len(p) != 6 || !aliases[p[0]+"/"+p[1]] || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[4] != "buckets" || !logConfigIDPattern.MatchString(p[5]) {
					partial = true
					continue
				}
				name := canonical + "/locations/" + p[3] + "/buckets/" + p[5]
				if seen[name] {
					continue
				}
				clean, err := viewerLogBucketProjection(d)
				if err != nil {
					partial = true
					continue
				}
				clean["name"] = name
				a := NewAsset("//logging.googleapis.com/"+name, "logging.googleapis.com/LogBucket", clean)
				a.Ancestors = []string{canonical}
				a.Resource.Location = p[3]
				out.Assets = append(out.Assets, a)
				seen[name] = true
			}
			unreachable, err := viewerBuildWorkflowUnreachable(page)
			partial = partial || unreachable
			return err
		})
		if err == nil && partial {
			err = fmt.Errorf("Logging bucket inventory contains invalid or unreachable records")
		}
		out.record("viewer-log-buckets:"+canonical, len(out.Assets)-start, err)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-log-buckets:limitations", Status: "notice", Error: "Bucket configuration only across requested/discovered containers and all API-supported locations. IAM denials on parent folders/organizations remain coverage failures. Configured retention, locks and CMEK do not prove ingestion, historical data retention, key usability or effective log access. No log entries, queries, exports, storage contents or analytics are read."})
}

func (c *Client) viewerLogBucketScope(ctx context.Context, out *Snapshot, scope string) (string, map[string]bool, error) {
	aliases := map[string]bool{scope: true}
	if !strings.HasPrefix(scope, "projects/") {
		return scope, aliases, nil
	}
	for _, a := range out.Assets {
		if a.Type != "cloudresourcemanager.googleapis.com/Project" {
			continue
		}
		d := a.Resource.Data
		number, id := Str(d["name"]), Str(d["projectId"])
		if projectNumberPattern.MatchString(number) && viewerResourceName.MatchString(id) && (scope == number || scope == "projects/"+id) {
			aliases[number], aliases["projects/"+id] = true, true
			return number, aliases, nil
		}
	}
	if projectNumberPattern.MatchString(scope) {
		return scope, aliases, nil
	}
	d, err := c.get(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+scope, nil)
	if err != nil {
		return "", nil, err
	}
	number := Str(d["name"])
	if !projectNumberPattern.MatchString(number) || "projects/"+Str(d["projectId"]) != scope {
		return "", nil, fmt.Errorf("mismatched Logging project identity")
	}
	aliases[number] = true
	return number, aliases, nil
}

func viewerLogBucketProjection(d Object) (Object, error) {
	clean := Object{}
	for _, field := range []string{"name", "lifecycleState", "createTime", "updateTime"} {
		if raw, exists := d[field]; exists {
			v, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("malformed Logging bucket metadata")
			}
			if strings.HasSuffix(field, "Time") && v != "" {
				if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
					return nil, fmt.Errorf("malformed Logging bucket timestamp")
				}
			}
			clean[field] = v
		}
	}
	for _, field := range []string{"locked", "analyticsEnabled"} {
		if raw, exists := d[field]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, fmt.Errorf("malformed Logging bucket boolean")
			}
			clean[field] = raw
		}
	}
	if raw, exists := d["retentionDays"]; exists {
		n, ok := raw.(float64)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 2147483647 || math.Trunc(n) != n {
			return nil, fmt.Errorf("malformed Logging bucket retention")
		}
		clean["retentionDays"] = n
	}
	if _, exists := d["restrictedFields"]; exists {
		rows, err := viewerRows(d, "restrictedFields")
		if err != nil {
			return nil, err
		}
		for _, raw := range rows {
			if _, ok := raw.(string); !ok {
				return nil, fmt.Errorf("malformed Logging restricted field")
			}
		}
		clean["restrictedFields"] = rows
	}
	if raw, exists := d["cmekSettings"]; exists {
		cmek := Obj(raw)
		if cmek == nil {
			return nil, fmt.Errorf("malformed Logging CMEK config")
		}
		values := Object{}
		for _, field := range []string{"kmsKeyName", "kmsKeyVersionName", "serviceAccountId"} {
			if v, exists := cmek[field]; exists {
				if _, ok := v.(string); !ok {
					return nil, fmt.Errorf("malformed Logging CMEK reference")
				}
				values[field] = v
			}
		}
		clean["cmekSettings"] = values
	}
	return clean, nil
}

// viewerLoggingConfigProjection retains routing/retention configuration, not
// arbitrary response fields. Embedded exclusions use the same strict schema.
func viewerLoggingConfigProjection(d Object, sink bool) (Object, error) {
	if d == nil {
		return nil, fmt.Errorf("missing Logging configuration")
	}
	clean := Object{}
	stringsAllowed := []string{"name", "description", "filter", "createTime", "updateTime"}
	boolsAllowed := []string{"disabled"}
	if sink {
		stringsAllowed = append(stringsAllowed, "resourceName", "destination", "writerIdentity")
		boolsAllowed = append(boolsAllowed, "includeChildren", "interceptChildren")
	}
	for _, field := range stringsAllowed {
		if raw, exists := d[field]; exists {
			v, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("malformed Logging configuration string")
			}
			if strings.HasSuffix(field, "Time") && v != "" {
				if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
					return nil, fmt.Errorf("malformed Logging configuration timestamp")
				}
			}
			clean[field] = v
		}
	}
	for _, field := range boolsAllowed {
		if raw, exists := d[field]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, fmt.Errorf("malformed Logging configuration boolean")
			}
			clean[field] = raw
		}
	}
	if sink {
		if raw, exists := d["bigqueryOptions"]; exists {
			options := Obj(raw)
			if options == nil {
				return nil, fmt.Errorf("malformed Logging BigQuery options")
			}
			selected := Object{}
			if raw, exists := options["usePartitionedTables"]; exists {
				if _, ok := raw.(bool); !ok {
					return nil, fmt.Errorf("malformed Logging BigQuery option")
				}
				selected["usePartitionedTables"] = raw
			}
			clean["bigqueryOptions"] = selected
		}
		if _, exists := d["exclusions"]; exists {
			rows, err := viewerRows(d, "exclusions")
			if err != nil {
				return nil, err
			}
			exclusions := []any{}
			for _, raw := range rows {
				e, err := viewerLoggingConfigProjection(Obj(raw), false)
				if err != nil || !logConfigIDPattern.MatchString(Str(e["name"])) {
					return nil, fmt.Errorf("malformed Logging sink exclusion")
				}
				exclusions = append(exclusions, e)
			}
			clean["exclusions"] = exclusions
		}
	}
	return clean, nil
}
