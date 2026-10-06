package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var sinkResourcePattern = regexp.MustCompile(`^(projects|folders|organizations)/[A-Za-z0-9._:-]+/sinks/(_Default|_Required|[A-Za-z0-9][A-Za-z0-9_.-]*)$`)
var logConfigIDPattern = regexp.MustCompile(`^(_Default|_Required|[A-Za-z0-9][A-Za-z0-9_.-]*)$`)

// CollectLoggingConfig reads sink/exclusion metadata, never log entries or
// destination contents. Sink listing includes ancestor routing context.
func (c *Client) CollectLoggingConfig(ctx context.Context, snap *Snapshot, scopes []string) {
	seenScopes, seenAssets := map[string]bool{}, map[string]bool{}
	for _, scope := range scopes {
		if seenScopes[scope] {
			continue
		}
		seenScopes[scope] = true
		if !logScopePattern.MatchString(scope) {
			snap.record("logging-config:scope", 0, fmt.Errorf("invalid logging container"))
			continue
		}
		for _, kind := range []string{"sinks", "exclusions"} {
			q := url.Values{"pageSize": {"100"}}
			q.Set("fields", "exclusions(name,description,filter,disabled,createTime,updateTime),nextPageToken")
			if kind == "sinks" {
				q.Set("filter", `in_scope("ALL")`)
				q.Set("fields", "sinks(name,resourceName,destination,description,filter,disabled,includeChildren,interceptChildren,writerIdentity,createTime,updateTime,bigqueryOptions(usePartitionedTables),exclusions(name,description,filter,disabled,createTime,updateTime)),nextPageToken")
			}
			seenPages := map[string]bool{}
			count := 0
			for {
				page, err := c.get(ctx, "https://logging.googleapis.com/v2/"+scope+"/"+kind, q)
				if err != nil {
					snap.record("logging-config:"+scope+":"+kind, count, err)
					break
				}
				if page == nil {
					snap.record("logging-config:"+scope+":"+kind, count, fmt.Errorf("invalid logging configuration response"))
					break
				}
				if raw, exists := page[kind]; exists {
					if _, ok := raw.([]any); !ok {
						snap.record("logging-config:"+scope+":"+kind, count, fmt.Errorf("invalid logging configuration list"))
						break
					}
				}
				invalid := false
				for _, raw := range List(page[kind]) {
					d, projectionErr := viewerLoggingConfigProjection(Obj(raw), kind == "sinks")
					if projectionErr != nil {
						invalid = true
						continue
					}
					id := Str(d["name"])
					name := scope + "/" + kind + "/" + id
					if !logConfigIDPattern.MatchString(id) {
						invalid = true
						continue
					}
					if kind == "sinks" && Str(d["resourceName"]) != "" {
						name = Str(d["resourceName"])
						if !sinkResourcePattern.MatchString(name) || !strings.HasSuffix(name, "/sinks/"+id) {
							invalid = true
							continue
						}
					}
					if kind == "sinks" && Str(d["resourceName"]) == "" && (Bool(d["includeChildren"]) || Bool(d["interceptChildren"])) {
						invalid = true
						continue
					}
					// ALL can return ancestor sinks. Their original resourceName is
					// kept instead of mislabeling them as child-project sinks.
					assetName := "//logging.googleapis.com/" + name
					count++
					if seenAssets[assetName] {
						continue
					}
					seenAssets[assetName] = true
					typ := "LogSink"
					if kind == "exclusions" {
						typ = "LogExclusion"
					}
					a := NewAsset(assetName, "logging.googleapis.com/"+typ, d)
					a.Ancestors = []string{strings.Split(name, "/"+kind+"/")[0]}
					snap.Assets = append(snap.Assets, a)
				}
				if invalid {
					snap.record("logging-config:"+scope+":"+kind, count, fmt.Errorf("invalid logging resource identity"))
					break
				}
				if raw, exists := page["nextPageToken"]; exists {
					if _, ok := raw.(string); !ok {
						snap.record("logging-config:"+scope+":"+kind, count, fmt.Errorf("invalid logging pagination token"))
						break
					}
				}
				next := Str(page["nextPageToken"])
				if next == "" {
					snap.record("logging-config:"+scope+":"+kind, count, nil)
					break
				}
				if seenPages[next] {
					snap.record("logging-config:"+scope+":"+kind, count, fmt.Errorf("repeated logging pagination token"))
					break
				}
				seenPages[next] = true
				q.Set("pageToken", next)
			}
		}
	}
}
