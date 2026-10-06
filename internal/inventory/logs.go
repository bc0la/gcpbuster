package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

const LogScanType = "gcpbuster.googleapis.com/LogContentScan"

// Data Access audit logs require privateLogEntries.list, which is outside the
// Viewer baseline. Access Transparency logs are excluded conservatively too.
// https://docs.cloud.google.com/logging/docs/access-control
const viewerLogExclusion = `NOT LOG_ID("cloudaudit.googleapis.com/data_access") AND NOT LOG_ID("cloudaudit.googleapis.com/access_transparency") AND NOT LOG_ID("externalaudit.googleapis.com/data_access") AND NOT LOG_ID("externalaudit.googleapis.com/access_transparency")`

// Parenthesizing an arbitrary filter isn't enough when a caller can terminate
// the expression or comment out its suffix. Accept only balanced expressions
// without comments, keeping quoted literals and their escapes intact.
func viewerLogFilter(filter string) (string, error) {
	depth, quoted, escaped := 0, false, false
	for i, ch := range filter {
		if quoted {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		switch ch {
		case '"':
			quoted = true
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", fmt.Errorf("unbalanced log filter")
			}
		case '#':
			return "", fmt.Errorf("comments are unsupported in viewer-only log filters")
		}
		if ch == '-' && i+1 < len(filter) && filter[i+1] == '-' {
			return "", fmt.Errorf("comments are unsupported in viewer-only log filters")
		}
	}
	if quoted || depth != 0 {
		return "", fmt.Errorf("unbalanced log filter")
	}
	if strings.TrimSpace(filter) == "" {
		return viewerLogExclusion, nil
	}
	return "(" + filter + ") AND " + viewerLogExclusion, nil
}

// A response from privileged credentials must not expand inspection to private
// audit logs even if the service or a test transport ignores the query filter.
// Missing/malformed names cannot establish baseline visibility and fail closed.
func viewerLogEntry(name string) (private bool, err error) {
	parts := strings.SplitN(name, "/logs/", 2)
	if len(parts) != 2 || !logScopePattern.MatchString(parts[0]) || parts[1] == "" {
		return false, fmt.Errorf("unclassifiable log entry name")
	}
	id, err := url.PathUnescape(parts[1])
	if err != nil || strings.Contains(id, "%") {
		return false, fmt.Errorf("unclassifiable log entry name")
	}
	switch strings.ToLower(id) {
	case "cloudaudit.googleapis.com/data_access", "cloudaudit.googleapis.com/access_transparency", "externalaudit.googleapis.com/data_access", "externalaudit.googleapis.com/access_transparency":
		return true, nil
	}
	return false, nil
}

type LogOptions struct {
	MaxEntries, MaxPages int
	Since, Until         time.Time
	Filter               string
}

func (o LogOptions) Validate() error {
	if o.MaxEntries <= 0 || o.MaxPages <= 0 {
		return fmt.Errorf("log entry and page limits must be positive")
	}
	if o.Since.IsZero() || !o.Until.After(o.Since) {
		return fmt.Errorf("log time window must have a start before its end")
	}
	return nil
}

// entries.list is a read operation whose API uses POST; the endpoint is fixed.
// No log write/delete/routing operations are performed.
func (c *Client) logPage(ctx context.Context, body Object) (Object, error) {
	filter, err := viewerLogFilter(Str(body["filter"]))
	if err != nil {
		return nil, err
	}
	requestBody := Object{}
	for key, value := range body {
		requestBody[key] = value
	}
	requestBody["filter"] = filter
	if err := c.requireViewerPermissions(ctx, "POST", "https://logging.googleapis.com/v2/entries:list", nil); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("cannot encode log query")
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	h := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.HTTP != nil {
		h.Transport = c.HTTP.Transport
		if c.HTTP.Timeout > 0 {
			h.Timeout = c.HTTP.Timeout
		}
	}
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://logging.googleapis.com/v2/entries:list", bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("cannot build log query")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.doRequest(h, req, attempt+1)
		if err != nil {
			return nil, fmt.Errorf("log query transport failure or cancellation")
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < 3 {
				select {
				case <-time.After(time.Duration(1<<attempt) * time.Second):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, fmt.Errorf("log query exhausted retries: HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("log query unavailable: HTTP %d", resp.StatusCode)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("log response read failed")
		}
		if len(data) > 16<<20 {
			return nil, fmt.Errorf("log response exceeded 16 MiB")
		}
		var page Object
		if json.Unmarshal(data, &page) != nil || page == nil {
			return nil, fmt.Errorf("invalid log query response")
		}
		return page, nil
	}
	return nil, fmt.Errorf("log query retry budget exhausted")
}

var logScopePattern = regexp.MustCompile(`^(projects|folders|organizations)/[A-Za-z0-9][A-Za-z0-9._:-]*$`)

func (c *Client) CollectLogs(ctx context.Context, snap *Snapshot, scopes []string, opts LogOptions) {
	if err := opts.Validate(); err != nil {
		snap.record("logs:options", 0, err)
		return
	}
	filter := fmt.Sprintf("timestamp >= %q AND timestamp < %q", opts.Since.UTC().Format(time.RFC3339Nano), opts.Until.UTC().Format(time.RFC3339Nano))
	if opts.Filter != "" {
		filter += " AND (" + opts.Filter + ")"
	}
	seenScopes := map[string]bool{}
	for _, scope := range scopes {
		if seenScopes[scope] {
			continue
		}
		seenScopes[scope] = true
		if !logScopePattern.MatchString(scope) {
			snap.record("logs:scope", 0, fmt.Errorf("invalid log resource container"))
			continue
		}
		body := Object{"resourceNames": []string{scope}, "filter": filter, "orderBy": "timestamp desc", "pageSize": min(opts.MaxEntries, 100)}
		seenPages := map[string]bool{}
		entries := 0
		inspected, excludedPrivate := 0, 0
		complete := false
		invalidEntries := false
		var matches []any
		for pageNum := 0; pageNum < opts.MaxPages; pageNum++ {
			page, err := c.logPage(ctx, body)
			if err != nil {
				snap.record("logs:"+scope, entries, err)
				break
			}
			if raw, exists := page["entries"]; exists {
				if _, ok := raw.([]any); !ok {
					snap.record("logs:"+scope, entries, fmt.Errorf("invalid log entries collection"))
					break
				}
			}
			if raw, exists := page["nextPageToken"]; exists {
				if _, ok := raw.(string); !ok {
					snap.record("logs:"+scope, entries, fmt.Errorf("invalid log pagination token"))
					break
				}
			}
			rows := List(page["entries"])
			limited := false
			for _, v := range rows {
				if entries >= opts.MaxEntries {
					limited = true
					break
				}
				entries++
				x := Obj(v)
				if x == nil {
					invalidEntries = true
					snap.record("logs:"+scope, 0, fmt.Errorf("invalid log entry"))
					continue
				}
				private, nameErr := viewerLogEntry(Str(x["logName"]))
				if nameErr != nil {
					invalidEntries = true
					snap.record("logs:"+scope, 0, nameErr)
					continue
				}
				if private {
					excludedPrivate++
					continue
				}
				inspected++
				for _, field := range []string{"textPayload", "jsonPayload", "protoPayload"} {
					if x[field] == nil {
						continue
					}
					var raw []byte
					if text, ok := x[field].(string); ok {
						raw = []byte(text)
					} else {
						raw, _ = json.Marshal(x[field])
					}
					if c.SecretCapture != nil {
						if strings.HasPrefix(scope, "projects/") && strings.HasPrefix(Str(x["logName"]), scope+"/logs/") {
							locator := Str(x["insertId"]) + "/" + Str(x["timestamp"])
							if locator != "/" {
								c.SecretCapture.Add(SecretSample{SourceType: "log_content", Resource: "//logging.googleapis.com/" + Str(x["logName"]), Path: locator + "/" + field, Data: raw})
							}
						} else {
							snap.Coverage = append(snap.Coverage, Coverage{Source: "log-secret-capture:" + scope, Status: "incomplete", Error: "Returned log payload scope was not proven to match an explicit requested project; value capture skipped."})
						}
					}
					for _, hit := range secretmatch.Text(raw, "") {
						matches = append(matches, Object{"rule": hit.Rule, "line": hit.Line, "payloadField": field, "logName": x["logName"], "timestamp": x["timestamp"], "insertId": x["insertId"]})
					}
				}
			}
			next := Str(page["nextPageToken"])
			if limited || (entries >= opts.MaxEntries && next != "") {
				snap.Coverage = append(snap.Coverage, Coverage{Source: "logs:" + scope, Status: "incomplete", Count: entries, Error: "Log entry sampling limit reached; more entries may exist in the requested time window."})
				break
			}
			if next == "" {
				complete = !invalidEntries
				if complete {
					snap.record("logs:"+scope, entries, nil)
				}
				break
			}
			if seenPages[next] {
				snap.record("logs:"+scope, entries, fmt.Errorf("repeated log pagination token"))
				break
			}
			seenPages[next] = true
			body["pageToken"] = next
			if pageNum+1 == opts.MaxPages {
				snap.Coverage = append(snap.Coverage, Coverage{Source: "logs:" + scope, Status: "incomplete", Count: entries, Error: "Log page limit reached before the time window was exhausted."})
			}
		}
		a := NewAsset("//logging.googleapis.com/"+scope+"/content-scan", LogScanType, Object{"matches": matches, "entriesInspected": inspected, "privateEntriesExcluded": excludedPrivate, "complete": complete, "since": opts.Since.UTC().Format(time.RFC3339), "until": opts.Until.UTC().Format(time.RFC3339), "customFilterApplied": opts.Filter != ""})
		a.Ancestors = []string{scope}
		snap.Assets = append(snap.Assets, a)
		snap.Coverage = append(snap.Coverage, Coverage{Source: "logs-window:" + scope, Status: "notice", Count: inspected, Error: "Only visible non-private entries in the requested time window and filter were inspected. Data Access and Access Transparency audit logs are excluded by query and response validation. A container query does not establish access to every log view or every descendant project's logs."})
	}
}
