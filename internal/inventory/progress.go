package inventory

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// ProgressEvent describes collection activity without response bodies, tokens,
// query parameters, or resource URLs. Callbacks must not call ReportProgress.
type ProgressEvent struct {
	Phase, Scope, Collector, Status              string
	Count                                        int
	Failures                                     int
	Duration                                     time.Duration
	Method, Host                                 string
	Attempt, HTTPStatus                          int
	Total, Queued, Running, Completed, Cancelled int
	Reason                                       string // Allowlisted API error reason only; never a response message.
	RetryAfter                                   time.Duration
}

// ReportProgress serializes callbacks even when collectors run concurrently.
func (c *Client) ReportProgress(event ProgressEvent) {
	if c.Progress == nil {
		return
	}
	c.progressMu.Lock()
	defer c.progressMu.Unlock()
	c.Progress(event)
}

func (c *Client) emitProgress(event ProgressEvent) { c.ReportProgress(event) }

func (c *Client) doRequest(h *http.Client, req *http.Request, attempt int) (*http.Response, error) {
	// Transport timing ends when headers arrive (or the transport fails).
	// Collector completion includes reading and processing the response body.
	// Host is a service category, never an arbitrary hostname: Data Fusion
	// hosts contain instance names, and test/custom transports may use secrets.
	host := "other"
	if name := req.URL.Hostname(); strings.HasSuffix(name, ".googleapis.com") {
		host = "googleapis.com"
		switch name {
		case "iam.googleapis.com", "cloudresourcemanager.googleapis.com", "cloudasset.googleapis.com", "compute.googleapis.com", "logging.googleapis.com", "run.googleapis.com", "cloudfunctions.googleapis.com", "secretmanager.googleapis.com", "parametermanager.googleapis.com", "apigee.googleapis.com", "sqladmin.googleapis.com", "storage.googleapis.com", "datafusion.googleapis.com", "dns.googleapis.com", "cloudbuild.googleapis.com", "aiplatform.googleapis.com", "workflows.googleapis.com":
			host = name
		}
	} else if strings.HasSuffix(req.URL.Hostname(), ".datafusion.googleusercontent.com") {
		host = "datafusion.googleusercontent.com"
	}
	counter, _ := req.Context().Value(requestAttemptKey{}).(*atomic.Int32)
	if counter == nil {
		counter = new(atomic.Int32)
		counter.Store(int32(attempt - 1))
	}
	budgetEnd := time.Now().Add(rateLimitWaitBudget)
	retryable := retryableViewerRequest(req)
	current := req
	for {
		if err := c.waitServiceCooldown(req.Context(), req.URL.Hostname(), budgetEnd); err != nil {
			if current.Body != nil {
				current.Body.Close()
			}
			return nil, err
		}
		if counter.Load() >= requestAttemptLimit {
			return nil, fmt.Errorf("request retry budget exhausted")
		}
		n := int(counter.Add(1))
		event := ProgressEvent{Phase: "request", Status: "started", Method: req.Method, Host: host, Attempt: n}
		c.ReportProgress(event)
		start := time.Now()
		resp, err := h.Do(current)
		event.Duration = time.Since(start)
		event.Status = "completed"
		if err != nil {
			event.Status = "failed"
		} else {
			event.HTTPStatus = resp.StatusCode
			if resp.StatusCode >= 400 {
				event.Status = "failed"
			}
		}
		if err == nil && resp.StatusCode == http.StatusTooManyRequests {
			event.Reason = "RATE_LIMITED"
			until := time.Now().Add(retryAfterDelay(resp.Header.Get("Retry-After"), time.Now(), n))
			event.RetryAfter = time.Until(until)
			c.setServiceCooldown(req.URL.Hostname(), until)
			if retryable && n < requestAttemptLimit && !until.After(budgetEnd) {
				event.Status = "retrying"
				c.ReportProgress(event)
				resp.Body.Close()
				current = req.Clone(req.Context())
				if req.GetBody != nil {
					current.Body, err = req.GetBody()
					if err != nil {
						return nil, fmt.Errorf("cannot replay read-only request body")
					}
				}
				continue
			}
		}
		c.ReportProgress(event)
		return resp, err
	}
}
