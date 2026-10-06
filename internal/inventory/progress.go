package inventory

import (
	"net/http"
	"strings"
	"time"
)

// ProgressEvent describes collection activity without response bodies, tokens,
// query parameters, or resource URLs. Callbacks must not call ReportProgress.
type ProgressEvent struct {
	Phase, Scope, Collector, Status string
	Count                           int
	Failures                        int
	Duration                        time.Duration
	Method, Host                    string
	Attempt, HTTPStatus             int
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
	event := ProgressEvent{Phase: "request", Status: "started", Method: req.Method, Host: host, Attempt: attempt}
	c.ReportProgress(event)
	start := time.Now()
	resp, err := h.Do(req)
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
	c.ReportProgress(event)
	return resp, err
}
