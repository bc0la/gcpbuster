package inventory

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"0", 0}, {"12", 12 * time.Second},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{now.Add(-time.Second).Format(http.TimeFormat), 0},
		{"9223372036854775807", time.Duration(1<<63 - 1)},
	} {
		if got := retryAfterDelay(tc.value, now, 1); got != tc.want {
			t.Fatalf("%s: %v", tc.value, got)
		}
	}
	for attempt := 1; attempt <= 4; attempt++ {
		base := time.Second << (attempt - 1)
		for i := 0; i < 20; i++ {
			if got := retryAfterDelay("invalid secret-header", now, attempt); got < base || got > base+base/2 {
				t.Fatal(got)
			}
		}
	}
}

func TestRateLimitRetriesBoundedAndVisible(t *testing.T) {
	for _, successes := range []bool{true, false} {
		calls := 0
		var events []ProgressEvent
		c := &Client{Progress: func(e ProgressEvent) { events = append(events, e) }}
		h := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			if successes && calls == 3 {
				return response(200, `{}`), nil
			}
			r := response(429, `PRIVATE`)
			r.Header.Set("Retry-After", "0")
			return r, nil
		})}
		req, _ := http.NewRequest("GET", "https://sqladmin.googleapis.com/v1/projects/demo/instances", nil)
		resp, err := c.doRequest(h, req, 1)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 4
		if successes {
			want = 3
		}
		if calls != want || len(events) != want*2 {
			t.Fatal(calls, events)
		}
		for i, e := range events {
			if e.Attempt != i/2+1 {
				t.Fatal(events)
			}
			if i%2 == 1 && e.HTTPStatus == 429 && e.Reason != "RATE_LIMITED" {
				t.Fatal(e)
			}
		}
	}
}

func TestRateLimitReadOnlyPolicyBodyReplay(t *testing.T) {
	c := &Client{}
	calls := 0
	h := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"options":{"requestedPolicyVersion":3}}` {
			t.Fatal(string(body))
		}
		if calls == 1 {
			resp := response(429, `PRIVATE`)
			resp.Header.Set("Retry-After", "0")
			return resp, nil
		}
		return response(200, `{}`), nil
	})}
	req, _ := http.NewRequest("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/demo:getIamPolicy", strings.NewReader(`{"options":{"requestedPolicyVersion":3}}`))
	resp, err := c.doRequest(h, req, 1)
	if err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
	resp.Body.Close()
}

func TestRateLimitNeverRetriesUnknownOrWriteRequests(t *testing.T) {
	for _, tc := range []struct{ method, url string }{
		{"POST", "https://sqladmin.googleapis.com/v1/projects/demo/instances"},
		{"DELETE", "https://sqladmin.googleapis.com/v1/projects/demo/instances/db"},
		{"GET", "https://unknown.example/private"},
	} {
		calls := 0
		c := &Client{}
		h := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			r := response(429, `PRIVATE`)
			r.Header.Set("Retry-After", "0")
			return r, nil
		})}
		req, _ := http.NewRequest(tc.method, tc.url, nil)
		resp, err := c.doRequest(h, req, 1)
		if err != nil || calls != 1 {
			t.Fatal(tc, calls, err)
		}
		resp.Body.Close()
	}
}

func TestRateLimitLongDelayFailsWithoutPrematureRetry(t *testing.T) {
	var calls atomic.Int32
	c := &Client{}
	h := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		r := response(429, `PRIVATE`)
		r.Header.Set("Retry-After", "3600")
		return r, nil
	})}
	req, _ := http.NewRequest("GET", "https://sqladmin.googleapis.com/v1/projects/demo/instances", nil)
	resp, err := c.doRequest(h, req, 1)
	if err != nil || calls.Load() != 1 {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A different project's worker shares the service cooldown; it must not
	// retry early or block for an unbounded Retry-After value.
	req, _ = http.NewRequest("GET", "https://sqladmin.googleapis.com/v1/projects/another/instances", nil)
	if _, err := c.doRequest(h, req, 1); err == nil || calls.Load() != 1 {
		t.Fatal(calls.Load(), err)
	}
}

func TestServiceCooldownCancellationAndHostIsolation(t *testing.T) {
	c := &Client{}
	c.setServiceCooldown("sqladmin.googleapis.com", time.Now().Add(time.Minute))
	if err := c.waitServiceCooldown(context.Background(), "compute.googleapis.com", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := c.waitServiceCooldown(ctx, "sqladmin.googleapis.com", time.Now().Add(2*time.Minute)); err != context.Canceled {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation blocked")
	}
}

func TestRateLimitRetryWaitCancelsWithoutAnotherRequest(t *testing.T) {
	c := &Client{}
	calls := 0
	h := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return response(429, `PRIVATE`), nil // Exponential fallback is at least 1s.
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://sqladmin.googleapis.com/v1/projects/demo/instances", nil)
	if _, err := c.doRequest(h, req, 1); err != context.DeadlineExceeded || calls != 1 {
		t.Fatal(calls, err)
	}
}

func TestSharedServiceCooldownCanBeExtendedByAnotherWorker(t *testing.T) {
	c := &Client{}
	c.setServiceCooldown("sqladmin.googleapis.com", time.Now().Add(10*time.Millisecond))
	// A concurrent worker cannot replace a longer cooldown with a shorter one.
	until := time.Now().Add(40 * time.Millisecond)
	c.setServiceCooldown("sqladmin.googleapis.com", until)
	c.setServiceCooldown("sqladmin.googleapis.com", time.Now().Add(time.Millisecond))
	if err := c.waitServiceCooldown(context.Background(), "sqladmin.googleapis.com", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if time.Now().Before(until) {
		t.Fatal("service retry occurred before shared deadline")
	}
}

func TestGetRateLimitDoesNotMultiplyOuterRetries(t *testing.T) {
	calls := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		r := response(429, `PRIVATE`)
		r.Header.Set("Retry-After", "0")
		return r, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.instances.list": true}
	if _, err := c.get(context.Background(), "https://sqladmin.googleapis.com/v1/projects/demo/instances", nil); err == nil || calls != 4 {
		t.Fatal(calls, err)
	}
}

func TestGetMixedRateLimitAndServerErrorsShareAttemptBudget(t *testing.T) {
	calls := 0
	var attempts []int
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			return response(503, `PRIVATE`), nil
		}
		r := response(429, `PRIVATE`)
		r.Header.Set("Retry-After", "0")
		return r, nil
	})
	c.viewerPolicy.permissions = map[string]bool{"cloudsql.instances.list": true}
	c.Progress = func(e ProgressEvent) {
		if e.Phase == "request" && e.Status == "started" {
			attempts = append(attempts, e.Attempt)
		}
	}
	if _, err := c.get(context.Background(), "https://sqladmin.googleapis.com/v1/projects/demo/instances", nil); err == nil || calls != 4 {
		t.Fatal(calls, err)
	}
	for i, n := range attempts {
		if n != i+1 {
			t.Fatal(attempts)
		}
	}
}
