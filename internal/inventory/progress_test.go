package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestProgressCallbacksSerialized(t *testing.T) {
	var active atomic.Int32
	var count int
	c := &Client{Progress: func(ProgressEvent) {
		if active.Add(1) != 1 {
			t.Error("concurrent callback")
		}
		count++ // Deliberately non-atomic: race test verifies serialization.
		active.Add(-1)
	}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.ReportProgress(ProgressEvent{Phase: "test"}) }()
	}
	wg.Wait()
	if count != 50 {
		t.Fatalf("callbacks = %d", count)
	}
}

func TestRequestProgressDoesNotExposeRequestOrError(t *testing.T) {
	for _, endpoint := range []string{
		"https://iam.googleapis.com/v1/secret-path?token=secret-query",
		"https://secret-host.googleapis.com/secret-path",
		"https://secret-instance.datafusion.googleusercontent.com/api/secret-path",
		"https://secret-other.example/secret-path",
	} {
		var events []ProgressEvent
		c := &Client{Progress: func(e ProgressEvent) { events = append(events, e) }}
		h := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("secret-error")
		})}
		req, _ := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		_, _ = c.doRequest(h, req, 1)
		encoded, _ := json.Marshal(events)
		if strings.Contains(string(encoded), "secret") {
			t.Fatalf("sensitive progress: %s", encoded)
		}
		if len(events) != 2 || events[0].Status != "started" || events[1].Status != "failed" {
			t.Fatalf("events: %+v", events)
		}
	}
}

func TestHierarchyProgressIncludesDiscoveryAndPages(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/projects") {
			return response(200, `{"projects":[{"name":"projects/10","parent":"organizations/1","state":"ACTIVE"}]}`), nil
		}
		return response(403, `{"error":"secret-response"}`), nil
	})
	var events []ProgressEvent
	c.Progress = func(e ProgressEvent) { events = append(events, e) }
	var snapshot Snapshot
	c.ExpandResourceScopes(context.Background(), &snapshot, []string{"organizations/1"})
	started, completed, failed, pages := 0, 0, 0, 0
	for _, e := range events {
		if e.Phase == "hierarchy-page" {
			pages++
			continue
		}
		if e.Phase != "hierarchy" {
			continue
		}
		if e.Scope != "organizations/1" {
			t.Fatalf("scope: %+v", e)
		}
		switch e.Status {
		case "started":
			started++
		case "completed":
			completed++
			if e.Count != 1 {
				t.Fatalf("count: %+v", e)
			}
		case "failed":
			failed++
		}
	}
	if started != 2 || completed != 1 || failed != 1 || pages != 1 {
		t.Fatalf("events: %+v", events)
	}
}
