package inventory

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const requestAttemptLimit = 4
const rateLimitWaitBudget = 120 * time.Second

type requestAttemptKey struct{}

func withRequestAttemptCounter(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestAttemptKey{}, new(atomic.Int32))
}

func retryAfterDelay(header string, now time.Time, attempt int) time.Duration {
	value := strings.TrimSpace(header)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		// Saturate instead of overflowing an untrusted duration.
		if seconds > int64((time.Duration(1<<63-1))/time.Second) {
			return time.Duration(1<<63 - 1)
		}
		return time.Duration(seconds) * time.Second
	}
	if deadline, err := http.ParseTime(value); err == nil {
		if delay := deadline.Sub(now); delay > 0 {
			return delay
		}
		return 0
	}
	if attempt < 1 {
		attempt = 1
	}
	if attempt > requestAttemptLimit {
		attempt = requestAttemptLimit
	}
	base := time.Second << (attempt - 1)
	return base + time.Duration(rand.Int64N(int64(base/2)+1))
}

func retryableViewerRequest(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return false
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false
	}
	_, err := viewerRequestPermissions(req.Method, req.URL.String(), nil)
	return err == nil
}

func (c *Client) setServiceCooldown(host string, until time.Time) {
	c.rateLimitMu.Lock()
	defer c.rateLimitMu.Unlock()
	if c.rateLimits == nil {
		c.rateLimits = make(map[string]time.Time)
	}
	if until.After(c.rateLimits[host]) {
		c.rateLimits[host] = until
	}
}

func (c *Client) waitServiceCooldown(ctx context.Context, host string, budgetEnd time.Time) error {
	for {
		c.rateLimitMu.Lock()
		until := c.rateLimits[host]
		c.rateLimitMu.Unlock()
		delay := time.Until(until)
		if delay <= 0 {
			return ctx.Err()
		}
		if until.After(budgetEnd) {
			return fmt.Errorf("service rate-limit cooldown exceeds request retry budget")
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		// Another worker may have extended this service's cooldown.
	}
}
