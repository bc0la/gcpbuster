package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/url"
	"strings"
	"time"
)

func automationIdentityDelivery(a inventory.Asset, _ time.Time) []Result {
	var target inventory.Object
	var endpoint string
	switch a.Type {
	case "cloudscheduler.googleapis.com/Job":
		if s(val(a, "state")) == "PAUSED" || s(val(a, "state")) == "DISABLED" {
			return nil
		}
		target = obj(val(a, "httpTarget"))
		endpoint = s(target["uri"])
	case "cloudtasks.googleapis.com/Queue":
		if s(val(a, "state")) == "PAUSED" || s(val(a, "state")) == "DISABLED" {
			return nil
		}
		target = obj(val(a, "httpTarget"))
		host := s(inventory.Get(target, "uriOverride", "host"))
		scheme := strings.ToLower(s(inventory.Get(target, "uriOverride", "scheme")))
		if host != "" {
			if scheme == "https" || scheme == "http" {
				endpoint = scheme + "://" + host
			} else {
				endpoint = "//" + host
			}
		}
	case "cloudtasks.googleapis.com/Task":
		target = obj(val(a, "httpRequest"))
		endpoint = s(target["url"])
	case "pubsub.googleapis.com/Subscription":
		target = obj(val(a, "pushConfig"))
		endpoint = s(target["pushEndpoint"])
	}
	var out []Result
	for _, kind := range []string{"oidcToken", "oauthToken"} {
		identity := obj(target[kind])
		email := s(identity["serviceAccountEmail"])
		if email == "" {
			continue
		}
		parsed, err := url.Parse(endpoint)
		host, scheme := "", ""
		if err == nil {
			host = parsed.Hostname()
			scheme = parsed.Scheme
		}
		e := inventory.Object{"service_account": email, "token_type": kind, "destination_host": host, "destination_scheme": scheme, "assessment": "configured identity delivery; destination ownership and business approval require review; no token was requested"}
		sev, title := "medium", "Automation delivers a service-account identity to an HTTP target"
		if scheme == "http" {
			sev = "high"
			title = "Automation token delivery is configured over unencrypted HTTP"
		}
		if endpoint == "" {
			e["assessment"] = "queue-wide token configuration; effective task destinations require task inventory"
		}
		if kind == "oidcToken" && s(identity["audience"]) != "" {
			aud, err := url.Parse(s(identity["audience"]))
			if err == nil {
				e["audience_host"] = aud.Hostname()
			}
		}
		out = append(out, Result{sev, title, e, "Validate every target and audience, the runtime service account's permissions, and who can change the job/queue/subscription. Remove unauthorized automation; rotating a service-account key does not remove this token delivery configuration."})
	}
	return out
}

func taskQueueLogging(a inventory.Asset, _ time.Time) []Result {
	v := val(a, "stackdriverLoggingConfig", "samplingRatio")
	if v == nil {
		return result("info", "Cloud Tasks queue has no explicit dispatch logging sample ratio", "Verify effective dispatch logging and configure an appropriate sampling ratio for sensitive queues.", nil)
	}
	if ratio, ok := v.(float64); ok && ratio == 0 {
		return result("medium", "Cloud Tasks queue dispatch logging is disabled", "Enable a nonzero dispatch logging sample ratio and retain relevant execution logs.", nil)
	}
	return nil
}
