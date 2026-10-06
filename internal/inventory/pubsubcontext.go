package inventory

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var pubsubContextName = regexp.MustCompile(`^projects/([A-Za-z0-9][A-Za-z0-9._:-]*)/(topics|subscriptions)/[A-Za-z][A-Za-z0-9._~+-]{0,254}$`)
var pubsubContextBQ = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*\.[A-Za-z0-9_]+\.[A-Za-z0-9_-]+$`)
var pubsubContextBT = regexp.MustCompile(`^projects/[A-Za-z0-9][A-Za-z0-9_-]*/instances/[A-Za-z0-9][A-Za-z0-9_-]*/tables/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var pubsubContextBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)

func pubsubDeliveryKind(d Object) string {
	kind, count := "unknown", 0
	for _, spec := range []struct{ field, target, kind string }{{"pushConfig", "pushEndpoint", "push"}, {"bigqueryConfig", "table", "bigquery"}, {"cloudStorageConfig", "bucket", "storage"}, {"bigtableConfig", "table", "bigtable"}} {
		raw, exists := d[spec.field]
		if !exists {
			continue
		}
		cfg, ok := raw.(map[string]any)
		if !ok {
			if o, yes := raw.(Object); yes {
				cfg = o
			} else {
				return "unknown"
			}
		}
		if len(cfg) == 0 {
			continue
		}
		count++
		target, ok := cfg[spec.target].(string)
		if !ok || target == "" || len(target) > 2048 {
			return "unknown"
		}
		if (spec.kind == "bigquery" && !pubsubContextBQ.MatchString(target)) || (spec.kind == "bigtable" && !pubsubContextBT.MatchString(target)) || (spec.kind == "storage" && !pubsubContextBucket.MatchString(target)) {
			return "unknown"
		}
		if spec.kind == "push" {
			u, e := url.Parse(target)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return "unknown"
			}
		}
		kind = spec.kind
	}
	if count != 1 {
		return "unknown"
	}
	return kind
}

// CorrelatePubSubDeliveryContext joins observed same-project subscription
// configurations to exact topic grants. No policy inheritance or message reads.
func CorrelatePubSubDeliveryContext(out *Snapshot) {
	for i := range out.Assets {
		if out.Assets[i].Type == PermissionGrantType {
			delete(out.Assets[i].Resource.Data, "_gcpbusterPubSubDelivery")
		}
	}
	if len(out.Assets) > 100000 {
		out.Coverage = append(out.Coverage, Coverage{Source: "pubsub-delivery-context", Status: "incomplete", Error: "Snapshot exceeds correlation bound"})
		return
	}
	type observation struct {
		topic, kind, state string
		detached           bool
	}
	seen := map[string]observation{}
	conflicts := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "pubsub.googleapis.com/Subscription" {
			continue
		}
		name := strings.TrimPrefix(a.Name, "//pubsub.googleapis.com/")
		m := pubsubContextName.FindStringSubmatch(name)
		if m == nil || m[2] != "subscriptions" || a.Name != "//pubsub.googleapis.com/"+name {
			continue
		}
		d := a.Resource.Data
		topic := Str(d["topic"])
		tm := pubsubContextName.FindStringSubmatch(topic)
		if Str(d["name"]) != name || tm == nil || tm[2] != "topics" || tm[1] != m[1] {
			conflicts[name] = true
			continue
		}
		o := observation{topic: topic, kind: pubsubDeliveryKind(d), state: "unknown"}
		if v, exists := d["detached"]; exists {
			flag, ok := v.(bool)
			if !ok {
				conflicts[name] = true
				continue
			}
			o.detached = flag
		}
		if v, exists := d["state"]; exists {
			if v == "ACTIVE" || v == "RESOURCE_ERROR" {
				o.state = Str(v)
			} else {
				conflicts[name] = true
				continue
			}
		}
		if old, ok := seen[name]; ok && old != o {
			conflicts[name] = true
		}
		seen[name] = o
	}
	counts := map[string]Object{}
	for name, o := range seen {
		if conflicts[name] {
			continue
		}
		c := counts[o.topic]
		if c == nil {
			c = Object{"observed_subscriptions": 0, "push": 0, "bigquery": 0, "storage": 0, "bigtable": 0, "unknown": 0, "detached": 0, "state_unknown": 0, "resource_error": 0}
			counts[o.topic] = c
		}
		c["observed_subscriptions"] = c["observed_subscriptions"].(int) + 1
		if o.detached {
			c["detached"] = c["detached"].(int) + 1
		} else {
			c[o.kind] = c[o.kind].(int) + 1
		}
		if o.state == "unknown" {
			c["state_unknown"] = c["state_unknown"].(int) + 1
		}
		if o.state == "RESOURCE_ERROR" {
			c["resource_error"] = c["resource_error"].(int) + 1
		}
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		d := a.Resource.Data
		if a.Type != PermissionGrantType || Str(d["resourceType"]) != "pubsub.googleapis.com/Topic" {
			continue
		}
		resource := Str(d["resource"])
		topic := strings.TrimPrefix(resource, "//pubsub.googleapis.com/")
		if resource != "//pubsub.googleapis.com/"+topic {
			continue
		}
		c := counts[topic]
		if c == nil {
			continue
		}
		safe := Object{"topic": resource, "coverage": "observed_subset_not_complete"}
		for k, v := range c {
			safe[k] = v
		}
		d["_gcpbusterPubSubDelivery"] = safe
	}
	if len(conflicts) > 0 {
		out.Coverage = append(out.Coverage, Coverage{Source: "pubsub-delivery-context", Status: "incomplete", Error: fmt.Sprintf("%d ambiguous subscription observations omitted", len(conflicts))})
	}
}
