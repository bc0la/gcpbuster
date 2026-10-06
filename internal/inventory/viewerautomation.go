package inventory

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var viewerAutomationLocation = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var viewerAutomationID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~+%-]*$`)

const viewerPubSubSubscriptionFields = "subscriptions(name,topic,detached,state,ackDeadlineSeconds,retainAckedMessages,messageRetentionDuration,enableMessageOrdering,enableExactlyOnceDelivery,topicMessageRetentionDuration,expirationPolicy(ttl),deadLetterPolicy(deadLetterTopic,maxDeliveryAttempts),retryPolicy(minimumBackoff,maximumBackoff),pushConfig(pushEndpoint,oidcToken(serviceAccountEmail,audience)),bigqueryConfig(table,serviceAccountEmail,state,useTopicSchema,useTableSchema,writeMetadata,dropUnknownFields),cloudStorageConfig(bucket,serviceAccountEmail,state),bigtableConfig(table,serviceAccountEmail,state)),nextPageToken"

var viewerPubSubDuration = regexp.MustCompile(`^[0-9]+(\.[0-9]{1,9})?s$`)

// CollectViewerAutomation reads repository, scheduled-job and subscription
// configuration only. Locations come from each service's paginated locations
// API, not an assumed region list or undocumented '-' wildcard. No artifact
// download, job execution, token minting or message consumption is performed.
func (c *Client) CollectViewerAutomation(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-automation:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	for _, spec := range []struct{ host, collection, kind string }{
		{"artifactregistry.googleapis.com", "repositories", "Repository"},
		{"cloudscheduler.googleapis.com", "jobs", "Job"},
	} {
		base := "https://" + spec.host + "/v1/projects/" + projectID
		locations := map[string]bool{}
		partial := false
		err := c.viewerPages(ctx, base+"/locations", url.Values{"pageSize": {"100"}}, func(page Object) error {
			rows, err := viewerRows(page, "locations")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				d := Obj(raw)
				parts := strings.Split(Str(d["name"]), "/")
				if len(parts) != 4 || parts[0] != "projects" || (parts[1] != projectID && parts[1] != strings.TrimPrefix(number, "projects/")) || parts[2] != "locations" || !viewerAutomationLocation.MatchString(parts[3]) {
					return fmt.Errorf("invalid or out-of-scope automation location")
				}
				if id := Str(d["locationId"]); id != "" && id != parts[3] {
					return fmt.Errorf("mismatched automation location ID")
				}
				locations[parts[3]] = true
			}
			return viewerAutomationPartial(page, &partial)
		})
		if err == nil && partial {
			err = fmt.Errorf("automation location inventory includes unreachable locations")
		}
		out.record("viewer-automation-locations:"+spec.host+":"+projectID, len(locations), err)
		ordered := make([]string, 0, len(locations))
		for location := range locations {
			ordered = append(ordered, location)
		}
		sort.Strings(ordered)
		for _, location := range ordered {
			if ctx.Err() != nil {
				out.record("viewer-automation:"+spec.host+":"+projectID, 0, ctx.Err())
				break
			}
			c.viewerAutomationRows(ctx, out, base+"/locations/"+location+"/"+spec.collection, spec.host, spec.collection, spec.kind, projectID, number, location)
		}
	}
	c.viewerAutomationRows(ctx, out, "https://pubsub.googleapis.com/v1/projects/"+projectID+"/subscriptions", "pubsub.googleapis.com", "subscriptions", "Subscription", projectID, number, "")
}

func (c *Client) viewerAutomationRows(ctx context.Context, out *Snapshot, endpoint, host, collection, kind, projectID, number, location string) {
	start := len(out.Assets)
	seen := map[string]bool{}
	partial := false
	q := url.Values{"pageSize": {"100"}}
	isSubscription := host == "pubsub.googleapis.com" && collection == "subscriptions" && kind == "Subscription"
	if isSubscription {
		q.Set("fields", viewerPubSubSubscriptionFields)
	}
	if c.SecretCapture != nil && host == "cloudscheduler.googleapis.com" {
		q.Set("fields", secretCaptureSchedulerFields)
	}
	err := c.viewerPages(ctx, endpoint, q, func(page Object) error {
		rows, err := viewerRows(page, collection)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			parts := strings.Split(name, "/")
			valid := len(parts) == 4
			if location != "" {
				valid = len(parts) == 6
			}
			if !valid || parts[0] != "projects" || (parts[1] != projectID && parts[1] != strings.TrimPrefix(number, "projects/")) {
				if isSubscription {
					partial = true
					continue
				}
				return fmt.Errorf("invalid or out-of-scope automation resource")
			}
			if location != "" {
				if parts[2] != "locations" || parts[3] != location || parts[4] != collection {
					return fmt.Errorf("mismatched automation resource parent")
				}
			} else if parts[2] != collection {
				if isSubscription {
					partial = true
					continue
				}
				return fmt.Errorf("mismatched subscription collection")
			}
			id := parts[len(parts)-1]
			if !viewerAutomationID.MatchString(id) || id == "." || id == ".." {
				if isSubscription {
					partial = true
					continue
				}
				return fmt.Errorf("invalid automation resource ID")
			}
			if host == "cloudscheduler.googleapis.com" {
				a := NewAsset("//"+host+"/"+Str(d["name"]), host+"/Job", d)
				a.Resource.Location = location
				c.SecretCapture.captureOther(a)
			}
			if isSubscription {
				clean, err := viewerPubSubSubscriptionProjection(d)
				if err != nil {
					partial = true
					continue
				}
				d = clean
			}
			// CAI documents project-ID names for Artifact Registry/PubSub.
			// Scheduler is not in that CAI table; its own Job API documents
			// the same project-ID form. Preserve the unmodified API data.name.
			parts[1] = projectID
			canonical := "//" + host + "/" + strings.Join(parts, "/")
			if seen[canonical] {
				continue
			}
			seen[canonical] = true
			a := NewAsset(canonical, host+"/"+kind, d)
			if host == "artifactregistry.googleapis.com" && kind == "Repository" {
				name := strings.TrimPrefix(canonical, "//artifactregistry.googleapis.com/")
				policy, policyErr := c.get(ctx, "https://artifactregistry.googleapis.com/v1/"+name+":getIamPolicy", url.Values{"options.requestedPolicyVersion": {"3"}, "fields": {"version,bindings,etag"}})
				if policyErr == nil {
					a.IAM, policyErr = viewerLogViewPolicy(policy)
				}
				n := 0
				if policyErr == nil {
					n = 1
				}
				out.record("viewer-artifact-iam:"+name, n, policyErr)
			}
			a.Resource.Location = location
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("automation inventory includes unreachable locations or malformed metadata")
	}
	out.record("viewer-automation:"+host+":"+projectID+":"+collection+":"+location, len(out.Assets)-start, err)
}

// Subscription lists are configuration reads, but also expose transform source
// code and arbitrary labels. Select and locally project only reviewed metadata.
func viewerPubSubSubscriptionProjection(d Object) (Object, error) {
	return viewerPubSubSubscriptionObject(d, map[string]string{
		"name": "string", "topic": "string", "state": "string", "detached": "bool", "ackDeadlineSeconds": "integer", "retainAckedMessages": "bool", "messageRetentionDuration": "duration", "enableMessageOrdering": "bool", "enableExactlyOnceDelivery": "bool", "topicMessageRetentionDuration": "duration",
	}, map[string]map[string]string{
		"expirationPolicy":   {"ttl": "duration"},
		"deadLetterPolicy":   {"deadLetterTopic": "string", "maxDeliveryAttempts": "integer"},
		"retryPolicy":        {"minimumBackoff": "duration", "maximumBackoff": "duration"},
		"pushConfig":         {"pushEndpoint": "string"},
		"bigqueryConfig":     {"table": "string", "serviceAccountEmail": "string", "state": "string", "useTopicSchema": "bool", "useTableSchema": "bool", "writeMetadata": "bool", "dropUnknownFields": "bool"},
		"cloudStorageConfig": {"bucket": "string", "serviceAccountEmail": "string", "state": "string"},
		"bigtableConfig":     {"table": "string", "serviceAccountEmail": "string", "state": "string"},
	})
}

func viewerPubSubSubscriptionObject(d Object, fields map[string]string, nested map[string]map[string]string) (Object, error) {
	clean := Object{}
	for field, kind := range fields {
		raw, exists := d[field]
		if !exists {
			continue
		}
		valid := false
		switch kind {
		case "string":
			_, valid = raw.(string)
		case "duration":
			v, ok := raw.(string)
			valid = ok && viewerPubSubDuration.MatchString(v)
		case "bool":
			_, valid = raw.(bool)
		case "integer":
			v, ok := raw.(float64)
			valid = ok && !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v && v >= 0 && v <= 2147483647
		}
		if !valid {
			return nil, fmt.Errorf("malformed subscription configuration")
		}
		clean[field] = raw
	}
	for field, projection := range nested {
		raw, exists := d[field]
		if !exists {
			continue
		}
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("malformed subscription configuration object")
		}
		var children map[string]map[string]string
		if field == "pushConfig" {
			children = map[string]map[string]string{"oidcToken": {"serviceAccountEmail": "string", "audience": "string"}}
		}
		projected, err := viewerPubSubSubscriptionObject(row, projection, children)
		if err != nil {
			return nil, err
		}
		clean[field] = projected
	}
	return clean, nil
}

// These list schemas currently do not document partial-location fields. If a
// service adds one, never silently treat returned subsets as complete. Continue
// pagination for validated partial lists, then report failed coverage.
func viewerAutomationPartial(page Object, partial *bool) error {
	for _, key := range []string{"unreachable", "unreachableLocations"} {
		rows, err := viewerRows(page, key)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			*partial = true
		}
		for _, raw := range rows {
			if Str(raw) == "" {
				return fmt.Errorf("invalid automation unreachable location")
			}
		}
	}
	return nil
}
