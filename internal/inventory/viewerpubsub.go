package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const viewerPubSubTopicFields = "topics(name,kmsKeyName,messageRetentionDuration,state,satisfiesPzs,messageStoragePolicy(allowedPersistenceRegions,enforceInTransit),schemaSettings(schema,encoding,firstRevisionId,lastRevisionId)),nextPageToken"

var viewerPubSubID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-_.~+%]{2,254}$`)

// CollectViewerPubSub discovers topic configuration only. Direct Pub/Sub IAM
// policy permissions are not present in the exact three-role baseline; no
// getIamPolicy request, publishing, subscription creation or consumption occurs.
func (c *Client) CollectViewerPubSub(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-pubsub:identity", 0, fmt.Errorf("invalid Pub/Sub project identity"))
		return
	}
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://pubsub.googleapis.com/v1/projects/"+projectID+"/topics", url.Values{"pageSize": {"100"}, "fields": {viewerPubSubTopicFields}}, func(page Object) error {
		rows, err := viewerRows(page, "topics")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			p := strings.Split(Str(d["name"]), "/")
			if len(p) != 4 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "topics" || !viewerPubSubID.MatchString(p[3]) || strings.HasPrefix(p[3], "goog") {
				partial = true
				continue
			}
			clean, err := viewerPubSubTopicProjection(d)
			if err != nil {
				partial = true
				continue
			}
			p[1] = projectID
			name := strings.Join(p, "/")
			if seen[name] {
				continue
			}
			seen[name] = true
			clean["name"] = name
			a := NewAsset("//pubsub.googleapis.com/"+name, "pubsub.googleapis.com/Topic", clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some Pub/Sub topic metadata was malformed or unavailable")
	}
	out.record("viewer-pubsub:topics:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-pubsub:direct-iam:" + projectID, Status: "incomplete", Error: "Direct topic/subscription IAM policies require pubsub.topics.getIamPolicy or pubsub.subscriptions.getIamPolicy, absent from the exact Viewer/folderViewer/organizationViewer baseline. No direct policy requests are made. Indexed CAI IAM evidence is separate and does not establish complete or effective access."}, Coverage{Source: "viewer-pubsub:limitations:" + projectID, Status: "notice", Error: "Selected topic configuration only; ingestion source settings, transforms, labels and schema contents are excluded. No messages are published, pulled, acknowledged, consumed or modified. Resource references are not followed."})
}

func viewerPubSubTopicProjection(d Object) (Object, error) {
	clean := Object{}
	for _, field := range []string{"kmsKeyName", "messageRetentionDuration", "state"} {
		if raw, exists := d[field]; exists {
			if _, ok := raw.(string); !ok {
				return nil, fmt.Errorf("malformed topic string")
			}
			clean[field] = raw
		}
	}
	if raw, exists := d["satisfiesPzs"]; exists {
		if _, ok := raw.(bool); !ok {
			return nil, fmt.Errorf("malformed topic boolean")
		}
		clean["satisfiesPzs"] = raw
	}
	if raw, exists := d["schemaSettings"]; exists {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("malformed schema metadata")
		}
		projected := Object{}
		for _, field := range []string{"schema", "encoding", "firstRevisionId", "lastRevisionId"} {
			if v, exists := row[field]; exists {
				if _, ok := v.(string); !ok {
					return nil, fmt.Errorf("malformed schema metadata")
				}
				projected[field] = v
			}
		}
		clean["schemaSettings"] = projected
	}
	if raw, exists := d["messageStoragePolicy"]; exists {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("malformed message storage policy")
		}
		projected := Object{}
		if v, exists := row["enforceInTransit"]; exists {
			if _, ok := v.(bool); !ok {
				return nil, fmt.Errorf("malformed transit constraint")
			}
			projected["enforceInTransit"] = v
		}
		if v, exists := row["allowedPersistenceRegions"]; exists {
			regions, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("malformed storage regions")
			}
			for _, region := range regions {
				if !viewerLocation.MatchString(Str(region)) {
					return nil, fmt.Errorf("malformed storage region")
				}
			}
			projected["allowedPersistenceRegions"] = regions
		}
		clean["messageStoragePolicy"] = projected
	}
	return clean, nil
}
