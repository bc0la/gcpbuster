package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const viewerPubSubSnapshotFields = "snapshots(name,topic,expireTime),nextPageToken"

// CollectViewerPubSubSnapshots reads configuration only, never acknowledgement
// state, message contents, snapshot IAM, or seek/replay operations.
func (c *Client) CollectViewerPubSubSnapshots(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-pubsub-snapshots:identity", 0, fmt.Errorf("invalid Pub/Sub project identity"))
		return
	}
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://pubsub.googleapis.com/v1/projects/"+projectID+"/snapshots", url.Values{"pageSize": {"100"}, "fields": {viewerPubSubSnapshotFields}}, func(page Object) error {
		rows, err := viewerRows(page, "snapshots")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			p := strings.Split(Str(d["name"]), "/")
			if len(p) != 4 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "snapshots" || !viewerPubSubID.MatchString(p[3]) || strings.HasPrefix(p[3], "goog") {
				partial = true
				continue
			}
			p[1] = projectID
			name := strings.Join(p, "/")
			clean := Object{"name": name}
			valid := true
			if raw, exists := d["topic"]; exists {
				topic, ok := raw.(string)
				q := strings.Split(topic, "/")
				if !ok || len(q) != 4 || q[0] != "projects" || !viewerResourceName.MatchString(q[1]) || q[2] != "topics" || !viewerPubSubID.MatchString(q[3]) || strings.HasPrefix(q[3], "goog") {
					valid = false
				} else {
					clean["topic"] = topic
				}
			}
			if raw, exists := d["expireTime"]; exists {
				stamp, ok := raw.(string)
				if _, err := time.Parse(time.RFC3339Nano, stamp); !ok || err != nil {
					valid = false
				} else {
					clean["expireTime"] = stamp
				}
			}
			if !valid {
				partial = true
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			a := NewAsset("//pubsub.googleapis.com/"+name, "pubsub.googleapis.com/Snapshot", clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some Pub/Sub snapshot metadata was malformed or unavailable")
	}
	out.record("viewer-pubsub-snapshots:"+projectID, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-pubsub-snapshots:limitations:" + projectID, Status: "notice", Error: "Snapshot name, topic reference and expiration metadata only. Labels, IAM, message bodies and acknowledgement state are not collected. Topic references are not followed; existence does not prove replay authority, captured messages, sensitivity or malicious use. No create, update, delete, seek or consume operation is performed."})
}
