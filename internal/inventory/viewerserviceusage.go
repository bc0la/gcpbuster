package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const viewerServiceUsageFields = "services(name,parent,state,config(name)),nextPageToken"

var viewerEnabledServiceName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// CollectViewerServiceUsage inventories enabled API metadata only. Presence is
// not a vulnerability and never triggers service enable/disable or API calls.
func (c *Client) CollectViewerServiceUsage(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-service-usage:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	seen := map[string]bool{}
	prefix := number + "/services/"
	partial := false
	err := c.viewerPages(ctx, "https://serviceusage.googleapis.com/v1/"+number+"/services", url.Values{"pageSize": {"200"}, "filter": {"state:ENABLED"}, "fields": {viewerServiceUsageFields}}, func(page Object) error {
		rows, err := viewerRows(page, "services")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			service := strings.TrimPrefix(name, prefix)
			if !strings.HasPrefix(name, prefix) || len(service) > 253 || !viewerEnabledServiceName.MatchString(service) || Str(d["state"]) != "ENABLED" {
				partial = true
				continue
			}
			if parent, exists := d["parent"]; exists && parent != number {
				partial = true
				continue
			}
			if config, exists := d["config"]; exists {
				m := Obj(config)
				if m == nil || Str(m["name"]) != service {
					partial = true
					continue
				}
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			a := NewAsset("//serviceusage.googleapis.com/"+name, "serviceusage.googleapis.com/Service", Object{"name": name, "parent": number, "state": "ENABLED", "config": Object{"name": service}})
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some enabled service records were malformed or outside the requested project")
	}
	out.record("viewer-service-usage:"+number, len(out.Assets)-start, err)
}
