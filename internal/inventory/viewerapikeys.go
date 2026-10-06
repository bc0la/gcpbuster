package inventory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// CollectViewerAPIKeys obtains restrictions only. keys.list explicitly omits
// keyString. Secret capture separately reads it using Viewer's getKeyString
// permission; it is never persisted into the metadata snapshot or validated.
// https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list
func (c *Client) CollectViewerAPIKeys(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-api-keys:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	parent := number + "/locations/global/keys/"
	start := len(out.Assets)
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://apikeys.googleapis.com/v2/"+number+"/locations/global/keys", url.Values{"pageSize": {"100"}, "showDeleted": {"false"}}, func(page Object) error {
		rows, err := viewerRows(page, "keys")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			id := strings.TrimPrefix(name, parent)
			if !strings.HasPrefix(name, parent) || !viewerResourceName.MatchString(id) {
				return fmt.Errorf("invalid or foreign API key identity")
			}
			if _, exists := d["restrictions"]; exists && Obj(d["restrictions"]) == nil {
				return fmt.Errorf("malformed API key restrictions")
			}
			if Str(d["deleteTime"]) != "" {
				return fmt.Errorf("unexpected deleted API key in active inventory")
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			// Project a metadata whitelist so an unexpected keyString in a
			// privileged/malformed response cannot enter the snapshot.
			metadata := Object{"name": name}
			for _, field := range []string{"uid", "displayName", "createTime", "updateTime", "restrictions"} {
				if value, exists := d[field]; exists {
					metadata[field] = value
				}
			}
			// API names are numeric; CAI's documented envelope uses project ID.
			canonical := "projects/" + projectID + "/locations/global/keys/" + id
			a := NewAsset("//apikeys.googleapis.com/"+canonical, "apikeys.googleapis.com/Key", metadata)
			a.Ancestors = []string{number}
			a.Resource.Location = "global"
			out.Assets = append(out.Assets, a)
			if c.SecretCapture != nil {
				if len(seen) > 10000 {
					return fmt.Errorf("API key value read limit reached")
				}
				value, valueErr := c.get(ctx, "https://apikeys.googleapis.com/v2/"+name+"/keyString", url.Values{"fields": {"keyString"}})
				if valueErr == nil {
					text, ok := value["keyString"].(string)
					if !ok || text == "" {
						valueErr = fmt.Errorf("malformed API key string")
					} else {
						c.SecretCapture.Add(SecretSample{SourceType: "api_key_value", Resource: a.Name, Location: "global", Path: "keyString", Data: []byte("API_KEY=" + text)})
					}
				}
				out.record("viewer-api-key-value:"+name, 0, valueErr)
			}
		}
		return nil
	})
	out.record("viewer-api-keys:"+number, len(out.Assets)-start, err)
}
