package inventory

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var iapSettingsContainer = regexp.MustCompile(`^(projects|folders|organizations)/[0-9]+$`)

// CollectIAPSettings reads local settings independently of IAM-read permission.
// Values are not flattened across parents: reauth has its own merge semantics.
func (c *Client) CollectIAPSettings(ctx context.Context, snap *Snapshot) {
	targets := map[string]bool{}
	unresolved := 0
	for _, a := range snap.Assets {
		for _, ancestor := range a.Ancestors {
			if iapSettingsContainer.MatchString(ancestor) {
				targets[ancestor] = true
			}
		}
		switch a.Type {
		case "appengine.googleapis.com/Application", "appengine.googleapis.com/Service", "appengine.googleapis.com/Version", "compute.googleapis.com/Instance", "compute.googleapis.com/BackendService", "compute.googleapis.com/RegionBackendService", "run.googleapis.com/Service", "cloudresourcemanager.googleapis.com/Project":
			paths, ok := iapTargets(a)
			if !ok {
				unresolved++
			}
			for _, path := range paths {
				if strings.Contains(path, "/iap_web") {
					targets[path] = true
					targets[strings.Split(path, "/iap_web")[0]] = true
				}
			}
		case "cloudresourcemanager.googleapis.com/Folder", "cloudresourcemanager.googleapis.com/Organization":
			name := strings.TrimPrefix(a.Name, "//cloudresourcemanager.googleapis.com/")
			if iapSettingsContainer.MatchString(name) {
				targets[name] = true
			}
		}
	}
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			snap.record("iap-settings:"+name, 0, err)
			break
		}
		d, err := c.get(ctx, "https://iap.googleapis.com/v1/"+name+":iapSettings", nil)
		if err == nil {
			err = validateIAPSettings(d, name)
		}
		if err != nil {
			snap.record("iap-settings:"+name, 0, err)
			continue
		}
		snap.record("iap-settings:"+name, 1, nil)
		snap.Assets = append(snap.Assets, NewAsset("//iap.googleapis.com/"+name, "iap.googleapis.com/IapSettings", d))
	}
	if unresolved > 0 {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "iap-settings:unresolved", Status: "incomplete", Count: unresolved, Error: "Some web settings targets lack supported names or numeric project ancestry."})
	}
	snap.Coverage = append(snap.Coverage, Coverage{Source: "iap-settings:limitations", Status: "notice", Error: "Explicit local settings for discovered web resources and supplied ancestors only. Effective inheritance, change history, intended trust, application behavior and missing service families remain unverified. No application URLs are requested."})
}

func validateIAPSettings(d Object, name string) error {
	if d == nil || Str(d["name"]) != name {
		return fmt.Errorf("missing or mismatched IAP settings identity")
	}
	for _, path := range [][]string{{"accessSettings"}, {"applicationSettings"}, {"accessSettings", "corsSettings"}, {"accessSettings", "oauthSettings"}, {"accessSettings", "reauthSettings"}, {"accessSettings", "allowedDomainsSettings"}} {
		v := Get(d, path...)
		if v != nil {
			if _, ok := v.(map[string]any); !ok {
				return fmt.Errorf("invalid IAP settings object")
			}
		}
	}
	for _, path := range [][]string{{"accessSettings", "corsSettings", "allowHttpOptions"}, {"accessSettings", "allowedDomainsSettings", "enable"}} {
		v := Get(d, path...)
		if v != nil {
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("invalid IAP settings boolean")
			}
		}
	}
	if v := Get(d, "accessSettings", "oauthSettings", "programmaticClients"); v != nil {
		xs, ok := v.([]any)
		if !ok {
			return fmt.Errorf("invalid IAP programmatic clients")
		}
		for _, x := range xs {
			if s, ok := x.(string); !ok || s == "" {
				return fmt.Errorf("invalid IAP programmatic client")
			}
		}
	}
	return nil
}
