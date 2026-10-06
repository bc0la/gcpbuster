package checks

import "github.com/bc0la/gcpbuster/internal/inventory"

// apiKeyRestrictionMetadata distinguishes omitted default restrictions from
// malformed supplied metadata. It does not interpret browser regex/glob syntax
// or treat empty client allowlists as universally allowed.
func apiKeyRestrictionMetadata(a inventory.Asset) (inventory.Object, bool) {
	if a.Type != "apikeys.googleapis.com/Key" {
		return nil, false
	}
	if raw, present := a.Resource.Data["deleteTime"]; present {
		text, ok := raw.(string)
		if !ok || text != "" {
			return nil, false
		}
	}
	raw, present := a.Resource.Data["restrictions"]
	if !present {
		return inventory.Object{}, true
	}
	r := obj(raw)
	if r == nil {
		return nil, false
	}
	clients := 0
	for field, value := range r {
		if field == "apiTargets" {
			rows, ok := value.([]any)
			if !ok || len(rows) > 4096 {
				return nil, false
			}
			for _, rawTarget := range rows {
				target := obj(rawTarget)
				if target == nil {
					return nil, false
				}
				service, ok := target["service"].(string)
				if !ok {
					return nil, false
				}
				if _, valid := inventory.DNSLookupName(service); !valid {
					return nil, false
				}
				if methods, exists := target["methods"]; exists && !apiKeyMetadataStrings(methods) {
					return nil, false
				}
			}
			continue
		}
		var listField string
		switch field {
		case "browserKeyRestrictions":
			listField = "allowedReferrers"
		case "serverKeyRestrictions":
			listField = "allowedIps"
		case "iosKeyRestrictions":
			listField = "allowedBundleIds"
		case "androidKeyRestrictions":
			listField = "allowedApplications"
		default:
			return nil, false
		}
		clients++
		if clients > 1 {
			return nil, false
		}
		client := obj(value)
		if client == nil {
			return nil, false
		}
		if list, exists := client[listField]; exists {
			if field != "androidKeyRestrictions" {
				if !apiKeyMetadataStrings(list) {
					return nil, false
				}
			} else {
				rows, ok := list.([]any)
				if !ok || len(rows) > 4096 {
					return nil, false
				}
				for _, rawApp := range rows {
					app := obj(rawApp)
					if app == nil {
						return nil, false
					}
					for _, key := range []string{"packageName", "sha1Fingerprint"} {
						text, ok := app[key].(string)
						if !ok || text == "" || len(text) > 4096 {
							return nil, false
						}
					}
				}
			}
		}
	}
	return r, true
}

func apiKeyMetadataStrings(raw any) bool {
	rows, ok := raw.([]any)
	if !ok || len(rows) > 4096 {
		return false
	}
	for _, v := range rows {
		text, ok := v.(string)
		if !ok || text == "" || len(text) > 4096 {
			return false
		}
	}
	return true
}
