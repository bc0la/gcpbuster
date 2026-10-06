package inventory

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const viewerDNSZoneFields = "managedZones(id,name,dnsName,visibility,dnssecConfig(state),cloudLoggingConfig(enableLogging),forwardingConfig(targetNameServers(ipv4Address,ipv6Address,domainName,forwardingPath)),peeringConfig(targetNetwork(networkUrl)),privateVisibilityConfig(networks(networkUrl))),nextPageToken"

var viewerDNSNetworkURL = regexp.MustCompile(`^https://(?:www|compute)\.googleapis\.com/compute/v1/projects/[a-zA-Z0-9][a-zA-Z0-9:.-]*/global/networks/[a-z][a-z0-9-]{0,62}$`)

// Selected routing configuration only: descriptions, labels and unrelated
// fields are never persisted. Referenced networks/targets are not contacted.
func projectViewerDNSZone(d Object) (Object, error) {
	id, name, domain := Str(d["id"]), Str(d["name"]), Str(d["dnsName"])
	if !viewerNumericID.MatchString(id) || !viewerDNSZoneName.MatchString(name) || !validDNSZoneName(domain) {
		return nil, fmt.Errorf("invalid managed-zone identity")
	}
	out := Object{"id": id, "name": name, "dnsName": domain}
	partial := false
	if value, exists := d["visibility"]; exists {
		if value == "public" || value == "private" {
			out["visibility"] = value
		} else {
			partial = true
		}
	}
	if value, exists := d["dnssecConfig"]; exists {
		config := Obj(value)
		state := Str(config["state"])
		if state == "off" || state == "on" || state == "transfer" {
			out["dnssecConfig"] = Object{"state": state}
		} else {
			partial = true
		}
	}
	if value, exists := d["cloudLoggingConfig"]; exists {
		enabled, known := Obj(value)["enableLogging"].(bool)
		if known {
			out["cloudLoggingConfig"] = Object{"enableLogging": enabled}
		} else {
			partial = true
		}
	}
	if value, exists := d["forwardingConfig"]; exists {
		rows, ok := Obj(value)["targetNameServers"].([]any)
		clean := []any{}
		valid := ok && len(rows) > 0 && len(rows) <= 1000
		for _, row := range rows {
			target := Obj(row)
			item := Object{}
			addresses := 0
			for _, key := range []string{"ipv4Address", "ipv6Address", "domainName"} {
				if raw, exists := target[key]; exists {
					text, ok := raw.(string)
					if !ok || text == "" {
						valid = false
						continue
					}
					addresses++
					if key == "domainName" {
						text = strings.TrimSuffix(strings.ToLower(text), ".") + "."
						if !validDNSZoneName(text) || text == "." {
							valid = false
							continue
						}
						item[key] = text
					} else {
						ip, err := netip.ParseAddr(text)
						if err != nil || ip.Zone() != "" || ip.Is4In6() || (key == "ipv4Address") != ip.Is4() {
							valid = false
							continue
						}
						item[key] = ip.String()
					}
				}
			}
			if addresses != 1 {
				valid = false
			}
			if raw, exists := target["forwardingPath"]; exists {
				if raw == "default" || raw == "private" {
					item["forwardingPath"] = raw
				} else {
					valid = false
				}
			}
			clean = append(clean, item)
		}
		if valid {
			out["forwardingConfig"] = Object{"targetNameServers": clean}
		} else {
			partial = true
		}
	}
	if value, exists := d["peeringConfig"]; exists {
		ref := Str(Get(Obj(value), "targetNetwork", "networkUrl"))
		if viewerDNSNetworkURL.MatchString(ref) {
			out["peeringConfig"] = Object{"targetNetwork": Object{"networkUrl": ref}}
		} else {
			partial = true
		}
	}
	if value, exists := d["privateVisibilityConfig"]; exists {
		rows, ok := Obj(value)["networks"].([]any)
		clean := []any{}
		valid := ok
		for _, row := range rows {
			ref := Str(Obj(row)["networkUrl"])
			if !viewerDNSNetworkURL.MatchString(ref) {
				valid = false
				continue
			}
			clean = append(clean, Object{"networkUrl": ref})
		}
		if valid {
			out["privateVisibilityConfig"] = Object{"networks": clean}
		} else {
			partial = true
		}
	}
	_, hasForwarding := d["forwardingConfig"]
	_, hasPeering := d["peeringConfig"]
	if hasForwarding && hasPeering {
		// These are mutually exclusive zone modes. Dropping one malformed
		// mode must not turn contradictory input into a valid other mode.
		delete(out, "forwardingConfig")
		delete(out, "peeringConfig")
		partial = true
	}
	if partial {
		return out, fmt.Errorf("some managed-zone configuration fields were malformed or unsupported")
	}
	return out, nil
}

func validDNSZoneName(name string) bool {
	if name == "." {
		return true
	}
	if len(name) > 254 || !strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
