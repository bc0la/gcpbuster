package inventory

import (
	"fmt"
	"net/url"
	"strings"
)

// Only hook presence and credential-forwarding switches are retained. Hook
// URIs may contain private identifiers or secrets and must never be copied.
func viewerIdentityBlockingFunctions(raw any) (Object, error) {
	marker := Object{"complete": false, "hooks": Object{}, "forward_credentials": Object{}}
	d := Obj(raw)
	if d == nil {
		return marker, fmt.Errorf("malformed blocking-function settings")
	}
	partial := false
	if value, present := d["triggers"]; present {
		triggers := Obj(value)
		if triggers == nil {
			partial = true
		} else {
			for event, rawTrigger := range triggers {
				if event != "beforeCreate" && event != "beforeSignIn" {
					partial = true
					continue
				}
				uri, ok := Obj(rawTrigger)["functionUri"].(string)
				u, err := url.Parse(uri)
				if !ok || len(uri) > 2048 || strings.TrimSpace(uri) != uri || err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.Opaque != "" {
					partial = true
					continue
				}
				Obj(marker["hooks"])[event] = true
			}
		}
	}
	if value, present := d["forwardInboundCredentials"]; present {
		flags := Obj(value)
		if flags == nil {
			partial = true
		} else {
			for _, key := range []string{"idToken", "accessToken", "refreshToken"} {
				if rawFlag, present := flags[key]; present {
					if flag, ok := rawFlag.(bool); ok {
						Obj(marker["forward_credentials"])[key] = flag
					} else {
						partial = true
					}
				}
			}
		}
	}
	marker["complete"] = !partial
	if partial {
		return marker, fmt.Errorf("malformed selected blocking-function settings")
	}
	return marker, nil
}
