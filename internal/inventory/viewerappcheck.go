package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const FirebaseAppCheckServiceType = "gcpbuster.googleapis.com/FirebaseAppCheckService"
const viewerAppCheckFields = "services(name,enforcementMode,replayProtection),nextPageToken"
const FirebaseAppCheckResourcePolicyType = "gcpbuster.googleapis.com/FirebaseAppCheckResourcePolicy"
const viewerAppCheckResourcePolicyFields = "resourcePolicies(name,enforcementMode,targetResource),nextPageToken"

var viewerAppCheckPolicyID = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$`)

// Service IDs are identifiers, NOT URLs to contact. Only service enforcement
// metadata is collected; attestation providers/debug tokens are not requested.
func viewerAppCheckServiceID(id string) bool {
	switch id {
	case "identitytoolkit.googleapis.com", "firebasedataconnect.googleapis.com", "firestore.googleapis.com", "firebasedatabase.googleapis.com", "firebasestorage.googleapis.com", "firebaseml.googleapis.com", "maps-backend.googleapis.com", "places.googleapis.com", "oauth2.googleapis.com":
		return true
	}
	return false
}

func (c *Client) CollectViewerAppCheck(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-appcheck:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	count := 0
	partial := false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://firebaseappcheck.googleapis.com/v1/"+number+"/services", url.Values{"fields": {viewerAppCheckFields}, "pageSize": {"100"}}, func(page Object) error {
		rows, e := viewerRows(page, "services")
		if e != nil {
			return e
		}
		for _, raw := range rows {
			r := Obj(raw)
			name := Str(r["name"])
			p := strings.Split(name, "/")
			if len(p) != 4 || p[0]+"/"+p[1] != number || p[2] != "services" || !viewerAppCheckServiceID(p[3]) || seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			safe := Object{"name": name}
			for _, key := range []string{"enforcementMode", "replayProtection"} {
				if v, exists := r[key]; exists {
					switch v {
					case "OFF", "UNENFORCED", "ENFORCED":
						safe[key] = v
					default:
						partial = true
					}
				}
			}
			a := NewAsset("//firebaseappcheck.googleapis.com/"+name, FirebaseAppCheckServiceType, safe)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
			count++
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some App Check service identities or explicit enforcement modes were malformed, unsupported or duplicated")
	}
	out.record("viewer-appcheck:services:"+number, count, err)
	// ResourcePolicy's documented OAuth2 parent does not depend on a service
	// appearing in the configured-only list. Collect independently, including
	// when service-list permission is denied; the exact policy read is gated.
	c.viewerAppCheckResourcePolicies(ctx, out, number)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-appcheck:limitations:" + number, Status: "notice", Error: "Only explicitly configured App Check services are listed. Resource policies are read independently beneath the fixed oauth2 service, the currently documented supported parent. Missing services or omitted modes are unknown, not OFF. OFF/UNENFORCED does not establish anonymous access: user authorization and other controls remain independent. ENFORCED has service-specific exceptions. Policy target existence and effective enforcement are not verified. No app attestation, tokens, debug tokens, providers, signup or protected data are accessed."})
}

func (c *Client) viewerAppCheckResourcePolicies(ctx context.Context, out *Snapshot, number string) {
	parent := number + "/services/oauth2.googleapis.com"
	prefix := parent + "/resourcePolicies/"
	targetPrefix := "//oauth2.googleapis.com/" + number + "/oauthClients/"
	count := 0
	partial := false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://firebaseappcheck.googleapis.com/v1/"+parent+"/resourcePolicies", url.Values{"fields": {viewerAppCheckResourcePolicyFields}, "pageSize": {"100"}}, func(page Object) error {
		rows, e := viewerRows(page, "resourcePolicies")
		if e != nil {
			return e
		}
		for _, raw := range rows {
			r := Obj(raw)
			name, target := Str(r["name"]), Str(r["targetResource"])
			if !strings.HasPrefix(name, prefix) || !viewerAppCheckPolicyID.MatchString(strings.TrimPrefix(name, prefix)) || !strings.HasPrefix(target, targetPrefix) || !viewerAppCheckPolicyID.MatchString(strings.TrimPrefix(target, targetPrefix)) || seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			safe := Object{"name": name, "targetResource": target}
			if v, exists := r["enforcementMode"]; exists {
				switch v {
				case "OFF", "UNENFORCED", "ENFORCED":
					safe["enforcementMode"] = v
				default:
					partial = true
				}
			}
			a := NewAsset("//firebaseappcheck.googleapis.com/"+name, FirebaseAppCheckResourcePolicyType, safe)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
			count++
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some App Check resource policy identities, targets or explicit modes malformed or duplicated")
	}
	out.record("viewer-appcheck:resource-policies:"+parent, count, err)
}
