package inventory

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
)

const GroupIAMType = "gcpbuster.googleapis.com/GroupIAMBinding"

func (c *Client) collectGroupMembers(ctx context.Context, snap *Snapshot, group Object) {
	id, email := Str(group["id"]), Str(group["email"])
	if id == "" || email == "" {
		snap.record("workspace:members", 0, fmt.Errorf("group identifier or email missing"))
		return
	}
	q := url.Values{"maxResults": {"200"}, "includeDerivedMembership": {"false"}}
	seen := map[string]bool{}
	var members []any
	complete := false
	for {
		page, err := c.get(ctx, "https://admin.googleapis.com/admin/directory/v1/groups/"+url.PathEscape(id)+"/members", q)
		if err != nil {
			snap.record("workspace:members:"+id, len(members), err)
			break
		}
		if page == nil {
			snap.record("workspace:members:"+id, len(members), fmt.Errorf("invalid member response"))
			break
		}
		if raw, exists := page["members"]; exists {
			if _, ok := raw.([]any); !ok {
				snap.record("workspace:members:"+id, len(members), fmt.Errorf("invalid member list"))
				break
			}
		}
		invalid := false
		for _, raw := range List(page["members"]) {
			m := Obj(raw)
			if Str(m["id"]) == "" || Str(m["role"]) == "" || Str(m["type"]) == "" {
				invalid = true
				continue
			}
			members = append(members, m)
		}
		if invalid {
			snap.record("workspace:members:"+id, len(members), fmt.Errorf("invalid membership record"))
			break
		}
		if raw, exists := page["nextPageToken"]; exists {
			if _, ok := raw.(string); !ok {
				snap.record("workspace:members:"+id, len(members), fmt.Errorf("invalid member pagination token"))
				break
			}
		}
		next := Str(page["nextPageToken"])
		if next == "" {
			complete = true
			snap.record("workspace:members:"+id, len(members), nil)
			break
		}
		if seen[next] {
			snap.record("workspace:members:"+id, len(members), fmt.Errorf("repeated member pagination token"))
			break
		}
		seen[next] = true
		q.Set("pageToken", next)
	}
	snap.Assets = append(snap.Assets, NewAsset("workspace/group-members/"+id, "workspace.googleapis.com/GroupMemberships", Object{"groupEmail": email, "groupId": id, "members": members, "complete": complete, "directOnly": true}))
}

// CorrelateGroupIAM preserves each binding's resource/role/condition. It does not
// expand effective permissions or assume that owners can edit locked groups.
func CorrelateGroupIAM(snap *Snapshot) {
	canonical := map[string]string{}
	settings := map[string]Object{}
	members := map[string]Object{}
	groupTypes := map[string]Object{}
	ambiguousAliases := map[string]bool{}
	addAlias := func(alias, email string) {
		alias = strings.ToLower(alias)
		email = strings.ToLower(email)
		if alias == "" || ambiguousAliases[alias] {
			return
		}
		if previous, exists := canonical[alias]; exists && previous != email {
			canonical[alias] = ""
			ambiguousAliases[alias] = true
		} else {
			canonical[alias] = email
		}
	}
	for _, a := range snap.Assets {
		d := a.Resource.Data
		switch a.Type {
		case "cloudidentity.googleapis.com/Group":
			email := strings.ToLower(Str(Get(d, "groupKey", "id")))
			if email == "" {
				continue
			}
			// Native Cloud Identity labels are supplied offline, not acquired
			// through the three Cloud IAM roles. Never infer ordinary group
			// membership semantics from absent or malformed labels.
			metadata := Object{"status": "unknown"}
			if labels := Obj(d["labels"]); labels != nil {
				selected := Object{}
				valid := true
				for _, key := range []string{"cloudidentity.googleapis.com/groups.discussion_forum", "cloudidentity.googleapis.com/groups.security", "cloudidentity.googleapis.com/groups.locked", "cloudidentity.googleapis.com/groups.dynamic"} {
					if v, present := labels[key]; present {
						if value, ok := v.(string); ok && value == "" {
							selected[key] = ""
						} else {
							valid = false
						}
					}
				}
				if valid && len(selected) > 0 {
					metadata = Object{"status": "observed", "labels": selected}
				}
			}
			if previous, exists := groupTypes[email]; exists && !reflect.DeepEqual(previous, metadata) {
				metadata = Object{"status": "conflicting"}
			}
			groupTypes[email] = metadata
			addAlias(email, email)
		case "workspace.googleapis.com/Group":
			email := Str(d["email"])
			if email == "" {
				continue
			}
			addAlias(email, email)
			for _, key := range []string{"aliases", "nonEditableAliases"} {
				for _, alias := range List(d[key]) {
					addAlias(Str(alias), email)
				}
			}
		case "workspace.googleapis.com/GroupSettings":
			email := strings.ToLower(Str(d["email"]))
			if email != "" {
				settings[email] = d
				addAlias(email, email)
			}
		case "workspace.googleapis.com/GroupMemberships":
			email := strings.ToLower(Str(d["groupEmail"]))
			if email != "" {
				members[email] = d
				addAlias(email, email)
			}
		}
	}
	assets := append([]Asset(nil), snap.Assets...)
	unresolved := 0
	for _, a := range assets {
		for bi, raw := range List(a.IAM["bindings"]) {
			binding := Obj(raw)
			for mi, rawMember := range List(binding["members"]) {
				principal := Str(rawMember)
				if !strings.HasPrefix(principal, "group:") {
					continue
				}
				email := canonical[strings.ToLower(strings.TrimPrefix(principal, "group:"))]
				if email == "" || (settings[email] == nil && members[email] == nil) {
					unresolved++
					continue
				}
				x := NewAsset(fmt.Sprintf("%s/group-iam/%d/%d", a.Name, bi, mi), GroupIAMType, Object{"groupEmail": email, "principal": principal, "role": binding["role"], "condition": binding["condition"], "boundResource": a.Name, "settings": settings[email], "membership": members[email], "cloudIdentity": groupTypes[email]})
				x.Ancestors = a.Ancestors
				snap.Assets = append(snap.Assets, x)
			}
		}
	}
	if unresolved > 0 {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "group-iam:unresolved", Status: "notice", Count: unresolved, Error: "IAM group bindings lack unambiguous Workspace settings/membership evidence. No inference of safe membership or effective access is possible."})
	}
}
