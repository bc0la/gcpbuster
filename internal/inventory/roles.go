package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
	"regexp"
	"sort"
	"strings"
)

const PermissionGrantType = "gcpbuster.googleapis.com/PermissionGrant"

var rolePattern = regexp.MustCompile(`^(roles/[A-Za-z0-9_.]+|(projects|organizations)/[A-Za-z0-9_-]+/roles/[A-Za-z0-9_.]+)$`)

func RoleName(name string) string { return strings.TrimPrefix(name, "//iam.googleapis.com/") }

// ResolveRoles fetches full definitions for exactly the roles in collected
// bindings, including predefined roles absent from CAI RESOURCE responses.
func (c *Client) ResolveRoles(ctx context.Context, snap *Snapshot) {
	wanted := map[string]bool{}
	for _, a := range snap.Assets {
		for _, v := range List(a.IAM["bindings"]) {
			name := Str(Obj(v)["role"])
			if name != "" {
				wanted[name] = true
			}
		}
	}
	names := make([]string, 0, len(wanted))
	for n := range wanted {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			snap.record("role:"+name, 0, err)
			return
		}
		if !rolePattern.MatchString(name) {
			snap.record("role:"+name, 0, fmt.Errorf("invalid IAM role name"))
			continue
		}
		data, err := c.get(ctx, "https://iam.googleapis.com/v1/"+name, nil)
		if err != nil {
			snap.record("role:"+name, 0, err)
			continue
		}
		if Str(data["name"]) != name {
			snap.record("role:"+name, 0, fmt.Errorf("role API returned a mismatched name"))
			continue
		}
		if _, ok := data["includedPermissions"]; !ok && !Bool(data["deleted"]) && Str(data["stage"]) != "DISABLED" {
			snap.record("role:"+name, 0, fmt.Errorf("role definition omitted includedPermissions"))
			continue
		}
		snap.Assets = append(snap.Assets, NewAsset("//iam.googleapis.com/"+name, "iam.googleapis.com/Role", data))
		snap.record("role:"+name, 1, nil)
	}
}

// ExpandBindings correlates role definitions with actual policy bindings. Only
// permissions on the SAME resource/principal/condition are combined. It never
// treats an unassigned role definition as a principal's capability.
func ExpandBindings(snap *Snapshot) {
	roles := map[string]Object{}
	for _, a := range snap.Assets {
		if a.Type == "iam.googleapis.com/Role" && a.Resource.Data != nil {
			name := Str(a.Resource.Data["name"])
			if name == "" {
				name = RoleName(a.Name)
			}
			roles[name] = a.Resource.Data
		}
	}
	type group struct {
		asset              Asset
		principal          string
		condition          any
		roles, permissions map[string]bool
	}
	groups := map[string]*group{}
	missing := map[string]bool{}
	unclassified := map[string]bool{}
	for _, a := range snap.Assets {
		for _, v := range List(a.IAM["bindings"]) {
			binding := Obj(v)
			role := Str(binding["role"])
			definition, ok := roles[role]
			if !ok || definition["includedPermissions"] == nil {
				if Bool(definition["deleted"]) || Str(definition["stage"]) == "DISABLED" {
					continue
				}
				if !missing[role] {
					snap.Coverage = append(snap.Coverage, Coverage{Source: "permission-analysis:" + role, Status: "incomplete", Error: "Missing full role definition; no permissions inferred for this binding."})
					missing[role] = true
				}
				continue
			}
			if Bool(definition["deleted"]) || Str(definition["stage"]) == "DISABLED" {
				continue
			}
			condition, _ := json.Marshal(binding["condition"])
			for _, m := range List(binding["members"]) {
				principal := Str(m)
				if principal == "" || strings.HasPrefix(principal, "deleted:") {
					continue
				}
				key := a.Name + "\x00" + a.Type + "\x00" + principal + "\x00" + string(condition)
				g := groups[key]
				if g == nil {
					g = &group{a, principal, binding["condition"], map[string]bool{}, map[string]bool{}}
					groups[key] = g
				}
				g.roles[role] = true
				for _, p := range List(definition["includedPermissions"]) {
					if name := Str(p); name != "" {
						if _, known := permissioncatalog.Severity(name); !known && !unclassified[name] {
							unclassified[name] = true
							snap.Coverage = append(snap.Coverage, Coverage{Source: "permission-classification:" + name, Status: "incomplete", Error: "Assigned role contains a permission absent from the embedded risk catalog; classification requires review."})
						}
						g.permissions[name] = true
					}
				}
			}
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	toList := func(m map[string]bool) []any {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, len(keys))
		for i, k := range keys {
			out[i] = k
		}
		return out
	}
	for _, key := range keys {
		g := groups[key]
		digest := sha256.Sum256([]byte(key))
		a := NewAsset(fmt.Sprintf("%s/permission-analysis/%x", g.asset.Name, digest[:12]), PermissionGrantType, Object{"resource": g.asset.Name, "resourceType": g.asset.Type, "principal": g.principal, "condition": g.condition, "roles": toList(g.roles), "permissions": toList(g.permissions), "basis": "role definitions and direct IAM allow policy; not effective authorization"})
		a.Ancestors = g.asset.Ancestors
		snap.Assets = append(snap.Assets, a)
	}
	snap.Coverage = append(snap.Coverage, Coverage{Source: "permission-analysis", Status: "notice", Count: len(groups), Error: "Only supplied direct bindings and role definitions are correlated. Resource-type permission applicability, inherited/group access, conditional evaluation, deny policies, boundaries and service prerequisites are not resolved. Different scopes/conditions are not combined."})
}
