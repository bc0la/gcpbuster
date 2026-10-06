package inventory

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func role(name string, permissions ...string) Asset {
	var p []any
	for _, v := range permissions {
		p = append(p, v)
	}
	return NewAsset("//iam.googleapis.com/"+name, "iam.googleapis.com/Role", Object{"name": name, "includedPermissions": p})
}
func policy(name, role, principal string, condition any) Asset {
	a := Asset{Name: name, Type: "cloudresourcemanager.googleapis.com/Project", IAM: Object{"bindings": []any{Object{"role": role, "members": []any{principal}, "condition": condition}}}}
	return a
}
func grants(s Snapshot) []Asset {
	var out []Asset
	for _, a := range s.Assets {
		if a.Type == PermissionGrantType {
			out = append(out, a)
		}
	}
	return out
}

func TestBindingsDoNotCombinePrincipalsScopesOrConditions(t *testing.T) {
	base := "//cloudresourcemanager.googleapis.com/projects/123"
	s := Snapshot{Assets: []Asset{role("roles/one", "cloudfunctions.functions.update"), role("roles/two", "iam.serviceAccounts.actAs"),
		policy(base, "roles/one", "user:one@example.invalid", nil), policy(base, "roles/two", "user:two@example.invalid", nil),
		policy(base+"4", "roles/two", "user:one@example.invalid", nil), policy(base, "roles/two", "user:one@example.invalid", Object{"expression": "false"})}}
	ExpandBindings(&s)
	if len(grants(s)) != 4 {
		t.Fatal(grants(s))
	}
	for _, g := range grants(s) {
		if len(List(g.Resource.Data["permissions"])) != 1 {
			t.Fatal("unrelated permissions combined", g)
		}
	}
}
func TestSameBindingContextCombinesRoles(t *testing.T) {
	s := Snapshot{Assets: []Asset{role("roles/one", "cloudfunctions.functions.update"), role("roles/two", "iam.serviceAccounts.actAs"), policy("scope", "roles/one", "user:one", nil), policy("scope", "roles/two", "user:one", nil)}}
	ExpandBindings(&s)
	g := grants(s)
	if len(g) != 1 || len(List(g[0].Resource.Data["permissions"])) != 2 {
		t.Fatal(g)
	}
}
func TestMissingDisabledAndUnboundRoles(t *testing.T) {
	disabled := role("roles/disabled", "iam.serviceAccounts.getAccessToken")
	disabled.Resource.Data["stage"] = "DISABLED"
	s := Snapshot{Assets: []Asset{disabled, role("roles/unbound", "storage.objects.get"), policy("scope", "roles/missing", "user:one", nil), policy("scope", "roles/disabled", "user:one", nil)}}
	ExpandBindings(&s)
	if len(grants(s)) != 0 {
		t.Fatal("inactive/unbound role became a grant")
	}
	if len(s.Coverage) != 2 || s.Coverage[0].Status != "incomplete" {
		t.Fatal(s.Coverage)
	}
}
func TestResolveOnlyBoundRolesAndRejectInvalidNames(t *testing.T) {
	var paths []string
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("unexpected write")
		}
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "missing") {
			return response(403, `{}`), nil
		}
		return response(200, `{"name":"roles/viewer","includedPermissions":["storage.objects.get"]}`), nil
	})
	s := Snapshot{Assets: []Asset{policy("a", "roles/viewer", "user:one", nil), policy("b", "roles/viewer", "user:two", nil), policy("c", "roles/missing", "user:one", nil), policy("d", "roles/../secrets", "user:one", nil)}}
	c.ResolveRoles(context.Background(), &s)
	if len(paths) != 2 {
		t.Fatal(paths)
	}
	if len(s.Coverage) != 3 || len(s.Assets) != 5 {
		t.Fatal(s)
	}
}
