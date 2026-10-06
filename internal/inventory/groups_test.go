package inventory

import (
	"context"
	"net/http"
	"testing"
)

func TestGroupMemberReadsBlockedByViewerBoundary(t *testing.T) {
	for _, denied := range []bool{false, true} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "GET" || r.URL.Host != "admin.googleapis.com" || r.URL.Path != "/admin/directory/v1/groups/group-id/members" || r.URL.Query().Get("includeDerivedMembership") != "false" {
				t.Fatal(r.URL)
			}
			if calls == 1 {
				return response(200, `{"members":[{"id":"owner-id","email":"owner@example.com","type":"USER","role":"OWNER"}],"nextPageToken":"more"}`), nil
			}
			if r.URL.Query().Get("pageToken") != "more" {
				t.Fatal("lost pagination")
			}
			if denied {
				return response(403, "PRIVATE_ERROR"), nil
			}
			return response(200, `{}`), nil
		})
		s := Snapshot{}
		c.collectGroupMembers(context.Background(), &s, Object{"id": "group-id", "email": "group@example.com"})
		if calls != 0 || len(s.Assets) != 1 || Bool(s.Assets[0].Resource.Data["complete"]) || !hasCoverage(s, "failed") {
			t.Fatal(calls, s)
		}
		if len(List(s.Assets[0].Resource.Data["members"])) != 0 {
			t.Fatal("viewer cannot collect membership")
		}
	}
}

func TestMalformedMembershipNotComplete(t *testing.T) {
	for _, body := range []string{`null`, `{"members":{}}`, `{"members":[{}]}`, `{"nextPageToken":42}`} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, body), nil })
		s := Snapshot{}
		c.collectGroupMembers(context.Background(), &s, Object{"id": "g", "email": "g@example.com"})
		if !hasCoverage(s, "failed") || Bool(s.Assets[0].Resource.Data["complete"]) {
			t.Fatal(body, s)
		}
	}
}

func TestGroupIAMAliasCorrelationPreservesBinding(t *testing.T) {
	g := NewAsset("g", "workspace.googleapis.com/Group", Object{"email": "group@example.com", "aliases": []any{"alias@example.com"}})
	settings := NewAsset("settings", "workspace.googleapis.com/GroupSettings", Object{"email": "group@example.com", "whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN"})
	iam := Asset{Name: "projects/test", IAM: Object{"bindings": []any{Object{"role": "roles/viewer", "members": []any{"group:ALIAS@example.com"}, "condition": Object{"expression": "request.time < timestamp('2020-01-01T00:00:00Z')"}}}}}
	s := Snapshot{Assets: []Asset{g, settings, iam}}
	CorrelateGroupIAM(&s)
	if len(s.Assets) != 4 {
		t.Fatal(s)
	}
	d := s.Assets[3].Resource.Data
	if Str(d["groupEmail"]) != "group@example.com" || Str(d["boundResource"]) != "projects/test" || Obj(d["condition"])["expression"] == nil {
		t.Fatal(d)
	}
	// Conflicting alias ownership must prevent a join to either group.
	s = Snapshot{Assets: []Asset{g, settings, iam, NewAsset("g2", "workspace.googleapis.com/Group", Object{"email": "other@example.com", "aliases": []any{"alias@example.com"}})}}
	CorrelateGroupIAM(&s)
	if len(s.Assets) != 4 || len(s.Coverage) == 0 {
		t.Fatal("ambiguous group matched", s)
	}
}

func TestGroupIAMOfflineNativeLabelsAndStickyAmbiguity(t *testing.T) {
	settings := NewAsset("settings", "workspace.googleapis.com/GroupSettings", Object{"email": "group@example.com", "whoCanJoin": "ANYONE_CAN_JOIN"})
	native := NewAsset("groups/123", "cloudidentity.googleapis.com/Group", Object{"groupKey": Object{"id": "group@example.com"}, "labels": Object{"cloudidentity.googleapis.com/groups.security": "", "cloudidentity.googleapis.com/groups.discussion_forum": ""}, "description": "PRIVATE_METADATA"})
	iam := Asset{Name: "projects/test", IAM: Object{"bindings": []any{Object{"role": "roles/viewer", "members": []any{"group:group@example.com"}}}}}
	s := Snapshot{Assets: []Asset{settings, native, iam}}
	CorrelateGroupIAM(&s)
	if len(s.Assets) != 4 || Str(Get(s.Assets[3].Resource.Data, "cloudIdentity", "status")) != "observed" {
		t.Fatal(s)
	}
	metadata := Obj(s.Assets[3].Resource.Data["cloudIdentity"])
	if len(metadata) != 2 || metadata["description"] != nil {
		t.Fatal("only selected type evidence should be correlated", metadata)
	}
	conflict := NewAsset("groups/124", "cloudidentity.googleapis.com/Group", Object{"groupKey": Object{"id": "group@example.com"}, "labels": Object{"cloudidentity.googleapis.com/groups.discussion_forum": ""}})
	s = Snapshot{Assets: []Asset{settings, native, conflict, native, iam}}
	CorrelateGroupIAM(&s)
	if Str(Get(s.Assets[5].Resource.Data, "cloudIdentity", "status")) != "conflicting" {
		t.Fatal("repeated evidence must not clear conflict", s)
	}
	alias := NewAsset("g", "workspace.googleapis.com/Group", Object{"email": "group@example.com", "aliases": []any{"alias@example.com"}})
	other := NewAsset("g2", "workspace.googleapis.com/Group", Object{"email": "other@example.com", "aliases": []any{"alias@example.com"}})
	iam.IAM = Object{"bindings": []any{Object{"role": "roles/viewer", "members": []any{"group:alias@example.com"}}}}
	s = Snapshot{Assets: []Asset{alias, other, alias, settings, iam}}
	CorrelateGroupIAM(&s)
	if len(s.Assets) != 5 || len(s.Coverage) == 0 {
		t.Fatal("repetition cleared alias ambiguity", s)
	}
}
