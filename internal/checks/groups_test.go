package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestGroupIAMPaths(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       int
	}{
		{"domain join", `{"settings":{"whoCanJoin":"ALL_IN_DOMAIN_CAN_JOIN"}}`, 1},
		{"public join", `{"settings":{"whoCanJoin":"ANYONE_CAN_JOIN"}}`, 1},
		{"request only", `{"settings":{"whoCanJoin":"CAN_REQUEST_TO_JOIN"}}`, 0},
		{"unknown", `{}`, 0},
		{"owner", `{"membership":{"members":[{"id":"u","role":"OWNER","status":"ACTIVE"}]}}`, 1},
		{"manager", `{"membership":{"members":[{"id":"u","role":"MANAGER"}]}}`, 1},
		{"ordinary member", `{"membership":{"members":[{"id":"u","role":"MEMBER"}]}}`, 0},
		{"suspended owner", `{"membership":{"members":[{"id":"u","role":"OWNER","status":"SUSPENDED"}]}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := groupIAMPaths(asset(inventory.GroupIAMType, tc.data), time.Now()); len(got) != tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestGroupIAMRestrictedTypesAreNotSelfJoinBypasses(t *testing.T) {
	for _, label := range []string{"cloudidentity.googleapis.com/groups.security", "cloudidentity.googleapis.com/groups.locked", "cloudidentity.googleapis.com/groups.dynamic"} {
		a := inventory.NewAsset("grant", inventory.GroupIAMType, inventory.Object{"settings": inventory.Object{"whoCanJoin": "ANYONE_CAN_JOIN"}, "membership": inventory.Object{"members": []any{inventory.Object{"id": "user", "role": "OWNER"}}}, "cloudIdentity": inventory.Object{"status": "observed", "labels": inventory.Object{label: ""}}})
		got := groupIAMPaths(a, time.Now())
		if len(got) != 2 || got[0].Severity != "info" || got[1].Severity != "info" || got[0].Evidence["group_type_assessment"] != "observed_restricted_group" {
			t.Fatal(label, got)
		}
		a.Resource.Data["cloudIdentity"] = inventory.Object{"status": "conflicting", "labels": inventory.Object{label: ""}}
		if got := groupIAMPaths(a, time.Now()); got[0].Severity != "high" || got[0].Evidence["group_type_assessment"] != "unknown" {
			t.Fatal("conflicts must stay unknown", got)
		}
		a.Resource.Data["cloudIdentity"] = inventory.Object{"status": "observed", "labels": inventory.Object{label: true}}
		if got := groupIAMPaths(a, time.Now()); got[0].Severity != "high" {
			t.Fatal("invalid label must not downgrade evidence", got)
		}
	}
}
