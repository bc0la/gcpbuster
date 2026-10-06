package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func pubsubGrant(kind, principal string, permissions ...any) inventory.Asset {
	typ := "Topic"
	if kind == "subscriptions" {
		typ = "Subscription"
	}
	return inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//pubsub.googleapis.com/projects/demo/" + kind + "/messages", "resourceType": "pubsub.googleapis.com/" + typ, "principal": principal, "permissions": permissions})
}
func TestPublicPubSubExactResourceCapabilities(t *testing.T) {
	for _, tc := range []struct {
		kind, principal, permission string
		want                        int
	}{
		{"topics", "allUsers", "pubsub.topics.publish", 1}, {"topics", "allAuthenticatedUsers", "pubsub.topics.attachSubscription", 1}, {"subscriptions", "allUsers", "pubsub.subscriptions.consume", 1},
		{"topics", "allUsers", "pubsub.subscriptions.consume", 0}, {"subscriptions", "allUsers", "pubsub.topics.publish", 0}, {"topics", "allUsers", "pubsub.topics.get", 0}, {"topics", "allUsers", "pubsub.topics.publish.extra", 0}, {"topics", "allUsers", "pubsub.topics.*", 0}, {"topics", "user:a@example.com", "pubsub.topics.publish", 0},
	} {
		a := pubsubGrant(tc.kind, tc.principal, tc.permission)
		got := publicPubSubCapabilities(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && tc.principal == "allAuthenticatedUsers" && !strings.Contains(got[0].Title, "Google-authenticated") {
			t.Fatal(got)
		}
	}
	a := pubsubGrant("topics", "allUsers", "pubsub.topics.publish", "pubsub.topics.publish", "pubsub.topics.attachSubscription")
	if got := publicPubSubCapabilities(a, time.Now()); len(got) != 2 {
		t.Fatal(got)
	}
	for _, change := range []func(*inventory.Asset){func(a *inventory.Asset) { a.Type = "iam.googleapis.com/Role" }, func(a *inventory.Asset) {
		a.Resource.Data["resourceType"] = "cloudresourcemanager.googleapis.com/Project"
	}, func(a *inventory.Asset) { a.Resource.Data["resource"] = "//evil.invalid/projects/demo/topics/messages" }, func(a *inventory.Asset) {
		a.Resource.Data["resource"] = "//pubsub.googleapis.com/projects/demo/topics/messages/extra"
	}} {
		a := pubsubGrant("topics", "allUsers", "pubsub.topics.publish")
		change(&a)
		if got := publicPubSubCapabilities(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
func TestPublicPubSubAttachmentAndConditionsNotAccessProof(t *testing.T) {
	for _, condition := range []any{inventory.Object{"expression": "false"}, inventory.Object{}, "malformed"} {
		a := pubsubGrant("topics", "allUsers", "pubsub.topics.attachSubscription")
		a.Resource.Data["condition"] = condition
		got := publicPubSubCapabilities(a, time.Now())
		if len(got) != 1 || got[0].Evidence["condition"] == nil || got[0].Evidence["condition_status"] == "no condition supplied on this binding" || !strings.Contains(s(got[0].Evidence["assessment"]), "alone does not establish") {
			t.Fatal(got)
		}
	}
}
func TestPublicPubSubBindingExpansionKeepsScope(t *testing.T) {
	topic := inventory.NewAsset("//pubsub.googleapis.com/projects/demo/topics/messages", "pubsub.googleapis.com/Topic", nil)
	topic.IAM = inventory.Object{"bindings": []any{inventory.Object{"role": "roles/synthetic", "members": []any{"allUsers"}, "condition": inventory.Object{"expression": "false"}}}}
	role := inventory.NewAsset("//iam.googleapis.com/roles/synthetic", "iam.googleapis.com/Role", inventory.Object{"name": "roles/synthetic", "includedPermissions": []any{"pubsub.topics.publish", "pubsub.subscriptions.consume"}})
	snap := inventory.Snapshot{Assets: []inventory.Asset{topic, role}}
	inventory.ExpandBindings(&snap)
	got := []Result{}
	for _, a := range snap.Assets {
		got = append(got, publicPubSubCapabilities(a, time.Now())...)
	}
	if len(got) != 1 || got[0].Evidence["permission"] != "pubsub.topics.publish" || inventory.Str(inventory.Get(got[0].Evidence, "condition", "expression")) != "false" {
		t.Fatal(got)
	}
}
