package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicPubSubObservedDeliveryContextScope(t *testing.T) {
	const topic = "projects/demo/topics/topic"
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//pubsub.googleapis.com/" + topic, "resourceType": "pubsub.googleapis.com/Topic", "principal": "allAuthenticatedUsers", "permissions": []any{"pubsub.topics.publish"}})
	s := inventory.Snapshot{Assets: []inventory.Asset{a, inventory.NewAsset("//pubsub.googleapis.com/projects/demo/subscriptions/sub", "pubsub.googleapis.com/Subscription", inventory.Object{"name": "projects/demo/subscriptions/sub", "topic": topic, "cloudStorageConfig": inventory.Object{"bucket": "bucket-name"}})}}
	inventory.CorrelatePubSubDeliveryContext(&s)
	got := publicPubSubCapabilities(s.Assets[0], time.Time{})
	if len(got) != 1 || obj(got[0].Evidence["observed_subscription_context"])["storage"] != 1 {
		t.Fatal(got)
	}
	marker := obj(s.Assets[0].Resource.Data["_gcpbusterPubSubDelivery"])
	marker["topic"] = "//pubsub.googleapis.com/projects/other/topics/topic"
	if pubsubDeliveryEvidence(s.Assets[0]) != nil {
		t.Fatal("foreign marker")
	}
	marker["topic"] = "//pubsub.googleapis.com/" + topic
	marker["push"] = 2
	if pubsubDeliveryEvidence(s.Assets[0]) != nil {
		t.Fatal("inconsistent counts")
	}
}
