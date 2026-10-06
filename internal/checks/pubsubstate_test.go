package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPubSubSubscriptionStateExplicitMetadata(t *testing.T) {
	a := inventory.NewAsset("//pubsub.googleapis.com/projects/demo/subscriptions/sub", "pubsub.googleapis.com/Subscription", inventory.Object{"detached": true, "topic": "_deleted-topic_"})
	got := pubsubSubscriptionState(a, time.Time{})
	if len(got) != 2 {
		t.Fatalf("expected two explicit state facets: %#v", got)
	}
	for _, d := range []inventory.Object{{"detached": true}, {"topic": "_deleted-topic_"}} {
		a.Resource.Data = d
		if got := pubsubSubscriptionState(a, time.Time{}); len(got) != 1 {
			t.Fatalf("expected one facet: %#v", got)
		}
	}
}

func TestPubSubSubscriptionStateRejectsUnknown(t *testing.T) {
	for _, d := range []inventory.Object{nil, {}, {"detached": false}, {"detached": "true"}, {"detached": 1}, {"topic": nil}, {"topic": "projects/demo/topics/_deleted-topic_"}, {"topic": "_deleted-topic_ "}, {"topic": "projects/other/topics/missing"}, {"state": "RESOURCE_ERROR"}} {
		a := inventory.NewAsset("//pubsub.googleapis.com/projects/demo/subscriptions/sub", "pubsub.googleapis.com/Subscription", d)
		if got := pubsubSubscriptionState(a, time.Time{}); len(got) != 0 {
			t.Fatalf("unknown state must not create a finding for %#v: %#v", d, got)
		}
	}
	a := inventory.NewAsset("wrong", "pubsub.googleapis.com/Topic", inventory.Object{"detached": true, "topic": "_deleted-topic_"})
	if got := pubsubSubscriptionState(a, time.Time{}); len(got) != 0 {
		t.Fatal("wrong type", got)
	}
}
