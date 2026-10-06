package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func pubsubContextSubscription(id, topic string, data Object) Asset {
	data["name"] = "projects/demo/subscriptions/" + id
	data["topic"] = topic
	return NewAsset("//pubsub.googleapis.com/"+Str(data["name"]), "pubsub.googleapis.com/Subscription", data)
}

func TestPubSubDeliveryExactTopicSubsetAndRedaction(t *testing.T) {
	const topic = "projects/demo/topics/topic"
	grant := NewAsset("grant", PermissionGrantType, Object{"resource": "//pubsub.googleapis.com/" + topic, "resourceType": "pubsub.googleapis.com/Topic"})
	s := Snapshot{Assets: []Asset{grant,
		pubsubContextSubscription("push", topic, Object{"pushConfig": Object{"pushEndpoint": "https://example.invalid/SENTINEL?secret=SENTINEL"}, "state": "ACTIVE"}),
		pubsubContextSubscription("export", topic, Object{"bigqueryConfig": Object{"table": "demo.dataset.table"}}),
		pubsubContextSubscription("unknown", topic, Object{}),
		pubsubContextSubscription("detached", topic, Object{"detached": true, "pushConfig": Object{"pushEndpoint": "https://example.invalid"}}),
	}}
	CorrelatePubSubDeliveryContext(&s)
	got := Obj(s.Assets[0].Resource.Data["_gcpbusterPubSubDelivery"])
	if got["observed_subscriptions"] != 4 || got["push"] != 1 || got["bigquery"] != 1 || got["unknown"] != 1 || got["detached"] != 1 {
		t.Fatal(got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SENTINEL") || strings.Contains(string(raw), "example.invalid") {
		t.Fatal(string(raw))
	}
	// Input metadata is untouched; only the marker contains safe aggregate facts.
	if Get(s.Assets[1].Resource.Data, "pushConfig", "pushEndpoint") == nil {
		t.Fatal("source modified")
	}
}

func TestPubSubDeliveryConflictsScopeAndBounds(t *testing.T) {
	const topic = "projects/demo/topics/topic"
	grant := NewAsset("grant", PermissionGrantType, Object{"resource": "//pubsub.googleapis.com/" + topic, "resourceType": "pubsub.googleapis.com/Topic"})
	one := pubsubContextSubscription("duplicate", topic, Object{"state": "ACTIVE"})
	s := Snapshot{Assets: []Asset{grant, one, pubsubContextSubscription("duplicate", topic, Object{"state": "RESOURCE_ERROR"}), one, pubsubContextSubscription("foreign", "projects/other/topics/topic", Object{}), pubsubContextSubscription("union", topic, Object{"pushConfig": Object{"pushEndpoint": "https://example.invalid"}, "bigqueryConfig": Object{"table": "demo.dataset.table"}})}}
	CorrelatePubSubDeliveryContext(&s)
	got := Obj(s.Assets[0].Resource.Data["_gcpbusterPubSubDelivery"])
	if got["observed_subscriptions"] != 1 || got["unknown"] != 1 {
		t.Fatal(got)
	}
	s.Assets[0].Resource.Data["resourceType"] = "cloudresourcemanager.googleapis.com/Project"
	CorrelatePubSubDeliveryContext(&s)
	if s.Assets[0].Resource.Data["_gcpbusterPubSubDelivery"] != nil {
		t.Fatal("project/stale marker")
	}
	s.Assets = append([]Asset{grant}, make([]Asset, 100001)...)
	s.Assets[0].Resource.Data["_gcpbusterPubSubDelivery"] = Object{"stale": true}
	CorrelatePubSubDeliveryContext(&s)
	if s.Assets[0].Resource.Data["_gcpbusterPubSubDelivery"] != nil || !hasCoverage(s, "incomplete") {
		t.Fatal("bounds")
	}
}
