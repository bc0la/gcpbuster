package inventory

import (
	"net/url"
	"reflect"
	"testing"
)

func TestViewerPubSubMetadataOnlyGuard(t *testing.T) {
	got, err := viewerRequestPermissions("GET", "https://pubsub.googleapis.com/v1/projects/demo/topics", nil)
	if err != nil || !reflect.DeepEqual(got, []string{"pubsub.topics.list"}) {
		t.Fatal(got, err)
	}
	for _, path := range []string{
		"topics/t:getIamPolicy", "topics/t:setIamPolicy", "topics/t:publish",
		"subscriptions/s:getIamPolicy", "subscriptions/s:pull", "subscriptions/s:acknowledge",
		"subscriptions/s:seek", "subscriptions/s:detach", "subscriptions/s:modifyPushConfig", "topics/t/subscriptions",
		"topics/topic", "subscriptions/subscription", "schemas/schema", "snapshots/snapshot", "schemas",
	} {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, "https://pubsub.googleapis.com/v1/projects/demo/"+path, nil); err == nil {
				t.Fatal("unreviewed PubSub request allowed", method, path)
			}
		}
	}
}

func TestViewerPubSubSchemaBasicGuard(t *testing.T) {
	for _, path := range []string{"schemas", "schemas/example:listRevisions"} {
		endpoint := "https://pubsub.googleapis.com/v1/projects/demo/" + path
		want := "pubsub.schemas.list"
		if path != "schemas" {
			want = "pubsub.schemas.listRevisions"
		}
		got, err := viewerRequestPermissions("GET", endpoint, url.Values{"view": {"BASIC"}})
		if err != nil || !reflect.DeepEqual(got, []string{want}) {
			t.Fatal(got, err)
		}
		for _, query := range []url.Values{nil, {"view": {"FULL"}}, {"view": {"BASIC", "FULL"}}, {"view": {"BASIC"}, "responseView": {"FULL"}}, {"view": {"BASIC"}, "response_view": {"FULL"}}} {
			if _, err := viewerRequestPermissions("GET", endpoint, query); err == nil {
				t.Fatal("unreviewed schema view", path, query)
			}
		}
		if _, err := viewerRequestPermissions("GET", endpoint+"?view=FULL", url.Values{"view": {"BASIC"}}); err == nil {
			t.Fatal("duplicate query sources")
		}
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, endpoint, url.Values{"view": {"BASIC"}}); err == nil {
				t.Fatal("mutation", method)
			}
		}
	}
	for _, path := range []string{"schemas/example", "schemas/example:commit", "schemas:validate", "snapshots/example", "snapshots/example:getIamPolicy", "snapshots/example:setIamPolicy"} {
		if _, err := viewerRequestPermissions("GET", "https://pubsub.googleapis.com/v1/projects/demo/"+path, url.Values{"view": {"BASIC"}}); err == nil {
			t.Fatal("unreviewed detail/action", path)
		}
	}
	got, err := viewerRequestPermissions("GET", "https://pubsub.googleapis.com/v1/projects/demo/snapshots", nil)
	if err != nil || !reflect.DeepEqual(got, []string{"pubsub.snapshots.list"}) {
		t.Fatal(got, err)
	}
}
