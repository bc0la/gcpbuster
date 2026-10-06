package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerPubSubSubscriptionsWhitelistPreservesCheckedMetadata(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/projects/demo/subscriptions" || r.URL.Query().Get("fields") != viewerPubSubSubscriptionFields {
			t.Fatal(r.URL)
		}
		return response(200, `{"subscriptions":[{"name":"projects/123/subscriptions/example","topic":"_deleted-topic_","detached":true,"state":"ACTIVE","ackDeadlineSeconds":10,"messageRetentionDuration":"600s","retainAckedMessages":true,"expirationPolicy":{"ttl":"86400s","unknown":"DO_NOT_KEEP"},"retryPolicy":{"minimumBackoff":"1.5s","maximumBackoff":"600s"},"deadLetterPolicy":{"deadLetterTopic":"projects/other/topics/dead","maxDeliveryAttempts":5},"pushConfig":{"pushEndpoint":"https://example.invalid","oidcToken":{"serviceAccountEmail":"worker@demo.iam.gserviceaccount.com","audience":"https://example.invalid","unknown":"DO_NOT_KEEP"},"unknown":"DO_NOT_KEEP"},"bigqueryConfig":{"table":"project.dataset.table","serviceAccountEmail":"writer@example.invalid","state":"ACTIVE","useTopicSchema":true,"unknown":"DO_NOT_KEEP"},"cloudStorageConfig":{"bucket":"example-bucket","serviceAccountEmail":"writer@example.invalid","state":"ACTIVE","filenamePrefix":"DO_NOT_KEEP"},"bigtableConfig":{"table":"projects/demo/instances/instance/tables/table","serviceAccountEmail":"writer@example.invalid","state":"ACTIVE"},"labels":{"x":"DO_NOT_KEEP"},"filter":"DO_NOT_KEEP","messageTransforms":[{"javascriptUdf":{"code":"DO_NOT_KEEP"}}],"unknown":"DO_NOT_KEEP"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"pubsub.subscriptions.list": true}
	s := Snapshot{}
	c.viewerAutomationRows(context.Background(), &s, "https://pubsub.googleapis.com/v1/projects/demo/subscriptions", "pubsub.googleapis.com", "subscriptions", "Subscription", "demo", "projects/123", "")
	if len(s.Assets) != 1 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	d := s.Assets[0].Resource.Data
	if d["detached"] != true || Str(d["topic"]) != "_deleted-topic_" || Str(Get(d, "pushConfig", "oidcToken", "serviceAccountEmail")) != "worker@demo.iam.gserviceaccount.com" || Str(Get(d, "bigqueryConfig", "table")) != "project.dataset.table" || Str(Get(d, "bigtableConfig", "state")) != "ACTIVE" {
		t.Fatal(d)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal(string(b))
	}
}

func TestViewerPubSubSubscriptionsMalformedRowsDoNotDiscardLaterValid(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"subscriptions":[null,{"name":"projects/other/subscriptions/foreign"},{"name":"projects/demo/subscriptions/bad","detached":"true"},{"name":"projects/demo/subscriptions/bad2","pushConfig":{"oidcToken":false}},{"name":"projects/demo/subscriptions/bad3","retryPolicy":{"minimumBackoff":"garbage"}},{"name":"projects/demo/subscriptions/bad4","ackDeadlineSeconds":1.5},{"name":"projects/demo/subscriptions/valid"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"subscriptions":[{"name":"projects/demo/subscriptions/last","topic":"projects/demo/topics/topic"}]}`), nil
	})
	c.viewerPolicy.permissions = map[string]bool{"pubsub.subscriptions.list": true}
	s := Snapshot{}
	c.viewerAutomationRows(context.Background(), &s, "https://pubsub.googleapis.com/v1/projects/demo/subscriptions", "pubsub.googleapis.com", "subscriptions", "Subscription", "demo", "projects/123", "")
	if calls != 2 || len(s.Assets) != 2 || !hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
}

func TestViewerPubSubSubscriptionProjectionRejectsMalformedTypes(t *testing.T) {
	for _, d := range []Object{
		{"state": false}, {"topic": nil}, {"detached": 1}, {"expirationPolicy": nil}, {"bigqueryConfig": []any{}}, {"cloudStorageConfig": Object{"serviceAccountEmail": false}}, {"bigtableConfig": Object{"state": 1}}, {"pushConfig": Object{"oidcToken": Object{"audience": false}}}, {"messageRetentionDuration": "-1s"}, {"ackDeadlineSeconds": float64(-1)},
	} {
		if _, err := viewerPubSubSubscriptionProjection(d); err == nil {
			t.Fatal("accepted malformed metadata", d)
		}
	}
}
