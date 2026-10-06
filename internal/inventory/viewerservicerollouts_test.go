package inventory

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
)

func TestViewerServiceRolloutsHistoryPaginationProjection(t *testing.T) {
	calls := 0
	c := serviceManagementClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "servicemanagement.googleapis.com" || r.URL.Path != "/v1/services/example.com/rollouts" || r.URL.Query().Get("filter") != "strategy=TrafficPercentStrategy" || r.URL.Query().Get("fields") != viewerServiceRolloutFields {
			t.Fatal(r.URL)
		}
		if calls == 1 {
			return response(200, `{"rollouts":[{"rolloutId":"new","serviceName":"example.com","createTime":"2026-01-02T00:00:00Z","status":"FAILED_ROLLED_BACK","trafficPercentStrategy":{"percentages":{"config-2":100}},"createdBy":"DO_NOT_KEEP"}],"nextPageToken":"next"}`), nil
		}
		if r.URL.Query().Get("pageToken") != "next" {
			t.Fatal(r.URL)
		}
		return response(200, `{"rollouts":[{"rolloutId":"old","createTime":"2026-01-01T00:00:00Z","status":"SUCCESS","trafficPercentStrategy":{"percentages":{"example.com/config-1":100}},"error":"DO_NOT_KEEP"}]}`), nil
	})
	s := Snapshot{}
	c.viewerManagedServiceRollouts(context.Background(), &s, "demo", "projects/123", "example.com")
	if len(s.Assets) != 2 || hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	for _, a := range s.Assets {
		if a.Resource.Data["_gcpbusterTemporalScope"] != "retained_history_not_current" {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "DO_NOT_KEEP") {
		t.Fatal(string(b))
	}
}

func TestViewerServiceRolloutValidation(t *testing.T) {
	for _, weights := range []Object{{"config": float64(0)}, {"config": float64(101)}, {"config": float64(99)}, {"config": math.NaN()}, {"config": math.Inf(1)}, {"config": "100"}, {"foreign.com/config": float64(100)}, {"config": float64(50), "example.com/config": float64(50)}} {
		d := Object{"rolloutId": "rollout", "status": "SUCCESS", "createTime": "2026-01-01T00:00:00Z", "trafficPercentStrategy": Object{"percentages": weights}}
		if _, err := viewerServiceRolloutProjection(d, "example.com"); err == nil {
			t.Fatal(weights)
		}
	}
	for key, value := range (Object{"rolloutId": "../bad", "status": "INVALID", "serviceName": "foreign.com", "createTime": "invalid", "deleteServiceStrategy": Object{}}) {
		d := Object{"rolloutId": "rollout", "status": "SUCCESS", "createTime": "2026-01-01T00:00:00Z", "trafficPercentStrategy": Object{"percentages": Object{"config": float64(100)}}}
		d[key] = value
		if _, err := viewerServiceRolloutProjection(d, "example.com"); err == nil {
			t.Fatal(key, d)
		}
	}
}

func TestViewerServiceRolloutsPartialDenialRetainsHistory(t *testing.T) {
	for _, mode := range []string{"permission", "server", "late"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := serviceManagementClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "permission" {
					t.Fatal("unauthorized request")
				}
				if mode == "server" || calls == 2 {
					return response(403, `{}`), nil
				}
				return response(200, `{"rollouts":[null,{"rolloutId":"valid","status":"SUCCESS","createTime":"2026-01-01T00:00:00Z","trafficPercentStrategy":{"percentages":{"config":100}}}],"nextPageToken":"next"}`), nil
			})
			if mode == "permission" {
				c.viewerPolicy.permissions = map[string]bool{}
			}
			s := Snapshot{}
			c.viewerManagedServiceRollouts(context.Background(), &s, "demo", "projects/123", "example.com")
			want := 0
			if mode == "late" {
				want = 1
			}
			if len(s.Assets) != want || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
		})
	}
}

func TestServiceRolloutHistoryExactConfigJoin(t *testing.T) {
	s := Snapshot{Assets: []Asset{NewAsset("//servicemanagement.googleapis.com/services/example.com/configs/config", ServiceConfigType, Object{"name": "example.com", "id": "config", "producerProjectId": "demo"})}}
	for _, spec := range []struct{ service, id, status string }{{"example.com", "old", "SUCCESS"}, {"example.com", "new", "FAILED"}, {"other.com", "foreign", "SUCCESS"}} {
		a := NewAsset("//servicemanagement.googleapis.com/services/"+spec.service+"/rollouts/"+spec.id, ServiceRolloutType, Object{"rolloutId": spec.id, "serviceName": spec.service, "producerProjectId": "demo", "createTime": "2026-01-01T00:00:00Z", "status": spec.status, "trafficPercentStrategy": Object{"percentages": Object{"config": float64(100)}}})
		s.Assets = append(s.Assets, a)
	}
	correlateServiceRolloutHistory(&s, "demo")
	rows := List(s.Assets[0].Resource.Data["_gcpbusterRolloutHistory"])
	if len(rows) != 2 {
		t.Fatal(s)
	}
	for _, raw := range rows {
		row := Obj(raw)
		if len(row) != 4 || row["percentage"] != float64(100) || row["current"] != nil || row["active"] != nil {
			t.Fatal(row)
		}
	}
	s.Assets = s.Assets[:1]
	correlateServiceRolloutHistory(&s, "demo")
	if s.Assets[0].Resource.Data["_gcpbusterRolloutHistory"] != nil {
		t.Fatal("stale history", s)
	}
}
