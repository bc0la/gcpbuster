package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAppEngineProtectionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{
		{`{}`, 0},
		{`{"iap":{"enabled":"false"}}`, 0},
		{`{"iap":{"enabled":true}}`, 0},
		{`{"iap":{"enabled":false},"servingStatus":"USER_DISABLED"}`, 0},
		{`{"iap":{"enabled":false},"servingStatus":"SYSTEM_DISABLED"}`, 0},
		{`{"iap":{"enabled":false,"oauth2ClientSecret":"PRIVATE_SECRET"},"servingStatus":"SERVING"}`, 1},
	} {
		got := appEngineProtection(asset("appengine.googleapis.com/Application", tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE_SECRET") {
			t.Fatal("secret persisted")
		}
	}
}

func TestAppEngineIngressBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{
		{"", 0}, {"INGRESS_TRAFFIC_ALLOWED_ALL", 1}, {"INGRESS_TRAFFIC_ALLOWED_UNSPECIFIED", 1},
		{"INGRESS_TRAFFIC_ALLOWED_INTERNAL_ONLY", 0}, {"INGRESS_TRAFFIC_ALLOWED_INTERNAL_AND_LB", 0}, {"unexpected", 0},
	} {
		got := appEngineIngress(asset("appengine.googleapis.com/Service", `{"networkSettings":{"ingressTrafficAllowed":"`+tc.value+`"}}`), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}
