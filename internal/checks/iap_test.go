package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestIAPBackendProtectionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{
		{`{}`, 0},
		{`{"protocol":"HTTP"}`, 0},
		{`{"protocol":"HTTP","iap":{}}`, 0},
		{`{"protocol":"HTTP","iap":{"enabled":"false"}}`, 0},
		{`{"protocol":"HTTP","iap":{"enabled":true}}`, 0},
		{`{"protocol":"TCP","iap":{"enabled":false}}`, 0},
		{`{"protocol":"HTTPS","iap":{"enabled":false,"oauth2ClientSecret":"PRIVATE_SECRET"}}`, 1},
		{`{"protocol":"HTTP2","iap":{"enabled":false}}`, 1},
	} {
		got := iapBackendProtection(asset("compute.googleapis.com/BackendService", tc.data), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE_SECRET") {
			t.Fatal("secret leaked")
		}
	}
}

func TestIAPAccessorBoundaries(t *testing.T) {
	for _, tc := range []struct {
		member, role, severity string
		conditional            bool
	}{
		{"allUsers", "roles/iap.httpsResourceAccessor", "high", false},
		{"allAuthenticatedUsers", "roles/iap.tunnelResourceAccessor", "medium", true},
		{"serviceAccount:sa@p.iam.gserviceaccount.com", "roles/iap.httpsResourceAccessor", "medium", false},
		{"user:person@example.com", "roles/iap.tunnelResourceAccessor", "info", false},
		{"deleted:serviceAccount:sa", "roles/iap.httpsResourceAccessor", "", false},
		{"", "roles/iap.httpsResourceAccessor", "", false},
		{"allUsers", "roles/viewer", "", false},
	} {
		b := inventory.Object{"role": tc.role, "members": []any{tc.member}}
		if tc.conditional {
			b["condition"] = inventory.Object{"expression": "true"}
		}
		a := inventory.NewAsset("//iap.googleapis.com/projects/123/iap_web", "iap.googleapis.com/PolicyResource", nil)
		a.IAM = inventory.Object{"bindings": []any{b}}
		got := iapAccessGrants(a, time.Now())
		if tc.severity == "" {
			if len(got) != 0 {
				t.Fatal(tc, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != tc.severity || got[0].Evidence["binding_resource"] != a.Name {
			t.Fatal(tc, got)
		}
		if tc.conditional && got[0].Evidence["condition"] == nil {
			t.Fatal("condition lost")
		}
	}
}
