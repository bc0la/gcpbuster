package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIAPSettingsDetectionAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{}`, 0},
		{`{"accessSettings":{"corsSettings":{"allowHttpOptions":false}}}`, 0},
		{`{"accessSettings":{"corsSettings":{"allowHttpOptions":"true"}}}`, 0},
		{`{"accessSettings":{"corsSettings":{"allowHttpOptions":true}}}`, 1},
		{`{"accessSettings":{"oauthSettings":{"clientSecret":"PRIVATE_SECRET","programmaticClients":["PRIVATE_CLIENT"]}}}`, 1},
		{`{"accessSettings":{"oauthSettings":{"programmaticClients":[]}}}`, 0},
		{`{"accessSettings":{"oauthSettings":{"programmaticClients":[1]}}}`, 0},
		{`{"accessSettings":{"reauthSettings":{"method":"METHOD_UNSPECIFIED"}}}`, 1},
		{`{"accessSettings":{"reauthSettings":{"method":"SECURE_KEY"}}}`, 0},
		{`{"accessSettings":{"allowedDomainsSettings":{"enable":false,"domains":["PRIVATE_DOMAIN"]}}}`, 1},
		{`{"accessSettings":{"allowedDomainsSettings":{"enable":true}}}`, 0},
	} {
		got := iapSettings(asset("iap.googleapis.com/IapSettings", tc.body), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE_") {
			t.Fatal("sensitive setting persisted")
		}
	}
}
