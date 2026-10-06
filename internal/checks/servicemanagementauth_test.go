package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestServiceManagementAuthExplicitRulesOnly(t *testing.T) {
	baseline := `{"_gcpbusterServiceAuth":{"complete":false,"methods":[{"method_digest":"` + strings.Repeat("a", 64) + `","authentication":"none","consumer_identity":"not_required","authentication_source":"rule","usage_source":"rule","source":"SOURCE_SENTINEL"}]}}`
	got := serviceManagementAuth(asset("gcpbuster.googleapis.com/ServiceConfig", baseline), time.Time{})
	if len(got) != 1 {
		t.Fatal(got)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "SOURCE_SENTINEL") {
		t.Fatal("leak")
	}
	for _, pair := range [][2]string{{`"none"`, `"jwt"`}, {`"none"`, `"oauth"`}, {`"none"`, `"api_key_alternative"`}, {`"none"`, `"unknown"`}, {`"not_required"`, `"required"`}, {`"not_required"`, `"unknown"`}, {strings.Repeat("a", 64), "bad"}} {
		if got := serviceManagementAuth(asset("gcpbuster.googleapis.com/ServiceConfig", strings.ReplaceAll(baseline, pair[0], pair[1])), time.Time{}); len(got) != 0 {
			t.Fatal(got)
		}
	}
	if got := serviceManagementAuth(asset("servicemanagement.googleapis.com/Service", baseline), time.Time{}); len(got) != 0 {
		t.Fatal(got)
	}
}
