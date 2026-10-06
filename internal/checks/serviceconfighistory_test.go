package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceConfigHistoryIsNotCurrent(t *testing.T) {
	a := asset("gcpbuster.googleapis.com/ServiceConfig", `{"_gcpbusterRolloutHistory":[{"rolloutId":"r1","status":"SUCCESS","createTime":"2026-01-01T00:00:00Z","percentage":100,"createdBy":"NEVER_SAVE"},{"rolloutId":"r2","status":"CURRENT","createTime":"2026-01-01T00:00:00Z","percentage":100},{"rolloutId":"r3","status":"SUCCESS","createTime":"invalid","percentage":100}]}`)
	got := serviceConfigHistoryEvidence(a)
	if len(got) != 1 {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "NEVER_SAVE") || !strings.Contains(string(b), "retained_history_not_current") {
		t.Fatal(string(b))
	}
}
