package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceGroupPublicArchiveHistoryBoundary(t *testing.T) {
	for _, tc := range []struct {
		data, severity string
		want           int
	}{
		{`{"whoCanViewMembership":"ANYONE_CAN_VIEW"}`, "", 0},
		{`{"whoCanDiscoverGroup":"ANYONE_CAN_DISCOVER","isArchived":"true"}`, "", 0},
		{`{"whoCanViewGroup":"ANYONE_CAN_VIEW"}`, "info", 1},
		{`{"whoCanViewGroup":"ANYONE_CAN_VIEW","isArchived":"false"}`, "info", 1},
		{`{"whoCanViewGroup":"ANYONE_CAN_VIEW","isArchived":"true"}`, "high", 1},
		{`{"whoCanViewGroup":"ANYONE_CAN_VIEW","isArchived":true}`, "high", 1},
		{`{"whoCanViewGroup":"ANYONE_CAN_VIEW","archiveOnly":"true","isArchived":"false"}`, "high", 1},
		{`{"whoCanViewGroup":"ALL_MEMBERS_CAN_VIEW","isArchived":"true"}`, "", 0},
	} {
		got := workspaceGroups(asset("workspace.googleapis.com/GroupSettings", tc.data), time.Now())
		if len(got) != tc.want || (len(got) > 0 && got[0].Severity != tc.severity) {
			t.Fatal(tc, got)
		}
	}
	got := workspaceGroups(asset("workspace.googleapis.com/GroupSettings", `{"whoCanJoin":"ANYONE_CAN_JOIN"}`), time.Now())
	if len(got) != 1 || !strings.Contains(got[0].Evidence["assessment"].(string), "eligible Google identity") {
		t.Fatal(got)
	}
}

func TestLookerStudioOfflinePublicSharingCredentials(t *testing.T) {
	a := inventory.NewAsset("workspace/lookerStudioReports/report-123", "workspace.googleapis.com/LookerStudioReport", inventory.Object{"schemaVersion": 1, "sharing": "ANYONE_WITH_LINK", "dataSources": []any{inventory.Object{"credentialMode": "OWNER", "name": "PRIVATE_SOURCE"}, inventory.Object{"credentialMode": "SERVICE_ACCOUNT"}, inventory.Object{"credentialMode": "VIEWER"}, inventory.Object{"credentialMode": "UNKNOWN"}}})
	got := lookerStudioSharing(a, time.Now())
	if len(got) != 3 || got[0].Severity != "info" || got[1].Severity != "medium" {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE_SOURCE") || !strings.Contains(string(b), "operator_supplied_offline_v1") {
		t.Fatal(string(b))
	}
	for _, sharing := range []any{"RESTRICTED", "PUBLIC", nil, true} {
		a.Resource.Data["sharing"] = sharing
		if len(lookerStudioSharing(a, time.Now())) != 0 {
			t.Fatal(sharing)
		}
	}
	a.Resource.Data["sharing"] = "PUBLIC_ON_WEB"
	a.Resource.Data["dataSources"] = []any{inventory.Object{"credentialMode": "VIEWER"}}
	if got := lookerStudioSharing(a, time.Now()); len(got) != 1 {
		t.Fatal("viewer not data-exposure proof", got)
	}
	a.Resource.Data["schemaVersion"] = "1"
	if len(lookerStudioSharing(a, time.Now())) != 0 {
		t.Fatal("invalid version")
	}
	a.Resource.Data["schemaVersion"] = 1
	a.Name = "https://lookerstudio.google.com/reporting/report-123"
	if len(lookerStudioSharing(a, time.Now())) != 0 {
		t.Fatal("not offline canonical name")
	}
}
