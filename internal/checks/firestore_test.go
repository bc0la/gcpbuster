package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFirestoreRecoveryExplicitEnums(t *testing.T) {
	for _, tc := range []struct {
		data             string
		protection, pitr int
	}{
		{`{}`, 0, 0}, {`{"deleteProtectionState":false,"pointInTimeRecoveryEnablement":false}`, 0, 0},
		{`{"deleteProtectionState":"DELETE_PROTECTION_STATE_UNSPECIFIED","pointInTimeRecoveryEnablement":"POINT_IN_TIME_RECOVERY_ENABLEMENT_UNSPECIFIED"}`, 0, 0},
		{`{"deleteProtectionState":"DELETE_PROTECTION_ENABLED","pointInTimeRecoveryEnablement":"POINT_IN_TIME_RECOVERY_ENABLED"}`, 0, 0},
		{`{"deleteProtectionState":"DELETE_PROTECTION_DISABLED"}`, 1, 0},
		{`{"pointInTimeRecoveryEnablement":"POINT_IN_TIME_RECOVERY_DISABLED","versionRetentionPeriod":"3600s"}`, 0, 1},
		{`{"deleteProtectionState":"DISABLED","pointInTimeRecoveryEnablement":"DISABLED"}`, 0, 0},
		{`{"versionRetentionPeriod":"3600s"}`, 0, 0},
	} {
		a := asset("firestore.googleapis.com/Database", tc.data)
		if got := firestoreDatabaseProtection(a, time.Now()); len(got) != tc.protection {
			t.Fatal(tc, got)
		}
		if got := firestorePITR(a, time.Now()); len(got) != tc.pitr {
			t.Fatal(tc, got)
		}
	}
}

func TestFirestoreRecoveryEvidenceAndTypeBoundary(t *testing.T) {
	data := `{"deleteProtectionState":"DELETE_PROTECTION_DISABLED","pointInTimeRecoveryEnablement":"POINT_IN_TIME_RECOVERY_DISABLED","description":"PRIVATE_SENTINEL"}`
	a := asset("firestore.googleapis.com/Database", data)
	p := firestoreDatabaseProtection(a, time.Now())
	r := firestorePITR(a, time.Now())
	if len(p) != 1 || len(r) != 1 || p[0].Severity != "low" || r[0].Severity != "info" {
		t.Fatal(p, r)
	}
	b, _ := json.Marshal(append(p, r...))
	if strings.Contains(string(b), "PRIVATE") || !strings.Contains(string(b), "one-hour") || !strings.Contains(string(b), "does not prevent document") {
		t.Fatal(string(b))
	}
	for _, typ := range []string{"firestore.googleapis.com/Backup", "spanner.googleapis.com/Database", "firebasedatabase.googleapis.com/DatabaseInstance"} {
		a.Type = typ
		if len(firestoreDatabaseProtection(a, time.Now())) != 0 || len(firestorePITR(a, time.Now())) != 0 {
			t.Fatal(typ)
		}
	}
}
