package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestInheritedAuditDetectionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		data string
		want int
	}{
		{`{"complete":false,"configs":[]}`, 0},
		{`{"complete":true,"configs":[]}`, 1},
		{`{"complete":true,"configs":[{"service":"allServices","logType":"ADMIN_READ"},{"service":"allServices","logType":"DATA_READ"},{"service":"allServices","logType":"DATA_WRITE"}]}`, 0},
		{`{"complete":false,"configs":[{"service":"allServices","logType":"DATA_READ","exemptedMembers":["user:a@example.com"]}]}`, 1},
		{`{"complete":true,"configs":[{"service":"storage.googleapis.com","logType":"DATA_READ"}]}`, 1},
	} {
		if got := inheritedAuditConfig(asset(inventory.AuditConfigType, tc.data), time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}
