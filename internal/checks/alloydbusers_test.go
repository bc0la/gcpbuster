package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestAlloyDBManagedUserRole(t *testing.T) {
	for _, tc := range []struct {
		roles any
		want  int
	}{{[]any{"alloydbsuperuser"}, 1}, {[]any{"postgres"}, 0}, {[]any{"ALLOYDBSUPERUSER"}, 0}, {[]any{false}, 0}, {"alloydbsuperuser", 0}, {nil, 0}} {
		a := inventory.NewAsset("user", inventory.AlloyDBUserType, inventory.Object{"databaseRoles": tc.roles})
		if got := alloyDBUserRoles(a, time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
		a.Type = "iam.googleapis.com/ServiceAccount"
		if got := alloyDBUserRoles(a, time.Now()); len(got) != 0 {
			t.Fatal(got)
		}
	}
}
