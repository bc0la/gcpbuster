package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestOrgPolicyGuardrailBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, id, rules string
		effective       bool
		want            int
	}{
		{"disabled", "iam.disableServiceAccountKeyCreation", `[{"enforce":false}]`, true, 1},
		{"enforced", "iam.disableServiceAccountKeyCreation", `[{"enforce":true}]`, true, 0},
		{"missing enforcement", "iam.disableServiceAccountKeyCreation", `[{}]`, true, 0},
		{"not effective", "iam.disableServiceAccountKeyCreation", `[{"enforce":false}]`, false, 0},
		{"conditional", "iam.disableServiceAccountKeyCreation", `[{"enforce":false,"condition":{"expression":"resource.hasTagKey('x')"}}]`, true, 0},
		{"unknown constraint", "custom.unknown", `[{"enforce":false}]`, true, 0},
		{"allow all domains", "iam.allowedPolicyMemberDomains", `[{"allowAll":true}]`, true, 1},
		{"restricted domains", "iam.allowedPolicyMemberDomains", `[{"values":{"allowedValues":["C01234"]}}]`, true, 0},
		{"deny all", "compute.vmExternalIpAccess", `[{"denyAll":true}]`, true, 0},
		{"conflicting variants", "compute.vmExternalIpAccess", `[{"allowAll":true,"denyAll":true}]`, true, 0},
		{"missing list", "compute.vmExternalIpAccess", `[{"values":{}}]`, true, 0},
		{"multiple boolean rules", "iam.disableServiceAccountKeyCreation", `[{"enforce":true},{"enforce":false}]`, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset(inventory.EffectiveOrgPolicyType, `{"constraint":"`+tc.id+`","spec":{"rules":`+tc.rules+`}}`)
			a.Resource.Data["effective"] = tc.effective
			if got := orgPolicyGuardrails(a, time.Now()); len(got) != tc.want {
				t.Fatal(got)
			}
		})
	}
}
