package checks

import (
	"testing"
	"time"
)

func TestFederationLiteralTrueConditionIsNotRestriction(t *testing.T) {
	for _, condition := range []string{"true", "  true ", "(true)", " (( true )) "} {
		a := asset("iam.googleapis.com/WorkloadIdentityPoolProvider", `{}`)
		a.Resource.Data["attributeCondition"] = condition
		got := federationTrust(a, time.Now())
		if len(got) != 1 || got[0].Evidence["condition_assessment"] != "literal_true" {
			t.Fatal(condition, got)
		}
		a.Resource.Data["disabled"] = true
		if len(federationTrust(a, time.Now())) != 0 {
			t.Fatal("disabled provider")
		}
	}
	for _, condition := range []any{true, false, "'true'", "false", "true && assertion.repository == 'team/repo'", "(true) || (false)", "assertion.repository_owner_id == '123'"} {
		a := asset("iam.googleapis.com/WorkloadIdentityPoolProvider", `{}`)
		a.Resource.Data["attributeCondition"] = condition
		if len(federationTrust(a, time.Now())) != 0 {
			t.Fatal("malformed/complex condition was treated as literal true", condition)
		}
	}
}
