package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestEffectiveOrgPoliciesCollection(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "orgpolicy.googleapis.com" || !strings.HasPrefix(r.URL.Path, "/v2/projects/test/policies/") || !strings.HasSuffix(r.URL.Path, ":getEffectivePolicy") {
			t.Fatal(r.URL)
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/projects/test/policies/"), ":getEffectivePolicy")
		rule := Object{"enforce": false}
		if id == "iam.allowedPolicyMemberDomains" || id == "compute.vmExternalIpAccess" {
			rule = Object{"allowAll": true}
		}
		b, _ := json.Marshal(Object{"name": "projects/123/policies/" + id, "spec": Object{"rules": []any{rule}}, "dryRunSpec": Object{"rules": []any{Object{"enforce": true}}}})
		return response(200, string(b)), nil
	})
	s := Snapshot{}
	c.CollectOrgPolicies(context.Background(), &s, []string{"projects/test", "projects/test"})
	if calls != len(OrgPolicyConstraints) || len(s.Assets) != calls || hasCoverage(s, "failed") {
		t.Fatal(calls, s)
	}
	for _, a := range s.Assets {
		if a.Resource.Data["dryRunSpec"] != nil || !Bool(a.Resource.Data["effective"]) {
			t.Fatal(a)
		}
	}
}

func TestOrgPolicyMissingEvidenceCannotLookClean(t *testing.T) {
	for _, body := range []string{`{}`, `{"name":"folders/elsewhere/policies/iam.disableServiceAccountKeyCreation","spec":{"rules":[{"enforce":false}]}}`, `DENIED`} {
		t.Run(body, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) {
				if body == "DENIED" {
					return response(403, "PRIVATE_ERROR"), nil
				}
				return response(200, body), nil
			})
			s := Snapshot{}
			c.CollectOrgPolicies(context.Background(), &s, []string{"folders/2"})
			if len(s.Assets) != 0 || !hasCoverage(s, "failed") {
				t.Fatal(s)
			}
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "PRIVATE_ERROR") {
				t.Fatal("upstream body leaked")
			}
		})
	}
}
