package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func asset(kind, data string) inventory.Asset {
	a := inventory.NewAsset("test", kind, nil)
	if err := json.Unmarshal([]byte(data), &a.Resource.Data); err != nil {
		panic(err)
	}
	return a
}
func TestDetectionBoundaries(t *testing.T) {
	cases := []struct {
		name, kind, data string
		eval             func(inventory.Asset, time.Time) []Result
		want             int
	}{
		{"world ingress", "compute.googleapis.com/Firewall", `{"sourceRanges":["::/0"],"allowed":[{"IPProtocol":"tcp"}]}`, firewallIngress, 1},
		{"disabled firewall", "compute.googleapis.com/Firewall", `{"disabled":true,"allowed":[{"IPProtocol":"all"}]}`, firewallIngress, 0},
		{"egress", "compute.googleapis.com/Firewall", `{"direction":"EGRESS","allowed":[{"IPProtocol":"all"}]}`, firewallIngress, 0},
		{"private range", "compute.googleapis.com/Firewall", `{"sourceRanges":["10.0.0.0/8"],"allowed":[{"IPProtocol":"tcp"}]}`, firewallIngress, 0},
		{"source tag restriction", "compute.googleapis.com/Firewall", `{"sourceTags":["web"],"allowed":[{"IPProtocol":"tcp"}]}`, firewallIngress, 0},
		{"absent firewall sources defaults world", "compute.googleapis.com/Firewall", `{"allowed":[{"IPProtocol":"all"}]}`, firewallIngress, 1},
		{"UBLA ignores legacy ACL", "storage.googleapis.com/Bucket", `{"iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true}},"acl":[{"entity":"allUsers","role":"READER"}]}`, storageACL, 0},
		{"default ACL", "storage.googleapis.com/Bucket", `{"defaultObjectAcl":[{"entity":"allAuthenticatedUsers","role":"READER"}]}`, storageACL, 1},
		{"missing 2sv fields", "workspace.googleapis.com/User", `{"isAdmin":true}`, workspace2SV, 0},
		{"unenrolled admin", "workspace.googleapis.com/User", `{"isAdmin":true,"isEnrolledIn2Sv":false,"isEnforcedIn2Sv":false}`, workspace2SV, 2},
		{"suspended admin", "workspace.googleapis.com/User", `{"isAdmin":true,"suspended":true,"isEnrolledIn2Sv":false}`, workspace2SV, 0},
		{"scoped federation", "iam.googleapis.com/WorkloadIdentityPoolProvider", `{"attributeCondition":"assertion.repository_owner_id == '1234'"}`, federationTrust, 0},
		{"disabled federation", "iam.googleapis.com/WorkloadIdentityPoolProvider", `{"disabled":true}`, federationTrust, 0},
		{"unconstrained federation", "iam.googleapis.com/WorkloadIdentityPoolProvider", `{}`, federationTrust, 1},
		{"system key", "iam.googleapis.com/ServiceAccountKey", `{"keyType":"SYSTEM_MANAGED"}`, serviceAccountKeys, 0},
		{"expired key", "iam.googleapis.com/ServiceAccountKey", `{"keyType":"USER_MANAGED","validBeforeTime":"2020-01-01T00:00:00Z"}`, serviceAccountKeys, 0},
		{"active key", "iam.googleapis.com/ServiceAccountKey", `{"keyType":"USER_MANAGED","validAfterTime":"2020-01-01T00:00:00Z"}`, serviceAccountKeys, 1},
		{"TLS enforced", "sqladmin.googleapis.com/Instance", `{"settings":{"ipConfiguration":{"sslMode":"ENCRYPTED_ONLY","requireSsl":false}}}`, sqlHardening, 0},
		{"TLS unencrypted", "sqladmin.googleapis.com/Instance", `{"settings":{"ipConfiguration":{"sslMode":"ALLOW_UNENCRYPTED_AND_ENCRYPTED"}}}`, sqlHardening, 1},
		{"private gke", "container.googleapis.com/Cluster", `{"endpoint":"10.0.0.2","privateClusterConfig":{"enablePrivateEndpoint":true}}`, publicGKE, 0},
		{"restricted gke", "container.googleapis.com/Cluster", `{"endpoint":"192.0.2.2","masterAuthorizedNetworksConfig":{"enabled":true,"cidrBlocks":[{"cidrBlock":"192.0.2.0/24"}]}}`, publicGKE, 0},
		{"public BQ", "bigquery.googleapis.com/Dataset", `{"access":[{"specialGroup":"allAuthenticatedUsers","role":"READER"}]}`, publicBigQuery, 1},
		{"public run", "run.googleapis.com/Service", `{"metadata":{"annotations":{"run.googleapis.com/invoker-iam-disabled":"true"}}}`, publicServerless, 1},
		{"API restrictions", "apikeys.googleapis.com/Key", `{"restrictions":{"apiTargets":[{"service":"maps.googleapis.com"}],"browserKeyRestrictions":{"allowedReferrers":["https://example.invalid/*"]}}}`, apiKeys, 0},
		{"sensitive OAuth", "workspace.googleapis.com/OAuthGrant", `{"scopes":["openid","https://www.googleapis.com/auth/drive.readonly"]}`, workspaceOAuth, 1},
		{"basic OAuth", "workspace.googleapis.com/OAuthGrant", `{"scopes":["openid","email"]}`, workspaceOAuth, 0},
		{"no active drive grant", "workspace.googleapis.com/DriveFile", `{"permissions":[{"type":"anyone","deleted":true}]}`, workspaceDrive, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.eval(asset(tc.kind, tc.data), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
			if len(got) != tc.want {
				t.Fatalf("got %d results, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}
func TestSecretRedactionAndReferences(t *testing.T) {
	a := asset("run.googleapis.com/Service", `{"containers":[{"env":[{"name":"PASSWORD","value":"EXAMPLE_SECRET_VALUE"},{"name":"PASSWORD_REF","valueSource":{"secretKeyRef":{"secret":"safe","version":"latest"}}}]}],"startup-script":"export password=ANOTHER_SECRET_VALUE"}`)
	got := configurationSecrets(a, time.Now())
	if len(got) != 2 {
		t.Fatalf("expected two plaintext candidates: %+v", got)
	}
	data, _ := json.Marshal(got)
	for _, secret := range []string{"EXAMPLE_SECRET_VALUE", "ANOTHER_SECRET_VALUE", "PASSWORD_REF"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("leaked secret or flagged safe reference: %s", data)
		}
	}
}
func TestConditionalPublicPolicy(t *testing.T) {
	a := inventory.Asset{IAM: inventory.Object{"bindings": []any{inventory.Object{"role": "roles/run.invoker", "members": []any{"allAuthenticatedUsers"}, "condition": inventory.Object{"expression": "request.time < timestamp('2020-01-01T00:00:00Z')"}}}}}
	r := publicIAM(a, time.Now())
	if len(r) != 1 || r[0].Severity != "medium" || !strings.Contains(r[0].Title, "condition") {
		t.Fatalf("condition lost: %+v", r)
	}
}
func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	cats := map[string]int{}
	for _, c := range All {
		if seen[c.ID] || c.Eval == nil || c.Source == "" || len(c.Types) == 0 {
			t.Fatalf("invalid check %+v", c)
		}
		seen[c.ID] = true
		cats[c.Category]++
	}
	if len(cats) != 4 {
		t.Fatal(cats)
	}
	for _, c := range Categories {
		if cats[c.Key] == 0 {
			t.Fatal(c)
		}
	}
	if _, err := Select([]string{"typo"}, nil, nil); err == nil {
		t.Fatal("accepted unknown module")
	}
	if _, err := Select(nil, []string{"typo"}, nil); err == nil {
		t.Fatal("accepted unknown category")
	}
	got, err := Select(nil, []string{"secrets"}, []string{"configuration_secrets"})
	if err != nil || len(got) != cats["secrets"]-1 {
		t.Fatalf("filter failed: %+v %v", got, err)
	}
}
