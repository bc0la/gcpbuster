package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFirebaseAppCheckResourcePolicyExplicitScopedOverride(t *testing.T) {
	for _, mode := range []any{"OFF", "UNENFORCED", "ENFORCED", "UNKNOWN", nil, false} {
		a := asset("gcpbuster.googleapis.com/FirebaseAppCheckResourcePolicy", `{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/policy-one","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/client.apps.googleusercontent.com"}`)
		a.Name = "//firebaseappcheck.googleapis.com/projects/123/services/oauth2.googleapis.com/resourcePolicies/policy-one"
		if mode != nil {
			a.Resource.Data["enforcementMode"] = mode
		}
		want := 0
		if mode == "OFF" || mode == "UNENFORCED" {
			want = 1
		}
		got := firebaseAppCheckResourceEnforcement(a, time.Now())
		if len(got) != want {
			t.Fatal(mode, got)
		}
	}
}

func TestFirebaseAppCheckResourcePolicyRejectsUnknownBindings(t *testing.T) {
	const name = "//firebaseappcheck.googleapis.com/projects/123/services/oauth2.googleapis.com/resourcePolicies/policy-one"
	for _, target := range []any{nil, true, "//oauth2.googleapis.com/projects/999/oauthClients/client", "//oauth2.googleapis.com/projects/demo/oauthClients/client", "https://oauth2.googleapis.com/projects/123/oauthClients/client", "//oauth2.googleapis.com/projects/123/oauthClients/../client", "//oauth2.googleapis.com/projects/123/oauthClients/client?secret=SENTINEL", "//firestore.googleapis.com/projects/123/databases/default"} {
		a := asset("gcpbuster.googleapis.com/FirebaseAppCheckResourcePolicy", `{"name":"projects/123/services/oauth2.googleapis.com/resourcePolicies/policy-one","enforcementMode":"OFF"}`)
		a.Name = name
		a.Resource.Data["targetResource"] = target
		if len(firebaseAppCheckResourceEnforcement(a, time.Now())) != 0 {
			t.Fatal(target)
		}
	}
	a := asset("gcpbuster.googleapis.com/FirebaseAppCheckResourcePolicy", `{"name":"projects/999/services/oauth2.googleapis.com/resourcePolicies/policy-one","targetResource":"//oauth2.googleapis.com/projects/123/oauthClients/client","enforcementMode":"OFF"}`)
	a.Name = name
	if len(firebaseAppCheckResourceEnforcement(a, time.Now())) != 0 {
		t.Fatal("mismatched data identity")
	}
	a.Resource.Data["name"] = strings.TrimPrefix(name, "//firebaseappcheck.googleapis.com/")
	a.Resource.Data["etag"] = "SENTINEL"
	a.Resource.Data["unknown"] = "SENTINEL"
	got := firebaseAppCheckResourceEnforcement(a, time.Now())
	raw, _ := json.Marshal(got)
	if len(got) != 1 || strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	a.Type = "gcpbuster.googleapis.com/FirebaseAppCheckService"
	if len(firebaseAppCheckResourceEnforcement(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
}

func TestFirebaseAppCheckEnforcementExplicitModes(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"enforcementMode":"OFF"}`, 1}, {`{"enforcementMode":"UNENFORCED"}`, 1},
		{`{"enforcementMode":"ENFORCED","replayProtection":"OFF"}`, 0}, {`{}`, 0},
		{`{"enforcementMode":"off"}`, 0}, {`{"enforcementMode":false}`, 0},
		{`{"enforcementMode":"UNSPECIFIED"}`, 0}, {`{"replayProtection":"UNENFORCED"}`, 0},
	} {
		a := asset("gcpbuster.googleapis.com/FirebaseAppCheckService", tc.body)
		a.Name = "//firebaseappcheck.googleapis.com/projects/123/services/firestore.googleapis.com"
		got := firebaseAppCheckEnforcement(a, time.Now())
		if len(got) != tc.want {
			t.Fatalf("%s: %+v", tc.body, got)
		}
	}
}

func TestFirebaseAppCheckScopeAndEvidence(t *testing.T) {
	a := asset("gcpbuster.googleapis.com/FirebaseAppCheckService", `{"name":"projects/123/services/firestore.googleapis.com","enforcementMode":"UNENFORCED","replayProtection":"SENTINEL","etag":"SENTINEL"}`)
	a.Name = "//firebaseappcheck.googleapis.com/projects/123/services/firestore.googleapis.com"
	got := firebaseAppCheckEnforcement(a, time.Now())
	raw, _ := json.Marshal(got)
	if len(got) != 1 || strings.Contains(string(raw), "SENTINEL") {
		t.Fatal(string(raw))
	}
	for _, name := range []string{"//firebaseappcheck.googleapis.com/projects/demo/services/firestore.googleapis.com", "//firebaseappcheck.googleapis.com/projects/123/services/evil.example", "//firebaseappcheck.googleapis.com/projects/999/services/firestore.googleapis.com", a.Name + "/resourcePolicies/p"} {
		a.Name = name
		if len(firebaseAppCheckEnforcement(a, time.Now())) != 0 {
			t.Fatal(name)
		}
	}
	a.Name = "//firebaseappcheck.googleapis.com/projects/123/services/firestore.googleapis.com"
	a.Type = "firestore.googleapis.com/Database"
	if len(firebaseAppCheckEnforcement(a, time.Now())) != 0 {
		t.Fatal("wrong type")
	}
}
