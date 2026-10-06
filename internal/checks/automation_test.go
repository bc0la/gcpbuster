package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestAutomationDeliveryRedactsURLCredentials(t *testing.T) {
	a := asset("cloudscheduler.googleapis.com/Job", `{"state":"ENABLED","httpTarget":{"uri":"https://name:PASSWORD@example.invalid/path?token=SECRET","oidcToken":{"serviceAccountEmail":"sa@example.invalid","audience":"https://example.invalid/?token=OTHER"}}}`)
	r := automationIdentityDelivery(a, time.Now())
	if len(r) != 1 || r[0].Severity != "medium" {
		t.Fatal(r)
	}
	b, _ := json.Marshal(r)
	for _, v := range []string{"PASSWORD", "SECRET", "OTHER"} {
		if strings.Contains(string(b), v) {
			t.Fatalf("sensitive URL retained: %s", b)
		}
	}
	a.Resource.Data["state"] = "PAUSED"
	if len(automationIdentityDelivery(a, time.Now())) != 0 {
		t.Fatal("paused job treated as active")
	}
	a = asset("pubsub.googleapis.com/Subscription", `{"pushConfig":{"pushEndpoint":"http://example.invalid/hook","oidcToken":{"serviceAccountEmail":"sa@example.invalid"}}}`)
	r = automationIdentityDelivery(a, time.Now())
	if len(r) != 1 || r[0].Severity != "high" {
		t.Fatal(r)
	}
}
func TestArtifactPrioritiesAndMissingUpstreams(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		publicPriority, privatePriority int
		want                            int
	}{
		{"private preferred", 10, 20, 0}, {"public preferred", 20, 10, 1}, {"tie", 10, 10, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			virtual := asset("artifactregistry.googleapis.com/Repository", `{"name":"projects/p/locations/r/repositories/virtual","virtualRepositoryConfig":{"upstreamPolicies":[]}}`)
			virtual.Resource.Data["virtualRepositoryConfig"] = inventory.Object{"upstreamPolicies": []any{inventory.Object{"repository": "standard", "priority": float64(tc.privatePriority)}, inventory.Object{"repository": "remote", "priority": float64(tc.publicPriority)}}}
			standard := asset("artifactregistry.googleapis.com/Repository", `{"name":"standard","mode":"STANDARD_REPOSITORY"}`)
			remote := asset("artifactregistry.googleapis.com/Repository", `{"name":"remote","mode":"REMOTE_REPOSITORY","remoteRepositoryConfig":{"pythonRepository":{"publicRepository":"PYPI"}}}`)
			snap := inventory.Snapshot{Assets: []inventory.Asset{virtual, standard, remote}}
			inventory.ResolveArtifactUpstreams(&snap)
			if len(snap.Assets) != 4 {
				t.Fatal(snap)
			}
			got := artifactUpstreams(snap.Assets[3], time.Now())
			if len(got) != tc.want {
				t.Fatal(got)
			}
		})
	}
	snap := inventory.Snapshot{Assets: []inventory.Asset{asset("artifactregistry.googleapis.com/Repository", `{"virtualRepositoryConfig":{"upstreamPolicies":[{"repository":"missing","priority":5}]}}`)}}
	inventory.ResolveArtifactUpstreams(&snap)
	if len(snap.Coverage) != 1 || snap.Coverage[0].Status != "incomplete" {
		t.Fatal("missing upstream hidden", snap)
	}
}
