package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func filestoreFixture(options []any) inventory.Asset {
	return inventory.NewAsset("filestore", "file.googleapis.com/Instance", inventory.Object{"fileShares": []any{inventory.Object{"name": "SENTINEL", "nfsExportOptions": options}}, "description": "SENTINEL"})
}
func TestFilestoreRootTrustExplicitOptionOnly(t *testing.T) {
	for _, tc := range []struct {
		access, squash string
		ranges         any
		want           int
	}{
		{"READ_WRITE", "NO_ROOT_SQUASH", []any{"10.0.0.1"}, 1}, {"READ_ONLY", "NO_ROOT_SQUASH", []any{"10.0.0.0/8"}, 0}, {"READ_WRITE", "ROOT_SQUASH", []any{"10.0.0.0/8"}, 0},
		{"", "NO_ROOT_SQUASH", []any{"10.0.0.0/8"}, 0}, {"READ_WRITE", "", []any{"10.0.0.0/8"}, 0}, {"ACCESS_MODE_UNSPECIFIED", "SQUASH_MODE_UNSPECIFIED", []any{"0.0.0.0/0"}, 0},
		{"READ_WRITE", "NO_ROOT_SQUASH", nil, 0}, {"READ_WRITE", "NO_ROOT_SQUASH", []any{"::/0"}, 0}, {"READ_WRITE", "NO_ROOT_SQUASH", []any{"10.0.0.0/8", "SENTINEL"}, 0},
	} {
		a := filestoreFixture([]any{inventory.Object{"accessMode": tc.access, "squashMode": tc.squash, "ipRanges": tc.ranges, "description": "SENTINEL"}})
		got := filestoreRootTrust(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SENTINEL") {
			t.Fatal(string(b))
		}
	}
}
func TestFilestoreExportSourcesConfigurationNotReachability(t *testing.T) {
	for _, tc := range []struct {
		ranges any
		mode   string
		want   int
	}{{[]any{"0.0.0.0/0", "0.0.0.0/0"}, "READ_WRITE", 1}, {[]any{"0.0.0.0/0"}, "READ_ONLY", 1}, {[]any{"10.0.0.0/8"}, "READ_WRITE", 0}, {[]any{"::/0"}, "READ_WRITE", 0}, {nil, "READ_WRITE", 0}, {[]any{"0.0.0.0/0"}, "", 0}, {[]any{false}, "READ_WRITE", 0}} {
		got := filestoreExportSources(filestoreFixture([]any{inventory.Object{"ipRanges": tc.ranges, "accessMode": tc.mode}}), time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		for _, r := range got {
			if !strings.Contains(s(r.Evidence["assessment"]), "not internet-public") {
				t.Fatal(r)
			}
		}
	}
}
func TestFilestoreOverlappingConfigurationRemainsExplicit(t *testing.T) {
	a := filestoreFixture([]any{inventory.Object{"accessMode": "READ_WRITE", "squashMode": "NO_ROOT_SQUASH", "ipRanges": []any{"0.0.0.0/0"}}, inventory.Object{"accessMode": "READ_ONLY", "squashMode": "ROOT_SQUASH", "ipRanges": []any{"10.0.0.0/8"}}})
	a.Resource.Data["tier"] = "REGIONAL"
	for _, got := range [][]Result{filestoreRootTrust(a, time.Now()), filestoreExportSources(a, time.Now())} {
		if len(got) != 1 || !strings.Contains(s(got[0].Evidence["assessment"]), "Narrower-prefix") {
			t.Fatal(got)
		}
	}
	a.Type = "storage.googleapis.com/Bucket"
	if len(filestoreRootTrust(a, time.Now())) != 0 || len(filestoreExportSources(a, time.Now())) != 0 {
		t.Fatal("wrong product")
	}
}

func TestFilestoreFullyShadowedRuleIsConfigurationOnly(t *testing.T) {
	a := filestoreFixture([]any{inventory.Object{"accessMode": "READ_WRITE", "squashMode": "NO_ROOT_SQUASH", "ipRanges": []any{"0.0.0.0/0"}}, inventory.Object{"accessMode": "READ_ONLY", "squashMode": "ROOT_SQUASH", "ipRanges": []any{"0.0.0.0/1", "128.0.0.0/1"}}})
	a.Resource.Data["tier"] = "REGIONAL"
	root := filestoreRootTrust(a, time.Now())
	sources := filestoreExportSources(a, time.Now())
	if len(root) != 1 || len(sources) != 1 || root[0].Title != "Filestore export option configures READ_WRITE with NO_ROOT_SQUASH" {
		t.Fatal(root, sources)
	}
	if !strings.Contains(s(root[0].Evidence["assessment"]), "Configured export option only") || !strings.Contains(s(sources[0].Evidence["assessment"]), "not internet-public access or effective permissions") || sources[0].Evidence["squash_mode"] != "NO_ROOT_SQUASH" {
		t.Fatal(root, sources)
	}
	for _, squash := range []any{nil, "", false, "SQUASH_MODE_UNSPECIFIED", "SENTINEL"} {
		got := filestoreExportSources(filestoreFixture([]any{inventory.Object{"accessMode": "READ_ONLY", "squashMode": squash, "ipRanges": []any{"0.0.0.0/0"}}}), time.Now())
		if len(got) != 1 {
			t.Fatal(got)
		}
		if _, exists := got[0].Evidence["squash_mode"]; exists {
			t.Fatal(got)
		}
	}
}
