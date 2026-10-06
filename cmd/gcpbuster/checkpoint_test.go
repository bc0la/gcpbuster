package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
)

func checkpointEngagement(t *testing.T) *engagement.Engagement {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	e, err := engagement.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestCollectionCheckpointSystemProjectPolicyBinding(t *testing.T) {
	ctx := context.Background()
	e := checkpointEngagement(t)
	scopes := []string{"organizations/123"}
	if _, err := newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, true, true); err == nil {
		t.Fatal("changed project selection must not reuse checkpoints")
	}
	cmd := scanCommand()
	include, err := cmd.Flags().GetBool("include-system-projects")
	if err != nil || include {
		t.Fatal("system projects must be excluded by default", include, err)
	}
}

func TestCollectionCheckpointPrivateRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := checkpointEngagement(t)
	scopes := []string{"projects/123"}
	c, err := newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	snap := inventory.Snapshot{Assets: []inventory.Asset{inventory.NewAsset("//compute.googleapis.com/projects/123/zones/z/instances/i", "compute.googleapis.com/Instance", inventory.Object{"name": "i"})}, Coverage: []inventory.Coverage{{Source: "compute:projects/123", Status: "complete", Count: 1}}}
	if err := c.Save(ctx, scopes[0], "compute", snap); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := c.Load(ctx, scopes[0], "compute"); err != nil || exists {
		t.Fatal("nonresume must not load", exists, err)
	}
	c, err = newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	got, exists, err := c.Load(ctx, scopes[0], "compute")
	if err != nil || !exists || !reflect.DeepEqual(got, snap) {
		t.Fatal(got, exists, err)
	}
	if _, exists, err := c.Load(ctx, scopes[0], "dns"); err != nil || exists {
		t.Fatal("missing checkpoint", exists, err)
	}
	info, err := os.Stat(filepath.Join(e.Dir, engagement.DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	info, err = os.Stat(e.Dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal(info, err)
	}
}

func TestCollectionCheckpointSortedScopeBinding(t *testing.T) {
	ctx := context.Background()
	e := checkpointEngagement(t)
	original := []string{"projects/456", "organizations/123"}
	before := append([]string(nil), original...)
	if _, err := newCollectionCheckpoint(ctx, e, original, false, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, before) {
		t.Fatal("caller scope ordering mutated")
	}
	if _, err := newCollectionCheckpoint(ctx, e, []string{"organizations/123", "projects/456"}, false, false, false, false, true); err != nil {
		t.Fatal(err)
	}
}

func TestCollectionCheckpointBindingRejectsUnsafeReuse(t *testing.T) {
	ctx := context.Background()
	e := checkpointEngagement(t)
	scopes := []string{"organizations/123"}
	if _, err := newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name                                    string
		scopes                                  []string
		capture, redacted, dns, refresh, resume bool
	}{
		{"nonresume", scopes, false, false, false, false, false},
		{"scope", []string{"organizations/456"}, false, false, false, false, true},
		{"capture", scopes, true, false, false, false, true},
		{"redacted", scopes, false, true, false, false, true},
		{"dns", scopes, false, false, true, false, true},
		{"refresh", scopes, false, false, false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newCollectionCheckpoint(ctx, e, tt.scopes, tt.capture, tt.redacted, tt.dns, tt.refresh, tt.resume); err == nil {
				t.Fatal("mismatched engagement accepted")
			}
		})
	}
	if _, err := newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, true); err != nil {
		t.Fatal("failed mismatches must not replace binding", err)
	}
}

func TestCollectionCheckpointOldVersionAndCorruptRow(t *testing.T) {
	ctx := context.Background()
	e := checkpointEngagement(t)
	if err := e.SetMeta(ctx, "version", "old-version"); err != nil {
		t.Fatal(err)
	}
	if _, err := newCollectionCheckpoint(ctx, e, []string{"projects/123"}, false, false, false, false, true); err == nil {
		t.Fatal("missing collection binding accepted")
	}
	c, err := newCollectionCheckpoint(ctx, e, []string{"projects/123"}, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetMeta(ctx, checkpointKey("projects/123", "compute"), "not JSON secret sentinel"); err != nil {
		t.Fatal(err)
	}
	c.resume = true
	if _, _, err := c.Load(ctx, "projects/123", "compute"); err == nil || strings.Contains(err.Error(), "sentinel") {
		t.Fatal("corrupt checkpoint must return sanitized error", err)
	}
}

func TestCollectionCheckpointKeysAreOpaqueAndUnambiguous(t *testing.T) {
	scope := "organizations/sensitive-org-name"
	family := "sensitive-family"
	key := checkpointKey(scope, family)
	if strings.Contains(key, scope) || strings.Contains(key, family) || len(key) != len("collection_checkpoint:")+64 {
		t.Fatal(key)
	}
	if key != checkpointKey(scope, family) || checkpointKey("ab", "c") == checkpointKey("a", "bc") {
		t.Fatal("unstable or ambiguous key")
	}
}

// An interrupted live collection has checkpoints but no assessment fingerprint.
// Its first assessment must run fresh, rather than requiring a prior report.
func TestCollectionCheckpointResumeBeforeFirstAssessment(t *testing.T) {
	ctx := context.Background()
	e := checkpointEngagement(t)
	scopes := []string{"projects/123"}
	c, err := newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	snap := inventory.Snapshot{Coverage: []inventory.Coverage{{Source: "storage:projects/123", Status: "ok"}}}
	if err := c.Save(ctx, scopes[0], "storage", snap); err != nil {
		t.Fatal(err)
	}
	c, err = newCollectionCheckpoint(ctx, e, scopes, false, false, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := c.Load(ctx, scopes[0], "storage")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	_, prior, err := e.GetMeta(ctx, "inventory_fingerprint")
	if err != nil || prior {
		t.Fatal("unexpected prior assessment", prior, err)
	}
	selected, err := checks.Select([]string{"public_storage_capabilities"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := rootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	// Mirror live CLI's resume && priorAssessment decision.
	if err := assess(ctx, cmd, e, loaded, selected, prior); err != nil {
		t.Fatal(err)
	}
	if _, prior, err = e.GetMeta(ctx, "inventory_fingerprint"); err != nil || !prior {
		t.Fatal("first report fingerprint missing", prior, err)
	}
}
