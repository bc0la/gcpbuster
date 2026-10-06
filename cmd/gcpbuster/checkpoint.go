package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
)

// Checkpoints contain reviewed metadata only, in the engagement's private DB.
// Authentication material and transient secret samples are never serialized.
type collectionCheckpoint struct {
	e      *engagement.Engagement
	resume bool
}

func checkpointKey(scope, family string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + family))
	return "collection_checkpoint:" + hex.EncodeToString(sum[:])
}

func newCollectionCheckpoint(ctx context.Context, e *engagement.Engagement, scopes []string, capture, redacted, dns, refresh, resume bool, includeSystem ...bool) (*collectionCheckpoint, error) {
	ordered := append([]string(nil), scopes...)
	sort.Strings(ordered)
	config, _ := json.Marshal(struct {
		Version                         string
		Scopes                          []string
		Capture, Redacted, DNS, Refresh bool
		IncludeSystem                   bool
	}{"collection-v2:" + permissioncatalog.SHA256(), ordered, capture, redacted, dns, refresh, len(includeSystem) > 0 && includeSystem[0]})
	sum := sha256.Sum256(config)
	binding := hex.EncodeToString(sum[:])
	old, exists, err := e.GetMeta(ctx, "collection_binding")
	if err != nil {
		return nil, err
	}
	if exists && (!resume || old != binding) {
		return nil, errors.New("engagement contains collection checkpoints; use --resume with matching scopes/options, or a new --engagement directory")
	}
	if resume && !exists {
		return nil, errors.New("cannot resume collection: engagement has no collection checkpoints from this version; use a new engagement")
	}
	if err := e.SetMeta(ctx, "collection_binding", binding); err != nil {
		return nil, err
	}
	return &collectionCheckpoint{e: e, resume: resume}, nil
}

func (c *collectionCheckpoint) Load(ctx context.Context, scope, family string) (inventory.Snapshot, bool, error) {
	var snap inventory.Snapshot
	if !c.resume {
		return snap, false, nil
	}
	raw, exists, err := c.e.GetMeta(ctx, checkpointKey(scope, family))
	if err != nil || !exists {
		return snap, false, err
	}
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return snap, false, errors.New("invalid collection checkpoint")
	}
	return snap, true, nil
}

func (c *collectionCheckpoint) Save(ctx context.Context, scope, family string, snap inventory.Snapshot) error {
	raw, err := json.Marshal(snap)
	if err != nil {
		return errors.New("cannot encode collection checkpoint")
	}
	return c.e.SetMeta(ctx, checkpointKey(scope, family), string(raw))
}
