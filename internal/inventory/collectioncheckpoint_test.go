package inventory

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

type memoryCollectionCheckpoint struct {
	mu           sync.Mutex
	rows         map[string][]byte
	loads, saves int
}

func (s *memoryCollectionCheckpoint) Load(_ context.Context, scope, family string) (Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	b, found := s.rows[scope+"|"+family]
	var out Snapshot
	if found {
		if err := json.Unmarshal(b, &out); err != nil {
			return Snapshot{}, false, err
		}
	}
	return out, found, nil
}

func (s *memoryCollectionCheckpoint) Save(_ context.Context, scope, family string, out Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	s.rows[scope+"|"+family] = b
	s.saves++
	return nil
}

func TestCollectionCheckpointReusesOnlySuccessfulMetadata(t *testing.T) {
	store := &memoryCollectionCheckpoint{rows: map[string][]byte{}}
	c := &Client{Concurrency: 3, CollectionCheckpoint: store, SecretCapture: NewSecretCapture(0, 0, 0)}
	var runs [3]int
	collect := func(fail bool) []Snapshot {
		out := make([]Snapshot, 3)
		tasks := make([]viewerTask, 3)
		for i, family := range []string{"redis", "memcache", "parameters"} {
			i, family := i, family
			tasks[i] = viewerTask{scope: "projects/123", family: family, out: &out[i], run: func() {
				runs[i]++
				status := "ok"
				if i == 1 && fail {
					status = "failed"
				}
				out[i] = Snapshot{Assets: []Asset{NewAsset("//test/"+family, "test.googleapis.com/Metadata", Object{"enabled": true})}, Coverage: []Coverage{{Source: family, Status: status}}}
			}}
		}
		c.runViewerTasks(context.Background(), tasks)
		return out
	}
	first := collect(true)
	second := collect(false)
	third := collect(false)
	if runs != [3]int{1, 2, 3} {
		t.Fatalf("unexpected re-collection counts: %v", runs)
	}
	if len(first[0].Assets) != 1 || len(second[0].Assets) != 1 || len(third[1].Assets) != 1 {
		t.Fatal("restored metadata lost")
	}
	if len(store.rows) != 2 || store.saves != 2 {
		t.Fatalf("unsafe/failed tasks cached: %#v", store)
	}
}

func TestCollectionCheckpointRejectsFailuresAndTransientSecrets(t *testing.T) {
	for _, s := range []Snapshot{
		{},
		{Coverage: []Coverage{{Status: "failed"}}},
		{Coverage: []Coverage{{Status: "incomplete"}}},
		{Coverage: []Coverage{{Status: "ok"}}, SecretArtifacts: map[string][]byte{"x": []byte("secret")}},
		{Coverage: []Coverage{{Status: "ok"}}, SecretFingerprint: []byte("secret")},
		{Coverage: []Coverage{{Status: "ok"}}, SecretValueMode: "actual"},
	} {
		if checkpointComplete(s) {
			t.Fatal("unsafe checkpoint accepted")
		}
	}
	for _, family := range []string{"compute-network", "sql-gke", "apigee", "parameters", "api-keys", "secrets-kms", "serverless-build-workflows", "dns", "unknown-future-family"} {
		if checkpointFamily(family) {
			t.Fatalf("secret-bearing/unknown family cached: %s", family)
		}
	}
}
