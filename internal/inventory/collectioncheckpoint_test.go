package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
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
	cached := 0
	c.Progress = func(e ProgressEvent) {
		if e.Phase == "collector" && e.Status == "completed" && e.Cached {
			cached++
		}
	}
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
	if cached != 3 {
		t.Fatalf("cached completions not tagged: %d", cached)
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

func TestCollectionCheckpointRealCompletedCollectorResume(t *testing.T) {
	store := &memoryCollectionCheckpoint{rows: map[string][]byte{}}
	var buckets atomic.Int32
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host + r.URL.Path {
		case "cloudresourcemanager.googleapis.com/v3/projects/demo":
			return response(200, `{"name":"projects/123","projectId":"demo","parent":"organizations/9"}`), nil
		case "cloudresourcemanager.googleapis.com/v3/projects/123:getIamPolicy":
			return response(200, `{"bindings":[]}`), nil
		case "storage.googleapis.com/storage/v1/b":
			buckets.Add(1)
			return response(200, `{"items":[]}`), nil
		default:
			return response(404, `{}`), nil
		}
	})
	c.CollectionCheckpoint = store
	c.SecretCapture = NewSecretCapture(0, 0, 0)
	for i := 0; i < 2; i++ {
		c.ViewerCloud(context.Background(), "projects/demo")
	}
	if buckets.Load() != 1 {
		t.Fatalf("successful real collector was not resumed: %d reads", buckets.Load())
	}
	if _, found := store.rows["projects/123 (demo)|storage"]; !found {
		t.Fatal("real completed status was not saved")
	}
}
