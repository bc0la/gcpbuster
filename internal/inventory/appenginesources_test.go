package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAppEngineSourceURLBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{"https://storage.googleapis.com/test-bucket/source/config.env", true},
		{"http://storage.googleapis.com/test-bucket/source%2Fconfig.env", true},
		{"https://storage.googleapis.com.evil.example/test-bucket/obj", false},
		{"https://user@storage.googleapis.com/test-bucket/obj", false},
		{"https://storage.googleapis.com:443/test-bucket/obj", false},
		{"https://storage.googleapis.com/test-bucket/obj?signature=PRIVATE", false},
		{"https://storage.googleapis.com/test-bucket/obj#42", false},
		{"https://storage.googleapis.com/test-bucket/", false},
		{"file:///etc/passwd", false},
	} {
		ref, ok := appEngineSourceURL(tc.raw)
		if ok != tc.ok {
			t.Fatal(tc, ref)
		}
		if ok && (ref.bucket != "test-bucket" || ref.name != "source/config.env") {
			t.Fatal(ref)
		}
	}
}

func TestAppEngineManifestBoundedDeduplicatedAndPartial(t *testing.T) {
	a := NewAsset("version", "appengine.googleapis.com/Version", Object{"deployment": Object{
		"files": Object{"a": Object{"sourceUrl": "https://storage.googleapis.com/test-bucket/a"}, "b": Object{"sourceUrl": "https://storage.googleapis.com/test-bucket/a"}, "c": Object{"sourceUrl": "http://storage.googleapis.com/test-bucket/c"}, "d": Object{"sourceUrl": "https://evil.example/d"}},
	}})
	refs, partial := appEngineSourceReferences(a, 1)
	if !partial || len(refs) != 1 || refs[0].name != "a" {
		t.Fatal(refs, partial)
	}
	refs, partial = appEngineSourceReferences(a, 10)
	if !partial || len(refs) != 2 {
		t.Fatal(refs, partial)
	}
}

func TestAppEngineFullSourcesAndDistinctGenerationPinnedFindings(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Scheme != "https" || r.Header.Get("Authorization") == "" {
			t.Fatal(r.URL)
		}
		if r.URL.Host == "appengine.googleapis.com" {
			if r.URL.Query().Get("view") != "FULL" {
				t.Fatal("not full metadata")
			}
			return response(200, `{"id":"v1","name":"apps/my-project/services/default/versions/v1","deployment":{"files":{"a":{"sourceUrl":"http://storage.googleapis.com/test-bucket/a"},"b":{"sourceUrl":"https://storage.googleapis.com/test-bucket/b"}}}}`), nil
		}
		if r.URL.Host != "storage.googleapis.com" {
			t.Fatal(r.URL)
		}
		name := strings.TrimPrefix(r.URL.Path, "/storage/v1/b/test-bucket/o/")
		if name != "a" && name != "b" {
			t.Fatal(r.URL)
		}
		if r.URL.Query().Get("alt") == "media" {
			if r.URL.Query().Get("generation") != "42" {
				t.Fatal("unpinned read")
			}
			return response(200, "password=PRIVATE_SOURCE_VALUE"), nil
		}
		b, _ := json.Marshal(Object{"name": name, "generation": "42", "size": "29"})
		return response(200, string(b)), nil
	})
	s := Snapshot{Assets: []Asset{NewAsset("//appengine.googleapis.com/apps/my-project/services/default/versions/v1", "appengine.googleapis.com/Version", nil)}}
	c.RefreshAppEngineSources(context.Background(), &s)
	c.CollectSources(context.Background(), &s, storageOptions())
	if calls != 5 || len(s.Assets) != 3 || hasCoverage(s, "failed") || hasCoverage(s, "incomplete") {
		t.Fatal(calls, s)
	}
	if s.Assets[1].Name == s.Assets[2].Name {
		t.Fatal("source scan identity collision")
	}
	for _, a := range s.Assets[1:] {
		if Str(a.Resource.Data["originResource"]) != s.Assets[0].Name {
			t.Fatal("origin lost")
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE_SOURCE_VALUE") {
		t.Fatal("payload retained")
	}
}

func TestAppEngineFullReadFailurePreservesPriorMetadata(t *testing.T) {
	for _, body := range []string{`null`, `{"id":"other","name":"apps/my-project/services/default/versions/other"}`, "DENIED"} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			if body == "DENIED" {
				return response(403, "PRIVATE_ERROR"), nil
			}
			return response(200, body), nil
		})
		s := Snapshot{Assets: []Asset{NewAsset("//appengine.googleapis.com/apps/my-project/services/default/versions/v1", "appengine.googleapis.com/Version", Object{"runtime": "go125"})}}
		c.RefreshAppEngineSources(context.Background(), &s)
		if !hasCoverage(s, "failed") || Str(s.Assets[0].Resource.Data["runtime"]) != "go125" {
			t.Fatal(s)
		}
	}
}
