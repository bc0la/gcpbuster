package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func storageOptions() StorageOptions {
	return StorageOptions{Anonymous: true, ScanContent: true, MaxObjects: 10, MaxObjectBytes: 4096, MaxArchiveBytes: 8192, MaxArchiveEntries: 10}
}
func storageSnapshot() Snapshot {
	return Snapshot{Assets: []Asset{NewAsset("//storage.googleapis.com/test-bucket", "storage.googleapis.com/Bucket", Object{"name": "test-bucket"})}}
}
func hasCoverage(s Snapshot, status string) bool {
	for _, c := range s.Coverage {
		if c.Status == status {
			return true
		}
	}
	return false
}

func TestStorageAuthIsolationGenerationAndRedaction(t *testing.T) {
	anonLists, anonReads, contentReads := 0, 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "storage.googleapis.com" || r.Method != "GET" {
			t.Fatal("unexpected target", r.URL)
		}
		if r.Header.Get("Cookie") != "" {
			t.Fatal("cookie leaked")
		}
		if r.URL.Query().Get("alt") == "media" {
			if r.URL.Query().Get("generation") != "42" || !strings.Contains(r.URL.EscapedPath(), "dir%2Fconfig.env") {
				t.Fatal("name/generation not pinned", r.URL)
			}
			if r.Header.Get("Authorization") == "" {
				anonReads++
				if r.Header.Get("Range") != "bytes=0-0" {
					t.Fatal("unbounded anonymous read")
				}
				return response(206, "p"), nil
			}
			contentReads++
			return response(200, "password=NEVER_PERSIST_SECRET"), nil
		}
		if r.Header.Get("Authorization") == "" {
			anonLists++
			return response(200, `{"kind":"storage#objects","items":[{"name":"dir/config.env"}]}`), nil
		}
		return response(200, `{"kind":"storage#objects","items":[{"name":"dir/config.env","generation":"42","size":"29","contentType":"text/plain"}]}`), nil
	})
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://storage.googleapis.com")
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "do-not-send"}})
	c.HTTP.Jar = jar
	s := storageSnapshot()
	c.CollectStorage(context.Background(), &s, storageOptions())
	if anonLists != 1 || anonReads != 1 || contentReads != 1 {
		t.Fatal(anonLists, anonReads, contentReads)
	}
	if hasCoverage(s, "failed") || hasCoverage(s, "incomplete") {
		t.Fatal(s.Coverage)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "NEVER_PERSIST_SECRET") || strings.Contains(string(data), "do-not-send") {
		t.Fatal("secret leaked into snapshot")
	}
	scans := 0
	for _, a := range s.Assets {
		if a.Type == ContentScanType {
			scans++
			if len(List(a.Resource.Data["matches"])) != 1 {
				t.Fatal(a)
			}
		}
	}
	if scans != 1 {
		t.Fatal("missing scan")
	}
}

func TestAnonymousProbeDoesNotAcquireTokenOrFollowRedirect(t *testing.T) {
	calls := 0
	c := &Client{TokenEnv: "NONEXISTENT_TOKEN_FOR_TEST", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "" {
			t.Fatal("auth sent")
		}
		resp := response(302, "")
		resp.Header.Set("Location", "https://attacker.invalid/")
		return resp, nil
	})}}
	r, err := c.storageGET(context.Background(), "https://storage.googleapis.com/storage/v1/b/test-bucket/o", false, 10, "")
	if err != nil || r.Status != 302 || calls != 1 {
		t.Fatal(r, err, calls)
	}
	if _, err := c.storageGET(context.Background(), "https://attacker.invalid/", false, 10, ""); err == nil {
		t.Fatal("arbitrary host allowed")
	}
}

func TestStoragePaginationAndSampleCap(t *testing.T) {
	for _, limit := range []int{1, 3} {
		t.Run(string(rune('0'+limit)), func(t *testing.T) {
			lists := 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("alt") == "media" {
					return response(200, "safe text"), nil
				}
				lists++
				if lists == 1 {
					return response(200, `{"kind":"storage#objects","items":[{"name":"one.txt","generation":"1"}],"nextPageToken":"page2"}`), nil
				}
				if r.URL.Query().Get("pageToken") != "page2" {
					t.Fatal("page token lost")
				}
				return response(200, `{"kind":"storage#objects","items":[{"name":"two.txt","generation":"2"}]}`), nil
			})
			opts := storageOptions()
			opts.Anonymous = false
			opts.MaxObjects = limit
			s := storageSnapshot()
			c.CollectStorage(context.Background(), &s, opts)
			if limit == 1 && (!hasCoverage(s, "incomplete") || lists != 1) {
				t.Fatal("cap not surfaced", s)
			}
			if limit == 3 && (hasCoverage(s, "incomplete") || lists != 2) {
				t.Fatal("pagination incomplete", s)
			}
		})
	}
}

func TestStoragePartialResponsesCannotLookClean(t *testing.T) {
	for _, kind := range []string{"denied", "malformed", "oversized", "transport"} {
		t.Run(kind, func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("alt") != "media" {
					return response(200, `{"kind":"storage#objects","items":[{"name":"one.txt","generation":"1"}]}`), nil
				}
				switch kind {
				case "denied":
					return response(403, `PRIVATE_ERROR_BODY`), nil
				case "transport":
					return nil, errors.New("PRIVATE_TRANSPORT_ERROR")
				case "oversized":
					return response(200, strings.Repeat("a", 50)), nil
				default:
					return response(302, ""), nil
				}
			})
			opts := storageOptions()
			opts.Anonymous = false
			opts.MaxObjectBytes = 16
			s := storageSnapshot()
			c.CollectStorage(context.Background(), &s, opts)
			if !hasCoverage(s, "failed") && !hasCoverage(s, "incomplete") {
				t.Fatal("missing coverage failure", s)
			}
			data, _ := json.Marshal(s)
			if strings.Contains(string(data), "PRIVATE_") {
				t.Fatal("error body leaked")
			}
		})
	}
}
