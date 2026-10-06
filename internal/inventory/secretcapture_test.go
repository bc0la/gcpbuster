package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestSecretCaptureAppEngineIdentityAndLegacyRedaction(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		c := appEngineClient(t, func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/v1/apps/demo":
				return response(200, `{"name":"apps/demo"}`), nil
			case "/v1/apps/demo/services":
				return response(200, `{"services":[{"name":"apps/demo/services/default"}]}`), nil
			case "/v1/apps/demo/services/default/versions":
				return response(200, `{"versions":[{"name":"apps/demo/services/default/versions/v1"}]}`), nil
			case "/v1/apps/demo/services/default/versions/v1":
				name := "apps/demo/services/default/versions/v1"
				if foreign {
					name = "apps/foreign/services/default/versions/v1"
				}
				return response(200, `{"name":"`+name+`","envVariables":{"PASSWORD":"exact-test-value"},"deployment":{"secret":"unrequested-value"}}`), nil
			default:
				t.Fatal(r.URL)
				return nil, nil
			}
		})
		c.SecretCapture = NewSecretCapture(0, 0, 0)
		var snap Snapshot
		c.CollectViewerAppEngine(context.Background(), &snap, "demo", "projects/123")
		want := 1
		if foreign {
			want = 0
		}
		if len(c.SecretCapture.Samples()) != want {
			t.Fatalf("foreign=%v captured=%d", foreign, len(c.SecretCapture.Samples()))
		}
		if !foreign && string(c.SecretCapture.Samples()[0].Data) != "PASSWORD=exact-test-value" {
			t.Fatal("value lost")
		}
		data, _ := json.Marshal(snap)
		for _, v := range []string{"exact-test-value", "unrequested-value"} {
			if strings.Contains(string(data), v) {
				t.Fatal("legacy snapshot leaked", v)
			}
		}
	}
}

func TestSecretCaptureBoundedCopiesConcurrent(t *testing.T) {
	c := NewSecretCapture(2, 20, 30)
	s := SecretSample{SourceType: "env", Resource: "//example.googleapis.com/projects/demo/x/a", Path: "env.PASSWORD", Data: []byte("test-secret")}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Add(s) }()
	}
	wg.Wait()
	s.Data[0] = 'X'
	got := c.Samples()
	if len(got) != 1 || string(got[0].Data) != "test-secret" {
		t.Fatal("not copied/deduped")
	}
	got[0].Data[0] = 'Y'
	if string(c.Samples()[0].Data) != "test-secret" {
		t.Fatal("Samples aliases capture")
	}
	s.Data = make([]byte, 21)
	if c.Add(s) {
		t.Fatal("accepted oversize")
	}
	if c.Coverage()[0].Status != "incomplete" {
		t.Fatal("missing limit evidence")
	}
}

func TestSecretCaptureIDsMetadataOnlyAndConflictsSticky(t *testing.T) {
	a, b := NewSecretCapture(0, 0, 0), NewSecretCapture(0, 0, 0)
	s := SecretSample{SourceType: "env", Resource: "//example.googleapis.com/projects/demo/x/a", Path: "env.PASSWORD", Data: []byte("first-value")}
	a.Add(s)
	s.Data = []byte("second-value")
	b.Add(s)
	if a.Samples()[0].ID != b.Samples()[0].ID {
		t.Fatal("secret-derived ID")
	}
	if a.Add(s) || len(a.Samples()) != 0 {
		t.Fatal("conflicting locator retained")
	}
	s.Data = []byte("first-value")
	if a.Add(s) || len(a.Samples()) != 0 {
		t.Fatal("conflict not sticky")
	}
	if a.Coverage()[0].Status != "incomplete" {
		t.Fatal("conflict coverage missing")
	}
}

func TestSecretCaptureSelectedLeavesOnly(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	raw := Object{"openapiDocuments": []any{Object{"document": Object{"contents": base64.StdEncoding.EncodeToString([]byte("password: exact-test-value")), "unknown": "DO_NOT_CAPTURE"}}}, "unrequested": "DO_NOT_CAPTURE"}
	c.captureOpenAPI("//apigateway.googleapis.com/projects/demo/locations/global/apis/api/configs/config", raw)
	c.captureServiceConfig("//servicemanagement.googleapis.com/services/api/configs/1", Object{"backend": Object{"rules": []any{Object{"address": "https://user:exact-test-value@example.test", "unknown": "DO_NOT_CAPTURE"}}}, "sourceInfo": "DO_NOT_CAPTURE"})
	if len(c.Samples()) != 2 {
		t.Fatal("unexpected samples")
	}
	for _, s := range c.Samples() {
		if strings.Contains(string(s.Data), "DO_NOT_CAPTURE") {
			t.Fatal("unrequested field captured")
		}
	}
	data, _ := json.Marshal(Snapshot{})
	if strings.Contains(string(data), "exact-test-value") {
		t.Fatal("capture serialized")
	}
	var nilCapture *SecretCapture
	nilCapture.CaptureStringMap("x", "//x", "", "x", Object{"PASSWORD": "exact-test-value"})
	if nilCapture.Samples() != nil {
		t.Fatal("nil capture active")
	}
}
