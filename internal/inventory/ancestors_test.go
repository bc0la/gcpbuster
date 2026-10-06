package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAncestorIAMParentChainAndPolicyVersion(t *testing.T) {
	gets, posts := 0, 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "cloudresourcemanager.googleapis.com" {
			t.Fatal(r.URL)
		}
		if r.Method == "POST" {
			posts++
			var body Object
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if Get(body, "options", "requestedPolicyVersion") != float64(3) || !strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
				t.Fatal(body, r.URL)
			}
			return response(200, `{"version":3,"bindings":[{"role":"roles/viewer","members":["user:reader@example.com"],"condition":{"expression":"request.time < timestamp('2026-01-01T00:00:00Z')"}}]}`), nil
		}
		gets++
		switch r.URL.Path {
		case "/v3/projects/test":
			return response(200, `{"name":"projects/123","projectId":"test","parent":"folders/2"}`), nil
		case "/v3/folders/2":
			return response(200, `{"name":"folders/2","parent":"organizations/1"}`), nil
		case "/v3/organizations/1":
			return response(200, `{"name":"organizations/1"}`), nil
		default:
			t.Fatal("unexpected resource traversal", r.URL)
			return nil, nil
		}
	})
	s := Snapshot{}
	c.CollectAncestorIAM(context.Background(), &s, []string{"projects/test", "folders/2"})
	if gets != 3 || posts != 3 || len(s.Assets) != 3 || hasCoverage(s, "failed") {
		t.Fatal(gets, posts, s)
	}
	for _, a := range s.Assets {
		if Get(Obj(List(a.IAM["bindings"])[0]), "condition", "expression") == nil {
			t.Fatal("condition lost")
		}
	}
}

func TestAncestorFailureContinuesParentCollection(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			if strings.Contains(r.URL.Path, "projects/") {
				return response(403, "PRIVATE_ERROR"), nil
			}
			return response(200, `{}`), nil
		}
		if strings.Contains(r.URL.Path, "projects/") {
			return response(200, `{"name":"projects/1","parent":"organizations/2"}`), nil
		}
		return response(200, `{"name":"organizations/2"}`), nil
	})
	s := Snapshot{}
	c.CollectAncestorIAM(context.Background(), &s, []string{"projects/1"})
	if len(s.Assets) != 1 || !hasCoverage(s, "failed") {
		t.Fatal(s)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "PRIVATE_ERROR") {
		t.Fatal("upstream error persisted")
	}
}

func TestAncestorCycleAndOutOfScopeParent(t *testing.T) {
	for _, parent := range []string{"folders/1", "projects/2", "https://attacker.invalid/"} {
		calls := 0
		c := testClient(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method == "POST" {
				return response(200, `{}`), nil
			}
			b, _ := json.Marshal(Object{"name": "folders/1", "parent": parent})
			return response(200, string(b)), nil
		})
		s := Snapshot{}
		c.CollectAncestorIAM(context.Background(), &s, []string{"folders/1"})
		if !hasCoverage(s, "failed") || calls > 2 {
			t.Fatal(parent, calls, s)
		}
	}
}

func TestContainerPolicyRejectsMalformedOrRedirectedResponse(t *testing.T) {
	for _, body := range []string{`null`, `{"bindings":{}}`, `{"bindings":[{}]}`, `{"bindings":[{"role":"roles/viewer","members":["user:a"],"condition":{"expression":"true"}}]}`, `REDIRECT`} {
		calls := 0
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			calls++
			if body == "REDIRECT" {
				r := response(302, "")
				r.Header.Set("Location", "https://attacker.invalid/")
				return r, nil
			}
			return response(200, body), nil
		})
		if _, err := c.getContainerPolicy(context.Background(), "projects/1"); err == nil || calls != 1 {
			t.Fatal(body, err, calls)
		}
	}
}
