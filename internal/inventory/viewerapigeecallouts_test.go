package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func calloutRef(name string) ApigeeFlowReference {
	return ApigeeFlowReference{SharedFlow: name, Enabled: true, EndpointDigest: strings.Repeat("a", 64), PolicyDigest: strings.Repeat("b", 64), EndpointKind: "ProxyEndpoint"}
}
func calloutBundle(t *testing.T, target string) []byte {
	return apigeeTestBundle(t, [][2]string{{"sharedflowbundle/policies/call.xml", `<FlowCallout name="private-policy-name"><SharedFlowBundle>` + target + `</SharedFlowBundle></FlowCallout>`}, {"sharedflowbundle/sharedflows/default.xml", `<SharedFlow name="default"><Step><Name>private-policy-name</Name></Step></SharedFlow>`}})
}
func TestViewerApigeeCalloutNestedCyclesAndEnvironmentScope(t *testing.T) {
	a, b := calloutBundle(t, "second"), calloutBundle(t, "first")
	calls := []string{}
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.Path)
		p := r.URL.Path
		if strings.HasSuffix(p, "/deployments") {
			name := strings.Split(p, "/")[5]
			return response(200, `{"deployments":[{"apiProxy":"`+name+`","environment":"other","revision":"99"},{"apiProxy":"`+name+`","environment":"prod","revision":"1","state":"READY"}]}`), nil
		}
		var body []byte
		switch p {
		case "/v1/organizations/demo/sharedflows/first/revisions/1":
			body = a
		case "/v1/organizations/demo/sharedflows/second/revisions/1":
			body = b
		default:
			t.Fatal("unexpected revision/env", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})
	var out Snapshot
	r := newApigeeCalloutResolver(c, &out, "organizations/demo")
	graph := r.resolve(context.Background(), "prod", []ApigeeFlowReference{calloutRef("first")}, 0, map[string]bool{})
	if graph["complete"] != false || len(calls) != 4 || r.downloads != 2 {
		t.Fatal(graph, calls)
	}
	raw, _ := json.Marshal(graph)
	if !bytes.Contains(raw, []byte(`"status":"cycle"`)) || bytes.Contains(raw, []byte("private-policy-name")) || bytes.Contains(raw, []byte("/revisions/99")) {
		t.Fatal(string(raw))
	}
}

func TestViewerApigeeCalloutFlagsMissingAndAmbiguous(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasSuffix(r.URL.Path, "/deployments") {
			t.Fatal("ambiguous bundle fetched", r.URL)
		}
		if strings.Contains(r.URL.Path, "/missing/") {
			return response(200, `{"deployments":[{"environment":"other","revision":"1"}]}`), nil
		}
		return response(200, `{"deployments":[{"environment":"prod","revision":"1"},{"environment":"prod","revision":"2"}]}`), nil
	})
	var out Snapshot
	r := newApigeeCalloutResolver(c, &out, "organizations/demo")
	disabled := calloutRef("disabled")
	disabled.Enabled = false
	conditional := calloutRef("ambiguous")
	conditional.Conditional = true
	conditional.ContinueOnError = true
	graph := r.resolve(context.Background(), "prod", []ApigeeFlowReference{disabled, calloutRef("missing"), conditional}, 0, map[string]bool{})
	edges := graph["edges"].([]any)
	if calls != 2 || r.downloads != 0 || Obj(edges[0])["status"] != "disabled" || Obj(edges[1])["status"] != "missing" || Obj(edges[2])["status"] != "ambiguous" || Obj(edges[2])["conditional"] != true || Obj(edges[2])["continue_on_error"] != true {
		t.Fatal(graph)
	}
}

func TestViewerApigeeCalloutBudgetsAndInvalidReferences(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("bounded or invalid reference reached transport", r.URL)
		return nil, nil
	})
	var out Snapshot
	for _, budget := range []string{"depth", "nodes"} {
		r := newApigeeCalloutResolver(c, &out, "organizations/demo")
		depth := 0
		if budget == "depth" {
			depth = viewerApigeeCalloutDepth
		} else {
			r.nodes = viewerApigeeCalloutNodes
		}
		graph := r.resolve(context.Background(), "prod", []ApigeeFlowReference{calloutRef("first")}, depth, map[string]bool{})
		if graph["complete"] != false || Obj(graph["edges"].([]any)[0])["status"] != "limit" {
			t.Fatal(graph)
		}
	}
	r := newApigeeCalloutResolver(c, &out, "organizations/demo")
	r.downloads = viewerApigeeCalloutDownloads
	r.lists["organizations/demo/sharedflows/first"] = apigeeCalloutList{rows: []any{Object{"environment": "prod", "revision": "1"}}}
	limited := r.resolve(context.Background(), "prod", []ApigeeFlowReference{calloutRef("first")}, 0, map[string]bool{})
	if limited["complete"] != false || Obj(limited["edges"].([]any)[0])["status"] != "limit" {
		t.Fatal(limited)
	}
	graph := r.resolve(context.Background(), "prod", []ApigeeFlowReference{calloutRef("../foreign")}, 0, map[string]bool{})
	if graph["complete"] != false {
		t.Fatal(graph)
	}
	denied := testClient(t, func(r *http.Request) (*http.Response, error) { return response(403, `SENTINEL`), nil })
	r = newApigeeCalloutResolver(denied, &out, "organizations/demo")
	graph = r.resolve(context.Background(), "prod", []ApigeeFlowReference{calloutRef("first")}, 0, map[string]bool{})
	if graph["complete"] != false || Obj(graph["edges"].([]any)[0])["status"] != "error" {
		t.Fatal(graph)
	}
}
