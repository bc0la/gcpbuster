package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApigeeBasePathExactLocationAndRedaction(t *testing.T) {
	for _, path := range []string{"/", "/v1/weather", "/v1/SENSITIVE_PATH_TOKEN"} {
		got, e := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/proxies/default.xml", `<ProxyEndpoint><HTTPProxyConnection><BasePath>` + path + `</BasePath></HTTPProxyConnection></ProxyEndpoint>`}}))
		if e != nil {
			t.Fatal(e)
		}
		row := Obj(List(got["request_authentication"])[0])
		route := Obj(row["configured_base_path"])
		if route["status"] != "explicit_literal_path" || route["root_path"] != (path == "/") {
			t.Fatal(got)
		}
		if path != "/v1/SENSITIVE_PATH_TOKEN" && route["base_path"] != path {
			t.Fatal("safe path missing", got)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), "SENSITIVE_PATH_TOKEN") {
			t.Fatal(string(raw))
		}
	}
}

func TestApigeeBasePathUnknownMalformedAndBounds(t *testing.T) {
	for _, content := range []string{`<BasePath>/outside</BasePath>`, `<HTTPProxyConnection/>`, `<HTTPProxyConnection><BasePath>/one</BasePath><BasePath>/two</BasePath></HTTPProxyConnection>`, `<HTTPProxyConnection><BasePath>/one</BasePath></HTTPProxyConnection><HTTPProxyConnection><BasePath>/two</BasePath></HTTPProxyConnection>`, `<HTTPProxyConnection><BasePath ref="secret">/one</BasePath></HTTPProxyConnection>`, `<HTTPProxyConnection><BasePath><Value>/one</Value></BasePath></HTTPProxyConnection>`} {
		got, e := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/proxies/default.xml", "<ProxyEndpoint>" + content + "</ProxyEndpoint>"}}))
		if e != nil {
			t.Fatal(e)
		}
		if Get(Obj(List(got["request_authentication"])[0]), "configured_base_path", "status") != "unknown" {
			t.Fatal(content, got)
		}
	}
	for _, path := range []string{"https://example.invalid", "/../x", "/x//y", "/x?token=secret", "/x%2fy", "/x/*", "/x/", strings.Repeat("/x", 65), "/" + strings.Repeat("a", 2050)} {
		got, e := projectApigeeBundle(apigeeTestBundle(t, [][2]string{{"apiproxy/proxies/default.xml", "<ProxyEndpoint><HTTPProxyConnection><BasePath>" + path + "</BasePath></HTTPProxyConnection></ProxyEndpoint>"}}))
		if e != nil {
			t.Fatal(e)
		}
		if Get(Obj(List(got["request_authentication"])[0]), "configured_base_path", "status") != "unknown" {
			t.Fatal(path, got)
		}
	}
}
