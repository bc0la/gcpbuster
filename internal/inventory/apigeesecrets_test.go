package inventory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestApigeeConfigurationCaptureFullValuesAndNoProjectionLeak(t *testing.T) {
	c := Client{SecretCapture: NewSecretCapture(10000, 4<<20, 64<<20)}
	xml := `<AssignMessage name="config"><Set><Password>very-weak-APIGEE_SECRET&amp;full</Password><Header name="API_TOKEN">another-APIGEE_SECRET</Header></Set></AssignMessage>`
	bundle := apigeeTestBundle(t, [][2]string{{"apiproxy/policies/config.xml", xml}, {"apiproxy/proxies/default.xml", `<ProxyEndpoint/>`}, {"apiproxy/resources/jsc/ignored.js", `password=EXCLUDED_CODE_SECRET`}})
	projection, _, err := c.projectApigeeBundleCapture(bundle, "organizations/demo/apis/api/revisions/3")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(projection)
	if bytes.Contains(b, []byte("APIGEE_SECRET")) || bytes.Contains(b, []byte("Password")) {
		t.Fatal(string(b))
	}
	samples := c.SecretCapture.Samples()
	raw, leaf := false, false
	for _, s := range samples {
		if bytes.Contains(s.Data, []byte("EXCLUDED_CODE_SECRET")) {
			t.Fatal("code captured")
		}
		if string(s.Data) == xml {
			raw = true
		}
		if string(s.Data) == "Password=very-weak-APIGEE_SECRET&full" {
			leaf = true
		}
		if endpoint, q := ApigeeSecretRefetchRequest(s); endpoint != "https://apigee.googleapis.com/v1/organizations/demo/apis/api/revisions/3" || q.Get("format") != "bundle" {
			t.Fatal(s, endpoint, q)
		}
	}
	if !raw || !leaf {
		t.Fatal(samples)
	}
}

func TestApigeeMalformedArchiveNeverPartiallyCaptured(t *testing.T) {
	for _, bad := range [][2]string{{"apiproxy/policies/bad.xml", `<Broken>`}, {"../bad.xml", `<X/>`}, {"apiproxy/policies/ok.xml", `<AssignMessage name="duplicate"/>`}, {"apiproxy/targets/bad.xml", `<!DOCTYPE X SYSTEM "https://evil.test"><TargetEndpoint/>`}} {
		c := Client{SecretCapture: NewSecretCapture(10000, 4<<20, 64<<20)}
		bundle := apigeeTestBundle(t, [][2]string{{"apiproxy/policies/ok.xml", `<AssignMessage name="good"><Password>NEVER_PARTIAL</Password></AssignMessage>`}, bad})
		if _, _, err := c.projectApigeeBundleCapture(bundle, "organizations/demo/apis/api/revisions/3"); err == nil {
			t.Fatal("accepted", bad)
		}
		if samples := c.SecretCapture.Samples(); len(samples) != 0 {
			t.Fatal("partial", samples)
		}
	}
}

func TestApigeeCaptureBoundsAndRefetchIdentity(t *testing.T) {
	c := Client{SecretCapture: NewSecretCapture(10000, 4<<20, 64<<20)}
	bundle := apigeeTestBundle(t, [][2]string{{"apiproxy/policies/huge.xml", `<AssignMessage name="huge">` + strings.Repeat("x", 4<<20) + `</AssignMessage>`}})
	if _, _, err := c.projectApigeeBundleCapture(bundle, "organizations/demo/apis/api/revisions/3"); err == nil || len(c.SecretCapture.Samples()) != 0 {
		t.Fatal("size bound")
	}
	for _, path := range []string{"bundle[../evil.xml].xml", "bundle[sharedflowbundle/policies/test.xml].xml", "bundle[apiproxy/policies/test.xml].xml; evil", "bundle[apiproxy/policies/test.xml].xml.elements[0].Password"} {
		s := SecretSample{SourceType: "apigee_bundle_config", Resource: "//apigee.googleapis.com/organizations/demo/apis/api/revisions/3", Path: path}
		endpoint, _ := ApigeeSecretRefetchRequest(s)
		if (endpoint != "") != strings.HasSuffix(path, ".elements[0].Password") {
			t.Fatal(path, endpoint)
		}
	}
}
