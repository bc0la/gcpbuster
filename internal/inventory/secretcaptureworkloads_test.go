package inventory

import (
	"strings"
	"testing"
)

func TestSecretCaptureWorkloadsExplicitLeaves(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	a := NewAsset("//run.googleapis.com/projects/demo/locations/us-central1/services/a", "run.googleapis.com/Service", Object{"template": Object{"containers": []any{Object{"env": []any{Object{"name": "PASSWORD", "value": "exact-value"}, Object{"name": "REF", "value": "DO_NOT_CAPTURE", "valueSource": Object{"secretKeyRef": Object{"secret": "s"}}}}, "args": []any{"--token=exact-value"}, "unknown": "DO_NOT_CAPTURE"}}}, "unknown": "DO_NOT_CAPTURE"})
	c.captureServerless(a)
	b := NewAsset("//cloudbuild.googleapis.com/projects/123/locations/global/builds/a", "cloudbuild.googleapis.com/Build", Object{"steps": []any{Object{"env": []any{"PASSWORD=exact-value"}, "script": "token=exact-value", "unknown": "DO_NOT_CAPTURE"}}, "secrets": []any{Object{"secretEnv": Object{"PASSWORD": "DO_NOT_CAPTURE"}}}})
	c.captureBuild(b)
	if len(c.Samples()) != 4 {
		t.Fatalf("got %d", len(c.Samples()))
	}
	for _, s := range c.Samples() {
		if strings.Contains(string(s.Data), "DO_NOT_CAPTURE") {
			t.Fatal("protected/unselected data captured")
		}
	}
}
