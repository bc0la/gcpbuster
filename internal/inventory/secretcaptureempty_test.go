package inventory

import "testing"

func TestEmptyEnvironmentAndRunContextCapture(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	c.CaptureStringMap("function_env", "//cloudfunctions.googleapis.com/projects/demo/locations/us-central1/functions/f", "us-central1", "environmentVariables", Object{"PASSWORD": "", "REF": "projects/demo/secrets/key/versions/1"})
	a := NewAsset("//run.googleapis.com/projects/demo/locations/us-central1/services/s", "run.googleapis.com/Service", Object{"template": Object{"serviceAccount": "runner@demo.iam.gserviceaccount.com", "containers": []any{Object{"image": "example/image:v1", "env": []any{Object{"name": "EMPTY", "value": ""}}}}}})
	c.CaptureInventory([]Asset{a})
	ss := c.Samples()
	if len(ss) != 5 {
		t.Fatal(ss)
	}
	seen := map[string]bool{}
	for _, s := range ss {
		seen[string(s.Data)] = true
	}
	for _, want := range []string{"PASSWORD=", "REF=projects/demo/secrets/key/versions/1", "EMPTY=", "image=example/image:v1", "serviceAccount=runner@demo.iam.gserviceaccount.com"} {
		if !seen[want] {
			t.Fatal("missing native inventory value", want)
		}
	}
}
