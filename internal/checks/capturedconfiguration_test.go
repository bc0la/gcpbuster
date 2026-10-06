package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestCapturedConfigurationActualValuesAndNativeHeuristics(t *testing.T) {
	samples := []inventory.SecretSample{
		{SourceType: "function_env", Resource: "//cloudfunctions.googleapis.com/projects/demo/locations/us/functions/f", Path: "environmentVariables.PASSWORD", Data: []byte("PASSWORD=long\nmultiline=value\n")},
		{SourceType: "cloud_build_config", Resource: "//cloudbuild.googleapis.com/projects/demo/builds/b", Path: "steps[0].env[1]", Data: []byte("NORMAL=ordinary-value")},
		{SourceType: "run_config", Resource: "//run.googleapis.com/projects/demo/locations/us/services/s", Path: "template.containers[0].env[0].value", Data: []byte("OTHER=-----BEGIN synthetic")},
	}
	assets := CapturedSampleAssets(samples, false)
	if len(assets) != 3 {
		t.Fatal(assets)
	}
	for i, a := range assets {
		got := capturedConfigurationValue(a, time.Time{})
		if len(got) != 1 {
			t.Fatal(got)
		}
		want := "high"
		if i == 1 {
			want = "info"
		}
		if got[0].Severity != want {
			t.Fatal(got)
		}
		_, value, _ := strings.Cut(string(samples[i].Data), "=")
		if got[0].Evidence["value"] != value {
			t.Fatal("value changed", got)
		}
		if strings.Contains(a.Name, value) || strings.Contains(got[0].Title, value) {
			t.Fatal("value in identity/title")
		}
	}
}

func TestCapturedConfigurationRedactedAllValueChannels(t *testing.T) {
	sample := inventory.SecretSample{SourceType: "appengine_env", Resource: "//appengine.googleapis.com/apps/sensitive-resource", Path: "envVariables.SECRET_SPECIAL", Data: []byte("SECRET_SPECIAL=synthetic-sensitive-value")}
	assets := CapturedSampleAssets([]inventory.SecretSample{sample}, true)
	if len(assets) != 1 {
		t.Fatal(assets)
	}
	got := capturedConfigurationValue(assets[0], time.Time{})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatal(got)
	}
	for _, v := range []any{assets, got} {
		encoded, _ := json.Marshal(v)
		for _, needle := range []string{"SECRET_SPECIAL", "synthetic-sensitive-value", "sensitive-resource"} {
			if strings.Contains(string(encoded), needle) {
				t.Fatal(string(encoded))
			}
		}
	}
}

func TestCapturedConfigurationExactAssignmentSourcesAndReferences(t *testing.T) {
	for source, path := range map[string]string{"appengine_build_env": "buildEnvVariables.KEY", "function_build_env": "buildConfig.environmentVariables.KEY", "run_job_config": "template.template.containers[0].env[1].value", "compute_instance_metadata": "metadata.items[0].value", "compute_project_metadata": "commonInstanceMetadata.items[0].value", "workflow_env": "userEnvVars.KEY"} {
		a := CapturedSampleAssets([]inventory.SecretSample{{SourceType: source, Resource: "//example.googleapis.com/r", Path: path, Data: []byte("KEY=normal")}}, false)
		if len(a) != 1 {
			t.Fatal(source, path)
		}
	}
	for _, sample := range []inventory.SecretSample{
		{SourceType: "cloud_build_config", Path: "steps[0].script", Data: []byte("PASSWORD=shell")},
		{SourceType: "run_config", Path: "template.containers[0].args[0]", Data: []byte("PASSWORD=short")},
		{SourceType: "workflow_definition", Path: "sourceContents", Data: []byte("PASSWORD=source")},
		{SourceType: "function_env", Path: "environmentVariables.OTHER", Data: []byte("PASSWORD=mismatch")},
	} {
		sample.Resource = "//example.googleapis.com/r"
		if got := CapturedSampleAssets([]inventory.SecretSample{sample}, false); len(got) != 0 {
			t.Fatal(sample.SourceType, sample.Path, got)
		}
	}
}

func TestNativeInformationalEmptyPlaceholderReferenceAndHistory(t *testing.T) {
	for _, ref := range []string{"projects/demo/locations/us-central1/secrets/key", "projects/demo/locations/us-central1/secrets/key/versions/latest", "//secretmanager.googleapis.com/projects/demo/locations/us-central1/secrets/key/versions/1"} {
		if candidate(ref) {
			t.Fatal("regional reference became credential candidate", ref)
		}
	}
	for _, sample := range []inventory.SecretSample{
		{SourceType: "function_env", Path: "environmentVariables.PASSWORD", Data: []byte("PASSWORD=")},
		{SourceType: "function_env", Path: "environmentVariables.PASSWORD", Data: []byte("PASSWORD=${ENV_PASSWORD}")},
		{SourceType: "function_env", Path: "environmentVariables.PASSWORD", Data: []byte("PASSWORD=projects/demo/secrets/a/versions/latest")},
		{SourceType: "function_env", Path: "environmentVariables.PASSWORD", Data: []byte("PASSWORD=projects/demo/locations/us-central1/secrets/a/versions/latest")},
		{SourceType: "function_env", Path: "environmentVariables.ODD.NAME", Data: []byte("ODD.NAME=ordinary-value")},
		{SourceType: "workflow_execution", Path: "argument", Data: []byte(`{"request":"benign"}`)},
		{SourceType: "workflow_execution", Path: "result", Data: []byte("done")},
		{SourceType: "workflow_execution", Path: "error.payload", Data: []byte("ordinary error")},
		{SourceType: "run_context", Path: "template.containers[0].image", Data: []byte("image=us-docker.pkg.dev/demo/repo/image:v1")},
		{SourceType: "run_context", Path: "template.serviceAccount", Data: []byte("serviceAccount=runner@demo.iam.gserviceaccount.com")},
	} {
		sample.Resource = "//example.googleapis.com/r"
		for _, redact := range []bool{false, true} {
			assets := CapturedSampleAssets([]inventory.SecretSample{sample}, redact)
			if len(assets) != 1 {
				t.Fatal(sample, assets)
			}
			got := capturedConfigurationValue(assets[0], time.Time{})
			if len(got) != 1 || got[0].Severity != "info" {
				t.Fatal(sample, got)
			}
			want := string(sample.Data)
			if sample.SourceType != "workflow_execution" {
				_, want, _ = strings.Cut(want, "=")
			}
			if redact {
				want = "[REDACTED]"
			}
			if got[0].Evidence["value"] != want {
				t.Fatal("value changed", got)
			}
		}
	}
}

func TestNativeRefetchFieldsActualOnly(t *testing.T) {
	sample := inventory.SecretSample{SourceType: "function_env", Resource: "//example.googleapis.com/r", Path: "environmentVariables.NORMAL", Data: []byte("NORMAL=ordinary-value")}
	for _, redact := range []bool{false, true} {
		assets := CapturedSampleAssets([]inventory.SecretSample{sample}, redact)
		assets[0].Resource.Data["pull_command"] = "example describe resource"
		assets[0].Resource.Data["source_location"] = "us-central1"
		assets[0].Resource.Data["refetch_metadata"] = inventory.Object{"source_field": "environmentVariables.NORMAL"}
		got := capturedConfigurationValue(assets[0], time.Time{})
		if len(got) != 1 {
			t.Fatal(got)
		}
		for _, key := range []string{"pull_command", "source_location", "refetch_metadata"} {
			_, ok := got[0].Evidence[key]
			if ok == redact {
				t.Fatal("refetch visibility mismatch", redact, key, got)
			}
		}
	}
}
