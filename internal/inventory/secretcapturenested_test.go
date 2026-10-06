package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestViewerSecretAnnotationsTransientOnly(t *testing.T) {
	for _, regional := range []bool{false, true} {
		var mask string
		fn := func(r *http.Request) (*http.Response, error) {
			mask = r.URL.Query().Get("fields")
			name := "projects/123/secrets/key"
			if regional {
				name = "projects/123/locations/us-central1/secrets/key"
			}
			return response(200, `{"secrets":[{"name":"`+name+`","annotations":{"password":"ANNOTATION_SECRET"}}]}`), nil
		}
		c := keyMetadataClient(t, fn)
		if regional {
			c = regionalSecretsClient(t, fn)
		}
		c.SecretCapture = NewSecretCapture(0, 0, 0)
		var s Snapshot
		if regional {
			c.viewerRegionalSecretList(context.Background(), &s, "demo", "projects/123", "us-central1", "projects/123/locations/us-central1", false)
		} else {
			c.viewerKeyChildren(context.Background(), &s, "secretmanager.googleapis.com", "projects/123", "secrets", "Secret", "projects/123", "demo", false)
		}
		if !strings.Contains(mask, "annotations") || len(c.SecretCapture.Samples()) != 1 || string(c.SecretCapture.Samples()[0].Data) != "password=ANNOTATION_SECRET" {
			t.Fatal("missing annotation capture", regional, s, c.SecretCapture.Samples(), mask)
		}
		b, _ := json.Marshal(s)
		if strings.Contains(string(b), "ANNOTATION_SECRET") {
			t.Fatal("annotation leaked into inventory", regional)
		}
	}
}

func TestSelectedNestedWorkloadCapture(t *testing.T) {
	c := NewSecretCapture(0, 0, 0)
	a := NewAsset("//dataflow.googleapis.com/projects/123/locations/us-central1/jobs/job", "dataflow.googleapis.com/Job", Object{
		"environment":   Object{"sdkPipelineOptions": Object{"db": Object{"password": "NESTED_PASSWORD"}, "list": []any{"ARRAY_VALUE"}}},
		"executionInfo": Object{"password": "OUTPUT_FORBIDDEN"},
	})
	c.CaptureInventory([]Asset{a})
	p := NewAsset("//aiplatform.googleapis.com/projects/123/locations/us-central1/pipelineJobs/job", "aiplatform.googleapis.com/PipelineJob", Object{
		"runtimeConfig": Object{"parameterValues": Object{"password": "PIPELINE_PASSWORD"}},
		"pipelineSpec":  Object{"deploymentSpec": Object{"executors": Object{"exec": Object{"container": Object{"args": []any{"--password=ARG_SECRET"}, "env": []any{Object{"name": "PASSWORD", "value": "ENV_SECRET"}, Object{"name": "REF", "value": "NO_CAPTURE", "valueFrom": Object{"secret": "ref"}}}}}}}, "root": Object{"inputDefinitions": Object{"parameters": Object{"password": Object{"defaultValue": "DEFAULT_SECRET"}}}, "dag": Object{"tasks": Object{"task": Object{"inputs": Object{"parameters": Object{"p": Object{"runtimeValue": Object{"constant": "CONSTANT_SECRET"}}}}}}}}},
		"jobDetail":     Object{"password": "OUTPUT_FORBIDDEN"},
	})
	c.CaptureInventory([]Asset{p})
	var all strings.Builder
	for _, s := range c.Samples() {
		all.Write(s.Data)
		all.WriteByte('\n')
	}
	for _, want := range []string{"NESTED_PASSWORD", "ARRAY_VALUE", "PIPELINE_PASSWORD", "ARG_SECRET", "ENV_SECRET", "DEFAULT_SECRET", "CONSTANT_SECRET"} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("missing selected value %s", want)
		}
	}
	for _, deny := range []string{"OUTPUT_FORBIDDEN", "NO_CAPTURE"} {
		if strings.Contains(all.String(), deny) {
			t.Errorf("captured forbidden value %s", deny)
		}
	}
	foreign := p
	foreign.Name = "//evil.googleapis.com/projects/123/locations/us-central1/pipelineJobs/job"
	fresh := NewSecretCapture(0, 0, 0)
	fresh.CaptureInventory([]Asset{foreign})
	if len(fresh.Samples()) != 0 {
		t.Fatal("captured foreign resource")
	}
}

func TestNestedCaptureDepthLimit(t *testing.T) {
	var value any = "DEEP_SECRET"
	for i := 0; i < 40; i++ {
		value = Object{"nested": value}
	}
	c := NewSecretCapture(0, 0, 0)
	c.captureConfigurationTree("dataflow_config", NewAsset("//dataflow.googleapis.com/projects/123/locations/us-central1/jobs/job", "dataflow.googleapis.com/Job", nil), "environment.sdkPipelineOptions", value)
	if len(c.Samples()) != 0 || c.Coverage()[0].Status != "incomplete" {
		t.Fatal("deep configuration must report incomplete without partial credential")
	}
}
