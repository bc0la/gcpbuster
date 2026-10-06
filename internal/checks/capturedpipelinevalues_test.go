package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/bc0la/gcpbuster/internal/inventory"
)

func TestPipelineDeclaredSensitiveParametersAcrossValueVariants(t *testing.T) {
	const actual = "arbitrary_password_without_token_signature"
	for _, tc := range []struct {
		name           string
		data           inventory.Object
		path, variable string
	}{
		{"deprecated_string", inventory.Object{"runtimeConfig": inventory.Object{"parameters": inventory.Object{"PASSWORD": inventory.Object{"stringValue": actual}}}}, "runtimeConfig.parameters.PASSWORD.stringValue", "PASSWORD"},
		{"json_list", inventory.Object{"runtimeConfig": inventory.Object{"parameterValues": inventory.Object{"PASSWORD": []any{actual}}}}, "runtimeConfig.parameterValues.PASSWORD[0]", "PASSWORD"},
		{"deprecated_struct", inventory.Object{"runtimeConfig": inventory.Object{"parameters": inventory.Object{"PASSWORD": inventory.Object{"structValue": inventory.Object{"fields": inventory.Object{"endpoint": inventory.Object{"stringValue": actual}}}}}}}, "runtimeConfig.parameters.PASSWORD.structValue.fields.endpoint.stringValue", "PASSWORD.endpoint"},
		{"deprecated_list", inventory.Object{"runtimeConfig": inventory.Object{"parameters": inventory.Object{"PASSWORD": inventory.Object{"listValue": inventory.Object{"values": []any{inventory.Object{"stringValue": actual}}}}}}}, "runtimeConfig.parameters.PASSWORD.listValue.values[0].stringValue", "PASSWORD"},
		{"json_scalar", inventory.Object{"runtimeConfig": inventory.Object{"parameterValues": inventory.Object{"PASSWORD": actual}}}, "runtimeConfig.parameterValues.PASSWORD", "PASSWORD"},
		{"json_nested", inventory.Object{"runtimeConfig": inventory.Object{"parameterValues": inventory.Object{"PASSWORD": inventory.Object{"endpoint": actual}}}}, "runtimeConfig.parameterValues.PASSWORD.endpoint", "PASSWORD.endpoint"},
		{"component_default", inventory.Object{"pipelineSpec": inventory.Object{"components": inventory.Object{"worker": inventory.Object{"inputDefinitions": inventory.Object{"parameters": inventory.Object{"PASSWORD": inventory.Object{"defaultValue": inventory.Object{"stringValue": actual}}}}}}}}, "pipelineSpec.components.worker.inputDefinitions.parameters.PASSWORD.defaultValue.stringValue", "PASSWORD"},
		{"task_constant", inventory.Object{"pipelineSpec": inventory.Object{"root": inventory.Object{"dag": inventory.Object{"tasks": inventory.Object{"task": inventory.Object{"inputs": inventory.Object{"parameters": inventory.Object{"PASSWORD": inventory.Object{"runtimeValue": inventory.Object{"constant": inventory.Object{"stringValue": actual}}}}}}}}}}}, "pipelineSpec.root.dag.tasks.task.inputs.parameters.PASSWORD.runtimeValue.constant.stringValue", "PASSWORD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := inventory.NewAsset("//aiplatform.googleapis.com/projects/123/locations/us-central1/pipelineJobs/job", "aiplatform.googleapis.com/PipelineJob", tc.data)
			capture := inventory.NewSecretCapture(0, 0, 0)
			capture.CaptureInventory([]inventory.Asset{a})
			samples := capture.Samples()
			if len(samples) != 1 || samples[0].Path != tc.path || string(samples[0].Data) != tc.variable+"="+actual {
				t.Fatal("semantic parameter name lost", samples)
			}
			for _, redact := range []bool{false, true} {
				assets := CapturedSampleAssets(samples, redact)
				if len(assets) != 1 {
					t.Fatal(assets)
				}
				got := capturedConfigurationValue(assets[0], time.Time{})
				if len(got) != 1 || got[0].Severity != "high" {
					t.Fatal("sensitive parameter missed", got)
				}
				want := actual
				if redact {
					want = "[REDACTED]"
				}
				if got[0].Evidence["value"] != want {
					t.Fatal("value changed", got)
				}
				if !redact && got[0].Evidence["variable"] != tc.variable {
					t.Fatal("variable changed", got)
				}
				if redact && strings.Contains(s(got[0].Evidence["value"]), actual) {
					t.Fatal("value leaked")
				}
			}
		})
	}
}
