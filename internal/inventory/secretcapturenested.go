package inventory

import (
	"fmt"
	"strings"
)

// captureConfigurationTree only walks a caller-selected configuration subtree.
// It never follows artifact references or reads execution results. Limits also
// bound deeply nested SDK option objects before they reach scanner staging.
func (c *SecretCapture) captureConfigurationTree(source string, a Asset, path string, value any) {
	if c == nil {
		return
	}
	nodes := 0
	var walk func(string, string, any, int)
	walk = func(p, key string, v any, depth int) {
		nodes++
		if nodes > 10000 || depth > 32 {
			c.Add(SecretSample{})
			return
		}
		switch x := v.(type) {
		case string:
			if x != "" && x != "[REDACTED]" {
				c.Add(SecretSample{SourceType: source, Resource: a.Name, Location: a.Resource.Location, Path: p, Data: []byte(key + "=" + x)})
			}
		case []any:
			for i, item := range x {
				if nodes > 10000 {
					break
				}
				walk(fmt.Sprintf("%s[%d]", p, i), key, item, depth+1)
			}
		default:
			m := Obj(v)
			for _, k := range sortedCaptureKeys(m) {
				if nodes > 10000 {
					break
				}
				leafKey := k
				if source == "vertex_pipeline_config" || source == "dataflow_config" {
					// Preserve the declared parameter identity through JSON and
					// deprecated protobuf Value wrappers. These wrapper names are
					// representation, not the credential's variable name.
					leafKey = key
					wrapper := k == "stringValue" || k == "intValue" || k == "doubleValue" || k == "numberValue" || k == "boolValue" || k == "nullValue" || k == "structValue" || k == "listValue" || k == "fields" || k == "values"
					if key == "" || !wrapper || source == "dataflow_config" && k != "stringValue" && k != "structValue" && k != "listValue" && k != "fields" && k != "values" {
						if leafKey != "" {
							leafKey += "."
						}
						leafKey += k
					}
				}
				walk(p+"."+k, leafKey, m[k], depth+1)
			}
		}
	}
	parts := strings.Split(path, ".")
	key := parts[len(parts)-1]
	if source == "vertex_pipeline_config" && (path == "runtimeConfig.parameterValues" || path == "runtimeConfig.parameters") || source == "dataflow_config" {
		key = ""
	}
	if key == "defaultValue" && len(parts) > 1 {
		key = parts[len(parts)-2]
	}
	if strings.HasSuffix(path, ".runtimeValue.constant") && len(parts) > 2 {
		key = parts[len(parts)-3]
	}
	walk(path, key, value, 0)
}

func (c *SecretCapture) capturePipeline(a Asset) {
	if c == nil {
		return
	}
	d := a.Resource.Data
	// Stored parameter values are inputs, not runtime jobDetail/output artifacts.
	for _, field := range []string{"parameterValues", "parameters"} {
		c.captureConfigurationTree("vertex_pipeline_config", a, "runtimeConfig."+field, Get(d, "runtimeConfig", field))
	}
	executors := Obj(Get(d, "pipelineSpec", "deploymentSpec", "executors"))
	for _, key := range sortedCaptureKeys(executors) {
		container := Obj(Get(Obj(executors[key]), "container"))
		c.captureContainers("vertex_pipeline_config", a.Name, a.Resource.Location, "pipelineSpec.deploymentSpec.executors."+key+".container", []any{container})
	}
	components := Obj(Get(d, "pipelineSpec", "components"))
	captureComponent := func(base string, component Object) {
		params := Obj(Get(component, "inputDefinitions", "parameters"))
		for _, p := range sortedCaptureKeys(params) {
			c.captureConfigurationTree("vertex_pipeline_config", a, base+".inputDefinitions.parameters."+p+".defaultValue", Get(Obj(params[p]), "defaultValue"))
		}
		tasks := Obj(Get(component, "dag", "tasks"))
		for _, task := range sortedCaptureKeys(tasks) {
			inputs := Obj(Get(Obj(tasks[task]), "inputs", "parameters"))
			for _, p := range sortedCaptureKeys(inputs) {
				c.captureConfigurationTree("vertex_pipeline_config", a, base+".dag.tasks."+task+".inputs.parameters."+p+".runtimeValue.constant", Get(Obj(inputs[p]), "runtimeValue", "constant"))
			}
		}
	}
	for _, key := range sortedCaptureKeys(components) {
		captureComponent("pipelineSpec.components."+key, Obj(components[key]))
	}
	captureComponent("pipelineSpec.root", Obj(Get(d, "pipelineSpec", "root")))
}
