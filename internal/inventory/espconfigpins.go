package inventory

import (
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var espVMName = regexp.MustCompile(`^//compute\.googleapis\.com/projects/([a-z][a-z0-9-]*)/zones/[a-z][a-z0-9-]*/instances/[a-z][a-z0-9-]*$`)
var espRuntimeImage = regexp.MustCompile(`^gcr\.io/endpoints-release/endpoints-runtime:[12](?:\.[0-9]+){0,3}$`)

// CorrelateESPConfigPins observes a narrow legacy GCE container declaration.
// It does not establish that the guest/container actually runs this config.
// Cloud Run serverless bakes config into its image: its ESPv2_ARGS cannot set
// service/version. Never guess a compiled config from an image tag or shell.
// https://docs.cloud.google.com/endpoints/docs/openapi/specify-esp-v2-startup-options
// https://docs.cloud.google.com/compute/docs/containers/migrate-containers
func CorrelateESPConfigPins(snap *Snapshot) {
	for i := range snap.Assets {
		if snap.Assets[i].Type == ServiceConfigType {
			delete(snap.Assets[i].Resource.Data, "_gcpbusterESPConfigPins")
		}
	}
	if len(snap.Assets) > 100000 {
		snap.Coverage = append(snap.Coverage, Coverage{Source: "esp-config-pins", Status: "incomplete", Error: "Snapshot exceeds bounded ESP declaration correlation limit"})
		return
	}
	type observation struct{ project, service, config, signature string }
	observed := map[string]observation{}
	conflicts := map[string]bool{}
	for _, a := range snap.Assets {
		if a.Type != "compute.googleapis.com/Instance" {
			continue
		}
		m := espVMName.FindStringSubmatch(a.Name)
		if m == nil {
			continue
		}
		body, count := "", 0
		for _, raw := range List(Get(a.Resource.Data, "metadata", "items")) {
			row := Obj(raw)
			if Str(row["key"]) == "gce-container-declaration" {
				count++
				body = Str(row["value"])
			}
		}
		status := Str(a.Resource.Data["status"])
		sig := status + "\x00" + Str(a.Resource.Data["name"]) + "\x00" + body
		service, config, ok := espDeclaredFixedConfig(body)
		if count != 1 || status != "RUNNING" || Str(a.Resource.Data["name"]) != a.Name[strings.LastIndex(a.Name, "/")+1:] || !ok {
			conflicts[a.Name] = true
			continue
		}
		if prev, exists := observed[a.Name]; exists && prev.signature != sig {
			conflicts[a.Name] = true
		}
		observed[a.Name] = observation{m[1], service, config, sig}
	}
	byConfig := map[string][]string{}
	for name, o := range observed {
		if !conflicts[name] {
			key := o.project + "\x00" + o.service + "\x00" + o.config
			byConfig[key] = append(byConfig[key], name)
		}
	}
	for _, names := range byConfig {
		sort.Strings(names)
	}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != ServiceConfigType {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterESPConfigPins")
		service, config := Str(a.Resource.Data["name"]), Str(a.Resource.Data["id"])
		project := Str(a.Resource.Data["producerProjectId"])
		if !viewerManagedServiceName.MatchString(service) || !viewerManagedConfigID.MatchString(config) || a.Name != "//servicemanagement.googleapis.com/services/"+service+"/configs/"+config {
			continue
		}
		names := byConfig[project+"\x00"+service+"\x00"+config]
		if len(names) > 100 {
			snap.Coverage = append(snap.Coverage, Coverage{Source: "esp-config-pins:" + a.Name, Status: "incomplete", Error: "More than 100 matching declarations; evidence truncated, not complete deployment inventory"})
			names = names[:100]
		}
		rows := []any{}
		for _, name := range names {
			rows = append(rows, Object{"workload": name, "workload_type": "compute.googleapis.com/Instance", "vm_status": "RUNNING", "selection": "explicit_fixed_container_declaration", "service": service, "config_id": config})
		}
		if len(rows) > 0 {
			a.Resource.Data["_gcpbusterESPConfigPins"] = rows
		}
	}
}

// Only explicit documented argv is accepted; no shell interpolation, aliases,
// arbitrary YAML tags/merges, local config paths or managed rollout inference.
func espDeclaredFixedConfig(body string) (string, string, bool) {
	if len(body) == 0 || len(body) > 65536 {
		return "", "", false
	}
	d := yaml.NewDecoder(strings.NewReader(body))
	var root, next yaml.Node
	if d.Decode(&root) != nil || d.Decode(&next) != io.EOF {
		return "", "", false
	}
	nodes := 0
	var valid func(*yaml.Node, int) bool
	valid = func(n *yaml.Node, depth int) bool {
		nodes++
		if nodes > 4096 || depth > 32 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		if n.Kind == yaml.MappingNode {
			if n.Tag != "!!map" {
				return false
			}
			keys := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Tag != "!!str" || keys[k.Value] || k.Value == "<<" {
					return false
				}
				keys[k.Value] = true
			}
		}
		if n.Kind == yaml.SequenceNode && n.Tag != "!!seq" {
			return false
		}
		if n.Kind == yaml.ScalarNode && n.Tag != "!!str" && n.Tag != "!!bool" && n.Tag != "!!int" && n.Tag != "!!null" {
			return false
		}
		for _, c := range n.Content {
			if !valid(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !valid(&root, 0) {
		return "", "", false
	}
	var data map[string]any
	if root.Decode(&data) != nil {
		return "", "", false
	}
	containers, ok := Get(data, "spec", "containers").([]any)
	if !ok || len(containers) != 1 {
		return "", "", false
	}
	c := Obj(containers[0])
	if !espRuntimeImage.MatchString(Str(c["image"])) {
		return "", "", false
	}
	// Entrypoint/environment overrides may change selection or suppress startup.
	for _, k := range []string{"command", "env"} {
		if raw, present := c[k]; present {
			v, ok := raw.([]any)
			if !ok || len(v) != 0 {
				return "", "", false
			}
		}
	}
	args, ok := c["args"].([]any)
	if !ok || len(args) > 128 {
		return "", "", false
	}
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a, ok := args[i].(string)
		if !ok || len(a) > 4096 {
			return "", "", false
		}
		key, value, eq := strings.Cut(a, "=")
		switch key {
		case "--service", "--version", "--rollout_strategy", "--backend", "--http_port", "--listener_port":
		default:
			return "", "", false
		}
		if _, duplicate := flags[key]; duplicate {
			return "", "", false
		}
		if !eq {
			i++
			if i >= len(args) {
				return "", "", false
			}
			value, ok = args[i].(string)
			if !ok {
				return "", "", false
			}
		}
		if value == "" || strings.ContainsAny(value, "\x00\r\n$`\\\"'") || strings.HasPrefix(value, "--") {
			return "", "", false
		}
		flags[key] = value
	}
	if strategy, present := flags["--rollout_strategy"]; present && strategy != "fixed" {
		return "", "", false
	}
	service, config := flags["--service"], flags["--version"]
	return service, config, viewerManagedServiceName.MatchString(service) && viewerManagedConfigID.MatchString(config)
}
