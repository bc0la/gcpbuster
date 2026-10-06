package inventory

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/url"
	"regexp"
	"strings"
)

var apiGatewayMCPToolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// projectAPIGatewayMCP projects discovery policy and declared tool eligibility,
// not deployed or callable tools. No names, descriptions, URLs or paths escape.
func projectAPIGatewayMCP(root map[string]*yaml.Node) (Object, error) {
	bad := func() (Object, error) {
		return Object{"complete": false}, fmt.Errorf("API Gateway MCP configuration is malformed or unsupported; discovery authentication is unknown")
	}
	if !apiGatewayOpenAPI3Version.MatchString(apiGatewayAuthString(root["openapi"])) {
		return bad()
	}
	if root["x-google-mcp-tool"] != nil {
		return bad()
	}
	global := false
	var mcp map[string]*yaml.Node
	var backends map[string]*yaml.Node
	if node, exists := root["x-google-api-management"]; exists {
		management, ok := apiGatewayAuthMap(node)
		if !ok {
			return bad()
		}
		if node, exists := management["backends"]; exists {
			backends, ok = apiGatewayAuthMap(node)
			if !ok {
				return bad()
			}
		}
		if node, exists := management["mcp"]; exists {
			if node.Kind == yaml.ScalarNode && node.Tag == "!!bool" {
				global = strings.EqualFold(node.Value, "true")
			} else {
				var ok bool
				mcp, ok = apiGatewayAuthMap(node)
				if !ok {
					return bad()
				}
				global = true
				for key := range mcp {
					if key != "tools-list" {
						return bad()
					}
				}
			}
		}
	}
	enabled := global
	ins, outs := 0, 0
	eligible := 0
	toolNames := map[string]bool{}
	router := false
	paths, ok := apiGatewayAuthMap(root["paths"])
	if !ok {
		return bad()
	}
	for path, node := range paths {
		if strings.HasPrefix(path, "x-") {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			return bad()
		}
		item, ok := apiGatewayAuthMap(node)
		if !ok || item["$ref"] != nil || item["x-google-mcp-tool"] != nil {
			return bad()
		}
		for _, method := range []string{"get", "post", "put", "patch", "delete", "options", "head", "trace"} {
			node, exists := item[method]
			if !exists {
				continue
			}
			op, ok := apiGatewayAuthMap(node)
			if !ok || op["$ref"] != nil {
				return bad()
			}
			router = router || op["x-google-model-router"] != nil
			tool, exists := op["x-google-mcp-tool"]
			if method == "options" || method == "head" || method == "trace" {
				if exists {
					return bad()
				}
				continue
			}
			opt := global
			toolName := apiGatewayAuthString(op["operationId"])
			description := apiGatewayAuthString(op["description"])
			if strings.TrimSpace(description) == "" {
				description = apiGatewayAuthString(op["summary"])
			}
			if !exists {
			} else if tool.Kind == yaml.ScalarNode && tool.Tag == "!!bool" {
				opt = strings.EqualFold(tool.Value, "true")
			} else {
				spec, ok := apiGatewayAuthMap(tool)
				if !ok {
					return bad()
				}
				for key, value := range spec {
					if key != "name" && key != "description" {
						return bad()
					}
					if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
						return bad()
					}
					if key == "name" && !apiGatewayMCPToolName.MatchString(value.Value) {
						return bad()
					}
					if key == "description" && strings.TrimSpace(value.Value) == "" {
						return bad()
					}
					if key == "name" {
						toolName = value.Value
					}
					if key == "description" {
						description = value.Value
					}
				}
				opt = true
			}
			if opt {
				enabled = true
				if exists {
					ins++
				}
				backendNode := root["x-google-backend"]
				if node, exists := op["x-google-backend"]; exists {
					backendNode = node
				}
				backendRef := apiGatewayAuthString(backendNode)
				backend, valid := apiGatewayAuthMap(backends[backendRef])
				if !valid || backendRef == "" || !apiGatewayMCPToolName.MatchString(toolName) || strings.TrimSpace(description) == "" || toolNames[toolName] {
					return bad()
				}
				address := apiGatewayAuthString(backend["address"])
				parsed, err := url.Parse(address)
				if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" || parsed.User != nil {
					return bad()
				}
				toolNames[toolName] = true
				eligible++
			} else {
				if exists {
					outs++
				}
			}
		}
	}
	if enabled && router {
		return bad()
	}
	mode := "none"
	if !enabled {
		mode = "disabled"
	}
	if node, exists := mcp["tools-list"]; exists {
		tools, ok := apiGatewayAuthMap(node)
		if !ok {
			return bad()
		}
		for key := range tools {
			if key != "security" {
				return bad()
			}
		}
		if node, exists := tools["security"]; exists {
			requirements, ok := apiGatewayAuthMap(node)
			if !ok || len(requirements) != 1 {
				return bad()
			}
			components, ok := apiGatewayAuthMap(root["components"])
			if !ok {
				return bad()
			}
			defs, ok := apiGatewayAuthMap(components["securitySchemes"])
			if !ok {
				return bad()
			}
			for name, scopes := range requirements {
				if scopes.Kind != yaml.SequenceNode || len(scopes.Content) != 0 {
					return bad()
				}
				scheme, ok := apiGatewayAuthMap(defs[name])
				if !ok || scheme["$ref"] != nil {
					return bad()
				}
				switch apiGatewayAuthString(scheme["type"]) {
				case "apiKey":
					if apiGatewayAuthString(scheme["in"]) != "header" || apiGatewayAuthString(scheme["name"]) != "x-api-key" {
						return bad()
					}
					mode = "api_key"
				case "oauth2":
					flows, valid := apiGatewayAuthMap(scheme["flows"])
					if !valid || len(flows) != 1 {
						return bad()
					}
					flow, valid := apiGatewayAuthMap(flows["implicit"])
					if !valid {
						return bad()
					}
					if _, valid = apiGatewayAuthMap(flow["scopes"]); !valid {
						return bad()
					}
					if n := flow["authorizationUrl"]; n == nil || n.Tag != "!!str" {
						return bad()
					}
					auth, ok := apiGatewayAuthMap(scheme["x-google-auth"])
					if !ok || strings.TrimSpace(apiGatewayAuthString(auth["issuer"])) == "" {
						return bad()
					}
					security := root["security"]
					if security == nil || security.Kind != yaml.SequenceNode {
						return bad()
					}
					found := false
					for _, node := range security.Content {
						entry, ok := apiGatewayAuthMap(node)
						if !ok {
							return bad()
						}
						if node, exists := entry[name]; exists {
							if node.Kind != yaml.SequenceNode {
								return bad()
							}
							for _, scope := range node.Content {
								if scope.Kind != yaml.ScalarNode || scope.Tag != "!!str" {
									return bad()
								}
							}
							found = true
						}
					}
					if !found {
						return bad()
					}
					mode = "jwt"
				default:
					return bad()
				}
			}
		}
	}
	return Object{"complete": true, "enabled": enabled, "global": global, "operation_opt_ins": ins, "operation_opt_outs": outs, "eligible_declared_tools": eligible, "tools_list_auth": mode}, nil
}
