package inventory

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const apiGatewayAuthMaxBytes = 4 << 20

var apiGatewayOpenAPI3Version = regexp.MustCompile(`^3\.[01]\.[0-9]+$`)

// projectAPIGatewayAuth inspects a transient FULL ApiConfig response. Only
// fixed classifications and operation digests leave this function. It neither
// follows references nor evaluates/executes backend or gateway requests.
func projectAPIGatewayAuth(raw Object) (Object, error) {
	bad := func() (Object, error) {
		return nil, fmt.Errorf("API Gateway auth analysis requires one unambiguous supported OpenAPI document; malformed, oversized or unsupported source was not assessed")
	}
	for _, field := range []string{"grpcServices", "managedServiceConfigs"} {
		if v, exists := raw[field]; exists {
			rows, ok := v.([]any)
			if !ok || len(rows) > 0 {
				return bad()
			}
		}
	}
	docs, ok := raw["openapiDocuments"].([]any)
	if !ok || len(docs) != 1 {
		return bad()
	}
	contents, ok := Obj(Obj(docs[0])["document"])["contents"].(string)
	if !ok || len(contents) > base64.StdEncoding.EncodedLen(apiGatewayAuthMaxBytes) {
		return bad()
	}
	data, err := base64.StdEncoding.Strict().DecodeString(contents)
	if err != nil || len(data) == 0 || len(data) > apiGatewayAuthMaxBytes {
		return bad()
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 {
		return bad()
	}
	var next yaml.Node
	if decoder.Decode(&next) != io.EOF {
		return bad()
	}
	nodes := 0
	var validate func(*yaml.Node, int) bool
	validate = func(n *yaml.Node, depth int) bool {
		nodes++
		if depth > 64 || nodes > 100000 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		if n.Kind == yaml.MappingNode {
			if len(n.Content)%2 != 0 {
				return false
			}
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Value == "<<" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		}
		for _, child := range n.Content {
			if !validate(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !validate(&doc, 0) {
		return bad()
	}
	root, ok := apiGatewayAuthMap(doc.Content[0])
	if !ok {
		return bad()
	}
	version := apiGatewayAuthString(root["swagger"])
	if root["openapi"] != nil {
		if root["swagger"] != nil {
			return bad()
		}
		version = apiGatewayAuthString(root["openapi"])
		if !apiGatewayOpenAPI3Version.MatchString(version) {
			return bad()
		}
	} else if version != "2.0" {
		return bad()
	}
	v3 := version != "2.0"
	if v3 && root["x-google-allow"] != nil {
		return bad()
	}
	// Unsupported Service Management authentication overrides must not be
	// silently treated as equivalent to standard security inheritance.
	if root["x-google-management"] != nil {
		return bad()
	}
	paths, ok := apiGatewayAuthMap(root["paths"])
	if !ok {
		return bad()
	}
	definitions := map[string]*yaml.Node{}
	definitionNode := root["securityDefinitions"]
	if v3 {
		if definitionNode != nil {
			return bad()
		}
		if root["components"] != nil {
			components, valid := apiGatewayAuthMap(root["components"])
			if !valid || components["$ref"] != nil {
				return bad()
			}
			definitionNode = components["securitySchemes"]
		}
	}
	if node := definitionNode; node != nil {
		definitions, ok = apiGatewayAuthMap(node)
		if !ok {
			return bad()
		}
	}
	rootAuth := root["security"]
	keys := make([]string, 0, len(paths))
	for key := range paths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	routes := []any{}
	incomplete := false
	if v3 && root["webhooks"] != nil {
		incomplete = true
	}
	for _, path := range keys {
		if strings.HasPrefix(path, "x-") {
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n\x00") {
			incomplete = true
			continue
		}
		item, ok := apiGatewayAuthMap(paths[path])
		if !ok || item["$ref"] != nil {
			incomplete = true
			continue
		}
		invalidItem := false
		for key := range item {
			if v3 && (key == "summary" || key == "description" || key == "servers" || key == "trace") {
				continue
			}
			if key != "parameters" && key != "get" && key != "put" && key != "post" && key != "delete" && key != "options" && key != "head" && key != "patch" && !strings.HasPrefix(key, "x-") {
				invalidItem = true
			}
		}
		if invalidItem || item["x-google-management"] != nil {
			incomplete = true
			continue
		}
		methods := []string{"get", "put", "post", "delete", "options", "head", "patch"}
		if v3 {
			methods = append(methods, "trace")
		}
		for _, method := range methods {
			node, exists := item[method]
			if !exists {
				continue
			}
			operation, ok := apiGatewayAuthMap(node)
			if !ok || operation["$ref"] != nil || operation["x-google-management"] != nil {
				incomplete = true
				continue
			}
			if v3 && operation["callbacks"] != nil {
				incomplete = true
			}
			security, source := rootAuth, "root"
			if security == nil {
				source = "implicit"
			}
			if n, exists := operation["security"]; exists {
				security, source = n, "operation"
			}
			auth, alternatives, err := apiGatewayAuthRequirements(security, definitions, version)
			if err != nil {
				incomplete = true
				continue
			}
			digest := sha256.Sum256([]byte(strings.ToUpper(method) + " " + path))
			routes = append(routes, Object{"method": strings.ToUpper(method), "route_digest": hex.EncodeToString(digest[:]), "auth": auth, "security_source": source, "alternatives": alternatives})
		}
	}
	result := Object{"version": version, "routes": routes}
	if v3 {
		mcp, mcpErr := projectAPIGatewayMCP(root)
		if mcp != nil {
			result["mcp"] = mcp
		}
		if mcpErr != nil {
			incomplete = true
		}
	}
	result["complete"] = !incomplete
	if incomplete {
		return result, fmt.Errorf("some API Gateway operations have unsupported or malformed authentication metadata; only independently resolved operations were assessed")
	}
	return result, nil
}

func apiGatewayAuthMap(n *yaml.Node) (map[string]*yaml.Node, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	m := map[string]*yaml.Node{}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, false
		}
		m[key.Value] = n.Content[i+1]
	}
	return m, true
}
func apiGatewayAuthString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return ""
	}
	return n.Value
}

// Requirements within one object are ANDed; array entries are alternatives.
// Empty security removes inherited authentication; an empty alternative also
// permits requests without any configured client credential.
func apiGatewayAuthRequirements(n *yaml.Node, defs map[string]*yaml.Node, versions ...string) (string, []any, error) {
	v3 := len(versions) > 0 && versions[0] != "2.0"
	bad := func() (string, []any, error) {
		return "", nil, fmt.Errorf("unsupported API Gateway security requirement")
	}
	if n == nil {
		return "none", []any{}, nil
	}
	if n.Kind != yaml.SequenceNode {
		return bad()
	}
	if len(n.Content) == 0 {
		return "none", []any{}, nil
	}
	alternatives := []any{}
	anonymous := false
	hasKey, hasJWT := false, false
	for _, entry := range n.Content {
		req, ok := apiGatewayAuthMap(entry)
		if !ok {
			return bad()
		}
		if len(req) == 0 {
			anonymous = true
			alternatives = append(alternatives, []any{})
			continue
		}
		names := []string{}
		for name := range req {
			names = append(names, name)
		}
		sort.Strings(names)
		kinds := []any{}
		for _, name := range names {
			scopes := req[name]
			if scopes.Kind != yaml.SequenceNode {
				return bad()
			}
			for _, scope := range scopes.Content {
				if scope.Kind != yaml.ScalarNode || scope.Tag != "!!str" {
					return bad()
				}
			}
			scheme, ok := apiGatewayAuthMap(defs[name])
			if !ok || scheme["$ref"] != nil {
				return bad()
			}
			kind := apiGatewayAuthString(scheme["type"])
			switch kind {
			case "apiKey":
				location := apiGatewayAuthString(scheme["in"])
				if len(scopes.Content) != 0 || (location != "header" && location != "query") || strings.TrimSpace(apiGatewayAuthString(scheme["name"])) == "" {
					return bad()
				}
				kinds = append(kinds, "api_key")
				hasKey = true
			case "oauth2":
				if v3 {
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
					auth, valid := apiGatewayAuthMap(scheme["x-google-auth"])
					if !valid || strings.TrimSpace(apiGatewayAuthString(auth["issuer"])) == "" {
						return bad()
					}
				} else if apiGatewayAuthString(scheme["flow"]) != "implicit" || strings.TrimSpace(apiGatewayAuthString(scheme["x-google-issuer"])) == "" {
					return bad()
				}
				kinds = append(kinds, "jwt")
				hasJWT = true
			default:
				return bad()
			}
		}
		alternatives = append(alternatives, kinds)
	}
	// Gateway does not support API-key alternatives (OR), or multiple JWT
	// schemes in one conjunction. Do not infer anonymous access from them.
	// Empty alternatives are documented as optional API-key security, but
	// optional OAuth security is unsupported by Gateway.
	if anonymous && hasJWT {
		return bad()
	}
	keyAlternatives := 0
	for _, alternative := range alternatives {
		if len(alternative.([]any)) > 0 {
			keyAlternatives++
		}
	}
	if hasKey && keyAlternatives > 1 {
		return bad()
	}
	for _, alternative := range alternatives {
		jwtCount := 0
		for _, kind := range alternative.([]any) {
			if kind == "jwt" {
				jwtCount++
			}
		}
		if jwtCount > 1 {
			return bad()
		}
	}
	if anonymous {
		return "optional", alternatives, nil
	}
	if hasKey && hasJWT {
		return "mixed", alternatives, nil
	}
	if hasKey {
		return "api_key", alternatives, nil
	}
	if hasJWT {
		return "jwt", alternatives, nil
	}
	return bad()
}
