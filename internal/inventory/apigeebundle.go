package inventory

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

type apigeeXMLNode struct {
	name     string
	attrs    map[string]string
	text     string
	children []*apigeeXMLNode
}

var apigeePolicyName = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,255}$`)
var apigeeXMLDeclaration = regexp.MustCompile(`^version\s*=\s*["']1\.0["'](?:\s+encoding\s*=\s*["'](?:UTF-8|utf-8)["'])?(?:\s+standalone\s*=\s*["'](?:yes|no)["'])?\s*$`)

func projectApigeeBundle(raw []byte) (Object, error) {
	return projectApigeeBundleInternal(raw, nil, nil)
}

// Only the collector receives literal names, transiently, for bounded reads.
// The report projection contains digests and typed flags, never source names.
type ApigeeFlowReference struct {
	SharedFlow                                 string
	Conditional, Enabled, ContinueOnError      bool
	EndpointDigest, PolicyDigest, EndpointKind string
}

func projectApigeeBundleWithReferences(raw []byte) (Object, []ApigeeFlowReference, error) {
	refs := []ApigeeFlowReference{}
	projection, err := projectApigeeBundleInternal(raw, &refs, nil)
	if err != nil {
		return projection, nil, err
	}
	return projection, refs, nil
}

func projectApigeeBundleInternal(raw []byte, refs *[]ApigeeFlowReference, members *[]apigeeConfigurationMember) (Object, error) {
	failed := func() (Object, error) {
		return Object{"complete": false, "auth_policies": []any{}}, fmt.Errorf("Apigee bundle is malformed, ambiguous, oversized or unsupported")
	}
	if len(raw) > 16<<20 {
		return failed()
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(z.File) > 4096 {
		return failed()
	}
	policies := map[string]*apigeeXMLNode{}
	attached := map[string]bool{}
	endpoints := map[string]*apigeeXMLNode{}
	seen := map[string]bool{}
	total := int64(0)
	xmlBudget := 250000
	for _, f := range z.File {
		name := f.Name
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\\x00:") || strings.HasPrefix(name, "/") || path.Clean(strings.TrimSuffix(name, "/")) != strings.TrimSuffix(name, "/") || strings.HasPrefix(name, "../") || seen[name] {
			return failed()
		}
		seen[name] = true
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.Mode().IsRegular() || f.UncompressedSize64 > 4<<20 {
			return failed()
		}
		total += int64(f.UncompressedSize64)
		if total > 32<<20 {
			return failed()
		}
		r, e := f.Open()
		if e != nil {
			return failed()
		}
		body, e := io.ReadAll(io.LimitReader(r, (4<<20)+1))
		closeErr := r.Close()
		if e != nil || closeErr != nil || len(body) > 4<<20 {
			return failed()
		}
		parts := strings.Split(name, "/")
		if len(parts) != 3 || (parts[0] != "apiproxy" && parts[0] != "sharedflowbundle") || !strings.HasSuffix(parts[2], ".xml") {
			continue
		}
		section := parts[1]
		if section != "policies" && section != "proxies" && section != "targets" && section != "sharedflows" {
			continue
		}
		n, e := parseApigeeXMLBudget(body, &xmlBudget)
		if e != nil {
			return failed()
		}
		if members != nil {
			*members = append(*members, apigeeConfigurationMember{name: name, body: body})
		}
		if section == "policies" {
			id := n.attrs["name"]
			if !apigeePolicyName.MatchString(id) || policies[id] != nil {
				return failed()
			}
			policies[id] = n
		} else {
			expected := map[string]string{"proxies": "ProxyEndpoint", "targets": "TargetEndpoint", "sharedflows": "SharedFlow"}[section]
			if n.name != expected {
				return failed()
			}
			if e := apigeeAttachedSteps(n, nil, attached); e != nil {
				return failed()
			}
			if n.name == "ProxyEndpoint" || n.name == "SharedFlow" {
				endpoints[name] = n
			}
		}
	}
	ids := []string{}
	for id := range attached {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []any{}
	for _, id := range ids {
		n := policies[id]
		if n == nil {
			return failed()
		}
		if n.name != "VerifyAPIKey" && n.name != "VerifyJWT" && n.name != "OAuthV2" {
			continue
		}
		if n.name == "OAuthV2" {
			operation := ""
			count := 0
			for _, child := range n.children {
				if child.name == "Operation" {
					operation = strings.TrimSpace(child.text)
					count++
					if len(child.children) > 0 {
						return failed()
					}
				}
			}
			if count != 1 {
				return failed()
			}
			if operation != "VerifyAccessToken" {
				continue
			}
		}
		disabled, cont := false, false
		for _, key := range []string{"enabled", "continueOnError"} {
			if value, exists := n.attrs[key]; exists {
				if value != "true" && value != "false" {
					return failed()
				}
				if key == "enabled" {
					disabled = value == "false"
				} else {
					cont = value == "true"
				}
			}
		}
		if !disabled && !cont {
			continue
		}
		digest := sha256.Sum256([]byte(id))
		out = append(out, Object{"policy_digest": hex.EncodeToString(digest[:]), "kind": n.name, "disabled": disabled, "continue_on_error": cont})
	}
	requestAuth, err := apigeeRequestAuthentication(endpoints, policies, refs)
	if err != nil {
		return failed()
	}
	return Object{"complete": true, "auth_policies": out, "request_authentication": requestAuth}, nil
}

// This is a native request-flow configuration summary, never an effective
// access decision. Conditional Flows are first-match, so even an unconditioned
// Flow is conservatively conditional here. Response/fault steps do not count.
// Only standalone lowercase boolean literals (optionally parenthesized) are
// evaluated. No variables, operators, coercion or substring matching.
// https://docs.cloud.google.com/apigee/docs/api-platform/reference/conditions-reference
func apigeeLiteralCondition(raw string) (bool, bool) {
	if len(raw) > 256 {
		return false, false
	}
	x := strings.TrimSpace(raw)
	for depth := 0; depth < 32 && strings.HasPrefix(x, "(") && strings.HasSuffix(x, ")"); depth++ {
		x = strings.TrimSpace(x[1 : len(x)-1])
	}
	if x == "true" {
		return true, true
	}
	if x == "false" {
		return false, true
	}
	return false, false
}

func apigeeRequestAuthentication(endpoints, policies map[string]*apigeeXMLNode, refs *[]ApigeeFlowReference) ([]any, error) {
	names := []string{}
	for name := range endpoints {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []any
	for _, name := range names {
		n := endpoints[name]
		digest := sha256.Sum256([]byte(name))
		row := Object{"endpoint_digest": hex.EncodeToString(digest[:]), "endpoint_kind": n.name, "unconditional_authentication_steps": 0, "conditional_authentication_steps": 0, "non_enforcing_authentication_steps": 0, "unresolved_request_steps": 0}
		row["literal_flow_callouts"] = []any{}
		row["unresolved_flow_callouts"] = 0
		if n.name == "ProxyEndpoint" {
			row["configured_base_path"] = apigeeBasePathProjection(n)
		}
		var walk func(*apigeeXMLNode, string, bool, bool) error
		walk = func(node *apigeeXMLNode, parent string, conditional, inactive bool) error {
			path := parent + "/" + node.name
			conditions := 0
			for _, child := range node.children {
				if child.name == "Condition" {
					conditions++
					if len(child.children) != 0 {
						return fmt.Errorf("nested flow condition")
					}
					if len(child.attrs) != 0 {
						return fmt.Errorf("unsupported flow condition attributes")
					}
					if value, known := apigeeLiteralCondition(child.text); known {
						inactive = inactive || !value
					} else {
						conditional = true
					}
				}
			}
			if conditions > 1 {
				return fmt.Errorf("duplicate flow condition")
			}
			conditional = conditional || path == "/ProxyEndpoint/Flows/Flow"
			if node.name == "Step" {
				request := parent == "/SharedFlow" || parent == "/ProxyEndpoint/PreFlow/Request" || parent == "/ProxyEndpoint/PostFlow/Request" || parent == "/ProxyEndpoint/Flows/Flow/Request"
				if !request {
					return nil
				}
				id := ""
				for _, child := range node.children {
					if child.name == "Name" {
						id = strings.TrimSpace(child.text)
					}
				}
				p := policies[id]
				if p == nil {
					return fmt.Errorf("unresolved policy reference")
				}
				// Validate structure/references above even for an unreachable Step.
				// False paths contribute no verifier or FlowCallout dependency.
				if inactive {
					return nil
				}
				if p.name == "FlowCallout" {
					enabled, cont := true, false
					for _, key := range []string{"enabled", "continueOnError"} {
						if value, exists := p.attrs[key]; exists {
							if value != "true" && value != "false" {
								return fmt.Errorf("invalid FlowCallout boolean")
							}
							if key == "enabled" {
								enabled = value == "true"
							} else {
								cont = value == "true"
							}
						}
					}
					var target *apigeeXMLNode
					for _, child := range p.children {
						if child.name == "SharedFlowBundle" {
							if target != nil {
								return fmt.Errorf("ambiguous FlowCallout target")
							}
							target = child
						}
					}
					if target == nil || len(target.children) != 0 {
						return fmt.Errorf("missing or nested FlowCallout target")
					}
					literal := strings.TrimSpace(target.text)
					if len(target.attrs) != 0 || !regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$`).MatchString(literal) {
						row["unresolved_flow_callouts"] = row["unresolved_flow_callouts"].(int) + 1
					} else {
						policyDigest := sha256.Sum256([]byte(id))
						flowDigest := sha256.Sum256([]byte(literal))
						ref := ApigeeFlowReference{SharedFlow: literal, Conditional: conditional, Enabled: enabled, ContinueOnError: cont, EndpointDigest: hex.EncodeToString(digest[:]), PolicyDigest: hex.EncodeToString(policyDigest[:]), EndpointKind: n.name}
						row["literal_flow_callouts"] = append(row["literal_flow_callouts"].([]any), Object{"policy_digest": ref.PolicyDigest, "shared_flow_digest": hex.EncodeToString(flowDigest[:]), "conditional": conditional, "enabled": enabled, "continue_on_error": cont})
						if refs != nil {
							*refs = append(*refs, ref)
						}
					}
				}
				auth := p.name == "VerifyAPIKey" || p.name == "VerifyJWT"
				if p.name == "OAuthV2" {
					for _, child := range p.children {
						if child.name == "Operation" && strings.TrimSpace(child.text) == "VerifyAccessToken" {
							auth = true
						}
					}
				}
				key := "unresolved_request_steps"
				if auth {
					key = "unconditional_authentication_steps"
					if conditional {
						key = "conditional_authentication_steps"
					}
					if p.attrs["enabled"] == "false" || p.attrs["continueOnError"] == "true" {
						key = "non_enforcing_authentication_steps"
					}
				}
				row[key] = row[key].(int) + 1
				return nil
			}
			// Multiple singleton phase/request blocks are ambiguous, not empty.
			seen := map[string]bool{}
			for _, child := range node.children {
				if child.name == "PreFlow" || child.name == "PostFlow" || child.name == "Flows" || child.name == "Request" || child.name == "Response" {
					if seen[child.name] {
						return fmt.Errorf("duplicate flow block")
					}
					seen[child.name] = true
				}
				if err := walk(child, path, conditional, inactive); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(n, "", false, false); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

func parseApigeeXML(raw []byte) (*apigeeXMLNode, error) {
	budget := 100000
	return parseApigeeXMLBudget(raw, &budget)
}

func parseApigeeXMLBudget(raw []byte, budget *int) (*apigeeXMLNode, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	var root *apigeeXMLNode
	stack := []*apigeeXMLNode{}
	tokens := 0
	declaration := false
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		tokens++
		*budget--
		if tokens > 100000 || *budget < 0 {
			return nil, fmt.Errorf("XML token bound")
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("XML directives unsupported")
		case xml.ProcInst:
			if t.Target != "xml" || root != nil || declaration || !apigeeXMLDeclaration.Match(t.Inst) {
				return nil, fmt.Errorf("XML processing instruction unsupported")
			}
			declaration = true
		case xml.StartElement:
			if t.Name.Space != "" || len(stack) >= 128 {
				return nil, fmt.Errorf("XML namespace/depth unsupported")
			}
			n := &apigeeXMLNode{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				if a.Name.Space != "" || a.Name.Local == "xmlns" {
					return nil, fmt.Errorf("XML namespace unsupported")
				}
				if _, exists := n.attrs[a.Name.Local]; exists {
					return nil, fmt.Errorf("duplicate XML attribute")
				}
				n.attrs[a.Name.Local] = a.Value
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple XML roots")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("invalid XML nesting")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				if n.name == "BasePath" && len(n.text) < 2049 {
					remaining := 2049 - len(n.text)
					if len(t) > remaining {
						n.text += string(t[:remaining])
					} else {
						n.text += string(t)
					}
				}
				// Retain only a bounded transient condition prefix; overflow is
				// deliberately unknown to the literal recognizer, never truncated true.
				if n.name == "Condition" && len(n.text) < 257 {
					remaining := 257 - len(n.text)
					if len(t) > remaining {
						n.text += string(t[:remaining])
					} else {
						n.text += string(t)
					}
				}
				if n.name == "Name" || n.name == "Operation" || n.name == "SharedFlowBundle" {
					if len(n.text)+len(t) > 1024 {
						return nil, fmt.Errorf("XML scalar bound")
					}
					n.text += string(t)
				}
			} else if strings.TrimSpace(string(t)) != "" {
				return nil, fmt.Errorf("XML trailing content")
			}
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, fmt.Errorf("missing XML root")
	}
	return root, nil
}

func apigeeAttachedSteps(n *apigeeXMLNode, parents []string, out map[string]bool) error {
	if n.name == "Step" {
		p := strings.Join(parents, "/")
		allowed := false
		if p == "SharedFlow" {
			allowed = true
		}
		for _, root := range []string{"ProxyEndpoint", "TargetEndpoint"} {
			for _, suffix := range []string{"PreFlow/Request", "PreFlow/Response", "PostFlow/Request", "PostFlow/Response", "Flows/Flow/Request", "Flows/Flow/Response", "FaultRules/FaultRule", "DefaultFaultRule", "PostClientFlow/Response"} {
				if p == root+"/"+suffix {
					allowed = true
				}
			}
		}
		if !allowed {
			return fmt.Errorf("unsupported Step placement")
		}
		id := ""
		count := 0
		for _, child := range n.children {
			if child.name != "Name" && child.name != "Condition" {
				return fmt.Errorf("unsupported Step child")
			}
			if child.name == "Name" {
				id = strings.TrimSpace(child.text)
				count++
				if len(child.children) > 0 {
					return fmt.Errorf("nested Step name")
				}
			}
		}
		if count != 1 || !apigeePolicyName.MatchString(id) {
			return fmt.Errorf("invalid Step name")
		}
		out[id] = true
	}
	for _, child := range n.children {
		if err := apigeeAttachedSteps(child, append(append([]string{}, parents...), n.name), out); err != nil {
			return err
		}
	}
	return nil
}
