package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var serviceMethodName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// projectServiceManagementAuth requires a complete compiled config projection
// containing apis/authentication/usage. Proto defaults apply only to absent
// fields, never malformed or null fields. Caller must not pass a partial view.
func projectServiceManagementAuth(raw Object) (Object, error) {
	bad := func() (Object, error) {
		return nil, fmt.Errorf("compiled service authentication configuration is malformed or unsupported")
	}
	apis, ok := raw["apis"].([]any)
	if _, exists := raw["apis"]; !exists {
		apis = []any{}
		ok = true
	}
	if !ok || len(apis) > 1000 {
		return bad()
	}
	auth, ok := serviceAuthObject(raw, "authentication")
	if !ok {
		return bad()
	}
	usage, ok := serviceAuthObject(raw, "usage")
	if !ok {
		return bad()
	}
	authRules, ok := serviceAuthRules(auth)
	if !ok {
		return bad()
	}
	usageRules, ok := serviceAuthRules(usage)
	if !ok {
		return bad()
	}
	providers := map[string]bool{}
	if v, exists := auth["providers"]; exists {
		rows, ok := v.([]any)
		if !ok || len(rows) > 10000 {
			return bad()
		}
		for _, row := range rows {
			p := Obj(row)
			id, valid := p["id"].(string)
			issuer, validIssuer := p["issuer"].(string)
			if !valid || id == "" || !validIssuer || strings.TrimSpace(issuer) == "" || providers[id] {
				return bad()
			}
			providers[id] = true
		}
	}
	result := Object{"complete": true}
	methods := []any{}
	seen := map[string]bool{}
	partial := false
	for _, entry := range apis {
		api := Obj(entry)
		name := Str(api["name"])
		if len(name) > 1024 || !serviceMethodName.MatchString(name) {
			return bad()
		}
		rows, ok := api["methods"].([]any)
		if _, exists := api["methods"]; !exists {
			rows = []any{}
			ok = true
		}
		if !ok || len(rows) > 10000 {
			return bad()
		}
		for _, entry := range rows {
			method := Str(Obj(entry)["name"])
			if len(method) > 256 || !serviceMethodName.MatchString(method) || strings.Contains(method, ".") {
				return bad()
			}
			full := name + "." + method
			if seen[full] || len(seen) >= 10000 {
				return bad()
			}
			seen[full] = true
			a := serviceLastAuthRule(authRules, full)
			u := serviceLastAuthRule(usageRules, full)
			mode := "none"
			consumer := "required"
			authSource, usageSource := "default", "default"
			if a != nil {
				authSource = "rule"
				mode = serviceAuthMode(a, providers)
			}
			if u != nil {
				usageSource = "rule"
				consumer = "unknown"
				validFields := true
				for key := range u {
					if key != "selector" && key != "allowUnregisteredCalls" && key != "skipServiceControl" {
						validFields = false
					}
				}
				skip, valid := serviceAuthBool(u, "skipServiceControl")
				unregistered, valid2 := serviceAuthBool(u, "allowUnregisteredCalls")
				if validFields && valid && valid2 && !skip {
					consumer = "required"
					if unregistered {
						consumer = "not_required"
					}
				}
			}
			if mode == "unknown" || consumer == "unknown" {
				partial = true
			}
			digest := sha256.Sum256([]byte(full))
			methods = append(methods, Object{"method_digest": hex.EncodeToString(digest[:]), "authentication": mode, "consumer_identity": consumer, "authentication_source": authSource, "usage_source": usageSource})
		}
	}
	result["methods"] = methods
	result["complete"] = !partial
	if partial {
		return result, fmt.Errorf("some compiled service methods have malformed or unsupported authentication and usage rules")
	}
	return result, nil
}

func serviceAuthObject(o Object, key string) (Object, bool) {
	v, exists := o[key]
	if !exists {
		return Object{}, true
	}
	switch m := v.(type) {
	case Object:
		return m, true
	}
	return nil, false
}
func serviceAuthBool(o Object, key string) (bool, bool) {
	v, exists := o[key]
	if !exists {
		return false, true
	}
	b, ok := v.(bool)
	return b, ok
}
func serviceAuthRules(o Object) ([]Object, bool) {
	v, exists := o["rules"]
	if !exists {
		return nil, true
	}
	rows, ok := v.([]any)
	if !ok || len(rows) > 10000 {
		return nil, false
	}
	out := []Object{}
	for _, r := range rows {
		rule := Obj(r)
		selector, ok := rule["selector"].(string)
		if !ok || len(selector) > 8192 {
			return nil, false
		}
		for _, p := range strings.Split(selector, ",") {
			p = strings.TrimSpace(p)
			if p != "*" && !serviceMethodName.MatchString(strings.TrimSuffix(p, ".*")) {
				return nil, false
			}
		}
		out = append(out, rule)
	}
	return out, true
}
func serviceLastAuthRule(rules []Object, method string) Object {
	var last Object
	for _, rule := range rules {
		for _, p := range strings.Split(Str(rule["selector"]), ",") {
			p = strings.TrimSpace(p)
			if p == "*" || p == method || (strings.HasSuffix(p, ".*") && strings.HasPrefix(method, strings.TrimSuffix(p, "*"))) {
				last = rule
				break
			}
		}
	}
	return last
}
func serviceAuthMode(rule Object, providers map[string]bool) string {
	for key := range rule {
		if key != "selector" && key != "oauth" && key != "requirements" && key != "allowWithoutCredential" {
			return "unknown"
		}
	}
	allow, ok := serviceAuthBool(rule, "allowWithoutCredential")
	if !ok {
		return "unknown"
	}
	mode := "none"
	if v, exists := rule["requirements"]; exists {
		rows, ok := v.([]any)
		if !ok {
			return "unknown"
		}
		for _, r := range rows {
			id := Str(Obj(r)["providerId"])
			if !providers[id] {
				return "unknown"
			}
		}
		if len(rows) > 0 {
			mode = "jwt"
		}
	}
	if _, exists := rule["oauth"]; exists {
		oauth, ok := serviceAuthObject(rule, "oauth")
		if !ok {
			return "unknown"
		}
		scope, ok := oauth["canonicalScopes"].(string)
		if !ok || strings.TrimSpace(scope) == "" {
			return "unknown"
		}
		if mode != "none" {
			return "unknown"
		}
		mode = "oauth"
	}
	// This flag permits API keys instead of another credential; it does not
	// independently prove an anonymous request is accepted.
	if allow {
		mode = "api_key_alternative"
	}
	return mode
}
