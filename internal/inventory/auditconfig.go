package inventory

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const AuditConfigType = "gcpbuster.googleapis.com/InheritedAuditConfig"

var auditServiceName = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)

func auditContainerScope(a Asset) (string, bool) {
	name := strings.TrimPrefix(a.Name, "//cloudresourcemanager.googleapis.com/")
	prefix := map[string]string{"cloudresourcemanager.googleapis.com/Project": "projects/", "cloudresourcemanager.googleapis.com/Folder": "folders/", "cloudresourcemanager.googleapis.com/Organization": "organizations/"}[a.Type]
	return name, prefix != "" && strings.HasPrefix(name, prefix) && logScopePattern.MatchString(name)
}

func containerAsset(a Asset) bool {
	return a.Type == "cloudresourcemanager.googleapis.com/Project" || a.Type == "cloudresourcemanager.googleapis.com/Folder" || a.Type == "cloudresourcemanager.googleapis.com/Organization"
}

// auditChain accepts an explicit Resource Manager parent chain, or a complete
// CAI ancestors list terminating at the organization. Missing topology is unknown.
func auditChain(a Asset, index map[string]Asset) ([]string, bool) {
	name, valid := auditContainerScope(a)
	if !valid {
		return nil, false
	}
	if _, known := a.Resource.Data["parent"]; !known && len(a.Ancestors) > 0 {
		chain := []string{name}
		seen := map[string]bool{name: true}
		for i, ancestor := range a.Ancestors {
			if ancestor == name && i == 0 {
				continue
			}
			if !logScopePattern.MatchString(ancestor) || strings.HasPrefix(ancestor, "projects/") || seen[ancestor] || strings.HasPrefix(chain[len(chain)-1], "organizations/") {
				return chain, false
			}
			seen[ancestor] = true
			chain = append(chain, ancestor)
		}
		complete := strings.HasPrefix(chain[len(chain)-1], "organizations/")
		// An ancestor list must not override contradictory supplied Resource
		// Manager metadata (for example a folder belonging to another org).
		for i, scope := range chain {
			if current, exists := index[scope]; exists {
				if _, valid := auditContainerScope(current); !valid {
					complete = false
				}
				if raw, known := current.Resource.Data["parent"]; known {
					expected := ""
					if i+1 < len(chain) {
						expected = chain[i+1]
					}
					parent, ok := raw.(string)
					if !ok || parent != expected {
						complete = false
					}
				}
			}
		}
		return chain, complete
	}
	var chain []string
	seen := map[string]bool{}
	for name != "" {
		if seen[name] || !logScopePattern.MatchString(name) {
			return chain, false
		}
		seen[name] = true
		chain = append(chain, name)
		current, exists := index[name]
		if !exists {
			return chain, false
		}
		if _, valid := auditContainerScope(current); !valid {
			return chain, false
		}
		parent, known := current.Resource.Data["parent"]
		if strings.HasPrefix(name, "organizations/") {
			if known {
				p, ok := parent.(string)
				if !ok || p != "" {
					return chain, false
				}
			}
			return chain, auditAncestorsAgree(a, chain)
		}
		if !known {
			return chain, false
		}
		p, ok := parent.(string)
		if !ok || (p != "" && !strings.HasPrefix(p, "folders/") && !strings.HasPrefix(p, "organizations/")) {
			return chain, false
		}
		if p == "" && strings.HasPrefix(name, "folders/") {
			return chain, false
		}
		name = p
	}
	return chain, auditAncestorsAgree(a, chain)
}

func auditAncestorsAgree(a Asset, chain []string) bool {
	position := 1
	for i, ancestor := range a.Ancestors {
		if i == 0 && len(chain) > 0 && ancestor == chain[0] {
			continue
		}
		if position >= len(chain) || ancestor != chain[position] {
			return false
		}
		position++
	}
	return true
}

// ResolveAuditConfigs unions audit log types and exemption lists across supplied
// policies. It does not claim that enabled streams are delivered or retained.
func ResolveAuditConfigs(snap *Snapshot) {
	index := map[string]Asset{}
	ambiguous := map[string]bool{}
	for _, a := range snap.Assets {
		if containerAsset(a) {
			name := strings.TrimPrefix(a.Name, "//cloudresourcemanager.googleapis.com/")
			if prior, exists := index[name]; exists && !reflect.DeepEqual(prior, a) {
				ambiguous[name] = true
			}
			index[name] = a
		}
	}
	assets := append([]Asset(nil), snap.Assets...)
	for _, a := range assets {
		if !containerAsset(a) || a.IAM == nil {
			continue
		}
		chain, complete := auditChain(a, index)
		type row struct {
			service, logType string
			members, sources map[string]bool
		}
		rows := map[string]*row{}
		services := map[string]bool{"allServices": true}
		for _, name := range chain {
			policy, exists := index[name]
			if ambiguous[name] {
				complete = false
			}
			if !exists || policy.IAM == nil {
				complete = false
				continue
			}
			if raw, exists := policy.IAM["_gcpbusterBindingsOnly"]; exists {
				limited, valid := raw.(bool)
				if !valid || limited {
					complete = false
					continue
				}
			}
			if raw, exists := policy.IAM["auditConfigs"]; exists {
				if _, ok := raw.([]any); !ok {
					complete = false
					continue
				}
			}
			for _, raw := range List(policy.IAM["auditConfigs"]) {
				config := Obj(raw)
				service := Str(config["service"])
				if service != "allServices" && !auditServiceName.MatchString(service) {
					complete = false
					continue
				}
				services[service] = true
				logs, ok := config["auditLogConfigs"].([]any)
				if !ok {
					complete = false
					continue
				}
				for _, rawLog := range logs {
					log := Obj(rawLog)
					typ := Str(log["logType"])
					if typ != "ADMIN_READ" && typ != "DATA_READ" && typ != "DATA_WRITE" {
						complete = false
						continue
					}
					key := service + "/" + typ
					r := rows[key]
					if r == nil {
						r = &row{service, typ, map[string]bool{}, map[string]bool{}}
						rows[key] = r
					}
					r.sources[name] = true
					if rawMembers, exists := log["exemptedMembers"]; exists {
						members, ok := rawMembers.([]any)
						if !ok {
							complete = false
							continue
						}
						for _, m := range members {
							member, ok := m.(string)
							if !ok || strings.TrimSpace(member) == "" || strings.TrimSpace(member) != member {
								complete = false
								continue
							}
							r.members[member] = true
						}
					}
				}
			}
		}
		var derived []any
		serviceNames := sortedSet(services)
		for _, service := range serviceNames {
			for _, typ := range []string{"ADMIN_READ", "DATA_READ", "DATA_WRITE"} {
				members, sources := map[string]bool{}, map[string]bool{}
				enabled := false
				for _, key := range []string{"allServices/" + typ, service + "/" + typ} {
					if r := rows[key]; r != nil {
						enabled = true
						for m := range r.members {
							members[m] = true
						}
						for source := range r.sources {
							sources[source] = true
						}
					}
				}
				if enabled {
					derived = append(derived, Object{"service": service, "logType": typ, "exemptedMembers": stringList(sortedSet(members)), "sources": stringList(sortedSet(sources))})
				}
			}
		}
		x := NewAsset(a.Name+"/inherited-audit-config", AuditConfigType, Object{"resource": a.Name, "chain": stringList(chain), "complete": complete, "configs": derived})
		x.Ancestors = a.Ancestors
		snap.Assets = append(snap.Assets, x)
		if !complete {
			snap.Coverage = append(snap.Coverage, Coverage{Source: "audit-inheritance:" + a.Name, Status: "notice", Error: "Parent topology or policies are missing/malformed. Known audit settings are reported, but absence of inherited logging cannot be established."})
		}
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func stringList(v []string) []any {
	out := make([]any, len(v))
	for i, x := range v {
		out[i] = x
	}
	return out
}
