package inventory

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

var dnsRecordType = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}$`)

// projectDNSRecordSet never returns arbitrary RDATA or routing-policy payloads.
// Names and simple address/host targets are metadata; credential candidates
// retain only their position and fixed detector rule, never values or hashes.
func projectDNSRecordSet(raw Object) (Object, error) {
	name, kind := Str(raw["name"]), Str(raw["type"])
	if !validDNSZoneName(strings.TrimPrefix(name, "*.")) || !dnsRecordType.MatchString(kind) {
		return nil, fmt.Errorf("invalid DNS record identity")
	}
	out := Object{"name": strings.ToLower(name), "type": kind}
	partial := false
	_, hasData := raw["rrdatas"]
	_, hasRouting := raw["routingPolicy"]
	if !hasData && !hasRouting {
		partial = true
	}
	if value, exists := raw["ttl"]; exists {
		n, ok := value.(float64)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < 0 || n > 2147483647 {
			partial = true
		} else {
			out["ttl"] = n
		}
	}
	remaining := 4 << 20
	candidates := []any{}
	scan := func(value []byte, field string, index int) bool {
		if len(value) > remaining {
			partial = true
			return false
		}
		remaining -= len(value)
		seen := map[string]bool{}
		for _, match := range secretmatch.Text(value, "") {
			if seen[match.Rule] {
				continue
			}
			seen[match.Rule] = true
			if len(candidates) >= 1000 {
				partial = true
				break
			}
			candidates = append(candidates, Object{"field": field, "record_index": index, "rule": match.Rule})
		}
		return len(seen) > 0
	}
	if value, exists := raw["rrdatas"]; exists {
		rows, ok := value.([]any)
		if !ok || len(rows) > 10000 {
			partial = true
		} else {
			out["data_count"] = len(rows)
			targets := []any{}
			for i, row := range rows {
				text, ok := row.(string)
				if !ok || len(text) > remaining {
					partial = true
					continue
				}
				candidate := scan([]byte(text), "rrdatas", i)
				if kind == "TXT" {
					if decoded, valid := dnsTXTCharacters(text); valid {
						// Scan joined quoted chunks too; quotes can split a token.
						if decoded != text {
							candidate = scan([]byte(decoded), "rrdatas", i) || candidate
						}
					} else {
						partial = true
					}
				}
				if !candidate {
					if target, known, valid := dnsRecordTarget(kind, text); known {
						if valid {
							target["record_index"] = i
							targets = append(targets, target)
						} else {
							partial = true
						}
					}
				}
			}
			if len(targets) > 0 {
				out["_gcpbusterRecordTargets"] = targets
			}
		}
	}
	if value, exists := raw["routingPolicy"]; exists {
		if policy := Obj(value); len(policy) > 0 {
			out["routing_policy_present"] = true
			data, err := json.Marshal(policy)
			if err != nil {
				partial = true
			} else {
				scan(data, "routingPolicy", 0)
			}
		} else {
			partial = true
		}
	}
	if len(candidates) > 0 {
		out["_gcpbusterSecretCandidates"] = candidates
	}
	if partial {
		return out, fmt.Errorf("DNS record metadata or bounded content inspection was incomplete")
	}
	return out, nil
}

func dnsRecordTarget(kind, value string) (Object, bool, bool) {
	fields := strings.Fields(value)
	item := Object{"kind": kind}
	switch kind {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || (kind == "A") != ip.Is4() {
			return nil, true, false
		}
		item["address"] = ip.String()
	case "CNAME", "NS", "PTR", "MX", "SRV":
		want := 1
		if kind == "MX" {
			want = 2
		}
		if kind == "SRV" {
			want = 4
		}
		if len(fields) != want {
			return nil, true, false
		}
		host := strings.ToLower(fields[want-1])
		if !validDNSZoneName(host) || (host == "." && kind != "SRV" && kind != "MX") {
			return nil, true, false
		}
		item["host"] = host
		for i, key := range []string{"priority", "weight", "port"} {
			if i >= want-1 {
				break
			}
			n, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, true, false
			}
			item[key] = int(n)
		}
	default:
		return nil, false, true
	}
	return item, true, true
}

// DNS master-file character strings use decimal \DDD escapes, not Go octal.
// Concatenate only chunks within one TXT RR, never unrelated RR values.
func dnsTXTCharacters(text string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(text); {
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i == len(text) {
			break
		}
		quoted := text[i] == '"'
		if quoted {
			i++
		}
		closed := !quoted
		for i < len(text) {
			c := text[i]
			if quoted && c == '"' {
				i++
				closed = true
				break
			}
			if !quoted && (c == ' ' || c == '\t') {
				break
			}
			if !quoted && c == '"' {
				return "", false
			}
			if c == '\n' || c == '\r' {
				return "", false
			}
			if c == '\\' {
				i++
				if i == len(text) {
					return "", false
				}
				if text[i] >= '0' && text[i] <= '9' {
					if i+3 > len(text) {
						return "", false
					}
					for _, d := range text[i : i+3] {
						if d < '0' || d > '9' {
							return "", false
						}
					}
					n, err := strconv.Atoi(text[i : i+3])
					if err != nil || n > 255 {
						return "", false
					}
					out.WriteByte(byte(n))
					i += 3
					continue
				}
				c = text[i]
			}
			out.WriteByte(c)
			i++
		}
		if !closed {
			return "", false
		}
		if quoted && i < len(text) && text[i] != ' ' && text[i] != '\t' {
			return "", false
		}
	}
	return out.String(), true
}
