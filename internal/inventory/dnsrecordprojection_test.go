package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDNSRecordProjectionSecretsAndTXTChunks(t *testing.T) {
	token := "ghp_" + strings.Repeat("A", 36)
	for _, value := range []string{token, `"ghp_" "` + strings.Repeat("A", 36) + `"`, `"\103hp_` + strings.Repeat("A", 36) + `"`} {
		got, err := projectDNSRecordSet(Object{"name": "_config.example.test.", "type": "TXT", "ttl": float64(60), "rrdatas": []any{value}})
		if err != nil || len(List(got["_gcpbusterSecretCandidates"])) == 0 {
			t.Fatal(got, err)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), token) || strings.Contains(string(b), strings.Repeat("A", 36)) || got["rrdatas"] != nil {
			t.Fatal(string(b))
		}
	}
	got, err := projectDNSRecordSet(Object{"name": "example.test.", "type": "TXT", "rrdatas": []any{`"v=spf1 include:example.test -all"`}})
	if err != nil || got["_gcpbusterSecretCandidates"] != nil {
		t.Fatal(got, err)
	}
}

func TestDNSRecordProjectionMetadataAndLimits(t *testing.T) {
	if got, err := projectDNSRecordSet(Object{"name": "example.test.", "type": "A"}); got == nil || err == nil {
		t.Fatal(got, err)
	}
	for _, tc := range []struct{ kind, value string }{{"A", "192.0.2.1"}, {"AAAA", "2001:db8::1"}, {"CNAME", "target.example.test."}, {"NS", "ns.example.test."}, {"MX", "10 mail.example.test."}, {"SRV", "0 5 443 target.example.test."}} {
		got, err := projectDNSRecordSet(Object{"name": "*.example.test.", "type": tc.kind, "rrdatas": []any{tc.value}})
		if err != nil || len(List(got["_gcpbusterRecordTargets"])) != 1 {
			t.Fatal(got, err)
		}
	}
	for _, value := range []any{nil, []any{false}, []any{strings.Repeat("a", (4<<20)+1)}} {
		got, err := projectDNSRecordSet(Object{"name": "example.test.", "type": "TXT", "rrdatas": value})
		if err == nil || got == nil {
			t.Fatal(got, err)
		}
	}
	for _, value := range []string{`"unterminated`, `"\999"`, `"\12"`, `"a"junk`} {
		if _, valid := dnsTXTCharacters(value); valid {
			t.Fatal(value)
		}
	}
	got, err := projectDNSRecordSet(Object{"name": "example.test.", "type": "A", "routingPolicy": Object{"wrr": Object{"items": []any{Object{"rrdatas": []any{"password=PRIVATE_SENTINEL"}}}}}})
	if err != nil || got["routing_policy_present"] != true || len(List(got["_gcpbusterSecretCandidates"])) == 0 {
		t.Fatal(got, err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PRIVATE_SENTINEL") {
		t.Fatal(string(b))
	}
}
