package inventory

import "testing"

func TestEffectivePolicyConfiguredWorldCandidatesAndUnknownSelectors(t *testing.T) {
	rule := func(action string, priority int) Object {
		return Object{"priority": priority, "action": action, "direction": "INGRESS", "match": Object{"srcIpRanges": []any{"0.0.0.0/0"}, "layer4Configs": []any{Object{"ipProtocol": "tcp", "ports": []any{"443"}}}}}
	}
	a, b, c := rule("allow", 1), rule("deny", 2), rule("goto_next", 3)
	policies := []any{Object{"type": "HIERARCHY", "priority": 99, "rules": []any{a, b, c}}}
	got, unknown := effectivePolicyCandidates(policies, "projects/demo/global/networks/default")
	if len(got) != 3 || unknown != 0 {
		t.Fatal(got, unknown)
	}
	if Obj(got[0])["association_priority"] != nil {
		t.Fatal("hierarchy priority interpreted")
	}
	for _, mode := range []string{"secure_tag", "service_account", "fqdn", "mixed_family", "missing_source", "duplicate_priority", "disabled"} {
		r := rule("allow", 1)
		rows := []any{r}
		switch mode {
		case "secure_tag":
			r["targetSecureTags"] = []any{Object{"name": "tagValues/1", "state": "EFFECTIVE"}}
		case "service_account":
			r["targetServiceAccounts"] = []any{"sa@demo.iam.gserviceaccount.com"}
		case "fqdn":
			Obj(r["match"])["srcFqdns_count"] = 1
		case "mixed_family":
			Obj(r["match"])["srcIpRanges"] = []any{"0.0.0.0/0", "2001:db8::/32"}
		case "missing_source":
			delete(Obj(r["match"]), "srcIpRanges")
		case "duplicate_priority":
			rows = append(rows, rule("deny", 1))
		case "disabled":
			r["disabled"] = true
		}
		got, _ := effectivePolicyCandidates([]any{Object{"type": "NETWORK", "rules": rows}}, "projects/demo/global/networks/default")
		if len(got) != 0 {
			t.Fatal(mode, got)
		}
	}
}
