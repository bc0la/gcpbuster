package checks

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFirewallIngressWorldSourcesAndOR(t *testing.T) {
	for _, tc := range []struct {
		fields string
		want   int
		world  string
	}{
		{``, 1, "0.0.0.0/0"},
		{`"sourceRanges":[],"sourceTags":[],`, 1, "0.0.0.0/0"},
		{`"sourceRanges":["0:0:0:0:0:0:0:0/0"],`, 1, "::/0"},
		{`"sourceRanges":["0.0.0.0/0"],"sourceTags":["trusted"],"targetTags":["web"],`, 1, "0.0.0.0/0"},
		{`"sourceRanges":["0.0.0.0/0"],"sourceServiceAccounts":["sa@example.com"],"targetServiceAccounts":["target@example.com"],`, 1, "0.0.0.0/0"},
		{`"sourceTags":["trusted"],`, 0, ""},
		{`"sourceServiceAccounts":["sa@example.com"],`, 0, ""},
		{`"sourceRanges":["10.0.0.0/8"],`, 0, ""},
		{`"sourceRanges":["0.0.0.0/0"],"destinationRanges":["10.0.0.0/8"],`, 1, "0.0.0.0/0"},
	} {
		a := asset("compute.googleapis.com/Firewall", `{`+tc.fields+`"allowed":[{"IPProtocol":"tcp","ports":["443"]}]}`)
		got := firewallIngress(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && (!strings.Contains(fmt.Sprint(got[0].Evidence["world_source_ranges"]), tc.world) || !strings.Contains(s(got[0].Evidence["assessment"]), "not a reachability test")) {
			t.Fatal(got)
		}
	}
}

func TestFirewallIngressMalformedIsNotDefaultWorld(t *testing.T) {
	for _, fields := range []string{
		`"disabled":"false",`, `"disabled":null,`, `"disabled":true,`, `"direction":false,`, `"direction":"",`, `"direction":"UNKNOWN",`, `"direction":"EGRESS",`,
		`"sourceRanges":null,`, `"sourceRanges":{},`, `"sourceRanges":[42],`, `"sourceRanges":["garbage"],`, `"sourceRanges":["0.0.0.0/0","bad"],`,
		`"sourceTags":"web",`, `"sourceServiceAccounts":[false],`, `"targetTags":null,`, `"destinationRanges":["bad"],`,
		`"sourceRanges":["0.0.0.0/0"],"destinationRanges":["::/0"],`,
		`"sourceRanges":["0.0.0.0/0","::/0"],`, `"destinationRanges":["::/0"],`,
		`"sourceRanges":["0.0.0.0/0"],"sourceTags":["web"],"targetServiceAccounts":["sa@example.com"],`,
		`"sourceRanges":["0.0.0.0/0"],"sourceServiceAccounts":["sa@example.com"],"targetTags":["web"],`,
		`"priority":"1000",`, `"priority":-1,`, `"priority":65536,`, `"priority":1.5,`, `"denied":[{"IPProtocol":"all"}],`, `"denied":{},`,
	} {
		a := asset("compute.googleapis.com/Firewall", `{`+fields+`"allowed":[{"IPProtocol":"tcp"}]}`)
		if got := firewallIngress(a, time.Now()); len(got) != 0 {
			t.Fatal(fields, got)
		}
	}
	a := asset("compute.googleapis.com/FirewallPolicy", `{"allowed":[{"IPProtocol":"all"}]}`)
	if got := firewallIngress(a, time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestFirewallIngressProtocolPortValidation(t *testing.T) {
	for _, tc := range []struct {
		allowed string
		want    int
	}{
		{`[{"IPProtocol":"all"}]`, 1}, {`[{"IPProtocol":"tcp"}]`, 1}, {`[{"IPProtocol":"udp","ports":["0-65535"]}]`, 1},
		{`[{"IPProtocol":"6","ports":["22","80-443"]}]`, 1}, {`[{"IPProtocol":"17","ports":["65535"]}]`, 1},
		{`[{"IPProtocol":"58"}]`, 1}, {`[{"IPProtocol":"icmp"}]`, 1}, {`[{"IPProtocol":"sctp"}]`, 1},
		{`null`, 0}, {`{}`, 0}, {`[]`, 0}, {`[{}]`, 0}, {`[null]`, 0},
		{`[{"IPProtocol":6}]`, 0}, {`[{"IPProtocol":"unknown"}]`, 0}, {`[{"IPProtocol":"256"}]`, 0},
		{`[{"IPProtocol":"0"}]`, 0},
		{`[{"IPProtocol":"-1"}]`, 0}, {`[{"IPProtocol":"tcp","ports":["-1"]}]`, 0},
		{`[{"IPProtocol":"tcp","ports":["443-80"]}]`, 0}, {`[{"IPProtocol":"tcp","ports":["65536"]}]`, 0},
		{`[{"IPProtocol":"tcp","ports":[80]}]`, 0}, {`[{"IPProtocol":"tcp","ports":null}]`, 0},
		{`[{"IPProtocol":"icmp","ports":["8"]}]`, 0}, {`[{"IPProtocol":"all","ports":["80"]}]`, 0},
		{`[{"IPProtocol":"sctp","ports":["80"]}]`, 0}, {`[{"IPProtocol":"80","ports":["80"]}]`, 0},
	} {
		a := asset("compute.googleapis.com/Firewall", `{"disabled":false,"direction":"INGRESS","priority":1000,"sourceRanges":["0.0.0.0/0"],"allowed":`+tc.allowed+`}`)
		if got := firewallIngress(a, time.Now()); len(got) != tc.want {
			t.Fatal(tc, got)
		}
	}
}
