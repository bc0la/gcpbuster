package checks

import (
	"testing"
	"time"
)

func TestSQLPublicAddressIndicator(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"ipAddresses":[{"type":"PRIMARY","ipAddress":"192.0.2.1"}]}`, 1},
		{`{"ipAddresses":[{"type":"PRIVATE","ipAddress":"10.0.0.1"}]}`, 0},
		{`{"ipAddresses":[{"type":"PRIMARY"}]}`, 0},
		{`{"ipAddresses":[{"type":"PRIMARY","ipAddress":"invalid"}]}`, 0},
		{`{}`, 0},
	} {
		got := publicSQL(asset("sqladmin.googleapis.com/Instance", tc.body), time.Now())
		if len(got) != tc.want {
			t.Fatalf("%s: %+v", tc.body, got)
		}
		if len(got) == 1 && (got[0].Severity != "medium" || got[0].Evidence["assessment"] == nil) {
			t.Fatal(got)
		}
	}
}

func TestSQLPolicyHardeningExplicitEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"mysql-disabled", `{"databaseVersion":"MYSQL_8_0","settings":{"deletionProtectionEnabled":false,"passwordValidationPolicy":{"enablePasswordPolicy":false}}}`, 2},
		{"postgres-disabled", `{"databaseVersion":"POSTGRES_16","settings":{"passwordValidationPolicy":{"enablePasswordPolicy":false}}}`, 1},
		{"sqlserver-no-mysql-policy", `{"databaseVersion":"SQLSERVER_2022_STANDARD","settings":{"deletionProtectionEnabled":false,"passwordValidationPolicy":{"enablePasswordPolicy":false}}}`, 1},
		{"enabled", `{"databaseVersion":"MYSQL_8_0","settings":{"deletionProtectionEnabled":true,"passwordValidationPolicy":{"enablePasswordPolicy":true}}}`, 0},
		{"missing", `{"databaseVersion":"MYSQL_8_0","settings":{}}`, 0},
		{"malformed", `{"databaseVersion":"MYSQL_8_0","settings":{"deletionProtectionEnabled":"false","passwordValidationPolicy":{"enablePasswordPolicy":0}}}`, 0},
		{"unknown-engine", `{"settings":{"passwordValidationPolicy":{"enablePasswordPolicy":false}}}`, 0},
		{"username-not-password-proof", `{"databaseVersion":"MYSQL_8_0","_gcpbusterSQLUsers":[{"name":"root","host":"%"}]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sqlHardening(asset("sqladmin.googleapis.com/Instance", tc.body), time.Now())
			if len(got) != tc.want {
				t.Fatalf("want %d, got %+v", tc.want, got)
			}
			for _, finding := range got {
				if finding.Evidence["assessment"] == nil {
					t.Fatal("missing limitation", finding)
				}
			}
		})
	}
}
