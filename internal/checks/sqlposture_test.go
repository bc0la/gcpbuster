package checks

import (
	"fmt"
	"testing"
	"time"
)

func TestSQLPosturePITREngineAndScope(t *testing.T) {
	for _, tc := range []struct {
		name, engine, kind, backup string
		want                       int
	}{
		{"mysql", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":false`, 1},
		{"postgres", "POSTGRES_16", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","pointInTimeRecoveryEnabled":false`, 1},
		{"sqlserver", "SQLSERVER_2022_STANDARD", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","pointInTimeRecoveryEnabled":false`, 1},
		{"wrong-mysql-field", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","pointInTimeRecoveryEnabled":false`, 0},
		{"wrong-postgres-field", "POSTGRES_16", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":false`, 0},
		{"enhanced", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"ENHANCED","binaryLogEnabled":false`, 0},
		{"deprecated-enhanced", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"ADVANCED","binaryLogEnabled":false`, 0},
		{"unknown-tier", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"binaryLogEnabled":false`, 0},
		{"replica", "MYSQL_8_0", "READ_REPLICA_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":false`, 0},
		{"external", "MYSQL_8_0", "ON_PREMISES_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":false`, 0},
		{"unknown-kind", "MYSQL_8_0", "", `"backupTier":"STANDARD","binaryLogEnabled":false`, 0},
		{"unknown-engine", "MYSQL_bad", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":false`, 0},
		{"enabled", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":true`, 0},
		{"malformed", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD","binaryLogEnabled":"false"`, 0},
		{"missing", "MYSQL_8_0", "CLOUD_SQL_INSTANCE", `"backupTier":"STANDARD"`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"databaseVersion":%q,"instanceType":%q,"settings":{"backupConfiguration":{%s}}}`, tc.engine, tc.kind, tc.backup)
			assertSQLPosture(t, body, tc.want)
		})
	}
}

func TestSQLPostureHARequiresExplicitPrimary(t *testing.T) {
	for _, tc := range []struct {
		name, extra, availability string
		want                      int
	}{
		{"zonal", `"instanceType":"CLOUD_SQL_INSTANCE"`, `"ZONAL"`, 1},
		{"regional", `"instanceType":"CLOUD_SQL_INSTANCE"`, `"REGIONAL"`, 0},
		{"replica", `"instanceType":"READ_REPLICA_INSTANCE"`, `"ZONAL"`, 0},
		{"conflicting-primary", `"instanceType":"CLOUD_SQL_INSTANCE","masterInstanceName":"other"`, `"ZONAL"`, 0},
		{"malformed-parent", `"instanceType":"CLOUD_SQL_INSTANCE","masterInstanceName":false`, `"ZONAL"`, 0},
		{"unknown-type", `"instanceType":null`, `"ZONAL"`, 0},
		{"missing", `"instanceType":"CLOUD_SQL_INSTANCE"`, `null`, 0},
		{"malformed", `"instanceType":"CLOUD_SQL_INSTANCE"`, `false`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSQLPosture(t, fmt.Sprintf(`{"databaseVersion":"POSTGRES_16",%s,"settings":{"availabilityType":%s}}`, tc.extra, tc.availability), tc.want)
		})
	}
}

func TestSQLPosturePasswordFacetsNoInventedThreshold(t *testing.T) {
	for _, tc := range []struct {
		name, engine, policy string
		want                 int
	}{
		{"explicit-facets", "MYSQL_8_0", `"enablePasswordPolicy":true,"disallowUsernameSubstring":false,"reuseInterval":0`, 2},
		{"mysql57-no-reuse", "MYSQL_5_7", `"enablePasswordPolicy":true,"disallowUsernameSubstring":false,"reuseInterval":0`, 1},
		{"positive-controls", "MYSQL_8_0", `"enablePasswordPolicy":true,"disallowUsernameSubstring":true,"reuseInterval":1`, 0},
		{"postgres-outside-source", "POSTGRES_16", `"enablePasswordPolicy":true,"disallowUsernameSubstring":false,"reuseInterval":0`, 0},
		{"disabled-policy", "MYSQL_8_0", `"enablePasswordPolicy":false,"disallowUsernameSubstring":false,"reuseInterval":0`, 0},
		{"missing-enabled", "MYSQL_8_0", `"disallowUsernameSubstring":false,"reuseInterval":0`, 0},
		{"malformed", "MYSQL_8_0", `"enablePasswordPolicy":true,"disallowUsernameSubstring":"false","reuseInterval":"0"`, 0},
		{"fractional", "MYSQL_8_0", `"enablePasswordPolicy":true,"reuseInterval":0.5`, 0},
		{"negative", "MYSQL_8_0", `"enablePasswordPolicy":true,"reuseInterval":-1`, 0},
		{"no-arbitrary-length", "MYSQL_8_0", `"enablePasswordPolicy":true,"minLength":1,"complexity":"COMPLEXITY_UNSPECIFIED"`, 0},
		{"missing-facets", "MYSQL_8_0", `"enablePasswordPolicy":true`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSQLPosture(t, fmt.Sprintf(`{"databaseVersion":%q,"settings":{"passwordValidationPolicy":{%s}}}`, tc.engine, tc.policy), tc.want)
		})
	}
}

func TestSQLPostureIntegratedWithHardening(t *testing.T) {
	a := asset("sqladmin.googleapis.com/Instance", `{"databaseVersion":"MYSQL_8_0","instanceType":"CLOUD_SQL_INSTANCE","settings":{"availabilityType":"ZONAL","backupConfiguration":{"backupTier":"STANDARD","binaryLogEnabled":false},"passwordValidationPolicy":{"enablePasswordPolicy":true,"disallowUsernameSubstring":false,"reuseInterval":0}}}`)
	got := sqlHardening(a, time.Now())
	if len(got) != 4 {
		t.Fatalf("expected four posture signals, got %+v", got)
	}
}

func assertSQLPosture(t *testing.T, body string, want int) {
	t.Helper()
	got := sqlConfigurationPosture(asset("sqladmin.googleapis.com/Instance", body))
	if len(got) != want {
		t.Fatalf("want %d, got %+v", want, got)
	}
	for _, r := range got {
		if r.Severity != "info" || r.Evidence["assessment"] == nil {
			t.Fatalf("unqualified posture claim: %+v", r)
		}
	}
}
