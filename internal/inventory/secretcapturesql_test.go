package inventory

import "testing"

func TestSQLFlagCaptureMetadataOnly(t *testing.T) {
	a := NewAsset("//cloudsql.googleapis.com/projects/123/instances/db", "sqladmin.googleapis.com/Instance", Object{"settings": Object{"databaseFlags": []any{Object{"name": "custom_flag", "value": "STRING_CONFIG"}}}, "replicaConfiguration": Object{"mysqlReplicaConfiguration": Object{"password": "DO_NOT_CAPTURE", "clientKey": "DO_NOT_CAPTURE"}}, "password": "DO_NOT_CAPTURE"})
	c := NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a})
	ss := c.Samples()
	if len(ss) != 1 || string(ss[0].Data) != "custom_flag=STRING_CONFIG" {
		t.Fatal(ss)
	}
	a.Name = "//sqladmin.googleapis.com/projects/123/instances/db"
	c = NewSecretCapture(0, 0, 0)
	c.CaptureInventory([]Asset{a})
	if len(c.Samples()) != 0 {
		t.Fatal("wrong SQL CAI hostname accepted")
	}
}
