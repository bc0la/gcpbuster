package inventory

import (
	"fmt"
	"strings"
)

// SQL flags are API-visible startup settings, not database rows or passwords.
// Replica credentials are explicitly not stored in instance metadata and are
// never treated as obtainable merely because the schema has input fields.
func (c *SecretCapture) captureSQLFlags(a Asset) {
	if c == nil {
		return
	}
	rows, _ := Get(a.Resource.Data, "settings", "databaseFlags").([]any)
	for i, row := range rows {
		d := Obj(row)
		name, nok := d["name"].(string)
		value, vok := d["value"].(string)
		if nok && vok && name != "" && value != "" && value != "[REDACTED]" {
			c.Add(SecretSample{SourceType: "sql_database_flags", Resource: a.Name, Location: a.Resource.Location, Path: fmt.Sprintf("settings.databaseFlags[%d].value", i), Data: []byte(name + "=" + value)})
		}
	}
}

func (c *SecretCapture) captureOfflineSQLFlags(a Asset) bool {
	if a.Type != "sqladmin.googleapis.com/Instance" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(a.Name, "//"), "/")
	if strings.HasPrefix(a.Name, "//") && len(parts) == 5 && parts[0] == "cloudsql.googleapis.com" && parts[1] == "projects" && viewerResourceName.MatchString(parts[2]) && parts[3] == "instances" && viewerResourceName.MatchString(parts[4]) {
		c.captureSQLFlags(a)
	}
	return true
}
