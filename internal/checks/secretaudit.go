package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"sort"
	"time"
)

// secretManagerAudit consumes resolved policy evidence, not log entries.
// Secret Manager metadata reads use ADMIN_READ; AccessSecretVersion uses
// DATA_READ. Both are Data Access classes, not always-on Admin Activity.
// https://docs.cloud.google.com/secret-manager/docs/audit-logging
// https://docs.cloud.google.com/logging/docs/audit/configure-data-access
func secretManagerAudit(a inventory.Asset, _ time.Time) []Result {
	return serviceReadAudit(a, "secretmanager.googleapis.com", "Secret Manager", []string{"ADMIN_READ", "DATA_READ"}, map[string]string{"ADMIN_READ": "metadata reads", "DATA_READ": "secret payload access"})
}

// Service evaluators consume the same inherited policy union, never log payloads.
func serviceReadAudit(a inventory.Asset, serviceName, serviceTitle string, classes []string, purposes map[string]string) []Result {
	complete, ok := val(a, "complete").(bool)
	complete = ok && complete
	rows, valid := val(a, "configs").([]any)
	if !valid {
		return nil // Missing/malformed derived evidence is not disabled logging.
	}
	enabled := map[string]bool{}
	exemptions := map[string]map[string]bool{}
	requested := map[string]bool{}
	for _, typ := range classes {
		if typ != "ADMIN_READ" && typ != "DATA_READ" && typ != "DATA_WRITE" {
			return nil
		}
		requested[typ] = true
		exemptions[typ] = map[string]bool{}
	}
	for _, raw := range rows {
		row := obj(raw)
		service, serviceOK := row["service"].(string)
		typ, typeOK := row["logType"].(string)
		if !serviceOK || service == "" || !typeOK || (typ != "ADMIN_READ" && typ != "DATA_READ" && typ != "DATA_WRITE") {
			complete = false
			continue
		}
		if service != "allServices" && service != serviceName {
			continue
		}
		if !requested[typ] {
			continue
		}
		enabled[typ] = true
		if value, exists := row["exemptedMembers"]; exists {
			members, ok := value.([]any)
			if !ok {
				complete = false
				continue
			}
			for _, rawMember := range members {
				member, ok := rawMember.(string)
				if !ok || member == "" {
					complete = false
					continue
				}
				exemptions[typ][member] = true
			}
		}
	}
	var out []Result
	for _, typ := range classes {
		purpose := purposes[typ]
		if complete && !enabled[typ] {
			out = append(out, Result{"medium", serviceTitle + " " + typ + " audit logging is not enabled in the complete supplied policy chain", inventory.Object{"service": serviceName, "log_type": typ, "operation_class": purpose, "complete_policy_chain": true, "assessment": "Policy configuration only; allServices and service-specific settings were unioned. Log delivery, retention and actual operation history were not tested."}, "Review whether " + serviceTitle + " " + purpose + " should emit Data Access audit logs; configure the relevant audit class through your normal change process."})
		}
		if len(exemptions[typ]) > 0 {
			members := make([]string, 0, len(exemptions[typ]))
			for member := range exemptions[typ] {
				members = append(members, member)
			}
			sort.Strings(members)
			out = append(out, Result{"medium", serviceTitle + " " + typ + " audit policy exempts principals", inventory.Object{"service": serviceName, "log_type": typ, "operation_class": purpose, "members": members, "complete_policy_chain": complete, "assessment": "Known exemptions unioned from allServices and service-specific settings. Incomplete evidence can omit additional exemptions; group membership, actual logging, delivery and retention were not tested."}, "Review the listed principal exemptions for " + serviceTitle + " " + purpose + "."})
		}
	}
	return out
}
