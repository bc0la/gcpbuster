package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"time"
)

// This is an operator-normalized offline schema, not a Google API response.
// schemaVersion:1; sharing:PUBLIC_ON_WEB|ANYONE_WITH_LINK|RESTRICTED;
// dataSources:[{credentialMode:OWNER|SERVICE_ACCOUNT|VIEWER}]. No credentials.
var lookerOfflineName = regexp.MustCompile(`^workspace/lookerStudioReports/[A-Za-z0-9_-]{1,128}$`)

func lookerStudioSharing(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "workspace.googleapis.com/LookerStudioReport" || !lookerOfflineName.MatchString(a.Name) {
		return nil
	}
	version, ok := gatewaySecretInteger(val(a, "schemaVersion"))
	if !ok || version != 1 {
		return nil
	}
	sharing := s(val(a, "sharing"))
	if sharing != "PUBLIC_ON_WEB" && sharing != "ANYONE_WITH_LINK" {
		return nil
	}
	out := result("info", "Supplied Looker Studio report metadata declares public sharing", "Review intended report visibility and every linked or embedded data source's credentials; restrict sharing if unintended.", inventory.Object{"sharing": sharing, "evidence_source": "operator_supplied_offline_v1", "assessment": "Report-sharing configuration only, not a live API result or proof of accessible underlying data. Report structure may be publicly visible; viewer authentication, connector constraints, row filters and data-source authorization can restrict rendered data. No report, connector or data source was fetched."})
	for index, raw := range arr(val(a, "dataSources")) {
		mode := s(obj(raw)["credentialMode"])
		if mode != "OWNER" && mode != "SERVICE_ACCOUNT" {
			continue
		}
		out = append(out, result("medium", "Publicly shared report declares delegated data-source credentials", "Review the data rendered by this source and whether delegated credentials are appropriate for the report's audience. Use viewer credentials where supported and required.", inventory.Object{"sharing": sharing, "data_source_index": index, "credential_mode": mode, "evidence_source": "operator_supplied_offline_v1", "assessment": "Configured credential delegation can render permitted source data to report viewers without their own direct source credentials. This is not an IAM bypass, proof of live data disclosure or access to every underlying row. Viewer-credential sources instead require viewer source authorization; missing or unknown modes are not assumed delegated. No credential values or source data were collected."})...)
	}
	return out
}
