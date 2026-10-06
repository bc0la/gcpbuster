package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

// Get/ListParameterVersions and RenderParameterVersion are DATA_READ methods.
// This checks supplied policy configuration only: it never renders parameters,
// reads private audit log entries, or resolves embedded Secret Manager values.
// https://docs.cloud.google.com/secret-manager/parameter-manager/docs/audit-logging
func parameterManagerAudit(a inventory.Asset, _ time.Time) []Result {
	out := serviceReadAudit(a, "parametermanager.googleapis.com", "Parameter Manager", []string{"DATA_READ"}, map[string]string{"DATA_READ": "raw version reads and server-side parameter rendering"})
	for i := range out {
		out[i].Evidence["methods"] = []string{"GetParameterVersion", "ListParameterVersions", "RenderParameterVersion"}
		out[i].Evidence["render_performed"] = false
		out[i].Evidence["reference_resolution_performed"] = false
		out[i].Evidence["attribution_limit"] = "Secret Manager audit logs alone can attribute delegated reads to the parameter identity, not the rendering caller. Configured audit enablement is not proof that logs were generated, delivered or retained; render authorization, references, identity grants, conditions and effective access are not evaluated."
	}
	return out
}
