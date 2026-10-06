package inventory

import (
	"encoding/json"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/secretmatch"
)

// Compiled config values are inspected in memory; neither paths, provider
// names, backend URLs nor matched values leave this function. SourceInfo is
// deliberately outside this compiled-configuration inspection.
func projectServiceManagementSecrets(raw Object) ([]any, error) {
	selected := Object{}
	for _, key := range []string{"authentication", "backend", "http", "usage"} {
		if value, ok := raw[key]; ok {
			selected[key] = value
		}
	}
	data, err := json.Marshal(selected)
	if err != nil {
		return nil, fmt.Errorf("compiled configuration could not be inspected for credential candidates")
	}
	if len(data) > 4<<20 {
		return nil, fmt.Errorf("compiled configuration exceeds credential inspection limit")
	}
	out := []any{}
	for _, hit := range secretmatch.Text(data, "") {
		out = append(out, Object{"rule": hit.Rule})
	}
	return out, nil
}
