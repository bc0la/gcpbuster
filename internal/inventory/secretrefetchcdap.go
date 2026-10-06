package inventory

import (
	"net/url"
	"regexp"
	"strings"
)

// DataFusionManualRefetchURL validates metadata provenance for report text
// only. It is NOT a client binding, an authorization proof or a network request
// capability. Live CDAP transport still requires a freshly fetched instance
// detail and the private client-specific cdapBinding. Offline metadata does not
// gain that capability by passing this structural validator.
func DataFusionManualRefetchURL(sample SecretSample, assets []Asset) string {
	kind, collection := DataFusionConnectionType, "connections"
	if sample.SourceType == "datafusion_pipeline_config" {
		kind = DataFusionPipelineType
		collection = "pipelines"
	} else if sample.SourceType != "datafusion_connection_config" {
		return ""
	}
	p := regexp.MustCompile(`^//datafusion\.googleapis\.com/(projects/[0-9]+/locations/([a-z][a-z0-9-]*)/instances/[A-Za-z0-9_-]+)/namespaces/([A-Za-z0-9_-]+)/` + collection + `/([A-Za-z0-9_-]+)$`).FindStringSubmatch(sample.Resource)
	if len(p) != 5 || sample.Location != "" && sample.Location != p[2] {
		return ""
	}
	endpoint := ""
	for _, asset := range assets {
		if asset.Name != sample.Resource || asset.Type != kind {
			continue
		}
		d := asset.Resource.Data
		if Str(d["name"]) != sample.Resource || Str(d["instance"]) != p[1] || Str(d["namespace"]) != p[3] || asset.Resource.Location != p[2] {
			return ""
		}
		u, err := url.Parse(Str(d["apiEndpoint"]))
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || !cdapHost.MatchString(u.Host) || u.Path != "/api" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
			return ""
		}
		if endpoint != "" && endpoint != u.String() {
			return ""
		}
		endpoint = u.String()
	}
	if endpoint == "" {
		return ""
	}
	path := "/v3/namespaces/" + p[3] + "/apps/" + p[4]
	if collection == "connections" {
		path = "/v3/namespaces/system/apps/pipeline/services/studio/methods/v1/contexts/" + p[3] + "/connections"
	}
	// All IDs are strict ASCII tokens. No user-selected host, URL references,
	// secure-key, runtime/action, connection validation or redirect path accepted.
	return strings.TrimSuffix(endpoint, "/") + path
}
