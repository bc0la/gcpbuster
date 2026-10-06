package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestGKENewMetadataBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		eval       func(inventory.Asset, time.Time) []Result
		want       int
	}{
		{"absent kubelet", `{}`, gkeKubelet, 0},
		{"pool read only", `{"nodePools":[{"name":"p","config":{"kubeletConfig":{"insecureKubeletReadonlyPortEnabled":true}}}]}`, gkeKubelet, 1},
		{"disabled pool", `{"nodePools":[{"config":{"kubeletConfig":{"insecureKubeletReadonlyPortEnabled":false}}}]}`, gkeKubelet, 0},
		{"future pool default", `{"nodePoolDefaults":{"nodeConfigDefaults":{"nodeKubeletConfig":{"insecureKubeletReadonlyPortEnabled":true}}},"nodePools":[{"config":{"kubeletConfig":{"insecureKubeletReadonlyPortEnabled":false}}}]}`, gkeKubelet, 1},
		{"legacy config", `{"nodeConfig":{"kubeletConfig":{"insecureKubeletReadonlyPortEnabled":true}}}`, gkeKubelet, 1},
		{"absent telemetry", `{}`, gkeTelemetry, 0},
		{"legacy disabled", `{"loggingService":"none","monitoringService":"none"}`, gkeTelemetry, 2},
		{"empty component sets", `{"loggingConfig":{"componentConfig":{"enableComponents":[]}},"monitoringConfig":{"componentConfig":{"enableComponents":[]}}}`, gkeTelemetry, 2},
		{"system only", `{"loggingConfig":{"componentConfig":{"enableComponents":["SYSTEM_COMPONENTS"]}}}`, gkeTelemetry, 1},
		{"workload logging", `{"loggingConfig":{"componentConfig":{"enableComponents":["SYSTEM_COMPONENTS","WORKLOADS"]}}}`, gkeTelemetry, 0},
		{"malformed components", `{"loggingConfig":{"componentConfig":{"enableComponents":[null]}}}`, gkeTelemetry, 0},
		{"IP access disabled", `{"endpoint":"192.0.2.1","controlPlaneEndpointsConfig":{"ipEndpointsConfig":{"enabled":false}}}`, publicGKE, 0},
		{"new restricted networks", `{"controlPlaneEndpointsConfig":{"ipEndpointsConfig":{"enabled":true,"enablePublicEndpoint":true,"authorizedNetworksConfig":{"enabled":true,"cidrBlocks":[{"cidrBlock":"192.0.2.0/24"}]}}}}`, publicGKE, 0},
		{"new world networks", `{"controlPlaneEndpointsConfig":{"ipEndpointsConfig":{"enabled":true,"enablePublicEndpoint":true,"authorizedNetworksConfig":{"enabled":true,"cidrBlocks":[{"cidrBlock":"::/0"}]}}}}`, publicGKE, 1},
		{"DNS user traffic", `{"controlPlaneEndpointsConfig":{"ipEndpointsConfig":{"enabled":false},"dnsEndpointConfig":{"allowExternalTraffic":true,"endpoint":"example.gke.goog"}}}`, publicGKE, 1},
		{"DNS address alone", `{"controlPlaneEndpointsConfig":{"dnsEndpointConfig":{"endpoint":"example.gke.goog"}}}`, publicGKE, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.eval(asset("container.googleapis.com/Cluster", tc.data), time.Now()); len(got) != tc.want {
				t.Fatal(got)
			}
		})
	}
}
