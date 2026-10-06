package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func publicGKE(a inventory.Asset, _ time.Time) []Result {
	out := gkeIPEndpoint(a)
	dns := obj(val(a, "controlPlaneEndpointsConfig", "dnsEndpointConfig"))
	if b(dns["allowExternalTraffic"]) {
		out = append(out, Result{"info", "GKE DNS control-plane endpoint permits user traffic", inventory.Object{"endpoint": dns["endpoint"], "kubernetes_token_auth": dns["enableK8sTokensViaDns"], "kubernetes_certificate_auth": dns["enableK8sCertsViaDns"], "assessment": "Internet-addressable DNS endpoint configuration, not unauthenticated access. IAM, Kubernetes authorization and perimeter controls still apply."}, "Validate intended DNS endpoint access, IAM permissions, optional Kubernetes authentication methods and VPC Service Controls."})
	}
	return out
}

func gkeKubelet(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	add := func(where string, value any) {
		if !b(value) {
			return
		}
		out = append(out, Result{"high", "GKE configuration enables the unauthenticated kubelet read-only port", inventory.Object{"configuration_scope": where, "port": 10255, "assessment": "Configuration indicator only; node reachability and running-node rollout are not tested. New-node defaults do not establish the state of existing pools."}, "Disable the insecure read-only port after migrating consumers to authenticated APIs; verify every node pool and applicable network controls."})
	}
	add("cluster node-pool defaults", val(a, "nodePoolDefaults", "nodeConfigDefaults", "nodeKubeletConfig", "insecureKubeletReadonlyPortEnabled"))
	for _, raw := range arr(val(a, "nodePools")) {
		p := obj(raw)
		add("node pool "+s(p["name"]), inventory.Get(p, "config", "kubeletConfig", "insecureKubeletReadonlyPortEnabled"))
	}
	// nodeConfig is the deprecated default-pool configuration. Inspect it only
	// when no explicit pool list is supplied, avoiding contradictory duplicate claims.
	if len(arr(val(a, "nodePools"))) == 0 {
		add("legacy cluster nodeConfig", val(a, "nodeConfig", "kubeletConfig", "insecureKubeletReadonlyPortEnabled"))
	}
	return out
}

func gkeTelemetry(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	for _, kind := range []string{"logging", "monitoring"} {
		components, explicit := val(a, kind+"Config", "componentConfig", "enableComponents").([]any)
		if explicit {
			valid := true
			for _, component := range components {
				text, ok := component.(string)
				if !ok || text == "" || text == "COMPONENT_UNSPECIFIED" {
					valid = false
				}
			}
			if !valid {
				continue
			}
		}
		legacyDisabled := s(val(a, kind+"Service")) == "none"
		if (explicit && len(components) == 0) || (!explicit && legacyDisabled) {
			out = append(out, Result{"medium", "GKE operational " + kind + " is explicitly disabled", inventory.Object{"service": kind, "assessment": "Operational telemetry only; Kubernetes/Google Cloud Admin Activity audit logs are separate and are not disabled by this setting. Third-party collection may exist."}, "Verify intended telemetry coverage and independent collectors; enable required operational streams and alert on unauthorized configuration changes."})
			continue
		}
		if kind == "logging" && explicit && len(components) > 0 && !has(components, "WORKLOADS") {
			out = append(out, Result{"medium", "GKE workload logging is omitted from the configured component set", inventory.Object{"enabled_components": components, "assessment": "Container stdout/stderr collection is not selected here; this does not establish an absence of independent collectors or audit logs."}, "Verify whether workload logs are captured elsewhere or enable WORKLOADS logging according to the detection requirements."})
		}
	}
	return out
}
