package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

func memorystoreAuthentication(a inventory.Asset, _ time.Time) []Result {
	evidence := inventory.Object{}
	switch a.Type {
	case "redis.googleapis.com/Instance":
		if !isFalse(val(a, "authEnabled")) {
			return nil
		}
		evidence["auth_enabled"] = false
		evidence["product"] = "redis_instance"
	case "redis.googleapis.com/Cluster":
		if s(val(a, "authorizationMode")) != "AUTH_MODE_DISABLED" {
			return nil
		}
		evidence["authorization_mode"] = "AUTH_MODE_DISABLED"
		evidence["product"] = "redis_cluster"
	default:
		return nil
	}
	evidence["assessment"] = "Explicit authentication configuration only. Memorystore private networking, client reachability, runtime state and data access are not established; no credentials were retrieved or Redis connections attempted. Missing fields are not treated as disabled."
	return result("medium", "Memorystore Redis authentication is explicitly disabled", "Review whether Redis authentication is required for trusted-network clients and configure a supported authentication mode. Validate private network access separately.", evidence)
}

func memorystoreTransport(a inventory.Asset, _ time.Time) []Result {
	mode := s(val(a, "transitEncryptionMode"))
	product := ""
	switch a.Type {
	case "redis.googleapis.com/Instance":
		if mode != "DISABLED" {
			return nil
		}
		product = "redis_instance"
	case "redis.googleapis.com/Cluster":
		if mode != "TRANSIT_ENCRYPTION_MODE_DISABLED" {
			return nil
		}
		product = "redis_cluster"
	default:
		return nil
	}
	return result("medium", "Memorystore Redis in-transit encryption is explicitly disabled", "Review client confidentiality requirements and plan supported TLS configuration or migration with compatible clients. Private addressing alone does not provide application-layer transport encryption.", inventory.Object{"product": product, "transit_encryption_mode": mode, "assessment": "Explicit client transport configuration only. This does not establish public exposure, interception, credential disclosure or client connectivity; no endpoint connection, credential retrieval or traffic capture occurred."})
}
