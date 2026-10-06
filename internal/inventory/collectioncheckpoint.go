package inventory

import "context"

// CollectionCheckpoint stores reviewed metadata-only collector results. The
// implementation must bind storage to the exact collection configuration and
// protect it with the same private-directory/database rules as the engagement.
// Secrets, transient capture samples and source artifacts are never checkpointed.
type CollectionCheckpoint interface {
	Load(context.Context, string, string) (Snapshot, bool, error)
	Save(context.Context, string, string, Snapshot) error
}

// Explicit positive list: a new collector family never becomes resumable by
// default. Secret-bearing families are deliberately reread on resume so full
// secret values cannot be lost by restoring their redacted inventory alone.
func checkpointFamily(family string) bool {
	switch family {
	case "model-armor", "storage", "redis", "memcache", "alloydb",
		"filestore", "bigtable", "spanner", "firestore", "healthcare",
		"pubsub", "data-identity-config", "service-usage", "federation":
		return true
	}
	return false
}

func checkpointComplete(s Snapshot) bool {
	if len(s.SecretArtifacts) != 0 || len(s.SecretFingerprint) != 0 || s.SecretValueMode != "" {
		return false
	}
	// No coverage is not affirmative proof that a collector completed.
	if len(s.Coverage) == 0 {
		return false
	}
	hasSuccess := false
	for _, row := range s.Coverage {
		if row.Status != "ok" && row.Status != "notice" {
			return false
		}
		hasSuccess = hasSuccess || row.Status == "ok"
	}
	return hasSuccess
}
