package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"time"
)

// Current configuration indicators only. No historical change, actor, intent,
// missing messages or security-pipeline dependency is inferred.
// https://docs.cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions
func pubsubSubscriptionState(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "pubsub.googleapis.com/Subscription" {
		return nil
	}
	var out []Result
	if detached, known := val(a, "detached").(bool); known && detached {
		out = append(out, result("medium", "Pub/Sub subscription is detached", "Confirm that detachment is intentional and review dependent consumers. The assessment does not reattach, recreate or exercise subscriptions.", inventory.Object{"detached": true, "assessment": "The API reports a detached subscription. Detached subscriptions do not receive topic messages or retain a backlog. This is current metadata, not proof of malicious detachment, a historical event, lost messages or a disrupted security pipeline."})...)
	}
	if topic, known := val(a, "topic").(string); known && topic == "_deleted-topic_" {
		out = append(out, result("medium", "Pub/Sub subscription references a deleted topic", "Review whether the orphaned subscription and its dependent consumers are still needed. Do not treat absence from a topic inventory as equivalent evidence of deletion.", inventory.Object{"topic": topic, "assessment": "The subscription explicitly returns the provider's deleted-topic marker. The actor, deletion time, intent, backlog state and actual business or security impact are unknown. No messages were inspected."})...)
	}
	return out
}
