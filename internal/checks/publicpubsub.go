package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var pubsubGrantResource = regexp.MustCompile(`^//pubsub\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/(topics|subscriptions)/[A-Za-z][A-Za-z0-9._~+%-]*$`)

// publicPubSubCapabilities reports configured direct grants, never a successful
// publish, subscription creation or message read. Permissions are resource-specific.
// https://docs.cloud.google.com/pubsub/docs/access-control
func publicPubSubCapabilities(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType {
		return nil
	}
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"pubsub.topics.publish", "pubsub.topics.attachSubscription", "pubsub.subscriptions.consume"}, "Pub/Sub messaging", "Project-level messaging permission only; applicable topics/subscriptions, inheritance and effective controls must be assessed separately. Subscription attachment alone is not creation or consumption. Pub/Sub requires accepted Google authentication; no messages or subscriptions were created, read or changed.")
	}
	m := pubsubGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if m == nil {
		return nil
	}
	typ := s(val(a, "resourceType"))
	if (m[1] == "topics" && typ != "pubsub.googleapis.com/Topic") || (m[1] == "subscriptions" && typ != "pubsub.googleapis.com/Subscription") {
		return nil
	}
	principal := s(val(a, "principal"))
	if principal != "allUsers" && principal != "allAuthenticatedUsers" {
		return nil
	}
	audience := "all users"
	if principal == "allAuthenticatedUsers" {
		audience = "any Google-authenticated identity"
	}
	conditionStatus := "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		conditionStatus = "condition supplied; expression was not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			conditionStatus = "malformed condition evidence; applicability unknown"
		}
	}
	allowed := map[string]string{}
	if m[1] == "topics" {
		allowed["pubsub.topics.publish"] = "publish"
		allowed["pubsub.topics.attachSubscription"] = "attach-subscription"
	} else {
		allowed["pubsub.subscriptions.consume"] = "consume"
	}
	seen := map[string]bool{}
	out := []Result{}
	for _, raw := range arr(val(a, "permissions")) {
		permission := s(raw)
		capability := allowed[permission]
		if capability == "" || seen[permission] {
			continue
		}
		seen[permission] = true
		assessment := "Configured direct binding resolved from role definitions only; effective authorization, deny, conditions and service perimeter are not evaluated. No messages were published, pulled, acknowledged or read and no subscription was created. Inherited grants are not expanded. Broad IAM principals do not prove anonymous API access or sensitive message availability."
		if capability == "attach-subscription" {
			assessment += " Attachment permission on a topic alone does not establish subscription creation or consumption: creation also needs pubsub.subscriptions.create on the containing project, and message consumption needs authorization on the subscription."
		}
		out = append(out, result("medium", "Pub/Sub resource grants "+capability+" capability to "+audience, "Review whether broad messaging grants are intentional. Restrict unneeded bindings after evaluating conditions and service-specific controls; do not exercise the capability as a test.", inventory.Object{"resource": val(a, "resource"), "resource_type": typ, "principal": principal, "roles": val(a, "roles"), "permission": permission, "capability": capability, "condition": val(a, "condition"), "condition_status": conditionStatus, "assessment": assessment, "observed_subscription_context": pubsubDeliveryEvidence(a)})...)
	}
	return out
}
