package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"regexp"
	"strings"
	"time"
)

var serverlessGrantResource = regexp.MustCompile(`^//(run|cloudfunctions)\.googleapis\.com/projects/[A-Za-z0-9][A-Za-z0-9._:-]*/locations/[a-z][a-z0-9-]*/(services|functions)/[A-Za-z0-9][A-Za-z0-9_-]*$`)

func publicServerlessInvocation(a inventory.Asset, _ time.Time) []Result {
	if a.Type != inventory.PermissionGrantType {
		return nil
	}
	if s(val(a, "resourceType")) == "cloudresourcemanager.googleapis.com/Project" {
		return projectPublicCapability(a, []string{"run.routes.invoke", "cloudfunctions.functions.invoke"}, "Serverless invocation", "Project-level invocation grant only. Applicable services/functions, inheritance and HTTP triggers remain unverified. First-generation functions.invoke does not establish access to a second-generation function; its underlying Run service requires run.routes.invoke. Ingress, IAP and application authentication can still restrict access. allAuthenticatedUsers requires an accepted Google identity; neither broad principal alone proves successful anonymous invocation. No workload was invoked or endpoint probed.")
	}
	m := serverlessGrantResource.FindStringSubmatch(s(val(a, "resource")))
	if m == nil {
		return nil
	}
	permission, kind := "", ""
	typ := s(val(a, "resourceType"))
	if m[1] == "run" && m[2] == "services" && typ == "run.googleapis.com/Service" {
		permission, kind = "run.routes.invoke", "Cloud Run service"
	}
	if m[1] == "cloudfunctions" && m[2] == "functions" && typ == "cloudfunctions.googleapis.com/CloudFunction" {
		permission, kind = "cloudfunctions.functions.invoke", "first-generation Cloud Function"
	}
	if permission == "" || !has(arr(val(a, "permissions")), permission) {
		return nil
	}
	principal := s(val(a, "principal"))
	if !public(principal) {
		return nil
	}
	audience := "all users"
	if principal == "allAuthenticatedUsers" {
		audience = "any Google-authenticated identity"
	}
	severity, conditionStatus := "high", "no condition supplied on this binding"
	if condition := val(a, "condition"); condition != nil {
		severity, conditionStatus = "medium", "condition supplied; expression was not evaluated"
		if strings.TrimSpace(s(obj(condition)["expression"])) == "" {
			conditionStatus = "malformed condition evidence; applicability unknown"
		}
	}
	assessment := "Configured direct resource binding resolved from role definitions only, not proof of anonymous invocation or internet reachability. allAuthenticatedUsers requires an accepted Google identity. IAM deny, conditions, ingress, IAP and application authentication remain unverified. No endpoint requests or invocations occurred. Inherited grants are not expanded."
	context := inventory.Object{"status": "not_correlated"}
	if c := obj(val(a, "_gcpbusterServerlessContext")); c["resource"] == val(a, "resource") && c["resource_type"] == typ && c["status"] == "observed" {
		context = inventory.Object{"status": "observed", "http_trigger": "unknown", "ingress": "unknown"}
		if trigger := s(c["http_trigger"]); (kind == "Cloud Run service" && trigger == "service_configuration") || (kind == "first-generation Cloud Function" && (trigger == "http_configuration" || trigger == "event_driven_configuration")) {
			context["http_trigger"] = trigger
		}
		if ingress := s(c["ingress"]); (kind == "Cloud Run service" && (ingress == "INGRESS_TRAFFIC_ALL" || ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" || ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER")) || (kind == "first-generation Cloud Function" && (ingress == "ALLOW_ALL" || ingress == "ALLOW_INTERNAL_ONLY" || ingress == "ALLOW_INTERNAL_AND_GCLB")) {
			context["ingress"] = ingress
		}
		for _, key := range []string{"invokerIamDisabled", "iapEnabled"} {
			if flag, ok := c[key].(bool); ok && kind == "Cloud Run service" {
				context[key] = flag
			}
		}
		assessment += " Exact same-resource current configuration is supplied separately in invocation_context; it is not an effective conjunction or route decision. Internal/load-balancer admission, public ingress, invoker bypass and IAP configuration are independent of app authentication."
		if context["http_trigger"] == "event_driven_configuration" {
			severity = "info"
			assessment += " This first-generation function is explicitly event-driven in the observed metadata; the invoker binding is residual configuration review, not HTTP exposure evidence."
		}
	}
	if kind == "first-generation Cloud Function" {
		assessment += " This permission applies to HTTP invocation; HTTP-trigger presence is not established by this role-derived record. Event-driven functions are not publicly HTTP-invocable on this evidence. Second-generation functions require evaluation of their underlying Cloud Run service IAM, not a first-generation invoker grant."
	}
	return result(severity, kind+" grants invocation capability to "+audience, "Review whether the broad invoker grant is intentional, together with the HTTP trigger, ingress and application authentication. Remove unintended public bindings without invoking the workload to test them.", inventory.Object{"resource": val(a, "resource"), "resource_type": typ, "principal": principal, "roles": val(a, "roles"), "permission": permission, "condition": val(a, "condition"), "condition_status": conditionStatus, "invocation_context": context, "assessment": assessment})
}
