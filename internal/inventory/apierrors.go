package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const apiErrorInspectLimit = 16 << 10

// Only fixed, reviewed machine identifiers may enter diagnostics. Messages,
// metadata, localized details, URLs, and unknown reasons never leave the parser.
func safeAPIErrorReason(body []byte) string {
	if len(body) > apiErrorInspectLimit {
		return ""
	}
	var envelope struct {
		Error struct {
			Details []struct {
				Type   string `json:"@type"`
				Reason string `json:"reason"`
				Domain string `json:"domain"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	reason := ""
	for _, detail := range envelope.Error.Details {
		if detail.Type != "type.googleapis.com/google.rpc.ErrorInfo" {
			continue
		}
		switch detail.Domain {
		case "googleapis.com", "iam.googleapis.com", "cloudbuild.googleapis.com", "serviceusage.googleapis.com":
		default:
			continue
		}
		switch detail.Reason {
		case "SERVICE_DISABLED", "IAM_PERMISSION_DENIED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "SECURITY_POLICY_VIOLATED", "RATE_LIMIT_EXCEEDED", "QUOTA_EXCEEDED", "RESOURCE_QUOTA_EXCEEDED", "RATE_LIMITED", "USER_PROJECT_DENIED", "BILLING_DISABLED", "ACCESS_TOKEN_EXPIRED", "ACCESS_TOKEN_INVALID":
		default:
			continue
		}
		if reason != "" && reason != detail.Reason {
			return ""
		} // Conflicting identifiers are unknown.
		reason = detail.Reason
	}
	return reason
}

type diagnosticResponseBody struct {
	io.Reader
	io.Closer
	reason string
}

// Inspect a bounded error prefix, then restore the complete stream for existing
// callers. Successful responses are untouched; original Close is preserved.
func inspectAPIErrorResponse(resp *http.Response) string {
	if resp == nil || resp.StatusCode < 400 || resp.Body == nil {
		return ""
	}
	if body, ok := resp.Body.(*diagnosticResponseBody); ok {
		return body.reason
	}
	original := resp.Body
	prefix, err := io.ReadAll(io.LimitReader(original, apiErrorInspectLimit+1))
	reason := ""
	if err == nil {
		reason = safeAPIErrorReason(prefix)
	}
	resp.Body = &diagnosticResponseBody{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original, reason: reason}
	return reason
}

func safeHTTPFailure(resp *http.Response) string {
	text := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if body, ok := resp.Body.(*diagnosticResponseBody); ok && body.reason != "" {
		text += " (" + body.reason + ")"
	}
	return text
}
