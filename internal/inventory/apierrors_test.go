package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func errorInfoFixture(reason string) string {
	return `{"error":{"code":403,"message":"PRIVATE_MESSAGE","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"` + reason + `","domain":"googleapis.com","metadata":{"permission":"PRIVATE_PERMISSION","resource":"PRIVATE_RESOURCE","token":"PRIVATE_TOKEN"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","message":"PRIVATE_LOCALIZED"}]}}`
}

func TestSafeAPIErrorReasonAllowlist(t *testing.T) {
	for _, reason := range []string{"SERVICE_DISABLED", "IAM_PERMISSION_DENIED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "SECURITY_POLICY_VIOLATED", "RATE_LIMIT_EXCEEDED", "QUOTA_EXCEEDED"} {
		if got := safeAPIErrorReason([]byte(errorInfoFixture(reason))); got != reason {
			t.Fatal(reason, got)
		}
	}
	for _, body := range []string{
		errorInfoFixture("PRIVATE_REASON"),
		strings.ReplaceAll(errorInfoFixture("SERVICE_DISABLED"), "googleapis.com", "PRIVATE_DOMAIN"),
		strings.ReplaceAll(errorInfoFixture("SERVICE_DISABLED"), "google.rpc.ErrorInfo", "PRIVATE_TYPE"),
		`{"error":{"message":"SERVICE_DISABLED PRIVATE_MESSAGE"}}`,
		`not json PRIVATE_MESSAGE`,
		errorInfoFixture("SERVICE_DISABLED") + strings.Repeat(" ", apiErrorInspectLimit),
		`{"error":{"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED","domain":"googleapis.com"},{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"IAM_PERMISSION_DENIED","domain":"googleapis.com"}]}}`,
	} {
		if got := safeAPIErrorReason([]byte(body)); got != "" {
			t.Fatal(got)
		}
	}
}

func TestErrorInspectionPreservesCompleteResponseAndClose(t *testing.T) {
	for _, body := range []string{errorInfoFixture("SERVICE_DISABLED"), strings.Repeat("PRIVATE", apiErrorInspectLimit)} {
		original := &trackingErrorBody{Reader: strings.NewReader(body)}
		resp := &http.Response{StatusCode: 403, Body: original}
		inspectAPIErrorResponse(resp)
		got, err := io.ReadAll(resp.Body)
		if err != nil || string(got) != body {
			t.Fatal(len(got), err)
		}
		resp.Body.Close()
		if !original.closed {
			t.Fatal("original body not closed")
		}
	}
}

type trackingErrorBody struct {
	io.Reader
	closed bool
}

func (b *trackingErrorBody) Close() error { b.closed = true; return nil }

func TestCloudBuild403DiagnosticsExposeOnlyMachineReason(t *testing.T) {
	for _, reason := range []string{"SERVICE_DISABLED", "IAM_PERMISSION_DENIED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "SECURITY_POLICY_VIOLATED", "PRIVATE_REASON"} {
		c := testClient(t, func(*http.Request) (*http.Response, error) { return response(403, errorInfoFixture(reason)), nil })
		c.viewerPolicy.permissions = map[string]bool{"cloudbuild.builds.list": true}
		var events []ProgressEvent
		c.Progress = func(e ProgressEvent) { events = append(events, e) }
		_, err := c.get(context.Background(), "https://cloudbuild.googleapis.com/v1/projects/demo/locations/global/builds", url.Values{"fields": {"builds(" + secretCaptureBuildFields + "),nextPageToken"}})
		if err == nil {
			t.Fatal("403 accepted")
		}
		encoded, _ := json.Marshal(events)
		if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal(err, string(encoded))
		}
		if reason != "PRIVATE_REASON" && (!strings.Contains(err.Error(), reason) || events[len(events)-1].Reason != reason) {
			t.Fatal(err, events)
		}
	}
}
