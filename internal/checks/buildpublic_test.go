package checks

import (
	"encoding/json"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
	"time"
)

func TestCloudBuildPRCommentControlExplicitGates(t *testing.T) {
	for _, tc := range []struct {
		data     string
		want     int
		severity string
	}{
		{`{}`, 0, ""}, {`{"github":{"pullRequest":{}}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY"}}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_ENABLED"}}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENT_CONTROL_DISABLED"}}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}}}`, 1, "info"},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"approvalConfig":{"approvalRequired":true}}`, 1, "info"},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"approvalConfig":{"approvalRequired":false},"disabled":false}`, 1, "medium"},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"disabled":true}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"disabled":"false"}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"},"push":{}}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"repositoryEventConfig":{}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"eventType":"MANUAL"}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"pubsubConfig":{}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"webhookConfig":{}}`, 0, ""},
		{`{"github":{"pullRequest":{"commentControl":"COMMENTS_DISABLED"}},"triggerTemplate":{}}`, 0, ""},
	} {
		got := cloudBuildPRCommentControl(asset("cloudbuild.googleapis.com/BuildTrigger", tc.data), time.Now())
		if len(got) != tc.want || (len(got) > 0 && got[0].Severity != tc.severity) {
			t.Fatal(tc, got)
		}
	}
}

func TestCloudBuildPRCommentControlFamiliesRedaction(t *testing.T) {
	for _, family := range []string{"github", "repositoryEventConfig", "developerConnectEventConfig", "bitbucketServerTriggerConfig"} {
		a := inventory.NewAsset("trigger", "cloudbuild.googleapis.com/BuildTrigger", inventory.Object{family: inventory.Object{"pullRequest": inventory.Object{"commentControl": "COMMENTS_DISABLED", "branch": "PRIVATE_PATTERN"}, "repository": "PRIVATE_REPOSITORY"}})
		got := cloudBuildPRCommentControl(a, time.Now())
		if len(got) != 1 {
			t.Fatal(family, got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "PRIVATE") {
			t.Fatal(string(b))
		}
		a.Type = "cloudbuild.googleapis.com/Build"
		if len(cloudBuildPRCommentControl(a, time.Now())) != 0 {
			t.Fatal("wrong type")
		}
	}
}
