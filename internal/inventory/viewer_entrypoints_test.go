package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// This intentionally does not use testClient's synthetic historical collector
// permissions. Each baseline response contains a small, real subset of that
// exact role, and the HTTP transport would happily serve privileged responses
// if an entrypoint failed to enforce the baseline before sending the request.
func restrictedViewerClient(t *testing.T) (*Client, *int, *int) {
	t.Helper()
	t.Setenv("GCPBUSTER_RESTRICTED_TEST_TOKEN", "overprivileged-credential")
	roleCalls, targetCalls := 0, 0
	rolePermissions := map[string][]string{
		"roles/viewer":                             {"compute.projects.get", "resourcemanager.projects.getIamPolicy", "storage.buckets.list", "logging.logEntries.list"},
		"roles/resourcemanager.folderViewer":       {"resourcemanager.folders.get"},
		"roles/resourcemanager.organizationViewer": {"resourcemanager.organizations.get"},
	}
	c := &Client{TokenEnv: "GCPBUSTER_RESTRICTED_TEST_TOKEN", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer overprivileged-credential" {
			t.Fatal("missing expected credential")
		}
		if r.URL.Host == "iam.googleapis.com" && strings.HasPrefix(r.URL.Path, "/v1/roles/") {
			roleCalls++
			role := strings.TrimPrefix(r.URL.Path, "/v1/")
			permissions, ok := rolePermissions[role]
			if !ok || r.Method != http.MethodGet {
				t.Fatalf("unexpected bootstrap %s %s", r.Method, r.URL)
			}
			body, _ := json.Marshal(Object{"name": role, "includedPermissions": permissions})
			return response(200, string(body)), nil
		}
		targetCalls++
		return response(200, `{"bindings":[],"items":[],"entries":[]}`), nil
	})}}
	return c, &roleCalls, &targetCalls
}

func TestViewerRestrictedBaselineBlocksActualHTTPEntrypoints(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name, missingPermission string
		call                    func(*Client) error
	}{
		{"get CAI resource export", "cloudasset.assets.listResource", func(c *Client) error {
			_, err := c.get(ctx, "https://cloudasset.googleapis.com/v1/projects/p/assets", url.Values{"contentType": {"RESOURCE"}})
			return err
		}},
		{"get bucket metadata", "storage.buckets.get", func(c *Client) error {
			_, err := c.get(ctx, "https://storage.googleapis.com/storage/v1/b/bucket", nil)
			return err
		}},
		{"storage object listing", "storage.objects.list", func(c *Client) error {
			_, err := c.storageGET(ctx, "https://storage.googleapis.com/storage/v1/b/bucket/o", true, 1024, "")
			return err
		}},
		{"storage object media", "storage.objects.get", func(c *Client) error {
			_, err := c.storageGET(ctx, "https://storage.googleapis.com/storage/v1/b/bucket/o/object?alt=media&generation=1", true, 1024, "")
			return err
		}},
		{"ancestor folder IAM", "resourcemanager.folders.getIamPolicy", func(c *Client) error {
			_, err := c.readIAMPolicy(ctx, "https://cloudresourcemanager.googleapis.com/v3/folders/1:getIamPolicy")
			return err
		}},
		{"IAP resource IAM", "iap.webServices.getIamPolicy", func(c *Client) error {
			_, err := c.readIAMPolicy(ctx, "https://iap.googleapis.com/v1/projects/1/iap_web/compute/services/backend:getIamPolicy")
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, roles, targets := restrictedViewerClient(t)
			err := tt.call(c)
			if err == nil || !strings.Contains(err.Error(), tt.missingPermission) {
				t.Fatalf("expected denial for %s, got %v", tt.missingPermission, err)
			}
			if *roles != 3 || *targets != 0 {
				t.Fatalf("HTTP bootstrap=%d targets=%d, want 3 and 0", *roles, *targets)
			}
		})
	}
}

func TestViewerRestrictedBaselineAllowsActualHTTPEntrypoints(t *testing.T) {
	ctx := context.Background()
	c, roles, targets := restrictedViewerClient(t)
	if _, err := c.get(ctx, "https://compute.googleapis.com/compute/v1/projects/p", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.storageGET(ctx, "https://storage.googleapis.com/storage/v1/b?project=p", true, 1024, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.readIAMPolicy(ctx, "https://cloudresourcemanager.googleapis.com/v3/projects/p:getIamPolicy"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.logPage(ctx, Object{"resourceNames": []string{"projects/p"}, "filter": "severity>=ERROR"}); err != nil {
		t.Fatal(err)
	}
	if *roles != 3 || *targets != 4 {
		t.Fatalf("HTTP bootstrap=%d targets=%d, want 3 and 4", *roles, *targets)
	}
	// Cached metadata is reused without permitting an otherwise reachable read.
	if _, err := c.storageGET(ctx, "https://storage.googleapis.com/storage/v1/b/bucket/o/private?alt=media", true, 1024, ""); err == nil {
		t.Fatal("allowed private content with privileged credential")
	}
	if *roles != 3 || *targets != 4 {
		t.Fatal("denied cached request reached HTTP")
	}
}

func TestViewerUnknownEntrypointsNeverBootstrapOrReachHTTP(t *testing.T) {
	ctx := context.Background()
	c, roles, targets := restrictedViewerClient(t)
	if _, err := c.get(ctx, "https://admin.googleapis.com/admin/directory/v1/users", nil); err == nil {
		t.Fatal("allowed Workspace API")
	}
	if _, err := c.storageGET(ctx, "https://storage.googleapis.com/storage/v1/b/bucket/o/object/acl", true, 1024, ""); err == nil {
		t.Fatal("allowed unreviewed storage ACL method")
	}
	if _, err := c.readIAMPolicy(ctx, "https://cloudresourcemanager.googleapis.com/v3/projects/p:setIamPolicy"); err == nil {
		t.Fatal("allowed IAM mutation")
	}
	if *roles != 0 || *targets != 0 {
		t.Fatalf("unknown operation performed HTTP: roles=%d targets=%d", *roles, *targets)
	}
}
