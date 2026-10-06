package inventory

import (
	"reflect"
	"testing"
)

func TestViewerLogBucketMetadataGuard(t *testing.T) {
	for _, scope := range []string{"projects/demo", "projects/123", "folders/123", "organizations/123"} {
		got, err := viewerRequestPermissions("GET", "https://logging.googleapis.com/v2/"+scope+"/locations/-/buckets", nil)
		if err != nil || !reflect.DeepEqual(got, []string{"logging.buckets.list"}) {
			t.Fatal(scope, got, err)
		}
	}
	for _, endpoint := range []string{
		"https://logging.googleapis.com/v2/projects/123/locations/-/buckets/b",
		"https://logging.googleapis.com/v2/projects/123/locations/-/buckets/b:undelete",
		"https://logging.googleapis.com/v2/projects/123/locations/-/buckets/b/views/v/logs",
		"https://logging.googleapis.com/v2/billingAccounts/123/locations/-/buckets",
		"https://example.test/v2/projects/123/locations/-/buckets",
	} {
		if _, err := viewerRequestPermissions("GET", endpoint, nil); err == nil {
			t.Fatal("unexpected endpoint allowed", endpoint)
		}
	}
	for _, method := range []string{"POST", "PATCH", "PUT", "DELETE"} {
		if _, err := viewerRequestPermissions(method, "https://logging.googleapis.com/v2/projects/123/locations/-/buckets", nil); err == nil {
			t.Fatal("mutation allowed", method)
		}
	}
}

func TestViewerLogViewMetadataAndPolicyGuard(t *testing.T) {
	for _, scope := range []string{"projects/123", "folders/123", "organizations/123"} {
		base := "https://logging.googleapis.com/v2/" + scope + "/locations/global/buckets/_Default/views"
		for _, tc := range []struct{ method, endpoint, permission string }{
			{"GET", base, "logging.views.list"},
			{"POST", base + "/_AllLogs:getIamPolicy", "logging.views.getIamPolicy"},
		} {
			got, err := viewerRequestPermissions(tc.method, tc.endpoint, nil)
			if err != nil || !reflect.DeepEqual(got, []string{tc.permission}) {
				t.Fatal(tc, got, err)
			}
		}
		for _, suffix := range []string{"/_AllLogs/logs", "/_AllLogs:setIamPolicy", "/_AllLogs:testIamPermissions", "/_AllLogs:delete"} {
			for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
				if _, err := viewerRequestPermissions(method, base+suffix, nil); err == nil {
					t.Fatal("unexpected view endpoint allowed", method, suffix)
				}
			}
		}
	}
}

func TestViewerLogMetricsAndLinksGuard(t *testing.T) {
	for _, tc := range []struct{ endpoint, permission string }{
		{"https://logging.googleapis.com/v2/projects/123/metrics", "logging.logMetrics.list"},
		{"https://logging.googleapis.com/v2/projects/123/locations/global/buckets/b/links", "logging.links.list"},
		{"https://logging.googleapis.com/v2/folders/123/locations/us-central1/buckets/b/links", "logging.links.list"},
		{"https://logging.googleapis.com/v2/organizations/123/locations/eu/buckets/b/links", "logging.links.list"},
	} {
		got, err := viewerRequestPermissions("GET", tc.endpoint, nil)
		if err != nil || !reflect.DeepEqual(got, []string{tc.permission}) {
			t.Fatal(tc, got, err)
		}
		for _, method := range []string{"POST", "PATCH", "DELETE"} {
			if _, err := viewerRequestPermissions(method, tc.endpoint, nil); err == nil {
				t.Fatal("mutation allowed", method, tc.endpoint)
			}
		}
	}
	for _, endpoint := range []string{
		"https://logging.googleapis.com/v2/folders/123/metrics",
		"https://logging.googleapis.com/v2/projects/123/metrics/m",
		"https://logging.googleapis.com/v2/projects/123/locations/global/buckets/b/links/l",
		"https://logging.googleapis.com/v2/projects/123/locations/global/buckets/b/links/l:delete",
	} {
		if _, err := viewerRequestPermissions("GET", endpoint, nil); err == nil {
			t.Fatal("unreviewed method allowed", endpoint)
		}
	}
}
