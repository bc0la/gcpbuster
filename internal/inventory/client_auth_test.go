package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A local fake gcloud prevents these auth tests from contacting any account.
func fakeAuthGcloud(t *testing.T, configuration string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$GCPBUSTER_AUTH_TEST_LOG"
if [ "$1 $2" = "config list" ]; then
  printf '%s' "$GCPBUSTER_AUTH_TEST_CONFIG"
  exit 0
fi
if [ "$1 $2" = "auth print-access-token" ]; then
  if [ "${CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT+x}" != x ] || [ -n "$CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT" ]; then
    exit 4
  fi
  printf '%s' 'test-access-token'
  exit 0
fi
exit 3
`
	if err := os.WriteFile(filepath.Join(dir, "gcloud"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("GCPBUSTER_AUTH_TEST_LOG", log)
	t.Setenv("GCPBUSTER_AUTH_TEST_CONFIG", configuration)
	t.Setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "")
	return log
}

func TestAccessTokenBlocksImplicitImpersonation(t *testing.T) {
	for _, configuration := range []string{`{"auth":{"impersonate_service_account":"PRIVATE@example.com"}}`, `{"auth":{"impersonate_service_account":["PRIVATE"]}}`, `null`, `not-json`, `{"auth":null}`} {
		t.Run(configuration, func(t *testing.T) {
			log := fakeAuthGcloud(t, configuration)
			c := Client{}
			token, err := c.accessToken(context.Background())
			if err == nil || token != "" || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal(token, err)
			}
			calls, _ := os.ReadFile(log)
			if strings.Contains(string(calls), "print-access-token") {
				t.Fatal("token mint attempted", string(calls))
			}
		})
	}
}

func TestAccessTokenPinsNoImpersonationAndCaches(t *testing.T) {
	for _, configuration := range []string{`{}`, `{"auth":{}}`, `{"auth":{"impersonate_service_account":""}}`} {
		t.Run(configuration, func(t *testing.T) {
			log := fakeAuthGcloud(t, configuration)
			c := Client{}
			for i := 0; i < 2; i++ {
				token, err := c.accessToken(context.Background())
				if err != nil || token != "test-access-token" {
					t.Fatal(token, err)
				}
			}
			calls, _ := os.ReadFile(log)
			if strings.Count(string(calls), "config list") != 1 || strings.Count(string(calls), "print-access-token") != 1 {
				t.Fatal(string(calls))
			}
		})
	}
}

func TestAccessTokenEnvironmentBlocksBeforeGcloud(t *testing.T) {
	log := fakeAuthGcloud(t, `{}`)
	t.Setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "PRIVATE@example.com")
	c := Client{}
	_, err := c.accessToken(context.Background())
	if err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal(err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("gcloud ran", err)
	}
}

func TestAccessTokenMissingGcloudFailsClosed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "")
	c := Client{}
	if _, err := c.accessToken(context.Background()); err == nil {
		t.Fatal("missing config check accepted")
	}
}

func TestAccessTokenSuppliedTokenDoesNotInvokeGcloud(t *testing.T) {
	log := fakeAuthGcloud(t, `{"auth":{"impersonate_service_account":"not-used"}}`)
	t.Setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "not-used")
	t.Setenv("GCPBUSTER_AUTH_TEST_SUPPLIED", "supplied-token")
	c := Client{TokenEnv: "GCPBUSTER_AUTH_TEST_SUPPLIED"}
	if token, err := c.accessToken(context.Background()); err != nil || token != "supplied-token" {
		t.Fatal(token, err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("gcloud ran", err)
	}
	c.Impersonate = "forbidden"
	if _, err := c.accessToken(context.Background()); err == nil {
		t.Fatal("explicit impersonation accepted")
	}
}
