package inventory

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestSecretCollectionBudgetStopsBeforeNetwork(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("exhausted budget made request"); return nil, nil })
	b := &secretCollectionBudget{pages: 1000}
	if err := c.secretCollectionPages(context.Background(), "https://clouddeploy.googleapis.com/v1/projects/123/locations", url.Values{}, b, func(Object) error { return nil }); err == nil || !b.exhausted {
		t.Fatal("page budget not enforced")
	}
	b = &secretCollectionBudget{resources: 10000}
	if err := b.takeResource(); err == nil || !b.exhausted || b.resources != 10000 {
		t.Fatal("resource budget not enforced")
	}
}
