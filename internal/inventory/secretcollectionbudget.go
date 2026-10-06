package inventory

import (
	"context"
	"fmt"
	"net/url"
)

// Shared across all discovered locations and child collections of one family.
type secretCollectionBudget struct {
	pages, resources int
	exhausted        bool
}

func (b *secretCollectionBudget) takeResource() error {
	if b.resources >= 10000 {
		b.exhausted = true
		return fmt.Errorf("configuration discovery resource limit reached")
	}
	b.resources++
	return nil
}
func (c *Client) secretCollectionPages(ctx context.Context, endpoint string, q url.Values, b *secretCollectionBudget, fn func(Object) error) error {
	if b.exhausted || b.pages >= 1000 {
		b.exhausted = true
		return fmt.Errorf("configuration discovery page limit reached")
	}
	seen := map[string]bool{}
	for {
		if b.pages >= 1000 {
			b.exhausted = true
			return fmt.Errorf("configuration discovery page limit reached")
		}
		b.pages++
		page, err := c.get(ctx, endpoint, q)
		if err != nil {
			return err
		}
		if page == nil {
			return fmt.Errorf("invalid configuration inventory page")
		}
		if err := fn(page); err != nil {
			return err
		}
		if raw, ok := page["nextPageToken"]; ok {
			if _, ok := raw.(string); !ok {
				return fmt.Errorf("invalid configuration pagination token")
			}
		}
		next := Str(page["nextPageToken"])
		if next == "" {
			return nil
		}
		if seen[next] {
			return fmt.Errorf("repeated configuration pagination token")
		}
		seen[next] = true
		q.Set("pageToken", next)
	}
}
