package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// getContainerPolicy is a read-semantic POST; the target and action are fixed.
func (c *Client) getContainerPolicy(ctx context.Context, scope string) (Object, error) {
	if !logScopePattern.MatchString(scope) {
		return nil, fmt.Errorf("invalid IAM container")
	}
	return c.readIAMPolicy(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+scope+":getIamPolicy")
}

// readIAMPolicy is internal: callers construct fixed read-only IAM endpoints.
func (c *Client) readIAMPolicy(ctx context.Context, endpoint string) (Object, error) {
	if err := c.requireViewerPermissions(ctx, "POST", endpoint, nil); err != nil {
		return nil, err
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	h := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.HTTP != nil {
		h.Transport = c.HTTP.Transport
		if c.HTTP.Timeout > 0 {
			h.Timeout = c.HTTP.Timeout
		}
	}
	ctx = withRequestAttemptCounter(ctx)
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(`{"options":{"requestedPolicyVersion":3}}`))
		if err != nil {
			return nil, fmt.Errorf("cannot construct IAM policy read")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.doRequest(h, req, attempt+1)
		if err != nil {
			return nil, fmt.Errorf("IAM policy read transport failure or cancellation")
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < 3 {
				select {
				case <-time.After(time.Duration(1<<attempt) * time.Second):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return nil, fmt.Errorf("IAM policy read exhausted retries: HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("IAM policy read unavailable: %s", safeHTTPFailure(resp))
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
		resp.Body.Close()
		if readErr != nil || len(data) > 16<<20 {
			return nil, fmt.Errorf("IAM policy response unreadable or oversized")
		}
		var policy Object
		if json.Unmarshal(data, &policy) != nil || policy == nil {
			return nil, fmt.Errorf("invalid IAM policy response")
		}
		if raw, exists := policy["bindings"]; exists {
			if _, ok := raw.([]any); !ok {
				return nil, fmt.Errorf("invalid IAM bindings")
			}
		}
		for _, raw := range List(policy["bindings"]) {
			b := Obj(raw)
			if !rolePattern.MatchString(Str(b["role"])) {
				return nil, fmt.Errorf("invalid IAM binding role")
			}
			members, ok := b["members"].([]any)
			if !ok {
				return nil, fmt.Errorf("invalid IAM binding members")
			}
			for _, v := range members {
				if text, ok := v.(string); !ok || text == "" {
					return nil, fmt.Errorf("invalid IAM member")
				}
			}
			if b["condition"] != nil && (Str(Get(b, "condition", "expression")) == "" || policy["version"] != float64(3)) {
				return nil, fmt.Errorf("conditional IAM policy missing version 3 or expression")
			}
		}
		return policy, nil
	}
	return nil, fmt.Errorf("IAM policy retry budget exhausted")
}

// CollectAncestorIAM follows each selected resource's parent chain, never its
// siblings or descendants. Policies remain attached to the granting container.
func (c *Client) CollectAncestorIAM(ctx context.Context, snap *Snapshot, scopes []string) {
	metadata := map[string]Object{}
	policySeen := map[string]bool{}
	for _, root := range scopes {
		seen := map[string]bool{}
		scope := root
		for scope != "" {
			if !logScopePattern.MatchString(scope) || seen[scope] {
				snap.record("ancestor-chain:"+root, 0, fmt.Errorf("invalid or cyclic parent chain"))
				break
			}
			seen[scope] = true
			d, ok := metadata[scope]
			if !ok {
				var err error
				d, err = c.get(ctx, "https://cloudresourcemanager.googleapis.com/v3/"+scope, nil)
				if err != nil {
					snap.record("ancestor-metadata:"+scope, 0, err)
					break
				}
				name := Str(d["name"])
				valid := name == scope
				if strings.HasPrefix(scope, "projects/") {
					valid = valid || (strings.HasPrefix(name, "projects/") && Str(d["projectId"]) == strings.TrimPrefix(scope, "projects/"))
				}
				if !valid || !logScopePattern.MatchString(name) {
					snap.record("ancestor-metadata:"+scope, 0, fmt.Errorf("mismatched container metadata"))
					break
				}
				metadata[scope] = d
				metadata[name] = d
			}
			name := Str(d["name"])
			parent := Str(d["parent"])
			isOrg := strings.HasPrefix(name, "organizations/")
			if (isOrg && parent != "") || (!isOrg && parent != "" && (!logScopePattern.MatchString(parent) || strings.HasPrefix(parent, "projects/"))) || (strings.HasPrefix(name, "folders/") && parent == "") {
				snap.record("ancestor-chain:"+root, 0, fmt.Errorf("invalid parent resource"))
				break
			}
			if !policySeen[name] {
				policySeen[name] = true
				policy, err := c.getContainerPolicy(ctx, name)
				snap.record("ancestor-iam:"+name, 1, err)
				if err == nil {
					kind := "Project"
					if strings.HasPrefix(name, "folders/") {
						kind = "Folder"
					}
					if isOrg {
						kind = "Organization"
					}
					a := NewAsset("//cloudresourcemanager.googleapis.com/"+name, "cloudresourcemanager.googleapis.com/"+kind, Object{"name": name, "parent": parent, "collectionBasis": "selected scope and parent-chain IAM context"})
					a.IAM = policy
					a.Ancestors = []string{name}
					if parent != "" {
						a.Ancestors = append(a.Ancestors, parent)
					}
					snap.Assets = append(snap.Assets, a)
				}
			}
			if parent == "" {
				snap.record("ancestor-chain:"+root, len(seen), nil)
				break
			}
			scope = parent
		}
	}
	snap.Coverage = append(snap.Coverage, Coverage{Source: "ancestor-iam:limitations", Status: "notice", Error: "Parent-chain direct allow policies only; grant locations and conditions are preserved. IAM deny, principal access boundaries, group expansion and service-specific authorization still affect effective access. Policy reads are not an atomic snapshot."})
}
