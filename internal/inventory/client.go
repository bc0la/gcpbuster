package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Client struct {
	HTTP                  *http.Client
	TokenEnv              string
	Impersonate           string
	DNSChecks             bool
	LookupHost            func(context.Context, string) ([]string, error)
	RefreshConfig         bool
	WorkspaceMembers      bool
	SecretCapture         *SecretCapture // Optional transient configuration samples; never serialized in Snapshot.
	Concurrency           int            // Bound concurrent collection jobs; zero preserves serial library behavior.
	PerProjectConcurrency int            // Optional per-project cap within the global worker limit.
	Progress              func(ProgressEvent)
	progressMu            sync.Mutex
	rateLimitMu           sync.Mutex
	rateLimits            map[string]time.Time
	mu                    sync.Mutex
	token                 string
	refresh               time.Time
	viewerPolicy          viewerPolicyCache
}

// Explicit supported types avoid collecting unrelated payload-bearing resources
// (for example Kubernetes Secrets) while retaining all IAM policy asset types.
var resourceTypes = []string{
	"compute.googleapis.com/BackendService",
	"secretmanager.googleapis.com/Secret", "secretmanager.googleapis.com/SecretVersion", "cloudkms.googleapis.com/CryptoKey", "cloudkms.googleapis.com/CryptoKeyVersion",
	"cloudtasks.googleapis.com/Queue", "pubsub.googleapis.com/Subscription", "artifactregistry.googleapis.com/Repository",
	"compute.googleapis.com/Instance", "compute.googleapis.com/Project", "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/MachineImage", "compute.googleapis.com/Firewall", "compute.googleapis.com/Image", "compute.googleapis.com/Snapshot",
	"container.googleapis.com/Cluster", "storage.googleapis.com/Bucket", "sqladmin.googleapis.com/Instance", "bigquery.googleapis.com/Dataset",
	"iam.googleapis.com/ServiceAccount", "iam.googleapis.com/ServiceAccountKey", "iam.googleapis.com/Role", "iam.googleapis.com/WorkloadIdentityPoolProvider", "iam.googleapis.com/WorkforcePoolProvider",
	"logging.googleapis.com/LogSink", "apikeys.googleapis.com/Key", "cloudfunctions.googleapis.com/CloudFunction", "cloudfunctions.googleapis.com/Function", "run.googleapis.com/Service", "run.googleapis.com/Job",
	"cloudbuild.googleapis.com/Build", "cloudbuild.googleapis.com/BuildTrigger", "appengine.googleapis.com/Version", "workflows.googleapis.com/Workflow", "cloudscheduler.googleapis.com/Job", "dataflow.googleapis.com/Job", "composer.googleapis.com/Environment", "aiplatform.googleapis.com/CustomJob", "aiplatform.googleapis.com/PipelineJob",
	"identitytoolkit.googleapis.com/Config", "identitytoolkit.googleapis.com/Tenant", "dns.googleapis.com/ManagedZone",
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	if c.Impersonate != "" {
		return "", fmt.Errorf("viewer-only policy: service-account impersonation is not permitted")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.TokenEnv != "" {
		t := strings.TrimSpace(os.Getenv(c.TokenEnv))
		if t == "" {
			return "", fmt.Errorf("token environment variable %s is empty", c.TokenEnv)
		}
		return t, nil
	}
	if os.Getenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT") != "" {
		return "", fmt.Errorf("viewer-only policy: gcloud environment service-account impersonation is not permitted; use a non-impersonating identity or --token-env")
	}
	if c.token != "" && time.Now().Before(c.refresh) {
		return c.token, nil
	}
	// Inspect only the impersonation property, never credentials or token data.
	// config list is local and does not mint a token. A failed/malformed read
	// cannot prove that the active gcloud configuration is non-impersonating.
	config, err := exec.CommandContext(ctx, "gcloud", "config", "list", "auth/impersonate_service_account", "--format=json", "--quiet").Output()
	if err != nil {
		return "", fmt.Errorf("viewer-only policy: cannot verify gcloud impersonation configuration; use --token-env or repair the local gcloud configuration")
	}
	var properties Object
	if json.Unmarshal(config, &properties) != nil || properties == nil {
		return "", fmt.Errorf("viewer-only policy: malformed gcloud impersonation configuration")
	}
	if raw, exists := properties["auth"]; exists {
		auth, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("viewer-only policy: malformed gcloud authentication configuration")
		}
		// gcloud's JSON formatter represents an unset property as null.
		// Only a non-null value can configure impersonation.
		if value, exists := auth["impersonate_service_account"]; exists && value != nil {
			account, ok := value.(string)
			if !ok || account != "" {
				return "", fmt.Errorf("viewer-only policy: configured gcloud service-account impersonation is not permitted; use a non-impersonating identity or --token-env")
			}
		}
	}
	cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token", "--quiet")
	// An explicit empty environment override also pins impersonation off if a
	// concurrent process changes the active configuration after inspection.
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=")
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gcloud auth print-access-token failed: %w (authenticate gcloud or use --token-env)", err)
	}
	c.token = strings.TrimSpace(string(b))
	c.refresh = time.Now().Add(5 * time.Minute)
	if c.token == "" {
		return "", fmt.Errorf("gcloud returned an empty token")
	}
	return c.token, nil
}

// get only performs GETs. No provider mutations or anonymous active probes.
func (c *Client) get(ctx context.Context, endpoint string, q url.Values) (Object, error) {
	if err := c.requireViewerPermissions(ctx, "GET", endpoint, q); err != nil {
		return nil, err
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	h := &http.Client{Timeout: 60 * time.Second}
	if c.HTTP != nil {
		copy := *c.HTTP
		h = &copy
		if h.Timeout <= 0 {
			h.Timeout = 60 * time.Second
		}
	}
	h.Jar = nil
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx = withRequestAttemptCounter(ctx)
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.doRequest(h, req, attempt+1)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode >= 500 {
			if attempt < 3 {
				select {
				case <-time.After(time.Duration(1<<attempt) * time.Second):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
		if resp.StatusCode != 200 {
			// Do not log response bodies: upstream errors can echo sensitive input.
			return nil, fmt.Errorf("GET %s: HTTP %d (check permissions, OAuth scopes, API enablement, and token expiry)", endpoint, resp.StatusCode)
		}
		var out Object
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, fmt.Errorf("retry budget exhausted")
}

func (c *Client) list(ctx context.Context, endpoint string, q url.Values, key string) ([]Object, error) {
	if q == nil {
		q = url.Values{}
	}
	var out []Object
	seen := map[string]bool{}
	for {
		page, err := c.get(ctx, endpoint, q)
		if err != nil {
			return out, err
		}
		for _, v := range List(page[key]) {
			if m := Obj(v); m != nil {
				out = append(out, m)
			}
		}
		next := Str(page["nextPageToken"])
		if next == "" {
			return out, nil
		}
		if seen[next] {
			return out, fmt.Errorf("repeated pagination token from %s", endpoint)
		}
		seen[next] = true
		q.Set("pageToken", next)
	}
}

func (s *Snapshot) record(source string, n int, err error) {
	c := Coverage{Source: source, Status: "completed", Count: n}
	if err != nil {
		c.Status = "failed"
		c.Error = err.Error()
	}
	s.Coverage = append(s.Coverage, c)
}

func (c *Client) Cloud(ctx context.Context, scope string) Snapshot {
	var out Snapshot
	// Pin both views to one point in time to avoid drifting between pages.
	readTime := time.Now().UTC().Format(time.RFC3339)
	for _, kind := range []string{"RESOURCE", "IAM_POLICY"} {
		q := url.Values{"contentType": {kind}, "pageSize": {"1000"}, "readTime": {readTime}}
		if kind == "RESOURCE" {
			q["assetTypes"] = resourceTypes
		}
		rows, err := c.list(ctx, "https://cloudasset.googleapis.com/v1/"+scope+"/assets", q, "assets")
		out.record(scope+":"+kind, len(rows), err)
		for _, row := range rows {
			b, _ := json.Marshal(row)
			var a Asset
			if err := json.Unmarshal(b, &a); err != nil {
				out.record(scope+":"+kind+":decode", 0, err)
				continue
			}
			out.Assets = append(out.Assets, a)
		}
	}
	// Refresh key metadata directly: CAI IAM data can be delayed.
	seen := map[string]bool{}
	for _, a := range out.Assets {
		if a.Type != "iam.googleapis.com/ServiceAccount" || a.Resource.Data == nil {
			continue
		}
		email := Str(a.Resource.Data["email"])
		if email == "" || seen[email] {
			continue
		}
		seen[email] = true
		rows, err := c.list(ctx, "https://iam.googleapis.com/v1/projects/-/serviceAccounts/"+url.PathEscape(email)+"/keys", url.Values{"keyTypes": {"USER_MANAGED"}}, "keys")
		out.record("service-account-keys:"+email, len(rows), err)
		for _, r := range rows {
			out.Assets = append(out.Assets, NewAsset("//iam.googleapis.com/"+Str(r["name"]), "iam.googleapis.com/ServiceAccountKey", r))
		}
	}
	if c.DNSChecks {
		c.collectDNS(ctx, &out)
	}
	if c.RefreshConfig {
		c.refreshCompute(ctx, &out)
	}
	return out
}

// CAI can omit arbitrary custom metadata. Direct Compute reads make the
// startup-script/environment check useful without persisting whole resources.
func (c *Client) refreshCompute(ctx context.Context, out *Snapshot) {
	for i, a := range out.Assets {
		switch a.Type {
		case "compute.googleapis.com/Instance", "compute.googleapis.com/Project", "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/MachineImage":
		default:
			continue
		}
		if a.Resource.Data == nil {
			continue
		}
		const prefix = "//compute.googleapis.com/"
		if !strings.HasPrefix(a.Name, prefix) {
			continue
		}
		path := strings.TrimPrefix(a.Name, prefix)
		if !strings.HasPrefix(path, "projects/") || strings.ContainsAny(path, "?#") {
			out.record("compute-config:"+a.Name, 0, fmt.Errorf("unexpected Compute resource name"))
			continue
		}
		r, err := c.get(ctx, "https://compute.googleapis.com/compute/v1/"+path, nil)
		count := 0
		if err == nil {
			count = 1
			out.Assets[i].Resource.Data = r
		}
		out.record("compute-config:"+a.Name, count, err)
	}
}

// DNSLookupName accepts only absolute, multi-label ASCII hostnames, not URLs,
// IP literals, resolver search names or arbitrary record content.
func DNSLookupName(value string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return name, true
}

func (c *Client) collectDNS(ctx context.Context, out *Snapshot) {
	lookup := c.LookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	assets := append([]Asset(nil), out.Assets...)
	for _, a := range assets {
		if a.Type != "dns.googleapis.com/ManagedZone" || a.Resource.Data == nil || Str(a.Resource.Data["visibility"]) != "public" {
			continue
		}
		parts := strings.Split(a.Name, "/")
		project := ""
		for i, p := range parts {
			if p == "projects" && i+1 < len(parts) {
				project = parts[i+1]
			}
		}
		zone := Str(a.Resource.Data["name"])
		if !viewerResourceName.MatchString(project) || !viewerDNSZoneName.MatchString(zone) {
			out.record("dns:"+a.Name, 0, fmt.Errorf("missing project or managed-zone name"))
			continue
		}
		endpoint := "https://dns.googleapis.com/dns/v1/projects/" + url.PathEscape(project) + "/managedZones/" + url.PathEscape(zone) + "/rrsets"
		rows, err := c.list(ctx, endpoint, nil, "rrsets")
		out.record("dns:"+a.Name, len(rows), err)
		for _, r := range rows {
			if Str(r["type"]) != "CNAME" {
				continue
			}
			record := Str(r["name"])
			if _, valid := DNSLookupName(strings.TrimPrefix(record, "*.")); !valid {
				out.record("dns-record:"+a.Name, 0, fmt.Errorf("invalid CNAME record name"))
				continue
			}
			for _, v := range List(r["rrdatas"]) {
				target, valid := DNSLookupName(Str(v))
				if !valid {
					out.record("dns-record:"+a.Name, 0, fmt.Errorf("invalid CNAME target"))
					continue
				}
				lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				addresses, err := lookup(lookupCtx, target+".")
				cancel()
				status := "resolved"
				if err != nil {
					status = "unknown"
					var dnsErr *net.DNSError
					if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
						status = "address_not_found"
					} else {
						out.record("dns-resolution:"+target, 0, fmt.Errorf("DNS lookup failed or timed out"))
					}
				} else if len(addresses) == 0 {
					status = "unknown"
					out.record("dns-resolution:"+target, 0, fmt.Errorf("DNS lookup returned no address and no status"))
				}
				data := Object{"name": record, "type": "CNAME", "target": target, "targetStatus": status, "zoneVisibility": "public"}
				out.Assets = append(out.Assets, NewAsset(a.Name+"/rrsets/"+Str(r["name"])+"/"+target, "dns.googleapis.com/ResourceRecordSet", data))
			}
		}
	}
}

func (c *Client) Workspace(ctx context.Context, customer string, tokens bool) Snapshot {
	var out Snapshot
	base := "https://admin.googleapis.com/admin/directory/v1/"
	users, err := c.list(ctx, base+"users", url.Values{"customer": {customer}, "projection": {"full"}, "maxResults": {"500"}}, "users")
	out.record("workspace:users", len(users), err)
	for _, u := range users {
		id := Str(u["id"])
		out.Assets = append(out.Assets, NewAsset("workspace/users/"+id, "workspace.googleapis.com/User", u))
		if tokens {
			rows, err := c.list(ctx, base+"users/"+url.PathEscape(id)+"/tokens", nil, "items")
			out.record("workspace:tokens:"+id, len(rows), err)
			for _, r := range rows {
				r["userId"] = id
				out.Assets = append(out.Assets, NewAsset("workspace/users/"+id+"/tokens/"+Str(r["clientId"]), "workspace.googleapis.com/OAuthGrant", r))
			}
		}
	}
	groups, err := c.list(ctx, base+"groups", url.Values{"customer": {customer}, "maxResults": {"200"}}, "groups")
	out.record("workspace:groups", len(groups), err)
	for _, g := range groups {
		email := Str(g["email"])
		out.Assets = append(out.Assets, NewAsset("workspace/directory-groups/"+Str(g["id"]), "workspace.googleapis.com/Group", g))
		if c.WorkspaceMembers {
			c.collectGroupMembers(ctx, &out, g)
		}
		r, err := c.get(ctx, "https://www.googleapis.com/groups/v1/groups/"+url.PathEscape(email), nil)
		out.record("workspace:group-settings:"+email, 1, err)
		if err == nil {
			out.Assets = append(out.Assets, NewAsset("workspace/groups/"+email, "workspace.googleapis.com/GroupSettings", r))
		}
	}
	for _, spec := range []struct{ path, key, kind string }{{"roles", "items", "Role"}, {"roleassignments", "items", "RoleAssignment"}} {
		rows, err := c.list(ctx, base+"customer/"+url.PathEscape(customer)+"/"+spec.path, nil, spec.key)
		out.record("workspace:"+spec.path, len(rows), err)
		for i, r := range rows {
			out.Assets = append(out.Assets, NewAsset(fmt.Sprintf("workspace/%s/%d", spec.path, i), "workspace.googleapis.com/"+spec.kind, r))
		}
	}
	return out
}
