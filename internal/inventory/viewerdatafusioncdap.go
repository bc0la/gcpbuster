package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const dataFusionEndpointFields = "name,apiEndpoint"
const DataFusionConnectionType = "gcpbuster.googleapis.com/DataFusionConnection"
const DataFusionPipelineType = "gcpbuster.googleapis.com/DataFusionPipeline"

func cdapMetadataAsset(resource, kind, region, namespace string, b cdapBinding) Asset {
	a := NewAsset(resource, kind, Object{"name": resource, "namespace": namespace, "instance": b.instance, "apiEndpoint": b.endpoint})
	a.Ancestors = []string{strings.Join(strings.Split(b.instance, "/")[:2], "/")}
	a.Resource.Location = region
	return a
}

type cdapBinding struct {
	instance, endpoint, host string
	client                   *Client
}

var cdapHost = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.datafusion\.googleusercontent\.com$`)
var cdapID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func (c *Client) bindCDAP(detail Object, expected, projectID, number, region string) (cdapBinding, error) {
	fail := func() (cdapBinding, error) {
		return cdapBinding{}, fmt.Errorf("invalid or unbound Data Fusion CDAP endpoint")
	}
	id, err := viewerBuildWorkflowName(Str(detail["name"]), projectID, number, region, "instances")
	if err != nil || expected != number+"/locations/"+region+"/instances/"+id {
		return fail()
	}
	u, err := url.Parse(Str(detail["apiEndpoint"]))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || !cdapHost.MatchString(u.Host) || u.Path != "/api" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return fail()
	}
	return cdapBinding{instance: expected, endpoint: u.String(), host: u.Host, client: c}, nil
}

func cdapReadPermissions(binding cdapBinding, path string) ([]string, error) {
	fail := func() ([]string, error) {
		return nil, fmt.Errorf("viewer-only policy: unreviewed or unbound CDAP metadata read")
	}
	if binding.client == nil || !regexp.MustCompile(`^projects/[0-9]+/locations/[a-z][a-z0-9-]*/instances/[A-Za-z0-9_-]+$`).MatchString(binding.instance) || !cdapHost.MatchString(binding.host) || binding.endpoint != "https://"+binding.host+"/api" {
		return fail()
	}
	base := []string{"datafusion.instances.get"}
	if path == "/v3/namespaces" {
		return append(base, "datafusion.namespaces.list"), nil
	}
	if regexp.MustCompile(`^/v3/namespaces/[A-Za-z0-9_-]+/apps$`).MatchString(path) {
		return append(base, "datafusion.namespaces.get", "datafusion.pipelines.list"), nil
	}
	if regexp.MustCompile(`^/v3/namespaces/[A-Za-z0-9_-]+/apps/[A-Za-z0-9_-]+$`).MatchString(path) {
		return append(base, "datafusion.namespaces.get", "datafusion.pipelines.get"), nil
	}
	if regexp.MustCompile(`^/v3/namespaces/system/apps/pipeline/services/studio/methods/v1/contexts/[A-Za-z0-9_-]+/connections$`).MatchString(path) {
		return append(base, "datafusion.namespaces.get", "datafusion.pipelineConnections.list"), nil
	}
	return fail()
}

// A binding is obtained from a freshly scope-validated control-plane response,
// never a caller URL. No redirects/cookies, probes, connection tests or private
// secure-key routes; parsing errors and HTTP bodies never enter coverage.
func (c *Client) cdapRead(ctx context.Context, binding cdapBinding, path string, budget *secretCollectionBudget) (any, error) {
	if binding.client != c {
		return nil, fmt.Errorf("viewer-only policy: CDAP endpoint is not bound to this client")
	}
	permissions, err := cdapReadPermissions(binding, path)
	if err != nil {
		return nil, err
	}
	if err := c.requireViewerPermissionSet(ctx, permissions); err != nil {
		return nil, err
	}
	if budget.exhausted || budget.pages >= 1000 {
		budget.exhausted = true
		return nil, fmt.Errorf("CDAP shared discovery page limit reached")
	}
	budget.pages++
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
	req, err := http.NewRequestWithContext(ctx, "GET", binding.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid CDAP metadata request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.doRequest(h, req, 1)
	if err != nil {
		return nil, fmt.Errorf("CDAP metadata transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CDAP metadata %s", safeHTTPFailure(resp))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return nil, fmt.Errorf("CDAP metadata body exceeded read limit or failed")
	}
	var out any
	if json.Unmarshal(data, &out) != nil {
		return nil, fmt.Errorf("invalid CDAP metadata JSON")
	}
	return out, nil
}

func (c *Client) viewerDataFusionCDAP(ctx context.Context, out *Snapshot, projectID, number, instance, region string, budget *secretCollectionBudget) {
	if budget.exhausted || budget.pages >= 1000 {
		budget.exhausted = true
		return
	}
	budget.pages++
	detail, err := c.get(ctx, "https://datafusion.googleapis.com/v1/"+instance, url.Values{"fields": {dataFusionEndpointFields}})
	if err != nil {
		out.record("viewer-datafusion:cdap-endpoint:"+instance, 0, err)
		return
	}
	binding, err := c.bindCDAP(detail, instance, projectID, number, region)
	if err != nil {
		out.record("viewer-datafusion:cdap-endpoint:"+instance, 0, err)
		return
	}
	raw, err := c.cdapRead(ctx, binding, "/v3/namespaces", budget)
	if err != nil {
		out.record("viewer-datafusion:cdap-namespaces:"+instance, 0, err)
		return
	}
	namespaces, ok := raw.([]any)
	if !ok || len(namespaces) > 10000 {
		out.record("viewer-datafusion:cdap-namespaces:"+instance, 0, fmt.Errorf("invalid or oversized CDAP namespace list"))
		return
	}
	seen := map[string]bool{}
	for _, row := range namespaces {
		namespace := Str(Obj(row)["name"])
		if !cdapID.MatchString(namespace) {
			out.record("viewer-datafusion:cdap-identity:"+instance, 0, fmt.Errorf("invalid CDAP namespace identity"))
			continue
		}
		if seen[namespace] {
			continue
		}
		seen[namespace] = true
		if err := budget.takeResource(); err != nil {
			out.record("viewer-datafusion:cdap-limit:"+instance, 0, err)
			return
		}
		c.viewerCDAPConnections(ctx, out, binding, namespace, region, budget)
		c.viewerCDAPPipelines(ctx, out, binding, namespace, region, budget)
		if budget.exhausted {
			return
		}
	}
}

func (c *Client) viewerCDAPConnections(ctx context.Context, out *Snapshot, b cdapBinding, namespace, region string, budget *secretCollectionBudget) {
	raw, err := c.cdapRead(ctx, b, "/v3/namespaces/system/apps/pipeline/services/studio/methods/v1/contexts/"+namespace+"/connections", budget)
	count := 0
	if err == nil {
		rows, ok := raw.([]any)
		if !ok || len(rows) > 10000 {
			err = fmt.Errorf("invalid or oversized CDAP connection list")
		} else {
			seen := map[string]bool{}
			for _, row := range rows {
				d := Obj(row)
				id := Str(d["connectionId"])
				if !cdapID.MatchString(id) {
					err = fmt.Errorf("invalid CDAP connection identity")
					continue
				}
				if seen[id] {
					err = fmt.Errorf("duplicated CDAP connection identity; inventory is incomplete")
					continue
				}
				seen[id] = true
				if e := budget.takeResource(); e != nil {
					err = e
					break
				}
				resource := "//datafusion.googleapis.com/" + b.instance + "/namespaces/" + namespace + "/connections/" + id
				c.SecretCapture.CaptureStringMap("datafusion_connection_config", resource, region, "plugin.properties", Get(d, "plugin", "properties"))
				out.Assets = append(out.Assets, cdapMetadataAsset(resource, DataFusionConnectionType, region, namespace, b))
				count++
			}
		}
	}
	out.record("viewer-datafusion:cdap-connections:"+b.instance+":"+namespace, count, err)
}

func (c *Client) viewerCDAPPipelines(ctx context.Context, out *Snapshot, b cdapBinding, namespace, region string, budget *secretCollectionBudget) {
	raw, err := c.cdapRead(ctx, b, "/v3/namespaces/"+namespace+"/apps", budget)
	if err != nil {
		out.record("viewer-datafusion:cdap-pipelines:"+b.instance+":"+namespace, 0, err)
		return
	}
	rows, ok := raw.([]any)
	if !ok || len(rows) > 10000 {
		out.record("viewer-datafusion:cdap-pipelines:"+b.instance+":"+namespace, 0, fmt.Errorf("invalid or oversized CDAP application list"))
		return
	}
	seen := map[string]bool{}
	for _, row := range rows {
		d := Obj(row)
		id := Str(d["name"])
		artifact := Str(Get(d, "artifact", "name"))
		if artifact != "cdap-data-pipeline" && artifact != "cdap-data-streams" {
			continue
		}
		if !cdapID.MatchString(id) {
			out.record("viewer-datafusion:cdap-identity:"+b.instance, 0, fmt.Errorf("invalid CDAP pipeline identity"))
			continue
		}
		if seen[id] {
			out.record("viewer-datafusion:cdap-identity:"+b.instance, 0, fmt.Errorf("duplicated CDAP pipeline identity/version; inventory is incomplete"))
			continue
		}
		seen[id] = true
		if err := budget.takeResource(); err != nil {
			out.record("viewer-datafusion:cdap-limit:"+b.instance, 0, err)
			return
		}
		full, e := c.cdapRead(ctx, b, "/v3/namespaces/"+namespace+"/apps/"+id, budget)
		count := 0
		if e == nil {
			app := Obj(full)
			if Str(app["name"]) != id {
				e = fmt.Errorf("mismatched CDAP pipeline detail identity")
			} else if text, ok := app["configuration"].(string); !ok || len(text) > 4<<20 {
				e = fmt.Errorf("missing or oversized CDAP pipeline configuration")
			} else {
				var config Object
				if json.Unmarshal([]byte(text), &config) != nil || config == nil {
					e = fmt.Errorf("invalid CDAP pipeline configuration JSON")
				} else {
					resource := "//datafusion.googleapis.com/" + b.instance + "/namespaces/" + namespace + "/pipelines/" + id
					c.SecretCapture.captureCDAPPipeline(resource, region, config)
					out.Assets = append(out.Assets, cdapMetadataAsset(resource, DataFusionPipelineType, region, namespace, b))
					count = 1
				}
			}
		}
		out.record("viewer-datafusion:cdap-pipeline:"+b.instance+":"+namespace+":"+id, count, e)
		if budget.exhausted {
			return
		}
	}
}

func (c *SecretCapture) captureCDAPPipeline(resource, region string, config Object) {
	c.CaptureStringMap("datafusion_pipeline_config", resource, region, "configuration.properties", config["properties"])
	for _, collection := range []string{"stages", "postActions"} {
		rows, _ := config[collection].([]any)
		if len(rows) > 10000 {
			c.Add(SecretSample{})
			continue
		}
		for i, row := range rows {
			c.CaptureStringMap("datafusion_pipeline_config", resource, region, fmt.Sprintf("configuration.%s[%d].plugin.properties", collection, i), Get(Obj(row), "plugin", "properties"))
		}
	}
}

func (c *SecretCapture) captureOfflineCDAP(a Asset) bool {
	if a.Type != DataFusionConnectionType && a.Type != DataFusionPipelineType {
		return false
	}
	collection := "connections"
	if a.Type == DataFusionPipelineType {
		collection = "pipelines"
	}
	if !regexp.MustCompile(`^//datafusion\.googleapis\.com/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/instances/[A-Za-z0-9_-]+/namespaces/[A-Za-z0-9_-]+/` + collection + `/[A-Za-z0-9_-]+$`).MatchString(a.Name) {
		return true
	}
	if collection == "connections" {
		c.CaptureStringMap("datafusion_connection_config", a.Name, a.Resource.Location, "plugin.properties", Get(a.Resource.Data, "plugin", "properties"))
	} else {
		config := Obj(a.Resource.Data["configuration"])
		if text, ok := a.Resource.Data["configuration"].(string); ok && len(text) <= 4<<20 {
			if json.Unmarshal([]byte(text), &config) != nil {
				return true
			}
		}
		if config != nil {
			c.captureCDAPPipeline(a.Name, a.Resource.Location, config)
		}
	}
	return true
}
