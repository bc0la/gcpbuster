package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// SecretSample is transient authorized configuration, not a Secret Manager payload.
type SecretSample struct {
	ID, SourceType, Resource, Location, Path string
	Data                                     []byte
}

// SecretCapture is deliberately separate from Snapshot and its persisted JSON.
type SecretCapture struct {
	mu                                        sync.Mutex
	maxSamples                                int
	maxSampleBytes, maxTotalBytes, totalBytes int64
	samples                                   []SecretSample
	seen                                      map[string]bool
	conflicts                                 map[string]bool
	rejected                                  int
}

func NewSecretCapture(maxSamples int, maxSampleBytes, maxTotalBytes int64) *SecretCapture {
	if maxSamples <= 0 {
		maxSamples = 10000
	}
	if maxSampleBytes <= 0 {
		maxSampleBytes = 4 << 20
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = 64 << 20
	}
	return &SecretCapture{maxSamples: maxSamples, maxSampleBytes: maxSampleBytes, maxTotalBytes: maxTotalBytes, seen: map[string]bool{}, conflicts: map[string]bool{}}
}

// Add copies an already scope-validated, explicitly selected configuration leaf.
// Limits reject whole samples, never silently truncate credential values.
func (c *SecretCapture) Add(s SecretSample) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.SourceType == "" || !strings.HasPrefix(s.Resource, "//") || s.Path == "" || len(s.Data) == 0 || int64(len(s.Data)) > c.maxSampleBytes {
		c.rejected++
		return false
	}
	h := sha256.New()
	for _, v := range []string{s.SourceType, s.Resource, s.Location, s.Path} {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	s.ID = hex.EncodeToString(h.Sum(nil))
	if c.conflicts[s.ID] {
		c.rejected++
		return false
	}
	if c.seen[s.ID] {
		for i, old := range c.samples {
			if old.ID == s.ID {
				if bytes.Equal(old.Data, s.Data) {
					return true
				}
				c.totalBytes -= int64(len(old.Data))
				c.samples = append(c.samples[:i], c.samples[i+1:]...)
				delete(c.seen, s.ID)
				c.conflicts[s.ID] = true
				c.rejected++
				return false
			}
		}
	}
	if int64(len(s.Data)) > c.maxTotalBytes-c.totalBytes || len(c.samples) >= c.maxSamples {
		c.rejected++
		return false
	}
	c.seen[s.ID] = true
	s.Data = append([]byte(nil), s.Data...)
	c.totalBytes += int64(len(s.Data))
	c.samples = append(c.samples, s)
	return true
}

func (c *SecretCapture) Samples() []SecretSample {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]SecretSample(nil), c.samples...)
	for i := range out {
		out[i].Data = append([]byte(nil), out[i].Data...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (c *SecretCapture) Coverage() []Coverage {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	status := "ok"
	detail := "Explicitly selected configuration samples retained transiently; no protected secret payload access or credential validation."
	if c.rejected > 0 {
		status = "incomplete"
		detail = fmt.Sprintf("%d configuration samples rejected by capture limits or malformed sample metadata; samples were not truncated.", c.rejected)
	}
	return []Coverage{{Source: "configuration-secret-capture", Status: status, Error: detail}}
}

func (c *SecretCapture) CaptureStringMap(source, resource, location, path string, value any) {
	if c == nil {
		return
	}
	m := Obj(value)
	for _, key := range sortedCaptureKeys(m) {
		if v, ok := m[key].(string); ok && v != "[REDACTED]" {
			c.Add(SecretSample{SourceType: source, Resource: resource, Location: location, Path: path + "." + key, Data: []byte(key + "=" + v)})
		}
	}
}

func sortedCaptureKeys(m Object) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (c *SecretCapture) captureOpenAPI(resource string, raw Object) {
	if c == nil {
		return
	}
	docs, _ := raw["openapiDocuments"].([]any)
	if len(docs) > 32 {
		c.Add(SecretSample{})
		return
	}
	remaining := 4 << 20
	for i, entry := range docs {
		encoded, ok := Get(Obj(entry), "document", "contents").(string)
		if !ok || len(encoded) > base64.StdEncoding.EncodedLen(remaining) {
			c.Add(SecretSample{})
			continue
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(data) > remaining || strings.IndexByte(string(data), 0) >= 0 {
			c.Add(SecretSample{})
			continue
		}
		remaining -= len(data)
		c.Add(SecretSample{SourceType: "apigateway_openapi", Resource: resource, Location: "global", Path: fmt.Sprintf("openapiDocuments[%d].document.contents", i), Data: data})
	}
}

func (c *SecretCapture) captureServiceConfig(resource string, raw Object) {
	if c == nil {
		return
	}
	// Only leaves present in viewerServiceConfigFields; never traverse unknown fields.
	for section, collection := range map[string]string{"authentication": "providers", "backend": "rules"} {
		rows, _ := Get(raw, section, collection).([]any)
		for i, row := range rows {
			for _, field := range map[string][]string{"authentication": {"id", "issuer"}, "backend": {"selector", "address", "jwtAudience"}}[section] {
				if v, ok := Obj(row)[field].(string); ok && v != "" {
					c.Add(SecretSample{SourceType: "service_management_config", Resource: resource, Path: fmt.Sprintf("%s.%s[%d].%s", section, collection, i, field), Data: []byte(v)})
				}
			}
		}
	}
}
