package inventory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Object = map[string]any

// Asset is the Cloud Asset Inventory wire format. Workspace records use
// workspace.googleapis.com/<kind> and the same resource.data envelope.
type Asset struct {
	Name     string `json:"name"`
	Type     string `json:"assetType"`
	Resource struct {
		Data     Object `json:"data"`
		Location string `json:"location,omitempty"`
	} `json:"resource"`
	IAM       Object   `json:"iamPolicy,omitempty"`
	Ancestors []string `json:"ancestors,omitempty"`
}

type Coverage struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Error  string `json:"error,omitempty"`
}

type Snapshot struct {
	Assets   []Asset    `json:"assets"`
	Coverage []Coverage `json:"coverage,omitempty"`
	// Authorized source files for matched secrets only, never snapshot exports.
	SecretArtifacts   map[string][]byte `json:"-"`
	SecretValueMode   string            `json:"-"`
	SecretFingerprint []byte            `json:"-"`
}

func NewAsset(name, kind string, data Object) Asset {
	a := Asset{Name: name, Type: kind}
	a.Resource.Data = data
	return a
}

// Load accepts CAI JSONL exports, JSON arrays, list responses, or snapshots.
// Malformed input is never silently ignored.
func Load(path string) (Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	var out Snapshot
	r := bufio.NewReader(f)
	dec := json.NewDecoder(r)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return out, fmt.Errorf("%s: %w", path, err)
		}
		if len(raw) == 0 {
			continue
		}
		if raw[0] == '[' {
			var assets []Asset
			if err := json.Unmarshal(raw, &assets); err != nil {
				return out, err
			}
			out.Assets = append(out.Assets, assets...)
		} else {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				return out, err
			}
			if _, ok := obj["assets"]; ok {
				var snap Snapshot
				if err := json.Unmarshal(raw, &snap); err != nil {
					return out, err
				}
				out.Assets = append(out.Assets, snap.Assets...)
				out.Coverage = append(out.Coverage, snap.Coverage...)
				var next string
				_ = json.Unmarshal(obj["nextPageToken"], &next)
				if next != "" {
					out.record(path+":pagination", len(snap.Assets), fmt.Errorf("input contains nextPageToken: this is an incomplete list response"))
				}
			} else {
				var a Asset
				if err := json.Unmarshal(raw, &a); err != nil {
					return out, err
				}
				out.Assets = append(out.Assets, a)
			}
		}
	}
	for i, a := range out.Assets {
		if a.Name == "" || a.Type == "" {
			return out, fmt.Errorf("%s: asset %d needs name and assetType", path, i+1)
		}
	}
	return out, nil
}

func Get(m Object, path ...string) any {
	var v any = m
	for _, key := range path {
		x, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = x[key]
	}
	return v
}
func Str(v any) string { s, _ := v.(string); return s }
func Bool(v any) bool  { b, _ := v.(bool); return b }
func Obj(v any) Object { m, _ := v.(map[string]any); return m }
func List(v any) []any { a, _ := v.([]any); return a }
