package inventory

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

type apigeeConfigurationMember struct {
	name string
	body []byte
}

var apigeeCaptureRevision = regexp.MustCompile(`^organizations/[A-Za-z0-9_-]+/(apis|sharedflows)/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}/revisions/[1-9][0-9]{0,18}$`)
var apigeeCaptureMember = regexp.MustCompile(`^(apiproxy|sharedflowbundle)/(policies|proxies|targets|sharedflows)/[A-Za-z0-9_. -]{1,255}\.xml$`)
var apigeeCaptureKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$`)

// Collection shares the authorization parser's complete ZIP/XML validation.
// Nothing is added until the entire archive and authentication projection pass.
// Only reviewed configuration XML is scanned; resources/code/images are excluded.
func (c *Client) projectApigeeBundleCapture(raw []byte, revision string) (Object, []ApigeeFlowReference, error) {
	refs := []ApigeeFlowReference{}
	if c.SecretCapture == nil {
		return projectApigeeBundleWithReferences(raw)
	}
	if !apigeeCaptureRevision.MatchString(revision) {
		return nil, nil, fmt.Errorf("invalid Apigee capture identity")
	}
	members := []apigeeConfigurationMember{}
	projection, err := projectApigeeBundleInternal(raw, &refs, &members)
	if err != nil {
		return projection, nil, err
	}
	samples := []SecretSample{}
	for _, member := range members {
		if !apigeeCaptureMember.MatchString(member.name) {
			return projection, nil, fmt.Errorf("unsupported Apigee configuration member identity")
		}
		if strings.Contains(revision, "/apis/") != strings.HasPrefix(member.name, "apiproxy/") {
			return projection, nil, fmt.Errorf("Apigee configuration kind mismatch")
		}
		path := "bundle[" + member.name + "].xml"
		samples = append(samples, SecretSample{SourceType: "apigee_bundle_config", Resource: "//apigee.googleapis.com/" + revision, Path: path, Data: member.body})
		leaves, err := apigeeConfigurationLeaves(member.body)
		if err != nil {
			return projection, nil, fmt.Errorf("invalid Apigee configuration values")
		}
		for i, leaf := range leaves {
			samples = append(samples, SecretSample{SourceType: "apigee_bundle_config", Resource: "//apigee.googleapis.com/" + revision, Path: fmt.Sprintf("%s.elements[%d].%s", path, i, leaf.key), Data: []byte(leaf.key + "=" + leaf.value)})
		}
	}
	for _, sample := range samples {
		if !c.SecretCapture.Add(sample) {
			return projection, refs, fmt.Errorf("Apigee configuration capture limit or conflicting source")
		}
	}
	return projection, refs, nil
}

// Manual report text only; no request is executed. Operator extracts the named
// reviewed XML member locally from this exact revision bundle, never runs it.
func ApigeeSecretRefetchRequest(sample SecretSample) (string, url.Values) {
	name := strings.TrimPrefix(sample.Resource, "//apigee.googleapis.com/")
	if sample.SourceType != "apigee_bundle_config" || !strings.HasPrefix(sample.Resource, "//apigee.googleapis.com/") || !apigeeCaptureRevision.MatchString(name) || sample.Location != "" {
		return "", nil
	}
	end := strings.Index(sample.Path, "].xml")
	if !strings.HasPrefix(sample.Path, "bundle[") || end < 0 {
		return "", nil
	}
	member := sample.Path[len("bundle["):end]
	if !apigeeCaptureMember.MatchString(member) || strings.Contains(name, "/apis/") != strings.HasPrefix(member, "apiproxy/") {
		return "", nil
	}
	suffix := sample.Path[end+len("].xml"):]
	if suffix != "" && !regexp.MustCompile(`^\.elements\[[0-9]+\]\.[A-Za-z_][A-Za-z0-9_.:-]{0,127}$`).MatchString(suffix) {
		return "", nil
	}
	return "https://apigee.googleapis.com/v1/" + name, url.Values{"format": {"bundle"}}
}

type apigeeConfigurationLeaf struct{ key, value string }

func apigeeConfigurationLeaves(raw []byte) ([]apigeeConfigurationLeaf, error) {
	type element struct {
		key      string
		text     strings.Builder
		children int
	}
	stack := []*element{}
	leaves := []apigeeConfigurationLeaf{}
	d := xml.NewDecoder(bytes.NewReader(raw))
	for tokens := 0; ; tokens++ {
		if tokens > 100000 {
			return nil, fmt.Errorf("XML token limit")
		}
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if len(stack) > 127 {
				return nil, fmt.Errorf("XML depth limit")
			}
			if len(stack) > 0 {
				stack[len(stack)-1].children++
			}
			key := t.Name.Local
			for _, a := range t.Attr {
				if apigeeCaptureKey.MatchString(a.Name.Local) && a.Name.Local != "name" && a.Value != "" {
					leaves = append(leaves, apigeeConfigurationLeaf{a.Name.Local, a.Value})
				}
				if a.Name.Local == "name" && apigeeCaptureKey.MatchString(a.Value) {
					key = a.Value
				}
			}
			stack = append(stack, &element{key: key})
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("XML nesting")
			}
			e := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if e.children == 0 && apigeeCaptureKey.MatchString(e.key) && e.text.Len() > 0 {
				leaves = append(leaves, apigeeConfigurationLeaf{e.key, e.text.String()})
			}
		}
	}
	return leaves, nil
}
