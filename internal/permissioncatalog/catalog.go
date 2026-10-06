// Package permissioncatalog retains the exact, versioned classification source
// from HackTricks Cloud. A permission's risk rating is not proof of exploitation.
package permissioncatalog

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed gcp.yaml
var source []byte

type Catalog struct {
	Version        int                   `yaml:"version"`
	Provider       string                `yaml:"provider"`
	Categories     map[string][]string   `yaml:"permission_categories"`
	Combinations   map[string][][]string `yaml:"combinations"`
	NonPermissions []string              `yaml:"non_permission_identifiers"`
}

var Data = parse()
var ratings = index()
var digest = fmt.Sprintf("%x", sha256.Sum256(source))

func parse() Catalog {
	var c Catalog
	if err := yaml.Unmarshal(source, &c); err != nil {
		panic(err)
	}
	if c.Provider != "gcp" || len(c.Categories) == 0 {
		panic("invalid embedded GCP permission catalog")
	}
	return c
}
func index() map[string]string {
	out := map[string]string{}
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		for _, p := range Data.Categories[sev] {
			if prior, ok := out[p]; ok {
				panic(fmt.Sprintf("duplicate permission %s (%s, %s)", p, prior, sev))
			}
			out[p] = sev
		}
	}
	for _, p := range Data.NonPermissions {
		delete(out, p)
	}
	out[supplementalManagedRotation] = "high"
	return out
}

// Supplemental reviewed capability impact; the pinned upstream catalog is
// preserved verbatim. This never authorizes issuing the mutating operation.
// https://docs.cloud.google.com/go/docs/reference/cloud.google.com/go/secretmanager/latest/apiv1
const supplementalManagedRotation = "secretmanager.secrets.enableManagedRotation"

func Severity(permission string) (string, bool) {
	v, ok := ratings[permission]
	return v, ok
}
func Count() int     { return len(ratings) }
func SHA256() string { return digest }
func Permissions() []string {
	out := make([]string, 0, len(ratings))
	for p := range ratings {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
func Match(pattern, permission string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(permission, pattern[1:])
	}
	return pattern == permission
}
