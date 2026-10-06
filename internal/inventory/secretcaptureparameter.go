package inventory

import (
	"regexp"
	"strings"
)

// Offline parameter payloads are explicitly supplied evidence, not authority to
// render parameters or fetch referenced Secret Manager versions.
func (c *SecretCapture) captureOfflineParameter(a Asset) bool {
	if a.Type != "parametermanager.googleapis.com/ParameterVersion" {
		return false
	}
	if !regexp.MustCompile(`^//parametermanager\.googleapis\.com/projects/[A-Za-z0-9_-]+/locations/[a-z][a-z0-9-]*/parameters/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+$`).MatchString(a.Name) {
		return true
	}
	name := strings.TrimPrefix(a.Name, "//parametermanager.googleapis.com/")
	parts := strings.Split(name, "/")
	client := Client{SecretCapture: c}
	if err := client.captureParameterVersion(a.Resource.Data, name, parts[3], parts[1], "projects/"+parts[1]); err != nil {
		c.mu.Lock()
		c.rejected++
		c.mu.Unlock()
	}
	return true
}
