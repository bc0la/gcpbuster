package main

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestParameterTemplateManualRefetchUsesRawDocumentedGET(t *testing.T) {
	for _, region := range []string{"global", "us-central1"} {
		s := inventory.SecretSample{SourceType: "parameter_template_raw", Resource: "//parametermanager.googleapis.com/projects/123/locations/" + region + "/templates/t/versions/v", Location: region, Path: "payload.data"}
		endpoint, q := secretRefetchRequest(s)
		if endpoint != "https://parametermanager.googleapis.com/v1/projects/123/locations/"+region+"/templates/t/versions/v" || q.Get("fields") != "name,payload(data)" || q.Has("view") {
			t.Fatal(endpoint, q)
		}
		command := secretPullCommand(s)
		if command == "" || strings.Contains(command, ":render") || strings.Contains(command, "view=FULL") {
			t.Fatal(command)
		}
	}
}
