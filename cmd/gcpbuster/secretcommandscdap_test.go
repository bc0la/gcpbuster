package main

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"strings"
	"testing"
)

func TestCDAPManualRefetchRequiresMatchingMetadataProvenance(t *testing.T) {
	const instance = "projects/123/locations/us-central1/instances/etl"
	for _, source := range []string{"datafusion_connection_config", "datafusion_pipeline_config"} {
		kind, collection := inventory.DataFusionConnectionType, "connections"
		if source == "datafusion_pipeline_config" {
			kind = inventory.DataFusionPipelineType
			collection = "pipelines"
		}
		resource := "//datafusion.googleapis.com/" + instance + "/namespaces/default/" + collection + "/config"
		sample := inventory.SecretSample{SourceType: source, Resource: resource, Location: "us-central1", Data: []byte("SECRET_SENTINEL")}
		makeAsset := func() inventory.Asset {
			a := inventory.NewAsset(resource, kind, inventory.Object{"name": resource, "instance": instance, "namespace": "default", "apiEndpoint": "https://etl-demo.datafusion.googleusercontent.com/api"})
			a.Resource.Location = "us-central1"
			return a
		}
		if secretPullCommandFromAssets(sample, nil) != "" {
			t.Fatal("missing metadata accepted")
		}
		command := secretPullCommandFromAssets(sample, []inventory.Asset{makeAsset()})
		if command == "" || !strings.Contains(command, "--request GET") || strings.Contains(command, "--location") || strings.Contains(command, "SECRET_SENTINEL") || strings.Contains(command, "securekeys") {
			t.Fatal(command)
		}
		if collection == "pipelines" && !strings.Contains(command, "/v3/namespaces/default/apps/config") {
			t.Fatal(command)
		}
		if collection == "connections" && !strings.Contains(command, "/contexts/default/connections") {
			t.Fatal(command)
		}
		for _, change := range []string{"unknown", "name", "instance", "namespace", "location", "http", "foreignhost", "query", "user", "port", "path", "encodedpath"} {
			a := makeAsset()
			switch change {
			case "unknown":
				a.Type = "unknown"
			case "name":
				a.Resource.Data["name"] = "other"
			case "instance":
				a.Resource.Data["instance"] = "projects/999/locations/us-central1/instances/etl"
			case "namespace":
				a.Resource.Data["namespace"] = "other"
			case "location":
				a.Resource.Location = "us-east1"
			case "http":
				a.Resource.Data["apiEndpoint"] = "http://etl-demo.datafusion.googleusercontent.com/api"
			case "foreignhost":
				a.Resource.Data["apiEndpoint"] = "https://attacker.invalid/api"
			case "query":
				a.Resource.Data["apiEndpoint"] = "https://etl-demo.datafusion.googleusercontent.com/api?next=evil"
			case "user":
				a.Resource.Data["apiEndpoint"] = "https://user@etl-demo.datafusion.googleusercontent.com/api"
			case "port":
				a.Resource.Data["apiEndpoint"] = "https://etl-demo.datafusion.googleusercontent.com:443/api"
			case "path":
				a.Resource.Data["apiEndpoint"] = "https://etl-demo.datafusion.googleusercontent.com/api/v3/securekeys"
			case "encodedpath":
				a.Resource.Data["apiEndpoint"] = "https://etl-demo.datafusion.googleusercontent.com/%61pi"
			}
			if command := secretPullCommandFromAssets(sample, []inventory.Asset{a}); command != "" {
				t.Fatal("unsafe metadata accepted", change, command)
			}
		}
	}
}
