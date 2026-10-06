package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"testing"
	"time"
)

func TestPublicHealthcareCapabilitiesScopeAndOAuth(t *testing.T) {
	for _, tc := range []struct {
		collection, typ, permission string
		want                        int
	}{
		{"fhirStores/s", "FhirStore", "healthcare.fhirResources.get", 1},
		{"fhirStores/s", "FhirStore", "healthcare.dicomStores.dicomWebRead", 0},
		{"dicomStores/s", "DicomStore", "healthcare.dicomStores.dicomWebRead", 1},
		{"hl7V2Stores/s", "Hl7V2Store", "healthcare.hl7V2Messages.list", 1},
		{"", "Dataset", "healthcare.fhirStores.searchResources", 1},
		{"fhirStores/s", "Dataset", "healthcare.fhirResources.get", 0},
	} {
		resource := "//healthcare.googleapis.com/projects/demo/locations/us-central1/datasets/data"
		if tc.collection != "" {
			resource += "/" + tc.collection
		}
		a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": resource, "resourceType": "healthcare.googleapis.com/" + tc.typ, "principal": "allAuthenticatedUsers", "permissions": []any{tc.permission, tc.permission}})
		got := publicHealthcareCapabilities(a, time.Now())
		if len(got) != tc.want {
			t.Fatal(tc, got)
		}
		if len(got) > 0 && got[0].Evidence["principal"] != "allAuthenticatedUsers" {
			t.Fatal(got)
		}
		a.Resource.Data["principal"] = "user:one@example.test"
		if len(publicHealthcareCapabilities(a, time.Now())) != 0 {
			t.Fatal("nonpublic")
		}
	}
}

func TestPublicHealthcareConditionalAndMalformed(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//healthcare.googleapis.com/projects/demo/locations/us-central1/datasets/data/fhirStores/s", "resourceType": "healthcare.googleapis.com/FhirStore", "principal": "allUsers", "permissions": []any{"healthcare.fhirResources.get"}, "condition": inventory.Object{"expression": "true"}})
	got := publicHealthcareCapabilities(a, time.Now())
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatal(got)
	}
	a.Resource.Data["resource"] = "//healthcare.googleapis.com/projects/demo/locations/us-central1/datasets/data/fhirStores/s/fhir/Patient/1"
	if len(publicHealthcareCapabilities(a, time.Now())) != 0 {
		t.Fatal("clinical path accepted")
	}
}

func TestPublicHealthcareUnicodeAndProjectScope(t *testing.T) {
	a := inventory.NewAsset("grant", inventory.PermissionGrantType, inventory.Object{"resource": "//healthcare.googleapis.com/projects/demo/locations/us-central1/datasets/病院/fhirStores/.store", "resourceType": "healthcare.googleapis.com/FhirStore", "principal": "allAuthenticatedUsers", "permissions": []any{"healthcare.fhirResources.get"}})
	if len(publicHealthcareCapabilities(a, time.Now())) != 1 {
		t.Fatal("documented identifier alphabet")
	}
	a.Resource.Data["resource"] = "//cloudresourcemanager.googleapis.com/projects/123"
	a.Resource.Data["resourceType"] = "cloudresourcemanager.googleapis.com/Project"
	got := publicHealthcareCapabilities(a, time.Now())
	if len(got) != 1 || got[0].Evidence["binding_scope"] != "project" {
		t.Fatal(got)
	}
}
