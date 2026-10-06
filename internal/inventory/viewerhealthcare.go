package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const viewerHealthcareLocationFields = "locations(name,locationId),nextPageToken"
const viewerHealthcareDatasetFields = "datasets(name),nextPageToken"
const viewerHealthcarePolicyFields = "version,bindings,etag"

var viewerHealthcareID = regexp.MustCompile(`^[\p{L}\p{N}_.-]{1,256}$`)

func viewerHealthcareStoreFields(collection string) string {
	return collection + "(name),nextPageToken"
}

func canonicalHealthcareName(raw, projectID, number, collection string) (string, bool) {
	p := strings.Split(raw, "/")
	want := 6
	if collection != "datasets" {
		want = 8
	}
	if len(p) != want || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || !viewerLocation.MatchString(p[3]) || p[3] == "global" || p[4] != "datasets" || !viewerHealthcareID.MatchString(p[5]) || p[5] == "." || p[5] == ".." {
		return "", false
	}
	if want == 8 && (p[6] != collection || !viewerHealthcareID.MatchString(p[7]) || p[7] == "." || p[7] == "..") {
		return "", false
	}
	p[1] = projectID
	return strings.Join(p, "/"), true
}

// Only resource identities and direct policies are read. Clinical endpoints
// and resource payloads are never requested, even when Viewer permits a read.
func (c *Client) CollectViewerHealthcare(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-healthcare:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	locations := []string{}
	seenLocations := map[string]bool{}
	partial := false
	err := c.viewerPages(ctx, "https://healthcare.googleapis.com/v1/projects/"+projectID+"/locations", url.Values{"fields": {viewerHealthcareLocationFields}, "pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			p := strings.Split(Str(d["name"]), "/")
			location := Str(d["locationId"])
			if len(p) != 4 || p[0] != "projects" || (p[1] != projectID && "projects/"+p[1] != number) || p[2] != "locations" || p[3] != location || !viewerLocation.MatchString(location) || location == "global" {
				partial = true
				continue
			}
			if !seenLocations[location] {
				seenLocations[location] = true
				locations = append(locations, location)
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("some Healthcare locations malformed or foreign")
	}
	out.record("viewer-healthcare:locations:"+projectID, len(locations), err)
	collect := func(parent, collection, kind, fields string) []string {
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		names := []string{}
		err := c.viewerPages(ctx, "https://healthcare.googleapis.com/v1/"+parent+"/"+collection, url.Values{"fields": {fields}, "pageSize": {"100"}}, func(page Object) error {
			rows, err := viewerRows(page, collection)
			if err != nil {
				return err
			}
			for _, raw := range rows {
				name, ok := canonicalHealthcareName(Str(Obj(raw)["name"]), projectID, number, collection)
				if !ok || !strings.HasPrefix(name, parent+"/"+collection+"/") || seen[name] {
					partial = true
					continue
				}
				seen[name] = true
				names = append(names, name)
				a := NewAsset("//healthcare.googleapis.com/"+name, "healthcare.googleapis.com/"+kind, Object{"name": name})
				a.Ancestors = []string{number}
				a.Resource.Location = strings.Split(name, "/")[3]
				policy, err := c.get(ctx, "https://healthcare.googleapis.com/v1/"+name+":getIamPolicy", url.Values{"options.requestedPolicyVersion": {"3"}, "fields": {viewerHealthcarePolicyFields}})
				if err == nil {
					a.IAM, err = viewerLogViewPolicy(policy)
				}
				count := 0
				if err == nil {
					count = 1
				}
				out.record("viewer-healthcare:iam:"+name, count, err)
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some Healthcare resource identities malformed, duplicated or foreign")
		}
		out.record("viewer-healthcare:"+collection+":"+parent, len(out.Assets)-start, err)
		return names
	}
	for _, location := range locations {
		datasets := collect("projects/"+projectID+"/locations/"+location, "datasets", "Dataset", viewerHealthcareDatasetFields)
		for _, dataset := range datasets {
			for _, spec := range []struct{ collection, kind string }{{"fhirStores", "FhirStore"}, {"dicomStores", "DicomStore"}, {"hl7V2Stores", "Hl7V2Store"}} {
				collect(dataset, spec.collection, spec.kind, viewerHealthcareStoreFields(spec.collection))
			}
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-healthcare:limitations:" + projectID, Status: "notice", Error: "Dataset/FHIR/DICOM/HL7v2 resource names and direct version-3 IAM only. No clinical resources, images, messages, searches, exports or mutations. Direct policies exclude inherited permissions and effective conditions/deny/perimeter evaluation; OAuth-authenticated broad grants do not establish tokenless access."})
}
