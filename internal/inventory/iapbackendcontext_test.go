package inventory

import (
	"reflect"
	"testing"
)

func contextBackend(name, typ, id string, enabled any) Asset {
	a := NewAsset(name, typ, Object{"name": "web", "id": id, "iap": Object{"enabled": enabled}, "protocol": "HTTPS", "loadBalancingScheme": "EXTERNAL_MANAGED", "oauth2ClientSecret": "SENTINEL"})
	a.Ancestors = []string{"projects/123"}
	return a
}
func contextIAPGrant(resource string) Asset {
	return NewAsset("grant", PermissionGrantType, Object{"resourceType": "iap.googleapis.com/PolicyResource", "resource": resource, "condition": Object{"expression": "true"}, "principal": "allUsers"})
}
func TestIAPBackendContextExactGlobalRegionalAndAlias(t *testing.T) {
	p := NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", Object{"name": "projects/123", "projectId": "demo"})
	global := contextBackend("//compute.googleapis.com/projects/demo/global/backendServices/web", "compute.googleapis.com/BackendService", "18446744073709551615", true)
	regional := contextBackend("//compute.googleapis.com/projects/123/regions/us-east1/backendServices/web", "compute.googleapis.com/RegionBackendService", "42", false)
	g := contextIAPGrant("//iap.googleapis.com/projects/123/iap_web/compute/services/18446744073709551615")
	r := contextIAPGrant("//iap.googleapis.com/projects/123/iap_web/compute-us-east1/services/42")
	s := Snapshot{Assets: []Asset{p, global, regional, g, r}}
	CorrelateIAPBackendContext(&s)
	for i, enabled := range []bool{true, false} {
		c := Obj(s.Assets[i+3].Resource.Data["_gcpbusterIAPBackendContext"])
		if c["status"] != "observed" || c["iap_enabled"] != enabled || c["oauth2ClientSecret"] != nil {
			t.Fatal(c)
		}
		if !reflect.DeepEqual(s.Assets[i+3].Resource.Data["condition"], Object{"expression": "true"}) {
			t.Fatal("condition changed")
		}
	}
}
func TestIAPBackendContextMissingAmbiguousAndNoParentExpansion(t *testing.T) {
	path := "//compute.googleapis.com/projects/123/global/backendServices/web"
	policy := "//iap.googleapis.com/projects/123/iap_web/compute/services/42"
	for _, mode := range []string{"missing_id", "foreign", "ambiguous", "no_alias", "conflicting_ancestor", "wrong_type"} {
		b := contextBackend(path, "compute.googleapis.com/BackendService", "42", true)
		assets := []Asset{b}
		switch mode {
		case "missing_id":
			delete(assets[0].Resource.Data, "id")
		case "foreign":
			assets[0].Ancestors = []string{"projects/999"}
		case "ambiguous":
			assets = append(assets, contextBackend(path, "compute.googleapis.com/BackendService", "42", false))
		case "no_alias":
			assets[0].Name = "//compute.googleapis.com/projects/demo/global/backendServices/web"
		case "conflicting_ancestor":
			assets[0].Ancestors = append(assets[0].Ancestors, "projects/999")
		case "wrong_type":
			assets[0].Type = "compute.googleapis.com/RegionBackendService"
		}
		s := Snapshot{Assets: append(assets, contextIAPGrant(policy))}
		CorrelateIAPBackendContext(&s)
		c := Obj(s.Assets[len(s.Assets)-1].Resource.Data["_gcpbusterIAPBackendContext"])
		want := "missing_context"
		if mode == "ambiguous" {
			want = "ambiguous"
		}
		if c["status"] != want {
			t.Fatal(mode, c)
		}
	}
	for _, p := range []string{"//iap.googleapis.com/projects/123/iap_web/compute", "//iap.googleapis.com/projects/123/iap_web/compute/services/042", "//iap.googleapis.com/projects/123/iap_web/compute/services/18446744073709551616"} {
		g := contextIAPGrant(p)
		g.Resource.Data["_gcpbusterIAPBackendContext"] = Object{"status": "observed"}
		s := Snapshot{Assets: []Asset{g}}
		CorrelateIAPBackendContext(&s)
		if s.Assets[0].Resource.Data["_gcpbusterIAPBackendContext"] != nil {
			t.Fatal(p)
		}
	}
}

func TestIAPBackendContextNamesExplicitScopeAndMissingID(t *testing.T) {
	p := NewAsset("//cloudresourcemanager.googleapis.com/projects/123", "cloudresourcemanager.googleapis.com/Project", Object{"name": "projects/123", "projectId": "demo"})
	for _, regional := range []bool{false, true} {
		scope, typ, iap := "global", "compute.googleapis.com/BackendService", "compute"
		if regional {
			scope, typ, iap = "regions/us-east1", "compute.googleapis.com/RegionBackendService", "compute-us-east1"
		}
		b := contextBackend("//compute.googleapis.com/projects/demo/"+scope+"/backendServices/web", typ, "42", true)
		for _, hasID := range []bool{true, false} {
			if !hasID {
				delete(b.Resource.Data, "id")
			}
			binding := "//iap.googleapis.com/projects/123/iap_web/" + iap + "/services/web"
			s := Snapshot{Assets: []Asset{p, b, contextIAPGrant(binding), contextIAPGrant("//iap.googleapis.com/projects/999/iap_web/" + iap + "/services/web")}}
			CorrelateIAPBackendContext(&s)
			c := Obj(s.Assets[2].Resource.Data["_gcpbusterIAPBackendContext"])
			if c["status"] != "observed" || c["scope"] != "exact_backend_name_metadata" || c["binding_resource"] != binding || c["project_number"] != "projects/123" {
				t.Fatal(c)
			}
			if (c["backend_id"] != nil) != hasID {
				t.Fatal(c)
			}
			if Obj(s.Assets[3].Resource.Data["_gcpbusterIAPBackendContext"])["status"] != "missing_context" {
				t.Fatal(s)
			}
		}
	}
	b := contextBackend("//compute.googleapis.com/projects/demo/global/backendServices/web", "compute.googleapis.com/BackendService", "42", true)
	conflict := contextBackend(b.Name, b.Type, "99", true)
	binding := "//iap.googleapis.com/projects/123/iap_web/compute/services/web"
	s := Snapshot{Assets: []Asset{p, b, conflict, b, contextIAPGrant(binding)}}
	CorrelateIAPBackendContext(&s)
	if Obj(s.Assets[4].Resource.Data["_gcpbusterIAPBackendContext"])["status"] != "ambiguous" {
		t.Fatal(s)
	}
}

func TestViewerComputeIDUint64Only(t *testing.T) {
	for _, v := range []any{"0", "42", "18446744073709551615"} {
		if _, ok := viewerComputeUint64(v); !ok {
			t.Fatal(v)
		}
	}
	for _, v := range []any{nil, 42, float64(42), "042", "-1", "+1", "18446744073709551616", "1e3", ""} {
		if _, ok := viewerComputeUint64(v); ok {
			t.Fatal(v)
		}
	}
}
