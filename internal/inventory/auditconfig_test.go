package inventory

import "testing"

func auditContainer(name, kind, parent string, policy Object) Asset {
	a := NewAsset("//cloudresourcemanager.googleapis.com/"+name, "cloudresourcemanager.googleapis.com/"+kind, Object{"parent": parent})
	a.IAM = policy
	return a
}
func auditPolicy(service, typ string, members ...any) Object {
	return Object{"auditConfigs": []any{Object{"service": service, "auditLogConfigs": []any{Object{"logType": typ, "exemptedMembers": members}}}}}
}
func TestAuditInheritanceUnionsTypesAndExemptions(t *testing.T) {
	s := Snapshot{Assets: []Asset{
		auditContainer("projects/1", "Project", "folders/2", auditPolicy("storage.googleapis.com", "DATA_WRITE", "user:local@example.com")),
		auditContainer("folders/2", "Folder", "organizations/3", auditPolicy("allServices", "DATA_READ", "user:folder@example.com")),
		auditContainer("organizations/3", "Organization", "", auditPolicy("allServices", "DATA_WRITE", "user:org@example.com")),
	}}
	ResolveAuditConfigs(&s)
	d := s.Assets[3].Resource.Data
	if !Bool(d["complete"]) || len(List(d["chain"])) != 3 {
		t.Fatal(d)
	}
	found := false
	for _, v := range List(d["configs"]) {
		c := Obj(v)
		if Str(c["service"]) == "storage.googleapis.com" && Str(c["logType"]) == "DATA_WRITE" {
			found = true
			if len(List(c["exemptedMembers"])) != 2 || len(List(c["sources"])) != 2 {
				t.Fatal(c)
			}
		}
	}
	if !found {
		t.Fatal("service/allServices union missing")
	}
}

func TestAuditMissingAncestorAndMalformedEvidence(t *testing.T) {
	for _, parent := range []string{"folders/missing", "projects/1"} {
		s := Snapshot{Assets: []Asset{auditContainer("projects/1", "Project", parent, Object{})}}
		ResolveAuditConfigs(&s)
		if Bool(s.Assets[1].Resource.Data["complete"]) || len(s.Coverage) == 0 {
			t.Fatal(s)
		}
	}
	s := Snapshot{Assets: []Asset{auditContainer("organizations/1", "Organization", "", Object{"auditConfigs": []any{Object{"service": "allServices", "auditLogConfigs": []any{Object{"logType": "DATA_READ", "exemptedMembers": 42}}}}})}}
	ResolveAuditConfigs(&s)
	if Bool(s.Assets[1].Resource.Data["complete"]) {
		t.Fatal("malformed exemptions treated complete")
	}
}

func TestAuditCAIAncestorChain(t *testing.T) {
	p := Asset{Name: "//cloudresourcemanager.googleapis.com/projects/1", Type: "cloudresourcemanager.googleapis.com/Project", IAM: Object{}, Ancestors: []string{"projects/1", "organizations/2"}}
	s := Snapshot{Assets: []Asset{p, auditContainer("organizations/2", "Organization", "", Object{})}}
	ResolveAuditConfigs(&s)
	if !Bool(s.Assets[2].Resource.Data["complete"]) {
		t.Fatal(s)
	}
	s = Snapshot{Assets: []Asset{{Name: p.Name, Type: p.Type, IAM: Object{}}}}
	ResolveAuditConfigs(&s)
	if Bool(s.Assets[1].Resource.Data["complete"]) {
		t.Fatal("unknown topology marked complete")
	}
}

func TestAuditIndexedBindingsAreNotCompletePolicies(t *testing.T) {
	s := Snapshot{Assets: []Asset{auditContainer("organizations/1", "Organization", "", Object{"_gcpbusterBindingsOnly": true, "bindings": []any{}})}}
	ResolveAuditConfigs(&s)
	if len(s.Assets) != 2 || Bool(s.Assets[1].Resource.Data["complete"]) || len(s.Coverage) == 0 {
		t.Fatal("indexed bindings cannot establish absent audit configuration", s)
	}
}

func TestAuditMalformedTopologyNeverProvesAbsence(t *testing.T) {
	for _, ancestors := range [][]string{
		{"projects/1", "organizations/2", "organizations/3"},
		{"projects/1", "organizations/2", "folders/4", "organizations/3"},
		{"projects/1", "projects/1", "organizations/2"},
		{"folders/4", "projects/1", "organizations/2"},
	} {
		p := Asset{Name: "//cloudresourcemanager.googleapis.com/projects/1", Type: "cloudresourcemanager.googleapis.com/Project", IAM: Object{}, Ancestors: ancestors}
		s := Snapshot{Assets: []Asset{p, auditContainer("organizations/2", "Organization", "", Object{}), auditContainer("organizations/3", "Organization", "", Object{}), auditContainer("folders/4", "Folder", "organizations/3", Object{})}}
		ResolveAuditConfigs(&s)
		if Bool(s.Assets[4].Resource.Data["complete"]) {
			t.Fatal("malformed topology marked complete", ancestors, s.Assets[4])
		}
	}
	for _, a := range []Asset{
		auditContainer("organizations/2", "Organization", "organizations/3", Object{}),
		auditContainer("organizations/2", "Project", "", Object{}),
	} {
		s := Snapshot{Assets: []Asset{a}}
		ResolveAuditConfigs(&s)
		if Bool(s.Assets[1].Resource.Data["complete"]) {
			t.Fatal(s)
		}
	}
}

func TestAuditConflictingParentEvidenceNeverProvesAbsence(t *testing.T) {
	p := Asset{Name: "//cloudresourcemanager.googleapis.com/projects/1", Type: "cloudresourcemanager.googleapis.com/Project", IAM: Object{}, Ancestors: []string{"projects/1", "folders/2", "organizations/3"}}
	s := Snapshot{Assets: []Asset{p, auditContainer("folders/2", "Folder", "organizations/4", Object{}), auditContainer("organizations/3", "Organization", "", Object{})}}
	ResolveAuditConfigs(&s)
	if Bool(s.Assets[3].Resource.Data["complete"]) {
		t.Fatal(s)
	}
	p.Resource.Data = Object{"parent": ""} // Claims no parent despite supplied ancestors.
	s = Snapshot{Assets: []Asset{p}}
	ResolveAuditConfigs(&s)
	if Bool(s.Assets[1].Resource.Data["complete"]) {
		t.Fatal(s)
	}
	s = Snapshot{Assets: []Asset{auditContainer("projects/1", "Project", "", auditPolicy("allServices", "DATA_READ")), auditContainer("projects/1", "Project", "", Object{})}}
	ResolveAuditConfigs(&s)
	for _, a := range s.Assets[2:] {
		if Bool(a.Resource.Data["complete"]) {
			t.Fatal("conflicting duplicate policy marked complete", a)
		}
	}
}

func TestAuditMalformedServiceAndPolicyMarkersNeverProveAbsence(t *testing.T) {
	for _, policy := range []Object{
		auditPolicy("secretmanager.googleapis.com ", "DATA_READ"),
		auditPolicy("allservices", "DATA_READ"),
		auditPolicy("allServices", "DATA_READ", " "),
		{"_gcpbusterBindingsOnly": "true"},
		{"_gcpbusterBindingsOnly": nil},
	} {
		s := Snapshot{Assets: []Asset{auditContainer("organizations/1", "Organization", "", policy)}}
		ResolveAuditConfigs(&s)
		if Bool(s.Assets[1].Resource.Data["complete"]) {
			t.Fatal(policy, s)
		}
	}
}

func TestAuditNoOrganizationAndPartialAncestorPolicy(t *testing.T) {
	// Explicitly parentless projects can establish a complete local-only chain.
	s := Snapshot{Assets: []Asset{auditContainer("projects/1", "Project", "", Object{})}}
	ResolveAuditConfigs(&s)
	if !Bool(s.Assets[1].Resource.Data["complete"]) {
		t.Fatal(s)
	}
	// Viewer may know the organization identity but cannot read its policy.
	s = Snapshot{Assets: []Asset{auditContainer("projects/1", "Project", "organizations/2", auditPolicy("allServices", "DATA_READ", "user:known@example.com")), auditContainer("organizations/2", "Organization", "", nil)}}
	ResolveAuditConfigs(&s)
	d := s.Assets[2].Resource.Data
	if Bool(d["complete"]) || len(List(d["configs"])) != 1 {
		t.Fatal(d)
	}
}
