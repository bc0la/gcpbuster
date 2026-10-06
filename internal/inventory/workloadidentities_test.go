package inventory

import (
	"encoding/json"
	"testing"
)

func TestWorkloadIdentityLayouts(t *testing.T) {
	for _, tc := range []struct {
		kind, data string
		want       int
	}{
		{"compute.googleapis.com/Instance", `{"serviceAccounts":[{"email":"runner@p.iam.gserviceaccount.com","scopes":["read-only"]}]}`, 1},
		{"compute.googleapis.com/InstanceTemplate", `{"properties":{"serviceAccounts":[{"email":"runner@p.iam.gserviceaccount.com"}]}}`, 1},
		{"compute.googleapis.com/MachineImage", `{"instanceProperties":{"serviceAccounts":[{"email":"runner@p.iam.gserviceaccount.com"}]}}`, 1},
		{"run.googleapis.com/Service", `{"template":{"serviceAccount":"runner@p.iam.gserviceaccount.com"}}`, 1},
		{"run.googleapis.com/Service", `{"spec":{"template":{"spec":{"serviceAccountName":"runner@p.iam.gserviceaccount.com"}}}}`, 1},
		{"run.googleapis.com/Job", `{"template":{"template":{"serviceAccount":"runner@p.iam.gserviceaccount.com"}}}`, 1},
		{"run.googleapis.com/Job", `{"spec":{"template":{"spec":{"template":{"spec":{"serviceAccountName":"runner@p.iam.gserviceaccount.com"}}}}}}`, 1},
		{"cloudfunctions.googleapis.com/CloudFunction", `{"serviceAccountEmail":"runner@p.iam.gserviceaccount.com"}`, 1},
		{"cloudfunctions.googleapis.com/Function", `{"serviceConfig":{"serviceAccountEmail":"runner@p.iam.gserviceaccount.com"}}`, 1},
		{"cloudbuild.googleapis.com/Build", `{"serviceAccount":"projects/p/serviceAccounts/runner@p.iam.gserviceaccount.com"}`, 1},
		{"workflows.googleapis.com/Workflow", `{"serviceAccount":"projects/p/serviceAccounts/runner@p.iam.gserviceaccount.com"}`, 1},
		{"composer.googleapis.com/Environment", `{"config":{"nodeConfig":{"serviceAccount":"runner@p.iam.gserviceaccount.com"}}}`, 1},
		{"composer.googleapis.com/Environment", `{"config":{"nodeConfig":{"serviceAccount":"default"}}}`, 0},
		{"composer.googleapis.com/Environment", `{"config":{"gkeCluster":"projects/p/locations/us-central1/clusters/cluster"}}`, 0},
		{"composer.googleapis.com/Environment", `{"serviceAccount":"service-123@cloudcomposer-accounts.iam.gserviceaccount.com"}`, 0},
		{"container.googleapis.com/Cluster", `{"nodePools":[{"config":{"serviceAccount":"default"}}]}`, 0},
		{"run.googleapis.com/Service", `{}`, 0},
		{"run.googleapis.com/Service", `{"template":{"serviceAccount":"runner@evil.gserviceaccount.com.attacker.invalid"}}`, 0},
	} {
		t.Run(tc.kind+tc.data, func(t *testing.T) {
			var d Object
			if err := json.Unmarshal([]byte(tc.data), &d); err != nil {
				t.Fatal(err)
			}
			ids, supported := workloadIdentities(NewAsset("test", tc.kind, d))
			if !supported || len(ids) != tc.want {
				t.Fatal(ids, supported)
			}
		})
	}
}

func TestAppEngineExplicitVersionIdentityScopedConditions(t *testing.T) {
	email := "runner@demo.iam.gserviceaccount.com"
	version := NewAsset("//appengine.googleapis.com/apps/demo/services/default/versions/v1", "appengine.googleapis.com/Version", Object{"serviceAccount": email, "servingStatus": "STOPPED"})
	snap := Snapshot{Assets: []Asset{version}}
	for _, scope := range []string{"projects/other", "//storage.googleapis.com/bucket"} {
		snap.Assets = append(snap.Assets, NewAsset(scope+"/grant", PermissionGrantType, Object{"principal": "serviceAccount:" + email, "resource": scope, "permissions": []any{"iam.serviceAccountKeys.create"}, "condition": Object{"expression": "false"}}))
	}
	CorrelateWorkloadGrants(&snap)
	if len(snap.Assets) != 5 {
		t.Fatal(snap)
	}
	for i, a := range snap.Assets[3:] {
		d := a.Resource.Data
		if d["workloadType"] != version.Type || d["identityField"] != "serviceAccount" || d["serviceAccount"] != email || d["grantResource"] != []string{"projects/other", "//storage.googleapis.com/bucket"}[i] || Str(Get(d, "condition", "expression")) != "false" {
			t.Fatal(a)
		}
	}
}

func TestAppEngineVersionIdentityNoDefaults(t *testing.T) {
	for _, value := range []any{nil, "", "default", "demo@appspot.gserviceaccount.com.attacker.test", false, "projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com"} {
		version := NewAsset("//appengine.googleapis.com/apps/demo/services/default/versions/v1", "appengine.googleapis.com/Version", Object{"serviceAccount": value})
		app := NewAsset("//appengine.googleapis.com/apps/demo", "appengine.googleapis.com/Application", Object{"serviceAccount": "demo@appspot.gserviceaccount.com"})
		grant := NewAsset("grant", PermissionGrantType, Object{"principal": "serviceAccount:demo@appspot.gserviceaccount.com", "resource": "projects/demo", "permissions": []any{"iam.serviceAccountKeys.create"}})
		snap := Snapshot{Assets: []Asset{version, app, grant}}
		CorrelateWorkloadGrants(&snap)
		if len(snap.Assets) != 3 {
			t.Fatal(value, snap)
		}
		ids, supported := workloadIdentities(version)
		if !supported || len(ids) != 0 {
			t.Fatal(value, ids)
		}
	}
}

func TestGatewayBackendIdentityExplicitEmailAndConditions(t *testing.T) {
	for _, email := range []string{"worker@demo.iam.gserviceaccount.com", "123-compute@developer.gserviceaccount.com"} {
		config := NewAsset("config", "apigateway.googleapis.com/ApiConfig", Object{"gatewayServiceAccount": email})
		snap := Snapshot{Assets: []Asset{config}}
		for _, condition := range []string{"first", "second"} {
			snap.Assets = append(snap.Assets, NewAsset("grant", PermissionGrantType, Object{"principal": "serviceAccount:" + email, "resource": "projects/other/" + condition, "permissions": []any{"run.routes.invoke"}, "condition": Object{"expression": condition}}))
		}
		CorrelateWorkloadGrants(&snap)
		if len(snap.Assets) != 5 {
			t.Fatal(snap)
		}
		for i, a := range snap.Assets[3:] {
			if a.Resource.Data["identityField"] != "gatewayServiceAccount" || Str(Get(a.Resource.Data, "condition", "expression")) != []string{"first", "second"}[i] || a.Resource.Data["grantResource"] != "projects/other/"+[]string{"first", "second"}[i] {
				t.Fatal(a)
			}
		}
	}
}

func gatewayAccountFixture() Asset {
	a := NewAsset("//iam.googleapis.com/projects/demo/serviceAccounts/12345", "iam.googleapis.com/ServiceAccount", Object{"name": "projects/demo/serviceAccounts/12345", "projectId": "demo", "email": "worker@demo.iam.gserviceaccount.com", "uniqueId": "12345"})
	a.Ancestors = []string{"projects/123"}
	return a
}
func TestGatewayBackendIdentityUIDScopeAndAmbiguity(t *testing.T) {
	for _, project := range []string{"demo", "123"} {
		config := NewAsset("config", "apigateway.googleapis.com/ApiConfig", Object{"gatewayServiceAccount": "projects/" + project + "/accounts/12345"})
		account := gatewayAccountFixture()
		grant := NewAsset("grant", PermissionGrantType, Object{"principal": "serviceAccount:worker@demo.iam.gserviceaccount.com", "resource": "projects/other", "condition": Object{"expression": "false"}, "permissions": []any{"run.routes.invoke"}})
		snap := Snapshot{Assets: []Asset{config, account, grant}}
		CorrelateWorkloadGrants(&snap)
		if len(snap.Assets) != 4 || snap.Assets[3].Type != WorkloadGrantType {
			t.Fatal(snap)
		}
	}
	for _, ref := range []string{"projects/other/accounts/12345", "projects/999/accounts/12345", "projects/demo/accounts/999", "projects/-/accounts/12345", "projects/demo/serviceAccounts/worker@demo.iam.gserviceaccount.com", "projects/demo/accounts/12345/extra", "default", ""} {
		config := NewAsset("config", "apigateway.googleapis.com/ApiConfig", Object{"gatewayServiceAccount": ref})
		if got := resolveGatewayAccountUID(config, []Asset{gatewayAccountFixture()}); got != "" {
			t.Fatal(ref, got)
		}
		ids, _ := workloadIdentities(config)
		if len(ids) != 0 {
			t.Fatal(ref, ids)
		}
	}
	config := NewAsset("config", "apigateway.googleapis.com/ApiConfig", Object{"gatewayServiceAccount": "projects/demo/accounts/12345"})
	if resolveGatewayAccountUID(config, nil) != "" {
		t.Fatal("missing account inferred")
	}
	conflict := gatewayAccountFixture()
	conflict.Resource.Data["email"] = "other@demo.iam.gserviceaccount.com"
	if resolveGatewayAccountUID(config, []Asset{gatewayAccountFixture(), conflict}) != "" {
		t.Fatal("ambiguous UID joined")
	}
	malformed := gatewayAccountFixture()
	malformed.Resource.Data["projectId"] = "other"
	if resolveGatewayAccountUID(config, []Asset{malformed}) != "" {
		t.Fatal("malformed account joined")
	}
	aliasConflict := gatewayAccountFixture()
	aliasConflict.Ancestors = []string{"projects/999"}
	if resolveGatewayAccountUID(config, []Asset{gatewayAccountFixture(), aliasConflict}) != "" {
		t.Fatal("ambiguous project alias joined")
	}
}

func TestWorkloadGrantsDoNotMergeConditionsOrIdentities(t *testing.T) {
	w := NewAsset("vm", "compute.googleapis.com/Instance", Object{"serviceAccounts": []any{Object{"email": "runner@p.iam.gserviceaccount.com", "scopes": []any{"read-only"}}}})
	g := func(principal, condition, resource string) Asset {
		return NewAsset("grant", PermissionGrantType, Object{"principal": principal, "condition": Object{"expression": condition}, "resource": resource, "permissions": []any{"iam.serviceAccountKeys.create"}})
	}
	s := Snapshot{Assets: []Asset{w, g("serviceAccount:runner@p.iam.gserviceaccount.com", "first", "project-a"), g("serviceAccount:runner@p.iam.gserviceaccount.com", "second", "project-b"), g("serviceAccount:other@p.iam.gserviceaccount.com", "third", "project-c")}}
	CorrelateWorkloadGrants(&s)
	if len(s.Assets) != 6 {
		t.Fatal(s)
	}
	for i, a := range s.Assets[4:] {
		d := a.Resource.Data
		if Str(d["workload"]) != "vm" || List(d["oauthScopes"])[0] != "read-only" {
			t.Fatal(d)
		}
		want := []string{"first", "second"}[i]
		if Str(Get(d, "condition", "expression")) != want {
			t.Fatal("condition was combined", d)
		}
	}
}

func TestComposerWorkerIdentityDoesNotBecomeServiceAgent(t *testing.T) {
	worker := "worker@demo.iam.gserviceaccount.com"
	environment := NewAsset("//composer.googleapis.com/projects/demo/locations/us-central1/environments/env", "composer.googleapis.com/Environment", Object{"config": Object{"nodeConfig": Object{"serviceAccount": worker, "oauthScopes": []any{"read-only"}}}})
	grant := func(principal string) Asset {
		return NewAsset("grant", PermissionGrantType, Object{"principal": "serviceAccount:" + principal, "resource": "projects/demo", "permissions": []any{"iam.serviceAccountKeys.create"}, "condition": Object{"expression": "false"}})
	}
	snap := Snapshot{Assets: []Asset{environment, grant(worker), grant("service-123@cloudcomposer-accounts.iam.gserviceaccount.com")}}
	CorrelateWorkloadGrants(&snap)
	if len(snap.Assets) != 4 {
		t.Fatal(snap)
	}
	d := snap.Assets[3].Resource.Data
	if Str(d["serviceAccount"]) != worker || Str(d["identityField"]) != "config.nodeConfig.serviceAccount" || Str(Get(d, "condition", "expression")) != "false" || len(List(d["oauthScopes"])) != 1 {
		t.Fatal(d)
	}
}

func managedSecretIdentityAsset() Asset {
	name := "projects/123/locations/us-central1/secrets/sql-secret"
	return NewAsset("//secretmanager.googleapis.com/"+name, "secretmanager.googleapis.com/Secret", Object{"name": name, "secretType": "CLOUD_SQL_DB_CREDENTIALS", "policyMember": Object{
		"iamPolicyUidPrincipal":  "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/unique-id",
		"iamPolicyNamePrincipal": "principal://secretmanager.googleapis.com/projects/123/name/locations/us-central1/secrets/sql-secret",
	}})
}

func TestManagedSecretPrincipalGrantsKeepUIDNameScopeAndCondition(t *testing.T) {
	secret := managedSecretIdentityAsset()
	uid := Str(Get(secret.Resource.Data, "policyMember", "iamPolicyUidPrincipal"))
	name := Str(Get(secret.Resource.Data, "policyMember", "iamPolicyNamePrincipal"))
	s := Snapshot{Assets: []Asset{secret, role("roles/rotation", "cloudsql.users.update", "cloudsql.users.list"),
		policy("project-a", "roles/rotation", uid, Object{"expression": "uid-condition"}),
		policy("project-b", "roles/rotation", name, Object{"expression": "name-condition"}),
		policy("project-c", "roles/rotation", "principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/sql-secret", nil),
		policy("project-d", "roles/rotation", "serviceAccount:unique-id@demo.iam.gserviceaccount.com", nil),
	}}
	ExpandBindings(&s)
	CorrelateWorkloadGrants(&s)
	found := map[string]Object{}
	for _, a := range s.Assets {
		if a.Type == WorkloadGrantType {
			found[Str(a.Resource.Data["principal"])] = a.Resource.Data
		}
	}
	if len(found) != 2 {
		t.Fatal(found)
	}
	for principal, want := range map[string][]string{uid: {"resource_uid", "project-a", "uid-condition"}, name: {"resource_name", "project-b", "name-condition"}} {
		d := found[principal]
		if d["identityKind"] != want[0] || d["grantResource"] != want[1] || Str(Get(d, "condition", "expression")) != want[2] || len(List(d["permissions"])) != 2 {
			t.Fatal(d)
		}
		if _, exists := d["serviceAccount"]; exists {
			t.Fatal("built-in identity mislabeled service account", d)
		}
	}
}

func TestManagedSecretIdentityRejectsGuessedOrMismatchedPrincipal(t *testing.T) {
	for _, principal := range []string{
		"principal://secretmanager.googleapis.com/projects/999/uid/locations/us-central1/secrets/unique-id",
		"principal://secretmanager.googleapis.com/projects/123/uid/locations/us-east1/secrets/unique-id",
		"principal://secretmanager.googleapis.com/projects/123/name/locations/us-central1/secrets/sql-secret",
		"principalSet://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/*",
		"principal://evil.invalid/projects/123/uid/locations/us-central1/secrets/unique-id",
		"principal://secretmanager.googleapis.com/projects/123/uid/locations/us-central1/secrets/unique-id?query=yes",
		"serviceAccount:worker@demo.iam.gserviceaccount.com", "",
	} {
		a := managedSecretIdentityAsset()
		a.Resource.Data["policyMember"] = Object{"iamPolicyUidPrincipal": principal}
		ids, supported := workloadIdentities(a)
		if !supported || len(ids) != 0 {
			t.Fatal(principal, ids)
		}
	}
	for _, change := range []func(*Asset){
		func(a *Asset) {
			a.Resource.Data["policyMember"] = Object{"iamPolicyNamePrincipal": "principal://secretmanager.googleapis.com/projects/123/name/locations/us-central1/secrets/other"}
		},
		func(a *Asset) { a.Resource.Data["name"] = "projects/123/locations/us-central1/secrets/other" },
		func(a *Asset) { a.Resource.Location = "us-east1" },
		func(a *Asset) {
			a.Name = "//secretmanager.googleapis.com/projects/123/secrets/sql-secret"
			a.Resource.Data["name"] = "projects/123/secrets/sql-secret"
		},
	} {
		a := managedSecretIdentityAsset()
		change(&a)
		ids, _ := workloadIdentities(a)
		if len(ids) != 0 {
			t.Fatal(ids)
		}
	}
}

func TestManagedSecretIdentityMissingGrantsIsNotLeastPrivilege(t *testing.T) {
	a := managedSecretIdentityAsset()
	s := Snapshot{Assets: []Asset{a}}
	CorrelateWorkloadGrants(&s)
	if len(s.Assets) != 1 || len(s.Coverage) != 1 || s.Coverage[0].Source != "workload-identities:grants" {
		t.Fatal(s)
	}
	delete(a.Resource.Data, "policyMember")
	s = Snapshot{Assets: []Asset{a}}
	CorrelateWorkloadGrants(&s)
	if len(s.Assets) != 1 || len(s.Coverage) != 1 || s.Coverage[0].Source != "workload-identities:unresolved" {
		t.Fatal(s)
	}
}
