package inventory

import "testing"

func TestStorageControlsExactBucketAndConflictingEvidence(t *testing.T) {
	bucket := NewAsset("//storage.googleapis.com/owned-bucket", "storage.googleapis.com/Bucket", Object{"name": "owned-bucket", "iamConfiguration": Object{"publicAccessPrevention": "enforced", "uniformBucketLevelAccess": Object{"enabled": true}}})
	grant := NewAsset("grant", PermissionGrantType, Object{"resource": bucket.Name, "resourceType": bucket.Type, "principal": "allUsers"})
	project := NewAsset("project-grant", PermissionGrantType, Object{"resource": "//cloudresourcemanager.googleapis.com/projects/demo", "resourceType": "cloudresourcemanager.googleapis.com/Project"})
	s := Snapshot{Assets: []Asset{bucket, grant, project}}
	CorrelateStorageControls(&s)
	if Get(s.Assets[1].Resource.Data, "_gcpbusterStorageControls", "public_access_prevention") != "enforced" || Get(s.Assets[1].Resource.Data, "_gcpbusterStorageControls", "uniform_bucket_level_access") != true || s.Assets[2].Resource.Data["_gcpbusterStorageControls"] != nil {
		t.Fatal(s)
	}
	other := NewAsset(bucket.Name, bucket.Type, Object{"name": "owned-bucket", "iamConfiguration": Object{"publicAccessPrevention": "inherited"}})
	s.Assets = append(s.Assets, other, bucket)
	CorrelateStorageControls(&s)
	if Get(s.Assets[1].Resource.Data, "_gcpbusterStorageControls", "status") != "conflicting" || Get(s.Assets[1].Resource.Data, "_gcpbusterStorageControls", "public_access_prevention") != "unknown" {
		t.Fatal("conflict was cleared by repetition", s)
	}
}

func TestStorageControlsUnknownAndForeignDoNotEnforce(t *testing.T) {
	for _, data := range []Object{{"name": "foreign-bucket", "iamConfiguration": Object{"publicAccessPrevention": "enforced"}}, {"name": "owned-bucket", "iamConfiguration": Object{"publicAccessPrevention": true}}, {"name": "owned-bucket"}} {
		bucket := NewAsset("//storage.googleapis.com/owned-bucket", "storage.googleapis.com/Bucket", data)
		grant := NewAsset("grant", PermissionGrantType, Object{"resource": bucket.Name, "resourceType": bucket.Type, "_gcpbusterStorageControls": Object{"public_access_prevention": "enforced"}})
		s := Snapshot{Assets: []Asset{bucket, grant}}
		CorrelateStorageControls(&s)
		if Get(s.Assets[1].Resource.Data, "_gcpbusterStorageControls", "public_access_prevention") == "enforced" {
			t.Fatal("unknown metadata became enforcement", s)
		}
	}
}
