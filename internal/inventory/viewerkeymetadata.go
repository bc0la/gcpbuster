package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var viewerKeyVersionID = regexp.MustCompile(`^[0-9]+$`)
var viewerKeyResourceID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// CollectViewerKeyMetadata never calls SecretVersion:access, cryptographic
// operations, public-key downloads, or credential/key export endpoints.
func (c *Client) CollectViewerKeyMetadata(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-key-metadata:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	secrets := c.viewerKeyChildren(ctx, out, "secretmanager.googleapis.com", number, "secrets", "Secret", number, projectID, false)
	for _, secret := range secrets {
		c.viewerKeyChildren(ctx, out, "secretmanager.googleapis.com", Str(secret["name"]), "versions", "SecretVersion", number, projectID, true)
	}
	project := "projects/" + projectID
	locations := c.viewerKeyChildren(ctx, out, "cloudkms.googleapis.com", project, "locations", "", number, projectID, false)
	for _, location := range locations {
		rings := c.viewerKeyChildren(ctx, out, "cloudkms.googleapis.com", Str(location["name"]), "keyRings", "KeyRing", number, projectID, false)
		for _, ring := range rings {
			keys := c.viewerKeyChildren(ctx, out, "cloudkms.googleapis.com", Str(ring["name"]), "cryptoKeys", "CryptoKey", number, projectID, false)
			for _, key := range keys {
				c.viewerKeyChildren(ctx, out, "cloudkms.googleapis.com", Str(key["name"]), "cryptoKeyVersions", "CryptoKeyVersion", number, projectID, true)
			}
		}
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-secret-global:" + projectID, Status: "notice", Error: "This stage covers global Secret Manager metadata only; regional metadata and direct secret policies are collected separately during default Viewer discovery."}, Coverage{Source: "viewer-key-metadata:limitations:" + projectID, Status: "notice", Error: "Secret/KMS lifecycle metadata and directly attached KMS key-ring/key IAM policies only. Conditional bindings are retained, not evaluated. Ancestor policies, IAM deny and principal-access boundaries are not resolved into effective access. No secret payload, cryptographic use, exported key material, or rotation worker verification is performed."})
}

// viewerKeyChildren validates each result as an immediate child of the exact
// requested parent. Response-provided URLs are never followed.
func (c *Client) viewerKeyChildren(ctx context.Context, out *Snapshot, host, parent, collection, kind, number, projectID string, numeric bool) []Object {
	var result []Object
	seen := map[string]bool{}
	q := url.Values{"pageSize": {"1000"}}
	if c.SecretCapture != nil && host == "secretmanager.googleapis.com" && collection == "secrets" {
		q.Set("fields", secretCaptureGlobalSecretFields)
	}
	partial := false
	err := c.viewerPages(ctx, "https://"+host+"/v1/"+parent+"/"+collection, q, func(page Object) error {
		rows, err := viewerRows(page, collection)
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			// Providers may echo either known project alias. Normalize to CAI's
			// documented numeric SM / project-ID KMS canonical resource form.
			canonicalProject := "projects/" + projectID
			otherProject := number
			if host == "secretmanager.googleapis.com" {
				canonicalProject, otherProject = number, canonicalProject
			}
			if strings.HasPrefix(name, otherProject+"/") {
				name = canonicalProject + strings.TrimPrefix(name, otherProject)
			}
			prefix := parent + "/" + collection + "/"
			id := strings.TrimPrefix(name, prefix)
			if !strings.HasPrefix(name, prefix) || !viewerKeyResourceID.MatchString(id) || (numeric && !viewerKeyVersionID.MatchString(id)) {
				return fmt.Errorf("invalid or out-of-parent key metadata resource")
			}
			if collection == "locations" && (!viewerLocation.MatchString(id) || (Str(d["locationId"]) != "" && Str(d["locationId"]) != id)) {
				return fmt.Errorf("invalid key metadata location")
			}
			if d["payload"] != nil || d["privateKeyData"] != nil || d["plaintext"] != nil {
				return fmt.Errorf("unexpected payload in metadata response")
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			d["name"] = name
			if host == "secretmanager.googleapis.com" && kind == "Secret" {
				c.SecretCapture.CaptureStringMap("secret_manager_annotations", "//"+host+"/"+name, "", "annotations", d["annotations"])
				// Annotation values travel through the transient capture channel only.
				delete(d, "annotations")
			}
			result = append(result, d)
			if kind != "" {
				a := NewAsset("//"+host+"/"+name, host+"/"+kind, d)
				a.Ancestors = []string{number}
				parts := strings.Split(name, "/")
				if len(parts) > 3 && parts[2] == "locations" {
					a.Resource.Location = parts[3]
				}
				if host == "cloudkms.googleapis.com" && (kind == "KeyRing" || kind == "CryptoKey") {
					c.viewerKeyIAM(ctx, out, &a, projectID)
				}
				out.Assets = append(out.Assets, a)
			}
		}
		if _, exists := page["unreachable"]; exists {
			missing, err := viewerRows(page, "unreachable")
			if err != nil {
				return err
			}
			if len(missing) > 0 {
				partial = true
			}
		}
		return nil
	})
	if err == nil && partial {
		err = fmt.Errorf("key metadata locations unreachable")
	}
	out.record("viewer-key-metadata:"+host+":"+parent+"/"+collection, len(result), err)
	return result
}

// KMS uses a read-only GET (unlike Resource Manager's policy POST). Version 3
// is mandatory to preserve conditional bindings. Resource identities originate
// from validated list results; validation here also prevents accidental reuse
// with unrelated asset names or API methods.
func (c *Client) viewerKeyIAM(ctx context.Context, out *Snapshot, a *Asset, projectID string) {
	const prefix = "//cloudkms.googleapis.com/"
	name := strings.TrimPrefix(a.Name, prefix)
	parts := strings.Split(name, "/")
	valid := strings.HasPrefix(a.Name, prefix) && (len(parts) == 6 || len(parts) == 8)
	if valid {
		valid = parts[0] == "projects" && parts[1] == projectID && viewerResourceName.MatchString(projectID) && parts[2] == "locations" && viewerLocation.MatchString(parts[3]) && parts[4] == "keyRings" && viewerKeyResourceID.MatchString(parts[5])
		if len(parts) == 8 {
			valid = valid && a.Type == "cloudkms.googleapis.com/CryptoKey" && parts[6] == "cryptoKeys" && viewerKeyResourceID.MatchString(parts[7])
		} else {
			valid = valid && a.Type == "cloudkms.googleapis.com/KeyRing"
		}
	}
	if !valid {
		out.record("viewer-kms-iam:identity", 0, fmt.Errorf("invalid KMS policy resource"))
		return
	}
	policy, err := c.get(ctx, "https://cloudkms.googleapis.com/v1/"+name+":getIamPolicy", url.Values{"options.requestedPolicyVersion": {"3"}})
	count := 0
	if err == nil {
		err = viewerValidateKeyPolicy(policy)
	}
	if err == nil {
		// An empty object is a valid explicit policy, not a missing policy.
		// Preserve direct-read provenance even when a caller returned unrelated
		// fields resembling our internal IAM-search marker.
		delete(policy, "_gcpbusterBindingsOnly")
		a.IAM = policy
		count = 1
	}
	out.record("viewer-kms-iam:"+name, count, err)
}

func viewerValidateKeyPolicy(policy Object) error {
	if policy == nil {
		return fmt.Errorf("missing KMS IAM policy")
	}
	if version, exists := policy["version"]; exists && version != float64(0) && version != float64(1) && version != float64(3) {
		return fmt.Errorf("invalid KMS IAM policy version")
	}
	bindings, err := viewerRows(policy, "bindings")
	if err != nil {
		return err
	}
	for _, raw := range bindings {
		b := Obj(raw)
		if !rolePattern.MatchString(Str(b["role"])) {
			return fmt.Errorf("invalid KMS IAM binding role")
		}
		members, ok := b["members"].([]any)
		if !ok || len(members) == 0 {
			return fmt.Errorf("invalid KMS IAM binding members")
		}
		for _, member := range members {
			if strings.TrimSpace(Str(member)) == "" {
				return fmt.Errorf("invalid KMS IAM member")
			}
		}
		if raw, exists := b["condition"]; exists {
			condition := Obj(raw)
			if strings.TrimSpace(Str(condition["expression"])) == "" || policy["version"] != float64(3) {
				return fmt.Errorf("conditional KMS IAM policy missing version 3 or expression")
			}
		}
	}
	return nil
}
