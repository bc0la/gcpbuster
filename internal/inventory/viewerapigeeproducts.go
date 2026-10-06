package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
)

const ApigeeAPIProductType = "gcpbuster.googleapis.com/ApigeeAPIProduct"
const viewerApigeeProductFields = "apiProduct(name,approvalType,attributes(name,value))"

var viewerApigeeProductID = regexp.MustCompile(`^[A-Za-z0-9 ._#$%\-]{1,255}$`)

// Called only after CollectViewerApigee verifies the organization/project binding.
// Cursor names and arbitrary attribute values are transient, not report data.
func (c *Client) collectViewerApigeeProducts(ctx context.Context, out *Snapshot, parent, number string) {
	if !regexp.MustCompile(`^organizations/[A-Za-z0-9_-]+$`).MatchString(parent) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-apigee-products:identity", 0, fmt.Errorf("invalid organization binding"))
		return
	}
	source := "viewer-apigee-products:" + parent
	out.Coverage = append(out.Coverage, Coverage{Source: source + ":limitations", Status: "notice", Error: "Selected product access and key-approval configuration only. Space-level access can limit listed products. Portal registration, published catalog/audiences, app credentials, actual key issuance and proxy authorization are not collected or tested; missing attributes are unknown."})
	cursor := ""
	seen := map[string]int{}
	seenCursors := map[string]bool{}
	partial := false
	count := 0
	for pageNo := 0; pageNo < 1000; pageNo++ {
		q := url.Values{"fields": {viewerApigeeProductFields}, "expand": {"true"}, "count": {"100"}}
		if cursor != "" {
			q.Set("startKey", cursor)
		}
		page, e := c.get(ctx, "https://apigee.googleapis.com/v1/"+parent+"/apiproducts", q)
		if e != nil {
			out.record(source, count, e)
			return
		}
		rows, e := viewerRows(page, "apiProduct")
		if e != nil || len(rows) > 100 {
			out.record(source, count, fmt.Errorf("invalid product page"))
			return
		}
		next := ""
		for _, raw := range rows {
			d := Obj(raw)
			name := Str(d["name"])
			if !viewerApigeeProductID.MatchString(name) || name == "." || name == ".." {
				partial = true
				continue
			}
			next = name
			hash := sha256.Sum256([]byte(name))
			digest := hex.EncodeToString(hash[:])
			safe, ok := projectViewerApigeeProduct(d)
			safe["organization"] = parent
			safe["product_digest"] = digest
			if !ok {
				partial = true
			}
			if old, exists := seen[digest]; exists {
				if !reflect.DeepEqual(out.Assets[old].Resource.Data, safe) {
					out.Assets[old].Resource.Data["projection_complete"] = false
					partial = true
				}
				continue
			}
			a := NewAsset("//apigee.googleapis.com/"+parent+"/apiproductObservations/"+digest, ApigeeAPIProductType, safe)
			a.Ancestors = []string{number}
			seen[digest] = len(out.Assets)
			out.Assets = append(out.Assets, a)
			count++
		}
		if len(rows) < 100 {
			if partial {
				out.record(source, count, fmt.Errorf("some product metadata malformed or conflicting"))
			} else {
				out.record(source, count, nil)
			}
			return
		}
		if next == "" || next == cursor || seenCursors[next] {
			out.record(source, count, fmt.Errorf("product pagination did not advance"))
			return
		}
		seenCursors[next] = true
		cursor = next
	}
	out.record(source, count, fmt.Errorf("product page limit reached"))
}

func projectViewerApigeeProduct(raw Object) (Object, bool) {
	out := Object{"projection_complete": true}
	valid := true
	if value, exists := raw["approvalType"]; exists {
		if value == "auto" || value == "manual" {
			out["approval_type"] = value
		} else {
			valid = false
		}
	}
	if value, exists := raw["attributes"]; exists {
		rows, ok := value.([]any)
		if !ok || len(rows) > 18 {
			valid = false
		} else {
			found := false
			for _, v := range rows {
				d, ok := v.(map[string]any)
				if !ok {
					valid = false
					continue
				}
				name, ok := d["name"].(string)
				if !ok {
					valid = false
					continue
				}
				if name != "access" {
					continue
				}
				if found {
					valid = false
				}
				found = true
				switch d["value"] {
				case "public", "private", "internal":
					out["access"] = d["value"]
				default:
					valid = false
				}
			}
		}
	}
	out["projection_complete"] = valid
	return out, valid
}

func viewerApigeeProductsQuery(q url.Values) bool {
	if q.Get("fields") != viewerApigeeProductFields || q.Get("expand") != "true" || q.Get("count") != "100" {
		return false
	}
	for k, v := range q {
		if len(v) != 1 {
			return false
		}
		switch k {
		case "fields", "expand", "count":
		case "startKey":
			if !viewerApigeeProductID.MatchString(v[0]) || v[0] == "." || v[0] == ".." {
				return false
			}
		default:
			return false
		}
	}
	return true
}
