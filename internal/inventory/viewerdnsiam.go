package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var viewerNumericID = regexp.MustCompile(`^[0-9]+$`)
var viewerDNSZoneName = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var viewerServiceEmail = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.gserviceaccount\.com$`)

// CollectViewerDNSIAM uses metadata list APIs with intrinsic Viewer permissions.
// Zone names use numeric IDs for CAI policy joins; service-account API names may
// contain either email or unique ID, both documented CAI forms. No credentials,
// key creation, key downloads or account impersonation are requested.
func (c *Client) CollectViewerDNSIAM(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-dns-iam:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	start := len(out.Assets)
	seenZones := map[string]bool{}
	partialZones := false
	err := c.viewerPages(ctx, "https://dns.googleapis.com/dns/v1/projects/"+projectID+"/managedZones", url.Values{"maxResults": {"100"}, "fields": {viewerDNSZoneFields}}, func(page Object) error {
		rows, err := viewerRows(page, "managedZones")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d, projectionErr := projectViewerDNSZone(Obj(raw))
			if projectionErr != nil {
				partialZones = true
			}
			if d == nil {
				continue
			}
			id := Str(d["id"])
			if seenZones[id] {
				continue
			}
			seenZones[id] = true
			a := NewAsset("//dns.googleapis.com/projects/"+projectID+"/managedZones/"+id, "dns.googleapis.com/ManagedZone", d)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return nil
	})
	if err == nil && partialZones {
		err = fmt.Errorf("some managed-zone records were malformed or unsupported")
	}
	out.record("viewer-dns-zones:"+projectID, len(out.Assets)-start, err)
	if c.DNSChecks {
		// Only this project's newly validated zones: avoid repeated probes of
		// prior projects when the caller shares a Snapshot across collectors.
		zones := Snapshot{Assets: append([]Asset(nil), out.Assets[start:]...)}
		zoneCount := len(zones.Assets)
		c.collectDNS(ctx, &zones)
		out.Assets = append(out.Assets, zones.Assets[zoneCount:]...)
		out.Coverage = append(out.Coverage, zones.Coverage...)
	}
	start = len(out.Assets)
	accounts := []Asset{}
	seenAccounts := map[string]bool{}
	err = c.viewerPages(ctx, "https://iam.googleapis.com/v1/projects/"+projectID+"/serviceAccounts", url.Values{"pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "accounts")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name, email, uid := Str(d["name"]), Str(d["email"]), Str(d["uniqueId"])
			prefix := "projects/" + projectID + "/serviceAccounts/"
			if Str(d["projectId"]) != projectID || !viewerServiceEmail.MatchString(email) || !viewerNumericID.MatchString(uid) || (name != prefix+email && name != prefix+uid) {
				return fmt.Errorf("invalid or out-of-scope service-account identity")
			}
			if seenAccounts[uid] {
				continue
			}
			seenAccounts[uid] = true
			a := NewAsset("//iam.googleapis.com/"+name, "iam.googleapis.com/ServiceAccount", d)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
			accounts = append(accounts, a)
		}
		return nil
	})
	out.record("viewer-service-accounts:"+projectID, len(out.Assets)-start, err)
	for _, account := range accounts {
		if ctx.Err() != nil {
			out.record("viewer-service-account-keys:"+account.Name, 0, ctx.Err())
			break
		}
		c.viewerAccountKeys(ctx, out, account, projectID, number)
	}
}

func (c *Client) viewerAccountKeys(ctx context.Context, out *Snapshot, account Asset, projectID, number string) {
	uid, email := Str(account.Resource.Data["uniqueId"]), Str(account.Resource.Data["email"])
	path := "projects/" + projectID + "/serviceAccounts/" + uid
	start := len(out.Assets)
	seen := map[string]bool{}
	page, err := c.get(ctx, "https://iam.googleapis.com/v1/"+path+"/keys", url.Values{"keyTypes": {"USER_MANAGED"}})
	consume := func(page Object) error {
		rows, err := viewerRows(page, "keys")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			parts := strings.Split(Str(d["name"]), "/")
			if len(parts) != 6 || parts[0] != "projects" || (parts[1] != projectID && parts[1] != strings.TrimPrefix(number, "projects/") && parts[1] != "-") || parts[2] != "serviceAccounts" || (parts[3] != uid && parts[3] != email) || parts[4] != "keys" || !viewerResourceName.MatchString(parts[5]) || Str(d["keyType"]) != "USER_MANAGED" {
				return fmt.Errorf("invalid or out-of-scope service-account key identity")
			}
			name := path + "/keys/" + parts[5]
			if seen[name] {
				continue
			}
			seen[name] = true
			// Explicit metadata projection also drops unexpected returned key
			// material; private/public key bytes have no role in these checks.
			metadata := Object{"name": name}
			for _, field := range []string{"keyType", "keyOrigin", "keyAlgorithm", "validAfterTime", "validBeforeTime", "disabled", "disableReason"} {
				if value, ok := d[field]; ok {
					metadata[field] = value
				}
			}
			a := NewAsset("//iam.googleapis.com/"+name, "iam.googleapis.com/ServiceAccountKey", metadata)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		// keys.list is not paginated. Preserve validated rows, but never
		// accept an unexpected continuation as complete or follow it.
		if _, unexpected := page["nextPageToken"]; unexpected {
			return fmt.Errorf("unexpected service-account key pagination")
		}
		return nil
	}
	if err == nil {
		if page == nil {
			err = fmt.Errorf("invalid service-account key response")
		} else {
			err = consume(page)
		}
	}
	out.record("viewer-service-account-keys:"+account.Name, len(out.Assets)-start, err)
}
