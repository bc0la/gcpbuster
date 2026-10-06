package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const DNSRecordSetType = "gcpbuster.googleapis.com/DNSRecordSet"
const viewerDNSRecordFields = "rrsets(name,type,ttl,rrdatas,routingPolicy),nextPageToken"

// CollectViewerDNSRecords reads record configuration for known zones only.
// Values are transient inputs to the safe projector, never resolution queries.
func (c *Client) CollectViewerDNSRecords(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-dns-records:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	assets := append([]Asset(nil), out.Assets...)
	prefix := "//dns.googleapis.com/projects/" + projectID + "/managedZones/"
	// Preflight all scoped observations before any network request. Choosing
	// the first of conflicting ID/name aliases could query the wrong zone.
	idSignatures, nameSignatures := map[string]string{}, map[string]string{}
	conflictingIDs, conflictingNames := map[string]bool{}, map[string]bool{}
	for _, zone := range assets {
		if zone.Type != "dns.googleapis.com/ManagedZone" || !strings.HasPrefix(zone.Name, prefix) {
			continue
		}
		d := zone.Resource.Data
		id, name := Str(d["id"]), Str(d["name"])
		signature := id + "\x00" + name + "\x00" + strings.ToLower(Str(d["dnsName"])) + "\x00" + Str(d["visibility"])
		if previous, exists := idSignatures[id]; exists && previous != signature {
			conflictingIDs[id] = true
		}
		if previous, exists := nameSignatures[name]; exists && previous != signature {
			conflictingNames[name] = true
		}
		idSignatures[id] = signature
		nameSignatures[name] = signature
	}
	zones := map[string]bool{}
	for _, zone := range assets {
		if zone.Type != "dns.googleapis.com/ManagedZone" {
			continue
		}
		if !strings.HasPrefix(zone.Name, prefix) {
			continue
		}
		d := zone.Resource.Data
		name, id, domain, visibility := Str(d["name"]), Str(d["id"]), strings.ToLower(Str(d["dnsName"])), Str(d["visibility"])
		canonical := strings.TrimPrefix(zone.Name, prefix)
		domainOK := validDNSZoneName(domain)
		if !viewerDNSZoneName.MatchString(name) || !viewerNumericID.MatchString(id) || (canonical != id && canonical != name) || !domainOK || !strings.HasSuffix(domain, ".") || (visibility != "public" && visibility != "private") {
			out.record("viewer-dns-records:identity", 0, fmt.Errorf("invalid managed-zone identity for record collection"))
			continue
		}
		if zones[id] {
			continue
		}
		zones[id] = true
		if conflictingIDs[id] || conflictingNames[name] {
			out.record("viewer-dns-records:identity", 0, fmt.Errorf("conflicting managed-zone identity observations"))
			continue
		}
		start := len(out.Assets)
		partial := false
		seen := map[string]bool{}
		err := c.viewerPages(ctx, "https://dns.googleapis.com/dns/v1/projects/"+projectID+"/managedZones/"+name+"/rrsets", url.Values{"maxResults": {"100"}, "fields": {viewerDNSRecordFields}}, func(page Object) error {
			rows, err := viewerRows(page, "rrsets")
			if err != nil {
				return err
			}
			for _, raw := range rows {
				r := Obj(raw)
				owner := strings.ToLower(Str(r["name"]))
				if owner == "" || !strings.HasSuffix(owner, ".") || (domain != "." && owner != domain && !strings.HasSuffix(owner, "."+domain)) {
					partial = true
					continue
				}
				clean, e := projectDNSRecordSet(r)
				if e != nil {
					partial = true
				}
				if clean == nil {
					continue
				}
				key := owner + " " + Str(r["type"])
				if seen[key] {
					partial = true
					continue
				}
				seen[key] = true
				clean["zoneVisibility"] = visibility
				clean["managedZone"] = zone.Name
				digest := sha256.Sum256([]byte(key))
				a := NewAsset(zone.Name+"/record-metadata/"+hex.EncodeToString(digest[:]), DNSRecordSetType, clean)
				a.Ancestors = []string{number}
				c.SecretCapture.captureDNSRecord(a.Name, "", r)
				out.Assets = append(out.Assets, a)
			}
			return nil
		})
		if err == nil && partial {
			err = fmt.Errorf("some DNS record metadata was malformed, duplicated or outside its managed zone")
		}
		out.record("viewer-dns-records:"+projectID+"/"+name, len(out.Assets)-start, err)
	}
}
