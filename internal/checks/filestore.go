package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/netip"
	"sort"
	"time"
)

// These are explicit export-option observations, not a resolution of the
// effective option for a client. More-specific prefixes may override a rule.
func filestoreRootTrust(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "file.googleapis.com/Instance" {
		return nil
	}
	var out []Result
	for si, share := range arr(val(a, "fileShares")) {
		for oi, raw := range arr(obj(share)["nfsExportOptions"]) {
			d := obj(raw)
			if s(d["accessMode"]) != "READ_WRITE" || s(d["squashMode"]) != "NO_ROOT_SQUASH" {
				continue
			}
			ranges := filestoreIPv4Ranges(d["ipRanges"])
			if len(ranges) == 0 {
				continue
			}
			out = append(out, Result{"medium", "Filestore export option configures READ_WRITE with NO_ROOT_SQUASH", inventory.Object{"share_index": si, "export_option_index": oi, "access_mode": "READ_WRITE", "squash_mode": "NO_ROOT_SQUASH", "configured_source_ranges": ranges, "assessment": "Configured export option only. Narrower-prefix rules can override it on zonal, regional and enterprise tiers. Network reachability, security flavor, client identity and POSIX permissions remain unverified; no NFS mount, probe or file access occurred. This grants no Google Cloud IAM permissions."}, "Review trusted clients and whether ROOT_SQUASH or read-only access meets the workload requirements; validate overlapping rules and filesystem permissions before changing exports."})
		}
	}
	return out
}

func filestoreExportSources(a inventory.Asset, _ time.Time) []Result {
	if a.Type != "file.googleapis.com/Instance" {
		return nil
	}
	var out []Result
	for si, share := range arr(val(a, "fileShares")) {
		for oi, raw := range arr(obj(share)["nfsExportOptions"]) {
			d := obj(raw)
			mode := s(d["accessMode"])
			if mode != "READ_ONLY" && mode != "READ_WRITE" {
				continue
			}
			ranges := filestoreIPv4Ranges(d["ipRanges"])
			for _, r := range ranges {
				if r != "0.0.0.0/0" {
					continue
				}
				out = append(out, Result{"info", "Filestore export option contains an unrestricted IPv4 source range", inventory.Object{"share_index": si, "export_option_index": oi, "configured_source_range": "0.0.0.0/0", "access_mode": mode, "assessment": "Configured export CIDR only, not internet-public access or effective permissions for every source. Narrower-prefix export rules can override this option on supported tiers. VPC connectivity, firewall rules, security flavor and filesystem permissions remain independent. No NFS mount, endpoint probe or file access occurred."}, "Limit the export source range to required clients where appropriate, and review narrower-prefix overrides together with network and filesystem controls."})
				if squash := s(d["squashMode"]); squash == "ROOT_SQUASH" || squash == "NO_ROOT_SQUASH" {
					out[len(out)-1].Evidence["squash_mode"] = squash
				}
			}
		}
	}
	return out
}

func filestoreIPv4Ranges(v any) []string {
	rows, ok := v.([]any)
	if !ok || len(rows) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range rows {
		value, ok := raw.(string)
		if !ok {
			return nil
		}
		p, e := netip.ParsePrefix(value)
		if e != nil {
			ip, err := netip.ParseAddr(value)
			if err != nil || !ip.Is4() {
				return nil
			}
			p = netip.PrefixFrom(ip, 32)
		}
		if !p.Addr().Is4() {
			return nil
		}
		value = p.Masked().String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
