package checks

import (
	"github.com/bc0la/gcpbuster/internal/inventory"
	"net/url"
	"time"
)

func artifactUpstreams(a inventory.Asset, _ time.Time) []Result {
	var out []Result
	if a.Type == inventory.ArtifactUpstreamsType {
		upstreams := arr(val(a, "upstreams"))
		for _, remote := range upstreams {
			r := obj(remote)
			if !b(r["publicRemote"]) {
				continue
			}
			rp, ok := r["priority"].(float64)
			if !ok {
				continue
			}
			for _, standard := range upstreams {
				p := obj(standard)
				if s(p["mode"]) != "STANDARD_REPOSITORY" {
					continue
				}
				sp, ok := p["priority"].(float64)
				if !ok || rp < sp {
					continue
				}
				title := "Public package upstream has priority over a standard repository"
				sev := "high"
				if rp == sp {
					title = "Public package upstream ties a standard repository's priority"
					sev = "medium"
				}
				out = append(out, Result{sev, title, inventory.Object{"public_upstream": r["repository"], "standard_upstream": p["repository"], "public_priority": rp, "standard_priority": sp, "assessment": "dependency-confusion configuration candidate; overlapping package names and consumer resolution behavior are not verified"}, "Give internal standard repositories higher priority than public remotes, reserve internal package names, and configure clients to use only the approved virtual repository."})
			}
		}
		return out
	}
	remote := obj(val(a, "remoteRepositoryConfig"))
	if remote == nil {
		return nil
	}
	for _, format := range []string{"dockerRepository", "mavenRepository", "npmRepository", "pythonRepository", "aptRepository", "yumRepository", "commonRepository"} {
		uri := s(inventory.Get(remote, format, "customRepository", "uri"))
		if format == "commonRepository" {
			uri = s(inventory.Get(remote, format, "uri"))
		}
		if uri == "" {
			continue
		}
		u, err := url.Parse(uri)
		if err != nil {
			continue
		}
		sev := "info"
		title := "Artifact Registry remote repository uses a custom upstream"
		if u.Scheme == "http" {
			sev = "high"
			title = "Artifact Registry custom upstream uses unencrypted HTTP"
		}
		out = append(out, Result{sev, title, inventory.Object{"format": format, "upstream_host": u.Hostname(), "scheme": u.Scheme, "validation_disabled": remote["disableUpstreamValidation"]}, "Validate upstream ownership, TLS and package provenance; review changes to the remote repository and downstream virtual repositories."})
	}
	return out
}
