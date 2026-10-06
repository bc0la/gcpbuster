package inventory

import "strings"

const ArtifactUpstreamsType = "gcpbuster.googleapis.com/ArtifactUpstreams"

func ResolveArtifactUpstreams(snap *Snapshot) {
	repos := map[string]Object{}
	for _, a := range snap.Assets {
		if a.Type == "artifactregistry.googleapis.com/Repository" && a.Resource.Data != nil {
			name := Str(a.Resource.Data["name"])
			if name == "" {
				name = strings.TrimPrefix(a.Name, "//artifactregistry.googleapis.com/")
			}
			repos[name] = a.Resource.Data
		}
	}
	var derived []Asset
	for _, a := range snap.Assets {
		if a.Type != "artifactregistry.googleapis.com/Repository" {
			continue
		}
		policies := List(Get(a.Resource.Data, "virtualRepositoryConfig", "upstreamPolicies"))
		if len(policies) == 0 {
			continue
		}
		upstreams := []any{}
		for _, v := range policies {
			p := Obj(v)
			name := Str(p["repository"])
			data, ok := repos[name]
			if !ok {
				snap.Coverage = append(snap.Coverage, Coverage{Source: "artifact-upstream:" + a.Name + ":" + name, Status: "incomplete", Error: "Referenced upstream repository was not collected; priority analysis is incomplete."})
				continue
			}
			mode := Str(data["mode"])
			if mode == "" {
				if data["remoteRepositoryConfig"] != nil {
					mode = "REMOTE_REPOSITORY"
				} else if data["virtualRepositoryConfig"] != nil {
					mode = "VIRTUAL_REPOSITORY"
				}
			}
			public := false
			for _, format := range []string{"dockerRepository", "mavenRepository", "npmRepository", "pythonRepository", "aptRepository", "yumRepository"} {
				v := Str(Get(data, "remoteRepositoryConfig", format, "publicRepository"))
				if v != "" && !strings.Contains(v, "UNSPECIFIED") {
					public = true
				}
			}
			priority := p["priority"]
			if priority == nil {
				priority = float64(0)
			}
			upstreams = append(upstreams, Object{"repository": name, "mode": mode, "priority": priority, "publicRemote": public})
		}
		item := NewAsset(a.Name+"/upstream-analysis", ArtifactUpstreamsType, Object{"resource": a.Name, "upstreams": upstreams})
		item.Ancestors = a.Ancestors
		derived = append(derived, item)
	}
	snap.Assets = append(snap.Assets, derived...)
}
