package inventory

import "strings"

// resolveGatewayAccountUID resolves only the ApiConfig reference format
// documented by API Gateway. A project-number alias must be observed on the
// matching account, never inferred from an email or workload project number.
func resolveGatewayAccountUID(config Asset, assets []Asset) string {
	ref := strings.Split(Str(config.Resource.Data["gatewayServiceAccount"]), "/")
	if len(ref) != 4 || ref[0] != "projects" || !viewerResourceName.MatchString(ref[1]) || ref[2] != "accounts" || !viewerNumericID.MatchString(ref[3]) {
		return ""
	}
	email := ""
	matched := false
	project := ""
	number := ""
	for _, a := range assets {
		if a.Type != "iam.googleapis.com/ServiceAccount" || Str(a.Resource.Data["uniqueId"]) != ref[3] {
			continue
		}
		d := a.Resource.Data
		p := Str(d["projectId"])
		e := Str(d["email"])
		name := Str(d["name"])
		if !viewerResourceName.MatchString(p) || !serviceAccountEmail.MatchString(e) || (name != "projects/"+p+"/serviceAccounts/"+e && name != "projects/"+p+"/serviceAccounts/"+ref[3]) || a.Name != "//iam.googleapis.com/"+name {
			return ""
		}
		if email != "" && (email != e || project != p) {
			return ""
		}
		email = e
		project = p
		scopeMatch := p == ref[1]
		observedNumber := ""
		for _, ancestor := range a.Ancestors {
			if projectNumberPattern.MatchString(ancestor) {
				if observedNumber != "" && observedNumber != ancestor {
					return ""
				}
				observedNumber = ancestor
			}
			if projectNumberPattern.MatchString(ancestor) && ancestor == "projects/"+ref[1] {
				scopeMatch = true
			}
		}
		if observedNumber != "" {
			if number != "" && number != observedNumber {
				return ""
			}
			number = observedNumber
		}
		if scopeMatch {
			matched = true
		}
	}
	if !matched {
		return ""
	}
	return email
}
