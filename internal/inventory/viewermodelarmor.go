package inventory

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const ModelArmorTemplateType = "gcpbuster.googleapis.com/ModelArmorTemplate"
const ModelArmorFloorSettingType = "gcpbuster.googleapis.com/ModelArmorFloorSetting"
const viewerModelArmorFilterContents = "piAndJailbreakFilterSettings(filterEnforcement,confidenceLevel),maliciousUriFilterSettings(filterEnforcement),raiSettings(raiFilters(filterType,confidenceLevel)),sdpSettings(basicConfig(filterEnforcement),advancedConfig(inspectTemplate,deidentifyTemplate))"
const viewerModelArmorFilters = "filterConfig(" + viewerModelArmorFilterContents + ")"
const viewerModelArmorTemplateFields = "templates(name,filterConfig(" + viewerModelArmorFilterContents + ",filterRuleSettings(ruleSets(filterTypes,rules(exclusionRule(regex(pattern),matchingScope,dictionary(wordList)))))),templateMetadata(enforcementType,ignorePartialInvocationFailures,logSanitizeOperations,logTemplateOperations,dataResidencyCompliant)),nextPageToken,unreachable"
const viewerModelArmorFloorFields = "name,enableFloorSettingEnforcement," + viewerModelArmorFilters
const viewerModelArmorLocationFields = "locations(name,locationId),nextPageToken"

var viewerModelArmorLocation = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var viewerModelArmorRegionalHost = regexp.MustCompile(`^modelarmor\.([a-z][a-z0-9-]{0,62})\.rep\.googleapis\.com$`)

func modelArmorProject(raw, projectID, number string) string {
	if strings.HasPrefix(raw, "projects/"+projectID+"/") {
		return number + strings.TrimPrefix(raw, "projects/"+projectID)
	}
	return raw
}

// Discovery publishes us-central1 as its bootstrap endpoint. Only locations
// returned by that scoped list are enumerated; no regional guesses or scans.
func (c *Client) CollectViewerModelArmor(ctx context.Context, out *Snapshot, projectID, number string) {
	if !viewerResourceName.MatchString(projectID) || !projectNumberPattern.MatchString(number) {
		out.record("viewer-modelarmor:identity", 0, fmt.Errorf("invalid project identity"))
		return
	}
	floorName := number + "/locations/global/floorSetting"
	floor, e := c.get(ctx, "https://modelarmor.googleapis.com/v1/"+floorName, url.Values{"fields": {viewerModelArmorFloorFields}})
	if e == nil {
		if modelArmorProject(Str(floor["name"]), projectID, number) != floorName {
			e = fmt.Errorf("invalid floor setting identity")
		} else {
			safe, pe := projectViewerModelArmor(floor)
			e = pe
			safe["name"] = floorName
			a := NewAsset("//modelarmor.googleapis.com/"+floorName, ModelArmorFloorSettingType, safe)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
	}
	out.record("viewer-modelarmor:floor:"+number, 1, e)
	locations := []string{}
	seen := map[string]bool{}
	partial := false
	e = c.viewerPages(ctx, "https://modelarmor.us-central1.rep.googleapis.com/v1/"+number+"/locations", url.Values{"fields": {viewerModelArmorLocationFields}, "pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "locations")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			loc := Str(d["locationId"])
			if !viewerModelArmorLocation.MatchString(loc) || modelArmorProject(Str(d["name"]), projectID, number) != number+"/locations/"+loc {
				partial = true
				continue
			}
			if loc == "global" {
				continue
			} // Global supports floor settings, not templates.
			if !seen[loc] {
				seen[loc] = true
				locations = append(locations, loc)
			}
		}
		return nil
	})
	if e == nil && partial {
		e = fmt.Errorf("some Model Armor locations invalid")
	}
	out.record("viewer-modelarmor:locations:"+number, len(locations), e)
	for _, loc := range locations {
		c.viewerModelArmorTemplates(ctx, out, projectID, number, loc)
	}
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-modelarmor:limitations:" + number, Status: "notice", Error: "Selected explicit configuration only. Bounded template exclusion-rule metadata is read transiently and projected to fixed literal-pattern indicators; raw patterns and dictionary words are not retained and arbitrary regular expressions are not executed. No prompts, responses, samples, sanitization, SDP template contents, effective inherited floor settings or application usage are read or tested. Advanced SDP references are discarded after recording configuration presence, never followed. Project floor metadata does not establish effective organization/folder enforcement; templates may be unused. Missing fields are unknown."})
}

func (c *Client) viewerModelArmorTemplates(ctx context.Context, out *Snapshot, projectID, number, loc string) {
	parent := number + "/locations/" + loc
	count := 0
	partial := false
	seen := map[string]bool{}
	e := c.viewerPages(ctx, "https://modelarmor."+loc+".rep.googleapis.com/v1/"+parent+"/templates", url.Values{"fields": {viewerModelArmorTemplateFields}, "pageSize": {"100"}}, func(page Object) error {
		rows, err := viewerRows(page, "templates")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			d := Obj(raw)
			name := modelArmorProject(Str(d["name"]), projectID, number)
			id := strings.TrimPrefix(name, parent+"/templates/")
			if !strings.HasPrefix(name, parent+"/templates/") || !viewerResourceName.MatchString(id) || seen[name] {
				partial = true
				continue
			}
			seen[name] = true
			safe, pe := projectViewerModelArmor(d)
			if pe != nil {
				partial = true
			}
			safe["name"] = name
			a := NewAsset("//modelarmor.googleapis.com/"+name, ModelArmorTemplateType, safe)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
			count++
		}
		return viewerAutomationPartial(page, &partial)
	})
	if e == nil && partial {
		e = fmt.Errorf("some Model Armor templates malformed or unreachable")
	}
	out.record("viewer-modelarmor:templates:"+parent, count, e)
}

func projectViewerModelArmor(raw Object) (Object, error) {
	out := Object{}
	valid := true
	var walk func(Object, Object, []string)
	walk = func(src, dst Object, path []string) {
		for k, v := range src {
			p := append(append([]string{}, path...), k)
			key := strings.Join(p, ".")
			choices := ""
			boolean := false
			switch key {
			case "filterConfig.sdpSettings.basicConfig.filterEnforcement":
				choices = "SDP_BASIC_CONFIG_ENFORCEMENT_UNSPECIFIED,ENABLED,DISABLED"
			case "filterConfig.sdpSettings.advancedConfig":
				m, ok := v.(map[string]any)
				if !ok {
					valid = false
					continue
				}
				for _, k := range []string{"inspectTemplate", "deidentifyTemplate"} {
					if v, exists := m[k]; exists {
						if _, ok := v.(string); !ok {
							valid = false
						}
					}
				}
				dst[k] = Object{}
				continue
			case "filterConfig.sdpSettings":
				m, ok := v.(map[string]any)
				if !ok {
					valid = false
					continue
				}
				_, basic := m["basicConfig"]
				_, advanced := m["advancedConfig"]
				if basic && advanced {
					valid = false
					continue
				}
				child := Object{}
				walk(m, child, p)
				dst[k] = child
				continue
			case "enableFloorSettingEnforcement", "templateMetadata.ignorePartialInvocationFailures", "templateMetadata.logSanitizeOperations", "templateMetadata.logTemplateOperations", "templateMetadata.dataResidencyCompliant":
				boolean = true
			case "templateMetadata.enforcementType":
				choices = "ENFORCEMENT_TYPE_UNSPECIFIED,INSPECT_ONLY,INSPECT_AND_BLOCK"
			case "filterConfig.piAndJailbreakFilterSettings.filterEnforcement":
				choices = "PI_AND_JAILBREAK_FILTER_ENFORCEMENT_UNSPECIFIED,ENABLED,DISABLED"
			case "filterConfig.maliciousUriFilterSettings.filterEnforcement":
				choices = "MALICIOUS_URI_FILTER_ENFORCEMENT_UNSPECIFIED,ENABLED,DISABLED"
			case "filterConfig.piAndJailbreakFilterSettings.confidenceLevel", "filterConfig.raiSettings.raiFilters.confidenceLevel":
				choices = "DETECTION_CONFIDENCE_LEVEL_UNSPECIFIED,LOW_AND_ABOVE,MEDIUM_AND_ABOVE,HIGH"
			case "filterConfig.raiSettings.raiFilters.filterType":
				choices = "RAI_FILTER_TYPE_UNSPECIFIED,SEXUALLY_EXPLICIT,HATE_SPEECH,HARASSMENT,DANGEROUS"
			case "filterConfig", "templateMetadata", "filterConfig.piAndJailbreakFilterSettings", "filterConfig.maliciousUriFilterSettings", "filterConfig.raiSettings", "filterConfig.sdpSettings.basicConfig":
				m, ok := v.(map[string]any)
				if !ok {
					valid = false
					continue
				}
				child := Object{}
				walk(m, child, p)
				dst[k] = child
				continue
			case "filterConfig.raiSettings.raiFilters":
				list, ok := v.([]any)
				if !ok {
					valid = false
					continue
				}
				safe := []any{}
				for _, r := range list {
					m, ok := r.(map[string]any)
					child := Object{}
					if !ok {
						valid = false
					} else {
						walk(m, child, p)
					}
					safe = append(safe, child)
				}
				dst[k] = safe
				continue
			default:
				continue
			}
			if boolean {
				if b, ok := v.(bool); ok {
					dst[k] = b
				} else {
					valid = false
				}
				continue
			}
			s, ok := v.(string)
			matched := false
			if ok {
				for _, allowed := range strings.Split(choices, ",") {
					if s == allowed {
						matched = true
						break
					}
				}
			}
			if matched {
				dst[k] = s
			} else {
				valid = false
			}
		}
	}
	walk(raw, out, nil)
	if v, exists := Obj(raw["filterConfig"])["filterRuleSettings"]; exists {
		marker := projectModelArmorExclusions(v)
		out["_gcpbusterModelArmorExclusions"] = marker
		if marker["complete"] != true {
			valid = false
		}
	}
	if !valid {
		out["projection_complete"] = false
		return out, fmt.Errorf("malformed selected Model Armor configuration")
	}
	return out, nil
}

func viewerModelArmorPermission(method string, u *url.URL, q url.Values) ([]string, error) {
	fields, permission := "", ""
	paged := false
	if u.Host == "modelarmor.googleapis.com" && regexp.MustCompile(`^/v1/projects/[0-9]+/locations/global/floorSetting$`).MatchString(u.Path) {
		fields = viewerModelArmorFloorFields
		permission = "modelarmor.floorSettings.get"
	}
	if h := viewerModelArmorRegionalHost.FindStringSubmatch(u.Host); h != nil {
		if u.Host == "modelarmor.us-central1.rep.googleapis.com" && regexp.MustCompile(`^/v1/projects/[0-9]+/locations$`).MatchString(u.Path) {
			fields = viewerModelArmorLocationFields
			permission = "modelarmor.locations.list"
			paged = true
		}
		if regexp.MustCompile(`^/v1/projects/[0-9]+/locations/` + regexp.QuoteMeta(h[1]) + `/templates$`).MatchString(u.Path) {
			fields = viewerModelArmorTemplateFields
			permission = "modelarmor.templates.list"
			paged = true
		}
	}
	if method != "GET" || fields == "" || q.Get("fields") != fields || (paged && q.Get("pageSize") != "100") {
		return nil, fmt.Errorf("viewer-only policy: unreviewed Model Armor request")
	}
	for k, v := range q {
		if len(v) != 1 || (k != "fields" && !(paged && (k == "pageSize" || k == "pageToken"))) {
			return nil, fmt.Errorf("viewer-only policy: unreviewed Model Armor query")
		}
	}
	return []string{permission}, nil
}
