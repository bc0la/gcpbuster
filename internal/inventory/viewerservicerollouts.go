package inventory

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const ServiceRolloutType = "gcpbuster.googleapis.com/ServiceRollout"
const viewerServiceRolloutFields = "rollouts(rolloutId,serviceName,createTime,status,trafficPercentStrategy(percentages)),nextPageToken"

var viewerServiceRolloutID = regexp.MustCompile(`^[a-z0-9._-]{1,63}$`)

// Called only after the parent collector confirms service producer ownership.
// SUCCESS is historical control-plane status, never current runtime deployment.
func (c *Client) viewerManagedServiceRollouts(ctx context.Context, out *Snapshot, projectID, number, service string) {
	start, partial := len(out.Assets), false
	seen := map[string]bool{}
	err := c.viewerPages(ctx, "https://servicemanagement.googleapis.com/v1/services/"+service+"/rollouts", url.Values{"pageSize": {"100"}, "filter": {"strategy=TrafficPercentStrategy"}, "fields": {viewerServiceRolloutFields}}, func(page Object) error {
		rows, err := viewerRows(page, "rollouts")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			clean, err := viewerServiceRolloutProjection(Obj(raw), service)
			if err != nil {
				partial = true
				continue
			}
			id := Str(clean["rolloutId"])
			if seen[id] {
				continue
			}
			seen[id] = true
			clean["producerProjectId"] = projectID
			a := NewAsset("//servicemanagement.googleapis.com/services/"+service+"/rollouts/"+id, ServiceRolloutType, clean)
			a.Ancestors = []string{number}
			out.Assets = append(out.Assets, a)
		}
		return viewerAutomationPartial(page, &partial)
	})
	if err == nil && partial {
		err = fmt.Errorf("some rollout history metadata was malformed or unavailable")
	}
	out.record("viewer-service-management:rollouts:"+service, len(out.Assets)-start, err)
	out.Coverage = append(out.Coverage, Coverage{Source: "viewer-service-management:rollout-history:" + service, Status: "notice", Error: "Retained traffic-percentage rollout history only; deletion strategies are excluded. SUCCESS records are not asserted to be the current rollout or current API Gateway/ESP deployment. Failed, cancelled or superseded records remain temporal evidence; no service traffic is generated or changed."})
}

// Attach only exact config references from validated same-service history.
// No ordering or SUCCESS status is converted into a current-deployment claim.
func correlateServiceRolloutHistory(out *Snapshot, projectID string) {
	history := map[string][]any{}
	for _, a := range out.Assets {
		if a.Type != ServiceRolloutType || Str(a.Resource.Data["producerProjectId"]) != projectID {
			continue
		}
		service := Str(a.Resource.Data["serviceName"])
		if !viewerManagedServiceName.MatchString(service) {
			continue
		}
		clean, err := viewerServiceRolloutProjection(a.Resource.Data, service)
		if err != nil || a.Name != "//servicemanagement.googleapis.com/services/"+service+"/rollouts/"+Str(clean["rolloutId"]) {
			continue
		}
		for id, weight := range Obj(Get(clean, "trafficPercentStrategy", "percentages")) {
			target := "//servicemanagement.googleapis.com/services/" + service + "/configs/" + id
			history[target] = append(history[target], Object{"rolloutId": clean["rolloutId"], "status": clean["status"], "createTime": clean["createTime"], "percentage": weight})
		}
	}
	for i := range out.Assets {
		a := &out.Assets[i]
		if a.Type != ServiceConfigType || Str(a.Resource.Data["producerProjectId"]) != projectID {
			continue
		}
		delete(a.Resource.Data, "_gcpbusterRolloutHistory")
		service, id := Str(a.Resource.Data["name"]), Str(a.Resource.Data["id"])
		if !viewerManagedServiceName.MatchString(service) || !viewerManagedConfigID.MatchString(id) || a.Name != "//servicemanagement.googleapis.com/services/"+service+"/configs/"+id {
			continue
		}
		rows := history[a.Name]
		sort.SliceStable(rows, func(i, j int) bool { return Str(Obj(rows[i])["rolloutId"]) < Str(Obj(rows[j])["rolloutId"]) })
		if len(rows) > 0 {
			a.Resource.Data["_gcpbusterRolloutHistory"] = rows
		}
	}
}

func viewerServiceRolloutProjection(d Object, service string) (Object, error) {
	bad := func() (Object, error) { return nil, fmt.Errorf("invalid rollout history metadata") }
	id := Str(d["rolloutId"])
	if !viewerServiceRolloutID.MatchString(id) || id == "." || id == ".." {
		return bad()
	}
	if name, exists := d["serviceName"]; exists && name != service {
		return bad()
	}
	stamp := Str(d["createTime"])
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		return bad()
	}
	status := Str(d["status"])
	switch status {
	case "ROLLOUT_STATUS_UNSPECIFIED", "IN_PROGRESS", "SUCCESS", "CANCELLED", "FAILED", "PENDING", "FAILED_ROLLED_BACK":
	default:
		return bad()
	}
	if _, exists := d["deleteServiceStrategy"]; exists {
		return bad()
	}
	strategy := Obj(d["trafficPercentStrategy"])
	if strategy == nil {
		return bad()
	}
	weights := Obj(strategy["percentages"])
	if len(weights) == 0 {
		return bad()
	}
	cleanWeights := Object{}
	total := 0.0
	for key, raw := range weights {
		config := strings.TrimPrefix(key, service+"/")
		if !viewerManagedConfigID.MatchString(config) {
			return bad()
		}
		if _, exists := cleanWeights[config]; exists {
			return bad()
		}
		weight, ok := raw.(float64)
		if !ok || math.IsNaN(weight) || math.IsInf(weight, 0) || weight <= 0 || weight > 100 {
			return bad()
		}
		total += weight
		cleanWeights[config] = weight
	}
	if math.Abs(total-100) > 0.000001 {
		return bad()
	}
	return Object{"rolloutId": id, "serviceName": service, "createTime": stamp, "status": status, "trafficPercentStrategy": Object{"percentages": cleanWeights}, "_gcpbusterTemporalScope": "retained_history_not_current"}, nil
}
