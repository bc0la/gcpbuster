package inventory

import (
	"context"
	"sync"
	"time"
)

type viewerProject struct{ id, number string }
type viewerCollector func(context.Context, *Snapshot, string, string)
type viewerFamily struct {
	name    string
	collect []viewerCollector
}
type viewerTask struct {
	scope, family string
	run           func()
	out           *Snapshot
}

// runViewerTasks uses one global pool for a stage: projects never create nested
// service pools. Library callers default to serial; the CLI explicitly opts in.
// The dispatcher checks cancellation before handing out any more work, and each
// worker checks it again after receiving a task. In-flight HTTP uses the context.
func (c *Client) runViewerTasks(ctx context.Context, tasks []viewerTask) {
	n := c.Concurrency
	if n < 1 {
		n = 1
	}
	if n > len(tasks) {
		n = len(tasks)
	}
	if n == 0 {
		return
	}
	queue := make(chan viewerTask)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range queue {
				if ctx.Err() != nil {
					continue
				}
				started := time.Now()
				c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Collector: task.family, Status: "started"})
				task.run()
				status := "completed"
				count, failures := 0, 0
				if task.out != nil {
					count = len(task.out.Assets)
					for _, coverage := range task.out.Coverage {
						if coverage.Status == "failed" || coverage.Status == "incomplete" {
							failures++
						}
					}
				}
				if ctx.Err() != nil {
					status = "cancelled"
				}
				c.ReportProgress(ProgressEvent{Phase: "collector", Scope: task.scope, Collector: task.family, Status: status, Count: count, Failures: failures, Duration: time.Since(started)})
			}
		}()
	}
dispatch:
	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break dispatch
		case queue <- task:
		}
	}
	close(queue)
	wg.Wait()
}

// Dependent enrichers remain ordered in the same family and share only their
// own snapshot. Independent families never read or mutate another's output.
func (c *Client) viewerFamilies() []viewerFamily {
	return []viewerFamily{
		{"compute-network", []viewerCollector{c.viewerCompute, c.CollectViewerBackendServices, c.CollectViewerRoutes, c.CollectViewerComputeExtras, c.CollectViewerComputeDisks, c.CollectViewerNetworks, c.CollectViewerEffectiveFirewalls, c.CollectViewerRegionalEffectiveFirewalls}},
		{"model-armor", []viewerCollector{c.CollectViewerModelArmor}},
		{"storage", []viewerCollector{c.viewerBuckets}},
		{"sql-gke", []viewerCollector{c.CollectViewerSQLGKE}},
		{"redis", []viewerCollector{c.CollectViewerRedis}},
		{"memcache", []viewerCollector{c.CollectViewerMemcache}},
		{"alloydb", []viewerCollector{c.CollectViewerAlloyDB, c.CollectViewerAlloyDBUsers}},
		{"filestore", []viewerCollector{c.CollectViewerFilestore}},
		{"bigtable", []viewerCollector{c.CollectViewerBigtable, c.CollectViewerBigtableAuthorizedViews}},
		{"spanner", []viewerCollector{c.CollectViewerSpanner, c.CollectViewerSpannerDDL}},
		{"firestore", []viewerCollector{c.CollectViewerFirestore}},
		{"healthcare", []viewerCollector{c.CollectViewerHealthcare}},
		{"apigee", []viewerCollector{c.CollectViewerApigee}},
		{"serverless-build-workflows", []viewerCollector{c.CollectViewerServerless, c.CollectViewerBuildWorkflows, c.CollectViewerWorkflowExecutions, c.CollectViewerHistoricalSecrets, c.CollectViewerBuildRepositoryReferences}},
		{"dns", []viewerCollector{c.CollectViewerDNSIAM, c.CollectViewerDNSRecords, c.CollectViewerDNSPolicies, c.CollectViewerDNSResponseRules}},
		{"api-keys", []viewerCollector{c.CollectViewerAPIKeys}},
		{"secrets-kms", []viewerCollector{c.CollectViewerKeyMetadata, c.CollectViewerRegionalSecrets, c.CollectViewerSecretAliases, c.CollectViewerSecretIAM}},
		{"parameters", []viewerCollector{c.CollectViewerParameterManager}},
		{"deployment-manager", []viewerCollector{c.CollectViewerDeploymentManager}},
		{"automation", []viewerCollector{c.CollectViewerAutomation}},
		{"pubsub", []viewerCollector{c.CollectViewerPubSub, c.CollectViewerPubSubSchemas, c.CollectViewerPubSubSnapshots}},
		{"data-identity-config", []viewerCollector{c.CollectViewerDataConfig}},
		{"tasks-vertex", []viewerCollector{c.CollectViewerTasksVertex}},
		// Managed compiled configs correlate explicit API Gateway deployment pins.
		{"api-gateway-service-management", []viewerCollector{c.CollectViewerAPIGateway, c.CollectViewerServiceManagement}},
		{"service-usage", []viewerCollector{c.CollectViewerServiceUsage}},
		{"app-engine", []viewerCollector{c.CollectViewerAppEngine, c.CollectViewerAppEngineFirewall}},
		{"federation", []viewerCollector{c.CollectViewerFederation}},
		{"dataflow", []viewerCollector{c.CollectViewerDataflow}},
		{"dataproc", []viewerCollector{c.CollectViewerDataprocSecrets}},
		{"workbench", []viewerCollector{c.CollectViewerNotebookSecrets}},
		{"cloud-deploy", []viewerCollector{c.CollectViewerCloudDeploy}},
		{"app-hosting", []viewerCollector{c.CollectViewerAppHosting}},
		{"data-fusion", []viewerCollector{c.CollectViewerDataFusionSecrets}},
		{"composer", []viewerCollector{c.CollectViewerComposer}},
	}
}
