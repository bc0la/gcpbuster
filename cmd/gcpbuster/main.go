package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/engagement"
	"github.com/bc0la/gcpbuster/internal/findings"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/kingfisher"
	"github.com/bc0la/gcpbuster/internal/permissioncatalog"
	"github.com/bc0la/gcpbuster/internal/report"
	"github.com/spf13/cobra"
)

var scopePattern = regexp.MustCompile(`^(projects|folders|organizations)/[A-Za-z0-9][A-Za-z0-9._:-]*$`)

func rootCommand() *cobra.Command {
	root := &cobra.Command{Use: "gcpbuster", Short: "GCP and Workspace security checks in four assessment categories", SilenceUsage: true, SilenceErrors: true, Version: "0.1.0"}
	root.AddCommand(scanCommand(), reportCommand(), collectCommand(), coverageCommand())
	root.AddCommand(&cobra.Command{Use: "modules", Short: "List checks, categories, supported asset types and sources as JSON", RunE: func(cmd *cobra.Command, _ []string) error {
		e := json.NewEncoder(cmd.OutOrStdout())
		e.SetIndent("", "  ")
		return e.Encode(map[string]any{"categories": checks.Categories, "native": checks.All, "external": []map[string]string{{"id": "scoutsuite", "category": "best_practices", "command": "collect", "status": "disabled: exact viewer-role boundary is not enforced by external processes"}}})
	}})
	return root
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := rootCommand().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func scanCommand() *cobra.Command {
	var scopes, projects, files, ids, categories, exclude []string
	var dir, tokenEnv, workspaceTokenEnv, impersonate, customer string
	var tokens, resume, dnsChecks, refreshConfig, resolveRoles bool
	var storage inventory.StorageOptions
	var scanSources bool
	var scanLogs bool
	var noSecrets, redactSecrets bool
	var orgPolicyChecks bool
	var workspaceMembers bool
	var ancestorIAM bool
	var loggingConfig bool
	var iapPolicies, iapSettings bool
	var logOptions inventory.LogOptions
	var logLookback time.Duration
	var verbose bool
	var concurrency int
	var perProjectConcurrency int
	var forceUI, noUI bool
	cmd := &cobra.Command{Use: "scan", Short: "Assess Viewer-readable GCP metadata or offline GCP/Workspace inventory", RunE: func(cmd *cobra.Command, _ []string) error {
		if concurrency < 1 || concurrency > 64 {
			return errors.New("--concurrency must be between 1 and 64")
		}
		if perProjectConcurrency < 1 || perProjectConcurrency > 64 {
			return errors.New("--per-project-concurrency must be between 1 and 64")
		}
		if impersonate != "" {
			return errors.New("service-account impersonation is disabled: it requires authority beyond the allowed Viewer roles")
		}
		if customer != "" || tokens || workspaceMembers || workspaceTokenEnv != "" {
			return errors.New("live Workspace collection is disabled: the three allowed GCP Viewer roles grant no Workspace Directory authority; only offline Workspace evidence can be evaluated")
		}
		if storage.ScanContent || scanSources || storage.Anonymous {
			return errors.New("storage payload/source scans and list-backed anonymous probes are disabled under the exact Viewer-role profile: required object reads/listing are not granted by the allowed roles")
		}
		if iapPolicies {
			return errors.New("--iap-policies is disabled: IAP getIamPolicy permissions are outside the three allowed Viewer roles; --iap-settings uses a separate permission path")
		}
		selected, err := checks.Select(ids, categories, exclude)
		if err != nil {
			return err
		}
		if noSecrets {
			filtered := selected[:0]
			for _, check := range selected {
				if check.ID != "secrets_scan" {
					filtered = append(filtered, check)
				}
			}
			selected = filtered
		}
		kingfisherSelected, plaintextSelected, parameterReferencesSelected := false, false, false
		for _, check := range selected {
			kingfisherSelected = kingfisherSelected || check.ID == "secrets_scan"
			plaintextSelected = plaintextSelected || check.ID == "configuration_plaintext"
			parameterReferencesSelected = parameterReferencesSelected || check.ID == "parameter_reference_delegation"
		}
		for _, p := range projects {
			scopes = append(scopes, "projects/"+p)
		}
		for _, scope := range scopes {
			if !scopePattern.MatchString(scope) {
				return fmt.Errorf("invalid scope %q; use projects/ID, folders/NUMBER or organizations/NUMBER", scope)
			}
		}
		if len(scopes) == 0 && len(files) == 0 && customer == "" {
			return errors.New("specify --project, --scope or --inventory")
		}
		if tokens && customer == "" {
			return errors.New("--workspace-tokens requires --workspace-customer")
		}
		if workspaceMembers && customer == "" {
			return errors.New("--workspace-members requires --workspace-customer")
		}
		if ancestorIAM && len(scopes) == 0 {
			return errors.New("--ancestor-iam requires a live --project or --scope")
		}
		if loggingConfig && len(scopes) == 0 {
			return errors.New("--logging-config requires a live --project or --scope")
		}
		if iapPolicies && len(scopes) == 0 {
			return errors.New("--iap-policies requires a live --project or --scope")
		}
		if iapSettings && len(scopes) == 0 {
			return errors.New("--iap-settings requires a live --project or --scope")
		}
		if orgPolicyChecks {
			if len(scopes) == 0 {
				return errors.New("--org-policy-checks requires a live --project or --scope")
			}
			found := false
			for _, c := range selected {
				found = found || c.ID == "org_policy_guardrails"
			}
			if !found {
				return errors.New("--org-policy-checks requires selecting org_policy_guardrails")
			}
		}
		if len(files) > 0 && (len(scopes) > 0 || customer != "") {
			return errors.New("use either offline --inventory inputs or live scope/customer collection; merge exports with repeated --inventory")
		}
		if storage.Anonymous || storage.ScanContent || scanSources {
			if len(scopes) == 0 {
				return errors.New("storage probes/content collection require an explicit live --project or --scope")
			}
			if err := storage.Validate(); err != nil {
				return err
			}
			selectedIDs := map[string]bool{}
			for _, c := range selected {
				selectedIDs[c.ID] = true
			}
			if storage.Anonymous && !selectedIDs["gcs_anonymous_access"] {
				return errors.New("--anonymous-storage requires selecting gcs_anonymous_access")
			}
			if (storage.ScanContent || scanSources) && !selectedIDs["gcs_content_secrets"] {
				return errors.New("--scan-gcs-content requires selecting gcs_content_secrets")
			}
		}
		if scanLogs {
			if len(scopes) == 0 {
				return errors.New("--scan-logs requires a live --project or --scope")
			}
			logOptions.Until = time.Now().UTC()
			logOptions.Since = logOptions.Until.Add(-logLookback)
			if err := logOptions.Validate(); err != nil {
				return err
			}
			found := false
			for _, c := range selected {
				found = found || c.ID == "log_content_secrets"
			}
			if !found {
				return errors.New("--scan-logs requires selecting log_content_secrets")
			}
		}
		if resume && dir == "" {
			return errors.New("--resume requires --engagement")
		}
		if dir == "" {
			dir = filepath.Join("engagements", time.Now().UTC().Format("20060102T150405.000000000Z"))
		}
		var snap inventory.Snapshot
		for _, path := range files {
			part, err := inventory.Load(path)
			if err != nil {
				return err
			}
			snap.Assets = append(snap.Assets, part.Assets...)
			snap.Coverage = append(snap.Coverage, part.Coverage...)
			snap.Coverage = append(snap.Coverage, inventory.Coverage{Source: path, Status: "provided", Count: len(part.Assets), Error: "Offline records only; freshness, omitted resources, ancestor policies and export completeness are not verified."})
		}
		progress := newScanProgressWithSink(cmd.ErrOrStderr(), verbose, progressSink(cmd.Context()))
		cmd.SetErr(progress.writer)
		defer progress.Close()
		client := &inventory.Client{TokenEnv: tokenEnv, Impersonate: impersonate, DNSChecks: dnsChecks, RefreshConfig: refreshConfig, Concurrency: concurrency, PerProjectConcurrency: perProjectConcurrency, Progress: progress.Report}
		if len(scopes) > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "Collection concurrency: %d global workers, %d per project\n", concurrency, perProjectConcurrency)
		}
		if kingfisherSelected || plaintextSelected || parameterReferencesSelected {
			client.SecretCapture = inventory.NewSecretCapture(10000, 4<<20, 64<<20)
			if !redactSecrets {
				fmt.Fprintln(cmd.ErrOrStderr(), "Secret values will be retained in private reports for manual validation; credential validation is disabled.")
			}
		}
		seen := map[string]bool{}
		for _, scope := range scopes {
			if seen[scope] {
				continue
			}
			seen[scope] = true
			fmt.Fprintln(cmd.ErrOrStderr(), "Collecting", scope)
			part := client.ViewerCloud(cmd.Context(), scope)
			snap.Assets = append(snap.Assets, part.Assets...)
			snap.Coverage = append(snap.Coverage, part.Coverage...)
		}
		if customer != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "Collecting Workspace", customer)
			if workspaceTokenEnv == "" {
				workspaceTokenEnv = tokenEnv
			}
			wc := &inventory.Client{TokenEnv: workspaceTokenEnv, Impersonate: impersonate, WorkspaceMembers: workspaceMembers}
			part := wc.Workspace(cmd.Context(), customer, tokens)
			snap.Assets = append(snap.Assets, part.Assets...)
			snap.Coverage = append(snap.Coverage, part.Coverage...)
		}
		if ancestorIAM {
			fmt.Fprintln(cmd.ErrOrStderr(), "Reading selected-container and ancestor IAM policies")
			client.CollectAncestorIAM(cmd.Context(), &snap, scopes)
		}
		snap.Assets = mergeAssets(snap.Assets)
		var descendantScopes []string
		if scanLogs || orgPolicyChecks || loggingConfig || iapPolicies || iapSettings {
			descendantScopes = client.ExpandResourceScopes(cmd.Context(), &snap, scopes)
		}
		if iapPolicies || iapSettings {
			fmt.Fprintln(cmd.ErrOrStderr(), "Discovering global backend services for IAP review")
			client.CollectIAPBackends(cmd.Context(), &snap, descendantScopes)
			snap.Assets = mergeAssets(snap.Assets)
			fmt.Fprintln(cmd.ErrOrStderr(), "Discovering App Engine service/version identities for IAP review")
			client.CollectAppEngineIAP(cmd.Context(), &snap)
			snap.Assets = mergeAssets(snap.Assets)
		}
		if iapSettings {
			fmt.Fprintln(cmd.ErrOrStderr(), "Reading discovered IAP web and ancestor settings")
			client.CollectIAPSettings(cmd.Context(), &snap)
		}
		if iapPolicies {
			fmt.Fprintln(cmd.ErrOrStderr(), "Reading discovered IAP resource policies")
			client.CollectIAPPolicies(cmd.Context(), &snap)
		}
		if len(scopes) > 0 && resolveRoles {
			fmt.Fprintln(cmd.ErrOrStderr(), "Resolving IAM role definitions")
			client.ResolveRoles(cmd.Context(), &snap)
		}
		if err := cmd.Context().Err(); err != nil {
			return err
		}
		snap.Assets = mergeAssets(snap.Assets)
		if storage.Anonymous || storage.ScanContent {
			fmt.Fprintln(cmd.ErrOrStderr(), "Inspecting discovered Cloud Storage objects")
			client.CollectStorage(cmd.Context(), &snap, storage)
		}
		if scanSources {
			fmt.Fprintln(cmd.ErrOrStderr(), "Inspecting GCS-backed workload source archives")
			client.RefreshAppEngineSources(cmd.Context(), &snap)
			client.CollectSources(cmd.Context(), &snap, storage)
		}
		if loggingConfig {
			fmt.Fprintln(cmd.ErrOrStderr(), "Reading Logging sinks, exclusions, buckets, views/IAM, links and metric metadata")
			client.CollectLoggingConfig(cmd.Context(), &snap, descendantScopes)
			client.CollectViewerLogBuckets(cmd.Context(), &snap, descendantScopes)
			client.CollectViewerLogViews(cmd.Context(), &snap, descendantScopes)
			client.CollectViewerLogLinks(cmd.Context(), &snap, descendantScopes)
			client.CollectViewerLogMetrics(cmd.Context(), &snap, descendantScopes)
			snap.Assets = mergeAssets(snap.Assets)
		}
		if orgPolicyChecks {
			fmt.Fprintln(cmd.ErrOrStderr(), "Reading selected effective organization policies")
			client.CollectOrgPolicies(cmd.Context(), &snap, descendantScopes)
		}
		if scanLogs {
			fmt.Fprintln(cmd.ErrOrStderr(), "Inspecting bounded Cloud Logging entries")
			client.CollectLogs(cmd.Context(), &snap, descendantScopes, logOptions)
		}
		if err := cmd.Context().Err(); err != nil {
			return err
		}
		snap.Coverage = append(snap.Coverage, inventory.Coverage{Source: "assessment-limitations", Status: "notice", Error: "Cloud Asset Inventory is eventually consistent and does not include every service/field. Direct IAM policies are not effective-permission calculations. Parent-chain IAM collection requires --ancestor-iam. IAM deny, access boundaries, VPC service controls and general endpoint reachability are not resolved. Selected effective organization-policy guardrails require --org-policy-checks; other constraints remain unassessed. Workspace DWD, Gmail and Drive checks require explicit offline exports. Storage anonymous probes, object/workload-source content and Cloud Logging scans are opt-in; limits and coverage records bound those results. No secret-manager payloads or message bodies are downloaded."})
		if client.SecretCapture != nil {
			if len(files) > 0 {
				client.SecretCapture.CaptureInventory(snap.Assets)
			}
			prepareSecrets(cmd.Context(), &snap, client.SecretCapture, redactSecrets, kingfisherSelected, plaintextSelected, kingfisher.Run)
		} else if redactSecrets {
			snap.SecretValueMode = "redacted"
		}
		e, err := engagement.Open(dir)
		if err != nil {
			return err
		}
		defer e.Close()
		return assess(cmd.Context(), cmd, e, snap, selected, resume)
	}}
	f := cmd.Flags()
	f.BoolVar(&forceUI, "ui", false, "Use interactive Progress/Logs tabs (automatically enabled on a terminal)")
	f.BoolVar(&noUI, "no-ui", false, "Disable terminal UI; use plain progress output")
	f.IntVar(&perProjectConcurrency, "per-project-concurrency", 4, "Maximum parallel collection jobs per project, within --concurrency (1-64)")
	f.BoolVar(&verbose, "verbose", false, "Show request-level progress and timings; tokens, bodies and secret values are never logged")
	f.IntVar(&concurrency, "concurrency", 8, "Maximum parallel collection jobs across projects and service families (1-64; 1 for serial)")
	f.BoolVar(&noSecrets, "no-secrets", false, "Skip Kingfisher; native plaintext configuration reporting remains independently selectable")
	f.BoolVar(&redactSecrets, "redact-secrets", false, "Suppress actual secret values and raw-hit artifacts in all new secret findings; use a fresh engagement")
	f.StringSliceVar(&projects, "project", nil, "Project IDs/numbers (repeat or comma-separate)")
	f.StringSliceVar(&scopes, "scope", nil, "Explicit projects/ID, folders/NUMBER or organizations/NUMBER")
	f.StringArrayVar(&files, "inventory", nil, "Offline CAI JSON/JSONL or GCPBuster snapshot; repeat for resource/IAM/Workspace exports")
	f.StringVar(&dir, "engagement", "", "Output engagement directory")
	f.StringSliceVar(&ids, "modules", nil, "Only named checks (see modules)")
	f.StringSliceVar(&categories, "category", nil, "best_practices,secrets,iam,exposure")
	f.StringSliceVar(&exclude, "exclude", nil, "Exclude named checks")
	f.StringVar(&tokenEnv, "token-env", "", "Environment variable containing a bearer token; default: gcloud active identity")
	f.StringVar(&impersonate, "impersonate-service-account", "", "Disabled: impersonation exceeds the Viewer-role boundary")
	f.StringVar(&customer, "workspace-customer", "", "Disabled: live Workspace requires separate Directory authority")
	f.StringVar(&workspaceTokenEnv, "workspace-token-env", "", "Disabled: use offline Workspace inventory")
	f.BoolVar(&tokens, "workspace-tokens", false, "Disabled: use offline Workspace inventory")
	f.BoolVar(&workspaceMembers, "workspace-members", false, "Disabled: use offline Workspace inventory")
	f.BoolVar(&ancestorIAM, "ancestor-iam", false, "Read IAM allow policies on selected containers and their parent chains; no sibling-resource discovery")
	f.BoolVar(&loggingConfig, "logging-config", false, "Refresh Logging sink, exclusion, bucket, view/IAM, link and metric metadata")
	f.BoolVar(&iapPolicies, "iap-policies", false, "Disabled: IAP IAM policy reads exceed the Viewer-role boundary")
	f.BoolVar(&iapSettings, "iap-settings", false, "Read IAP settings for discovered web resources and supplied ancestor containers")
	f.BoolVar(&dnsChecks, "dns-checks", false, "List public-zone CNAME records and resolve targets for dangling-DNS candidates")
	f.BoolVar(&refreshConfig, "refresh-compute-config", true, "Refresh Compute metadata through direct GETs (CAI can omit custom metadata)")
	f.BoolVar(&resolveRoles, "resolve-roles", true, "Resolve assigned IAM role definitions for permission-based checks")
	f.BoolVar(&storage.Anonymous, "anonymous-storage", false, "Disabled: supporting object discovery exceeds the Viewer-role boundary")
	f.BoolVar(&storage.ScanContent, "scan-gcs-content", false, "Disabled: GCS object reads exceed the Viewer-role boundary")
	f.BoolVar(&scanSources, "scan-source-archives", false, "Disabled: GCS source reads exceed the Viewer-role boundary")
	f.BoolVar(&scanLogs, "scan-logs", false, "Read bounded non-private Cloud Logging entries; Kingfisher follows the selected secret-value policy")
	f.BoolVar(&orgPolicyChecks, "org-policy-checks", false, "Read selected effective organization-policy guardrails, including discovered descendants")
	f.IntVar(&logOptions.MaxEntries, "logs-max-entries", 1000, "Maximum log entries per selected or discovered descendant container")
	f.IntVar(&logOptions.MaxPages, "logs-max-pages", 100, "Maximum log pages per container, including empty continuation pages")
	f.DurationVar(&logLookback, "logs-lookback", 24*time.Hour, "Time window preceding scan start for Cloud Logging")
	f.StringVar(&logOptions.Filter, "log-filter", "", "Additional Cloud Logging filter within the selected resource/time window")
	f.IntVar(&storage.MaxObjects, "storage-max-objects", 100, "Maximum objects inspected per bucket; reaching the cap is incomplete coverage")
	f.Int64Var(&storage.MaxObjectBytes, "storage-max-object-bytes", 1<<20, "Maximum content bytes per object (up to 64 MiB)")
	f.Int64Var(&storage.MaxArchiveBytes, "storage-max-archive-bytes", 10<<20, "Maximum total decompressed ZIP bytes per object (up to 256 MiB)")
	f.IntVar(&storage.MaxArchiveEntries, "storage-max-archive-entries", 1000, "Maximum ZIP entries inspected per object")
	f.StringVar(&storage.Prefix, "storage-prefix", "", "Restrict storage object collection to this prefix")
	f.BoolVar(&resume, "resume", false, "Skip completed checks only when the inventory fingerprint matches")
	run := cmd.RunE
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runWithTerminalUI(cmd, args, run, forceUI, noUI)
	}
	return cmd
}

func mergeAssets(in []inventory.Asset) []inventory.Asset {
	var out []inventory.Asset
	indices := map[string]int{}
	for _, a := range in {
		key := a.Type + "|" + a.Name
		if i, ok := indices[key]; ok {
			if a.Resource.Data != nil {
				out[i].Resource = a.Resource
			}
			// Indexed search bindings are partial/eventually consistent. Keep a
			// full supplied or directly read policy regardless of input order.
			if a.IAM != nil && (out[i].IAM == nil || inventory.Bool(out[i].IAM["_gcpbusterBindingsOnly"]) || !inventory.Bool(a.IAM["_gcpbusterBindingsOnly"])) {
				out[i].IAM = a.IAM
			}
			if len(a.Ancestors) > 0 {
				out[i].Ancestors = a.Ancestors
			}
		} else {
			indices[key] = len(out)
			out = append(out, a)
		}
	}
	return out
}

func assess(ctx context.Context, cmd *cobra.Command, e *engagement.Engagement, snap inventory.Snapshot, selected []checks.Check, resume bool) error {
	if snap.SecretValueMode == "redacted" {
		redactSuppliedSecretAssets(&snap)
	}
	snap.Assets = append(snap.Assets, checks.SecretAliasAssets(snap.Assets)...)
	raw, _ := json.Marshal(snap.Assets)
	if snap.SecretValueMode == "redacted" {
		// Redacted engagements cannot resume. Do not retain even a digest of
		// raw configuration values that happened to be present in memory.
		raw = nil
		snap.SecretFingerprint = nil
	}
	fingerprintInput := append([]byte("gcpbuster-analysis-v44-viewer:"+permissioncatalog.SHA256()+":"+snap.SecretValueMode+":"), raw...)
	fingerprintInput = append(fingerprintInput, snap.SecretFingerprint...)
	if snap.SecretValueMode == "redacted" {
		oldMode, exists, err := e.GetMeta(ctx, "secret_value_policy")
		if err != nil {
			return err
		}
		if exists && oldMode == "actual" {
			return errors.New("cannot reuse an engagement that retained actual secrets in redacted mode; choose a fresh directory")
		}
		if resume {
			return errors.New("redacted secret scans require a fresh engagement; secret-derived resume fingerprints are not persisted")
		}
	}
	permissionAnalysis, artifactAnalysis, groupAnalysis, workloadAnalysis := false, false, false, false
	auditAnalysis, buildAnalysis, rotationAnalysis := false, false, false
	for _, c := range selected {
		buildAnalysis = buildAnalysis || c.ID == "cloud_build_pr_comment_control" || c.ID == "cloud_build_mirrored_source"
		for _, typ := range c.Types {
			rotationAnalysis = rotationAnalysis || typ == checks.ManagedRotationPrerequisiteType
			permissionAnalysis = permissionAnalysis || typ == inventory.PermissionGrantType
			artifactAnalysis = artifactAnalysis || typ == inventory.ArtifactUpstreamsType
			groupAnalysis = groupAnalysis || typ == inventory.GroupIAMType
			workloadAnalysis = workloadAnalysis || typ == inventory.WorkloadGrantType
			auditAnalysis = auditAnalysis || typ == inventory.AuditConfigType
		}
	}
	if permissionAnalysis || workloadAnalysis || buildAnalysis || rotationAnalysis {
		inventory.ExpandBindings(&snap)
		inventory.CorrelateStorageControls(&snap)
		inventory.CorrelateServerlessContext(&snap)
		inventory.CorrelateIAPBackendContext(&snap)
		inventory.CorrelatePubSubDeliveryContext(&snap)
		inventory.CorrelateSpannerPublicRole(&snap)
	}
	if workloadAnalysis {
		inventory.CorrelateWorkloadGrants(&snap)
	}
	if rotationAnalysis {
		snap.Assets = append(snap.Assets, checks.ManagedRotationPrerequisiteAssets(snap.Assets)...)
	}
	if buildAnalysis {
		inventory.CorrelateBuildTrustContext(&snap)
	}
	inventory.CorrelateESPConfigPins(&snap)
	inventory.CorrelateDNSServiceTargets(&snap)
	inventory.CorrelateComputeIngressContext(&snap)
	if auditAnalysis {
		inventory.ResolveAuditConfigs(&snap)
	}
	if artifactAnalysis {
		inventory.ResolveArtifactUpstreams(&snap)
	}
	if groupAnalysis {
		inventory.CorrelateGroupIAM(&snap)
	}
	sum := sha256.Sum256(fingerprintInput)
	fingerprint := hex.EncodeToString(sum[:])
	old, exists, err := e.GetMeta(ctx, "inventory_fingerprint")
	if err != nil {
		return err
	}
	if exists && (!resume || old != fingerprint) {
		return errors.New("engagement already contains an assessment; use a new directory, or --resume with the identical inventory")
	}
	if resume && !exists {
		return errors.New("cannot resume: engagement has no prior inventory fingerprint")
	}
	if err := e.SetMeta(ctx, "inventory_fingerprint", fingerprint); err != nil {
		return err
	}
	if snap.SecretValueMode != "" {
		if err := e.SetMeta(ctx, "secret_value_policy", snap.SecretValueMode); err != nil {
			return err
		}
	}
	coverage, _ := json.MarshalIndent(snap.Coverage, "", "  ")
	if err := e.SetMeta(ctx, "coverage", string(coverage)); err != nil {
		return err
	}
	done, err := e.CompletedModules(ctx)
	if err != nil {
		return err
	}
	const target = "assessment"
	if err := e.UpsertProject(ctx, target, "Explicitly selected inventory"); err != nil {
		return err
	}
	failed := false
	secretFiles := map[string]string{}
	for _, c := range snap.Coverage {
		if c.Status == "failed" || c.Status == "incomplete" {
			failed = true
			fmt.Fprintln(cmd.ErrOrStderr(), "Coverage failure:", c.Source, c.Error)
		}
	}
	for _, c := range selected {
		if resume && done[target+"|"+c.ID] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := e.DB().ExecContext(ctx, `DELETE FROM findings WHERE module=?`, c.ID); err != nil {
			return err
		}
		if err := e.MarkModule(ctx, target, c.ID, "running", ""); err != nil {
			return err
		}
		applicable, hits := 0, 0
		for _, a := range snap.Assets {
			if !c.Applies(a) {
				continue
			}
			applicable++
			for _, r := range c.Eval(a, time.Now().UTC()) {
				detail := inventory.Object{"evidence": r.Evidence, "remediation": r.Remediation, "source": c.Source, "asset_type": a.Type, "ancestors": a.Ancestors}
				f := findings.Finding{ProjectID: assetScope(a), Region: a.Resource.Location, Module: c.ID, Severity: findings.Severity(r.Severity), ResourceName: a.Name, Title: r.Title, Detail: detail}
				if payload, ok := snap.SecretArtifacts[a.Name]; ok && snap.SecretValueMode == "actual" {
					key := inventory.Str(a.Resource.Data["sample_id"])
					if key == "" {
						key = a.Name
					}
					file := secretFiles[key]
					if file == "" {
						var err error
						file, err = e.WriteSecretArtifact(payload)
						if err != nil {
							return err
						}
						secretFiles[key] = file
					}
					f.RawOutputPath = file
					if r.Evidence != nil {
						r.Evidence["saved_file"] = file
					}
				}
				if err := e.Write(ctx, f); err != nil {
					_ = e.MarkModule(ctx, target, c.ID, "failed", err.Error())
					return err
				}
				hits++
			}
		}
		status, note := "completed", fmt.Sprintf("%d applicable records evaluated", applicable)
		if applicable == 0 {
			status = "skipped"
			note = "No applicable records supplied; resource absence and insufficient collection cannot be distinguished."
		}
		if err := e.MarkModule(ctx, target, c.ID, status, note); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-30s %-10s %d findings (%d records)\n", c.ID, status, hits, applicable)
	}
	status := "completed"
	if failed {
		status = "partial"
	}
	if err := e.MarkProject(ctx, target, status, ""); err != nil {
		return err
	}
	if err := report.Export(e); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Report: %s\n", filepath.Join(e.Dir, "report.html"))
	if failed {
		return errors.New("assessment saved with collection failures; review coverage before interpreting findings")
	}
	return nil
}

func assetScope(a inventory.Asset) string {
	if strings.HasPrefix(a.Type, "workspace.googleapis.com/") {
		return "workspace"
	}
	for _, parent := range a.Ancestors {
		if strings.HasPrefix(parent, "projects/") {
			return parent
		}
	}
	parts := strings.Split(a.Name, "/")
	for i, p := range parts {
		if (p == "projects" || p == "folders" || p == "organizations") && i+1 < len(parts) {
			return p + "/" + parts[i+1]
		}
	}
	return "inventory"
}

func reportCommand() *cobra.Command {
	var dir, addr string
	cmd := &cobra.Command{Use: "report", Short: "Serve saved findings locally with the four category tabs", RunE: func(cmd *cobra.Command, _ []string) error {
		if strings.TrimSpace(dir) == "" {
			return errors.New("--engagement is required")
		}
		if _, err := os.Stat(filepath.Join(dir, engagement.DBFileName)); err != nil {
			return err
		}
		e, err := engagement.Open(dir)
		if err != nil {
			return err
		}
		defer e.Close()
		fmt.Fprintln(cmd.OutOrStdout(), "Report listening on http://"+addr)
		return report.Serve(addr, e)
	}}
	cmd.Flags().StringVar(&dir, "engagement", "", "Existing engagement directory")
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "HTTP bind address")
	return cmd
}
