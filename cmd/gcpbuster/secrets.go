package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/bc0la/gcpbuster/internal/checks"
	"github.com/bc0la/gcpbuster/internal/inventory"
	"github.com/bc0la/gcpbuster/internal/kingfisher"
)

type secretRunner func(context.Context, []kingfisher.Sample, kingfisher.Options) (kingfisher.Report, error)

// Supplied inventories can contain previously generated actual-value rows.
// The CLI policy must also apply to those rows, not only newly scanned samples.
func redactSuppliedSecretAssets(snap *inventory.Snapshot) {
	snap.SecretArtifacts = nil
	snap.Assets = append([]inventory.Asset(nil), snap.Assets...)
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if a.Type != checks.SecretScanFindingType && a.Type != checks.CapturedConfigurationValueType && a.Type != checks.ParameterReferenceType {
			continue
		}
		d := inventory.Object{}
		for key, value := range a.Resource.Data {
			d[key] = value
		}
		d["redacted"] = true
		if a.Type == checks.ParameterReferenceType {
			for _, key := range []string{"parameter_version", "parameter", "target_version", "identity"} {
				d[key] = "[REDACTED]"
			}
			d["identity_payload_grants"], d["caller_render_grants"] = []any{}, []any{}
			a.Resource.Data = d
			continue
		}
		d["source"] = "[REDACTED]"
		if a.Type == checks.SecretScanFindingType {
			d["match"] = "[REDACTED]"
			d["source_field"] = "[REDACTED]"
		} else {
			for _, key := range []string{"field", "variable", "value"} {
				d[key] = "[REDACTED]"
			}
		}
		for _, key := range []string{"pull_command", "saved_file", "source_location", "source_revision", "refetch_metadata", "refetch_instruction"} {
			delete(d, key)
		}
		a.Resource.Data = d
	}
}

// prepareSecrets never persists raw samples. Only finding-bound artifacts are
// passed transiently to assess, which writes them after the engagement gate.
func prepareSecrets(ctx context.Context, snap *inventory.Snapshot, capture *inventory.SecretCapture, redact, scanKingfisher, plaintext bool, run secretRunner) {
	samples := capture.Samples()
	snap.Assets = append(snap.Assets, checks.ParameterReferenceAssets(samples, snap.Assets, redact)...)
	snap.Coverage = append(snap.Coverage, capture.Coverage()...)
	snap.SecretValueMode = "actual"
	if redact {
		snap.SecretValueMode = "redacted"
	}
	if !redact {
		hash := sha256.New()
		for _, sample := range samples {
			fmt.Fprintf(hash, "%d:%s:%d:", len(sample.ID), sample.ID, len(sample.Data))
			hash.Write(sample.Data)
		}
		snap.SecretFingerprint = hash.Sum(nil)
	}
	byID := map[string]inventory.SecretSample{}
	ancestors := map[string][]string{}
	for _, a := range snap.Assets {
		ancestors[a.Name] = a.Ancestors
	}
	for _, s := range samples {
		byID[s.ID] = s
	}
	if !redact {
		snap.SecretArtifacts = map[string][]byte{}
	}
	if plaintext {
		for _, a := range checks.CapturedSampleAssets(samples, redact) {
			sample, ok := byID[inventory.Str(a.Resource.Data["sample_id"])]
			if !ok {
				continue
			}
			a.Ancestors = ancestors[sample.Resource]
			if !redact {
				a.Resource.Data["pull_command"] = secretPullCommandFromAssets(sample, snap.Assets)
				a.Resource.Data["source_location"] = sample.Location
				a.Resource.Data["source_revision"] = secretSourceRevision(sample)
				a.Resource.Data["refetch_metadata"] = inventory.Object{"source_resource": sample.Resource, "source_field": sample.Path, "source_location": sample.Location, "manual_only": true, "collection_reads": "first page; locate the exact source and follow nextPageToken where applicable"}
				a.Resource.Data["refetch_instruction"] = secretRefetchInstruction(sample)
			}
			snap.Assets = append(snap.Assets, a)
			if !redact && a.Resource.Data["severity"] == "high" {
				snap.SecretArtifacts[a.Name] = sample.Data
			}
		}
	}
	if !scanKingfisher {
		return
	}
	input := make([]kingfisher.Sample, 0, len(samples))
	for _, s := range samples {
		input = append(input, kingfisher.Sample{ID: s.ID, Source: s.SourceType + "/" + s.Resource, Region: s.Location, Content: string(s.Data)})
	}
	report, err := run(ctx, input, kingfisher.Options{Redact: redact})
	if err != nil {
		// Runner diagnostics are deliberately sanitized; never serialize stderr.
		snap.Coverage = append(snap.Coverage, inventory.Coverage{Source: "kingfisher", Status: "incomplete", Error: err.Error()})
	}
	for _, warning := range report.Warnings {
		snap.Coverage = append(snap.Coverage, inventory.Coverage{Source: "kingfisher", Status: "incomplete", Error: warning})
	}
	if err == nil && len(report.Warnings) == 0 {
		snap.Coverage = append(snap.Coverage, inventory.Coverage{Source: "kingfisher", Status: "completed", Count: report.SamplesScanned})
	}
	for i, f := range report.Findings {
		sample, ok := byID[f.SampleID]
		if !ok {
			continue
		}
		match := f.Snippet
		field := sample.Path
		if redact {
			match = "[REDACTED]"
			field = "[REDACTED]"
		}
		name := fmt.Sprintf("//gcpbuster.googleapis.com/secretFindings/%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d", f.SampleID, f.RuleID, f.Line, i))))
		a := inventory.NewAsset(name, checks.SecretScanFindingType, inventory.Object{
			"sample_id": sample.ID,
			"scanner":   "kingfisher", "credential_validation_performed": false, "redacted": redact,
			"rule_id": f.RuleID, "rule_name": f.RuleName, "match": match,
			"source": sample.Resource, "source_type": sample.SourceType, "check": "kf:" + sample.SourceType,
			"source_field": field,
			"line":         f.Line, "confidence": f.Confidence, "validation": f.Validation,
		})
		a.Ancestors = ancestors[sample.Resource]
		a.Resource.Location = sample.Location
		if !redact {
			a.Resource.Data["pull_command"] = secretPullCommandFromAssets(sample, snap.Assets)
			a.Resource.Data["source_location"] = sample.Location
			a.Resource.Data["source_revision"] = secretSourceRevision(sample)
			a.Resource.Data["refetch_metadata"] = inventory.Object{"source_resource": sample.Resource, "source_field": sample.Path, "source_location": sample.Location, "manual_only": true, "collection_reads": "first page; locate the exact source and follow nextPageToken where applicable"}
			a.Resource.Data["refetch_instruction"] = secretRefetchInstruction(sample)
		}
		snap.Assets = append(snap.Assets, a)
		if !redact {
			snap.SecretArtifacts[a.Name] = sample.Data
		}
	}
}
