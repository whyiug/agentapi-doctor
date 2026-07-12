// Package report renders one immutable result model into human and machine
// formats. Renderers never reinterpret verdicts or attribution.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	SchemaVersion       = "urn:agentapi-doctor:report-bundle:v1alpha2"
	legacySchemaVersion = "urn:agentapi-doctor:report-bundle:v1alpha1"
)

type Condition struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Bundle struct {
	SchemaVersion   string                             `json:"schema_version"`
	RunID           schema.InstanceID                  `json:"run_id"`
	IntentPlanRef   schema.ObjectRef                   `json:"intent_plan_ref"`
	ResolvedPlanRef schema.ObjectRef                   `json:"resolved_plan_ref"`
	Profile         schema.ArtifactPin                 `json:"profile"`
	Artifacts       []schema.ArtifactPin               `json:"artifacts"`
	SupportLock     schema.Digest                      `json:"support_lock_digest"`
	Denominators    schema.DenominatorSummary          `json:"denominators"`
	Outcome         schema.ProfileOutcome              `json:"profile_outcome"`
	Dimensions      map[string]schema.DimensionOutcome `json:"dimension_outcomes"`
	Cases           []schema.CaseResult                `json:"cases"`
	Conditions      []Condition                        `json:"conditions"`
	PrimaryExitCode int                                `json:"primary_exit_code"`
}

func Decode(raw []byte) (Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode report: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Bundle{}, errors.New("report contains a trailing JSON value")
		}
		return Bundle{}, fmt.Errorf("decode trailing report data: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (bundle Bundle) Validate() error {
	if bundle.SchemaVersion != SchemaVersion && bundle.SchemaVersion != legacySchemaVersion {
		return fmt.Errorf("unsupported report schema %q", bundle.SchemaVersion)
	}
	if err := bundle.RunID.Validate(); err != nil {
		return fmt.Errorf("run ID: %w", err)
	}
	if err := bundle.IntentPlanRef.Validate(); err != nil {
		return fmt.Errorf("intent plan: %w", err)
	}
	if err := bundle.ResolvedPlanRef.Validate(); err != nil {
		return fmt.Errorf("resolved plan: %w", err)
	}
	if err := bundle.Profile.Validate(); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if len(bundle.Artifacts) == 0 {
		return errors.New("report requires exact artifact pins")
	}
	for index, artifact := range bundle.Artifacts {
		if err := artifact.Validate(); err != nil {
			return fmt.Errorf("artifact %d: %w", index, err)
		}
	}
	if err := bundle.SupportLock.Validate(); err != nil {
		return fmt.Errorf("support lock: %w", err)
	}
	if err := validateDenominators(bundle.Denominators); err != nil {
		return err
	}
	if !containsProfileOutcome(bundle.Outcome) {
		return fmt.Errorf("invalid profile outcome %q", bundle.Outcome)
	}
	for dimension, outcome := range bundle.Dimensions {
		if strings.TrimSpace(dimension) == "" || !containsDimensionOutcome(outcome) {
			return errors.New("dimension names and outcomes must be valid")
		}
	}
	seen := make(map[string]struct{}, len(bundle.Cases))
	for index, result := range bundle.Cases {
		if _, duplicate := seen[result.ScenarioID]; duplicate {
			return fmt.Errorf("duplicate scenario %q", result.ScenarioID)
		}
		seen[result.ScenarioID] = struct{}{}
		if err := result.Validate(); err != nil {
			return fmt.Errorf("case %d: %w", index, err)
		}
	}
	if !validExitCode(bundle.PrimaryExitCode) {
		return fmt.Errorf("invalid stable exit code %d", bundle.PrimaryExitCode)
	}
	for _, condition := range bundle.Conditions {
		if strings.TrimSpace(condition.Code) == "" || strings.TrimSpace(condition.Message) == "" {
			return errors.New("conditions require code and message")
		}
	}
	return nil
}

func validateDenominators(summary schema.DenominatorSummary) error {
	for label, digest := range map[string]schema.Digest{"candidate": summary.CandidateDigest, "applicable": summary.ApplicableDigest, "executed": summary.ExecutedDigest} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s denominator digest: %w", label, err)
		}
	}
	if summary.CandidateCount < 0 || summary.ApplicableCount < 0 || summary.ExecutedCount < 0 || summary.ExecutedCount > summary.ApplicableCount || summary.ApplicableCount > summary.CandidateCount {
		return errors.New("denominator counts must satisfy 0 <= executed <= applicable <= candidate")
	}
	return nil
}

func containsProfileOutcome(value schema.ProfileOutcome) bool {
	return value == schema.ProfileCompatible || value == schema.ProfileDegraded || value == schema.ProfileIncompatible || value == schema.ProfileInconclusive
}

func containsDimensionOutcome(value schema.DimensionOutcome) bool {
	return value == schema.DimensionPass || value == schema.DimensionFail || value == schema.DimensionDegraded || value == schema.DimensionInconclusive || value == schema.DimensionNotRun
}

func validExitCode(value int) bool {
	return value >= 0 && value <= 6 || value == 130
}

type Counts struct {
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	Warn         int `json:"warn"`
	Inconclusive int `json:"inconclusive"`
	Skipped      int `json:"skipped"`
	Errored      int `json:"errored"`
}

func Count(bundle Bundle) Counts {
	var counts Counts
	for _, result := range bundle.Cases {
		if result.ExecutionStatus == schema.ExecutionErrored || result.ExecutionStatus == schema.ExecutionCancelled {
			counts.Errored++
			continue
		}
		if result.PlanDisposition != schema.DispositionExecute || result.ExecutionStatus == schema.ExecutionSkipped {
			counts.Skipped++
			continue
		}
		if result.Verdict == nil {
			continue
		}
		switch *result.Verdict {
		case schema.VerdictPass:
			counts.Pass++
		case schema.VerdictFail:
			counts.Fail++
		case schema.VerdictWarn:
			counts.Warn++
		case schema.VerdictInconclusive:
			counts.Inconclusive++
		}
	}
	return counts
}

func sortedCases(bundle Bundle) []schema.CaseResult {
	results := append([]schema.CaseResult(nil), bundle.Cases...)
	sort.SliceStable(results, func(i, j int) bool { return results[i].ScenarioID < results[j].ScenarioID })
	return results
}
