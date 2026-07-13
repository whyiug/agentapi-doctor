package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

var ErrIncomparable = errors.New("baseline and run have different immutable test identities")
var baselineNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

const BaselineSchemaVersion = "urn:agentapi-doctor:baseline:v1"

type CaseState struct {
	Disposition schema.PlanDisposition `json:"plan_disposition"`
	Execution   schema.ExecutionStatus `json:"execution_status,omitempty"`
	Verdict     *schema.Verdict        `json:"verdict,omitempty"`
}

type Baseline struct {
	SchemaVersion     string               `json:"schema_version"`
	Name              string               `json:"name"`
	ProfileDigest     schema.Digest        `json:"profile_digest"`
	PackDigest        schema.Digest        `json:"pack_digest"`
	SupportLockDigest schema.Digest        `json:"support_lock_digest"`
	DenominatorDigest schema.Digest        `json:"denominator_digest"`
	Cases             map[string]CaseState `json:"cases"`
}

func (baseline Baseline) Validate() error {
	if baseline.SchemaVersion != BaselineSchemaVersion {
		return fmt.Errorf("unsupported baseline schema %q", baseline.SchemaVersion)
	}
	if !baselineNamePattern.MatchString(baseline.Name) {
		return errors.New("invalid baseline name")
	}
	for label, digest := range map[string]schema.Digest{"profile": baseline.ProfileDigest, "pack": baseline.PackDigest, "support lock": baseline.SupportLockDigest, "denominator": baseline.DenominatorDigest} {
		if err := digest.Validate(); err != nil {
			return fmt.Errorf("%s digest: %w", label, err)
		}
	}
	if baseline.Cases == nil {
		return errors.New("baseline cases are required")
	}
	for id, state := range baseline.Cases {
		if strings.TrimSpace(id) == "" {
			return errors.New("baseline scenario ID is required")
		}
		if state.Disposition != schema.DispositionExecute && state.Disposition != schema.DispositionSkip && state.Disposition != schema.DispositionNotApplicable {
			return fmt.Errorf("scenario %s has invalid disposition", id)
		}
		switch state.Execution {
		case "", schema.ExecutionPlanned, schema.ExecutionRunning, schema.ExecutionCompleted, schema.ExecutionSkipped, schema.ExecutionCancelled, schema.ExecutionErrored:
		default:
			return fmt.Errorf("scenario %s has invalid execution status", id)
		}
		if state.Verdict != nil {
			switch *state.Verdict {
			case schema.VerdictPass, schema.VerdictFail, schema.VerdictWarn, schema.VerdictInconclusive:
			default:
				return fmt.Errorf("scenario %s has invalid verdict", id)
			}
		}
		if state.Verdict != nil && state.Execution != schema.ExecutionCompleted {
			return fmt.Errorf("scenario %s has verdict without completed execution", id)
		}
	}
	return nil
}

func BaselineJSON(baseline Baseline) ([]byte, error) {
	if err := baseline.Validate(); err != nil {
		return nil, err
	}
	return schema.CanonicalMarshal(baseline)
}

func DecodeBaseline(raw []byte) (Baseline, error) {
	canonical, err := schema.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Baseline{}, errors.New("baseline must be strict canonical JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var baseline Baseline
	if err := decoder.Decode(&baseline); err != nil {
		return Baseline{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Baseline{}, errors.New("baseline contains trailing JSON")
	}
	var shape struct {
		SchemaVersion json.RawMessage `json:"schema_version"`
		Cases         map[string]struct {
			Execution json.RawMessage `json:"execution_status"`
			Verdict   json.RawMessage `json:"verdict"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return Baseline{}, err
	}
	for id, state := range shape.Cases {
		if len(state.Execution) > 0 && (bytes.Equal(state.Execution, []byte("null")) || bytes.Equal(state.Execution, []byte(`""`))) {
			return Baseline{}, fmt.Errorf("scenario %s has invalid execution status", id)
		}
		if bytes.Equal(state.Verdict, []byte("null")) {
			return Baseline{}, fmt.Errorf("scenario %s has invalid verdict", id)
		}
	}
	// Release candidates wrote an otherwise identical, unversioned baseline.
	// Continue to read that exact shape while every new write uses v1.
	if baseline.SchemaVersion == "" {
		if len(shape.SchemaVersion) != 0 {
			return Baseline{}, fmt.Errorf("unsupported baseline schema %q", baseline.SchemaVersion)
		}
		baseline.SchemaVersion = BaselineSchemaVersion
	}
	if err := baseline.Validate(); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

type Change string

const (
	NewFailure     Change = "NEW_FAILURE"
	Regression     Change = "REGRESSION"
	Fixed          Change = "FIXED"
	Unchanged      Change = "UNCHANGED"
	NewCapability  Change = "NEW_CAPABILITY"
	NoLongerTested Change = "NO_LONGER_TESTED"
)

type Difference struct {
	ScenarioID string     `json:"scenario_id"`
	Change     Change     `json:"change"`
	Before     *CaseState `json:"before,omitempty"`
	After      *CaseState `json:"after,omitempty"`
}

// NewBaseline snapshots only exact comparable identities. A report without
// exactly one ProtocolPack is rejected rather than choosing one implicitly.
func NewBaseline(name string, bundle Bundle) (Baseline, error) {
	if !baselineNamePattern.MatchString(name) {
		return Baseline{}, errors.New("baseline name is required")
	}
	if err := bundle.Validate(); err != nil {
		return Baseline{}, err
	}
	var pack *schema.ArtifactPin
	for index := range bundle.Artifacts {
		if bundle.Artifacts[index].Kind != "ProtocolPack" {
			continue
		}
		if pack != nil {
			return Baseline{}, errors.New("baseline requires exactly one ProtocolPack")
		}
		pack = &bundle.Artifacts[index]
	}
	if pack == nil {
		return Baseline{}, errors.New("baseline requires exactly one ProtocolPack")
	}
	cases := make(map[string]CaseState, len(bundle.Cases))
	for _, result := range bundle.Cases {
		var verdictCopy *schema.Verdict
		if result.Verdict != nil {
			value := *result.Verdict
			verdictCopy = &value
		}
		cases[result.ScenarioID] = CaseState{Disposition: result.PlanDisposition, Execution: result.ExecutionStatus, Verdict: verdictCopy}
	}
	baseline := Baseline{SchemaVersion: BaselineSchemaVersion, Name: name, ProfileDigest: bundle.Profile.Digest, PackDigest: pack.Digest, SupportLockDigest: bundle.SupportLock, DenominatorDigest: bundle.Denominators.CandidateDigest, Cases: cases}
	return baseline, baseline.Validate()
}

func Compare(before, after Baseline) ([]Difference, error) {
	if err := before.Validate(); err != nil {
		return nil, err
	}
	if err := after.Validate(); err != nil {
		return nil, err
	}
	for label, pair := range map[string][2]schema.Digest{"profile": {before.ProfileDigest, after.ProfileDigest}, "pack": {before.PackDigest, after.PackDigest}, "support lock": {before.SupportLockDigest, after.SupportLockDigest}, "denominator": {before.DenominatorDigest, after.DenominatorDigest}} {
		if pair[0] != pair[1] {
			return nil, fmt.Errorf("%w: %s digest changed", ErrIncomparable, label)
		}
	}
	ids := make(map[string]struct{}, len(before.Cases)+len(after.Cases))
	for id := range before.Cases {
		ids[id] = struct{}{}
	}
	for id := range after.Cases {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	differences := make([]Difference, 0, len(ordered))
	for _, id := range ordered {
		left, leftOK := before.Cases[id]
		right, rightOK := after.Cases[id]
		change := Unchanged
		switch {
		case !leftOK && rightOK && isFailure(right):
			change = NewFailure
		case !leftOK && rightOK:
			change = NewCapability
		case leftOK && !rightOK:
			change = NoLongerTested
		case !isFailure(left) && isFailure(right):
			change = Regression
		case isFailure(left) && !isFailure(right) && right.Disposition == schema.DispositionExecute:
			change = Fixed
		case left.Disposition != schema.DispositionExecute && right.Disposition == schema.DispositionExecute:
			change = NewCapability
		}
		item := Difference{ScenarioID: id, Change: change}
		if leftOK {
			value := left
			item.Before = &value
		}
		if rightOK {
			value := right
			item.After = &value
		}
		differences = append(differences, item)
	}
	return differences, nil
}

func isFailure(state CaseState) bool {
	return state.Verdict != nil && *state.Verdict == schema.VerdictFail
}
