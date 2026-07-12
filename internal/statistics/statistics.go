// Package statistics contains deterministic statistical helpers used by
// behavioral and operational-reliability oracles.
package statistics

import (
	"errors"
	"math"
	"slices"
)

// Interval is a bounded estimate over [0,1].
type Interval struct {
	SampleCount int64   `json:"sample_count"`
	Estimate    float64 `json:"estimate"`
	LowerBound  float64 `json:"lower_bound"`
	UpperBound  float64 `json:"upper_bound"`
	Method      string  `json:"method"`
}

// Wilson returns a two-sided Wilson score interval. z=1.959963984540054 is
// the conventional 95% interval. Zero samples are rejected rather than
// being represented as an apparently meaningful 0% estimate.
func Wilson(successes, samples int64, z float64) (Interval, error) {
	if samples <= 0 {
		return Interval{}, errors.New("Wilson interval requires at least one sample")
	}
	if successes < 0 || successes > samples {
		return Interval{}, errors.New("success count must be between zero and sample count")
	}
	if math.IsNaN(z) || math.IsInf(z, 0) || z <= 0 {
		return Interval{}, errors.New("z score must be finite and positive")
	}
	n := float64(samples)
	p := float64(successes) / n
	z2 := z * z
	denominator := 1 + z2/n
	center := (p + z2/(2*n)) / denominator
	margin := z * math.Sqrt((p*(1-p)+z2/(4*n))/n) / denominator
	return Interval{
		SampleCount: samples,
		Estimate:    p,
		LowerBound:  math.Max(0, center-margin),
		UpperBound:  math.Min(1, center+margin),
		Method:      "wilson-score",
	}, nil
}

// Quantile computes the R-7 sample quantile used by common statistical
// packages. The input is copied so callers never observe a reorder.
func Quantile(values []float64, probability float64) (float64, error) {
	if len(values) == 0 {
		return 0, errors.New("quantile requires at least one value")
	}
	if math.IsNaN(probability) || probability < 0 || probability > 1 {
		return 0, errors.New("quantile probability must be in [0,1]")
	}
	copyValues := append([]float64(nil), values...)
	for _, value := range copyValues {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, errors.New("quantile values must be finite")
		}
	}
	slices.Sort(copyValues)
	if len(copyValues) == 1 {
		return copyValues[0], nil
	}
	position := probability * float64(len(copyValues)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return copyValues[lower], nil
	}
	fraction := position - float64(lower)
	return copyValues[lower] + fraction*(copyValues[upper]-copyValues[lower]), nil
}

// Flakiness describes whether repeated completed attempts disagree. It does
// not replace the verdict of any individual attempt.
type Flakiness struct {
	Samples       int64   `json:"samples"`
	Passes        int64   `json:"passes"`
	Failures      int64   `json:"failures"`
	Inconclusive  int64   `json:"inconclusive"`
	Disagreement  float64 `json:"disagreement"`
	FlakyDetected bool    `json:"flaky_detected"`
}

// MeasureFlakiness counts stable public verdict labels. WARN is neither a
// pass nor target failure and therefore contributes to inconclusive samples.
func MeasureFlakiness(verdicts []string) (Flakiness, error) {
	result := Flakiness{Samples: int64(len(verdicts))}
	for _, verdict := range verdicts {
		switch verdict {
		case "pass":
			result.Passes++
		case "fail":
			result.Failures++
		case "warn", "inconclusive":
			result.Inconclusive++
		default:
			return Flakiness{}, errors.New("unknown verdict in flakiness sample")
		}
	}
	decisive := result.Passes + result.Failures
	if decisive > 0 {
		minority := min(result.Passes, result.Failures)
		result.Disagreement = float64(minority) / float64(decisive)
	}
	result.FlakyDetected = result.Passes > 0 && result.Failures > 0
	return result, nil
}
