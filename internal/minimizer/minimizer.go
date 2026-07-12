// Package minimizer implements bounded, deterministic delta debugging over
// already captured and redacted artifacts. Live callers must provide their own
// network authorization and budget before constructing a Predicate.
package minimizer

import (
	"context"
	"errors"
	"fmt"
)

type Predicate[T any] func(context.Context, []T) (bool, error)

type Status string

const (
	StatusMinimized    Status = "minimized"
	StatusUnchanged    Status = "unchanged"
	StatusInconclusive Status = "inconclusive"
)

type Options struct {
	Attempts       int
	RequiredPasses int
	MaxEvaluations int
}

type Result[T any] struct {
	Items       []T    `json:"items"`
	Status      Status `json:"status"`
	ReasonCode  string `json:"reason_code,omitempty"`
	Evaluations int    `json:"evaluations"`
	Attempts    int    `json:"attempts"`
	Required    int    `json:"required_passes"`
}

var ErrBudgetExhausted = errors.New("minimization evaluation budget exhausted")

type evaluator[T any] struct {
	predicate Predicate[T]
	options   Options
	count     int
}

func normalizeOptions(options Options) (Options, error) {
	if options.Attempts == 0 {
		options.Attempts = 1
	}
	if options.RequiredPasses == 0 {
		options.RequiredPasses = options.Attempts
	}
	if options.MaxEvaluations == 0 {
		options.MaxEvaluations = 1000
	}
	if options.Attempts < 1 || options.RequiredPasses < 1 || options.RequiredPasses > options.Attempts || options.MaxEvaluations < 1 {
		return Options{}, errors.New("invalid minimizer attempts, required passes, or evaluation budget")
	}
	return options, nil
}

// DDMin removes contiguous partitions until no remaining complement
// reproduces. A candidate is accepted only when k-of-n predicate attempts
// reproduce; errors and mixed evidence are preserved as inconclusive.
func DDMin[T any](ctx context.Context, input []T, predicate Predicate[T], options Options) (Result[T], error) {
	if predicate == nil {
		return Result[T]{}, errors.New("minimization predicate is required")
	}
	normalized, err := normalizeOptions(options)
	if err != nil {
		return Result[T]{}, err
	}
	evaluation := &evaluator[T]{predicate: predicate, options: normalized}
	current := append([]T(nil), input...)
	reproduces, conclusive, err := evaluation.check(ctx, current)
	if err != nil {
		return Result[T]{}, err
	}
	if !conclusive {
		return evaluation.result(current, StatusInconclusive, "insufficient_samples"), nil
	}
	if !reproduces {
		return Result[T]{}, errors.New("initial input does not reproduce the finding")
	}
	if len(current) < 2 {
		return evaluation.result(current, StatusUnchanged, ""), nil
	}
	originalLength := len(current)
	granularity := 2
	sawInconclusive := false
	for len(current) >= 2 {
		if err := ctx.Err(); err != nil {
			return Result[T]{}, err
		}
		chunkSize := (len(current) + granularity - 1) / granularity
		reduced := false
		for start := 0; start < len(current); start += chunkSize {
			end := min(start+chunkSize, len(current))
			candidate := make([]T, 0, len(current)-(end-start))
			candidate = append(candidate, current[:start]...)
			candidate = append(candidate, current[end:]...)
			if len(candidate) == 0 {
				continue
			}
			reproduces, conclusive, checkErr := evaluation.check(ctx, candidate)
			if errors.Is(checkErr, ErrBudgetExhausted) {
				return evaluation.result(current, StatusInconclusive, "budget_exhausted"), nil
			}
			if checkErr != nil {
				return Result[T]{}, checkErr
			}
			if !conclusive {
				sawInconclusive = true
				continue
			}
			if reproduces {
				current = append([]T(nil), candidate...)
				granularity = max(2, granularity-1)
				reduced = true
				break
			}
		}
		if reduced {
			continue
		}
		if granularity >= len(current) {
			break
		}
		granularity = min(len(current), granularity*2)
	}
	if sawInconclusive {
		return evaluation.result(current, StatusInconclusive, "flaky_detected"), nil
	}
	status := StatusMinimized
	if len(current) == originalLength {
		status = StatusUnchanged
	}
	return evaluation.result(current, status, ""), nil
}

func (evaluation *evaluator[T]) check(ctx context.Context, candidate []T) (bool, bool, error) {
	passes := 0
	failures := 0
	for attempt := 0; attempt < evaluation.options.Attempts; attempt++ {
		if evaluation.count >= evaluation.options.MaxEvaluations {
			return false, false, ErrBudgetExhausted
		}
		evaluation.count++
		matched, err := evaluation.predicate(ctx, append([]T(nil), candidate...))
		if err != nil {
			continue
		}
		if matched {
			passes++
		} else {
			failures++
		}
		if passes >= evaluation.options.RequiredPasses {
			return true, true, nil
		}
		if failures > evaluation.options.Attempts-evaluation.options.RequiredPasses {
			return false, true, nil
		}
	}
	return false, false, nil
}

func (evaluation *evaluator[T]) result(items []T, status Status, reason string) Result[T] {
	return Result[T]{Items: append([]T(nil), items...), Status: status, ReasonCode: reason, Evaluations: evaluation.count, Attempts: evaluation.options.Attempts, Required: evaluation.options.RequiredPasses}
}

// RemoveJSONObjectKeys applies DDMin to a stable list of JSON-object keys.
// The predicate receives a fresh shallow map for each evaluation.
func RemoveJSONObjectKeys(ctx context.Context, input map[string]any, orderedKeys []string, predicate func(context.Context, map[string]any) (bool, error), options Options) (map[string]any, Result[string], error) {
	if predicate == nil {
		return nil, Result[string]{}, errors.New("JSON predicate is required")
	}
	seen := make(map[string]struct{}, len(orderedKeys))
	for _, key := range orderedKeys {
		if _, ok := input[key]; !ok {
			return nil, Result[string]{}, fmt.Errorf("ordered key %q is not present", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, Result[string]{}, fmt.Errorf("ordered key %q is duplicated", key)
		}
		seen[key] = struct{}{}
	}
	result, err := DDMin(ctx, orderedKeys, func(ctx context.Context, retained []string) (bool, error) {
		candidate := make(map[string]any, len(retained))
		for _, key := range retained {
			candidate[key] = input[key]
		}
		return predicate(ctx, candidate)
	}, options)
	if err != nil {
		return nil, Result[string]{}, err
	}
	output := make(map[string]any, len(result.Items))
	for _, key := range result.Items {
		output[key] = input[key]
	}
	return output, result, nil
}
