package minimizer

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDDMinFindsMinimalPair(t *testing.T) {
	input := []string{"noise-a", "trigger-a", "noise-b", "trigger-b", "noise-c"}
	result, err := DDMin(context.Background(), input, func(_ context.Context, candidate []string) (bool, error) {
		seenA, seenB := false, false
		for _, item := range candidate {
			seenA = seenA || item == "trigger-a"
			seenB = seenB || item == "trigger-b"
		}
		return seenA && seenB, nil
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusMinimized || !reflect.DeepEqual(result.Items, []string{"trigger-a", "trigger-b"}) {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDDMinKOfNInconclusive(t *testing.T) {
	result, err := DDMin(context.Background(), []int{1, 2}, func(_ context.Context, _ []int) (bool, error) {
		return false, errors.New("fixture unavailable")
	}, Options{Attempts: 3, RequiredPasses: 2, MaxEvaluations: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusInconclusive || result.ReasonCode != "insufficient_samples" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDDMinBudgetIsExplicit(t *testing.T) {
	result, err := DDMin(context.Background(), []int{1, 2, 3, 4}, func(_ context.Context, _ []int) (bool, error) {
		return true, nil
	}, Options{MaxEvaluations: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusInconclusive || result.ReasonCode != "budget_exhausted" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRemoveJSONObjectKeysDoesNotMutateInput(t *testing.T) {
	input := map[string]any{"keep": true, "noise": "x"}
	output, _, err := RemoveJSONObjectKeys(context.Background(), input, []string{"keep", "noise"}, func(_ context.Context, candidate map[string]any) (bool, error) {
		return candidate["keep"] == true, nil
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(output, map[string]any{"keep": true}) || len(input) != 2 {
		t.Fatalf("output=%v input=%v", output, input)
	}
}
