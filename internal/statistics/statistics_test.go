package statistics

import (
	"math"
	"reflect"
	"testing"
)

func TestWilsonKnownInterval(t *testing.T) {
	interval, err := Wilson(8, 10, 1.959963984540054)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(interval.LowerBound-0.490162) > 0.00001 || math.Abs(interval.UpperBound-0.943318) > 0.00001 {
		t.Fatalf("unexpected interval: %#v", interval)
	}
	if interval.Method != "wilson-score" || interval.Estimate != 0.8 {
		t.Fatalf("unexpected estimate: %#v", interval)
	}
}

func TestWilsonRejectsInvalidCounts(t *testing.T) {
	for _, input := range [][2]int64{{0, 0}, {-1, 2}, {3, 2}} {
		if _, err := Wilson(input[0], input[1], 1.96); err == nil {
			t.Fatalf("expected error for %v", input)
		}
	}
}

func TestQuantileDoesNotMutateInput(t *testing.T) {
	values := []float64{4, 1, 3, 2}
	original := append([]float64(nil), values...)
	median, err := Quantile(values, 0.5)
	if err != nil || median != 2.5 {
		t.Fatalf("median=%v err=%v", median, err)
	}
	if !reflect.DeepEqual(values, original) {
		t.Fatalf("input mutated: %v", values)
	}
}

func TestFlakinessPreservesAttemptSemantics(t *testing.T) {
	result, err := MeasureFlakiness([]string{"pass", "pass", "fail", "inconclusive"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.FlakyDetected || result.Disagreement != 1.0/3.0 || result.Inconclusive != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}
