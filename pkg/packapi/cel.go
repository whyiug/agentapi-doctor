package packapi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const maxCELSourceBytes = 8192

var forbiddenCELFunctions = map[string]struct{}{
	"exec":       {},
	"shell":      {},
	"open":       {},
	"read_file":  {},
	"write_file": {},
	"fetch":      {},
	"http_get":   {},
	"http_post":  {},
	"socket":     {},
	"getenv":     {},
}

// CompiledCEL records the deterministic, public part of a checked CEL
// expression. Runtime programs are deliberately not serialized into pack IR.
type CompiledCEL struct {
	Source        string `json:"source"`
	EstimatedCost uint64 `json:"estimated_cost"`
}

type boundedCostEstimator struct{}

func (boundedCostEstimator) EstimateSize(checker.AstNode) *checker.SizeEstimate {
	estimate := checker.FixedSizeEstimate(1024)
	return &estimate
}

func (boundedCostEstimator) EstimateCallCost(string, string, *checker.AstNode, []checker.AstNode) *checker.CallEstimate {
	return nil
}

func compileCEL(source string, maxCost uint64) (CompiledCEL, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return CompiledCEL{}, errors.New("CEL expression is empty")
	}
	if len(source) > maxCELSourceBytes {
		return CompiledCEL{}, fmt.Errorf("CEL expression exceeds %d bytes", maxCELSourceBytes)
	}
	if maxCost == 0 {
		maxCost = DefaultMaxCELCost
	}
	if maxCost > AbsoluteMaxCELCost {
		return CompiledCEL{}, fmt.Errorf("CEL cost limit %d exceeds absolute maximum %d", maxCost, AbsoluteMaxCELCost)
	}
	environment, err := cel.NewEnv(
		cel.ClearMacros(),
		cel.Variable("actual", cel.DynType),
		cel.Variable("expected", cel.DynType),
		cel.Variable("evidence", cel.DynType),
		cel.Variable("fixture", cel.DynType),
		cel.Variable("ir", cel.DynType),
		cel.Variable("steps", cel.DynType),
		cel.Variable("target", cel.DynType),
	)
	if err != nil {
		return CompiledCEL{}, fmt.Errorf("create restricted CEL environment: %w", err)
	}
	ast, issues := environment.Compile(source)
	if issues != nil && issues.Err() != nil {
		return CompiledCEL{}, fmt.Errorf("compile restricted CEL: %w", issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return CompiledCEL{}, fmt.Errorf("CEL assertion must return bool, got %s", ast.OutputType())
	}
	checked, err := cel.AstToCheckedExpr(ast)
	if err != nil {
		return CompiledCEL{}, fmt.Errorf("convert checked CEL expression: %w", err)
	}
	if function := findForbiddenCELFunction(checked.GetExpr()); function != "" {
		return CompiledCEL{}, fmt.Errorf("CEL function %q is forbidden", function)
	}
	cost, err := environment.EstimateCost(ast, boundedCostEstimator{})
	if err != nil {
		return CompiledCEL{}, fmt.Errorf("estimate CEL cost: %w", err)
	}
	if cost.Max > maxCost {
		return CompiledCEL{}, fmt.Errorf("CEL estimated cost %d exceeds limit %d", cost.Max, maxCost)
	}
	if _, err := environment.Program(ast, cel.CostLimit(maxCost)); err != nil {
		return CompiledCEL{}, fmt.Errorf("build cost-limited CEL program: %w", err)
	}
	return CompiledCEL{Source: source, EstimatedCost: cost.Max}, nil
}

func findForbiddenCELFunction(expression *exprpb.Expr) string {
	if expression == nil {
		return ""
	}
	switch kind := expression.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		if _, forbidden := forbiddenCELFunctions[kind.CallExpr.Function]; forbidden {
			return kind.CallExpr.Function
		}
		if function := findForbiddenCELFunction(kind.CallExpr.Target); function != "" {
			return function
		}
		for _, argument := range kind.CallExpr.Args {
			if function := findForbiddenCELFunction(argument); function != "" {
				return function
			}
		}
	case *exprpb.Expr_ListExpr:
		for _, element := range kind.ListExpr.Elements {
			if function := findForbiddenCELFunction(element); function != "" {
				return function
			}
		}
	case *exprpb.Expr_StructExpr:
		for _, entry := range kind.StructExpr.Entries {
			if function := findForbiddenCELFunction(entry.Value); function != "" {
				return function
			}
		}
	case *exprpb.Expr_ComprehensionExpr:
		for _, child := range []*exprpb.Expr{
			kind.ComprehensionExpr.IterRange,
			kind.ComprehensionExpr.AccuInit,
			kind.ComprehensionExpr.LoopCondition,
			kind.ComprehensionExpr.LoopStep,
			kind.ComprehensionExpr.Result,
		} {
			if function := findForbiddenCELFunction(child); function != "" {
				return function
			}
		}
	case *exprpb.Expr_SelectExpr:
		return findForbiddenCELFunction(kind.SelectExpr.Operand)
	}
	return ""
}
