package oracle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

type JSONType string

const (
	TypeObject  JSONType = "object"
	TypeArray   JSONType = "array"
	TypeString  JSONType = "string"
	TypeNumber  JSONType = "number"
	TypeBoolean JSONType = "boolean"
	TypeNull    JSONType = "null"
)

type Schema struct {
	Types        []JSONType
	Properties   map[string]Schema
	Required     []string
	Items        *Schema
	AllowUnknown bool
}

// EvaluateSchema validates a bounded structural schema. A malformed observed
// value is a target failure only when evidence is complete and the harness
// schema itself is valid.
func EvaluateSchema(input Input[json.RawMessage], expected Schema) Outcome {
	if result := preflight(input); result != nil {
		return *result
	}
	if err := validateSchemaDefinition(expected, "$", 0); err != nil {
		return harness(input.EvidenceRefs, "invalid_oracle_schema", err)
	}
	if !input.Complete {
		return insufficient(input.EvidenceRefs, "incomplete_schema_evidence", expected.Types, "partial JSON evidence")
	}
	canonical, err := publicschema.CanonicalizeJSON(input.Value)
	if err != nil {
		return targetFail(input.EvidenceRefs, "invalid_json", expected.Types, "malformed or ambiguous JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return targetFail(input.EvidenceRefs, "invalid_json", expected.Types, "undecodable JSON")
	}
	if violation := validateValue(value, expected, "$", 0); violation != nil {
		return targetFail(input.EvidenceRefs, violation.code, violation.expected, violation.observed)
	}
	return pass(input.EvidenceRefs)
}

type schemaViolation struct {
	code     string
	expected string
	observed string
}

func validateSchemaDefinition(definition Schema, path string, depth int) error {
	if depth > 64 {
		return errors.New("oracle schema nesting exceeds 64")
	}
	if len(definition.Types) == 0 {
		return fmt.Errorf("%s has no allowed types", path)
	}
	for _, candidate := range definition.Types {
		if !slices.Contains([]JSONType{TypeObject, TypeArray, TypeString, TypeNumber, TypeBoolean, TypeNull}, candidate) {
			return fmt.Errorf("%s has unsupported type %q", path, candidate)
		}
	}
	for name, property := range definition.Properties {
		if name == "" {
			return fmt.Errorf("%s has empty property name", path)
		}
		if err := validateSchemaDefinition(property, path+"."+name, depth+1); err != nil {
			return err
		}
	}
	for _, required := range definition.Required {
		if _, exists := definition.Properties[required]; !exists {
			return fmt.Errorf("%s requires undefined property %q", path, required)
		}
	}
	if definition.Items != nil {
		if err := validateSchemaDefinition(*definition.Items, path+"[]", depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateValue(value any, expected Schema, path string, depth int) *schemaViolation {
	if depth > 64 {
		return &schemaViolation{"value_too_deep", "nesting at most 64", path}
	}
	actual := valueType(value)
	if !slices.Contains(expected.Types, actual) {
		return &schemaViolation{"json_type_mismatch", fmt.Sprintf("%s type in %v", path, expected.Types), string(actual)}
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, required := range expected.Required {
			if _, exists := typed[required]; !exists {
				return &schemaViolation{"missing_required_field", path + "." + required, "absent"}
			}
		}
		for name, child := range typed {
			property, exists := expected.Properties[name]
			if !exists {
				if !expected.AllowUnknown {
					return &schemaViolation{"unknown_field", "declared property", path + "." + name}
				}
				continue
			}
			if violation := validateValue(child, property, path+"."+name, depth+1); violation != nil {
				return violation
			}
		}
	case []any:
		if expected.Items != nil {
			for index, child := range typed {
				if violation := validateValue(child, *expected.Items, fmt.Sprintf("%s[%d]", path, index), depth+1); violation != nil {
					return violation
				}
			}
		}
	}
	return nil
}

func valueType(value any) JSONType {
	switch value.(type) {
	case map[string]any:
		return TypeObject
	case []any:
		return TypeArray
	case string:
		return TypeString
	case json.Number:
		return TypeNumber
	case bool:
		return TypeBoolean
	case nil:
		return TypeNull
	default:
		return ""
	}
}
