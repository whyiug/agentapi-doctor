package packapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"unicode/utf8"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const (
	MaxAuthoredYAMLBytes = 4 << 20
	maxYAMLDepth         = 128
	maxYAMLNodes         = 100000
)

var (
	jsonIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	jsonNumberPattern  = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
)

func decodeScenarioYAML(raw []byte) (Scenario, error) {
	var scenario Scenario
	if err := decodeAuthoredYAML(raw, scenarioJSONSchema(), &scenario); err != nil {
		return Scenario{}, err
	}
	return scenario, nil
}

func decodePackYAML(raw []byte) (ProtocolPack, error) {
	var pack ProtocolPack
	if err := decodeAuthoredYAML(raw, packJSONSchema(), &pack); err != nil {
		return ProtocolPack{}, err
	}
	return pack, nil
}

func decodeAuthoredYAML(raw []byte, schema *jsonschema.Schema, destination any) error {
	if len(raw) == 0 {
		return errors.New("authored YAML is empty")
	}
	if len(raw) > MaxAuthoredYAMLBytes {
		return fmt.Errorf("authored YAML exceeds %d bytes", MaxAuthoredYAMLBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("authored YAML is not valid UTF-8")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("parse authored YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("authored YAML must contain exactly one document")
		}
		return fmt.Errorf("read trailing YAML document: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("authored YAML root must be one mapping document")
	}
	nodeCount := 0
	if err := validateYAMLNode(document.Content[0], "$", 0, &nodeCount); err != nil {
		return err
	}
	value, err := yamlNodeToJSON(document.Content[0], "$")
	if err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("JSON Schema validation: %w", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal authored JSON projection: %w", err)
	}
	jsonDecoder := json.NewDecoder(bytes.NewReader(encoded))
	jsonDecoder.DisallowUnknownFields()
	jsonDecoder.UseNumber()
	if err := jsonDecoder.Decode(destination); err != nil {
		return fmt.Errorf("decode authored contract: %w", err)
	}
	if err := ensureJSONEOF(jsonDecoder); err != nil {
		return err
	}
	return nil
}

func validateYAMLNode(node *yaml.Node, path string, depth int, count *int) error {
	*count++
	if *count > maxYAMLNodes {
		return fmt.Errorf("authored YAML exceeds %d nodes", maxYAMLNodes)
	}
	if depth > maxYAMLDepth {
		return fmt.Errorf("authored YAML nesting exceeds %d at %s", maxYAMLDepth, path)
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode || node.Alias != nil {
		return fmt.Errorf("YAML anchors and aliases are forbidden at %s", path)
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" {
			return fmt.Errorf("custom YAML mapping tag %q is forbidden at %s", node.Tag, path)
		}
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("malformed YAML mapping at %s", path)
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			value := node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("YAML mapping key at %s must be a string", path)
			}
			if key.Value == "<<" {
				return fmt.Errorf("YAML merge keys are forbidden at %s", path)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("duplicate YAML field %q at %s", key.Value, path)
			}
			seen[key.Value] = struct{}{}
			if err := validateYAMLNode(value, path+"."+key.Value, depth+1, count); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return fmt.Errorf("custom YAML sequence tag %q is forbidden at %s", node.Tag, path)
		}
		for index, child := range node.Content {
			if err := validateYAMLNode(child, fmt.Sprintf("%s[%d]", path, index), depth+1, count); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
		case "!!bool":
			if node.Value != "true" && node.Value != "false" {
				return fmt.Errorf("boolean at %s must be true or false", path)
			}
		case "!!int":
			if !jsonIntegerPattern.MatchString(node.Value) {
				return fmt.Errorf("integer %q at %s is not canonical JSON syntax", node.Value, path)
			}
		case "!!float":
			if !jsonNumberPattern.MatchString(node.Value) {
				return fmt.Errorf("number %q at %s is not finite canonical JSON syntax", node.Value, path)
			}
		case "!!null":
			if node.Value != "null" {
				return fmt.Errorf("null at %s must be written as null", path)
			}
		default:
			return fmt.Errorf("custom or implicit YAML tag %q is forbidden at %s; quote timestamps and special values", node.Tag, path)
		}
	default:
		return fmt.Errorf("unsupported YAML node kind %d at %s", node.Kind, path)
	}
	return nil
}

func yamlNodeToJSON(node *yaml.Node, path string) (any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		value := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index].Value
			child, err := yamlNodeToJSON(node.Content[index+1], path+"."+key)
			if err != nil {
				return nil, err
			}
			value[key] = child
		}
		return value, nil
	case yaml.SequenceNode:
		value := make([]any, len(node.Content))
		for index, child := range node.Content {
			converted, err := yamlNodeToJSON(child, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			value[index] = converted
		}
		return value, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			return node.Value, nil
		case "!!bool":
			return node.Value == "true", nil
		case "!!int":
			integer, err := strconv.ParseInt(node.Value, 10, 64)
			if err != nil || integer > 1<<53-1 || integer < -(1<<53-1) {
				return nil, fmt.Errorf("integer %q at %s is outside the interoperable JSON range", node.Value, path)
			}
			return json.Number(node.Value), nil
		case "!!float":
			number, err := strconv.ParseFloat(node.Value, 64)
			if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
				return nil, fmt.Errorf("invalid finite number %q at %s", node.Value, path)
			}
			return json.Number(node.Value), nil
		case "!!null":
			return nil, nil
		}
	}
	return nil, fmt.Errorf("cannot convert YAML node at %s", path)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return fmt.Errorf("read trailing JSON value: %w", err)
	}
	return nil
}
