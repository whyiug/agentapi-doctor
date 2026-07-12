// Package normalizer builds provider-neutral IR without overwriting the
// provider-native JSON type or the capture-layer evidence that supports it.
package normalizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

type Transform string

const (
	TransformIdentity         Transform = "identity"
	TransformDecodeJSONString Transform = "decode_json_string"
)

type Request struct {
	ItemID         string
	IRType         schema.IRType
	SourceProtocol string
	InteractionID  string
	ParentItemID   string
	CallID         string
	NativeValue    json.RawMessage
	EvidenceRefs   []schema.ObjectRef
	Extension      string
	Transform      Transform
	Version        string
}

// Normalize canonicalizes native JSON while preserving its type. A transform
// that cannot round-trip produces an explicit loss/unavailable marker instead
// of silently claiming semantic equality.
func Normalize(request Request) (schema.IRItem, error) {
	if request.Version == "" {
		return schema.IRItem{}, errors.New("normalization transform version is required")
	}
	canonicalNative, err := schema.CanonicalizeJSON(request.NativeValue)
	if err != nil {
		return schema.IRItem{}, fmt.Errorf("provider-native value: %w", err)
	}
	sourceType, err := JSONType(canonicalNative)
	if err != nil {
		return schema.IRItem{}, err
	}
	item := schema.IRItem{
		ItemID:           request.ItemID,
		IRType:           request.IRType,
		SourceProtocol:   request.SourceProtocol,
		SourceType:       sourceType,
		InteractionID:    request.InteractionID,
		ParentItemID:     request.ParentItemID,
		CallID:           request.CallID,
		NativeValue:      append(json.RawMessage(nil), canonicalNative...),
		EvidenceRefs:     append([]schema.ObjectRef(nil), request.EvidenceRefs...),
		Extension:        request.Extension,
		TransformID:      string(request.Transform),
		TransformVersion: request.Version,
	}

	switch request.Transform {
	case TransformIdentity:
		item.NormalizedValue = append(json.RawMessage(nil), canonicalNative...)
	case TransformDecodeJSONString:
		if sourceType != "string" {
			return schema.IRItem{}, fmt.Errorf("decode_json_string requires native string, got %s", sourceType)
		}
		var encoded string
		if err := json.Unmarshal(canonicalNative, &encoded); err != nil {
			return schema.IRItem{}, fmt.Errorf("decode native JSON string: %w", err)
		}
		canonicalInner, err := schema.CanonicalizeJSON([]byte(encoded))
		if err != nil {
			item.LossMarkers = []schema.LossMarker{{
				TransformID: string(request.Transform),
				Reason:      "provider-native string does not contain valid JSON",
			}}
			item.Unavailable = []string{"normalized_value"}
		} else {
			item.NormalizedValue = append(json.RawMessage(nil), canonicalInner...)
		}
	default:
		return schema.IRItem{}, fmt.Errorf("unsupported normalization transform %q", request.Transform)
	}
	if item.Extension != "" && (!strings.HasPrefix(item.Extension, schema.ExtensionPrefix) || len(item.Extension) == len(schema.ExtensionPrefix)) {
		return schema.IRItem{}, errors.New("extension namespace must start with x- and include a name")
	}
	if len(item.NormalizedValue) > 0 && !json.Valid(item.NormalizedValue) {
		return schema.IRItem{}, errors.New("normalized value is not valid JSON")
	}
	if err := item.Validate(); err != nil {
		return schema.IRItem{}, fmt.Errorf("validate IR item: %w", err)
	}
	return item, nil
}

// JSONType returns the provider-native JSON type without converting numbers or
// string-contained JSON into another type.
func JSONType(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return "", errors.New("value is not valid JSON")
	}
	switch trimmed[0] {
	case '{':
		return "object", nil
	case '[':
		return "array", nil
	case '"':
		return "string", nil
	case 't', 'f':
		return "boolean", nil
	case 'n':
		return "null", nil
	default:
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		var number json.Number
		if err := decoder.Decode(&number); err != nil {
			return "", fmt.Errorf("decode JSON number: %w", err)
		}
		return "number", nil
	}
}
