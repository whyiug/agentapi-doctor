package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

var (
	// ErrDuplicateJSONKey is returned before canonicalization if an object
	// contains a repeated member name.  encoding/json otherwise accepts the
	// last occurrence, which would make a signed input ambiguous.
	ErrDuplicateJSONKey = errors.New("duplicate JSON object key")
	// ErrTrailingJSONValue rejects concatenated or trailing JSON values.
	ErrTrailingJSONValue = errors.New("trailing JSON value")
)

// CanonicalizeJSON validates a single UTF-8 JSON value, rejects duplicate
// object keys and non-finite/ambiguous numbers, and returns RFC 8785 JCS bytes.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validateUniqueJSON(raw); err != nil {
		return nil, err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize RFC 8785 JSON: %w", err)
	}
	return canonical, nil
}

// CanonicalMarshal marshals a typed value and canonicalizes the result.
// Typed values cannot carry duplicate member names; custom MarshalJSON
// implementations are still subjected to strict validation.
func CanonicalMarshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON input: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalDigest hashes the RFC 8785 representation of value.
func CanonicalDigest(value any) (Digest, error) {
	canonical, err := CanonicalMarshal(value)
	if err != nil {
		return "", err
	}
	return NewDigest(canonical), nil
}

func validateUniqueJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, "$", 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("read trailing JSON: %w", err)
		}
		return fmt.Errorf("%w: unexpected token %v", ErrTrailingJSONValue, token)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string, depth int) error {
	if depth > 256 {
		return fmt.Errorf("JSON nesting exceeds 256 at %s", path)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON at %s: %w", path, err)
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode object key at %s: %w", path, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("non-string object key at %s", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w %q at %s", ErrDuplicateJSONKey, key, path)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("unterminated object at %s", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("unterminated array at %s", path)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delim, path)
	}
	return nil
}
