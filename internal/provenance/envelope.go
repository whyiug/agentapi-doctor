// Package provenance provides deterministic local attestations. It does not
// assign Registry trust labels; those are derived by an independent policy.
package provenance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

const EnvelopeVersion = "dsse-envelope-v1"

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	Version     string      `json:"version"`
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

func KeyID(publicKey ed25519.PublicKey) string {
	return string(schema.NewDigest(publicKey))
}

// Sign canonicalizes a JSON statement, signs DSSE pre-authentication bytes,
// and returns an envelope containing exactly one signature.
func Sign(payloadType string, statement []byte, privateKey ed25519.PrivateKey) (Envelope, error) {
	if payloadType == "" {
		return Envelope{}, errors.New("payload type is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid Ed25519 private key")
	}
	canonical, err := schema.CanonicalizeJSON(statement)
	if err != nil {
		return Envelope{}, fmt.Errorf("canonicalize statement: %w", err)
	}
	signature := ed25519.Sign(privateKey, pae(payloadType, canonical))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return Envelope{Version: EnvelopeVersion, PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(canonical), Signatures: []Signature{{KeyID: KeyID(publicKey), Sig: base64.StdEncoding.EncodeToString(signature)}}}, nil
}

// AddSignature signs the same immutable payload with another key. Duplicate
// key IDs are rejected so threshold verification counts independent keys.
func AddSignature(envelope Envelope, privateKey ed25519.PrivateKey) (Envelope, error) {
	statement, err := decodeEnvelope(envelope)
	if err != nil {
		return Envelope{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid Ed25519 private key")
	}
	keyID := KeyID(privateKey.Public().(ed25519.PublicKey))
	for _, signature := range envelope.Signatures {
		if signature.KeyID == keyID {
			return Envelope{}, errors.New("signer already present")
		}
	}
	signed := ed25519.Sign(privateKey, pae(envelope.PayloadType, statement))
	envelope.Signatures = append(append([]Signature(nil), envelope.Signatures...), Signature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signed)})
	return envelope, nil
}

// Verify requires threshold distinct trusted signatures and returns a copy of
// the canonical statement. Unknown keys do not count; malformed signatures
// fail closed rather than being ignored.
func Verify(envelope Envelope, trusted map[string]ed25519.PublicKey, threshold int) ([]byte, error) {
	if threshold < 1 {
		return nil, errors.New("signature threshold must be positive")
	}
	statement, err := decodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(envelope.Signatures))
	valid := 0
	for _, signature := range envelope.Signatures {
		if _, duplicate := seen[signature.KeyID]; duplicate {
			return nil, fmt.Errorf("duplicate signature for key %s", signature.KeyID)
		}
		seen[signature.KeyID] = struct{}{}
		decoded, err := base64.StdEncoding.Strict().DecodeString(signature.Sig)
		if err != nil || len(decoded) != ed25519.SignatureSize {
			return nil, fmt.Errorf("malformed signature for key %s", signature.KeyID)
		}
		publicKey, trustedKey := trusted[signature.KeyID]
		if !trustedKey {
			continue
		}
		if len(publicKey) != ed25519.PublicKeySize || KeyID(publicKey) != signature.KeyID {
			return nil, fmt.Errorf("trusted key binding mismatch for %s", signature.KeyID)
		}
		if !ed25519.Verify(publicKey, pae(envelope.PayloadType, statement), decoded) {
			return nil, fmt.Errorf("invalid signature for trusted key %s", signature.KeyID)
		}
		valid++
	}
	if valid < threshold {
		return nil, fmt.Errorf("signature threshold not met: got %d, require %d", valid, threshold)
	}
	return append([]byte(nil), statement...), nil
}

func decodeEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.Version != EnvelopeVersion || envelope.PayloadType == "" || envelope.Payload == "" || len(envelope.Signatures) == 0 {
		return nil, errors.New("incomplete or unsupported provenance envelope")
	}
	statement, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return nil, errors.New("payload is not strict base64")
	}
	canonical, err := schema.CanonicalizeJSON(statement)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON statement: %w", err)
	}
	if !bytes.Equal(statement, canonical) {
		return nil, errors.New("signed statement is not canonical RFC8785 JSON")
	}
	return statement, nil
}

func pae(payloadType string, payload []byte) []byte {
	return []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " " + string(payload))
}
