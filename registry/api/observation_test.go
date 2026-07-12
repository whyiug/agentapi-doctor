package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func mustObject(t *testing.T, raw string) CanonicalObject {
	t.Helper()
	object, err := ParseCanonicalObject([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func fixtureProjection(t *testing.T) ObservationProjection {
	t.Helper()
	return ObservationProjection{
		SchemaVersion:  ObservationSchemaV1,
		Subject:        mustObject(t, `{"project":"example/runtime","version":"1.2.3"}`),
		Test:           mustObject(t, `{"pack":"responses","pack_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		Environment:    mustObject(t, `{"arch":"amd64","os":"linux"}`),
		Result:         mustObject(t, `{"profile_outcome":"incompatible","verdict_counts":{"fail":1,"pass":2}}`),
		ManifestDigest: schema.NewDigest([]byte("manifest")),
	}
}

func TestObservationDigestExcludesRegistryDerivedAndProvenance(t *testing.T) {
	projection := fixtureProjection(t)
	classID := schema.NewDigest([]byte("class"))
	first, err := NewObservation(projection, classID, nil, RegistryDerived{})
	if err != nil {
		t.Fatal(err)
	}
	published := schema.NewUTCTime(time.Date(2026, 7, 12, 3, 4, 5, 0, time.UTC))
	second, err := first.WithAttestation(AttestationReference{
		Digest: schema.NewDigest([]byte("attestation")),
		URI:    "oci://registry.invalid/attestation@sha256:opaque",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err = second.WithRegistryDerived(RegistryDerived{
		TrustLabels:  []string{"owner-verified"},
		Freshness:    FreshnessFresh,
		PublishedAt:  &published,
		DisputeIDs:   []string{"dispute-1"},
		SupersededBy: schema.NewDigest([]byte("replacement")),
		Tombstoned:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatalf("derived fields changed observation ID: %s != %s", first.ID(), second.ID())
	}
	if first.ClassID() != second.ClassID() {
		t.Fatal("class ID changed while attaching Registry metadata")
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) == string(secondJSON) {
		t.Fatal("derived views should differ on the wire")
	}
}

func TestObservationClassIDIsOutsideObservationIDProjection(t *testing.T) {
	projection := fixtureProjection(t)
	first, err := NewObservation(projection, schema.NewDigest([]byte("class one")), nil, RegistryDerived{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewObservation(projection, schema.NewDigest([]byte("class two")), nil, RegistryDerived{})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatal("observation_class_id incorrectly entered observation_id projection")
	}
	if first.ClassID() == second.ClassID() {
		t.Fatal("fixture class IDs should differ")
	}
}

func TestEveryProjectionSectionAffectsObservationID(t *testing.T) {
	base := fixtureProjection(t)
	baseID, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(ObservationProjection) ObservationProjection{
		"subject": func(value ObservationProjection) ObservationProjection {
			value.Subject = mustObject(t, `{"project":"different/runtime","version":"1.2.3"}`)
			return value
		},
		"test": func(value ObservationProjection) ObservationProjection {
			value.Test = mustObject(t, `{"pack":"chat","pack_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
			return value
		},
		"environment": func(value ObservationProjection) ObservationProjection {
			value.Environment = mustObject(t, `{"arch":"arm64","os":"linux"}`)
			return value
		},
		"result": func(value ObservationProjection) ObservationProjection {
			value.Result = mustObject(t, `{"profile_outcome":"compatible","verdict_counts":{"fail":0,"pass":3}}`)
			return value
		},
		"manifest": func(value ObservationProjection) ObservationProjection {
			value.ManifestDigest = schema.NewDigest([]byte("other manifest"))
			return value
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := mutate(base).Digest()
			if err != nil {
				t.Fatal(err)
			}
			if got == baseID {
				t.Fatalf("changing %s did not change observation ID", name)
			}
		})
	}
}

func TestCanonicalEquivalentObjectsProduceSameObservationID(t *testing.T) {
	first := fixtureProjection(t)
	second := fixtureProjection(t)
	second.Subject = mustObject(t, "{\n  \"version\": \"1.2.3\", \"project\": \"example/runtime\"\n}")
	firstID, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstID != secondID {
		t.Fatalf("canonical-equivalent objects differ: %s != %s", firstID, secondID)
	}
}

func TestCanonicalObjectRejectsAmbiguousOrNonObjectInput(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `[]`, `null`, `{"a":1} {"b":2}`} {
		if _, err := ParseCanonicalObject([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid object %s", raw)
		}
	}

	raw := []byte(`{"a":1}`)
	object, err := ParseCanonicalObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[2] = 'z'
	if got := string(object.Bytes()); got != `{"a":1}` {
		t.Fatalf("caller mutated canonical object through input alias: %s", got)
	}
	returned := object.Bytes()
	returned[2] = 'z'
	if got := string(object.Bytes()); got != `{"a":1}` {
		t.Fatalf("caller mutated canonical object through output alias: %s", got)
	}
}

func TestObservationJSONRoundTripVerifiesClaimedID(t *testing.T) {
	observation, err := NewObservation(fixtureProjection(t), schema.NewDigest([]byte("class")), nil, RegistryDerived{Freshness: FreshnessUnknown})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Observation
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID() != observation.ID() {
		t.Fatalf("round-trip ID mismatch: %s != %s", decoded.ID(), observation.ID())
	}

	tampered := strings.Replace(string(raw), string(observation.ID()), string(schema.NewDigest([]byte("tampered ID"))), 1)
	if err := json.Unmarshal([]byte(tampered), &decoded); err == nil || !strings.Contains(err.Error(), "ID mismatch") {
		t.Fatalf("expected claimed ID mismatch, got %v", err)
	}

	duplicate := strings.Replace(string(raw), `"schema_version":`, `"schema_version":"urn:agentapi-doctor:observation:v1","schema_version":`, 1)
	if err := json.Unmarshal([]byte(duplicate), &decoded); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("expected duplicate top-level key rejection, got %v", err)
	}
}

func TestObservationRejectsInvalidDerivedMetadata(t *testing.T) {
	projection := fixtureProjection(t)
	classID := schema.NewDigest([]byte("class"))
	attestation := AttestationReference{Digest: schema.NewDigest([]byte("attestation"))}
	_, err := NewObservation(projection, classID, []AttestationReference{attestation, attestation}, RegistryDerived{})
	if err == nil || !strings.Contains(err.Error(), "duplicate attestation") {
		t.Fatalf("expected duplicate attestation rejection, got %v", err)
	}
	_, err = NewObservation(projection, classID, nil, RegistryDerived{Freshness: "brand-new"})
	if err == nil {
		t.Fatal("accepted unknown freshness")
	}
}
