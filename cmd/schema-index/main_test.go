package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildRejectsDuplicateIDsAndSorts(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "schemas", "x")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, id string) {
		t.Helper()
		raw := `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"` + id + `","type":"object"}`
		if err := os.WriteFile(filepath.Join(directory, name), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("b.schema.json", "urn:test:b")
	write("a.schema.json", "urn:test:a")
	encoded, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(encoded), "urn:test:a") > strings.Index(string(encoded), "urn:test:b") {
		t.Fatal("schema index is not sorted")
	}
	write("duplicate.schema.json", "urn:test:a")
	if _, err := build(root); err == nil {
		t.Fatal("duplicate schema ID was accepted")
	}
}

func TestBuildRejectsNon202012AndUnresolvedReference(t *testing.T) {
	tests := []struct {
		name   string
		schema string
	}{
		{
			name:   "wrong draft",
			schema: `{"$schema":"http://json-schema.org/draft-07/schema#","$id":"urn:test:draft","type":"object"}`,
		},
		{
			name:   "unresolved reference",
			schema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:test:ref","$ref":"urn:test:missing"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "schemas")
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "invalid.schema.json"), []byte(test.schema), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := build(root); err == nil {
				t.Fatal("invalid schema registry was accepted")
			}
		})
	}
}
