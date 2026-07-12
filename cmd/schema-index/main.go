// Command schema-index regenerates the deterministic schema registry.  It is
// a repository maintenance tool, not a user-facing command.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
	"gopkg.in/yaml.v3"
)

const draft202012 = "https://json-schema.org/draft/2020-12/schema"

type entry struct {
	ID     string        `yaml:"id"`
	Path   string        `yaml:"path"`
	Digest schema.Digest `yaml:"digest"`
}

type index struct {
	SchemaVersion string  `yaml:"schemaVersion"`
	Kind          string  `yaml:"kind"`
	Status        string  `yaml:"status"`
	Entries       []entry `yaml:"entries"`
}

func main() {
	root := "."
	check := false
	for _, argument := range os.Args[1:] {
		switch argument {
		case "--check":
			check = true
		default:
			if strings.HasPrefix(argument, "-") || root != "." {
				fatal(errors.New("usage: schema-index [--check] [root]"))
			}
			root = argument
		}
	}
	generated, err := build(root)
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(root, "schemas", "index.yaml")
	if check {
		current, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		if !bytes.Equal(current, generated) {
			fatal(errors.New("schemas/index.yaml is stale; run go run ./cmd/schema-index"))
		}
		return
	}
	if err := os.WriteFile(path, generated, 0o644); err != nil {
		fatal(err)
	}
}

func build(root string) ([]byte, error) {
	schemasRoot := filepath.Join(root, "schemas")
	entries := []entry{}
	seen := map[string]string{}
	documents := map[string]any{}
	err := filepath.WalkDir(schemasRoot, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".schema.json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		canonical, err := schema.CanonicalizeJSON(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var header struct {
			Schema string `json:"$schema"`
			ID     string `json:"$id"`
		}
		if err := json.Unmarshal(canonical, &header); err != nil || header.ID == "" {
			return fmt.Errorf("%s: non-empty $id is required", path)
		}
		if header.Schema != draft202012 {
			return fmt.Errorf("%s: $schema must be %s", path, draft202012)
		}
		if previous, duplicate := seen[header.ID]; duplicate {
			return fmt.Errorf("duplicate schema ID %s in %s and %s", header.ID, previous, path)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(canonical))
		if err != nil {
			return fmt.Errorf("%s: decode JSON Schema: %w", path, err)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		seen[header.ID] = relative
		documents[header.ID] = document
		entries = append(entries, entry{ID: header.ID, Path: relative, Digest: schema.NewDigest(canonical)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].ID < entries[right].ID })
	if len(entries) == 0 {
		return nil, errors.New("no JSON schemas found")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	for id, document := range documents {
		if err := compiler.AddResource(id, document); err != nil {
			return nil, fmt.Errorf("register schema %s: %w", id, err)
		}
	}
	for _, indexed := range entries {
		if _, err := compiler.Compile(indexed.ID); err != nil {
			return nil, fmt.Errorf("compile %s (%s): %w", indexed.ID, indexed.Path, err)
		}
	}
	encoded, err := yaml.Marshal(index{SchemaVersion: "urn:agentapi-doctor:schema-index:v1alpha1", Kind: "SchemaIndex", Status: "provisional", Entries: entries})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
