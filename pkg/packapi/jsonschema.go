package packapi

import (
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	scenarioSchemaOnce sync.Once
	scenarioSchema     *jsonschema.Schema
	packSchemaOnce     sync.Once
	packSchema         *jsonschema.Schema
)

func scenarioJSONSchema() *jsonschema.Schema {
	scenarioSchemaOnce.Do(func() {
		scenarioSchema = mustCompileJSONSchema("urn:agentapi-doctor:schema:scenario-authoring:v1beta1", scenarioSchemaDocument)
	})
	return scenarioSchema
}

func packJSONSchema() *jsonschema.Schema {
	packSchemaOnce.Do(func() {
		packSchema = mustCompileJSONSchema("urn:agentapi-doctor:schema:pack-authoring:v1", packSchemaDocument)
	})
	return packSchema
}

func mustCompileJSONSchema(uri, document string) *jsonschema.Schema {
	decoded, err := jsonschema.UnmarshalJSON(strings.NewReader(document))
	if err != nil {
		panic(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	if err := compiler.AddResource(uri, decoded); err != nil {
		panic(err)
	}
	compiled, err := compiler.Compile(uri)
	if err != nil {
		panic(err)
	}
	return compiled
}

const scenarioSchemaDocument = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:agentapi-doctor:schema:scenario-authoring:v1beta1",
  "type": "object",
  "additionalProperties": false,
  "required": ["apiVersion", "kind", "metadata", "spec"],
  "properties": {
    "apiVersion": {"const": "urn:agentapi-doctor:scenario:v1beta1"},
    "kind": {"const": "Scenario"},
    "metadata": {"$ref": "#/$defs/metadata"},
    "spec": {"$ref": "#/$defs/spec"}
  },
  "$defs": {
    "name": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,127}$"},
    "artifactName": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._/-]{0,127}$"},
    "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "duration": {"type": "string", "minLength": 2, "maxLength": 32},
    "bytes": {"type": "string", "pattern": "^[1-9][0-9]*(B|KiB|MiB|GiB)$"},
    "metadata": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "version", "title"],
      "properties": {
        "id": {"$ref": "#/$defs/name"},
        "version": {"type": "string"},
        "title": {"type": "string", "minLength": 1, "maxLength": 512},
        "labels": {"type": "object", "propertyNames": {"$ref": "#/$defs/name"}, "additionalProperties": {"type": "string"}}
      }
    },
    "spec": {
      "type": "object", "additionalProperties": false,
      "required": ["protocol", "classification", "requirements", "budgets", "steps", "publication"],
      "properties": {
        "protocol": {"$ref": "#/$defs/protocol"},
        "classification": {"$ref": "#/$defs/classification"},
        "requirements": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/requirement"}},
        "requires": {"$ref": "#/$defs/requires"},
        "budgets": {"$ref": "#/$defs/budgets"},
        "steps": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/step"}},
        "resources": {"type": "array", "items": {"$ref": "#/$defs/resource"}},
        "finally": {"type": "array", "items": {"$ref": "#/$defs/finalize"}},
        "repetition": {"$ref": "#/$defs/repetition"},
        "publication": {"$ref": "#/$defs/publication"}
      }
    },
    "protocol": {
      "type": "object", "additionalProperties": false,
      "required": ["family", "snapshot", "digest"],
      "properties": {
        "family": {"$ref": "#/$defs/artifactName"},
        "snapshot": {"type": "string", "minLength": 1},
        "digest": {"$ref": "#/$defs/digest"}
      }
    },
    "classification": {
      "type": "object", "additionalProperties": false,
      "required": ["type", "stability", "sideEffects", "idempotent"],
      "properties": {
        "type": {"enum": ["normative", "de-facto-client", "consumer-profile", "behavioral", "advisory"]},
        "stability": {"enum": ["stable", "experimental", "incubating"]},
        "sideEffects": {"enum": ["none", "reversible-local", "reversible-remote", "irreversible"]},
        "idempotent": {"type": "boolean"}
      }
    },
    "requirement": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "level"],
      "properties": {
        "id": {"type": "string", "pattern": "^[A-Z][A-Z0-9._-]{2,127}$"},
        "level": {"enum": ["MUST", "SHOULD", "MAY"]}
      }
    },
    "requires": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "all": {"type": "array", "items": {"$ref": "#/$defs/name"}},
        "any": {"type": "array", "items": {"$ref": "#/$defs/name"}},
        "none": {"type": "array", "items": {"$ref": "#/$defs/name"}}
      }
    },
    "budgets": {
      "type": "object", "additionalProperties": false,
      "required": ["timeout", "maxRequests", "maxInputTokens", "maxOutputTokens", "maxArtifactBytes"],
      "properties": {
        "timeout": {"$ref": "#/$defs/duration"},
        "maxRequests": {"type": "integer", "minimum": 1},
        "maxInputTokens": {"type": "integer", "minimum": 0},
        "maxOutputTokens": {"type": "integer", "minimum": 0},
        "maxResponseBytes": {"$ref": "#/$defs/bytes"},
        "maxArtifactBytes": {"$ref": "#/$defs/bytes"}
      }
    },
    "step": {
      "type": "object", "additionalProperties": false,
      "required": ["id"], "minProperties": 2, "maxProperties": 2,
      "properties": {
        "id": {"$ref": "#/$defs/name"},
        "invoke": {"$ref": "#/$defs/invoke"},
        "capture": {"$ref": "#/$defs/capture"},
        "register_resource": {"$ref": "#/$defs/registerResource"},
        "provide_tool_result": {"$ref": "#/$defs/provideToolResult"},
        "wait_for": {"$ref": "#/$defs/waitFor"},
        "assert": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/assertion"}},
        "cancel": {"$ref": "#/$defs/cancel"},
        "replay": {"$ref": "#/$defs/replay"},
        "finalize": {"$ref": "#/$defs/finalize"}
      }
    },
    "invoke": {
      "type": "object", "additionalProperties": false,
      "required": ["operation", "driver", "request"],
      "properties": {
        "operation": {"$ref": "#/$defs/artifactName"},
        "driver": {"$ref": "#/$defs/artifactName"},
        "controlledBackend": {
          "type": "object", "additionalProperties": false, "required": ["fixture"],
          "properties": {"fixture": {"type": "string", "minLength": 1}}
        },
        "request": {"type": "object"}
      }
    },
    "capture": {
      "type": "object", "additionalProperties": false, "required": ["stream", "as"],
      "properties": {"stream": {"type": "string", "minLength": 1}, "as": {"$ref": "#/$defs/name"}}
    },
    "registerResource": {
      "type": "object", "additionalProperties": false, "required": ["resource", "acquireFrom"],
      "properties": {"resource": {"$ref": "#/$defs/name"}, "acquireFrom": {"type": "string", "minLength": 1}}
    },
    "provideToolResult": {
      "type": "object", "additionalProperties": false, "required": ["callIdFrom", "result"],
      "properties": {"callIdFrom": {"type": "string", "minLength": 1}, "result": true}
    },
    "waitFor": {
      "type": "object", "additionalProperties": false, "required": ["source", "condition", "timeout"],
      "properties": {"source": {"type": "string", "minLength": 1}, "condition": {"type": "string", "minLength": 1}, "timeout": {"$ref": "#/$defs/duration"}}
    },
    "assertion": {
      "type": "object", "additionalProperties": false, "required": ["assertionRole"],
      "properties": {
        "use": {"$ref": "#/$defs/artifactName"},
        "expression": {"type": "string", "minLength": 1, "maxLength": 8192},
        "equals": true,
        "assertionRole": {"enum": ["precondition", "normative", "consumer_profile", "behavioral", "advisory"]},
        "observedAt": {"type": "string", "minLength": 1},
        "requirement": {"type": "string", "pattern": "^[A-Z][A-Z0-9._-]{2,127}$"}
      },
      "oneOf": [
        {"required": ["use"], "not": {"required": ["expression"]}},
        {"required": ["expression"], "not": {"required": ["use"]}}
      ]
    },
    "cancel": {
      "type": "object", "additionalProperties": false, "required": ["invocation", "reason"],
      "properties": {"invocation": {"type": "string", "minLength": 1}, "reason": {"type": "string", "minLength": 1}}
    },
    "replay": {
      "type": "object", "additionalProperties": false, "required": ["fixture", "as"],
      "properties": {"fixture": {"type": "string", "minLength": 1}, "as": {"$ref": "#/$defs/name"}}
    },
    "finalize": {
      "type": "object", "additionalProperties": false, "required": ["finalize"],
      "properties": {"finalize": {"$ref": "#/$defs/name"}}
    },
    "resource": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "acquireFrom", "sideEffectClass", "finalizer", "cleanupBudget"],
      "properties": {
        "id": {"$ref": "#/$defs/name"},
        "acquireFrom": {"type": "string", "minLength": 1},
        "sideEffectClass": {"enum": ["none", "reversible-local", "reversible-remote", "irreversible"]},
        "finalizer": {"$ref": "#/$defs/resourceFinalizer"},
        "cleanupBudget": {"$ref": "#/$defs/cleanupBudget"}
      }
    },
    "resourceFinalizer": {
      "type": "object", "additionalProperties": false, "required": ["operation", "idempotent", "retry"],
      "properties": {
        "operation": {"$ref": "#/$defs/artifactName"},
        "idempotent": {"type": "boolean"},
        "retry": {
          "type": "object", "additionalProperties": false, "required": ["maxAttempts"],
          "properties": {"maxAttempts": {"type": "integer", "minimum": 1, "maximum": 10}}
        }
      }
    },
    "cleanupBudget": {
      "type": "object", "additionalProperties": false, "required": ["requests", "duration"],
      "properties": {"requests": {"type": "integer", "minimum": 1}, "duration": {"$ref": "#/$defs/duration"}}
    },
    "repetition": {
      "type": "object", "additionalProperties": false, "required": ["count", "policy"],
      "properties": {"count": {"type": "integer", "minimum": 1, "maximum": 1000}, "policy": {"enum": ["all", "any"]}}
    },
    "publication": {
      "type": "object", "additionalProperties": false, "required": ["dataClass"],
      "properties": {"dataClass": {"enum": ["synthetic-only", "metadata-only", "local-private"]}}
    }
  }
}`

const packSchemaDocument = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:agentapi-doctor:schema:pack-authoring:v1",
  "type": "object", "additionalProperties": false,
  "required": ["apiVersion", "kind", "metadata", "spec"],
  "properties": {
    "apiVersion": {"const": "urn:agentapi-doctor:pack:v1"},
    "kind": {"const": "ProtocolPack"},
    "metadata": {
      "type": "object", "additionalProperties": false, "required": ["name", "version"],
      "properties": {
        "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._/-]{0,127}$"},
        "version": {"type": "string", "pattern": "^20[0-9]{2}\\.(0[1-9]|1[0-2])\\.(0|[1-9][0-9]*)$"}
      }
    },
    "spec": {"$ref": "#/$defs/spec"}
  },
  "$defs": {
    "duration": {"type": "string", "minLength": 2, "maxLength": 32},
    "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "spec": {
      "type": "object", "additionalProperties": false,
      "required": ["engine", "protocolSnapshot", "scenarios", "conformanceSuites", "defaultBudget"],
      "properties": {
        "engine": {
          "type": "object", "additionalProperties": false, "required": ["minVersion", "maxMajor"],
          "properties": {"minVersion": {"type": "string"}, "maxMajor": {"type": "integer", "minimum": 1}}
        },
        "protocolSnapshot": {
          "type": "object", "additionalProperties": false, "required": ["ref"],
          "properties": {"ref": {"type": "string", "minLength": 1}}
        },
        "scenarios": {
          "type": "object", "additionalProperties": false, "required": ["include"],
          "properties": {"include": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}}}
        },
        "conformanceSuites": {
          "type": "object", "minProperties": 1,
          "propertyNames": {"pattern": "^[a-z][a-z0-9._-]{0,127}$"},
          "additionalProperties": {
            "type": "object", "additionalProperties": false, "required": ["requirements"],
            "properties": {"requirements": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,127}$"}}}
          }
        },
        "defaultBudget": {
          "type": "object", "additionalProperties": false, "required": ["maxRequests", "maxDuration"],
          "properties": {"maxRequests": {"type": "integer", "minimum": 1}, "maxDuration": {"$ref": "#/$defs/duration"}}
        },
        "signing": {
          "type": "object", "additionalProperties": false,
          "properties": {"digest": {"$ref": "#/$defs/digest"}}
        }
      }
    }
  }
}`
