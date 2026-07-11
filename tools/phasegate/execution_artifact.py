"""Strict, portable evidence bundle for protected P00 Run A/Run B execution.

The in-memory seals in :mod:`tools.phasegate.gate_runner` intentionally do not
survive a process boundary.  This module carries the raw, bounded stdout and
stderr plus the non-secret execution facts needed to reconstruct those seals.
Import never trusts a serialized verdict or summary: it re-evaluates the raw
logs, evaluator input/output, command manifest, and both RunEvidence objects.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import json
import re
from typing import Any, Mapping, Sequence

from .digest import canonical_json_bytes, sha256_bytes
from .gate_runner import (
    BOOTSTRAP_ASSERTIONS,
    BOOTSTRAP_EVALUATORS,
    EVALUATOR_CRITERION_IDS,
    FIXED_COMMANDS,
    GateRunnerError,
    SealedPhaseRunPair,
    SealedRunPair,
    combine_phase_runs,
    combine_runs,
    criterion_result_projection,
    phase_criterion_result_projection,
    record_phase_run,
    record_run,
)
from .p00_evaluators import EvaluationError, canonical_digest, evaluate_strict
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    CriterionBinding,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedProtectedInputFreeze,
    _require_verified,
)


BUNDLE_SCHEMA = "urn:agentapi-doctor:execution-artifact-bundle:v1"
PHASE_BUNDLE_SCHEMA = "urn:agentapi-doctor:phase-execution-artifact-bundle:v1"
RUN_SCHEMA = "urn:agentapi-doctor:execution-command-artifact:v1"
OUTPUT_SCHEMA = "urn:agentapi-doctor:execution-output-bytes:v1"
TOOL_SCHEMA = "urn:agentapi-doctor:execution-tools:v1"
ENVIRONMENT_SCHEMA = "urn:agentapi-doctor:execution-environment:v1"
MANIFEST_SCHEMA = "urn:agentapi-doctor:protected-run-artifacts:v1"
ASSERTION_SCHEMA = "urn:agentapi-doctor:protected-command-assertion:v1"
ISOLATED_EVALUATOR_SCHEMA = "urn:agentapi-doctor:isolated-p00-evaluator:v1"
REDACTION_POLICY = "reject-synthetic-canary-and-host-path-v1"
SYNTHETIC_SECRET_CANARY = b"AGENTAPI_DOCTOR_EXECUTION_SECRET_CANARY_V1"
MAX_STREAM_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UNITTEST_COUNT_RE = re.compile(rb"(?:^|\n)Ran ([1-9][0-9]*) tests? in ")
UNITTEST_OK_RE = re.compile(rb"(?:^|\n)OK(?:\n|$)")
CANARY_RE = re.compile(rb"(?i)(?:secret[-_ ]?canary|run_executor_sentinel_secret)")
PUBLIC_CANARY_IDENTIFIERS = (
    b"evaluator://redaction/secret-canary/v1",
    b"evidence-schema://redaction/secret-canary-report/v1",
)
HOST_PATH_RE = re.compile(
    rb"(?:(?:/tmp|/home|/data[0-9]*|/var/tmp)/[^\x00\r\n ]+|[A-Za-z]:\\[^\x00\r\n ]+)"
)

BUNDLE_FIELDS = {
    "schemaVersion",
    "freezeDigest",
    "criterionId",
    "evaluator",
    "sourceCommit",
    "controlPlaneDigest",
    "contractDigest",
    "evaluatorInput",
    "runs",
    "runPair",
    "runPairDigest",
    "bundleDigest",
}
PHASE_BUNDLE_FIELDS = (BUNDLE_FIELDS - {"contractDigest"}) | {
    "aggregateContractDigest"
}
RUN_FIELDS = {
    "schemaVersion",
    "label",
    "evaluator",
    "commandDigest",
    "checkoutIdentity",
    "execution",
    "environmentFacts",
    "toolFacts",
    "stdout",
    "stderr",
    "evaluatorEvidence",
    "semanticAssertions",
    "logDigest",
    "artifactManifestDigest",
    "producerObservedDestruction",
    "artifactDigest",
}
OUTPUT_FIELDS = {
    "schemaVersion",
    "encoding",
    "data",
    "byteLength",
    "digest",
    "complete",
    "redactionPolicy",
}
EXECUTION_FIELDS = {
    "exitCode",
    "durationMs",
    "startedAt",
    "finishedAt",
    "timedOut",
    "outputTruncated",
}
CHECKOUT_FIELDS = {
    "sourceCommit",
    "headVerified",
    "sourceDirtyBeforeRun",
    "freshIsolatedClone",
    "cleanCheckout",
}
ENVIRONMENT_FIELDS = {
    "schemaVersion",
    "environmentClass",
    "minimalEnvironment",
    "temporaryHome",
    "networkCredentialsInherited",
    "networkNamespace",
    "networkNamespaceFailClosed",
    "shell",
    "outputLimitBytes",
}
TOOL_FIELDS = {
    "schemaVersion",
    "gitDigest",
    "pythonDigest",
    "unshareDigest",
    "unshareArguments",
}
DESTRUCTION_FIELDS = {
    "kind",
    "checkoutAbsent",
    "homeAbsent",
    "temporaryAbsent",
    "observedBeforeNextRun",
    "requiresProtectedOidcBinding",
}
ASSERTION_FIELDS = {"id", "status", "evidenceDigest"}


@dataclass
class ExecutionArtifactError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class CapturedRunArtifact:
    """Raw facts retained after the owned checkout/HOME/TMP were destroyed."""

    label: str
    stdout: bytes
    stderr: bytes
    command_result: Mapping[str, Any]
    evaluator_evidence: Mapping[str, Any] | None
    output_limit_bytes: int
    git_digest: str
    python_digest: str
    unshare_digest: str


@dataclass(frozen=True)
class VerifiedExecutionArtifact:
    """Fresh in-memory seals reconstructed from one strict serialized bundle."""

    run_pair: SealedRunPair
    run_pair_digest: str
    bundle_digest: str
    criterion_id: str
    evaluator: str
    evaluator_dataset_freeze_digest: str


@dataclass(frozen=True)
class VerifiedPhaseExecutionArtifact:
    """Fresh phase-only seal reconstructed from one strict phase bundle."""

    run_pair: SealedPhaseRunPair
    run_pair_digest: str
    bundle_digest: str
    criterion_id: str
    evaluator: str
    evaluator_dataset_freeze_digest: str


def _fail(code: str, path: str, message: str) -> None:
    raise ExecutionArtifactError(code, path, message)


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _exact(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("invalid_artifact_schema", path, "field set mismatch")
    return value


def canonical_toolchain_manifest(tool_facts: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return the only toolchain projection bound by a freeze."""

    document = deepcopy(dict(tool_facts))
    _exact(document, TOOL_FIELDS, "toolFacts")
    if document["schemaVersion"] != TOOL_SCHEMA or document["unshareArguments"] != [
        "--user",
        "--map-root-user",
        "--net",
        "--",
    ]:
        _fail("invalid_tool_facts", "toolFacts", "fixed tool schema drift")
    for field in ("gitDigest", "pythonDigest", "unshareDigest"):
        _sha(document[field], f"toolFacts.{field}")
    return document


def toolchain_digest(tool_facts: Mapping[str, Any]) -> str:
    """Digest the exact public toolchain manifest used by runner and importer."""

    return canonical_digest(canonical_toolchain_manifest(tool_facts))


def _strict_load(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_BUNDLE_BYTES:
        _fail("invalid_artifact_bytes", "bundle", "bounded bytes are required")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_key", "bundle", key)
            result[key] = value
        return result

    def constant(value: str) -> None:
        _fail("noncanonical_json", "bundle", f"non-finite number {value}")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("invalid_artifact_json", "bundle", str(exc))
    if not isinstance(value, dict):
        _fail("invalid_artifact_schema", "bundle", "object required")
    if canonical_json_bytes(value) != raw:
        _fail("noncanonical_json", "bundle", "canonical JSON bytes required")
    return value


def _verified_freeze(value: Any) -> VerifiedProtectedInputFreeze:
    try:
        _require_verified(value, VerifiedProtectedInputFreeze, "freeze")
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    assert isinstance(value, VerifiedProtectedInputFreeze)
    return value


def _verified_phase_freeze(value: Any) -> VerifiedPhaseProtectedInputFreeze:
    try:
        _require_verified(value, VerifiedPhaseProtectedInputFreeze, "phaseFreeze")
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    assert isinstance(value, VerifiedPhaseProtectedInputFreeze)
    return value


def _criterion(
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
) -> CriterionBinding:
    matches = [item for item in freeze.criteria if item.criterion_id == criterion_id]
    if len(matches) != 1:
        _fail("unknown_criterion", "criterionId", str(criterion_id))
    criterion = matches[0]
    if criterion.kind != "MACHINE":
        _fail("invalid_criterion_kind", "criterionId", "MACHINE required")
    if EVALUATOR_CRITERION_IDS.get(criterion.evaluator) != criterion.criterion_id:
        _fail("unknown_evaluator", "criterion.evaluator", criterion.evaluator)
    return criterion


def _reject_sensitive(raw: bytes, path: str, *, limit: int) -> None:
    if len(raw) > limit or len(raw) > MAX_STREAM_BYTES:
        _fail("output_limit_exceeded", path, "raw output exceeds its sealed bound")
    scanned = raw
    for identifier in PUBLIC_CANARY_IDENTIFIERS:
        scanned = scanned.replace(identifier, b"public-redaction-evaluator")
    if (
        SYNTHETIC_SECRET_CANARY in raw
        or CANARY_RE.search(scanned) is not None
        or HOST_PATH_RE.search(raw) is not None
    ):
        _fail(
            "sensitive_output_rejected",
            path,
            "synthetic canary or host path is forbidden in portable artifacts",
        )


def _output_document(raw: bytes, path: str, *, limit: int) -> dict[str, Any]:
    _reject_sensitive(raw, path, limit=limit)
    return {
        "schemaVersion": OUTPUT_SCHEMA,
        "encoding": "base64-standard",
        "data": base64.b64encode(raw).decode("ascii"),
        "byteLength": len(raw),
        "digest": sha256_bytes(raw),
        "complete": True,
        "redactionPolicy": REDACTION_POLICY,
    }


def _decode_output(value: Any, path: str, *, limit: int) -> bytes:
    document = _exact(value, OUTPUT_FIELDS, path)
    if (
        document["schemaVersion"] != OUTPUT_SCHEMA
        or document["encoding"] != "base64-standard"
        or document["complete"] is not True
        or document["redactionPolicy"] != REDACTION_POLICY
    ):
        _fail("invalid_raw_output", path, "output metadata mismatch")
    encoded = document["data"]
    if not isinstance(encoded, str):
        _fail("invalid_raw_output", f"{path}.data", "base64 string required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        _fail("invalid_raw_output", f"{path}.data", str(exc))
    if base64.b64encode(raw).decode("ascii") != encoded:
        _fail("noncanonical_base64", f"{path}.data", "canonical base64 required")
    if document["byteLength"] != len(raw) or document["digest"] != sha256_bytes(raw):
        _fail("raw_output_digest_mismatch", path, "length or digest mismatch")
    _reject_sensitive(raw, path, limit=limit)
    return raw


def _strict_json_output(raw: bytes, path: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_key", path, key)
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("invalid_raw_evaluator_output", path, str(exc))


def _bootstrap_semantics(
    evaluator: str, *, exit_code: int, stdout: bytes, stderr: bytes
) -> tuple[str, str, dict[str, Any]]:
    if evaluator == "evaluator://bootstrap/control-plane/v1":
        try:
            value = _strict_json_output(stdout, "stdout")
        except ExecutionArtifactError:
            value = None
        if not isinstance(value, dict):
            return (
                "candidate-semantically-valid",
                "FAIL",
                {"reasonCode": "invalid_control_plane_result"},
            )
        facts = {
            "schemaVersion": value.get("schemaVersion"),
            "status": value.get("status"),
            "reasonCode": value.get("reasonCode"),
            "controlPlaneDigest": value.get("controlPlaneDigest"),
            "componentCount": value.get("componentCount"),
        }
        passed = (
            exit_code == 0
            and facts["schemaVersion"] == "urn:agentapi-doctor:phasegate-result:v1"
            and facts["status"] == "pass"
            and facts["reasonCode"] == "candidate_valid"
            and isinstance(facts["controlPlaneDigest"], str)
            and SHA256_RE.fullmatch(facts["controlPlaneDigest"]) is not None
            and isinstance(facts["componentCount"], int)
            and not isinstance(facts["componentCount"], bool)
            and facts["componentCount"] > 0
        )
        return "candidate-semantically-valid", "PASS" if passed else "FAIL", facts
    combined = stdout + b"\n" + stderr
    match = UNITTEST_COUNT_RE.search(combined)
    count = int(match.group(1)) if match else 0
    passed = (
        exit_code == 0 and count > 0 and UNITTEST_OK_RE.search(combined) is not None
    )
    return (
        BOOTSTRAP_ASSERTIONS[evaluator],
        "PASS" if passed else "FAIL",
        {
            "reasonCode": (
                "anti_placeholder_suite_passed"
                if passed
                else "anti_placeholder_suite_failed"
            ),
            "testCount": count,
        },
    )


def _derived_evidence(
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion: CriterionBinding,
    evaluator_input: Mapping[str, Any] | None,
    stdout: bytes,
    stderr: bytes,
    exit_code: int,
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    evaluator = criterion.evaluator
    if evaluator in BOOTSTRAP_EVALUATORS:
        if evaluator_input is not None:
            _fail("unexpected_evaluator_input", "evaluatorInput", evaluator)
        assertion_id, status, facts = _bootstrap_semantics(
            evaluator, exit_code=exit_code, stdout=stdout, stderr=stderr
        )
        evidence_digest = canonical_digest(
            {
                "schemaVersion": ASSERTION_SCHEMA,
                "evaluator": evaluator,
                "assertionId": assertion_id,
                "status": status,
                "facts": facts,
            }
        )
        return None, [
            {"id": assertion_id, "status": status, "evidenceDigest": evidence_digest}
        ]
    if evaluator_input is None:
        _fail("missing_evaluator_input", "evaluatorInput", evaluator)
    try:
        recomputed = evaluate_strict(evaluator, evaluator_input)
    except EvaluationError as exc:
        _fail(exc.code, f"evaluatorInput.{exc.path}", exc.message)
    envelope = _strict_json_output(stdout, "stdout")
    expected = {
        "schemaVersion": ISOLATED_EVALUATOR_SCHEMA,
        "evaluator": evaluator,
        "evidence": recomputed,
    }
    if exit_code != 0 or envelope != expected:
        _fail(
            "isolated_evaluator_evidence_mismatch",
            "stdout",
            "raw evaluator output differs from independent recomputation",
        )
    assertion_digest = canonical_digest(
        {
            "schemaVersion": ASSERTION_SCHEMA,
            "evaluator": evaluator,
            "assertionId": "protected-evaluator-executed",
            "evidenceDigest": recomputed["evidenceDigest"],
        }
    )
    return recomputed, [
        {
            "id": "protected-evaluator-executed",
            "status": "PASS",
            "evidenceDigest": assertion_digest,
        }
    ]


def _environment_digest(
    *, label: str, environment: Mapping[str, Any], tools: Mapping[str, Any]
) -> str:
    return canonical_digest(
        {
            "schemaVersion": "urn:agentapi-doctor:protected-run-environment:v1",
            "label": label,
            "isolation": {
                "distinctTemporaryCheckout": True,
                "temporaryHome": environment["temporaryHome"],
                "minimalEnvironment": environment["minimalEnvironment"],
                "networkCredentialsInherited": environment[
                    "networkCredentialsInherited"
                ],
                "networkNamespace": environment["networkNamespace"],
                "networkNamespaceFailClosed": environment["networkNamespaceFailClosed"],
                "shell": environment["shell"],
            },
            "gitDigest": tools["gitDigest"],
            "pythonDigest": tools["pythonDigest"],
            "unshareDigest": tools["unshareDigest"],
            "unshareArguments": tools["unshareArguments"],
            "outputLimitBytes": environment["outputLimitBytes"],
        }
    )


def _manifest_digest(
    *, label: str, evaluator: str, log_digest: str, output_bytes: int, exit_code: int
) -> str:
    return canonical_digest(
        {
            "schemaVersion": MANIFEST_SCHEMA,
            "label": label,
            "evaluator": evaluator,
            "logDigest": log_digest,
            "capturedOutputBytes": output_bytes,
            "exitCode": exit_code,
            "outputComplete": True,
        }
    )


def _build_run_document(
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion: CriterionBinding,
    evaluator_input: Mapping[str, Any] | None,
    captured: CapturedRunArtifact,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    label = captured.label
    if label not in {"A", "B"}:
        _fail("invalid_run_label", "runs.label", str(label))
    command = deepcopy(dict(captured.command_result))
    required_command_fields = {
        "exitCode",
        "durationMs",
        "startedAt",
        "finishedAt",
        "environmentDigest",
        "logDigest",
        "artifactManifestDigest",
        "sourceDirtyBeforeRun",
        "cleanCheckout",
        "semanticAssertions",
    }
    _exact(command, required_command_fields, f"run{label}.commandResult")
    output_limit = captured.output_limit_bytes
    if (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or output_limit <= 0
        or output_limit > MAX_STREAM_BYTES
        or len(captured.stdout) + len(captured.stderr) > output_limit
    ):
        _fail("output_limit_exceeded", f"run{label}", "invalid output bound")
    stdout_document = _output_document(
        captured.stdout, f"run{label}.stdout", limit=output_limit
    )
    stderr_document = _output_document(
        captured.stderr, f"run{label}.stderr", limit=output_limit
    )
    derived_evidence, assertions = _derived_evidence(
        freeze=freeze,
        criterion=criterion,
        evaluator_input=evaluator_input,
        stdout=captured.stdout,
        stderr=captured.stderr,
        exit_code=command["exitCode"],
    )
    if captured.evaluator_evidence is None:
        declared_evidence = None
    else:
        declared_evidence = deepcopy(dict(captured.evaluator_evidence))
    if declared_evidence != derived_evidence:
        _fail(
            "evaluator_evidence_mismatch",
            f"run{label}.evaluatorEvidence",
            "declared evidence differs from raw-output recomputation",
        )
    if command["semanticAssertions"] != assertions:
        _fail(
            "semantic_assertion_mismatch",
            f"run{label}.semanticAssertions",
            "declared assertion differs from raw-output recomputation",
        )
    tools = {
        "schemaVersion": TOOL_SCHEMA,
        "gitDigest": _sha(captured.git_digest, f"run{label}.tools.gitDigest"),
        "pythonDigest": _sha(captured.python_digest, f"run{label}.tools.pythonDigest"),
        "unshareDigest": _sha(
            captured.unshare_digest, f"run{label}.tools.unshareDigest"
        ),
        "unshareArguments": ["--user", "--map-root-user", "--net", "--"],
    }
    environment = {
        "schemaVersion": ENVIRONMENT_SCHEMA,
        "environmentClass": (
            "development-isolated" if label == "A" else "clean-checkout-offline"
        ),
        "minimalEnvironment": True,
        "temporaryHome": True,
        "networkCredentialsInherited": False,
        "networkNamespace": "linux-user-net-unshare",
        "networkNamespaceFailClosed": True,
        "shell": False,
        "outputLimitBytes": output_limit,
    }
    expected_environment_digest = _environment_digest(
        label=label, environment=environment, tools=tools
    )
    if command["environmentDigest"] != expected_environment_digest:
        _fail(
            "environment_digest_mismatch",
            f"run{label}.environmentDigest",
            "environment facts differ from command observation",
        )
    log_digest = sha256_bytes(captured.stdout + b"\x00stderr\x00" + captured.stderr)
    if command["logDigest"] != log_digest:
        _fail("log_digest_mismatch", f"run{label}.logDigest", "raw log drift")
    manifest_digest = _manifest_digest(
        label=label,
        evaluator=criterion.evaluator,
        log_digest=log_digest,
        output_bytes=len(captured.stdout) + len(captured.stderr),
        exit_code=command["exitCode"],
    )
    if command["artifactManifestDigest"] != manifest_digest:
        _fail(
            "artifact_manifest_digest_mismatch",
            f"run{label}.artifactManifestDigest",
            "raw artifact manifest drift",
        )
    document = {
        "schemaVersion": RUN_SCHEMA,
        "label": label,
        "evaluator": criterion.evaluator,
        "commandDigest": sha256_bytes(FIXED_COMMANDS[criterion.evaluator].encode()),
        "checkoutIdentity": {
            "sourceCommit": freeze.subject.source_commit,
            "headVerified": True,
            "sourceDirtyBeforeRun": False,
            "freshIsolatedClone": True,
            "cleanCheckout": label == "B",
        },
        "execution": {
            "exitCode": command["exitCode"],
            "durationMs": command["durationMs"],
            "startedAt": command["startedAt"],
            "finishedAt": command["finishedAt"],
            "timedOut": False,
            "outputTruncated": False,
        },
        "environmentFacts": environment,
        "toolFacts": tools,
        "stdout": stdout_document,
        "stderr": stderr_document,
        "evaluatorEvidence": derived_evidence,
        "semanticAssertions": assertions,
        "logDigest": log_digest,
        "artifactManifestDigest": manifest_digest,
        "producerObservedDestruction": {
            "kind": "producer-observed-filesystem-absence",
            "checkoutAbsent": True,
            "homeAbsent": True,
            "temporaryAbsent": True,
            "observedBeforeNextRun": label == "A",
            "requiresProtectedOidcBinding": True,
        },
    }
    document["artifactDigest"] = document_digest(document)
    return document, command, derived_evidence


def _serialize_execution_artifact_bundle(
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedRunPair | SealedPhaseRunPair,
    captured_runs: Sequence[CapturedRunArtifact],
    evaluator_input: Mapping[str, Any] | None = None,
    phase: bool,
) -> bytes:
    """Serialize one exact scope-specific seal into portable canonical bytes."""

    verified_freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze
    verified_freeze = (
        _verified_phase_freeze(freeze) if phase else _verified_freeze(freeze)
    )
    criterion = _criterion(verified_freeze, criterion_id)
    if len(captured_runs) != 2 or [item.label for item in captured_runs] != ["A", "B"]:
        _fail("invalid_run_pair", "capturedRuns", "ordered A/B runs required")
    try:
        if phase:
            assert isinstance(verified_freeze, VerifiedPhaseProtectedInputFreeze)
            projection = phase_criterion_result_projection(
                freeze=verified_freeze,
                criterion_id=criterion_id,
                run_pair=run_pair,
            )
        else:
            assert isinstance(verified_freeze, VerifiedProtectedInputFreeze)
            projection = criterion_result_projection(
                freeze=verified_freeze,
                criterion_id=criterion_id,
                run_pair=run_pair,
            )
    except GateRunnerError as exc:
        _fail(exc.code, exc.path, exc.message)
    runs = [
        _build_run_document(
            freeze=verified_freeze,
            criterion=criterion,
            evaluator_input=evaluator_input,
            captured=item,
        )[0]
        for item in captured_runs
    ]
    if runs[0]["toolFacts"] != runs[1]["toolFacts"]:
        _fail("toolchain_mismatch", "runs", "Run A/B tool facts differ")
    expected_toolchain = dict(verified_freeze.protected_inputs).get("toolchainDigest")
    if toolchain_digest(runs[0]["toolFacts"]) != expected_toolchain:
        _fail(
            "toolchain_freeze_mismatch",
            "toolFacts",
            "observed A/B toolchain differs from the sealed protected input",
        )
    if evaluator_input is not None:
        encoded_input = canonical_json_bytes(evaluator_input)
        _reject_sensitive(encoded_input, "evaluatorInput", limit=MAX_STREAM_BYTES)
        serialized_input: Any = json.loads(encoded_input)
    else:
        serialized_input = None
    body: dict[str, Any] = {
        "schemaVersion": PHASE_BUNDLE_SCHEMA if phase else BUNDLE_SCHEMA,
        "freezeDigest": verified_freeze.attestation_digest,
        "criterionId": criterion_id,
        "evaluator": criterion.evaluator,
        "sourceCommit": verified_freeze.subject.source_commit,
        "controlPlaneDigest": verified_freeze.subject.control_plane_digest,
        "evaluatorInput": serialized_input,
        "runs": runs,
        "runPair": deepcopy(dict(run_pair)),
        "runPairDigest": projection["runPairDigest"],
    }
    if phase:
        assert isinstance(verified_freeze, VerifiedPhaseProtectedInputFreeze)
        body["aggregateContractDigest"] = (
            verified_freeze.subject.aggregate_contract_digest
        )
    else:
        assert isinstance(verified_freeze, VerifiedProtectedInputFreeze)
        body["contractDigest"] = verified_freeze.subject.contract_digest
    body["bundleDigest"] = document_digest(body)
    raw = canonical_json_bytes(body)
    if len(raw) > MAX_BUNDLE_BYTES:
        _fail("artifact_bundle_too_large", "bundle", "serialized bundle is too large")
    # Producer and importer deliberately share only the strict byte contract.
    verified = (
        verify_phase_execution_artifact_bundle(
            raw,
            freeze=verified_freeze,
            expected_criterion_id=criterion_id,
        )
        if phase
        else verify_execution_artifact_bundle(
            raw,
            freeze=verified_freeze,
            expected_criterion_id=criterion_id,
        )
    )
    if verified.run_pair_digest != projection["runPairDigest"]:
        _fail("run_pair_digest_mismatch", "runPair", "self-verification drift")
    return raw


def serialize_execution_artifact_bundle(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedRunPair,
    captured_runs: Sequence[CapturedRunArtifact],
    evaluator_input: Mapping[str, Any] | None = None,
) -> bytes:
    """Serialize exact work-unit execution into canonical portable bytes."""

    return _serialize_execution_artifact_bundle(
        freeze=freeze,
        criterion_id=criterion_id,
        run_pair=run_pair,
        captured_runs=captured_runs,
        evaluator_input=evaluator_input,
        phase=False,
    )


def serialize_phase_execution_artifact_bundle(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedPhaseRunPair,
    captured_runs: Sequence[CapturedRunArtifact],
    evaluator_input: Mapping[str, Any] | None = None,
) -> bytes:
    """Serialize an aggregate pair under a phase-only schema and seal."""

    return _serialize_execution_artifact_bundle(
        freeze=freeze,
        criterion_id=criterion_id,
        run_pair=run_pair,
        captured_runs=captured_runs,
        evaluator_input=evaluator_input,
        phase=True,
    )


def _verify_execution_artifact_bundle(
    raw: bytes,
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    expected_criterion_id: str,
    phase: bool,
) -> VerifiedExecutionArtifact | VerifiedPhaseExecutionArtifact:
    """Recompute a fresh scope-specific RunPair from strict raw evidence."""

    verified_freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze
    verified_freeze = (
        _verified_phase_freeze(freeze) if phase else _verified_freeze(freeze)
    )
    criterion = _criterion(verified_freeze, expected_criterion_id)
    body = _exact(
        _strict_load(raw), PHASE_BUNDLE_FIELDS if phase else BUNDLE_FIELDS, "bundle"
    )
    expected_schema = PHASE_BUNDLE_SCHEMA if phase else BUNDLE_SCHEMA
    if body["schemaVersion"] != expected_schema:
        _fail(
            "unsupported_artifact_schema", "schemaVersion", str(body["schemaVersion"])
        )
    expected_bindings: dict[str, Any] = {
        "freezeDigest": verified_freeze.attestation_digest,
        "criterionId": expected_criterion_id,
        "evaluator": criterion.evaluator,
        "sourceCommit": verified_freeze.subject.source_commit,
        "controlPlaneDigest": verified_freeze.subject.control_plane_digest,
    }
    if phase:
        assert isinstance(verified_freeze, VerifiedPhaseProtectedInputFreeze)
        expected_bindings["aggregateContractDigest"] = (
            verified_freeze.subject.aggregate_contract_digest
        )
    else:
        assert isinstance(verified_freeze, VerifiedProtectedInputFreeze)
        expected_bindings["contractDigest"] = verified_freeze.subject.contract_digest
    for field, expected in expected_bindings.items():
        if body[field] != expected:
            _fail("artifact_binding_mismatch", field, "trusted binding differs")
    declared_bundle_digest = _sha(body["bundleDigest"], "bundleDigest")
    if document_digest(body, omit_field="bundleDigest") != declared_bundle_digest:
        _fail("bundle_digest_mismatch", "bundleDigest", "bundle tamper detected")
    evaluator_input = body["evaluatorInput"]
    if evaluator_input is not None and not isinstance(evaluator_input, dict):
        _fail("invalid_evaluator_input", "evaluatorInput", "object or null required")
    if evaluator_input is not None:
        _reject_sensitive(
            canonical_json_bytes(evaluator_input),
            "evaluatorInput",
            limit=MAX_STREAM_BYTES,
        )
        evaluator_dataset_freeze_digest = _sha(
            evaluator_input.get("datasetFreezeDigest"),
            "evaluatorInput.datasetFreezeDigest",
        )
    else:
        evaluator_dataset_freeze_digest = verified_freeze.attestation_digest
    raw_runs = body["runs"]
    if not isinstance(raw_runs, list) or len(raw_runs) != 2:
        _fail("invalid_run_pair", "runs", "exactly two runs required")
    sealed_runs = []
    rebuilt_runs = []
    for index, expected_label in enumerate(("A", "B")):
        path = f"runs[{index}]"
        run = _exact(raw_runs[index], RUN_FIELDS, path)
        if run["schemaVersion"] != RUN_SCHEMA or run["label"] != expected_label:
            _fail("invalid_run_pair", path, "ordered A/B labels required")
        execution = _exact(run["execution"], EXECUTION_FIELDS, f"{path}.execution")
        checkout = _exact(
            run["checkoutIdentity"], CHECKOUT_FIELDS, f"{path}.checkoutIdentity"
        )
        environment = _exact(
            run["environmentFacts"], ENVIRONMENT_FIELDS, f"{path}.environmentFacts"
        )
        tools = _exact(run["toolFacts"], TOOL_FIELDS, f"{path}.toolFacts")
        destruction = _exact(
            run["producerObservedDestruction"],
            DESTRUCTION_FIELDS,
            f"{path}.producerObservedDestruction",
        )
        expected_checkout = {
            "sourceCommit": verified_freeze.subject.source_commit,
            "headVerified": True,
            "sourceDirtyBeforeRun": False,
            "freshIsolatedClone": True,
            "cleanCheckout": expected_label == "B",
        }
        if checkout != expected_checkout:
            _fail("checkout_identity_mismatch", f"{path}.checkoutIdentity", "drift")
        expected_destruction = {
            "kind": "producer-observed-filesystem-absence",
            "checkoutAbsent": True,
            "homeAbsent": True,
            "temporaryAbsent": True,
            "observedBeforeNextRun": expected_label == "A",
            "requiresProtectedOidcBinding": True,
        }
        if destruction != expected_destruction:
            _fail(
                "producer_observation_mismatch",
                f"{path}.producerObservedDestruction",
                "producer-observed fact drift",
            )
        if (
            execution["timedOut"] is not False
            or execution["outputTruncated"] is not False
        ):
            _fail("incomplete_execution", f"{path}.execution", "complete run required")
        if environment["schemaVersion"] != ENVIRONMENT_SCHEMA:
            _fail("invalid_environment_facts", f"{path}.environmentFacts", "schema")
        expected_environment = {
            "schemaVersion": ENVIRONMENT_SCHEMA,
            "environmentClass": (
                "development-isolated"
                if expected_label == "A"
                else "clean-checkout-offline"
            ),
            "minimalEnvironment": True,
            "temporaryHome": True,
            "networkCredentialsInherited": False,
            "networkNamespace": "linux-user-net-unshare",
            "networkNamespaceFailClosed": True,
            "shell": False,
            "outputLimitBytes": environment["outputLimitBytes"],
        }
        if environment != expected_environment:
            _fail("invalid_environment_facts", f"{path}.environmentFacts", "drift")
        if tools["schemaVersion"] != TOOL_SCHEMA or tools["unshareArguments"] != [
            "--user",
            "--map-root-user",
            "--net",
            "--",
        ]:
            _fail("invalid_tool_facts", f"{path}.toolFacts", "drift")
        for field in ("gitDigest", "pythonDigest", "unshareDigest"):
            _sha(tools[field], f"{path}.toolFacts.{field}")
        limit = environment["outputLimitBytes"]
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 0 < limit <= MAX_STREAM_BYTES
        ):
            _fail("invalid_output_limit", f"{path}.environmentFacts", "invalid bound")
        stdout = _decode_output(run["stdout"], f"{path}.stdout", limit=limit)
        stderr = _decode_output(run["stderr"], f"{path}.stderr", limit=limit)
        if len(stdout) + len(stderr) > limit:
            _fail("output_limit_exceeded", path, "combined output exceeds bound")
        command_result = {
            "exitCode": execution["exitCode"],
            "durationMs": execution["durationMs"],
            "startedAt": execution["startedAt"],
            "finishedAt": execution["finishedAt"],
            "environmentDigest": _environment_digest(
                label=expected_label, environment=environment, tools=tools
            ),
            "logDigest": sha256_bytes(stdout + b"\x00stderr\x00" + stderr),
            "artifactManifestDigest": _manifest_digest(
                label=expected_label,
                evaluator=criterion.evaluator,
                log_digest=sha256_bytes(stdout + b"\x00stderr\x00" + stderr),
                output_bytes=len(stdout) + len(stderr),
                exit_code=execution["exitCode"],
            ),
            "sourceDirtyBeforeRun": False,
            "cleanCheckout": expected_label == "B",
            "semanticAssertions": run["semanticAssertions"],
        }
        derived_evidence, derived_assertions = _derived_evidence(
            freeze=verified_freeze,
            criterion=criterion,
            evaluator_input=evaluator_input,
            stdout=stdout,
            stderr=stderr,
            exit_code=execution["exitCode"],
        )
        if run["evaluatorEvidence"] != derived_evidence:
            _fail("evaluator_evidence_mismatch", f"{path}.evaluatorEvidence", "drift")
        if run["semanticAssertions"] != derived_assertions:
            _fail("semantic_assertion_mismatch", f"{path}.semanticAssertions", "drift")
        if run["evaluator"] != criterion.evaluator:
            _fail("artifact_binding_mismatch", f"{path}.evaluator", "drift")
        if run["commandDigest"] != sha256_bytes(
            FIXED_COMMANDS[criterion.evaluator].encode()
        ):
            _fail("command_digest_mismatch", f"{path}.commandDigest", "drift")
        if run["logDigest"] != command_result["logDigest"]:
            _fail("log_digest_mismatch", f"{path}.logDigest", "drift")
        if run["artifactManifestDigest"] != command_result["artifactManifestDigest"]:
            _fail("artifact_manifest_digest_mismatch", path, "drift")
        if run["artifactDigest"] != document_digest(run, omit_field="artifactDigest"):
            _fail("artifact_digest_mismatch", f"{path}.artifactDigest", "drift")
        captured = CapturedRunArtifact(
            label=expected_label,
            stdout=stdout,
            stderr=stderr,
            command_result=command_result,
            evaluator_evidence=derived_evidence,
            output_limit_bytes=limit,
            git_digest=tools["gitDigest"],
            python_digest=tools["pythonDigest"],
            unshare_digest=tools["unshareDigest"],
        )
        rebuilt, command_result, derived_evidence = _build_run_document(
            freeze=verified_freeze,
            criterion=criterion,
            evaluator_input=evaluator_input,
            captured=captured,
        )
        if rebuilt != run:
            _fail("artifact_recompute_mismatch", path, "raw artifact drift")
        try:
            if phase:
                assert isinstance(verified_freeze, VerifiedPhaseProtectedInputFreeze)
                sealed_run = record_phase_run(
                    freeze=verified_freeze,
                    criterion_id=expected_criterion_id,
                    label=expected_label,
                    command_result=command_result,
                    evaluator_input=evaluator_input,
                    evaluator_evidence=derived_evidence,
                )
            else:
                assert isinstance(verified_freeze, VerifiedProtectedInputFreeze)
                sealed_run = record_run(
                    freeze=verified_freeze,
                    criterion_id=expected_criterion_id,
                    label=expected_label,
                    command_result=command_result,
                    evaluator_input=evaluator_input,
                    evaluator_evidence=derived_evidence,
                )
            sealed_runs.append(sealed_run)
        except GateRunnerError as exc:
            _fail(exc.code, exc.path, exc.message)
        rebuilt_runs.append(rebuilt)
    if rebuilt_runs[0]["toolFacts"] != rebuilt_runs[1]["toolFacts"]:
        _fail("toolchain_mismatch", "runs", "Run A/B tool facts differ")
    expected_toolchain = dict(verified_freeze.protected_inputs).get("toolchainDigest")
    if toolchain_digest(rebuilt_runs[0]["toolFacts"]) != expected_toolchain:
        _fail(
            "toolchain_freeze_mismatch",
            "toolFacts",
            "observed A/B toolchain differs from the sealed protected input",
        )
    try:
        if phase:
            assert isinstance(verified_freeze, VerifiedPhaseProtectedInputFreeze)
            pair = combine_phase_runs(
                freeze=verified_freeze,
                criterion_id=expected_criterion_id,
                run_a=sealed_runs[0],
                run_b=sealed_runs[1],
            )
        else:
            assert isinstance(verified_freeze, VerifiedProtectedInputFreeze)
            pair = combine_runs(
                freeze=verified_freeze,
                criterion_id=expected_criterion_id,
                run_a=sealed_runs[0],
                run_b=sealed_runs[1],
            )
    except GateRunnerError as exc:
        _fail(exc.code, exc.path, exc.message)
    if body["runs"] != rebuilt_runs:
        _fail("artifact_recompute_mismatch", "runs", "drift")
    if body["runPair"] != dict(pair):
        _fail(
            "run_pair_recompute_mismatch", "runPair", "serialized verdict is untrusted"
        )
    pair_digest = document_digest(pair)
    if body["runPairDigest"] != pair_digest:
        _fail("run_pair_digest_mismatch", "runPairDigest", "drift")
    artifact_fields = {
        "run_pair": pair,
        "run_pair_digest": pair_digest,
        "bundle_digest": declared_bundle_digest,
        "criterion_id": expected_criterion_id,
        "evaluator": criterion.evaluator,
        "evaluator_dataset_freeze_digest": evaluator_dataset_freeze_digest,
    }
    if phase:
        assert isinstance(pair, SealedPhaseRunPair)
        return VerifiedPhaseExecutionArtifact(**artifact_fields)
    assert isinstance(pair, SealedRunPair) and not isinstance(pair, SealedPhaseRunPair)
    return VerifiedExecutionArtifact(**artifact_fields)


def verify_execution_artifact_bundle(
    raw: bytes,
    *,
    freeze: VerifiedProtectedInputFreeze,
    expected_criterion_id: str,
) -> VerifiedExecutionArtifact:
    """Recompute a fresh work-unit RunPair from strict serialized evidence."""

    result = _verify_execution_artifact_bundle(
        raw,
        freeze=freeze,
        expected_criterion_id=expected_criterion_id,
        phase=False,
    )
    assert isinstance(result, VerifiedExecutionArtifact)
    return result


def verify_phase_execution_artifact_bundle(
    raw: bytes,
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    expected_criterion_id: str,
) -> VerifiedPhaseExecutionArtifact:
    """Recompute a fresh phase-only RunPair from strict serialized evidence."""

    result = _verify_execution_artifact_bundle(
        raw,
        freeze=freeze,
        expected_criterion_id=expected_criterion_id,
        phase=True,
    )
    assert isinstance(result, VerifiedPhaseExecutionArtifact)
    return result


__all__ = [
    "BUNDLE_SCHEMA",
    "PHASE_BUNDLE_SCHEMA",
    "CapturedRunArtifact",
    "ExecutionArtifactError",
    "SYNTHETIC_SECRET_CANARY",
    "VerifiedExecutionArtifact",
    "VerifiedPhaseExecutionArtifact",
    "canonical_toolchain_manifest",
    "serialize_execution_artifact_bundle",
    "serialize_phase_execution_artifact_bundle",
    "toolchain_digest",
    "verify_execution_artifact_bundle",
    "verify_phase_execution_artifact_bundle",
]
