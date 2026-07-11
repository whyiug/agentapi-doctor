"""Pure in-memory bridge from verified P00 inputs to MACHINE Run A/B evidence.

The module deliberately does not execute commands, access the filesystem, or
use the network.  A protected outer workflow supplies an already observed
command result.  This bridge validates that observation, recomputes evaluator
evidence, binds it to an internally sealed protected-input freeze, and emits
the exact ``runPair`` shape consumed by :mod:`tools.phasegate.provenance`.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime
import json
import re
from typing import Any, Mapping
import weakref

from .p00_evaluators import (
    EVALUATORS,
    EVALUATOR_CRITERIA,
    EvaluationError,
    canonical_digest,
    evaluate_strict,
)
from .protected import ProtectedVerificationError, document_digest
from .provenance import (
    CriterionBinding,
    VerifiedPhaseProtectedInputFreeze,
    VerifiedProtectedInputFreeze,
    _require_verified,
    _validate_run_pair,
)


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

BOOTSTRAP_EVALUATORS = {
    "evaluator://bootstrap/control-plane/v1": "P00-M-BOOTSTRAP-CONTROL",
    "evaluator://bootstrap/anti-placeholder/v1": "P00-M-ANTI-PLACEHOLDER",
}
BOOTSTRAP_ASSERTIONS = {
    "evaluator://bootstrap/control-plane/v1": "candidate-semantically-valid",
    "evaluator://bootstrap/anti-placeholder/v1": "anti-placeholder-suite-passed",
}
FIXED_COMMANDS = {
    "evaluator://bootstrap/control-plane/v1": (
        "python3 tools/phasegate/main.py bootstrap --root ."
    ),
    "evaluator://bootstrap/anti-placeholder/v1": (
        "python3 -m unittest discover -s test/bootstrap -p 'test_phasegate.py'"
    ),
    **{
        evaluator: f"builtin tools.phasegate.p00_evaluators.evaluate_strict {evaluator}"
        for evaluator in EVALUATORS
    },
}
EVALUATOR_CRITERION_IDS = {**BOOTSTRAP_EVALUATORS, **EVALUATOR_CRITERIA}

PROTECTED_INPUT_FIELDS = {
    "planDigest",
    "supportLockDigest",
    "toolchainDigest",
    "dependencySetDigest",
    "gateRunnerDigest",
    "evaluatorSetDigest",
    "metricDefinitionsDigest",
    "protectedAcceptanceDigest",
}
COMMAND_RESULT_FIELDS = {
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
ASSERTION_FIELDS = {"id", "status", "evidenceDigest"}


@dataclass
class GateRunnerError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class SemanticAssertion:
    assertion_id: str
    status: str
    evidence_digest: str

    def as_document(self) -> dict[str, str]:
        return {
            "id": self.assertion_id,
            "status": self.status,
            "evidenceDigest": self.evidence_digest,
        }


@dataclass(frozen=True)
class CommandObservation:
    command: str
    exit_code: int
    duration_ms: int
    started_at: str
    finished_at: str
    log_digest: str
    artifact_manifest_digest: str
    assertions: tuple[SemanticAssertion, ...]

    def as_document(self) -> dict[str, Any]:
        summary = {
            "passed": sum(item.status == "PASS" for item in self.assertions),
            "failed": sum(item.status == "FAIL" for item in self.assertions),
            "skipped": sum(item.status == "SKIP" for item in self.assertions),
        }
        return {
            "command": self.command,
            "exitCode": self.exit_code,
            "durationMs": self.duration_ms,
            "summary": summary,
            "logDigest": self.log_digest,
            "artifactManifestDigest": self.artifact_manifest_digest,
        }


@dataclass(frozen=True)
class RunResult:
    """One sealed, recomputed environment-specific MACHINE run."""

    label: str
    environment_class: str
    environment_digest: str
    source_commit: str
    control_plane_digest: str
    contract_digest: str
    protected_inputs: tuple[tuple[str, str], ...]
    evaluator: str
    evaluator_digest: str
    dataset_digest: str
    criterion_id: str
    source_dirty_before_run: bool
    clean_checkout: bool
    command: CommandObservation
    evaluator_input_digest: str
    evaluator_evidence_digest: str
    deterministic_result_set_digest: str
    outcome: str
    run_evidence_digest: str
    freeze_digest: str
    _freeze_identity: int
    _seal_digest: str

    def as_document(self) -> dict[str, Any]:
        inputs = dict(self.protected_inputs)
        return {
            "label": self.label,
            "environmentClass": self.environment_class,
            "environmentDigest": self.environment_digest,
            "sourceCommit": self.source_commit,
            "controlPlaneDigest": self.control_plane_digest,
            "contractDigest": self.contract_digest,
            "planDigest": inputs["planDigest"],
            "supportLockDigest": inputs["supportLockDigest"],
            "dependencySetDigest": inputs["dependencySetDigest"],
            "toolchainDigest": inputs["toolchainDigest"],
            "gateRunnerDigest": inputs["gateRunnerDigest"],
            "evaluatorSetDigest": inputs["evaluatorSetDigest"],
            "metricDefinitionsDigest": inputs["metricDefinitionsDigest"],
            "protectedAcceptanceDigest": inputs["protectedAcceptanceDigest"],
            "evaluatorDigest": self.evaluator_digest,
            "datasetDigest": self.dataset_digest,
            "sourceDirtyBeforeRun": self.source_dirty_before_run,
            "cleanCheckout": self.clean_checkout,
            "startedAt": self.command.started_at,
            "finishedAt": self.command.finished_at,
            "commands": [self.command.as_document()],
            "deterministicResultSetDigest": self.deterministic_result_set_digest,
            "runEvidenceDigest": self.run_evidence_digest,
        }


class SealedRunPair(dict[str, Any]):
    """Immutable dict subclass that remains JSON-serializable as ``runPair``."""

    __slots__ = (
        "_freeze_identity",
        "_freeze_digest",
        "_criterion_id",
        "_evaluator",
        "_outcome",
        "_deterministic_digest",
        "_pair_digest",
        "__weakref__",
    )

    def __init__(
        self,
        document: Mapping[str, Any],
        *,
        freeze_identity: int,
        freeze_digest: str,
        criterion_id: str,
        evaluator: str,
        outcome: str,
        deterministic_digest: str,
        pair_digest: str,
    ) -> None:
        dict.__init__(self, document)
        object.__setattr__(self, "_freeze_identity", freeze_identity)
        object.__setattr__(self, "_freeze_digest", freeze_digest)
        object.__setattr__(self, "_criterion_id", criterion_id)
        object.__setattr__(self, "_evaluator", evaluator)
        object.__setattr__(self, "_outcome", outcome)
        object.__setattr__(self, "_deterministic_digest", deterministic_digest)
        object.__setattr__(self, "_pair_digest", pair_digest)

    @property
    def outcome(self) -> str:
        return self._outcome

    @property
    def run_pair_digest(self) -> str:
        return self._pair_digest

    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("sealed runPair is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("sealed runPair metadata is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("sealed runPair metadata is immutable")

    def __deepcopy__(self, memo: dict[int, Any]) -> SealedRunPair:
        clone = SealedRunPair(
            deepcopy(dict(self), memo),
            freeze_identity=self._freeze_identity,
            freeze_digest=self._freeze_digest,
            criterion_id=self._criterion_id,
            evaluator=self._evaluator,
            outcome=self._outcome,
            deterministic_digest=self._deterministic_digest,
            pair_digest=self._pair_digest,
        )
        memo[id(self)] = clone
        return clone


class SealedPhaseRunPair(SealedRunPair):
    """Phase-aggregate pair sealed in a registry disjoint from work units."""


_SEALED_RUNS: dict[int, weakref.ReferenceType[Any]] = {}
_SEALED_PAIRS: dict[int, weakref.ReferenceType[Any]] = {}
_SEALED_PHASE_PAIRS: dict[int, weakref.ReferenceType[Any]] = {}


def _fail(code: str, path: str, message: str) -> None:
    raise GateRunnerError(code, path, message)


def _seal(registry: dict[int, weakref.ReferenceType[Any]], value: Any) -> Any:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        if registry.get(identity) is reference:
            registry.pop(identity, None)

    registry[identity] = weakref.ref(value, discard)
    return value


def _is_sealed(registry: dict[int, weakref.ReferenceType[Any]], value: Any) -> bool:
    reference = registry.get(id(value))
    return reference is not None and reference() is value


def _verified_freeze(value: Any) -> VerifiedProtectedInputFreeze:
    try:
        _require_verified(value, VerifiedProtectedInputFreeze, "freeze")
    except ProtectedVerificationError as exc:
        _fail(exc.code, "freeze", exc.message)
    assert isinstance(value, VerifiedProtectedInputFreeze)
    return value


def _verified_phase_freeze(value: Any) -> VerifiedPhaseProtectedInputFreeze:
    try:
        _require_verified(value, VerifiedPhaseProtectedInputFreeze, "phaseFreeze")
    except ProtectedVerificationError as exc:
        _fail(exc.code, "phaseFreeze", exc.message)
    assert isinstance(value, VerifiedPhaseProtectedInputFreeze)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _strict_json(value: Any, path: str) -> Any:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        _fail("non_canonical_input", path, str(exc))


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        _fail("invalid_timestamp", path, "expected second-precision UTC timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        _fail("invalid_timestamp", path, str(exc))


def _criterion(
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
) -> CriterionBinding:
    matches = [item for item in freeze.criteria if item.criterion_id == criterion_id]
    if len(matches) != 1:
        _fail("unknown_criterion", "criterionId", criterion_id)
    criterion = matches[0]
    if criterion.kind != "MACHINE":
        _fail("invalid_criterion_kind", "criterionId", "MACHINE required")
    expected_id = EVALUATOR_CRITERION_IDS.get(criterion.evaluator)
    if expected_id is None:
        _fail("unknown_evaluator", "criterion.evaluator", criterion.evaluator)
    if expected_id != criterion.criterion_id:
        _fail(
            "criterion_evaluator_mismatch",
            "criterion",
            "criterion ID does not match the builtin evaluator",
        )
    return criterion


def _parse_assertions(value: Any) -> tuple[SemanticAssertion, ...]:
    if not isinstance(value, list) or not value:
        _fail(
            "missing_semantic_assertions",
            "commandResult.semanticAssertions",
            "at least one verified semantic assertion is required",
        )
    assertions: list[SemanticAssertion] = []
    for index, raw in enumerate(value):
        path = f"commandResult.semanticAssertions[{index}]"
        if not isinstance(raw, dict) or set(raw) != ASSERTION_FIELDS:
            _fail("invalid_semantic_assertion", path, "field set mismatch")
        assertion_id = raw["id"]
        status = raw["status"]
        if (
            not isinstance(assertion_id, str)
            or not assertion_id
            or len(assertion_id) > 256
            or assertion_id == "evaluator-outcome"
        ):
            _fail("invalid_semantic_assertion", f"{path}.id", "invalid assertion ID")
        if status not in {"PASS", "FAIL", "SKIP"}:
            _fail("invalid_semantic_assertion", f"{path}.status", str(status))
        assertions.append(
            SemanticAssertion(
                assertion_id=assertion_id,
                status=status,
                evidence_digest=_sha(raw["evidenceDigest"], f"{path}.evidenceDigest"),
            )
        )
    ids = [item.assertion_id for item in assertions]
    if ids != sorted(ids, key=lambda item: item.encode("utf-8")) or len(
        set(ids)
    ) != len(ids):
        _fail(
            "invalid_semantic_assertion",
            "commandResult.semanticAssertions",
            "assertion IDs must be sorted and unique",
        )
    return tuple(assertions)


def _parse_command_result(
    value: Any, *, label: str
) -> tuple[dict[str, Any], tuple[SemanticAssertion, ...]]:
    document = _strict_json(value, "commandResult")
    if not isinstance(document, dict) or set(document) != COMMAND_RESULT_FIELDS:
        _fail("invalid_command_result", "commandResult", "field set mismatch")
    for field in ("exitCode", "durationMs"):
        item = document[field]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            _fail("invalid_command_result", f"commandResult.{field}", "invalid integer")
    started = _timestamp(document["startedAt"], "commandResult.startedAt")
    finished = _timestamp(document["finishedAt"], "commandResult.finishedAt")
    if started >= finished:
        _fail("invalid_run_time", "commandResult", "startedAt must precede finishedAt")
    elapsed_ms = int((finished - started).total_seconds() * 1000)
    if document["durationMs"] != elapsed_ms:
        _fail(
            "invalid_run_time",
            "commandResult.durationMs",
            "duration does not match timestamps",
        )
    expected_clean = label == "B"
    if document["sourceDirtyBeforeRun"] is not False:
        _fail(
            "dirty_source",
            "commandResult.sourceDirtyBeforeRun",
            "dirty source forbidden",
        )
    if document["cleanCheckout"] is not expected_clean:
        _fail("clean_checkout_mismatch", "commandResult.cleanCheckout", label)
    for field in ("environmentDigest", "logDigest", "artifactManifestDigest"):
        _sha(document[field], f"commandResult.{field}")
    return document, _parse_assertions(document["semanticAssertions"])


def _bootstrap_evidence(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion: CriterionBinding,
    assertions: tuple[SemanticAssertion, ...],
    command_ok: bool,
) -> dict[str, Any]:
    required = BOOTSTRAP_ASSERTIONS[criterion.evaluator]
    required_pass = any(
        item.assertion_id == required and item.status == "PASS" for item in assertions
    )
    result = "PASS" if command_ok and required_pass else "FAIL"
    body = {
        "schemaVersion": "urn:agentapi-doctor:bootstrap-evaluator-evidence:v1",
        "criterionId": criterion.criterion_id,
        "evaluator": criterion.evaluator,
        "evaluatorDigest": criterion.evaluator_digest,
        "sourceCommit": freeze.subject.source_commit,
        "controlPlaneDigest": freeze.subject.control_plane_digest,
        "contractDigest": freeze.subject.contract_digest,
        "datasetFreezeDigest": freeze.attestation_digest,
        "datasetDigest": criterion.dataset_digest,
        "result": result,
        "reasonCode": "threshold_met"
        if result == "PASS"
        else "semantic_assertion_failed",
        "semanticAssertions": [item.as_document() for item in assertions],
    }
    body["evidenceDigest"] = canonical_digest(body)
    return body


def _p00_evidence(
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion: CriterionBinding,
    evaluator_input: Any,
    evaluator_evidence: Any,
) -> tuple[dict[str, Any], str]:
    if evaluator_input is None or evaluator_evidence is None:
        _fail(
            "missing_evaluator_material",
            "evaluatorInput",
            "P00 evaluator input and evidence are both required",
        )
    input_document = _strict_json(evaluator_input, "evaluatorInput")
    evidence_document = _strict_json(evaluator_evidence, "evaluatorEvidence")
    if not isinstance(input_document, dict) or not isinstance(evidence_document, dict):
        _fail("invalid_evaluator_material", "evaluatorInput", "objects required")
    expected_bindings = {
        "criterionId": criterion.criterion_id,
        "evaluator": criterion.evaluator,
        "sourceCommit": freeze.subject.source_commit,
        "controlPlaneDigest": freeze.subject.control_plane_digest,
        "evaluatorDigest": criterion.evaluator_digest,
        "datasetDigest": criterion.dataset_digest,
    }
    if any(
        input_document.get(key) != value for key, value in expected_bindings.items()
    ):
        _fail(
            "evaluator_binding_mismatch",
            "evaluatorInput",
            "criterion/source/control/evaluator/dataset binding differs from freeze",
        )
    try:
        recomputed = evaluate_strict(criterion.evaluator, input_document)
    except EvaluationError as exc:
        _fail(exc.code, f"evaluatorInput.{exc.path}", exc.message)
    if evidence_document != recomputed:
        _fail(
            "evaluator_evidence_mismatch",
            "evaluatorEvidence",
            "evidence must exactly equal recomputed evaluator output",
        )
    for key, value in expected_bindings.items():
        if evidence_document.get(key) != value:
            _fail("evaluator_binding_mismatch", f"evaluatorEvidence.{key}", str(value))
    declared = evidence_document.get("evidenceDigest")
    evidence_core = dict(evidence_document)
    evidence_core.pop("evidenceDigest", None)
    if declared != canonical_digest(evidence_core):
        _fail("evaluator_evidence_digest_mismatch", "evaluatorEvidence", "digest drift")
    return evidence_document, canonical_digest(input_document)


def _run_seal_payload(run: RunResult) -> dict[str, Any]:
    return {
        "run": run.as_document(),
        "criterionId": run.criterion_id,
        "evaluator": run.evaluator,
        "evaluatorInputDigest": run.evaluator_input_digest,
        "evaluatorEvidenceDigest": run.evaluator_evidence_digest,
        "outcome": run.outcome,
        "freezeDigest": run.freeze_digest,
        "semanticAssertions": [item.as_document() for item in run.command.assertions],
    }


def _require_run(value: Any, path: str) -> RunResult:
    if not isinstance(value, RunResult) or not _is_sealed(_SEALED_RUNS, value):
        _fail("unsealed_run_result", path, "exact record_run result required")
    expected_run_digest = document_digest(
        value.as_document(), omit_field="runEvidenceDigest"
    )
    if value.run_evidence_digest != expected_run_digest:
        _fail("run_evidence_digest_mismatch", path, "sealed run was altered")
    if value._seal_digest != canonical_digest(_run_seal_payload(value)):
        _fail("run_seal_mismatch", path, "sealed run metadata was altered")
    return value


def _record_run(
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    label: str,
    command_result: Mapping[str, Any],
    evaluator_input: Mapping[str, Any] | None = None,
    evaluator_evidence: Mapping[str, Any] | None = None,
) -> RunResult:
    """Validate one injected command observation and recompute its evidence."""

    verified_freeze = freeze
    criterion = _criterion(verified_freeze, criterion_id)
    if label not in {"A", "B"}:
        _fail("invalid_run_label", "label", str(label))
    command_data, caller_assertions = _parse_command_result(command_result, label=label)
    caller_pass = any(item.status == "PASS" for item in caller_assertions)
    caller_failed = any(item.status == "FAIL" for item in caller_assertions)
    command_ok = command_data["exitCode"] == 0 and caller_pass and not caller_failed

    if criterion.evaluator in BOOTSTRAP_EVALUATORS:
        if not isinstance(verified_freeze, VerifiedProtectedInputFreeze):
            _fail(
                "phase_bootstrap_evaluator_forbidden",
                "criterion.evaluator",
                "phase aggregates cannot execute work-unit bootstrap evaluators",
            )
        if evaluator_input is not None or evaluator_evidence is not None:
            _fail(
                "unexpected_evaluator_material",
                "evaluatorInput",
                "bootstrap builtins derive evidence from verified assertions",
            )
        evidence = _bootstrap_evidence(
            freeze=verified_freeze,
            criterion=criterion,
            assertions=caller_assertions,
            command_ok=command_ok,
        )
        input_digest = canonical_digest(
            {
                "freezeDigest": verified_freeze.attestation_digest,
                "criterionId": criterion.criterion_id,
                "evaluator": criterion.evaluator,
            }
        )
    else:
        evidence, input_digest = _p00_evidence(
            freeze=verified_freeze,
            criterion=criterion,
            evaluator_input=evaluator_input,
            evaluator_evidence=evaluator_evidence,
        )
    evaluator_outcome = evidence["result"]
    outcome = "PASS" if command_ok and evaluator_outcome == "PASS" else "FAIL"
    assertions = tuple(
        sorted(
            (
                *caller_assertions,
                SemanticAssertion(
                    assertion_id="evaluator-outcome",
                    status="PASS" if evaluator_outcome == "PASS" else "FAIL",
                    evidence_digest=evidence["evidenceDigest"],
                ),
            ),
            key=lambda item: item.assertion_id.encode("utf-8"),
        )
    )
    command = CommandObservation(
        command=FIXED_COMMANDS[criterion.evaluator],
        exit_code=command_data["exitCode"],
        duration_ms=command_data["durationMs"],
        started_at=command_data["startedAt"],
        finished_at=command_data["finishedAt"],
        log_digest=command_data["logDigest"],
        artifact_manifest_digest=command_data["artifactManifestDigest"],
        assertions=assertions,
    )
    evidence_digest = evidence["evidenceDigest"]
    deterministic_digest = canonical_digest(
        {
            "criterionId": criterion.criterion_id,
            "evaluator": criterion.evaluator,
            "evaluatorInputDigest": input_digest,
            "evaluatorEvidenceDigest": evidence_digest,
            "outcome": outcome,
            "semanticAssertions": [item.as_document() for item in assertions],
        }
    )
    inputs = dict(verified_freeze.protected_inputs)
    if set(inputs) != PROTECTED_INPUT_FIELDS:
        _fail("protected_input_mismatch", "freeze.protectedInputs", "field set drift")
    for key, value in inputs.items():
        _sha(value, f"freeze.protectedInputs.{key}")
    provisional = RunResult(
        label=label,
        environment_class=(
            "development-isolated" if label == "A" else "clean-checkout-offline"
        ),
        environment_digest=command_data["environmentDigest"],
        source_commit=verified_freeze.subject.source_commit,
        control_plane_digest=verified_freeze.subject.control_plane_digest,
        contract_digest=(
            verified_freeze.subject.contract_digest
            if isinstance(verified_freeze, VerifiedProtectedInputFreeze)
            else verified_freeze.subject.aggregate_contract_digest
        ),
        protected_inputs=tuple(sorted(inputs.items())),
        evaluator=criterion.evaluator,
        evaluator_digest=criterion.evaluator_digest,
        dataset_digest=criterion.dataset_digest,
        criterion_id=criterion.criterion_id,
        source_dirty_before_run=False,
        clean_checkout=label == "B",
        command=command,
        evaluator_input_digest=input_digest,
        evaluator_evidence_digest=evidence_digest,
        deterministic_result_set_digest=deterministic_digest,
        outcome=outcome,
        run_evidence_digest="",
        freeze_digest=verified_freeze.attestation_digest,
        _freeze_identity=id(verified_freeze),
        _seal_digest="",
    )
    run_digest = document_digest(
        provisional.as_document(), omit_field="runEvidenceDigest"
    )
    with_run_digest = replace(provisional, run_evidence_digest=run_digest)
    sealed = replace(
        with_run_digest,
        _seal_digest=canonical_digest(_run_seal_payload(with_run_digest)),
    )
    return _seal(_SEALED_RUNS, sealed)


def record_run(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_id: str,
    label: str,
    command_result: Mapping[str, Any],
    evaluator_input: Mapping[str, Any] | None = None,
    evaluator_evidence: Mapping[str, Any] | None = None,
) -> RunResult:
    """Record one work-unit run against an identity-sealed work-unit freeze."""

    return _record_run(
        freeze=_verified_freeze(freeze),
        criterion_id=criterion_id,
        label=label,
        command_result=command_result,
        evaluator_input=evaluator_input,
        evaluator_evidence=evaluator_evidence,
    )


def record_phase_run(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    label: str,
    command_result: Mapping[str, Any],
    evaluator_input: Mapping[str, Any] | None = None,
    evaluator_evidence: Mapping[str, Any] | None = None,
) -> RunResult:
    """Record one phase aggregate run against a sealed aggregate freeze."""

    return _record_run(
        freeze=_verified_phase_freeze(freeze),
        criterion_id=criterion_id,
        label=label,
        command_result=command_result,
        evaluator_input=evaluator_input,
        evaluator_evidence=evaluator_evidence,
    )


def _pair_id(freeze_digest: str, criterion_id: str, deterministic_digest: str) -> str:
    digest = canonical_digest(
        {
            "freezeDigest": freeze_digest,
            "criterionId": criterion_id,
            "deterministicResultSetDigest": deterministic_digest,
        }
    )
    return "pair-" + digest.removeprefix("sha256:")[:32]


def _combine_runs(
    *,
    freeze: VerifiedProtectedInputFreeze | VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    run_a: RunResult,
    run_b: RunResult,
    pair_type: type[SealedRunPair],
    pair_registry: dict[int, weakref.ReferenceType[Any]],
) -> SealedRunPair:
    """Combine exact sealed A/B runs into provenance-compatible ``runPair``."""

    verified_freeze = freeze
    criterion = _criterion(verified_freeze, criterion_id)
    first = _require_run(run_a, "runA")
    second = _require_run(run_b, "runB")
    if first.label != "A" or second.label != "B":
        _fail("invalid_run_pair", "runs", "runA/runB labels are required")
    for path, run in (("runA", first), ("runB", second)):
        if (
            run._freeze_identity != id(verified_freeze)
            or run.freeze_digest != verified_freeze.attestation_digest
        ):
            _fail(
                "freeze_identity_mismatch", path, "run belongs to another sealed freeze"
            )
        if (
            run.criterion_id != criterion.criterion_id
            or run.evaluator != criterion.evaluator
        ):
            _fail("cross_criterion_run", path, "run belongs to another criterion")
    invariant_fields = (
        "source_commit",
        "control_plane_digest",
        "contract_digest",
        "protected_inputs",
        "evaluator_digest",
        "dataset_digest",
        "evaluator_input_digest",
        "evaluator_evidence_digest",
        "deterministic_result_set_digest",
        "outcome",
    )
    if any(
        getattr(first, field) != getattr(second, field) for field in invariant_fields
    ):
        _fail(
            "deterministic_evidence_mismatch",
            "runs",
            "A/B source/freeze inputs or deterministic evidence differ",
        )
    document = {
        "verificationPairId": _pair_id(
            verified_freeze.attestation_digest,
            criterion.criterion_id,
            first.deterministic_result_set_digest,
        ),
        "runA": first.as_document(),
        "runB": second.as_document(),
    }
    pair_digest = document_digest(document)
    pair = pair_type(
        document,
        freeze_identity=id(verified_freeze),
        freeze_digest=verified_freeze.attestation_digest,
        criterion_id=criterion.criterion_id,
        evaluator=criterion.evaluator,
        outcome=first.outcome,
        deterministic_digest=first.deterministic_result_set_digest,
        pair_digest=pair_digest,
    )
    try:
        validated_digest = _validate_run_pair(
            pair,
            freeze=verified_freeze,
            criterion=criterion,
            outcome=pair.outcome,
            path="runPair",
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    if validated_digest != pair_digest:
        _fail("run_pair_digest_mismatch", "runPair", "provenance projection drift")
    return _seal(pair_registry, pair)


def combine_runs(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_id: str,
    run_a: RunResult,
    run_b: RunResult,
) -> SealedRunPair:
    """Combine exact sealed work-unit A/B runs."""

    return _combine_runs(
        freeze=_verified_freeze(freeze),
        criterion_id=criterion_id,
        run_a=run_a,
        run_b=run_b,
        pair_type=SealedRunPair,
        pair_registry=_SEALED_PAIRS,
    )


def combine_phase_runs(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    run_a: RunResult,
    run_b: RunResult,
) -> SealedPhaseRunPair:
    """Combine exact sealed phase A/B runs without weakening work-unit seals."""

    pair = _combine_runs(
        freeze=_verified_phase_freeze(freeze),
        criterion_id=criterion_id,
        run_a=run_a,
        run_b=run_b,
        pair_type=SealedPhaseRunPair,
        pair_registry=_SEALED_PHASE_PAIRS,
    )
    assert isinstance(pair, SealedPhaseRunPair)
    return pair


def _require_pair(
    value: Any,
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion: CriterionBinding,
) -> SealedRunPair:
    if not isinstance(value, SealedRunPair) or not _is_sealed(_SEALED_PAIRS, value):
        _fail("unsealed_run_pair", "runPair", "exact combine_runs result required")
    if (
        value._freeze_identity != id(freeze)
        or value._freeze_digest != freeze.attestation_digest
        or value._criterion_id != criterion.criterion_id
        or value._evaluator != criterion.evaluator
    ):
        _fail(
            "run_pair_identity_mismatch", "runPair", "freeze/criterion identity drift"
        )
    actual_digest = document_digest(value)
    if value._pair_digest != actual_digest:
        _fail("run_pair_digest_mismatch", "runPair", "sealed pair was altered")
    return value


def _require_phase_pair(
    value: Any,
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion: CriterionBinding,
) -> SealedPhaseRunPair:
    if not isinstance(value, SealedPhaseRunPair) or not _is_sealed(
        _SEALED_PHASE_PAIRS, value
    ):
        _fail(
            "unsealed_phase_run_pair",
            "runPair",
            "exact combine_phase_runs result required",
        )
    if (
        value._freeze_identity != id(freeze)
        or value._freeze_digest != freeze.attestation_digest
        or value._criterion_id != criterion.criterion_id
        or value._evaluator != criterion.evaluator
    ):
        _fail(
            "phase_run_pair_identity_mismatch",
            "runPair",
            "phase freeze/criterion identity drift",
        )
    if value._pair_digest != document_digest(value):
        _fail("run_pair_digest_mismatch", "runPair", "sealed pair was altered")
    return value


def criterion_result_projection(
    *,
    freeze: VerifiedProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedRunPair,
) -> dict[str, Any]:
    """Return fields directly insertable into a MACHINE SignedCriterionResult."""

    verified_freeze = _verified_freeze(freeze)
    criterion = _criterion(verified_freeze, criterion_id)
    pair = _require_pair(run_pair, freeze=verified_freeze, criterion=criterion)
    try:
        digest = _validate_run_pair(
            pair,
            freeze=verified_freeze,
            criterion=criterion,
            outcome=pair.outcome,
            path="runPair",
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    return {
        "outcome": pair.outcome,
        "evidenceDigest": digest,
        "runPair": pair,
        "runPairDigest": digest,
    }


def phase_criterion_result_projection(
    *,
    freeze: VerifiedPhaseProtectedInputFreeze,
    criterion_id: str,
    run_pair: SealedPhaseRunPair,
) -> dict[str, Any]:
    """Return exact fields for one phase MACHINE criterion result."""

    verified_freeze = _verified_phase_freeze(freeze)
    criterion = _criterion(verified_freeze, criterion_id)
    pair = _require_phase_pair(run_pair, freeze=verified_freeze, criterion=criterion)
    try:
        digest = _validate_run_pair(
            pair,
            freeze=verified_freeze,
            criterion=criterion,
            outcome=pair.outcome,
            path="runPair",
        )
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    return {
        "outcome": pair.outcome,
        "evidenceDigest": digest,
        "runPair": pair,
        "runPairDigest": digest,
    }


__all__ = [
    "FIXED_COMMANDS",
    "GateRunnerError",
    "RunResult",
    "SealedPhaseRunPair",
    "SealedRunPair",
    "combine_phase_runs",
    "combine_runs",
    "criterion_result_projection",
    "phase_criterion_result_projection",
    "record_phase_run",
    "record_run",
]
