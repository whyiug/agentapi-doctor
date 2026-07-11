"""Mechanically derive P00 aggregate MACHINE evidence from raw-chain replay.

This module does not accept aggregate records, counts, verdicts, or summaries
from a caller.  Its sole evidence source is the identity-sealed MACHINE index
produced while :mod:`workflow_orchestrator` re-verifies every raw authorization
bundle and signed StateEvent.  Exact sealed work-unit/phase control contexts
provide the approved criterion, evaluator, contract, and dataset-slot map.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, NoReturn, Sequence
import weakref

from .control_context import (
    ControlContextError,
    VerifiedPhaseControlContext,
    VerifiedWorkUnitControlContext,
    require_verified_phase_control_context,
    require_verified_work_unit_control_context,
)
from .digest import canonical_json_bytes, sha256_bytes
from .p00_evaluators import (
    AGGREGATE_CRITERIA,
    build_paired_input,
)
from .protected import document_digest
from .evidence_index import (
    VerifiedMachineEvidenceRecord,
    VerifiedProtectedChainReplay,
    require_verified_protected_chain_replay,
)


PHASE_EVIDENCE_SCHEMA = "urn:agentapi-doctor:p00-phase-aggregate-evidence:v1alpha1"
PHASE_DATASET_ID = "P00-phase-aggregate-machine-evidence-v1"

EXPECTED_CRITERION_UNITS = {
    "P00-M-BOOTSTRAP-CONTROL": "P00.W01",
    "P00-M-ANTI-PLACEHOLDER": "P00.W01",
    "P00-M-COMPETITIVE": "P00.W02",
    "P00-M-PROVENANCE": "P00.W03",
    "P00-M-REPRO": "P00.W03",
    "P00-M-TAXONOMY": "P00.W03",
    "P00-M-REPLAY": "P00.W03",
    "P00-M-DUAL-VIEW": "P00.W04",
    "P00-M-REDUCTION": "P00.W04",
    "P00-M-SECRET": "P00.W04",
    "P00-M-UNKNOWN": "P00.W04",
    "P00-M-DOCS": "P00.W05",
}
EXPECTED_UNITS = tuple(f"P00.W0{index}" for index in range(1, 6))
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass
class PhaseEvidenceError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class VerifiedPhaseAggregateEvidence:
    """Identity-sealed exact 12-record aggregate evaluator input."""

    evidence_digest: str
    source_machine_index_digest: str
    phase_context_digest: str
    source_commit: str
    control_plane_digest: str
    aggregate_contract_digest: str
    dataset_digest: str
    dataset_manifest: Mapping[str, Any]
    records: tuple[Mapping[str, Any], ...]
    evaluator_input: Mapping[str, Any]


_VERIFIED: dict[int, tuple[weakref.ReferenceType[Any], str]] = {}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise PhaseEvidenceError(code, path, message)


def _projection(value: VerifiedPhaseAggregateEvidence) -> dict[str, Any]:
    return {
        "schemaVersion": PHASE_EVIDENCE_SCHEMA,
        "sourceMachineIndexDigest": value.source_machine_index_digest,
        "phaseContextDigest": value.phase_context_digest,
        "sourceCommit": value.source_commit,
        "controlPlaneDigest": value.control_plane_digest,
        "aggregateContractDigest": value.aggregate_contract_digest,
        "datasetDigest": value.dataset_digest,
        "datasetManifest": value.dataset_manifest,
        "records": list(value.records),
        "evaluatorInput": value.evaluator_input,
    }


def _seal(value: VerifiedPhaseAggregateEvidence) -> VerifiedPhaseAggregateEvidence:
    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        present = _VERIFIED.get(identity)
        if present is not None and present[0] is reference:
            _VERIFIED.pop(identity, None)

    reference = weakref.ref(value, discard)
    _VERIFIED[identity] = (reference, document_digest(_projection(value)))
    return value


def require_verified_phase_aggregate_evidence(
    value: Any, *, path: str = "phaseAggregateEvidence"
) -> VerifiedPhaseAggregateEvidence:
    entry = _VERIFIED.get(id(value))
    if (
        not isinstance(value, VerifiedPhaseAggregateEvidence)
        or entry is None
        or entry[0]() is not value
        or entry[1] != document_digest(_projection(value))
        or value.evidence_digest != document_digest(_projection(value))
    ):
        _fail(
            "unverified_internal_result",
            path,
            "expected the exact identity-sealed phase evidence result",
        )
    return value


def _contexts(
    contexts: Sequence[VerifiedWorkUnitControlContext],
) -> dict[str, VerifiedWorkUnitControlContext]:
    if isinstance(contexts, (str, bytes)) or not isinstance(contexts, Sequence):
        _fail("invalid_work_contexts", "workUnitContexts", "sequence required")
    result: dict[str, VerifiedWorkUnitControlContext] = {}
    for index, value in enumerate(contexts):
        try:
            context = require_verified_work_unit_control_context(
                value, path=f"workUnitContexts[{index}]"
            )
        except ControlContextError as exc:
            _fail(exc.code, exc.path, exc.message)
        work_unit = context.subject.work_unit
        if work_unit in result:
            _fail("duplicate_work_context", f"workUnitContexts[{index}]", work_unit)
        result[work_unit] = context
    if tuple(sorted(result)) != EXPECTED_UNITS:
        _fail(
            "work_context_set_mismatch",
            "workUnitContexts",
            "exact P00.W01 through P00.W05 contexts required",
        )
    return result


def _criterion_authority(
    contexts: Mapping[str, VerifiedWorkUnitControlContext],
) -> tuple[dict[str, Any], dict[str, tuple[str, str]], set[str]]:
    if set(EXPECTED_CRITERION_UNITS) != set(AGGREGATE_CRITERIA):
        _fail(
            "aggregate_criterion_map_mismatch",
            "EXPECTED_CRITERION_UNITS",
            "criterion ownership map differs from the fixed aggregate evaluator",
        )
    criteria: dict[str, Any] = {}
    slots: dict[str, tuple[str, str]] = {}
    late_bound: set[str] = set()
    for work_unit in EXPECTED_UNITS:
        context = contexts[work_unit]
        late_bound.update(context.late_bound_dataset_criteria)
        bindings = {
            criterion_id: (catalog_path, slot_digest)
            for criterion_id, catalog_path, slot_digest in context.dataset_catalog_bindings
        }
        for criterion in context.criteria:
            if criterion.kind != "MACHINE":
                continue
            criterion_id = criterion.criterion_id
            if criterion_id in criteria or criterion_id not in bindings:
                _fail("criterion_authority_mismatch", work_unit, criterion_id)
            criteria[criterion_id] = criterion
            slots[criterion_id] = bindings[criterion_id]
    if set(criteria) != set(AGGREGATE_CRITERIA):
        _fail(
            "aggregate_criterion_set_mismatch",
            "workUnitContexts",
            "sealed contexts do not define the exact P00 MACHINE set",
        )
    if not late_bound.issubset(criteria):
        _fail(
            "late_bound_criterion_mismatch",
            "workUnitContexts",
            "late-bound IDs must name exact MACHINE criteria",
        )
    return criteria, slots, late_bound


def _select_records(
    index: Sequence[VerifiedMachineEvidenceRecord],
    *,
    source_commit: str,
    control_plane_digest: str,
    criteria: Mapping[str, Any],
    slots: Mapping[str, tuple[str, str]],
    late_bound_criteria: set[str],
    contract_digests: Mapping[str, str],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[VerifiedMachineEvidenceRecord]] = {
        criterion_id: [] for criterion_id in AGGREGATE_CRITERIA
    }
    for position, record in enumerate(index):
        # A raw replay intentionally retains evidence from prior source
        # revisions.  Phase aggregation consumes only the current P00
        # source/control tuple; stale historical evidence is neither a pass nor
        # an error and therefore falls through to the exact missing-set check.
        if (
            record.phase != "P00"
            or record.source_commit != source_commit
            or record.control_plane_digest != control_plane_digest
        ):
            continue
        criterion_id = record.criterion_id
        if criterion_id not in grouped:
            _fail(
                "unexpected_machine_criterion",
                f"machineEvidenceIndex[{position}]",
                criterion_id,
            )
        expected_unit = EXPECTED_CRITERION_UNITS[criterion_id]
        criterion = criteria[criterion_id]
        expected_catalog_path, expected_slot_digest = slots[criterion_id]
        if (
            record.work_unit != expected_unit
            or record.contract_digest != contract_digests.get(expected_unit)
        ):
            _fail("aggregate_subject_mismatch", f"machineEvidenceIndex[{position}]", criterion_id)
        if (
            record.evaluator != AGGREGATE_CRITERIA[criterion_id]
            or record.evaluator != criterion.evaluator
            or record.evaluator_digest != criterion.evaluator_digest
            or (
                criterion_id not in late_bound_criteria
                and record.dataset_digest != criterion.dataset_digest
            )
            or record.outcome != "PASS"
            or not record.verification_pair_id
            or record.dataset_catalog_path != expected_catalog_path
            or record.dataset_slot_digest != expected_slot_digest
            or (
                criterion_id in late_bound_criteria
                and (
                    not isinstance(record.dataset_selection_digest, str)
                    or SHA256_RE.fullmatch(record.dataset_selection_digest) is None
                )
            )
            or (
                criterion_id not in late_bound_criteria
                and record.dataset_selection_digest is not None
            )
        ):
            _fail(
                "aggregate_record_binding_mismatch",
                f"machineEvidenceIndex[{position}]",
                criterion_id,
            )
        grouped[criterion_id].append(record)
    selected: list[dict[str, Any]] = []
    dataset_groups: dict[tuple[str, str], set[tuple[str, str | None]]] = {}
    evidence_digests: set[str] = set()
    for criterion_id in sorted(AGGREGATE_CRITERIA):
        records = grouped[criterion_id]
        if not records:
            _fail("missing_machine_criterion", "machineEvidenceIndex", criterion_id)
        by_result: dict[str, list[VerifiedMachineEvidenceRecord]] = {}
        for record in records:
            by_result.setdefault(record.result_digest, []).append(record)
        if len(by_result) != 1:
            _fail("conflicting_machine_result", "machineEvidenceIndex", criterion_id)
        duplicates = next(iter(by_result.values()))
        first = duplicates[0]
        aggregate_projection = (
            first.evidence_digest,
            first.verification_pair_id,
            first.evaluator_digest,
            first.evaluator_dataset_freeze_digest,
            first.dataset_catalog_path,
            first.dataset_slot_digest,
            first.dataset_selection_digest,
            first.dataset_digest,
            first.verifier_digest,
            first.run_pair_digest,
            first.execution_bundle_digest,
        )
        if any(
            (
                item.evidence_digest,
                item.verification_pair_id,
                item.evaluator_digest,
                item.evaluator_dataset_freeze_digest,
                item.dataset_catalog_path,
                item.dataset_slot_digest,
                item.dataset_selection_digest,
                item.dataset_digest,
                item.verifier_digest,
                item.run_pair_digest,
                item.execution_bundle_digest,
            )
            != aggregate_projection
            for item in duplicates[1:]
        ):
            _fail("conflicting_duplicate_result", "machineEvidenceIndex", criterion_id)
        if first.evidence_digest in evidence_digests:
            _fail("duplicate_child_evidence", "machineEvidenceIndex", criterion_id)
        evidence_digests.add(first.evidence_digest)
        dataset_groups.setdefault(slots[criterion_id], set()).add(
            (first.dataset_digest, first.dataset_selection_digest)
        )
        selected.append(
            {
                "id": criterion_id,
                "criterionId": criterion_id,
                "kind": "MACHINE",
                "evaluator": first.evaluator,
                "result": "PASS",
                "evidenceDigest": first.evidence_digest,
                "verificationPairId": first.verification_pair_id,
                "sourceCommit": first.source_commit,
                "controlPlaneDigest": first.control_plane_digest,
                "evaluatorDigest": first.evaluator_digest,
                "datasetFreezeDigest": first.evaluator_dataset_freeze_digest,
                "datasetDigest": first.dataset_digest,
                "verifierDigest": first.verifier_digest,
            }
        )
    if any(len(bindings) != 1 for bindings in dataset_groups.values()):
        _fail(
            "dataset_selection_fork",
            "machineEvidenceIndex",
            "one approved catalog path/slot resolved to multiple dataset/selection bindings",
        )
    return selected


def build_p00_phase_aggregate_evidence(
    replay: VerifiedProtectedChainReplay,
    *,
    phase_context: VerifiedPhaseControlContext,
    work_unit_contexts: Sequence[VerifiedWorkUnitControlContext],
) -> VerifiedPhaseAggregateEvidence:
    """Derive the exact aggregate evaluator input without caller summaries."""

    chain = require_verified_protected_chain_replay(replay)
    try:
        phase = require_verified_phase_control_context(phase_context)
    except ControlContextError as exc:
        _fail(exc.code, exc.path, exc.message)
    if phase.subject.phase != "P00":
        _fail("unsupported_phase", "phaseContext", "only P00 is supported")
    source_commit = chain.head_source_commit
    if (
        phase.subject.source_commit != source_commit
        or phase.subject.control_plane_digest != chain.control_plane_digest
    ):
        _fail("phase_subject_mismatch", "phaseContext", "phase context differs from chain head")
    state_phase = chain.current.state_core.get("phases", {}).get("P00")
    state_units = state_phase.get("workUnits") if isinstance(state_phase, Mapping) else None
    if (
        not isinstance(state_units, Mapping)
        or tuple(sorted(state_units)) != EXPECTED_UNITS
        or any(state_units[unit].get("status") != "CONVERGED" for unit in EXPECTED_UNITS)
    ):
        _fail(
            "phase_units_not_converged",
            "replay.state.P00.workUnits",
            "all five exact work units must be CONVERGED",
        )
    contexts = _contexts(work_unit_contexts)
    expected_contracts = dict(phase.unit_contract_digests)
    for work_unit, context in contexts.items():
        if (
            context.subject.source_commit != source_commit
            or context.subject.control_plane_digest != chain.control_plane_digest
            or context.subject.contract_digest != expected_contracts.get(work_unit)
            or state_units[work_unit].get("contractDigest") != context.subject.contract_digest
        ):
            _fail("work_context_binding_mismatch", work_unit, "context/state/phase contract differs")
    criteria, slots, late_bound = _criterion_authority(contexts)
    records = _select_records(
        chain.machine_evidence_index,
        source_commit=source_commit,
        control_plane_digest=chain.control_plane_digest,
        criteria=criteria,
        slots=slots,
        late_bound_criteria=late_bound,
        contract_digests={
            work_unit: context.subject.contract_digest
            for work_unit, context in contexts.items()
        },
    )
    aggregate_criteria = [
        item
        for item in phase.criteria
        if item.criterion_id == "P00-M-AGGREGATE" and item.kind == "MACHINE"
    ]
    if len(aggregate_criteria) != 1:
        _fail("missing_aggregate_criterion", "phaseContext.criteria", "exact MACHINE criterion required")
    aggregate = aggregate_criteria[0]
    evaluator_input = build_paired_input(
        aggregate.evaluator,
        records,
        source_commit=source_commit,
        control_plane_digest=chain.control_plane_digest,
        evaluator_digest=aggregate.evaluator_digest,
        dataset_id=PHASE_DATASET_ID,
    )
    dataset_manifest = {
        "schemaVersion": "urn:agentapi-doctor:p00-dataset-records:v1alpha1",
        "datasetId": PHASE_DATASET_ID,
        "records": records,
    }
    dataset_digest = sha256_bytes(canonical_json_bytes(records))
    if evaluator_input["datasetDigest"] != dataset_digest:
        _fail("aggregate_dataset_digest_mismatch", "evaluatorInput", "record digest drift")
    provisional = VerifiedPhaseAggregateEvidence(
        evidence_digest="",
        source_machine_index_digest=chain.machine_evidence_index_digest,
        phase_context_digest=phase.context_digest,
        source_commit=source_commit,
        control_plane_digest=chain.control_plane_digest,
        aggregate_contract_digest=phase.subject.aggregate_contract_digest,
        dataset_digest=dataset_digest,
        dataset_manifest=dataset_manifest,
        records=tuple(records),
        evaluator_input=evaluator_input,
    )
    digest = document_digest(_projection(provisional))
    value = VerifiedPhaseAggregateEvidence(
        **{**provisional.__dict__, "evidence_digest": digest}
    )
    return _seal(value)


__all__ = [
    "EXPECTED_CRITERION_UNITS",
    "PHASE_DATASET_ID",
    "PHASE_EVIDENCE_SCHEMA",
    "PhaseEvidenceError",
    "VerifiedPhaseAggregateEvidence",
    "build_p00_phase_aggregate_evidence",
    "require_verified_phase_aggregate_evidence",
]
