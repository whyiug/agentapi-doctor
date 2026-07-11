"""Identity-sealed raw-chain replay and MACHINE evidence index protocol.

The workflow orchestrator constructs this projection only after replaying raw
signed artifacts.  Downstream phase aggregation can consume it without
importing the orchestrator itself, which keeps the protected workflow import
graph acyclic and prevents caller-authored evidence summaries.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, NoReturn
import weakref

from .digest import canonical_json_bytes, sha256_bytes
from .protected import ProtectedVerificationError
from .protected_v2 import STATE_VIEW_SCHEMA
from .state_chain_v2 import (
    VerifiedGenesisAnchorV2,
    VerifiedStateChainV2,
    require_verified_state_context_v2,
)


@dataclass
class EvidenceIndexError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class VerifiedMachineEvidenceRecord:
    """One MACHINE result reverified from a raw bundle at a signed event."""

    event_sequence: int
    event_digest: str
    bundle_digest: str
    operation: str
    phase: str
    work_unit: str
    source_commit: str
    control_plane_digest: str
    contract_digest: str
    criterion_id: str
    evaluator: str
    evaluator_digest: str
    verifier_digest: str
    evaluator_dataset_freeze_digest: str
    dataset_catalog_path: str
    dataset_slot_digest: str
    dataset_selection_digest: str | None
    dataset_digest: str
    freeze_digest: str
    result_digest: str
    evidence_digest: str
    verification_pair_id: str
    run_pair_digest: str
    execution_bundle_digest: str
    outcome: str


@dataclass(frozen=True)
class VerifiedProtectedChainReplay:
    """Fresh process-local result of raw trust verification and replay."""

    artifact_digest: str
    bootstrap_request_commit: str
    candidate_source_commit: str
    control_plane_digest: str
    trust_policy_digest: str
    jwks_snapshot_digest: str
    event_count: int
    head_sequence: int
    head_digest: str
    head_source_commit: str
    state_digest: str
    machine_evidence_index_digest: str
    machine_evidence_index: tuple[VerifiedMachineEvidenceRecord, ...]
    state_view: Mapping[str, Any]
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2


_VERIFIED_REPLAYS: dict[int, tuple[weakref.ReferenceType[Any], str]] = {}


def _fail(code: str, path: str, message: str) -> NoReturn:
    raise EvidenceIndexError(code, path, message)


def _machine_record_document(record: VerifiedMachineEvidenceRecord) -> dict[str, Any]:
    return {
        "eventSequence": record.event_sequence,
        "eventDigest": record.event_digest,
        "bundleDigest": record.bundle_digest,
        "operation": record.operation,
        "phase": record.phase,
        "workUnit": record.work_unit,
        "sourceCommit": record.source_commit,
        "controlPlaneDigest": record.control_plane_digest,
        "contractDigest": record.contract_digest,
        "criterionId": record.criterion_id,
        "evaluator": record.evaluator,
        "evaluatorDigest": record.evaluator_digest,
        "verifierDigest": record.verifier_digest,
        "evaluatorDatasetFreezeDigest": record.evaluator_dataset_freeze_digest,
        "datasetCatalogPath": record.dataset_catalog_path,
        "datasetSlotDigest": record.dataset_slot_digest,
        "datasetSelectionDigest": record.dataset_selection_digest,
        "datasetDigest": record.dataset_digest,
        "freezeDigest": record.freeze_digest,
        "resultDigest": record.result_digest,
        "evidenceDigest": record.evidence_digest,
        "verificationPairId": record.verification_pair_id,
        "runPairDigest": record.run_pair_digest,
        "executionBundleDigest": record.execution_bundle_digest,
        "outcome": record.outcome,
    }


def machine_index_document(
    records: tuple[VerifiedMachineEvidenceRecord, ...],
) -> list[dict[str, Any]]:
    return [_machine_record_document(record) for record in records]


def machine_index_digest(records: tuple[VerifiedMachineEvidenceRecord, ...]) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "schemaVersion": (
                    "urn:agentapi-doctor:verified-machine-evidence-index:v1alpha1"
                ),
                "records": machine_index_document(records),
            }
        )
    )


def state_view(
    current: VerifiedGenesisAnchorV2 | VerifiedStateChainV2,
) -> dict[str, Any]:
    """Project the exact replayed read-only state view."""

    sealed = require_verified_state_context_v2(current)
    if isinstance(sealed, VerifiedGenesisAnchorV2):
        head_digest = sealed.chain_head_digest
        head_timestamp = sealed.timestamp
        head_source_commit = sealed.head_source_commit
        workflow_runs = ((sealed.workflow_run_id, sealed.workflow_check_run_id),)
        attachments = sealed.attachments
        event_count = sealed.event_count
        head_sequence = sealed.head_sequence
    else:
        head_digest = sealed.head_digest
        head_timestamp = sealed.head_timestamp
        head_source_commit = sealed.head_source_commit
        workflow_runs = sealed.workflow_runs
        attachments = sealed.attachments
        event_count = sealed.event_count
        head_sequence = sealed.head_sequence
    return {
        "schemaVersion": STATE_VIEW_SCHEMA,
        **deepcopy(dict(sealed.state_core)),
        "stateDigest": sealed.state_digest,
        "attachments": [deepcopy(dict(item)) for item in attachments],
        "chain": {
            "eventCount": event_count,
            "headSequence": head_sequence,
            "headDigest": head_digest,
        },
        "provenance": {
            "oidcJwksSnapshotDigest": sealed.jwks_snapshot_digest,
            "bootstrapWorkflowExecutionCommit": sealed.workflow_execution_commit,
            "headTimestamp": head_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "headSourceCommit": head_source_commit,
            "workflowRuns": [
                {"runId": run_id, "checkRunId": check_run_id}
                for run_id, check_run_id in workflow_runs
            ],
            "bootstrapApprovalDigest": sealed.bootstrap_approval_digest,
            "bootstrapRequestDigest": sealed.bootstrap_request_digest,
        },
    }


def _replay_projection_digest(value: VerifiedProtectedChainReplay) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "artifactDigest": value.artifact_digest,
                "bootstrapRequestCommit": value.bootstrap_request_commit,
                "candidateSourceCommit": value.candidate_source_commit,
                "controlPlaneDigest": value.control_plane_digest,
                "trustPolicyDigest": value.trust_policy_digest,
                "jwksSnapshotDigest": value.jwks_snapshot_digest,
                "eventCount": value.event_count,
                "headSequence": value.head_sequence,
                "headDigest": value.head_digest,
                "headSourceCommit": value.head_source_commit,
                "stateDigest": value.state_digest,
                "machineEvidenceIndexDigest": value.machine_evidence_index_digest,
                "machineEvidenceIndex": machine_index_document(
                    value.machine_evidence_index
                ),
                "stateView": value.state_view,
            }
        )
    )


def seal_verified_protected_chain_replay(
    value: VerifiedProtectedChainReplay,
) -> VerifiedProtectedChainReplay:
    """Seal the orchestrator's freshly replayed projection by object identity."""

    identity = id(value)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        present = _VERIFIED_REPLAYS.get(identity)
        if present is not None and present[0] is reference:
            _VERIFIED_REPLAYS.pop(identity, None)

    reference = weakref.ref(value, discard)
    _VERIFIED_REPLAYS[identity] = (reference, _replay_projection_digest(value))
    return value


def require_verified_protected_chain_replay(
    value: Any, *, path: str = "chainReplay"
) -> VerifiedProtectedChainReplay:
    """Reject copied, reconstructed, mutated, or deserialized replay objects."""

    entry = _VERIFIED_REPLAYS.get(id(value))
    if (
        not isinstance(value, VerifiedProtectedChainReplay)
        or entry is None
        or entry[0]() is not value
        or entry[1] != _replay_projection_digest(value)
    ):
        _fail(
            "unverified_internal_result",
            path,
            "expected the exact result returned by raw protected-chain replay",
        )
    try:
        current = require_verified_state_context_v2(value.current)
    except ProtectedVerificationError as exc:
        _fail(exc.code, exc.path, exc.message)
    expected_head = (
        current.chain_head_digest
        if isinstance(current, VerifiedGenesisAnchorV2)
        else current.head_digest
    )
    if (
        value.bootstrap_request_commit != current.workflow_execution_commit
        or value.control_plane_digest != current.control_plane_digest
        or value.trust_policy_digest != current.trust_policy_digest
        or value.jwks_snapshot_digest != current.jwks_snapshot_digest
        or value.event_count != current.event_count
        or value.head_sequence != current.head_sequence
        or value.head_digest != expected_head
        or value.head_source_commit != current.head_source_commit
        or value.state_digest != current.state_digest
        or value.machine_evidence_index_digest
        != machine_index_digest(value.machine_evidence_index)
        or value.state_view != state_view(current)
    ):
        _fail("replay_result_mutated", path, "replay projection differs from sealed state")
    return value


def verified_machine_evidence_index(
    replay: Any,
) -> tuple[VerifiedMachineEvidenceRecord, ...]:
    """Return the exact MACHINE index only from an identity-sealed replay."""

    return require_verified_protected_chain_replay(replay).machine_evidence_index


__all__ = [
    "EvidenceIndexError",
    "VerifiedMachineEvidenceRecord",
    "VerifiedProtectedChainReplay",
    "machine_index_digest",
    "require_verified_protected_chain_replay",
    "seal_verified_protected_chain_replay",
    "state_view",
    "verified_machine_evidence_index",
]
