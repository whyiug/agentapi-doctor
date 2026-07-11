"""Pure, offline P00 machine evaluators.

The module accepts only strict, paired raw-record inputs.  It never performs
network or filesystem I/O and never trusts caller-supplied counts, ratios, or
aggregate verdicts.  ``evaluate_json`` is the preferred boundary API because
it also rejects duplicate JSON keys and non-finite numbers.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable, Mapping, Sequence


INPUT_SCHEMA = "urn:agentapi-doctor:p00-evaluator-input:v1"
FREEZE_SCHEMA = "urn:agentapi-doctor:p00-dataset-freeze:v1"
EVIDENCE_SCHEMA = "urn:agentapi-doctor:p00-evaluator-evidence:v1"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
HTTPS_RE = re.compile(r"^https://[^\s]+$")
HTTPS_IN_TEXT_RE = re.compile(r"https://[^\s)>\]\"']+")


@dataclass
class EvaluationError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _fail(code: str, path: str, message: str) -> None:
    raise EvaluationError(code, path, message)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail("non_canonical_input", "document", str(exc))


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact(value: Any, fields: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_schema", path, "must be an object")
    actual = set(value)
    if actual != fields:
        _fail(
            "invalid_schema",
            path,
            f"field set mismatch; missing={sorted(fields - actual)}, extra={sorted(actual - fields)}",
        )
    return value


def _string(value: Any, path: str, *, maximum: int = 16384) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        _fail("invalid_schema", path, "must be a non-empty bounded string")
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        _fail("invalid_digest", path, "expected lowercase sha256:<64 hex>")
    return value


def _commit(value: Any, path: str) -> str:
    if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
        _fail("invalid_source_commit", path, "expected lowercase 40-hex commit")
    return value


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        _fail("invalid_schema", path, "must be boolean")
    return value


def _int(value: Any, path: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        _fail("invalid_schema", path, f"must be an integer >= {minimum}")
    return value


def _strings(value: Any, path: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list):
        _fail("invalid_schema", path, "must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_string(item, f"{path}[{index}]") if not allow_empty else str(item))
    return result


def _unique_ids(records: Any, path: str) -> list[Mapping[str, Any]]:
    if not isinstance(records, list):
        _fail("invalid_schema", path, "records must be an array")
    result: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(records):
        if not isinstance(item, Mapping):
            _fail("invalid_schema", f"{path}[{index}]", "record must be an object")
        record_id = _string(item.get("id"), f"{path}[{index}].id", maximum=256)
        if record_id in seen:
            _fail("duplicate_record", f"{path}[{index}].id", record_id)
        seen.add(record_id)
        result.append(item)
    return result


def _sorted_records(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(records, key=lambda item: item["id"].encode("utf-8"))


def _records_digest(records: Sequence[Mapping[str, Any]]) -> str:
    return canonical_digest(_sorted_records(records))


EVALUATOR_CRITERIA = {
    "evaluator://research/competitive/v1": "P00-M-COMPETITIVE",
    "evaluator://catalog/provenance-count/v1": "P00-M-PROVENANCE",
    "evaluator://corpus/reproduction/v1": "P00-M-REPRO",
    "evaluator://corpus/taxonomy/v1": "P00-M-TAXONOMY",
    "evaluator://corpus/replay/v1": "P00-M-REPLAY",
    "evaluator://experiment/dual-view/v1": "P00-M-DUAL-VIEW",
    "evaluator://experiment/minimization/v1": "P00-M-REDUCTION",
    "evaluator://redaction/secret-canary/v1": "P00-M-SECRET",
    "evaluator://attribution/unknown/v1": "P00-M-UNKNOWN",
    "evaluator://docs/license-links/v1": "P00-M-DOCS",
    "evaluator://phase/aggregate/v1": "P00-M-AGGREGATE",
}


def build_paired_input(
    evaluator: str,
    records: Sequence[Mapping[str, Any]],
    *,
    source_commit: str,
    control_plane_digest: str,
    evaluator_digest: str,
    dataset_id: str,
) -> dict[str, Any]:
    """Build a deterministic A/B input; approval of the freeze remains external."""

    if evaluator not in EVALUATOR_CRITERIA:
        _fail("unknown_evaluator", "evaluator", evaluator)
    _commit(source_commit, "sourceCommit")
    _sha(control_plane_digest, "controlPlaneDigest")
    _sha(evaluator_digest, "evaluatorDigest")
    copied = [deepcopy(dict(item)) for item in records]
    checked = _unique_ids(copied, "records")
    dataset_digest = _records_digest(checked)
    record_ids = sorted(item["id"] for item in checked)
    freeze = {
        "schemaVersion": FREEZE_SCHEMA,
        "datasetId": _string(dataset_id, "datasetId", maximum=256),
        "recordIds": record_ids,
        "datasetDigest": dataset_digest,
        "sourceCommit": source_commit,
        "controlPlaneDigest": control_plane_digest,
        "evaluatorDigest": evaluator_digest,
    }
    freeze_digest = canonical_digest(freeze)
    runs = []
    for label in ("A", "B"):
        runs.append(
            {
                "label": label,
                "sourceCommit": source_commit,
                "controlPlaneDigest": control_plane_digest,
                "evaluatorDigest": evaluator_digest,
                "datasetFreezeDigest": freeze_digest,
                "datasetDigest": dataset_digest,
                "records": deepcopy(copied),
            }
        )
    return {
        "schemaVersion": INPUT_SCHEMA,
        "evaluator": evaluator,
        "criterionId": EVALUATOR_CRITERIA[evaluator],
        "sourceCommit": source_commit,
        "controlPlaneDigest": control_plane_digest,
        "evaluatorDigest": evaluator_digest,
        "datasetFreeze": freeze,
        "datasetFreezeDigest": freeze_digest,
        "datasetDigest": dataset_digest,
        "runs": runs,
    }


def _validate_envelope(
    evaluator: str, payload: Any
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]], dict[str, Any]]:
    document = _exact(
        payload,
        {
            "schemaVersion",
            "evaluator",
            "criterionId",
            "sourceCommit",
            "controlPlaneDigest",
            "evaluatorDigest",
            "datasetFreeze",
            "datasetFreezeDigest",
            "datasetDigest",
            "runs",
        },
        "input",
    )
    if document["schemaVersion"] != INPUT_SCHEMA:
        _fail("unsupported_schema", "input.schemaVersion", str(document["schemaVersion"]))
    if evaluator not in EVALUATOR_CRITERIA or document["evaluator"] != evaluator:
        _fail("evaluator_mismatch", "input.evaluator", str(document["evaluator"]))
    if document["criterionId"] != EVALUATOR_CRITERIA[evaluator]:
        _fail("criterion_mismatch", "input.criterionId", str(document["criterionId"]))
    source_commit = _commit(document["sourceCommit"], "input.sourceCommit")
    control_digest = _sha(document["controlPlaneDigest"], "input.controlPlaneDigest")
    evaluator_digest = _sha(document["evaluatorDigest"], "input.evaluatorDigest")
    dataset_digest = _sha(document["datasetDigest"], "input.datasetDigest")
    freeze_digest = _sha(document["datasetFreezeDigest"], "input.datasetFreezeDigest")

    freeze = _exact(
        document["datasetFreeze"],
        {
            "schemaVersion",
            "datasetId",
            "recordIds",
            "datasetDigest",
            "sourceCommit",
            "controlPlaneDigest",
            "evaluatorDigest",
        },
        "input.datasetFreeze",
    )
    if freeze["schemaVersion"] != FREEZE_SCHEMA:
        _fail("unsupported_schema", "input.datasetFreeze.schemaVersion", str(freeze["schemaVersion"]))
    _string(freeze["datasetId"], "input.datasetFreeze.datasetId", maximum=256)
    freeze_ids = _strings(freeze["recordIds"], "input.datasetFreeze.recordIds")
    if freeze_ids != sorted(set(freeze_ids)):
        _fail("invalid_dataset_freeze", "input.datasetFreeze.recordIds", "must be sorted and unique")
    if (
        freeze["datasetDigest"] != dataset_digest
        or freeze["sourceCommit"] != source_commit
        or freeze["controlPlaneDigest"] != control_digest
        or freeze["evaluatorDigest"] != evaluator_digest
    ):
        _fail("dataset_freeze_binding_mismatch", "input.datasetFreeze", "identity binding drift")
    if canonical_digest(freeze) != freeze_digest:
        _fail("dataset_freeze_digest_mismatch", "input.datasetFreezeDigest", "freeze digest drift")

    runs = document["runs"]
    if not isinstance(runs, list) or len(runs) != 2:
        _fail("invalid_run_pair", "input.runs", "exactly two runs are required")
    by_label: dict[str, tuple[list[Mapping[str, Any]], str]] = {}
    run_fields = {
        "label",
        "sourceCommit",
        "controlPlaneDigest",
        "evaluatorDigest",
        "datasetFreezeDigest",
        "datasetDigest",
        "records",
    }
    for index, raw_run in enumerate(runs):
        run = _exact(raw_run, run_fields, f"input.runs[{index}]")
        label = run["label"]
        if label not in {"A", "B"} or label in by_label:
            _fail("invalid_run_pair", f"input.runs[{index}].label", str(label))
        if (
            run["sourceCommit"] != source_commit
            or run["controlPlaneDigest"] != control_digest
            or run["evaluatorDigest"] != evaluator_digest
            or run["datasetFreezeDigest"] != freeze_digest
            or run["datasetDigest"] != dataset_digest
        ):
            _fail("run_identity_mismatch", f"input.runs[{index}]", "A/B identity drift")
        records = _unique_ids(run["records"], f"input.runs[{index}].records")
        digest = _records_digest(records)
        if digest != dataset_digest:
            _fail("dataset_digest_mismatch", f"input.runs[{index}].records", "raw records do not match datasetDigest")
        if sorted(item["id"] for item in records) != freeze_ids:
            _fail("dataset_freeze_record_mismatch", f"input.runs[{index}].records", "record IDs differ from freeze")
        by_label[label] = (records, digest)
    if set(by_label) != {"A", "B"}:
        _fail("invalid_run_pair", "input.runs", "labels A and B are required")
    if _canonical_bytes(_sorted_records(by_label["A"][0])) != _canonical_bytes(
        _sorted_records(by_label["B"][0])
    ):
        _fail("run_pair_mismatch", "input.runs", "A/B raw record sets differ")
    pair = {
        "labels": ["A", "B"],
        "runRecordDigests": {"A": by_label["A"][1], "B": by_label["B"][1]},
        "consistent": True,
    }
    return document, by_label["A"][0], pair


SOURCE_FIELDS = {
    "sourceType",
    "originalURL",
    "resolvedURL",
    "retrievedAt",
    "revision",
    "contentDigest",
    "licenseOrReuseStatus",
}
ALLOWED_LICENSE = {"allowed", "permissive", "public-facts-only", "Apache-2.0", "CC-BY-4.0", "original-project-content"}


def _source_valid(value: Any, path: str) -> bool:
    source = _exact(value, SOURCE_FIELDS, path)
    for field in SOURCE_FIELDS:
        if not isinstance(source[field], str):
            _fail("invalid_schema", f"{path}.{field}", "must be a string")
    return bool(
        source["sourceType"] == "primary"
        and HTTPS_RE.fullmatch(source["originalURL"])
        and HTTPS_RE.fullmatch(source["resolvedURL"])
        and RFC3339_UTC_RE.fullmatch(source["retrievedAt"])
        and source["revision"].strip()
        and SHA256_RE.fullmatch(source["contentDigest"])
        and source["licenseOrReuseStatus"] in ALLOWED_LICENSE
    )


NAMED_PROJECTS = {
    "am-i-openai-compatible",
    "octest",
    "FauxpenAI-conformance",
    "Open Responses",
}
MATRIX_DIMENSIONS = {
    "capability overlap",
    "architecture",
    "evidence model",
    "client-observed behavior",
    "governance",
    "reuse or collaboration opportunity",
    "independent-project justification",
}
NAMING_CHECKS = {
    "GitHub repository and organization",
    "Go module",
    "Python package",
    "npm package",
    "OCI namespace",
    "domain",
    "obvious trademark conflict",
}
PROHIBITED_CLAIMS = (
    "willingness inferred from silence",
    "agent-authored statement represented as external feedback",
    "public compatibility ranking",
    "compatibility badge",
    "differentiation based only on interface quality",
)


def _claims(value: Any, path: str) -> tuple[list[str], list[str]]:
    claims = _strings(value, path)
    findings = []
    for claim in claims:
        normalized = " ".join(claim.lower().split())
        if any(marker in normalized for marker in PROHIBITED_CLAIMS):
            findings.append(claim)
    return claims, findings


def _competitive(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    projects: set[str] = set()
    project_record_count = 0
    interviews: set[str] = set()
    names: set[str] = set()
    primary_checks = 0
    prohibited: list[str] = []
    results: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        path = f"records[{index}]"
        record_type = record.get("recordType")
        common = {"id", "recordType", "source", "claims"}
        if record_type == "project":
            item = _exact(record, common | {"project", "dimensions"}, path)
            project = _string(item["project"], f"{path}.project", maximum=256)
            dimensions = _exact(item["dimensions"], MATRIX_DIMENSIONS, f"{path}.dimensions")
            for key, value in dimensions.items():
                _string(value, f"{path}.dimensions.{key}")
            if project in projects:
                _fail("duplicate_project_record", f"{path}.project", project)
            projects.add(project)
            project_record_count += 1
            kind_key = project
        elif record_type == "interview":
            item = _exact(record, common | {"interviewId", "participantRole", "organization"}, path)
            kind_key = _string(item["interviewId"], f"{path}.interviewId", maximum=256)
            _string(item["participantRole"], f"{path}.participantRole")
            _string(item["organization"], f"{path}.organization")
            interviews.add(kind_key)
        elif record_type == "naming":
            item = _exact(record, common | {"candidate", "checks"}, path)
            kind_key = _string(item["candidate"], f"{path}.candidate", maximum=256)
            checks = _exact(item["checks"], NAMING_CHECKS, f"{path}.checks")
            for key, value in checks.items():
                check = _exact(
                    value,
                    {"finding", "source"},
                    f"{path}.checks.{key}",
                )
                _string(check["finding"], f"{path}.checks.{key}.finding")
                if _source_valid(check["source"], f"{path}.checks.{key}.source"):
                    primary_checks += 1
            names.add(kind_key)
        else:
            _fail("invalid_record_type", f"{path}.recordType", str(record_type))
        source_valid = _source_valid(item["source"], f"{path}.source")
        if source_valid:
            primary_checks += 1
        _, findings = _claims(item["claims"], f"{path}.claims")
        prohibited.extend(findings)
        results.append({"id": item["id"], "recordType": record_type, "key": kind_key, "primarySourceValid": source_valid, "prohibitedClaimCount": len(findings)})
    passed = bool(
        projects == NAMED_PROJECTS
        and project_record_count == 4
        and len(interviews) >= 5
        and len(names) >= 3
        and primary_checks == len(records) + len(names) * len(NAMING_CHECKS)
        and not prohibited
    )
    recomputed = {
        "namedProjects": sorted(projects),
        "matrixRecordCount": len(projects),
        "interviewRecordCount": len(interviews),
        "namingCandidateCount": len(names),
        "primarySourceChecks": primary_checks,
        "prohibitedClaimFindings": prohibited,
    }
    reason = "threshold_met" if passed else "policy_or_threshold_not_met"
    return passed, reason, recomputed, results


PROVENANCE_FIELDS = {
    "id", "originalURL", "resolvedURL", "retrievedAt", "revision", "contentDigest",
    "sourceType", "licenseOrReuseStatus", "protocol", "client", "runtime", "model",
    "symptom", "adjudicatedGroundTruth", "syntheticEligibility", "redactionStatus",
}


def _provenance(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    results = []
    eligible = 0
    seen_source_keys: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, PROVENANCE_FIELDS, path)
        for field in PROVENANCE_FIELDS - {"syntheticEligibility"}:
            _string(item[field], f"{path}.{field}")
        _bool(item["syntheticEligibility"], f"{path}.syntheticEligibility")
        source_key = (item["resolvedURL"], item["revision"], item["contentDigest"])
        duplicate_source = source_key in seen_source_keys
        seen_source_keys.add(source_key)
        valid = bool(
            not duplicate_source
            and item["sourceType"] == "primary"
            and HTTPS_RE.fullmatch(item["originalURL"])
            and HTTPS_RE.fullmatch(item["resolvedURL"])
            and RFC3339_UTC_RE.fullmatch(item["retrievedAt"])
            and SHA256_RE.fullmatch(item["contentDigest"])
            and item["licenseOrReuseStatus"] in ALLOWED_LICENSE
            and item["redactionStatus"] == "redacted"
            and item["syntheticEligibility"] is True
        )
        eligible += int(valid)
        results.append({"id": item["id"], "eligible": valid, "duplicateSource": duplicate_source})
    passed = eligible >= 30
    reason = "threshold_met" if passed else ("insufficient_samples" if len(records) < 30 else "threshold_not_met")
    return passed, reason, {"eligibleCount": eligible, "rejectedCount": len(records) - eligible, "recordCount": len(records)}, results


REPRODUCTION_FIELDS = {
    "id", "executionStatus", "realCodePath", "localOnly", "publicTargetContacted",
    "weaponizedPayload", "expectedFailureFingerprint", "observedFailureFingerprint",
}


def _reproduction(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    results = []
    reproduced = 0
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, REPRODUCTION_FIELDS, path)
        if item["executionStatus"] not in {"completed", "errored", "skipped"}:
            _fail("invalid_schema", f"{path}.executionStatus", str(item["executionStatus"]))
        for field in ("realCodePath", "localOnly", "publicTargetContacted", "weaponizedPayload"):
            _bool(item[field], f"{path}.{field}")
        expected = _string(item["expectedFailureFingerprint"], f"{path}.expectedFailureFingerprint")
        observed = item["observedFailureFingerprint"]
        if observed is not None:
            observed = _string(observed, f"{path}.observedFailureFingerprint")
        success = bool(item["executionStatus"] == "completed" and item["realCodePath"] and item["localOnly"] and not item["publicTargetContacted"] and not item["weaponizedPayload"] and observed == expected)
        reproduced += int(success)
        results.append({"id": item["id"], "reproduced": success})
    passed = len(records) >= 20 and reproduced >= 16
    reason = "threshold_met" if passed else ("insufficient_samples" if len(records) < 20 else "threshold_not_met")
    return passed, reason, {"attempted": len(records), "reproduced": reproduced}, results


FAULT_DOMAIN_FAMILY = {
    "TRANSPORT": "transport", "AUTH": "transport", "RATE_LIMIT_OR_TRANSIENT": "transport",
    "REQUEST_MAPPING": "wire", "PROTOCOL_SERIALIZER": "wire", "STREAM_STATE_MACHINE": "wire", "GATEWAY_TRANSLATION": "wire",
    "TOOL_PARSER": "protocol", "REASONING_PARSER": "protocol", "CHAT_TEMPLATE": "protocol",
    "MODEL_BEHAVIOR": "model", "SDK_PARSER": "client", "AGENT_ORCHESTRATION": "client",
    "HARNESS": "harness", "SPEC_AMBIGUITY": "unknown", "UNKNOWN_FAULT_DOMAIN": "unknown",
}
TAXONOMY_FIELDS = {"id", "groundTruthDigest", "evidenceSufficient", "faultDomain", "faultFamily"}


def _taxonomy(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    domains: set[str] = set()
    unknown = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, TAXONOMY_FIELDS, path)
        _sha(item["groundTruthDigest"], f"{path}.groundTruthDigest")
        sufficient = _bool(item["evidenceSufficient"], f"{path}.evidenceSufficient")
        domain = item["faultDomain"]
        family = item["faultFamily"]
        if domain not in FAULT_DOMAIN_FAMILY or family != FAULT_DOMAIN_FAMILY.get(domain):
            _fail("taxonomy_mapping_mismatch", path, f"{domain}/{family}")
        if not sufficient and domain != "UNKNOWN_FAULT_DOMAIN":
            _fail("unsupported_attribution", path, "insufficient evidence must remain unknown")
        if domain == "UNKNOWN_FAULT_DOMAIN":
            unknown += 1
        else:
            domains.add(domain)
        results.append({"id": item["id"], "faultDomain": domain, "faultFamily": family})
    passed = len(records) >= 20 and len(domains) >= 2
    reason = "threshold_met" if passed else ("insufficient_samples" if len(records) < 20 else "threshold_not_met")
    return passed, reason, {"classified": len(records) - unknown, "unknown": unknown, "faultDomains": sorted(domains)}, results


REPLAY_FIELDS = {"id", "controlledFixture", "nonDeterministicEnvelopeExcluded", "replayResultDigests"}


def _replay(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    deterministic = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, REPLAY_FIELDS, path)
        controlled = _bool(item["controlledFixture"], f"{path}.controlledFixture")
        excluded = _bool(item["nonDeterministicEnvelopeExcluded"], f"{path}.nonDeterministicEnvelopeExcluded")
        digests = item["replayResultDigests"]
        if not isinstance(digests, list) or len(digests) < 2:
            _fail("invalid_schema", f"{path}.replayResultDigests", "at least two replay digests required")
        for offset, digest in enumerate(digests):
            _sha(digest, f"{path}.replayResultDigests[{offset}]")
        success = bool(controlled and excluded and len(set(digests)) == 1)
        deterministic += int(success)
        results.append({"id": item["id"], "deterministic": success})
    passed = deterministic >= 10
    reason = "threshold_met" if passed else ("insufficient_samples" if len(records) < 10 else "threshold_not_met")
    return passed, reason, {"eligible": len(records), "deterministicReplayCount": deterministic}, results


DUAL_VIEW_FIELDS = {"id", "captureLayerDigest", "clientViewDigest", "captureCorrelationId", "clientCorrelationId"}


def _dual_view(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    correlated = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, DUAL_VIEW_FIELDS, path)
        for field in ("captureLayerDigest", "clientViewDigest"):
            if item[field] is not None:
                _sha(item[field], f"{path}.{field}")
        for field in ("captureCorrelationId", "clientCorrelationId"):
            if item[field] is not None:
                _string(item[field], f"{path}.{field}", maximum=256)
        success = bool(item["captureLayerDigest"] and item["clientViewDigest"] and item["captureCorrelationId"] and item["captureCorrelationId"] == item["clientCorrelationId"])
        correlated += int(success)
        results.append({"id": item["id"], "correlated": success})
    passed = len(records) >= 10 and correlated >= 8
    reason = "threshold_met" if passed else ("insufficient_samples" if len(records) < 10 else "threshold_not_met")
    return passed, reason, {"eligible": len(records), "correlatedDualViewCount": correlated}, results


MINIMIZATION_FIELDS = {
    "id", "originalRequestBytes", "originalEventBytes", "minimizedRequestBytes",
    "minimizedEventBytes", "originalFingerprint", "minimizedFingerprint", "requiredInputsPreserved",
}


def _minimization(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    qualifying = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, MINIMIZATION_FIELDS, path)
        original = _int(item["originalRequestBytes"], f"{path}.originalRequestBytes") + _int(item["originalEventBytes"], f"{path}.originalEventBytes")
        minimized = _int(item["minimizedRequestBytes"], f"{path}.minimizedRequestBytes") + _int(item["minimizedEventBytes"], f"{path}.minimizedEventBytes")
        if original <= 0 or minimized > original:
            _fail("invalid_minimization_bytes", path, "original must be positive and minimized <= original")
        original_fp = _string(item["originalFingerprint"], f"{path}.originalFingerprint")
        minimized_fp = _string(item["minimizedFingerprint"], f"{path}.minimizedFingerprint")
        preserved = _bool(item["requiredInputsPreserved"], f"{path}.requiredInputsPreserved")
        reduction = (original - minimized) / original
        success = bool(preserved and original_fp == minimized_fp and reduction >= 0.30)
        qualifying += int(success)
        results.append({"id": item["id"], "reduction": reduction, "fingerprintPreserved": original_fp == minimized_fp, "qualifies": success})
    passed = len(records) >= 10 and qualifying >= 5
    reason = "threshold_met" if passed else ("insufficient_samples" if len(records) < 10 else "threshold_not_met")
    return passed, reason, {"attempted": len(records), "qualifyingReductionCount": qualifying, "minimumReduction": 0.30}, results


SECRET_SINKS = {"raw artifacts", "normalized artifacts", "reports", "logs", "temporary files", "crash output"}
SECRET_FIELDS = {"id", "sink", "scanned", "artifactDigest", "canaryDigest", "persistedLocations"}


def _secret(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    sinks: set[str] = set()
    canaries: set[str] = set()
    persisted = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, SECRET_FIELDS, path)
        sink = _string(item["sink"], f"{path}.sink", maximum=128)
        if sink in sinks:
            _fail("duplicate_sink", f"{path}.sink", sink)
        sinks.add(sink)
        scanned = _bool(item["scanned"], f"{path}.scanned")
        _sha(item["artifactDigest"], f"{path}.artifactDigest")
        canaries.add(_sha(item["canaryDigest"], f"{path}.canaryDigest"))
        locations = _strings(item["persistedLocations"], f"{path}.persistedLocations")
        persisted += len(locations)
        results.append({"id": item["id"], "sink": sink, "scanned": scanned, "persistedOccurrenceCount": len(locations)})
    passed = sinks == SECRET_SINKS and len(canaries) == 1 and all(item["scanned"] for item in results) and persisted == 0
    reason = "threshold_met" if passed else ("insufficient_samples" if sinks != SECRET_SINKS else "secret_canary_persisted")
    return passed, reason, {"scannedSinks": sorted(sinks), "persistedOccurrenceCount": persisted, "canaryDigest": next(iter(canaries), None)}, results


UNKNOWN_FIELDS = {"id", "evidenceSufficient", "evidenceDigests", "attribution"}


def _unknown(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    correct = 0
    unsupported = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, UNKNOWN_FIELDS, path)
        sufficient = _bool(item["evidenceSufficient"], f"{path}.evidenceSufficient")
        digests = item["evidenceDigests"]
        if not isinstance(digests, list):
            _fail("invalid_schema", f"{path}.evidenceDigests", "must be an array")
        for offset, digest in enumerate(digests):
            _sha(digest, f"{path}.evidenceDigests[{offset}]")
        attribution = _string(item["attribution"], f"{path}.attribution", maximum=128)
        is_correct = bool(not sufficient and attribution == "UNKNOWN_FAULT_DOMAIN")
        if not sufficient and attribution != "UNKNOWN_FAULT_DOMAIN":
            unsupported += 1
        correct += int(is_correct)
        results.append({"id": item["id"], "correctUnknown": is_correct, "unsupportedAttribution": not sufficient and not is_correct})
    passed = len(records) >= 1 and correct == len(records) and unsupported == 0
    reason = "threshold_met" if passed else ("insufficient_samples" if not records else "unsupported_attribution")
    return passed, reason, {"eligible": len(records), "correctUnknownCount": correct, "unsupportedAttributionCount": unsupported}, results


REQUIRED_DOCUMENTS = {
    "RFC-0001 compatibility layers", "RFC-0002 evidence and result schema",
    "RFC-0003 scenario and pack model", "RFC-0004 driver isolation",
    "RFC-0005 Registry trust", "Threat Model v1 candidate", "Data Policy v1 candidate",
    "Competitive Landscape", "known limitations", "naming conflict evidence",
}
DOC_FIELDS = {"id", "documentName", "path", "content", "sourceLicense"}
STABLE_CLAIM_RE = re.compile(
    r"(?i)\b(?:certified|officially|fully)\s+compatible\b|\bstable compatibility (?:guarantee|claim|badge)\b"
)


def _docs(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    names: set[str] = set()
    license_findings = []
    invalid_links = []
    stable_findings = []
    validated_links = 0
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, DOC_FIELDS, path)
        name = _string(item["documentName"], f"{path}.documentName", maximum=256)
        if name in names:
            _fail("duplicate_document", f"{path}.documentName", name)
        doc_path = _string(item["path"], f"{path}.path", maximum=1024)
        if doc_path.startswith("/") or ".." in doc_path.split("/"):
            _fail("unsafe_document_path", f"{path}.path", doc_path)
        content = _string(item["content"], f"{path}.content", maximum=1_000_000)
        license_id = _string(item["sourceLicense"], f"{path}.sourceLicense", maximum=128)
        names.add(name)
        license_ok = license_id in ALLOWED_LICENSE
        if not license_ok:
            license_findings.append(item["id"])
        links = HTTPS_IN_TEXT_RE.findall(content)
        if "http://" in content or not links:
            invalid_links.append(item["id"])
        validated_links += len(links)
        stable = bool(STABLE_CLAIM_RE.search(content))
        if stable:
            stable_findings.append(item["id"])
        results.append({"id": item["id"], "documentName": name, "contentDigest": canonical_digest(content), "licenseValid": license_ok, "validatedLinkCount": len(links), "stableClaim": stable})
    passed = names == REQUIRED_DOCUMENTS and not license_findings and not invalid_links and not stable_findings
    reason = "threshold_met" if passed else ("insufficient_samples" if names != REQUIRED_DOCUMENTS else "policy_violation")
    return passed, reason, {"requiredDocuments": sorted(names), "validatedLinks": validated_links, "licenseFindings": license_findings, "invalidLinkFindings": invalid_links, "stableClaimFindings": stable_findings}, results


AGGREGATE_CRITERIA = {
    "P00-M-BOOTSTRAP-CONTROL": "evaluator://bootstrap/control-plane/v1",
    "P00-M-ANTI-PLACEHOLDER": "evaluator://bootstrap/anti-placeholder/v1",
    "P00-M-COMPETITIVE": "evaluator://research/competitive/v1",
    "P00-M-PROVENANCE": "evaluator://catalog/provenance-count/v1",
    "P00-M-REPRO": "evaluator://corpus/reproduction/v1",
    "P00-M-TAXONOMY": "evaluator://corpus/taxonomy/v1",
    "P00-M-REPLAY": "evaluator://corpus/replay/v1",
    "P00-M-DUAL-VIEW": "evaluator://experiment/dual-view/v1",
    "P00-M-REDUCTION": "evaluator://experiment/minimization/v1",
    "P00-M-SECRET": "evaluator://redaction/secret-canary/v1",
    "P00-M-UNKNOWN": "evaluator://attribution/unknown/v1",
    "P00-M-DOCS": "evaluator://docs/license-links/v1",
}
AGGREGATE_FIELDS = {
    "id", "criterionId", "kind", "evaluator", "result", "evidenceDigest",
    "verificationPairId", "sourceCommit", "controlPlaneDigest", "evaluatorDigest",
    "datasetFreezeDigest", "datasetDigest", "verifierDigest",
}


def _aggregate(records: list[Mapping[str, Any]]) -> tuple[bool, str, dict[str, Any], list[dict[str, Any]]]:
    criteria: dict[str, Mapping[str, Any]] = {}
    evidence_digests: set[str] = set()
    results = []
    for index, raw in enumerate(records):
        path = f"records[{index}]"
        item = _exact(raw, AGGREGATE_FIELDS, path)
        criterion = _string(item["criterionId"], f"{path}.criterionId", maximum=128)
        if item["id"] != criterion:
            _fail("aggregate_record_identity_mismatch", path, "id must equal criterionId")
        if criterion in criteria:
            _fail("duplicate_criterion", f"{path}.criterionId", criterion)
        if item["kind"] != "MACHINE":
            _fail("invalid_aggregate_kind", f"{path}.kind", str(item["kind"]))
        expected = AGGREGATE_CRITERIA.get(criterion)
        if expected is None or item["evaluator"] != expected:
            _fail("aggregate_evaluator_mismatch", path, f"{criterion}/{item['evaluator']}")
        if item["result"] not in {"PASS", "FAIL", "ERROR"}:
            _fail("invalid_aggregate_result", f"{path}.result", str(item["result"]))
        for field in ("evidenceDigest", "evaluatorDigest", "datasetFreezeDigest", "datasetDigest", "verifierDigest"):
            _sha(item[field], f"{path}.{field}")
        if item["evidenceDigest"] in evidence_digests:
            _fail(
                "duplicate_child_evidence",
                f"{path}.evidenceDigest",
                "one evidence artifact cannot satisfy multiple criteria",
            )
        evidence_digests.add(item["evidenceDigest"])
        _commit(item["sourceCommit"], f"{path}.sourceCommit")
        _sha(item["controlPlaneDigest"], f"{path}.controlPlaneDigest")
        _string(item["verificationPairId"], f"{path}.verificationPairId", maximum=256)
        criteria[criterion] = item
        results.append({"id": criterion, "result": item["result"], "evidenceDigest": item["evidenceDigest"]})
    exact_set = set(criteria) == set(AGGREGATE_CRITERIA)
    all_pass = exact_set and all(item["result"] == "PASS" for item in criteria.values())
    passed = bool(all_pass)
    reason = "threshold_met" if passed else ("criterion_set_mismatch" if not exact_set else "child_criterion_not_passed")
    return passed, reason, {"phase": "P00", "criterionIds": sorted(criteria), "requiredCriterionIds": sorted(AGGREGATE_CRITERIA), "allMachineCriteriaPass": all_pass}, results


Evaluator = Callable[[list[Mapping[str, Any]]], tuple[bool, str, dict[str, Any], list[dict[str, Any]]]]
EVALUATORS: dict[str, Evaluator] = {
    "evaluator://research/competitive/v1": _competitive,
    "evaluator://catalog/provenance-count/v1": _provenance,
    "evaluator://corpus/reproduction/v1": _reproduction,
    "evaluator://corpus/taxonomy/v1": _taxonomy,
    "evaluator://corpus/replay/v1": _replay,
    "evaluator://experiment/dual-view/v1": _dual_view,
    "evaluator://experiment/minimization/v1": _minimization,
    "evaluator://redaction/secret-canary/v1": _secret,
    "evaluator://attribution/unknown/v1": _unknown,
    "evaluator://docs/license-links/v1": _docs,
    "evaluator://phase/aggregate/v1": _aggregate,
}


def _evidence(
    *,
    criterion_id: Any,
    evaluator: str,
    evaluator_digest: Any,
    source_commit: Any,
    control_plane_digest: Any,
    freeze_digest: Any,
    dataset_digest: Any,
    result: str,
    reason: str,
    pair: dict[str, Any] | None,
    recomputed: dict[str, Any],
    record_results: list[dict[str, Any]],
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    body = {
        "schemaVersion": EVIDENCE_SCHEMA,
        "criterionId": criterion_id if isinstance(criterion_id, str) else None,
        "evaluator": evaluator,
        "evaluatorDigest": evaluator_digest if isinstance(evaluator_digest, str) and SHA256_RE.fullmatch(evaluator_digest) else None,
        "sourceCommit": source_commit if isinstance(source_commit, str) and COMMIT_RE.fullmatch(source_commit) else None,
        "controlPlaneDigest": control_plane_digest if isinstance(control_plane_digest, str) and SHA256_RE.fullmatch(control_plane_digest) else None,
        "datasetFreezeDigest": freeze_digest if isinstance(freeze_digest, str) and SHA256_RE.fullmatch(freeze_digest) else None,
        "datasetDigest": dataset_digest if isinstance(dataset_digest, str) and SHA256_RE.fullmatch(dataset_digest) else None,
        "result": result,
        "reasonCode": reason,
        "runPair": pair,
        "recomputed": recomputed,
        "recordResults": record_results,
        "issues": issues,
    }
    body["evidenceDigest"] = canonical_digest(body)
    return body


def evaluate_strict(evaluator: str, payload: Any) -> dict[str, Any]:
    if evaluator not in EVALUATORS:
        _fail("unknown_evaluator", "evaluator", evaluator)
    document, records, pair = _validate_envelope(evaluator, payload)
    implementation = EVALUATORS.get(evaluator)
    if evaluator == "evaluator://phase/aggregate/v1":
        for index, record in enumerate(records):
            if (
                record.get("sourceCommit") != document["sourceCommit"]
                or record.get("controlPlaneDigest") != document["controlPlaneDigest"]
            ):
                _fail(
                    "aggregate_subject_mismatch",
                    f"records[{index}]",
                    "child evidence differs from aggregate source/control identity",
                )
    assert implementation is not None
    passed, reason, recomputed, record_results = implementation(records)
    return _evidence(
        criterion_id=document["criterionId"],
        evaluator=evaluator,
        evaluator_digest=document["evaluatorDigest"],
        source_commit=document["sourceCommit"],
        control_plane_digest=document["controlPlaneDigest"],
        freeze_digest=document["datasetFreezeDigest"],
        dataset_digest=document["datasetDigest"],
        result="PASS" if passed else "FAIL",
        reason=reason,
        pair=pair,
        recomputed=recomputed,
        record_results=record_results,
        issues=[],
    )


def evaluate(evaluator: str, payload: Any) -> dict[str, Any]:
    """Evaluate one mapping and convert every malformed input into ERROR evidence."""

    try:
        return evaluate_strict(evaluator, payload)
    except EvaluationError as exc:
        document = payload if isinstance(payload, Mapping) else {}
        return _evidence(
            criterion_id=document.get("criterionId"),
            evaluator=evaluator,
            evaluator_digest=document.get("evaluatorDigest"),
            source_commit=document.get("sourceCommit"),
            control_plane_digest=document.get("controlPlaneDigest"),
            freeze_digest=document.get("datasetFreezeDigest"),
            dataset_digest=document.get("datasetDigest"),
            result="ERROR",
            reason=exc.code,
            pair=None,
            recomputed={},
            record_results=[],
            issues=[exc.as_dict()],
        )


def evaluate_json(evaluator: str, raw: str | bytes) -> dict[str, Any]:
    """Strict JSON boundary that also detects duplicate keys and NaN/Infinity."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_json_key", key, "duplicate JSON key")
            result[key] = value
        return result

    def constant(value: str) -> None:
        _fail("non_finite_number", "document", value)

    try:
        payload = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except EvaluationError as exc:
        return _evidence(
            criterion_id=None,
            evaluator=evaluator,
            evaluator_digest=None,
            source_commit=None,
            control_plane_digest=None,
            freeze_digest=None,
            dataset_digest=None,
            result="ERROR",
            reason=exc.code,
            pair=None,
            recomputed={},
            record_results=[],
            issues=[exc.as_dict()],
        )
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        issue = EvaluationError("invalid_json", "document", str(exc))
        return _evidence(
            criterion_id=None,
            evaluator=evaluator,
            evaluator_digest=None,
            source_commit=None,
            control_plane_digest=None,
            freeze_digest=None,
            dataset_digest=None,
            result="ERROR",
            reason=issue.code,
            pair=None,
            recomputed={},
            record_results=[],
            issues=[issue.as_dict()],
        )
    return evaluate(evaluator, payload)


__all__ = [
    "AGGREGATE_CRITERIA",
    "EVALUATOR_CRITERIA",
    "EVALUATORS",
    "EVIDENCE_SCHEMA",
    "EvaluationError",
    "build_paired_input",
    "canonical_digest",
    "evaluate",
    "evaluate_json",
    "evaluate_strict",
]
