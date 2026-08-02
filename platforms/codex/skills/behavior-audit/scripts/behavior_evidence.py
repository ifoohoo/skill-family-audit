"""Build conservative public evidence references for behavior execution records."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

try:
    from . import behavior_contracts
except ImportError:  # pragma: no cover - direct script-directory loading
    import behavior_contracts  # type: ignore[no-redef]


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_METHOD_ID = "skill-family-audit:behavior-audit"
_SOURCE = "skill-family-audit-behavior:execution-engine"


class BehaviorEvidenceError(Exception):
    """Raised when execution evidence cannot be represented without ambiguity."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_execution_evidence_refs(
    *,
    plan: dict[str, Any],
    execution_records: list[dict[str, Any]],
    run_id: str,
    environment_digest: str,
    implementation_digest: str,
    executor_id: str,
    execution_records_path: str,
) -> list[dict[str, Any]]:
    """Return schema-valid evidence references in plan fixture order."""

    errors: list[str] = []
    for name, value in (
        ("run_id", run_id),
        ("executor_id", executor_id),
        ("execution_records_path", execution_records_path),
    ):
        if not isinstance(value, str) or not value:
            errors.append(f"{name} must be a non-empty string")
    for name, value in (
        ("environment_digest", environment_digest),
        ("implementation_digest", implementation_digest),
    ):
        if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
            errors.append(f"{name} must be a 64-character lowercase SHA-256")

    summary = plan.get("manifest_summary") if isinstance(plan, dict) else None
    candidate_id = summary.get("candidate_id") if isinstance(summary, dict) else None
    if not isinstance(candidate_id, str) or not candidate_id:
        errors.append("plan.manifest_summary.candidate_id must be a non-empty string")

    fixtures = plan.get("fixtures") if isinstance(plan, dict) else None
    if not isinstance(fixtures, list) or not fixtures:
        errors.append("plan.fixtures must be a non-empty array")
        fixtures = []

    ordered_ids: list[str] = []
    plan_seen: set[str] = set()
    for index, fixture in enumerate(fixtures):
        fixture_id = fixture.get("fixture_id") if isinstance(fixture, dict) else None
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(f"plan.fixtures[{index}].fixture_id is invalid")
        elif fixture_id in plan_seen:
            errors.append(f"duplicate plan fixture_id: {fixture_id}")
        else:
            plan_seen.add(fixture_id)
            ordered_ids.append(fixture_id)

    indexed: dict[str, dict[str, Any]] = {}
    if not isinstance(execution_records, list):
        errors.append("execution_records must be an array")
    else:
        for index, record in enumerate(execution_records):
            fixture_id = record.get("fixture_id") if isinstance(record, dict) else None
            if not isinstance(fixture_id, str) or not fixture_id:
                errors.append(f"execution_records[{index}].fixture_id is invalid")
            elif fixture_id in indexed:
                errors.append(f"duplicate execution fixture_id: {fixture_id}")
            else:
                indexed[fixture_id] = record

    missing = sorted(plan_seen - set(indexed))
    unknown = sorted(set(indexed) - plan_seen)
    if missing:
        errors.append(f"missing execution fixture_ids: {missing}")
    if unknown:
        errors.append(f"unknown execution fixture_ids: {unknown}")

    content_digests: dict[str, str] = {}
    for fixture_id in ordered_ids:
        record = indexed.get(fixture_id)
        if record is None:
            continue
        try:
            content_digests[fixture_id] = _canonical_digest(record)
        except (TypeError, ValueError) as exc:
            errors.append(f"record {fixture_id} is not canonical JSON: {exc}")

    if errors:
        raise BehaviorEvidenceError(errors)

    schemas = behavior_contracts.load_contract_schemas()
    registry = behavior_contracts.build_contract_registry(schemas)
    refs: list[dict[str, Any]] = []
    for sequence, fixture_id in enumerate(ordered_ids):
        ref = {
            "evidence_id": f"behavior-execution:{run_id}:{fixture_id}",
            "kind": "execution_record",
            "path": f"{execution_records_path}#/{sequence}",
            "source": _SOURCE,
            "candidate_id": candidate_id,
            "task_id": run_id,
            "environment_digest": environment_digest,
            "rule_ref": _METHOD_ID,
            "implementation_digest": implementation_digest,
            "executor_id": executor_id,
            "sequence_number": sequence,
            "content_digest": content_digests[fixture_id],
            "credibility": "self_reported",
        }
        schema_errors = behavior_contracts.validate_contract(
            ref,
            "evidence-ref",
            schemas,
            registry,
        )
        if schema_errors:
            errors.extend(
                f"fixture {fixture_id}: {schema_error}"
                for schema_error in schema_errors
            )
        refs.append(ref)

    if errors:
        raise BehaviorEvidenceError(errors)
    return refs
