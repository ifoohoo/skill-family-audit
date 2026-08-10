"""Build behavior-domain evidence in fixture execution order."""

from __future__ import annotations

import re
from typing import Any


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = "skill-family-audit-behavior:execution-engine"


class BehaviorEvidenceError(Exception):
    """Raised when execution evidence cannot be represented without ambiguity."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


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
    """Return Audit-owned evidence interpretations in plan fixture order.

    These records deliberately are not generic Resource/evidence envelopes. The
    Foundation Quickstart runner owns that transport layer.
    """

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

    if errors:
        raise BehaviorEvidenceError(errors)

    refs: list[dict[str, Any]] = []
    for sequence, fixture_id in enumerate(ordered_ids):
        record = indexed[fixture_id]
        ref = {
            "fixture_id": fixture_id,
            "sequence": sequence,
            "source": _SOURCE,
            "candidate_id": candidate_id,
            "run_id": run_id,
            "record_path": f"{execution_records_path}#/{sequence}",
            "environment_digest": environment_digest,
            "implementation_digest": implementation_digest,
            "executor_id": executor_id,
            "status": record.get("status"),
            "exit_code": record.get("exit_code"),
        }
        refs.append(ref)
    return refs
