"""Compose Audit-owned release findings and evidence.

Foundation Quickstart owns the operation request/result exchange. This module
recomputes only release-domain decisions and serializes their four outputs.
"""

from __future__ import annotations

import json
import os
from typing import Any

try:
    from . import release_receipts
except ImportError:  # pragma: no cover - direct script-directory loading
    import release_receipts  # type: ignore[no-redef]


FILENAMES = (
    "release-result.json",
    "gate-findings.json",
    "evidence-list.json",
    "blocking-reasons.json",
)


class ReleasePublicError(Exception):
    """Release-domain output cannot be composed without ambiguity."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _absolute(value: Any, label: str) -> str:
    if not isinstance(value, str) or not os.path.isabs(value):
        raise ReleasePublicError([f"{label} 必须是绝对路径"])
    return value


def _assessment_rows(value: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    assessments = value.get("assessments", {})
    if not isinstance(assessments, dict):
        return []
    rows = [
        (name, row)
        for name, row in assessments.items()
        if name != "platforms" and isinstance(row, dict)
    ]
    platforms = assessments.get("platforms", {})
    if isinstance(platforms, dict):
        rows.extend(
            (f"platform:{name}", row)
            for name, row in platforms.items()
            if isinstance(row, dict)
        )
    return sorted(rows)


def build_public_bundle(
    *,
    provider_root: str,
    plan_path: str | None,
    run_path: str | None,
    expected_unit_id: str,
    expected_target_version: str,
    claimed_audit: dict[str, Any],
    runtime_context: dict[str, Any],
    assessment_result: dict[str, Any] | None = None,
    assessments_path: str | None = None,
) -> dict[str, Any]:
    """Recompute the release decision and return four domain outputs."""

    provider_root = _absolute(provider_root, "provider_root")
    if plan_path is not None:
        plan_path = _absolute(plan_path, "plan_path")
    if run_path is not None:
        run_path = _absolute(run_path, "run_path")
    if assessments_path is not None:
        assessments_path = _absolute(assessments_path, "assessments_path")
    if not isinstance(runtime_context, dict):
        raise ReleasePublicError(["runtime_context 必须是对象"])

    recomputed = release_receipts.audit_release_receipts(
        provider_root=provider_root,
        plan_path=plan_path,
        run_path=run_path,
        expected_unit_id=expected_unit_id,
        expected_target_version=expected_target_version,
    )
    if claimed_audit != recomputed:
        raise ReleasePublicError(["claimed_audit 与领域验证器重新计算结果不一致"])
    if (assessment_result is None) != (assessments_path is None):
        raise ReleasePublicError(["assessment_result 与 assessments_path 必须同时提供"])

    assessment_status = (
        "SUCCEEDED"
        if assessment_result is None
        else assessment_result.get("execution_status")
    )
    if assessment_status not in {"SUCCEEDED", "BLOCKED", "FAILED"}:
        raise ReleasePublicError(["assessment_result.execution_status 无效"])
    status_order = {"SUCCEEDED": 0, "BLOCKED": 1, "FAILED": 2}
    status = max(
        (recomputed["status"], assessment_status),
        key=lambda item: status_order[item],
    )
    assessment_blockers = [
        f"{name}:{row.get('status')}"
        for name, row in _assessment_rows(assessment_result or {})
        if row.get("status") not in {"valid", "exception_pass", "not_applicable"}
    ]
    gate_findings = list(recomputed["gate_findings"])
    blocking_reasons = list(recomputed["blocking_reasons"])
    if assessment_status == "FAILED":
        gate_findings.extend(assessment_blockers)
    elif assessment_status == "BLOCKED":
        blocking_reasons.extend(assessment_blockers)

    evidence = [
        {"source": "release-skill", **item}
        for item in recomputed.get("evidence", [])
        if isinstance(item, dict)
    ]
    evidence.extend(
        {
            "source": "release-assessment",
            "name": name,
            "path": row.get("path"),
            "digest": row.get("digest"),
            "status": row.get("status"),
        }
        for name, row in _assessment_rows(assessment_result or {})
        if isinstance(row.get("path"), str)
    )
    release_result = {
        "protocol_id": "skill-family-audit:release-audit",
        "protocol_version": "1.0.0-candidate",
        "status": status,
        "candidate_id": f"{expected_unit_id}:{expected_target_version}",
        "receipt_audit": recomputed,
        "assessments": assessment_result,
        "source_results_reexecuted": False,
    }
    domain_result = {
        "release_result": release_result,
        "gate_findings": gate_findings,
        "evidence_list": evidence,
        "blocking_reasons": blocking_reasons,
    }
    values = {
        "release-result.json": release_result,
        "gate-findings.json": gate_findings,
        "evidence-list.json": evidence,
        "blocking-reasons.json": blocking_reasons,
    }
    return {
        "domain_result": domain_result,
        "artifact_bytes": {name: _json_bytes(value) for name, value in values.items()},
    }


__all__ = ["FILENAMES", "ReleasePublicError", "build_public_bundle"]
