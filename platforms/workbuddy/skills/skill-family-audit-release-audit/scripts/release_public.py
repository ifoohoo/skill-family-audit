"""Compose Audit-owned release findings and evidence in memory.

Foundation Quickstart owns the operation request/result exchange. This module
combines the thin upstream-verifier consumption with the release assessment
rows into one domain result object; it never reimplements release semantics.
"""

from __future__ import annotations

from typing import Any


class ReleasePublicError(Exception):
    """Release-domain output cannot be composed without ambiguity."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


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


def _compose_domain_result(
    *,
    expected_unit_id: str,
    expected_target_version: str,
    verifier_audit: dict[str, Any],
    assessment_result: dict[str, Any] | None = None,
    assessments_path: str | None = None,
) -> dict[str, Any]:
    """Compose the thin upstream-verifier result with release assessments.

    模块私有组合函数：只消费 receipt 审计结果，不构成公共调用入口，
    不得绕过已封闭的上游消费契约构造 SUCCEEDED。
    """

    if not isinstance(verifier_audit, dict):
        raise ReleasePublicError(["verifier_audit 必须是领域结果对象"])
    if (
        verifier_audit.get("status")
        not in {"SUCCEEDED", "BLOCKED", "FAILED"}
    ):
        raise ReleasePublicError(["verifier_audit.status 无效"])
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
        (verifier_audit["status"], assessment_status),
        key=lambda item: status_order[item],
    )
    assessment_blockers = [
        f"{name}:{row.get('status')}"
        for name, row in _assessment_rows(assessment_result or {})
        if row.get("status") not in {"valid", "exception_pass", "not_applicable"}
    ]
    gate_findings = list(verifier_audit["gate_findings"])
    blocking_reasons = list(verifier_audit["blocking_reasons"])
    if assessment_status == "FAILED":
        gate_findings.extend(assessment_blockers)
    elif assessment_status == "BLOCKED":
        blocking_reasons.extend(assessment_blockers)

    evidence = [
        {"source": "release-skill", **item}
        for item in verifier_audit.get("evidence", [])
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
        "receipt_audit": verifier_audit,
        "assessments": assessment_result,
        "source_results_reexecuted": False,
    }
    return {
        "release_result": release_result,
        "gate_findings": gate_findings,
        "evidence_list": evidence,
        "blocking_reasons": blocking_reasons,
    }


__all__ = ["ReleasePublicError"]
