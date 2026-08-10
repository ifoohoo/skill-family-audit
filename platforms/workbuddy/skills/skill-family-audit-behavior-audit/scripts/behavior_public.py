"""Compose Audit-owned behavior findings and evidence.

The module intentionally does not create Task, Result, Resource, side-effect,
usage, or control-channel envelopes. Quickstart delegates those generic
mechanics to the Foundation candidate runner.
"""

from __future__ import annotations

import json
from typing import Any

try:
    from . import behavior_domain, behavior_evidence
except ImportError:  # pragma: no cover - direct script-directory loading
    import behavior_domain  # type: ignore[no-redef]
    import behavior_evidence  # type: ignore[no-redef]


class BehaviorPublicError(Exception):
    """Raised when behavior-domain output cannot be composed."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _ordered_records(
    plan: dict[str, Any], execution_records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    fixtures = plan.get("fixtures")
    if not isinstance(fixtures, list):
        raise BehaviorPublicError(["plan.fixtures must be an array"])
    indexed = {
        record.get("fixture_id"): record
        for record in execution_records
        if isinstance(record, dict) and isinstance(record.get("fixture_id"), str)
    }
    ordered = [indexed.get(fixture.get("fixture_id")) for fixture in fixtures]
    if any(record is None for record in ordered):
        raise BehaviorPublicError(
            ["execution records cannot be ordered by fixture identity"]
        )
    return [record for record in ordered if isinstance(record, dict)]


def build_public_bundle(
    *,
    plan: dict[str, Any],
    execution_records: list[dict[str, Any]],
    domain_outputs: dict[str, Any],
    runtime_context: dict[str, Any],
) -> dict[str, Any]:
    """Build the four behavior-domain outputs consumed by Foundation Result."""

    recomputed = behavior_domain.build_domain_outputs(
        plan=plan,
        execution_records=execution_records,
    )
    if domain_outputs != recomputed:
        raise BehaviorPublicError(
            ["domain_outputs do not match behavior_domain recomputation"]
        )
    ordered_records = _ordered_records(plan, execution_records)
    output_dir = runtime_context.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        raise BehaviorPublicError(["runtime_context.output_dir is required"])
    evidence = behavior_evidence.build_execution_evidence_refs(
        plan=plan,
        execution_records=ordered_records,
        run_id=str(runtime_context.get("run_id", "behavior-audit")),
        environment_digest=str(runtime_context.get("environment_digest", "")),
        implementation_digest=str(runtime_context.get("implementation_digest", "")),
        executor_id=str(runtime_context.get("executor_id", "")),
        execution_records_path=f"{output_dir.rstrip('/')}/execution-records.json",
    )
    result = {
        "behavior_result": domain_outputs["behavior_result"],
        "execution_records": ordered_records,
        "evidence_list": evidence,
        "regression_record": domain_outputs["regression_record"],
    }
    return {
        "domain_result": result,
        "artifact_bytes": {
            "behavior-result.json": _json_bytes(result["behavior_result"]),
            "execution-records.json": _json_bytes(result["execution_records"]),
            "evidence-list.json": _json_bytes(result["evidence_list"]),
            "regression-record.json": _json_bytes(result["regression_record"]),
        },
    }


__all__ = ["BehaviorPublicError", "build_public_bundle"]
