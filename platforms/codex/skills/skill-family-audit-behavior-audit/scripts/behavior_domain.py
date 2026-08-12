"""Build deterministic behavior-audit domain results from verified in-memory inputs.

This module owns only domain conservation and adjudication.  It does not build
public envelopes, assign evidence credibility, read the filesystem, execute a
fixture, or publish artifacts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


_VALID_STATUSES = frozenset({"SUCCEEDED", "FAILED"})
_PROCESS_FACT_FIELDS = (
    "executable",
    "argv",
    "cwd",
    "start_time",
    "end_time",
    "duration_seconds",
    "exit_code",
    "timed_out",
    "launch_error",
    "timeout_seconds",
    "stdout_sha256",
    "stderr_sha256",
)
_MANIFEST_FIELDS = (
    "candidate_id",
    "candidate_digest",
    "platform_selector",
    "model_selector",
    "scope_selector",
)


class BehaviorDomainError(Exception):
    """Raised when domain inputs violate one or more conservation rules."""

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


def _recomputed_status(record: dict[str, Any]) -> str:
    succeeded = (
        record.get("expected_judgment") == "PASS"
        and record.get("timed_out") is False
        and record.get("launch_error") is None
        and record.get("side_effect_status") == "CLEAN"
        and record.get("cleanup_status") == "OK"
    )
    return "SUCCEEDED" if succeeded else "FAILED"


def _validate_manifest_summary(
    plan: dict[str, Any],
    errors: list[str],
) -> dict[str, str]:
    summary = plan.get("manifest_summary")
    if not isinstance(summary, dict):
        errors.append("plan.manifest_summary must be an object")
        return {}

    values: dict[str, str] = {}
    for field in _MANIFEST_FIELDS:
        value = summary.get(field)
        if not isinstance(value, str) or not value:
            errors.append(f"plan.manifest_summary.{field} must be a non-empty string")
        else:
            values[field] = value
    return values


def _validate_plan_fixtures(
    plan: dict[str, Any],
    errors: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    fixtures = plan.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        errors.append("plan.fixtures must be a non-empty array")
        return [], []

    ordered_ids: list[str] = []
    seen: set[str] = set()
    valid_fixtures: list[dict[str, Any]] = []
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict):
            errors.append(f"plan.fixtures[{index}] must be an object")
            continue
        fixture_id = fixture.get("fixture_id")
        category = fixture.get("category")
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(f"plan.fixtures[{index}].fixture_id must be a non-empty string")
            continue
        if fixture_id in seen:
            errors.append(f"duplicate plan fixture_id: {fixture_id}")
            continue
        if not isinstance(category, str) or not category:
            errors.append(
                f"plan fixture {fixture_id}.category must be a non-empty string"
            )
            continue
        seen.add(fixture_id)
        ordered_ids.append(fixture_id)
        valid_fixtures.append(fixture)
    return valid_fixtures, ordered_ids


def _index_records(
    execution_records: list[dict[str, Any]],
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    if not isinstance(execution_records, list):
        errors.append("execution_records must be an array")
        return {}

    indexed: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(execution_records):
        if not isinstance(record, dict):
            errors.append(f"execution_records[{index}] must be an object")
            continue
        fixture_id = record.get("fixture_id")
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(
                f"execution_records[{index}].fixture_id must be a non-empty string"
            )
            continue
        if fixture_id in indexed:
            errors.append(f"duplicate execution fixture_id: {fixture_id}")
            continue
        indexed[fixture_id] = record
    return indexed


def build_domain_outputs(
    *,
    plan: dict[str, Any],
    execution_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return deterministic behavior and regression domain objects.

    Any identity drift, malformed normalized input, or contradiction between a
    record's reported status and the independently recomputed status fails
    closed with :class:`BehaviorDomainError`.
    """

    errors: list[str] = []
    if not isinstance(plan, dict):
        raise BehaviorDomainError(["plan must be an object"])

    manifest = _validate_manifest_summary(plan, errors)
    fixtures, ordered_fixture_ids = _validate_plan_fixtures(plan, errors)
    records_by_id = _index_records(execution_records, errors)

    plan_ids = set(ordered_fixture_ids)
    record_ids = set(records_by_id)
    missing = sorted(plan_ids - record_ids)
    unknown = sorted(record_ids - plan_ids)
    if missing:
        errors.append(f"missing execution fixture_ids: {missing}")
    if unknown:
        errors.append(f"unknown execution fixture_ids: {unknown}")

    recomputed: dict[str, str] = {}
    record_digests: dict[str, str] = {}
    fixture_by_id = {fixture["fixture_id"]: fixture for fixture in fixtures}
    for fixture_id in ordered_fixture_ids:
        record = records_by_id.get(fixture_id)
        if record is None:
            continue

        if record.get("category") != fixture_by_id[fixture_id]["category"]:
            errors.append(
                f"record {fixture_id}.category does not match the plan category"
            )
        status = record.get("status")
        if status not in _VALID_STATUSES:
            errors.append(f"record {fixture_id}.status is invalid: {status!r}")
            continue

        for field in _PROCESS_FACT_FIELDS:
            if field not in record:
                errors.append(f"record {fixture_id}.{field} is missing")
        if not isinstance(record.get("timed_out"), bool):
            errors.append(f"record {fixture_id}.timed_out must be a boolean")
        if record.get("launch_error") is not None and not isinstance(
            record.get("launch_error"), str
        ):
            errors.append(f"record {fixture_id}.launch_error must be null or a string")

        calculated = _recomputed_status(record)
        recomputed[fixture_id] = calculated
        if calculated != status:
            errors.append(
                f"record {fixture_id} reports {status} but recomputes to {calculated}"
            )

        try:
            record_digests[fixture_id] = _canonical_digest(record)
        except (TypeError, ValueError) as exc:
            errors.append(f"record {fixture_id} is not canonical JSON: {exc}")

    if errors:
        raise BehaviorDomainError(errors)

    category_rows: list[dict[str, Any]] = []
    category_index: dict[str, int] = {}
    for fixture_id in ordered_fixture_ids:
        category = fixture_by_id[fixture_id]["category"]
        if category not in category_index:
            category_index[category] = len(category_rows)
            category_rows.append(
                {
                    "category": category,
                    "fixture_ids": [],
                    "succeeded": 0,
                    "failed": 0,
                }
            )
        row = category_rows[category_index[category]]
        row["fixture_ids"].append(fixture_id)
        if recomputed[fixture_id] == "SUCCEEDED":
            row["succeeded"] += 1
        else:
            row["failed"] += 1

    overall_status = (
        "SUCCEEDED"
        if all(recomputed[fixture_id] == "SUCCEEDED" for fixture_id in ordered_fixture_ids)
        else "FAILED"
    )
    behavior_result = {
        "overall_status": overall_status,
        **manifest,
        "fixture_ids": list(ordered_fixture_ids),
        "category_coverage": category_rows,
    }

    regression_record: list[dict[str, Any]] = []
    for fixture_id in ordered_fixture_ids:
        fixture = fixture_by_id[fixture_id]
        record = records_by_id[fixture_id]
        regression_record.append(
            {
                "fixture_id": fixture_id,
                "category": fixture["category"],
                "final_status": recomputed[fixture_id],
                "expected_judgment": record.get("expected_judgment"),
                "process": {
                    field: record.get(field) for field in _PROCESS_FACT_FIELDS
                },
                "side_effect_status": record.get("side_effect_status"),
                "cleanup_status": record.get("cleanup_status"),
                "record_json_sha256": record_digests[fixture_id],
            }
        )

    return {
        "behavior_result": behavior_result,
        "regression_record": regression_record,
    }
