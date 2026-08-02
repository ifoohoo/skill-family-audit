"""Compose deterministic public behavior-audit envelopes without publishing them."""

from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    from . import behavior_contracts, behavior_domain, behavior_evidence
except ImportError:  # pragma: no cover - direct script-directory loading
    import behavior_contracts  # type: ignore[no-redef]
    import behavior_domain  # type: ignore[no-redef]
    import behavior_evidence  # type: ignore[no-redef]


_REQUIRED_CONTEXT = (
    "run_id",
    "operation_id",
    "stage_id",
    "authorization_ref",
    "acceptance_ref",
    "isolation_profile",
    "workspace_root",
    "output_dir",
    "output_workspace_scope",
    "write_set",
    "budget",
    "inputs",
    "process_id",
    "lease_deadline",
    "usage",
    "target_project_path",
    "environment_digest",
    "implementation_digest",
    "executor_id",
)


class BehaviorPublicError(Exception):
    """Raised when a public bundle cannot be composed and validated."""

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


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _output_path(output_dir: str, filename: str) -> str:
    return f"{output_dir.rstrip('/')}/{filename}"


def _resource(
    *,
    resource_id: str,
    name: str,
    kind: str,
    path: str,
    digest: str,
    workspace_scope: str,
) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "name": name,
        "kind": kind,
        "path": path,
        "required": True,
        "content_digest": digest,
        "access": "authorized_write",
        "workspace_scope": workspace_scope,
    }


def _derive_side_effects(
    fixtures: list[dict[str, Any]],
    ordered_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    effects: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def append(kind: str, target: str, status: str, effect_id: str) -> None:
        identity = (kind, target, status)
        if identity in seen:
            return
        seen.add(identity)
        effects.append(
            {
                "side_effect_id": effect_id,
                "kind": kind,
                "target": target,
                "status": status,
                "reversible": kind != "command_execute",
            }
        )

    for sequence, (fixture, record) in enumerate(zip(fixtures, ordered_records)):
        fixture_id = fixture["fixture_id"]
        append(
            "command_execute",
            record["executable"],
            "COMMITTED",
            f"behavior:{sequence}:{fixture_id}:command",
        )

        cleanup_status = record.get("cleanup_status")
        for write_index, path in enumerate(fixture.get("write_set") or []):
            append(
                "file_create",
                path,
                "ROLLED_BACK" if cleanup_status == "OK" else "UNKNOWN",
                f"behavior:{sequence}:{fixture_id}:write:{write_index}",
            )

        target_diff = record.get("target_diff")
        sandbox_diff = record.get("sandbox_diff")
        unknown_writes = record.get("unknown_writes")
        if not isinstance(target_diff, dict):
            raise BehaviorPublicError([f"record {fixture_id}.target_diff is required"])
        if not isinstance(sandbox_diff, dict):
            raise BehaviorPublicError([f"record {fixture_id}.sandbox_diff is required"])
        if not isinstance(unknown_writes, list):
            raise BehaviorPublicError([f"record {fixture_id}.unknown_writes is required"])

        for change, kind in (
            ("added", "file_create"),
            ("modified", "file_modify"),
            ("removed", "file_delete"),
        ):
            paths = target_diff.get(change)
            if not isinstance(paths, list):
                raise BehaviorPublicError(
                    [f"record {fixture_id}.target_diff.{change} must be an array"]
                )
            for change_index, path in enumerate(paths):
                append(
                    kind,
                    path,
                    "UNKNOWN",
                    f"behavior:{sequence}:{fixture_id}:target:{change}:{change_index}",
                )

        for unknown_index, path in enumerate(unknown_writes):
            kind = "file_modify"
            if path in sandbox_diff.get("added", []):
                kind = "file_create"
            elif path in sandbox_diff.get("removed", []):
                kind = "file_delete"
            append(
                kind,
                path,
                "UNKNOWN",
                f"behavior:{sequence}:{fixture_id}:unknown:{unknown_index}",
            )
    return effects


def _validate_input_bindings(
    *,
    inputs: Any,
    target_project_path: Any,
    manifest_path: Any,
) -> list[str]:
    if not isinstance(inputs, list):
        return ["runtime_context.inputs must be an array"]
    by_name = {
        item.get("name"): item
        for item in inputs
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    errors: list[str] = []
    expected = {
        "target_project_path": target_project_path,
        "fixture_manifest": manifest_path,
    }
    for name, path in expected.items():
        item = by_name.get(name)
        if item is None:
            errors.append(f"runtime_context.inputs lacks {name}")
        elif item.get("path") != path:
            errors.append(f"runtime_context.inputs.{name} path does not match")
    return errors


def build_public_bundle(
    *,
    plan: dict[str, Any],
    execution_records: list[dict[str, Any]],
    domain_outputs: dict[str, Any],
    runtime_context: dict[str, Any],
) -> dict[str, Any]:
    """Build validated public envelopes and six deterministic artifact payloads."""

    errors: list[str] = []
    if not isinstance(runtime_context, dict):
        raise BehaviorPublicError(["runtime_context must be an object"])
    for field in _REQUIRED_CONTEXT:
        if field not in runtime_context:
            errors.append(f"runtime_context.{field} is required")

    if set(domain_outputs) != {"behavior_result", "regression_record"}:
        errors.append(
            "domain_outputs must contain exactly behavior_result and regression_record"
        )
    try:
        recomputed_domain = behavior_domain.build_domain_outputs(
            plan=plan,
            execution_records=execution_records,
        )
    except behavior_domain.BehaviorDomainError as exc:
        errors.extend(exc.errors)
        recomputed_domain = None
    if recomputed_domain is not None and domain_outputs != recomputed_domain:
        errors.append("domain_outputs do not match behavior_domain recomputation")

    summary = plan.get("manifest_summary") if isinstance(plan, dict) else None
    candidate_id = summary.get("candidate_id") if isinstance(summary, dict) else None
    behavior_result = domain_outputs.get("behavior_result")
    if not isinstance(behavior_result, dict):
        errors.append("domain_outputs.behavior_result must be an object")
    elif behavior_result.get("candidate_id") != candidate_id:
        errors.append("domain candidate_id does not match plan.manifest_summary")

    fixtures = plan.get("fixtures") if isinstance(plan, dict) else None
    if not isinstance(fixtures, list):
        errors.append("plan.fixtures must be an array")
        fixtures = []
    record_by_id: dict[str, dict[str, Any]] = {}
    if isinstance(execution_records, list):
        for record in execution_records:
            if isinstance(record, dict) and isinstance(record.get("fixture_id"), str):
                record_by_id[record["fixture_id"]] = record
    ordered_records = [
        record_by_id.get(fixture.get("fixture_id"))
        for fixture in fixtures
        if isinstance(fixture, dict)
    ]
    if any(record is None for record in ordered_records):
        errors.append("execution records cannot be ordered by the plan fixture identities")
    if not isinstance(plan.get("manifest") if isinstance(plan, dict) else None, dict):
        errors.append("plan.manifest must be an object")
    manifest_path = plan.get("manifest_path") if isinstance(plan, dict) else None
    if not isinstance(manifest_path, str) or not manifest_path:
        errors.append("plan.manifest_path must be a non-empty string")
    errors.extend(
        _validate_input_bindings(
            inputs=runtime_context.get("inputs"),
            target_project_path=runtime_context.get("target_project_path"),
            manifest_path=manifest_path,
        )
    )

    if errors:
        raise BehaviorPublicError(errors)

    output_dir = runtime_context["output_dir"]
    if not isinstance(output_dir, str) or not output_dir:
        raise BehaviorPublicError(["runtime_context.output_dir must be non-empty"])

    try:
        evidence_items = behavior_evidence.build_execution_evidence_refs(
            plan=plan,
            execution_records=execution_records,
            run_id=runtime_context["run_id"],
            environment_digest=runtime_context["environment_digest"],
            implementation_digest=runtime_context["implementation_digest"],
            executor_id=runtime_context["executor_id"],
            execution_records_path=_output_path(
                output_dir,
                "execution-records.json",
            ),
        )
        method_payloads = {
            "behavior-result.json": _json_bytes(domain_outputs["behavior_result"]),
            "execution-records.json": _json_bytes(ordered_records),
            "evidence-list.json": _json_bytes(evidence_items),
            "regression-record.json": _json_bytes(
                domain_outputs["regression_record"]
            ),
        }
        side_effects = _derive_side_effects(fixtures, ordered_records)
    except (
        behavior_evidence.BehaviorEvidenceError,
        TypeError,
        ValueError,
    ) as exc:
        nested_errors = getattr(exc, "errors", [str(exc)])
        raise BehaviorPublicError(list(nested_errors)) from exc

    scope = runtime_context["output_workspace_scope"]
    output_resources = {
        "behavior_result": _resource(
            resource_id="behavior-result",
            name="behavior_result",
            kind="domain_result",
            path=_output_path(output_dir, "behavior-result.json"),
            digest=_digest(method_payloads["behavior-result.json"]),
            workspace_scope=scope,
        ),
        "execution_records": _resource(
            resource_id="behavior-execution-records",
            name="execution_records",
            kind="artifact",
            path=_output_path(output_dir, "execution-records.json"),
            digest=_digest(method_payloads["execution-records.json"]),
            workspace_scope=scope,
        ),
        "evidence_list": _resource(
            resource_id="behavior-evidence-list",
            name="evidence_list",
            kind="artifact",
            path=_output_path(output_dir, "evidence-list.json"),
            digest=_digest(method_payloads["evidence-list.json"]),
            workspace_scope=scope,
        ),
        "regression_record": _resource(
            resource_id="behavior-regression-record",
            name="regression_record",
            kind="artifact",
            path=_output_path(output_dir, "regression-record.json"),
            digest=_digest(method_payloads["regression-record.json"]),
            workspace_scope=scope,
        ),
    }

    task = behavior_contracts.build_task_envelope(
        run_id=runtime_context["run_id"],
        operation_id=runtime_context["operation_id"],
        stage_id=runtime_context["stage_id"],
        authorization_ref=runtime_context["authorization_ref"],
        acceptance_ref=runtime_context["acceptance_ref"],
        isolation_profile=runtime_context["isolation_profile"],
        workspace_root=runtime_context["workspace_root"],
        output_dir=output_dir,
        write_set=runtime_context["write_set"],
        budget=runtime_context["budget"],
        parameters={
            "target_project_path": runtime_context["target_project_path"],
            "fixture_manifest": plan["manifest"],
            "platform_selector": summary["platform_selector"],
            "model_selector": summary["model_selector"],
            "scope_selector": summary["scope_selector"],
        },
        inputs=runtime_context["inputs"],
        expected_outputs=list(output_resources.values()),
        process_id=runtime_context["process_id"],
        lease_deadline=runtime_context["lease_deadline"],
    )
    result = behavior_contracts.build_result_envelope(
        run_id=runtime_context["run_id"],
        stage_id=runtime_context["stage_id"],
        execution_status=behavior_result["overall_status"],
        summary=(
            "行为审计全部 fixture 通过"
            if behavior_result["overall_status"] == "SUCCEEDED"
            else "行为审计存在未通过 fixture"
        ),
        outputs=[
            output_resources["execution_records"],
            output_resources["regression_record"],
        ],
        domain_results=[
            {
                "protocol_id": "skill-family-audit:behavior-result",
                "protocol_version": "1.0.0-candidate",
                "result_path": output_resources["behavior_result"]["path"],
                "content_digest": output_resources["behavior_result"]["content_digest"],
            }
        ],
        evidence=evidence_items,
        missing_inputs=[],
        warnings=[],
        errors=[],
        side_effects=side_effects,
        usage=runtime_context["usage"],
    )

    try:
        behavior_contracts.assert_valid_envelope(task, result, evidence_items)
    except behavior_contracts.EnvelopeValidationError as exc:
        raise BehaviorPublicError(exc.errors) from exc

    artifact_bytes = {
        "task.json": _json_bytes(task),
        "result.json": _json_bytes(result),
        **method_payloads,
    }
    return {
        "task": task,
        "result": result,
        "evidence_items": evidence_items,
        "artifact_bytes": artifact_bytes,
    }
