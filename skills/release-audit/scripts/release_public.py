"""Compose deterministic public release-audit envelopes without publishing."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

try:
    from . import release_receipts
except ImportError:  # pragma: no cover - direct script-directory loading
    import release_receipts  # type: ignore[no-redef]


CONTRACT_NAMES = (
    "task",
    "result",
    "evidence-ref",
    "error",
    "resource",
    "side-effect",
    "usage",
    "budget",
    "control-channel",
)
METHOD_ID = "skill-family-audit:release-audit"
SCHEMA_VERSION = "1.1.0-candidate"
PROTOCOL_ID = "skill-family-audit:release-result"
PROTOCOL_VERSION = "1.0.0-candidate"
FILENAMES = (
    "release-result.json",
    "gate-findings.json",
    "evidence-list.json",
    "blocking-reasons.json",
)
def contract_root() -> Path:
    """Resolve the projected shared contract root or the source authority."""

    script_path = Path(__file__).resolve()
    for root in script_path.parents:
        projected = root / "shared" / "contracts"
        if (root / "platform-manifest.json").is_file() and projected.is_dir():
            return projected
    source_root = script_path.parents[4] / "spec" / "contracts"
    if source_root.is_dir():
        return source_root
    raise FileNotFoundError(
        "cannot locate public contract root (shared/contracts or spec/contracts)"
    )


class ReleasePublicError(Exception):
    """The public result cannot be built without weakening its bindings."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _load_contracts() -> tuple[dict[str, dict[str, Any]], Registry]:
    schemas: dict[str, dict[str, Any]] = {}
    for name in CONTRACT_NAMES:
        path = contract_root() / f"{name}.schema.json"
        schemas[name] = json.loads(path.read_text(encoding="utf-8"))

    def retrieve(uri: str):
        name = uri.rsplit("/", 1)[-1].removesuffix(".schema.json")
        if name not in schemas:
            raise ReleasePublicError([f"公共 Schema 引用不可解析: {uri}"])
        return Resource.from_contents(schemas[name], DRAFT202012)

    return schemas, Registry(retrieve=retrieve)


def _validate(
    value: Any,
    schema_name: str,
    schemas: dict[str, dict[str, Any]],
    registry: Registry,
) -> list[str]:
    errors = Draft202012Validator(
        schemas[schema_name], registry=registry
    ).iter_errors(value)
    rendered = []
    for error in sorted(errors, key=lambda item: list(item.absolute_path)):
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in error.absolute_path
        )
        rendered.append(f"[{schema_name}] {path}: {error.message}")
    return rendered


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleasePublicError([f"{label} 必须是非空字符串"])
    return value


def _require_digest(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ReleasePublicError([f"{label} 必须是小写 SHA-256"])
    return text


def _require_absolute(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if not os.path.isabs(text) or os.path.normpath(text) != text:
        raise ReleasePublicError([f"{label} 必须是规范化绝对路径"])
    return text


def _resource(
    *,
    resource_id: str,
    name: str,
    kind: str,
    path: str,
    access: str,
    workspace_scope: str,
    content_digest: str | None = None,
) -> dict[str, Any]:
    value = {
        "resource_id": resource_id,
        "name": name,
        "kind": kind,
        "path": path,
        "required": True,
        "access": access,
        "workspace_scope": workspace_scope,
    }
    if content_digest is not None:
        value["content_digest"] = content_digest
    return value


def _evidence_refs(
    *,
    audit: dict[str, Any],
    run_id: str,
    candidate_id: str,
    environment_digest: str,
    implementation_digest: str,
    executor_id: str,
) -> list[dict[str, Any]]:
    refs = []
    kind_map = {
        "provider-manifest": "environment_fact",
        "release-plan": "candidate_fact",
        "release-run": "execution_record",
        "release-approval": "execution_record",
        "schema": "rule_reference",
    }
    for sequence, item in enumerate(audit["evidence"]):
        if not isinstance(item, dict) or set(item) != {"kind", "path", "sha256"}:
            raise ReleasePublicError(["领域 evidence 条目结构无效"])
        kind = item["kind"]
        if kind not in kind_map:
            raise ReleasePublicError([f"未知领域 evidence kind: {kind}"])
        path = _require_absolute(item["path"], "evidence.path")
        digest = _require_digest(item["sha256"], "evidence.sha256")
        refs.append(
            {
                "evidence_id": f"release:{sequence}:{kind}",
                "kind": kind_map[kind],
                "path": path,
                "source": f"{release_receipts.PROVIDER_NAME}@"
                f"{release_receipts.PROVIDER_VERSION}",
                "candidate_id": candidate_id,
                "task_id": run_id,
                "environment_digest": environment_digest,
                "rule_ref": f"release-skill@{release_receipts.PROVIDER_VERSION}:{kind}",
                "implementation_digest": implementation_digest,
                "executor_id": executor_id,
                "sequence_number": sequence,
                "content_digest": digest,
                "credibility": "verified",
            }
        )
    return refs


def _error_for_audit(audit: dict[str, Any], stage_id: str) -> list[dict[str, Any]]:
    if audit["status"] != "FAILED":
        return []
    return [
        {
            "error_code": "RELEASE_AUDIT.RECEIPT_INVALID",
            "category": "CONTRACT_INCOMPATIBLE",
            "stage_id": stage_id,
            "message": "; ".join(audit["gate_findings"]),
            "affected_resources": [],
            "evidence": [],
            "side_effect_status": "NONE",
            "retry_possible": False,
            "remediation": "由 Release Skill 重新产生与冻结计划一致的权威收据",
        }
    ]


def build_public_bundle(
    *,
    provider_root: str,
    plan_path: str | None,
    run_path: str | None,
    expected_unit_id: str,
    expected_target_version: str,
    claimed_audit: dict[str, Any],
    runtime_context: dict[str, Any],
) -> dict[str, Any]:
    """Recompute the domain decision and build validated public artifacts."""
    if not isinstance(claimed_audit, dict) or not isinstance(runtime_context, dict):
        raise ReleasePublicError(["claimed_audit 与 runtime_context 必须是对象"])

    required_context = (
        "run_id",
        "operation_id",
        "stage_id",
        "authorization_ref",
        "acceptance_ref",
        "workspace_root",
        "target_project_path",
        "output_dir",
        "output_workspace_scope",
        "process_id",
        "lease_deadline",
        "implementation_digest",
        "executor_id",
    )
    missing = [name for name in required_context if name not in runtime_context]
    if missing:
        raise ReleasePublicError(
            [f"runtime_context 缺少字段: {', '.join(missing)}"]
        )

    provider_root = _require_absolute(provider_root, "provider_root")
    plan_bound = None if plan_path is None else _require_absolute(plan_path, "plan_path")
    run_bound = None if run_path is None else _require_absolute(run_path, "run_path")
    target_project_path = _require_absolute(
        runtime_context["target_project_path"], "target_project_path"
    )
    workspace_root = _require_absolute(
        runtime_context["workspace_root"], "workspace_root"
    )
    output_dir = _require_absolute(runtime_context["output_dir"], "output_dir")
    implementation_digest = _require_digest(
        runtime_context["implementation_digest"], "implementation_digest"
    )
    executor_id = _require_text(runtime_context["executor_id"], "executor_id")
    run_id = _require_text(runtime_context["run_id"], "run_id")
    if len(run_id) < 8:
        raise ReleasePublicError(["run_id 至少 8 个字符"])

    recomputed = release_receipts.audit_release_receipts(
        provider_root=provider_root,
        plan_path=plan_bound,
        run_path=run_bound,
        expected_unit_id=expected_unit_id,
        expected_target_version=expected_target_version,
    )
    if claimed_audit != recomputed:
        raise ReleasePublicError(["claimed_audit 与收据验证器重新计算结果不一致"])

    candidate_id = f"{expected_unit_id}:{expected_target_version}"
    provider_facts = {
        "provider": recomputed["provider"],
        "schema_digests": release_receipts.SCHEMA_DIGESTS,
    }
    environment_digest = _canonical_digest(provider_facts)
    evidence = _evidence_refs(
        audit=recomputed,
        run_id=run_id,
        candidate_id=candidate_id,
        environment_digest=environment_digest,
        implementation_digest=implementation_digest,
        executor_id=executor_id,
    )

    method_values = {
        "release-result.json": recomputed,
        "gate-findings.json": recomputed["gate_findings"],
        "evidence-list.json": evidence,
        "blocking-reasons.json": recomputed["blocking_reasons"],
    }
    method_bytes = {name: _json_bytes(value) for name, value in method_values.items()}
    scope = runtime_context["output_workspace_scope"]
    if scope not in {"inside_workspace", "outside_workspace"}:
        raise ReleasePublicError(["output_workspace_scope 无效"])

    output_resources = {
        name: _resource(
            resource_id=f"release-{name.removesuffix('.json')}",
            name=name.removesuffix(".json").replace("-", "_"),
            kind="domain_result" if name == "release-result.json" else "artifact",
            path=f"{output_dir}/{name}",
            access="authorized_write",
            workspace_scope=scope,
            content_digest=_sha256(raw),
        )
        for name, raw in method_bytes.items()
    }
    input_resources = [
        _resource(
            resource_id="release-target-project",
            name="target_project_path",
            kind="directory",
            path=target_project_path,
            access="read_only",
            workspace_scope="inside_workspace",
        ),
        _resource(
            resource_id="release-provider",
            name="release_skill_provider",
            kind="directory",
            path=provider_root,
            access="read_only",
            workspace_scope="outside_workspace",
        ),
    ]
    if plan_bound is not None:
        input_resources.append(
            _resource(
                resource_id="release-plan-input",
                name="candidate_release_ref",
                kind="artifact",
                path=plan_bound,
                access="read_only",
                workspace_scope="inside_workspace",
            )
        )
    if run_bound is not None:
        input_resources.append(
            _resource(
                resource_id="release-run-input",
                name="assessments_ref",
                kind="artifact",
                path=run_bound,
                access="read_only",
                workspace_scope="inside_workspace",
            )
        )

    task = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "method_id": METHOD_ID,
        "operation_id": _require_text(
            runtime_context["operation_id"], "operation_id"
        ),
        "stage_id": _require_text(runtime_context["stage_id"], "stage_id"),
        "attempt": 1,
        "target": {
            "skill": "release-audit",
            "method_ref": METHOD_ID,
            "script_id": "release_audit.py",
        },
        "workspace_root": workspace_root,
        "parameters": {
            "target_project_path": target_project_path,
            "candidate_release_ref": plan_bound or "",
            "assessments_ref": run_bound or "",
        },
        "inputs": input_resources,
        "expected_outputs": list(output_resources.values()),
        "output_dir": output_dir,
        "write_set": [],
        "authorization_ref": _require_text(
            runtime_context["authorization_ref"], "authorization_ref"
        ),
        "acceptance_ref": _require_text(
            runtime_context["acceptance_ref"], "acceptance_ref"
        ),
        "required_extensions": [],
        "budget": {
            "model_context_limit_tokens": 200000,
            "skill_warning_tokens": 2000,
            "skill_intervention_tokens": 2400,
            "context_observation_threshold": 80000,
            "context_static_split_threshold": 96000,
            "reserved_output_tokens": 4000,
            "measurement_policy": "unavailable",
        },
        "control_channel": {
            "run_id": run_id,
            "process_id": _require_text(
                runtime_context["process_id"], "process_id"
            ),
            "cancel_sequence": [
                "STOP_DISPATCH",
                "PROPAGATE_CANCEL",
                "GRACEFUL_STOP",
            ],
            "lease_deadline": _require_text(
                runtime_context["lease_deadline"], "lease_deadline"
            ),
            "cancel_acknowledged": False,
            "pre_submit_auth_recheck": False,
            "late_result_disposition": "discard",
        },
    }
    status = recomputed["status"]
    result = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "stage_id": task["stage_id"],
        "attempt": 1,
        "execution_status": status,
        "summary": {
            "SUCCEEDED": "Release Skill 权威收据链达到 VERIFIED",
            "BLOCKED": "Release Skill 权威收据尚未达到 VERIFIED",
            "FAILED": "Release Skill 权威收据链无效",
        }[status],
        "outputs": [
            output_resources["gate-findings.json"],
            output_resources["blocking-reasons.json"],
        ],
        "domain_results": [
            {
                "protocol_id": PROTOCOL_ID,
                "protocol_version": PROTOCOL_VERSION,
                "result_path": output_resources["release-result.json"]["path"],
                "content_digest": output_resources["release-result.json"][
                    "content_digest"
                ],
            }
        ],
        "evidence": evidence,
        "missing_inputs": (
            list(recomputed["blocking_reasons"]) if status == "BLOCKED" else []
        ),
        "warnings": [],
        "errors": _error_for_audit(recomputed, task["stage_id"]),
        "side_effects": [],
        "producer": {
            "skill": "release-audit",
            "method_ref": METHOD_ID,
            "script_id": "release_audit.py",
        },
        "usage": {
            "measurement_method": "unavailable",
            "context_limit_tokens": 200000,
        },
    }

    schemas, registry = _load_contracts()
    errors = _validate(task, "task", schemas, registry)
    errors.extend(_validate(result, "result", schemas, registry))
    for index, item in enumerate(evidence):
        errors.extend(
            f"[evidence[{index}]] {message}"
            for message in _validate(item, "evidence-ref", schemas, registry)
        )
    if errors:
        raise ReleasePublicError(errors)

    artifacts = {
        "task.json": _json_bytes(task),
        "result.json": _json_bytes(result),
        **method_bytes,
    }
    return {
        "task": copy.deepcopy(task),
        "result": copy.deepcopy(result),
        "evidence_items": copy.deepcopy(evidence),
        "artifact_bytes": artifacts,
    }


__all__ = ["FILENAMES", "ReleasePublicError", "build_public_bundle"]
