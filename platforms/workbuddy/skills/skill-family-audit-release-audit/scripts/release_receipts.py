"""Release Skill 0.3.0 immutable receipt-chain validator.

This module consumes Release Skill authorities.  It never invokes Release
Skill, mutates a release authority, or reimplements release state transitions.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, FormatChecker


PROVIDER_NAME = "release-skill"
PROVIDER_VERSION = "0.3.0"
SCHEMA_DIGESTS = {
    "approval-record.schema.json": (
        "05b5a16d58372e4fdda625a472a4bb71439aa5db4e9813bf7f3d3cf2d39d144e"
    ),
    "release-plan.schema.json": (
        "01c96659223918b5ce0e2d0d01d1ce5095baeb056de401babb8928add4d2a221"
    ),
    "release-run.schema.json": (
        "bf3c8fb4ca2fc078272a45a6ee6bf663fd2420a722b2f995dbaabf2635e2179e"
    ),
}
MAX_LINEAGE_DEPTH = 16
MARKETPLACE_ACTION_DISTRIBUTIONS = {
    "claude-marketplace-install": ("claude-plugin", "claude"),
    "codex-marketplace-install": ("codex-plugin", "codex"),
    "kimi-marketplace-install": ("kimi-plugin", "kimi"),
    "codebuddy-marketplace-install": ("codebuddy-plugin", "codebuddy"),
}
RESOURCE_DISTRIBUTIONS = {
    "npm",
    "claude-plugin",
    "codex-plugin",
    "kimi-plugin",
    "codebuddy-plugin",
}


class ReleaseReceiptError(Exception):
    """A present receipt authority is contradictory or invalid."""


class ReleaseReceiptMissing(Exception):
    """A required receipt authority is not available yet."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _install_foundation_host() -> None:
    if "conformance_check" in sys.modules:
        return
    script = next(
        (
            root / relative
            for root in Path(__file__).resolve().parents
            for relative in (
                "skills/skill-family-audit-conformance/scripts/conformance_check.py",
                "skills/skill-family-audit-conformance-audit/scripts/conformance_check.py",
            )
            if (root / relative).is_file()
            and not (root / relative).is_symlink()
        ),
        None,
    )
    if script is None:
        raise ReleaseReceiptError("FOUNDATION_TRANSPORT_MISSING")
    sys.path.insert(0, str(script.parent))
    __import__("conformance_check")


def _foundation(request: dict[str, Any]) -> dict[str, Any]:
    _install_foundation_host()
    host = sys.modules.get("conformance_check")
    if host is None:
        raise ReleaseReceiptError("FOUNDATION_TRANSPORT_MISSING")
    return host.foundation_host_for(__file__)._foundation(request)


def _compute_plan_digest(plan: dict[str, Any]) -> str:
    if plan.get("planVersion") == 2:
        binding = {
            key: value
            for key, value in plan.items()
            if key not in {"digest", "status", "createdAt", "baseline"}
        }
        binding["externalActions"] = [
            {key: value for key, value in action.items() if key != "status"}
            for action in plan.get("externalActions", [])
        ]
    else:
        binding = {key: value for key, value in plan.items() if key != "digest"}
    return str(_foundation({"operation": "digest-document", "document": binding})["digest"])


def _compute_run_digest(run: dict[str, Any]) -> str:
    # Release Skill deliberately uses JSON.stringify(rest, null, 2), not its
    # canonical JSON helper, for runDigest. JSON object insertion order is
    # preserved by Python's parser and dict.
    binding = {key: value for key, value in run.items() if key != "runDigest"}
    serialized = json.dumps(
        binding,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        separators=(",", ": "),
    )
    return _sha256(serialized.encode("utf-8"))


def _load_json_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ReleaseReceiptMissing(f"缺少收据权威: {path}") from exc
    except OSError as exc:
        raise ReleaseReceiptError(f"无法读取收据权威 {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseReceiptError(f"收据不是有效 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ReleaseReceiptError(f"收据顶层必须是对象: {path}")
    return value, raw


def _require_absolute_normalized(path: str | os.PathLike[str], label: str) -> Path:
    raw = os.fspath(path)
    if not raw or not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise ReleaseReceiptError(f"{label} 必须是规范化绝对路径")
    return Path(raw)


def _require_authority_file(
    path: str | os.PathLike[str],
    *,
    label: str,
) -> Path:
    candidate = _require_absolute_normalized(path, label)
    try:
        mode = candidate.lstat().st_mode
    except FileNotFoundError as exc:
        raise ReleaseReceiptMissing(f"缺少{label}: {candidate}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ReleaseReceiptError(f"{label} 必须是真实普通文件: {candidate}")

    seen_anchor = False
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:-1]:
        cursor /= part
        if part == ".release-skill":
            seen_anchor = True
        if not seen_anchor:
            continue
        try:
            ancestor_mode = cursor.lstat().st_mode
        except OSError as exc:
            raise ReleaseReceiptError(f"无法检查{label}路径祖先 {cursor}: {exc}") from exc
        if stat.S_ISLNK(ancestor_mode) or not stat.S_ISDIR(ancestor_mode):
            raise ReleaseReceiptError(f"{label}路径含符号链接或非目录祖先: {cursor}")
    if not seen_anchor:
        raise ReleaseReceiptError(f"{label}不位于 .release-skill 权威树内")
    return candidate


def _release_root(path: Path) -> Path:
    parts = path.parts
    indices = [index for index, part in enumerate(parts) if part == ".release-skill"]
    if len(indices) != 1:
        raise ReleaseReceiptError("收据路径必须包含且只包含一个 .release-skill 权威根")
    return Path(*parts[: indices[0] + 1])


def _validate_schema(
    instance: dict[str, Any],
    schema: dict[str, Any],
    *,
    label: str,
) -> None:
    errors = sorted(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        rendered = []
        for error in errors[:8]:
            pointer = "/" + "/".join(str(part) for part in error.absolute_path)
            rendered.append(f"{pointer}: {error.message}")
        raise ReleaseReceiptError(f"{label} Schema 校验失败: {'; '.join(rendered)}")


def _load_provider(provider_root: str | os.PathLike[str]) -> dict[str, Any]:
    root = _require_absolute_normalized(provider_root, "Release Skill provider 根")
    try:
        root_mode = root.lstat().st_mode
    except FileNotFoundError as exc:
        raise ReleaseReceiptMissing(f"缺少 Release Skill provider: {root}") from exc
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ReleaseReceiptError("Release Skill provider 根必须是真实目录")

    package, package_raw = _load_json_bytes(root / "package.json")
    if package.get("name") != PROVIDER_NAME or package.get("version") != PROVIDER_VERSION:
        raise ReleaseReceiptError(
            f"只接受 {PROVIDER_NAME}@{PROVIDER_VERSION}，实际为 "
            f"{package.get('name')}@{package.get('version')}"
        )

    schemas: dict[str, dict[str, Any]] = {}
    schema_evidence = []
    for name, expected_digest in SCHEMA_DIGESTS.items():
        schema_path = root / "schemas" / name
        schema, raw = _load_json_bytes(schema_path)
        actual_digest = _sha256(raw)
        if actual_digest != expected_digest:
            raise ReleaseReceiptError(
                f"Release Skill Schema 摘要漂移: {name} "
                f"expected={expected_digest} actual={actual_digest}"
            )
        Draft7Validator.check_schema(schema)
        schemas[name] = schema
        schema_evidence.append(
            {"path": str(schema_path), "sha256": actual_digest, "kind": "schema"}
        )
    return {
        "root": root,
        "package_digest": _sha256(package_raw),
        "schemas": schemas,
        "schema_evidence": schema_evidence,
    }


def _validate_plan(
    plan_path: Path,
    plan: dict[str, Any],
    *,
    schema: dict[str, Any],
    expected_unit_id: str,
    expected_target_version: str,
) -> str:
    _validate_schema(plan, schema, label="release plan")
    if plan.get("planVersion") != 2:
        raise ReleaseReceiptError("release-audit 仅接受 Release Skill 0.3.0 planVersion 2")
    if not plan.get("production"):
        raise ReleaseReceiptError("release-audit 只接受 Release Skill 生产权威计划")
    digest = _compute_plan_digest(plan)
    if plan.get("digest") != digest:
        raise ReleaseReceiptError("release plan digest 与内容不一致")
    if plan_path.parent.name != "plans" or plan_path.name != f"{digest}.json":
        raise ReleaseReceiptError("release plan 必须使用 plans/<planDigest>.json 权威路径")

    units = plan.get("units", [])
    matching = [unit for unit in units if unit.get("id") == expected_unit_id]
    if len(matching) != 1:
        raise ReleaseReceiptError("release plan 未精确绑定期望的唯一 unit")
    if matching[0].get("targetVersion") != expected_target_version:
        raise ReleaseReceiptError("release plan targetVersion 与候选引用不一致")
    if len({unit.get("id") for unit in units}) != len(units):
        raise ReleaseReceiptError("release plan 包含重复 unit id")
    _validate_source_authority_binding(plan)
    _validate_skill_resource_plan_binding(plan)
    return digest


def _validate_source_authority_binding(plan: dict[str, Any]) -> None:
    authority = plan.get("sourceAuthority")
    if not authority:
        raise ReleaseReceiptError("0.3.0 生产计划缺少冻结 sourceAuthority")
    paths = [entry.get("path") for entry in authority.get("entries", [])]
    if len(paths) != len(set(paths)):
        raise ReleaseReceiptError("sourceAuthority 包含重复源文件路径")


def _validate_skill_resource_plan_binding(plan: dict[str, Any]) -> None:
    closure = plan.get("skillResourceClosure")
    if not closure:
        raise ReleaseReceiptError("0.3.0 生产计划缺少 skillResourceClosure")
    receipts = closure.get("unitReceipts", [])
    unit_ids = [unit.get("id") for unit in plan.get("units", [])]
    receipt_ids = [receipt.get("unitId") for receipt in receipts]
    if len(receipt_ids) != len(set(receipt_ids)) or sorted(receipt_ids) != sorted(unit_ids):
        raise ReleaseReceiptError("skillResourceClosure 必须精确覆盖每个 release unit")
    if any(
        receipt.get("checkerVersion") != closure.get("checkerVersion")
        for receipt in receipts
    ):
        raise ReleaseReceiptError("skillResourceClosure checkerVersion 不一致")
    totals = {
        "totalSkillCount": sum(receipt.get("skillCount", 0) for receipt in receipts),
        "totalReferenceCount": sum(
            receipt.get("referenceCount", 0) for receipt in receipts
        ),
        "totalSourceOnlyCount": sum(
            receipt.get("sourceOnlyCount", 0) for receipt in receipts
        ),
        "totalFindingCount": sum(
            receipt.get("findingCount", 0) for receipt in receipts
        ),
    }
    for field, expected in totals.items():
        if closure.get(field) != expected:
            raise ReleaseReceiptError(f"skillResourceClosure {field} 与 unit 收据不一致")


def _validate_checkpoint_mapping(
    run: dict[str, Any],
    actions: list[dict[str, Any]],
) -> None:
    action_map = {action.get("id"): action for action in actions}
    if len(action_map) != len(actions):
        raise ReleaseReceiptError("release plan 包含重复 action id")
    checkpoints = run.get("checkpoints", [])
    checkpoint_map = {checkpoint.get("actionId"): checkpoint for checkpoint in checkpoints}
    if len(checkpoint_map) != len(checkpoints):
        raise ReleaseReceiptError("release run 包含重复 checkpoint actionId")
    if set(action_map) != set(checkpoint_map):
        raise ReleaseReceiptError("release run checkpoint 集合与 plan action 集合不一致")
    for action_id, action in action_map.items():
        if checkpoint_map[action_id].get("actionType") != action.get("type"):
            raise ReleaseReceiptError(
                f"checkpoint actionType 与 plan 不一致: {action_id}"
            )
    if run.get("status") == "VERIFIED":
        if any(
            checkpoint.get("status") not in {"succeeded", "skipped"}
            for checkpoint in checkpoints
        ):
            raise ReleaseReceiptError("VERIFIED run 含未完成的 checkpoint")
    elif run.get("status") == "PUBLISHED":
        for checkpoint in checkpoints:
            status = checkpoint.get("status")
            action_type = checkpoint.get("actionType")
            if status in {"succeeded", "skipped"}:
                continue
            if status == "deferred" and action_type in MARKETPLACE_ACTION_DISTRIBUTIONS:
                continue
            raise ReleaseReceiptError("PUBLISHED run 含不允许的未完成 checkpoint")


def _validate_run(
    *,
    run_path: Path,
    run: dict[str, Any],
    schema: dict[str, Any],
    plan: dict[str, Any],
    plan_path: Path,
    plan_digest: str,
) -> str:
    _validate_schema(run, schema, label="release run")
    digest = _compute_run_digest(run)
    if run.get("runDigest") != digest:
        raise ReleaseReceiptError("release run digest 与内容不一致")
    if run.get("planDigest") != plan_digest:
        raise ReleaseReceiptError("release run planDigest 与 plan 不一致")
    if run.get("planPath") != str(plan_path):
        raise ReleaseReceiptError("release run planPath 未绑定所提供的不可变计划")

    root = _release_root(plan_path)
    try:
        run_path.relative_to(root / "runs")
    except ValueError as exc:
        raise ReleaseReceiptError("release run 不位于 plan 同源的 runs/ 权威树") from exc
    if run_path.name != "release-run.json":
        raise ReleaseReceiptError("只接受最终 release-run.json 权威")
    _validate_checkpoint_mapping(run, plan.get("externalActions", []))
    return digest


def _load_lineage(
    *,
    terminal_path: Path,
    terminal_run: dict[str, Any],
    run_schema: dict[str, Any],
    plan: dict[str, Any],
    plan_path: Path,
    plan_digest: str,
) -> list[tuple[Path, dict[str, Any], bytes]]:
    chain: list[tuple[Path, dict[str, Any], bytes]] = []
    current_path = terminal_path
    current_run = terminal_run
    current_raw = current_path.read_bytes()
    for _ in range(MAX_LINEAGE_DEPTH + 1):
        _validate_run(
            run_path=current_path,
            run=current_run,
            schema=run_schema,
            plan=plan,
            plan_path=plan_path,
            plan_digest=plan_digest,
        )
        chain.append((current_path, current_run, current_raw))
        command = current_run.get("command")
        if command == "publish":
            return chain
        if command not in {"verify", "reconcile"}:
            raise ReleaseReceiptError(f"不支持的 source-run lineage 命令: {command}")
        required = ("sourceRunPath", "sourceRunId", "sourceRunDigest")
        if any(not current_run.get(field) for field in required):
            raise ReleaseReceiptError(f"{command} run 的 source lineage 不完整")

        try:
            parent_path = _require_authority_file(
                current_run["sourceRunPath"], label="source release run"
            )
        except ReleaseReceiptMissing as exc:
            raise ReleaseReceiptError("source-run lineage 引用的权威不存在") from exc
        parent_run, parent_raw = _load_json_bytes(parent_path)
        if (
            parent_run.get("runId") != current_run["sourceRunId"]
            or parent_run.get("runDigest") != current_run["sourceRunDigest"]
        ):
            raise ReleaseReceiptError("source run id/digest 与引用的权威字节不一致")
        if command == "verify":
            if (
                parent_run.get("command") not in {"publish", "reconcile"}
                or parent_run.get("status") != "PUBLISHED"
            ):
                raise ReleaseReceiptError("verify 必须引用 PUBLISHED publish/reconcile run")
        elif (
            parent_run.get("command") not in {"publish", "reconcile"}
            or parent_run.get("status") != "PARTIAL"
        ):
            raise ReleaseReceiptError("reconcile 必须引用 PARTIAL publish/reconcile run")
        current_path, current_run, current_raw = parent_path, parent_run, parent_raw
    raise ReleaseReceiptError("source-run lineage 超过最大深度")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseReceiptError(f"{label} 必须是 ISO 8601 时间")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ReleaseReceiptError(f"{label} 不是有效时间") from exc
    if parsed.tzinfo is None:
        raise ReleaseReceiptError(f"{label} 必须包含时区")
    return parsed


def _validate_source_authority_receipt(
    *,
    plan: dict[str, Any],
    source_run: dict[str, Any],
    plan_digest: str,
) -> None:
    authority = plan["sourceAuthority"]
    receipts = source_run.get("sourceAuthorityReceipts", [])
    matching = [
        receipt
        for receipt in receipts
        if receipt.get("sourceRepository") == authority["sourceRepository"]
        and receipt.get("defaultBranch") == authority["defaultBranch"]
        and receipt.get("inputDigest") == authority["inputDigest"]
        and receipt.get("algorithmVersion") == authority["algorithmVersion"]
        and receipt.get("entryCount") == len(authority["entries"])
        and receipt.get("planDigest") == plan_digest
        and receipt.get("result") == "CONSISTENT"
    ]
    if len(receipts) != 1 or len(matching) != 1:
        raise ReleaseReceiptError(
            "source run 缺少唯一且与冻结计划一致的 sourceAuthority receipt"
        )


def _unit_distribution_map(plan: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for unit in plan.get("units", []):
        for distribution in unit.get("distributions", []):
            key = (unit["id"], distribution["type"])
            if key in result:
                raise ReleaseReceiptError("release plan 包含重复 unit distribution")
            result[key] = distribution
    return result


def _validate_consumer_verification_receipts(
    *,
    plan: dict[str, Any],
    run: dict[str, Any],
    plan_digest: str,
) -> None:
    distributions = _unit_distribution_map(plan)
    actions = {
        action["id"]: action
        for action in plan.get("externalActions", [])
        if action.get("type") in MARKETPLACE_ACTION_DISTRIBUTIONS
    }
    receipts = run.get("consumerVerificationReceipts", [])
    receipt_map = {receipt.get("actionId"): receipt for receipt in receipts}
    if len(receipt_map) != len(receipts) or set(receipt_map) != set(actions):
        raise ReleaseReceiptError(
            "consumerVerificationReceipts 未精确覆盖 marketplace actions"
        )
    checkpoints = {
        checkpoint["actionId"]: checkpoint
        for checkpoint in run.get("checkpoints", [])
    }
    for action_id, action in actions.items():
        distribution_type, default_platform = MARKETPLACE_ACTION_DISTRIBUTIONS[
            action["type"]
        ]
        unit_id = action.get("unitId")
        distribution = distributions.get((unit_id, distribution_type))
        if distribution is None:
            raise ReleaseReceiptError(
                f"marketplace action 未绑定声明的 unit distribution: {action_id}"
            )
        expected_digest = distribution.get("installationContractDigest")
        action_digest = action.get("parameters", {}).get(
            "installationContractDigest"
        )
        if not expected_digest or action_digest != expected_digest:
            raise ReleaseReceiptError(
                f"marketplace action installationContractDigest 未闭合: {action_id}"
            )
        receipt = receipt_map[action_id]
        expected_platform = action.get("parameters", {}).get(
            "consumer", default_platform
        )
        expected_algorithm = action.get("parameters", {}).get(
            "algorithmVersion", 1
        )
        if (
            receipt.get("unitId") != unit_id
            or receipt.get("platform") != expected_platform
            or receipt.get("installationContractDigest") != expected_digest
            or receipt.get("algorithmVersion") != expected_algorithm
            or receipt.get("planDigest") != plan_digest
        ):
            raise ReleaseReceiptError(
                f"consumer verification receipt 未绑定冻结 action: {action_id}"
            )
        expected_checkpoint = (
            "skipped"
            if receipt.get("result") == "NOT_REQUIRED_UNCHANGED"
            else "succeeded"
        )
        if checkpoints[action_id].get("status") != expected_checkpoint:
            raise ReleaseReceiptError(
                f"consumer verification receipt 与 checkpoint 冲突: {action_id}"
            )


def _validate_skill_resource_run_receipts(
    *,
    plan: dict[str, Any],
    run: dict[str, Any],
) -> None:
    expected = {
        (unit["id"], distribution["type"])
        for unit in plan.get("units", [])
        for distribution in unit.get("distributions", [])
        if distribution.get("type") in RESOURCE_DISTRIBUTIONS
    }
    receipts = run.get("skillResourceClosureReceipts", [])
    observed = [
        (receipt.get("unitId"), receipt.get("distribution"))
        for receipt in receipts
    ]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ReleaseReceiptError(
            "skillResourceClosureReceipts 未精确覆盖声明的消费分发面"
        )


def _validate_approval(
    *,
    approval_path: Path,
    approval: dict[str, Any],
    approval_raw: bytes,
    schema: dict[str, Any],
    plan: dict[str, Any],
    plan_digest: str,
    publish_run: dict[str, Any],
) -> str:
    _validate_schema(approval, schema, label="approval record")
    digest = _sha256(approval_raw)
    root = _release_root(approval_path)
    expected_parent = root / "approvals" / plan_digest
    if approval_path.parent != expected_parent or approval_path.name != f"{digest}.json":
        raise ReleaseReceiptError(
            "approval 必须使用 approvals/<planDigest>/<approvalDigest>.json 权威路径"
        )
    if approval.get("planDigest") != plan_digest:
        raise ReleaseReceiptError("approval planDigest 与 plan 不一致")

    expected_versions = {
        unit["id"]: unit["targetVersion"] for unit in plan.get("units", [])
    }
    if approval.get("unitVersions") is not None:
        if approval["unitVersions"] != expected_versions:
            raise ReleaseReceiptError("approval unitVersions 未精确绑定 plan units")
        if "targetVersion" in approval:
            versions = set(expected_versions.values())
            if len(versions) != 1 or approval["targetVersion"] not in versions:
                raise ReleaseReceiptError("approval targetVersion 与 unitVersions 冲突")
    else:
        versions = set(expected_versions.values())
        if len(versions) != 1 or approval.get("targetVersion") not in versions:
            raise ReleaseReceiptError("approval targetVersion 未精确绑定 plan")

    expected_actions = {action["id"] for action in plan.get("externalActions", [])}
    if set(approval.get("approvedActions", [])) != expected_actions:
        raise ReleaseReceiptError("approval approvedActions 与 plan actions 不完全相等")
    approved_at = _parse_time(approval.get("approvedAt"), "approvedAt")
    expires_at = _parse_time(approval.get("expiresAt"), "expiresAt")
    duration = (expires_at - approved_at).total_seconds()
    if duration <= 0 or duration > 24 * 60 * 60:
        raise ReleaseReceiptError("approval 有效期必须大于 0 且不超过 24 小时")
    publish_started = _parse_time(publish_run.get("startedAt"), "publish.startedAt")
    if approved_at.timestamp() > publish_started.timestamp() + 5 * 60:
        raise ReleaseReceiptError("approval 在 publish 启动时间之后签发")
    if publish_started > expires_at:
        raise ReleaseReceiptError("approval 在 publish 启动前已经过期")
    return digest


def audit_release_receipts(
    *,
    provider_root: str | os.PathLike[str],
    plan_path: str | os.PathLike[str] | None,
    run_path: str | os.PathLike[str] | None,
    expected_unit_id: str,
    expected_target_version: str,
) -> dict[str, Any]:
    """Validate a Release Skill receipt chain and return a domain decision."""
    base = {
        "protocol_id": "skill-family-audit.release-receipt-audit",
        "protocol_version": "1.0.0",
        "provider": f"{PROVIDER_NAME}@{PROVIDER_VERSION}",
        "candidate": {
            "unit_id": expected_unit_id,
            "target_version": expected_target_version,
        },
        "gate_findings": [],
        "blocking_reasons": [],
        "evidence": [],
    }
    if not expected_unit_id or not expected_target_version:
        base.update(
            status="FAILED",
            gate_findings=["候选 unit id 和 target version 必须为非空字符串"],
        )
        return base
    if plan_path is None or run_path is None:
        base.update(
            status="BLOCKED",
            blocking_reasons=["缺少 Release Skill plan 或 run 收据引用"],
        )
        return base

    try:
        provider = _load_provider(provider_root)
        checked_plan_path = _require_authority_file(plan_path, label="release plan")
        checked_run_path = _require_authority_file(run_path, label="release run")
        if _release_root(checked_plan_path) != _release_root(checked_run_path):
            raise ReleaseReceiptError("plan 与 run 不属于同一 .release-skill 权威根")

        plan, plan_raw = _load_json_bytes(checked_plan_path)
        plan_digest = _validate_plan(
            checked_plan_path,
            plan,
            schema=provider["schemas"]["release-plan.schema.json"],
            expected_unit_id=expected_unit_id,
            expected_target_version=expected_target_version,
        )
        terminal_run, _ = _load_json_bytes(checked_run_path)
        chain = _load_lineage(
            terminal_path=checked_run_path,
            terminal_run=terminal_run,
            run_schema=provider["schemas"]["release-run.schema.json"],
            plan=plan,
            plan_path=checked_plan_path,
            plan_digest=plan_digest,
        )
        source_authority_run = chain[1][1] if terminal_run.get("command") == "verify" else chain[0][1]
        _validate_source_authority_receipt(
            plan=plan,
            source_run=source_authority_run,
            plan_digest=plan_digest,
        )

        for _, run, _ in chain:
            if not run.get("approvalPath") or not run.get("approvalDigest"):
                raise ReleaseReceiptError(
                    "run lineage 中每个生产 run 都必须绑定 approvalPath/approvalDigest"
                )
        approval_paths = {run["approvalPath"] for _, run, _ in chain}
        approval_digests = {run["approvalDigest"] for _, run, _ in chain}
        if len(approval_paths) != 1 or len(approval_digests) != 1:
            raise ReleaseReceiptError("run lineage 未绑定唯一 approval authority")
        try:
            approval_path = _require_authority_file(
                next(iter(approval_paths)), label="release approval"
            )
        except ReleaseReceiptMissing as exc:
            raise ReleaseReceiptError("run lineage 引用的 approval 权威不存在") from exc
        if _release_root(approval_path) != _release_root(checked_plan_path):
            raise ReleaseReceiptError("approval 与 plan 不属于同一 .release-skill 权威根")
        approval, approval_raw = _load_json_bytes(approval_path)
        approval_digest = _validate_approval(
            approval_path=approval_path,
            approval=approval,
            approval_raw=approval_raw,
            schema=provider["schemas"]["approval-record.schema.json"],
            plan=plan,
            plan_digest=plan_digest,
            publish_run=chain[-1][1],
        )
        if approval_digest != next(iter(approval_digests)):
            raise ReleaseReceiptError("run lineage approvalDigest 与权威字节不一致")

        consumer_gates = [
            gate
            for gate in plan.get("verificationGates", [])
            if gate.get("phase") == "consumer-verify"
        ]
        consumer_gate_map = {gate["id"]: gate for gate in consumer_gates}
        if len(consumer_gate_map) != len(consumer_gates):
            raise ReleaseReceiptError("plan 包含重复 consumer gate id")
        observed_gates = terminal_run.get("gateResults", [])
        observed_gate_map = {gate["id"]: gate for gate in observed_gates}
        if len(observed_gate_map) != len(observed_gates):
            raise ReleaseReceiptError("VERIFIED run 包含重复 consumer gate id")
        if terminal_run.get("status") == "VERIFIED":
            if terminal_run.get("command") != "verify":
                raise ReleaseReceiptError("VERIFIED 只能由 verify run 表达")
            _validate_consumer_verification_receipts(
                plan=plan,
                run=terminal_run,
                plan_digest=plan_digest,
            )
            _validate_skill_resource_run_receipts(
                plan=plan,
                run=terminal_run,
            )
            if set(observed_gate_map) != set(consumer_gate_map):
                raise ReleaseReceiptError(
                    "VERIFIED run 的 consumer gate 集合与 plan 不一致"
                )
            for gate_id, gate in consumer_gate_map.items():
                observed = observed_gate_map[gate_id]
                expected_digest = str(
                    _foundation({"operation": "digest-document", "document": gate})["digest"]
                )
                if (
                    observed.get("unitId") != gate["scope"]["unit"]
                    or observed.get("distribution")
                    != gate["scope"].get("distribution")
                    or observed.get("gateDigest") != expected_digest
                ):
                    raise ReleaseReceiptError(
                        f"consumer gate 结果未绑定冻结定义: {gate_id}"
                    )

        base["evidence"] = [
            {
                "kind": "provider-manifest",
                "path": str(provider["root"] / "package.json"),
                "sha256": provider["package_digest"],
            },
            {
                "kind": "release-plan",
                "path": str(checked_plan_path),
                "sha256": _sha256(plan_raw),
            },
            *[
                {
                    "kind": "release-run",
                    "path": str(path),
                    "sha256": _sha256(raw),
                }
                for path, _, raw in chain
            ],
            {
                "kind": "release-approval",
                "path": str(approval_path),
                "sha256": approval_digest,
            },
            *provider["schema_evidence"],
        ]
        if (
            terminal_run.get("command") == "verify"
            and terminal_run.get("status") == "VERIFIED"
        ):
            base.update(
                status="SUCCEEDED",
                gate_findings=[
                    "Release Skill provider、Schema、plan、approval、run lineage、"
                    "source authority、resource closure、checkpoint 与 consumer gate"
                    " 均已验证"
                ],
            )
        else:
            base.update(
                status="BLOCKED",
                blocking_reasons=[
                    f"Release Skill 终态为 {terminal_run.get('status')}；"
                    "只有 verify/VERIFIED 可通过发布审计"
                ],
            )
    except ReleaseReceiptMissing as exc:
        base.update(status="BLOCKED", blocking_reasons=[str(exc)])
    except (ReleaseReceiptError, json.JSONDecodeError, ValueError, TypeError) as exc:
        base.update(status="FAILED", gate_findings=[str(exc)])
    return base


__all__ = [
    "PROVIDER_NAME",
    "PROVIDER_VERSION",
    "SCHEMA_DIGESTS",
    "ReleaseReceiptError",
    "audit_release_receipts",
]
