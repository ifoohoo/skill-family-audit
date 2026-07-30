#!/usr/bin/env python3
"""runtime-audit：消费 loop-agent 权威运行证据的薄编排 CLI。

只组合 runtime_contracts.py（公共信封）与 runtime_evidence.py（证据验证），
不在入口文件内复制 Schema 校验、Loop Agent 证据验证或版本判断逻辑。

只读目标项目和运行证据；唯一写根为 output-dir。无网络依赖。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
_SKILL_DIR = _SCRIPT_DIR.parent
# 依赖模块路径
_RUNTIME_CONTRACTS_PY = _SCRIPT_DIR / "runtime_contracts.py"
_RUNTIME_EVIDENCE_PY = _SCRIPT_DIR / "runtime_evidence.py"

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

_METHOD_ID = "skill-family-audit:runtime-audit"
_CANDIDATE_ID = "skill-family-audit:0.1.4-candidate"
_VALID_MATURITY_LEVELS = ("candidate_ready", "consumer_qualified", "stable")

# BLOCKED 归类模式：成熟度所需证据缺失、稳定消费者不足、控制场景缺失
_BLOCKED_PATTERNS = (
    "missing required artifact",
    "must have at least 2 items",
    "must have at least 2 distinct consumer_domain",
    "missing required scenario types",
    "evidence_path: file does not exist",
)


# ---------------------------------------------------------------------------
# 依赖加载
# ---------------------------------------------------------------------------


def _load_module(module_name: str, module_path: Path):
    """从文件路径加载 Python 模块。失败关闭。"""
    import importlib.util

    if not module_path.is_file():
        die(f"依赖模块不存在: {module_path}")
    spec = importlib.util.spec_from_file_location(module_name, str(module_path))
    if spec is None or spec.loader is None:
        die(f"无法加载模块: {module_name}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_bytes(
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def die(msg: str, code: int = 2):
    print(json.dumps({"error": msg}, ensure_ascii=False), file=sys.stderr)
    sys.exit(code)


def validate_absolute_path(value: str, label: str) -> Path:
    """绝对路径校验：必须为绝对路径，根目录不得为符号链接。"""
    p = Path(value)
    if not p.is_absolute():
        die(f"{label} 必须是绝对路径，收到: {value}")
    try:
        p.resolve()
    except OSError as e:
        die(f"{label} 路径解析失败: {e}")
    return p


def validate_dir_not_symlink(path: Path, label: str) -> None:
    """校验目录真实存在，且根不得为符号链接。"""
    if path.is_symlink():
        die(f"{label} 不得是符号链接: {path}")
    if not path.is_dir():
        die(f"{label} 必须是存在的目录: {path}")


def validate_file_not_symlink(path: Path, label: str) -> None:
    """校验普通文件真实存在，且根不得为符号链接。"""
    if path.is_symlink():
        die(f"{label} 不得是符号链接: {path}")
    if not path.is_file():
        die(f"{label} 必须是存在的普通文件: {path}")


def _has_symlink_ancestor(path: Path) -> bool:
    """检查路径或任一现存祖先是否为符号链接。"""
    current = path
    while True:
        if current.is_symlink():
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def validate_output_dir(path: Path) -> None:
    """输出目录：不存在或为空，根目录及祖先不得通过符号链接逃逸。"""
    if _has_symlink_ancestor(path):
        die(f"output-dir 或其祖先不得包含符号链接: {path}")
    if path.exists():
        if not path.is_dir():
            die(f"output-dir 已存在但不是目录: {path}")
        if any(path.iterdir()):
            die(f"output-dir 必须不存在或为空: {path}")
    parent = path.parent
    if not parent.is_dir():
        die(f"output-dir 父目录必须是存在的目录: {parent}")


def workspace_scope(path: Path, workspace_root: Path) -> str:
    """根据真实路径判断资源是否位于目标工作区内。"""
    try:
        common = os.path.commonpath((str(path.resolve()), str(workspace_root.resolve())))
    except ValueError:
        return "outside_workspace"
    return "inside_workspace" if common == str(workspace_root.resolve()) else "outside_workspace"


# ---------------------------------------------------------------------------
# 错误分类
# ---------------------------------------------------------------------------


def classify_errors(errors: list[str]) -> tuple[str, str, str]:
    """将 runtime_evidence 错误分为 BLOCKED 或 FAILED。

    BLOCKED: 成熟度所需证据缺失、稳定消费者不足、控制场景缺失
    FAILED:  结构、摘要、Schema、身份、链、路径或 provider 错误

    Returns:
        (execution_status, error_category, error_code) 元组。
    """
    if errors and all(
        any(pattern in error.lower() for pattern in _BLOCKED_PATTERNS)
        for error in errors
    ):
        return "BLOCKED", "INPUT_MISSING", "EVIDENCE_MISSING"
    return "FAILED", "CONTRACT_INCOMPATIBLE", "EVIDENCE_INVALID"


# ---------------------------------------------------------------------------
# 证据引用构建（仅从已验证的 artifact descriptor 构建）
# ---------------------------------------------------------------------------


def _build_evidence_refs_from_bundle(
    bundle: dict[str, Any],
    run_id: str,
    task_id: str,
) -> list[dict[str, Any]]:
    """从证据包中实际存在并通过验证的 artifact descriptor 生成 evidence-ref 列表。

    仅读取 bundle 的 artifacts/stable_consumers/control_scenarios 结构，
    不执行校验（校验由 runtime_evidence.py 完成）。
    """
    refs: list[dict[str, Any]] = []
    identity = bundle["identity"]
    provider = bundle["provider"]
    platform = identity["platform"]
    env_digest = sha256_json({
        "platform": platform,
        "provider_manifest_digest": provider["provider_manifest_digest"],
        "contract_digest": provider["contract_digest"],
    })
    impl_digest = provider["provider_manifest_digest"]
    evidence_task_id = identity["task_id"]
    artifacts = bundle.get("artifacts", {})
    seq = 0

    # artifacts 条目：process_evidence, delivery_task, task_result,
    # isolation_manifest, cleanup_proof, attempt_seal, finalization
    for cat in (
        "process_evidence", "delivery_task", "task_result",
        "isolation_manifest", "cleanup_proof", "attempt_seal", "finalization",
    ):
        art = artifacts.get(cat)
        if not isinstance(art, dict):
            continue
        refs.append({
            "evidence_id": f"EV-{cat}-{sha256_bytes(cat.encode())[:8]}",
            "kind": _EVIDENCE_KIND_MAP.get(cat, "execution_record"),
            "path": art.get("path", ""),
            "source": "loop-agent",
            "candidate_id": _CANDIDATE_ID,
            "task_id": evidence_task_id,
            "environment_digest": env_digest,
            "rule_ref": f"runtime-audit:{cat}",
            "implementation_digest": impl_digest,
            "executor_id": provider.get("provider_id", "loop-agent"),
            "sequence_number": seq,
            "content_digest": art.get("content_digest", ""),
            "credibility": "verified",
        })
        seq += 1

    # observer_events（整个数组作为一个 artifact）
    oe = artifacts.get("observer_events")
    if isinstance(oe, dict):
        refs.append({
            "evidence_id": "EV-observer-events-" + sha256_bytes(b"observer_events")[:8],
            "kind": "observer_event",
            "path": oe.get("path", ""),
            "source": "loop-agent",
            "candidate_id": _CANDIDATE_ID,
            "task_id": evidence_task_id,
            "environment_digest": env_digest,
            "rule_ref": "runtime-audit:observer-events",
            "implementation_digest": impl_digest,
            "executor_id": provider.get("provider_id", "loop-agent"),
            "sequence_number": seq,
            "content_digest": oe.get("content_digest", ""),
            "credibility": "verified",
        })
        seq += 1

    # stable_consumers
    for sc in bundle.get("stable_consumers", []):
        if not isinstance(sc, dict):
            continue
        cid = sc.get("consumer_id", "unknown")
        refs.append({
            "evidence_id": f"EV-consumer-{sha256_bytes(cid.encode())[:8]}",
            "kind": "output_artifact",
            "path": sc.get("evidence_path", ""),
            "source": "stable-consumer",
            "candidate_id": _CANDIDATE_ID,
            "task_id": evidence_task_id,
            "environment_digest": env_digest,
            "rule_ref": "runtime-audit:stable-consumer",
            "implementation_digest": impl_digest,
            "executor_id": cid,
            "sequence_number": seq,
            "content_digest": sc.get("content_digest", ""),
            "credibility": "verified",
        })
        seq += 1

    # control_scenarios
    for cs in bundle.get("control_scenarios", []):
        if not isinstance(cs, dict):
            continue
        st = cs.get("scenario_type", "unknown")
        refs.append({
            "evidence_id": f"EV-scenario-{sha256_bytes(st.encode())[:8]}",
            "kind": "environment_fact",
            "path": cs.get("evidence_path", ""),
            "source": "control-scenario",
            "candidate_id": _CANDIDATE_ID,
            "task_id": evidence_task_id,
            "environment_digest": env_digest,
            "rule_ref": f"runtime-audit:scenario-{st}",
            "implementation_digest": impl_digest,
            "executor_id": provider.get("provider_id", "loop-agent"),
            "sequence_number": seq,
            "content_digest": cs.get("content_digest", ""),
            "credibility": "verified",
        })
        seq += 1

    return refs


_EVIDENCE_KIND_MAP = {
    "process_evidence": "execution_record",
    "delivery_task": "task_input",
    "task_result": "execution_record",
    "isolation_manifest": "candidate_fact",
    "cleanup_proof": "execution_record",
    "attempt_seal": "execution_record",
    "finalization": "execution_record",
}


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------


def generate_report(
    execution_status: str,
    maturity_level: str,
    platform: str,
    error_category: str,
    error_code: str,
    errors: list[str],
) -> str:
    """生成中文审计报告，准确区分 SUCCEEDED / BLOCKED / FAILED。"""
    lines = [
        "# 运行治理审计报告",
        "",
        f"- **成熟度等级**: {maturity_level}",
        f"- **目标平台**: {platform}",
        f"- **审计时间**: {datetime.now(timezone.utc).isoformat()}",
        f"- **执行状态**: {execution_status}",
        "",
        "## 审计结论",
        "",
    ]

    if execution_status == "SUCCEEDED":
        lines.append("✅ 审计通过：所有必需证据齐全且验证一致。")
    elif execution_status == "BLOCKED":
        lines.append("🔒 审计受阻（INPUT_MISSING）：缺少成熟度所需证据，无法完成审计。")
    elif execution_status == "FAILED":
        lines.append("❌ 审计失败（CONTRACT_INCOMPATIBLE）：发现合同不兼容错误。")
    else:
        lines.append(f"ℹ️ 状态: {execution_status}")

    if errors:
        lines.extend(["", "## 验证错误", ""])
        for e in errors:
            lines.append(f"- {e}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 原子写入
# ---------------------------------------------------------------------------


def atomic_write_bundle(output_dir: Path, file_map: dict[str, bytes]) -> None:
    """在同一父目录完整落盘后，以目录替换一次性发布六个文件。"""
    parent = output_dir.parent
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.staging-", dir=parent))
    try:
        for filename, data in file_map.items():
            target = staging / filename
            with target.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        if output_dir.exists():
            if not output_dir.is_dir() or any(output_dir.iterdir()):
                raise OSError(f"output-dir 在发布前已不再为空: {output_dir}")
            output_dir.rmdir()
        os.replace(staging, output_dir)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def main() -> None:
    # ── CLI 参数 ──
    parser = argparse.ArgumentParser(
        description="runtime-audit：薄编排 CLI，组合 runtime_contracts 与 runtime_evidence",
    )
    parser.add_argument("--target-project", required=True, help="目标项目绝对目录")
    parser.add_argument("--runtime-evidence", required=True, help="证据包 JSON 文件（绝对路径）")
    parser.add_argument("--maturity-level", required=True,
                        choices=list(_VALID_MATURITY_LEVELS), help="成熟度等级")
    parser.add_argument("--platform", required=True, help="平台标识")
    parser.add_argument("--provider-root", required=True, help="loop-agent 0.1.x 插件根（绝对路径）")
    parser.add_argument("--output-dir", required=True, help="输出目录（绝对、不存在或为空）")
    args = parser.parse_args()

    # ── 加载依赖模块 ──
    contracts_mod = _load_module("runtime_contracts", _RUNTIME_CONTRACTS_PY)
    evidence_mod = _load_module("runtime_evidence", _RUNTIME_EVIDENCE_PY)

    # ── 路径边界检查 ──
    target_project = validate_absolute_path(args.target_project, "target-project")
    validate_dir_not_symlink(target_project, "target-project")

    evidence_path = validate_absolute_path(args.runtime_evidence, "runtime-evidence")
    validate_file_not_symlink(evidence_path, "runtime-evidence")

    provider_root = validate_absolute_path(args.provider_root, "provider-root")
    validate_dir_not_symlink(provider_root, "provider-root")

    output_dir = validate_absolute_path(args.output_dir, "output-dir")
    validate_output_dir(output_dir)

    maturity_level: str = args.maturity_level
    platform: str = args.platform
    if not platform.strip():
        die("platform 必须是非空字符串")

    # 证据根 = runtime-evidence 的父目录
    evidence_root = str(evidence_path.parent)

    # 公共合同根由适配器按安装根标记解析；候选态使用 shared/contracts，
    # 源码态明确回退到本仓 spec/contracts。
    public_contract_root = str(contracts_mod.contract_root())

    # ── 加载证据包（顶层 JSON 对象） ──
    try:
        raw_bytes = evidence_path.read_bytes()
    except OSError as e:
        die(f"无法读取证据文件: {e}")
    try:
        bundle: dict[str, Any] = json.loads(raw_bytes)
    except json.JSONDecodeError as e:
        die(f"证据文件 JSON 解析失败: {e}")
    if not isinstance(bundle, dict):
        die("证据包顶层必须是 JSON 对象")

    # ── 平台身份一致性：identity.platform 必须与 --platform 完全一致 ──
    identity = bundle.get("identity")
    if not isinstance(identity, dict):
        die("证据包缺少 identity 对象")
    bundle_platform = identity.get("platform")
    if bundle_platform != platform:
        die(f"证据包 identity.platform={bundle_platform!r} 与 --platform={platform!r} 不一致")

    # ── 调用 runtime_evidence 的公共验证 API ──
    errors = evidence_mod.validate_runtime_evidence_bundle(
        bundle,
        evidence_root=evidence_root,
        provider_root=provider_root,
        public_contract_root=public_contract_root,
        maturity_level=maturity_level,
    )

    # ── 状态分类 ──
    if not errors:
        execution_status = "SUCCEEDED"
        error_category = ""
        error_code = ""
    else:
        execution_status, error_category, error_code = classify_errors(errors)

    # ── 运行标识：从输入原始字节摘要与运行环境元数据构造 ──
    content_hash = sha256_bytes(raw_bytes)
    run_id = f"run-runtime-audit-{content_hash[:32]}"
    operation_id = f"op-runtime-audit-{maturity_level}"
    stage_id = f"runtime-audit-{maturity_level}"
    process_id = f"proc-runtime-audit-{content_hash[:32]}"
    lease_deadline = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    # ── 提取 provider 和 identity 信息（安全取值） ──
    provider = bundle.get("provider") or {}
    provider_id = provider.get("provider_id", "loop-agent")
    provider_version = provider.get("provider_version", "")
    provider_contract_digest = provider.get("contract_digest", "")
    bundle_run_id = identity.get("run_id", "")
    bundle_task_id = identity.get("task_id", "")

    # ── 成功时构建证据引用（仅从已验证的 artifact descriptor） ──
    if execution_status == "SUCCEEDED":
        evidence_refs = _build_evidence_refs_from_bundle(
            bundle, run_id, identity["task_id"]
        )
    else:
        evidence_refs = []

    # ── 领域结果（先在内存中生成） ──
    runtime_result = {
        "protocol_id": _METHOD_ID,
        "protocol_version": "1.0.0-candidate",
        "result_path": "runtime-result.json",
        "maturity_level": maturity_level,
        "platform": platform,
        "execution_status": execution_status,
        "validation_errors": errors,
        "provider": {
            "provider_id": provider_id,
            "provider_version": provider_version,
            "contract_digest": provider_contract_digest,
        },
        "identity": {
            "run_id": bundle_run_id,
            "task_id": bundle_task_id,
        },
        "evidence_digest": content_hash,
    }
    runtime_result_bytes = json.dumps(
        runtime_result, ensure_ascii=False, indent=2,
    ).encode("utf-8")
    runtime_result_digest = sha256_bytes(runtime_result_bytes)

    # ── 治理发现（结构化） ──
    governance_findings = []
    if error_category:
        for err in errors:
            governance_findings.append({
                "finding_id": f"GF-{sha256_bytes(err.encode())[:16]}",
                "severity": "error",
                "category": error_category,
                "error_code": error_code,
                "message": err,
                "source": "runtime-audit",
            })
    gov_findings_bytes = json.dumps(
        governance_findings, ensure_ascii=False, indent=2,
    ).encode("utf-8")
    evidence_bytes = json.dumps(
        evidence_refs, ensure_ascii=False, indent=2,
    ).encode("utf-8")
    report_text = generate_report(
        execution_status, maturity_level, platform,
        error_category, error_code, errors,
    )
    report_bytes = report_text.encode("utf-8")

    output_scope = workspace_scope(output_dir, target_project)
    evidence_scope = workspace_scope(evidence_path, target_project)

    # ── task 信封 ──
    task_envelope = contracts_mod.build_task_envelope(
        run_id=run_id,
        operation_id=operation_id,
        stage_id=stage_id,
        workspace_root=str(target_project),
        output_dir=str(output_dir),
        parameters={
            "target_project_path": str(target_project),
            "runtime_evidence_ref": str(evidence_path),
            "maturity_level": maturity_level,
            "platform_filter": platform,
        },
        inputs=[
            {
                "resource_id": "target-project",
                "name": "target_project_path",
                "kind": "directory",
                "path": str(target_project),
                "required": True,
                "access": "read_only",
                "workspace_scope": "inside_workspace",
            },
            {
                "resource_id": "runtime-evidence-package",
                "name": "runtime_evidence_ref",
                "kind": "file",
                "path": str(evidence_path),
                "required": True,
                "access": "read_only",
                "workspace_scope": evidence_scope,
                "content_digest": content_hash,
            },
            {
                "resource_id": "loop-agent-provider",
                "name": "provider_root",
                "kind": "external",
                "path": str(provider_root),
                "required": True,
                "access": "read_only",
                "workspace_scope": "outside_workspace",
            },
        ],
        expected_outputs=[
            {
                "resource_id": "runtime-result",
                "name": "runtime_result",
                "kind": "file",
                "path": "runtime-result.json",
                "required": True,
                "access": "authorized_write",
                "workspace_scope": output_scope,
            },
            {
                "resource_id": "governance-findings",
                "name": "governance_findings",
                "kind": "file",
                "path": "governance-findings.json",
                "required": True,
                "access": "authorized_write",
                "workspace_scope": output_scope,
            },
            {
                "resource_id": "evidence-list",
                "name": "evidence_list",
                "kind": "file",
                "path": "evidence.json",
                "required": True,
                "access": "authorized_write",
                "workspace_scope": output_scope,
            },
            {
                "resource_id": "runtime-report",
                "name": "runtime_report",
                "kind": "artifact",
                "path": "report.zh-CN.md",
                "required": True,
                "access": "authorized_write",
                "workspace_scope": output_scope,
            },
        ],
        process_id=process_id,
        lease_deadline=lease_deadline,
    )

    # ── result 信封 ──
    error_objects = []
    for err in errors:
        error_objects.append(contracts_mod.build_error(
            error_code=f"RUNTIME_AUDIT.{error_code}" if error_code else "RUNTIME_AUDIT.OK",
            category=error_category or "NONE",
            stage_id=stage_id,
            message=err,
            retry_possible=(error_category == "BLOCKED"),
            remediation="修正证据包中的验证错误后重试" if error_category else "",
        ))

    summary_map = {
        "SUCCEEDED": f"运行治理审计通过：{maturity_level} 等级所有证据齐全且验证一致",
        "BLOCKED": f"运行治理审计受阻（INPUT_MISSING）：{maturity_level} 等级缺少必需证据",
        "FAILED": f"运行治理审计失败（CONTRACT_INCOMPATIBLE）：{maturity_level} 等级发现合同不兼容错误",
    }

    result_envelope = contracts_mod.build_result_envelope(
        run_id=run_id,
        stage_id=stage_id,
        execution_status=execution_status,
        summary=summary_map.get(execution_status, ""),
        outputs=[
            {
                "resource_id": "runtime-result",
                "name": "runtime_result",
                "kind": "domain_result",
                "path": "runtime-result.json",
                "required": True,
                "access": "read_only",
                "workspace_scope": output_scope,
                "content_digest": runtime_result_digest,
            },
            {
                "resource_id": "governance-findings",
                "name": "governance_findings",
                "kind": "artifact",
                "path": "governance-findings.json",
                "required": True,
                "access": "read_only",
                "workspace_scope": output_scope,
                "content_digest": sha256_bytes(gov_findings_bytes),
            },
            {
                "resource_id": "evidence-list",
                "name": "evidence_list",
                "kind": "artifact",
                "path": "evidence.json",
                "required": True,
                "access": "read_only",
                "workspace_scope": output_scope,
                "content_digest": sha256_bytes(evidence_bytes),
            },
            {
                "resource_id": "runtime-report",
                "name": "runtime_report",
                "kind": "artifact",
                "path": "report.zh-CN.md",
                "required": True,
                "access": "read_only",
                "workspace_scope": output_scope,
                "content_digest": sha256_bytes(report_bytes),
            },
        ],
        domain_results=[{
            "protocol_id": _METHOD_ID,
            "protocol_version": "1.0.0-candidate",
            "result_path": "runtime-result.json",
            "content_digest": runtime_result_digest,
        }],
        evidence=evidence_refs,
        missing_inputs=errors if execution_status == "BLOCKED" else [],
        warnings=[],
        errors=error_objects,
    )

    # ── 信封校验：任何文件写入前调用 assert_valid_envelope ──
    try:
        contracts_mod.assert_valid_envelope(
            task=task_envelope,
            result=result_envelope,
            evidence_items=evidence_refs,
        )
    except contracts_mod.EnvelopeValidationError as e:
        die(f"信封校验失败，不写入任何产物: {e}", code=2)

    # ── 所有产物先在内存中准备好 ──
    task_bytes = json.dumps(task_envelope, ensure_ascii=False, indent=2).encode("utf-8")
    result_bytes = json.dumps(result_envelope, ensure_ascii=False, indent=2).encode("utf-8")

    file_map = {
        "task.json": task_bytes,
        "result.json": result_bytes,
        "runtime-result.json": runtime_result_bytes,
        "governance-findings.json": gov_findings_bytes,
        "evidence.json": evidence_bytes,
        "report.zh-CN.md": report_bytes,
    }

    try:
        atomic_write_bundle(output_dir, file_map)
    except OSError as e:
        die(f"写入产物失败: {e}", code=2)

    # ── stdout 只输出一个机器可读摘要 JSON ──
    print(json.dumps({
        "execution_status": execution_status,
        "maturity_level": maturity_level,
        "platform": platform,
        "run_id": run_id,
        "error_count": len(errors),
        "output_dir": str(output_dir),
    }, ensure_ascii=False, indent=2))

    # ── 退出码 ──
    # SUCCEEDED → 0; BLOCKED/FAILED → 1; CLI 边界错误已在 die() 中退出 2
    sys.exit(0 if execution_status == "SUCCEEDED" else 1)


if __name__ == "__main__":
    main()
