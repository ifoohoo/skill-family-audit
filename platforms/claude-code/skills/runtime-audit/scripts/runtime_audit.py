#!/usr/bin/env python3
"""Audit existing runtime evidence and return only Audit-owned domain output.

Foundation Quickstart owns the operation request/result envelope. This module
validates Loop Agent evidence and writes the four runtime-domain artifacts; it
does not define or validate a second Task, Result, Resource, or lifecycle.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SCRIPT_DIR = Path(__file__).resolve().parent
_RUNTIME_EVIDENCE_PY = _SCRIPT_DIR / "runtime_evidence.py"
_METHOD_ID = "skill-family-audit:runtime-audit"
_VALID_MATURITY_LEVELS = ("candidate_ready", "consumer_qualified", "stable")
_BLOCKED_PATTERNS = (
    "missing required artifact",
    "must have at least 2 items",
    "must have at least 2 distinct consumer_domain",
    "missing required scenario types",
    "evidence_path: file does not exist",
)


class RuntimeAuditError(RuntimeError):
    """Runtime evidence input is unavailable or outside the read boundary."""


def _load_module(module_name: str, module_path: Path):
    if not module_path.is_file():
        raise RuntimeAuditError(f"依赖模块不存在: {module_path}")
    spec = importlib.util.spec_from_file_location(module_name, str(module_path))
    if spec is None or spec.loader is None:
        raise RuntimeAuditError(f"无法加载模块: {module_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_absolute_path(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeAuditError(f"{label} 必须是绝对路径，收到: {value}")
    try:
        path.resolve()
    except OSError as exc:
        raise RuntimeAuditError(f"{label} 路径解析失败: {exc}") from exc
    return path


def validate_dir_not_symlink(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeAuditError(f"{label} 必须是无符号链接的现存目录: {path}")


def validate_file_not_symlink(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeAuditError(f"{label} 必须是无符号链接的现存普通文件: {path}")


def _has_symlink_ancestor(path: Path) -> bool:
    current = path
    while True:
        if current.is_symlink():
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def validate_output_dir(path: Path) -> None:
    if _has_symlink_ancestor(path):
        raise RuntimeAuditError(f"output-dir 或其祖先不得包含符号链接: {path}")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise RuntimeAuditError(f"output-dir 必须不存在或为空: {path}")
    if not path.parent.is_dir():
        raise RuntimeAuditError(f"output-dir 父目录必须存在: {path.parent}")


def audit_contract_root() -> Path:
    """Locate Audit-owned evidence schemas; never expose generic envelopes."""

    for root in Path(__file__).resolve().parents:
        projected = root / "shared/contracts"
        if (root / "platform-manifest.json").is_file() and projected.is_dir():
            return projected
    source = Path(__file__).resolve().parents[4] / "spec/contracts"
    if source.is_dir():
        return source
    raise RuntimeAuditError("无法定位 Audit 领域合同根")


def classify_errors(errors: list[str]) -> tuple[str, str, str]:
    if errors and all(
        any(pattern in error.lower() for pattern in _BLOCKED_PATTERNS)
        for error in errors
    ):
        return "BLOCKED", "INPUT_MISSING", "EVIDENCE_MISSING"
    return "FAILED", "CONTRACT_INCOMPATIBLE", "EVIDENCE_INVALID"


def _build_evidence_refs_from_bundle(
    bundle: dict[str, Any],
    _run_id: str | None = None,
    _task_id: str | None = None,
) -> list[dict[str, Any]]:
    """Project validated Loop Agent descriptors into runtime-domain evidence."""

    evidence: list[dict[str, Any]] = []
    for category, descriptor in sorted((bundle.get("artifacts") or {}).items()):
        if isinstance(descriptor, dict):
            evidence.append({"category": category, **descriptor})
    for consumer in bundle.get("stable_consumers", []):
        if isinstance(consumer, dict):
            evidence.append({"category": "stable_consumer", **consumer})
    for scenario in bundle.get("control_scenarios", []):
        if isinstance(scenario, dict):
            evidence.append({"category": "control_scenario", **scenario})
    return evidence


def generate_report(
    execution_status: str,
    maturity_level: str,
    platform: str,
    error_category: str,
    error_code: str,
    errors: list[str],
) -> str:
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
    conclusions = {
        "SUCCEEDED": "✅ 审计通过：所有必需证据齐全且验证一致。",
        "BLOCKED": "🔒 审计受阻：缺少成熟度所需证据。",
        "FAILED": "❌ 审计失败：发现合同或证据不一致。",
    }
    lines.append(conclusions.get(execution_status, execution_status))
    if errors:
        lines.extend(["", f"## {error_category}:{error_code}", ""])
        lines.extend(f"- {error}" for error in errors)
    lines.append("")
    return "\n".join(lines)


def atomic_write_bundle(output_dir: Path, file_map: dict[str, bytes]) -> None:
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
            output_dir.rmdir()
        os.replace(staging, output_dir)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def _blocked_domain(message: str) -> dict[str, Any]:
    return {
        "runtime_result": {
            "protocol_id": _METHOD_ID,
            "execution_status": "BLOCKED",
            "validation_errors": [message],
        },
        "governance_findings": [{
            "severity": "error",
            "category": "INPUT_INVALID",
            "message": message,
        }],
        "evidence_list": [],
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Audit existing runtime evidence")
    value.add_argument("--target-project", required=True)
    value.add_argument("--runtime-evidence", required=True)
    value.add_argument("--maturity-level", required=True, choices=_VALID_MATURITY_LEVELS)
    value.add_argument("--platform", required=True)
    value.add_argument("--provider-root", required=True)
    value.add_argument("--output-dir", required=True)
    return value


def run(args: argparse.Namespace) -> dict[str, Any]:
    target_project = validate_absolute_path(args.target_project, "target-project")
    validate_dir_not_symlink(target_project, "target-project")
    evidence_path = validate_absolute_path(args.runtime_evidence, "runtime-evidence")
    validate_file_not_symlink(evidence_path, "runtime-evidence")
    provider_root = validate_absolute_path(args.provider_root, "provider-root")
    validate_dir_not_symlink(provider_root, "provider-root")
    output_dir = validate_absolute_path(args.output_dir, "output-dir")
    validate_output_dir(output_dir)
    if not args.platform.strip():
        raise RuntimeAuditError("platform 必须是非空字符串")

    raw_bytes = evidence_path.read_bytes()
    bundle = json.loads(raw_bytes)
    if not isinstance(bundle, dict):
        raise RuntimeAuditError("证据包顶层必须是 JSON 对象")
    identity = bundle.get("identity")
    if not isinstance(identity, dict) or identity.get("platform") != args.platform:
        raise RuntimeAuditError("证据包平台身份与 --platform 不一致")

    evidence_module = _load_module("runtime_evidence", _RUNTIME_EVIDENCE_PY)
    errors = evidence_module.validate_runtime_evidence_bundle(
        bundle,
        evidence_root=str(evidence_path.parent),
        provider_root=str(provider_root),
        public_contract_root=str(audit_contract_root()),
        maturity_level=args.maturity_level,
    )
    if errors:
        status, category, code = classify_errors(errors)
    else:
        status, category, code = "SUCCEEDED", "", ""

    provider = bundle.get("provider") or {}
    runtime_result = {
        "protocol_id": _METHOD_ID,
        "protocol_version": "1.0.0-candidate",
        "maturity_level": args.maturity_level,
        "platform": args.platform,
        "execution_status": status,
        "validation_errors": errors,
        "provider": {
            "provider_id": provider.get("provider_id", "loop-agent"),
            "provider_version": provider.get("provider_version", ""),
            "contract_digest": provider.get("contract_digest", ""),
        },
        "identity": {
            "run_id": identity.get("run_id", ""),
            "task_id": identity.get("task_id", ""),
        },
        "evidence_digest": sha256_bytes(raw_bytes),
    }
    findings = [
        {
            "finding_id": f"runtime-{index + 1}",
            "severity": "error",
            "category": category,
            "error_code": code,
            "message": error,
        }
        for index, error in enumerate(errors)
    ]
    evidence = _build_evidence_refs_from_bundle(bundle) if status == "SUCCEEDED" else []
    result = {
        "runtime_result": runtime_result,
        "governance_findings": findings,
        "evidence_list": evidence,
    }
    report = generate_report(
        status, args.maturity_level, args.platform, category, code, errors
    )
    file_map = {
        "runtime-result.json": json.dumps(runtime_result, ensure_ascii=False, indent=2).encode(),
        "governance-findings.json": json.dumps(findings, ensure_ascii=False, indent=2).encode(),
        "evidence.json": json.dumps(evidence, ensure_ascii=False, indent=2).encode(),
        "report.zh-CN.md": report.encode("utf-8"),
    }
    atomic_write_bundle(output_dir, file_map)
    return result


def main() -> int:
    try:
        result = run(parser().parse_args())
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["runtime_result"]["execution_status"] == "SUCCEEDED" else 1
    except (RuntimeAuditError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps(_blocked_domain(str(exc)), ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
