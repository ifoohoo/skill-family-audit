#!/usr/bin/env python3
"""只读 release-audit CLI；领域结果只经 stdout 或宿主 Result 返回。

方法合同只绑定一个 ``release-audit-input`` Resource。该文档显式指定 Release
Skill 0.9.17 公共 CLI、计划、批准、目标 run、全部前驱 run、候选身份
和发布评估。Audit 只执行字节锁定的 ``verify-records`` 命令并消费其 stdout，
不读取相邻工作树、不扫描 ``.release-skill``，也不复制上游判定逻辑。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import release_public
import release_receipts
import release_assessments

IMPLEMENTATION_FILES = (
    "release_audit.py",
    "release_assessments.py",
    "release_public.py",
    "release_receipts.py",
)

RELEASE_AUDIT_INPUT_KIND = "skill-family-audit.release-audit-input"


class ReleaseCliError(Exception):
    """CLI input or boundary validation failed."""


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseCliError(f"argument error: {message}")


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
        raise ReleaseCliError("FOUNDATION_TRANSPORT_MISSING")
    sys.path.insert(0, str(script.parent))
    __import__("conformance_check")


def implementation_digest() -> str:
    scripts_dir = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for filename in IMPLEMENTATION_FILES:
        raw = (scripts_dir / filename).read_bytes()
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def _foundation_node_runtime() -> tuple[Path, str]:
    """Get the managed Node runtime through the existing Foundation host."""
    _install_foundation_host()
    host = sys.modules["conformance_check"].foundation_host_for(__file__)
    try:
        node_runtime, node_version = host.foundation_node_runtime()
    except Exception as exc:
        code = getattr(exc, "code", exc.__class__.__name__)
        raise ReleaseCliError(f"FOUNDATION_NODE_RUNTIME_UNAVAILABLE:{code}") from exc
    if not isinstance(node_runtime, Path) or not isinstance(node_version, str):
        raise ReleaseCliError("FOUNDATION_NODE_RUNTIME_UNAVAILABLE:INVALID_RESULT")
    return node_runtime, node_version


def _absolute_normalized(value: str, label: str) -> str:
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ReleaseCliError(f"{label} must be an absolute normalized path")
    return value


def _existing_real_directory(value: str, label: str) -> str:
    path = Path(_absolute_normalized(value, label))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseCliError(f"{label} is unavailable: {exc}") from exc
    if resolved != path or not resolved.is_dir():
        raise ReleaseCliError(f"{label} must be a real directory without symlinks")
    return str(resolved)


def _load_release_audit_input(value: str) -> dict[str, Any]:
    path = Path(_absolute_normalized(value, "release-audit input"))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseCliError(f"release-audit input is unavailable: {exc}") from exc
    if resolved != path or not resolved.is_file():
        raise ReleaseCliError(
            "release-audit input must be a real file without symlinks"
        )
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseCliError(f"release-audit input is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ReleaseCliError("release-audit input top level must be an object")
    if set(document) != {
        "schema_version",
        "kind",
        "candidate",
        "assessments_ref",
        "release_skill",
        "records",
    }:
        raise ReleaseCliError("release-audit input field set must be exactly closed")
    if (
        document.get("schema_version") != "1.0.0"
        or document.get("kind") != RELEASE_AUDIT_INPUT_KIND
    ):
        raise ReleaseCliError("release-audit input identity is invalid")
    candidate = document.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {
        "unit_id",
        "target_version",
    }:
        raise ReleaseCliError("release-audit input candidate shape is invalid")
    if (
        not isinstance(candidate.get("unit_id"), str)
        or not candidate["unit_id"]
        or not isinstance(candidate.get("target_version"), str)
        or not candidate["target_version"]
    ):
        raise ReleaseCliError("release-audit input candidate identity is invalid")
    release_skill = document.get("release_skill")
    if not isinstance(release_skill, dict) or set(release_skill) != {
        "version",
        "cli_path",
    }:
        raise ReleaseCliError("release_skill shape is invalid")
    if release_skill.get("version") != release_receipts.UPSTREAM_CONTRACT_VERSION:
        raise ReleaseCliError("release_skill version is not the pinned version")
    _absolute_normalized(release_skill.get("cli_path"), "release_skill.cli_path")
    records = document.get("records")
    if not isinstance(records, dict) or set(records) != {
        "plan",
        "approval",
        "target_run",
        "source_runs",
    }:
        raise ReleaseCliError("records shape is invalid")
    for field in ("plan", "approval", "target_run"):
        _absolute_normalized(records.get(field), f"records.{field}")
    source_runs = records.get("source_runs")
    if not isinstance(source_runs, list) or not all(
        isinstance(path, str) for path in source_runs
    ):
        raise ReleaseCliError("records.source_runs must be an array of paths")
    for index, path in enumerate(source_runs):
        _absolute_normalized(path, f"records.source_runs[{index}]")
    assessments_ref = document.get("assessments_ref")
    if not isinstance(assessments_ref, str) or not os.path.isabs(assessments_ref):
        raise ReleaseCliError("assessments_ref must be an absolute path")
    return document


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    document = _load_release_audit_input(args.release_audit_input)
    candidate = document["candidate"]
    digest_before = implementation_digest()

    release_skill = document["release_skill"]
    records = document["records"]
    node_runtime, node_version = _foundation_node_runtime()
    audit = release_receipts.audit_release_receipts(
        node_runtime=node_runtime,
        node_version=node_version,
        release_skill_cli=release_skill["cli_path"],
        plan_path=records["plan"],
        approval_path=records["approval"],
        target_run_path=records["target_run"],
        source_run_paths=records["source_runs"],
        expected_unit_id=candidate["unit_id"],
        expected_target_version=candidate["target_version"],
    )
    assessment_result = release_assessments.assess(
        release_assessments.load(
            Path(
                _absolute_normalized(
                    document["assessments_ref"], "release assessments"
                )
            ).resolve(strict=True)
        ),
        expected_candidate_id=f"{candidate['unit_id']}:{candidate['target_version']}",
    )
    if implementation_digest() != digest_before:
        raise ReleaseCliError("release-audit implementation changed during execution")
    response = release_public._compose_domain_result(
        expected_unit_id=candidate["unit_id"],
        expected_target_version=candidate["target_version"],
        verifier_audit=audit,
        assessment_result=assessment_result,
        assessments_path=document["assessments_ref"],
    )
    status = response["release_result"]["status"]
    return (0 if status == "SUCCEEDED" else 1 if status == "BLOCKED" else 2), response


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        description="Audit one immutable Release Skill receipt chain"
    )
    parser.add_argument("--release-audit-input", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        _install_foundation_host()
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        code, response = run(_parser().parse_args(raw_argv))
    except Exception as exc:
        response = {
            "release_result": {
                "status": "BLOCKED",
                "summary": f"发布审计预执行失败: {exc}",
            },
            "gate_findings": [],
            "evidence_list": [],
            "blocking_reasons": [str(exc)],
        }
        code = 2
    print(json.dumps(response, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
