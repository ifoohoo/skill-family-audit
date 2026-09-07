#!/usr/bin/env python3
"""只读 release-audit CLI；领域结果只经 stdout 或宿主 Result 返回。

方法合同只绑定一个 ``release-audit-input`` Resource：候选身份、发布评估
引用与 Release Skill 公开验证器输出全部冻结在该文档内。``provider_root``、
``plan``、``run`` 等未进入方法合同的旁路参数不再存在；Audit 不复制
Release Skill 的判定逻辑。上游公开验证器尚未发布：输入文档携带的
``release_verifier_output`` 对象不解释为上游权威输出，确定性返回
BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE。
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
        "release_verifier_output",
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
    verifier_output = document.get("release_verifier_output")
    # 字段合同只接受对象或 null：null 表示未提供；提供对象时也不解释为
    # 上游权威输出（上游公开验证器尚未发布），稳定返回
    # BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE，不接受文件引用或符号链接旁路。
    if verifier_output is not None and not isinstance(verifier_output, dict):
        raise ReleaseCliError(
            "release_verifier_output must be an object or null; upstream "
            "verifier output may not be a file reference or a symlink"
        )
    assessments_ref = document.get("assessments_ref")
    if not isinstance(assessments_ref, str) or not os.path.isabs(assessments_ref):
        raise ReleaseCliError("assessments_ref must be an absolute path")
    return document


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    document = _load_release_audit_input(args.release_audit_input)
    candidate = document["candidate"]
    digest_before = implementation_digest()

    audit = release_receipts.audit_release_verifier_output(
        document.get("release_verifier_output"),
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
