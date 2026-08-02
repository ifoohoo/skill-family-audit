#!/usr/bin/env python3
"""Thin release-audit CLI over the receipt, public, and publish modules."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import release_public
import release_publish
import release_receipts
import release_assessments

# 动态导入 runtime_contracts（源码态与四平台投影使用不同兄弟目录名）
_SKILLS_ROOT = Path(__file__).resolve().parent.parent.parent
_RUNTIME_CONTRACTS_CANDIDATES = (
    _SKILLS_ROOT / "skill-family-audit-runtime/scripts/runtime_contracts.py",
    _SKILLS_ROOT / "skill-family-audit-runtime-audit/scripts/runtime_contracts.py",
    _SKILLS_ROOT / "runtime-audit/scripts/runtime_contracts.py",
)
_RUNTIME_CONTRACTS_MATCHES = [
    path for path in _RUNTIME_CONTRACTS_CANDIDATES
    if path.is_file() and not path.is_symlink()
]
if len(_RUNTIME_CONTRACTS_MATCHES) != 1:
    raise RuntimeError("release-audit runtime_contracts sibling is not unique")
_RUNTIME_CONTRACTS_PATH = _RUNTIME_CONTRACTS_MATCHES[0]
_spec = importlib.util.spec_from_file_location("release_runtime_contracts", _RUNTIME_CONTRACTS_PATH)
assert _spec and _spec.loader
_runtime_contracts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_runtime_contracts)


IMPLEMENTATION_FILES = (
    "release_audit.py",
    "release_assessments.py",
    "release_public.py",
    "release_publish.py",
    "release_receipts.py",
)


class ReleaseCliError(Exception):
    """CLI input or boundary validation failed."""


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseCliError(f"argument error: {message}")


def _consume_quickstart_task(argv: list[str]) -> dict[str, Any] | None:
    if not os.environ.get("SFA_NORMALIZED_TASK_REF"):
        return None
    path = Path(os.environ.get("SFA_RUNTIME_CONTRACTS_REF", ""))
    if not path.is_absolute() or path.is_symlink():
        raise ReleaseCliError("normalized Task contracts ref is invalid")
    resolved = path.resolve(strict=True)
    spec = importlib.util.spec_from_file_location(
        "release_quickstart_contracts", resolved
    )
    if spec is None or spec.loader is None:
        raise ReleaseCliError("normalized Task contracts are unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.consume_normalized_task(
        method_id="skill-family-audit:release-audit",
        script_path=__file__,
        argv=argv,
    )


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


def _load_context(value: str) -> dict[str, Any]:
    path = Path(_absolute_normalized(value, "runtime context"))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseCliError(f"runtime context is unavailable: {exc}") from exc
    if resolved != path or not resolved.is_file():
        raise ReleaseCliError("runtime context must be a real regular file")
    try:
        context = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseCliError(f"runtime context is not valid JSON: {exc}") from exc
    if not isinstance(context, dict):
        raise ReleaseCliError("runtime context must contain an object")
    return context


def _is_within(path: str, boundary: str) -> bool:
    try:
        return os.path.commonpath((path, boundary)) == boundary
    except ValueError:
        return False


def _preflight_context(context: dict[str, Any], target_project: str) -> str:
    if context.get("target_project_path") != target_project:
        raise ReleaseCliError("runtime context target_project_path does not match CLI")
    output = _absolute_normalized(context.get("output_dir"), "output_dir")
    release_publish.validate_output_target(output)
    if _is_within(output, target_project):
        raise ReleaseCliError("output_dir must be outside target_project")
    return output


def run(
    args: argparse.Namespace,
    quickstart_binding: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    target_project = _existing_real_directory(args.target_project, "target project")
    provider_root = _absolute_normalized(args.provider_root, "provider root")
    plan_path = (
        None
        if args.plan is None
        else _absolute_normalized(args.plan, "release plan")
    )
    run_path = (
        None if args.run is None else _absolute_normalized(args.run, "release run")
    )
    context = _load_context(args.runtime_context)
    output_dir = _preflight_context(context, target_project)
    digest_before = implementation_digest()

    audit = release_receipts.audit_release_receipts(
        provider_root=provider_root,
        plan_path=plan_path,
        run_path=run_path,
        expected_unit_id=args.unit_id,
        expected_target_version=args.target_version,
    )
    assessment_result = release_assessments.assess(
        release_assessments.load(
            Path(
                _absolute_normalized(
                    args.assessments_ref, "release assessments"
                )
            ).resolve(strict=True)
        ),
        expected_candidate_id=f"skill-family-audit:{args.target_version}",
    )
    if implementation_digest() != digest_before:
        raise ReleaseCliError("release-audit implementation changed during execution")
    bound_context = copy.deepcopy(context)
    bound_context["implementation_digest"] = digest_before
    bound_context["executor_id"] = (
        f"{release_receipts.PROVIDER_NAME}@{release_receipts.PROVIDER_VERSION}"
    )
    bundle = release_public.build_public_bundle(
        provider_root=provider_root,
        plan_path=plan_path,
        run_path=run_path,
        expected_unit_id=args.unit_id,
        expected_target_version=args.target_version,
        claimed_audit=audit,
        runtime_context=bound_context,
        assessment_result=assessment_result,
        assessments_path=_absolute_normalized(
            args.assessments_ref, "release assessments"
        ),
    )
    if quickstart_binding is not None:
        bundle["result"].setdefault("extensions", []).append(
            quickstart_binding
        )
        bundle["artifact_bytes"]["result.json"] = (
            json.dumps(
                bundle["result"],
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    artifact_digests = release_publish.publish_artifacts(
        output_dir=output_dir,
        artifact_bytes=bundle["artifact_bytes"],
    )
    status = bundle["result"]["execution_status"]
    response = {
        "run_id": bound_context["run_id"],
        "execution_status": status,
        "output_dir": output_dir,
        "artifact_digests": artifact_digests,
    }
    return (0 if status == "SUCCEEDED" else 1 if status == "BLOCKED" else 2), response


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        description="Audit one immutable Release Skill receipt chain"
    )
    parser.add_argument("--target-project", required=True)
    parser.add_argument("--provider-root", required=True)
    parser.add_argument("--plan")
    parser.add_argument("--run")
    parser.add_argument("--unit-id", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--runtime-context", required=True)
    parser.add_argument("--assessments-ref", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    binding = None
    try:
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        binding = _consume_quickstart_task(raw_argv)
        code, response = run(_parser().parse_args(raw_argv), binding)
    except Exception as exc:
        errors_list = list(getattr(exc, "errors", [str(exc)]))
        run_id = "run-release-audit-unknown"
        try:
            task_ref = os.environ.get("SFA_NORMALIZED_TASK_REF", "")
            if task_ref:
                run_id = json.loads(Path(task_ref).read_text()).get("run_id", run_id)
        except Exception:
            pass
        error_obj = _runtime_contracts.build_error(
            error_code="RELEASE_AUDIT.EXECUTION_EXCEPTION",
            category="EXECUTION_EXCEPTION",
            stage_id="release-audit",
            message=str(exc),
            affected_resources=[],
            evidence=[],
            retry_possible=False,
            remediation="修正输入参数或环境后重试",
        )
        response = _runtime_contracts.build_result_envelope(
            run_id=run_id,
            stage_id="release-audit",
            execution_status="BLOCKED",
            summary=f"发布审计预执行失败: {exc}",
            outputs=[],
            domain_results=[],
            evidence=[],
            missing_inputs=[],
            warnings=[],
            errors=[error_obj],
        )
        response["producer"] = {
            "skill": "skill-family-audit:release-audit",
            "method_ref": "skill-family-audit:release-audit",
            "script_id": "release_audit.py",
        }
        if binding is not None:
            response.setdefault("extensions", []).append(binding)
            _runtime_contracts.publish_bound_failure_result(
                binding, response
            )
        code = 2
    print(json.dumps(response, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
