#!/usr/bin/env python3
"""Thin release-audit CLI over the receipt, public, and publish modules."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import release_public
import release_publish
import release_receipts
import release_assessments

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


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
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
        expected_candidate_id=f"{args.unit_id}:{args.target_version}",
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
    release_publish.publish_artifacts(
        output_dir=output_dir,
        artifact_bytes=bundle["artifact_bytes"],
    )
    response = bundle["domain_result"]
    status = response["release_result"]["status"]
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
    try:
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
