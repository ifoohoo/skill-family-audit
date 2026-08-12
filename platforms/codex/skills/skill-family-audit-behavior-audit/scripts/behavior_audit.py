#!/usr/bin/env python3
"""Thin behavior-audit CLI over independently validated modules."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import behavior_domain
import behavior_execution
import behavior_fixture
import behavior_public
import behavior_publish


_IMPLEMENTATION_FILES = (
    "behavior_audit.py",
    "behavior_domain.py",
    "behavior_evidence.py",
    "behavior_execution.py",
    "behavior_fixture.py",
    "behavior_public.py",
    "behavior_publish.py",
)


class BehaviorCliError(Exception):
    """Raised for pre-execution CLI contract failures."""


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise BehaviorCliError(f"argument error: {message}")


def implementation_digest() -> str:
    """Bind evidence to the exact eight-module implementation used by this CLI."""

    scripts_dir = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for filename in _IMPLEMENTATION_FILES:
        content = (scripts_dir / filename).read_bytes()
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _load_json_file(path_value: str, label: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_absolute() or os.path.normpath(path_value) != path_value:
        raise BehaviorCliError(f"{label} must be an absolute normalized path")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise BehaviorCliError(f"{label} or an ancestor contains a symlink")
    if not resolved.is_file():
        raise BehaviorCliError(f"{label} must be a regular file")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BehaviorCliError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BehaviorCliError(f"{label} must contain a JSON object")
    return value


def _parse_now(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BehaviorCliError("--now-utc must be an ISO 8601 date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BehaviorCliError("--now-utc must include a timezone")
    return parsed


def _strict_existing_path(path_value: str, label: str, *, directory: bool) -> str:
    path = Path(path_value)
    if not path.is_absolute() or os.path.normpath(path_value) != path_value:
        raise BehaviorCliError(f"{label} must be an absolute normalized path")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise BehaviorCliError(f"{label} or an ancestor contains a symlink")
    if directory and not resolved.is_dir():
        raise BehaviorCliError(f"{label} must be a directory")
    if not directory and not resolved.is_file():
        raise BehaviorCliError(f"{label} must be a regular file")
    return str(resolved)


def _is_within(path: str, boundary: str) -> bool:
    try:
        return os.path.commonpath((path, boundary)) == boundary
    except ValueError:
        return False


def _preflight_context(
    context: dict[str, Any],
    *,
    target_project_path: str,
    fixture_manifest_path: str,
    sandbox_root: str,
) -> None:
    if context.get("target_project_path") != target_project_path:
        raise BehaviorCliError("runtime context target_project_path does not match CLI")
    inputs = context.get("inputs")
    if not isinstance(inputs, list):
        raise BehaviorCliError("runtime context inputs must be an array")
    by_name = {
        item.get("name"): item
        for item in inputs
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    expected = {
        "target_project_path": target_project_path,
        "fixture_manifest": fixture_manifest_path,
    }
    for name, path in expected.items():
        if by_name.get(name, {}).get("path") != path:
            raise BehaviorCliError(f"runtime context input {name} does not match CLI")
    output_dir = context.get("output_dir")
    if not isinstance(output_dir, str):
        raise BehaviorCliError("runtime context output_dir is required")
    behavior_publish.validate_output_target(output_dir)
    normalized_output = os.path.normpath(output_dir)
    if _is_within(normalized_output, target_project_path):
        raise BehaviorCliError("output_dir must be outside target_project_path")
    if _is_within(normalized_output, sandbox_root):
        raise BehaviorCliError("output_dir must be outside sandbox_root")


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    target_project_path = _strict_existing_path(
        args.target_project,
        "target project",
        directory=True,
    )
    fixture_manifest_path = _strict_existing_path(
        args.fixture_manifest,
        "fixture manifest",
        directory=False,
    )
    sandbox_root = _strict_existing_path(
        args.sandbox_root,
        "sandbox root",
        directory=True,
    )
    context = _load_json_file(args.runtime_context, "runtime context")
    _preflight_context(
        context,
        target_project_path=target_project_path,
        fixture_manifest_path=fixture_manifest_path,
        sandbox_root=sandbox_root,
    )
    implementation_digest_before = implementation_digest()

    plan = behavior_fixture.load_and_validate_fixture_plan(
        fixture_manifest_path=fixture_manifest_path,
        sandbox_root=sandbox_root,
        target_project_path=target_project_path,
        platform_selector=args.platform_selector,
        model_selector=args.model_selector,
        scope_selector=args.scope_selector,
        now_utc=_parse_now(args.now_utc),
    )
    max_wall_seconds = plan["manifest"]["isolation_profile"]["max_wall_seconds"]
    execution_records = [
        behavior_execution.run_fixture(
            fixture=fixture,
            sandbox_root=sandbox_root,
            target_project_root=target_project_path,
            isolation_max_wall_seconds=max_wall_seconds,
        )
        for fixture in plan["fixtures"]
    ]
    if implementation_digest() != implementation_digest_before:
        raise BehaviorCliError("behavior implementation changed during execution")
    domain_outputs = behavior_domain.build_domain_outputs(
        plan=plan,
        execution_records=execution_records,
    )

    bound_context = copy.deepcopy(context)
    bound_context["environment_digest"] = plan["provider_proof_summary"]["proof_digest"]
    bound_context["implementation_digest"] = implementation_digest_before
    bound_context["executor_id"] = plan["provider_proof_summary"]["provider_id"]
    bundle = behavior_public.build_public_bundle(
        plan=plan,
        execution_records=execution_records,
        domain_outputs=domain_outputs,
        runtime_context=bound_context,
    )
    behavior_publish.publish_artifacts(
        output_dir=bound_context["output_dir"],
        artifact_bytes=bundle["artifact_bytes"],
    )
    response = bundle["domain_result"]
    execution_status = response["behavior_result"]["overall_status"]
    return (0 if execution_status == "SUCCEEDED" else 1), response


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(description="Run one bounded behavior audit")
    parser.add_argument("--fixture-manifest", required=True)
    parser.add_argument("--sandbox-root", required=True)
    parser.add_argument("--target-project", required=True)
    parser.add_argument("--platform-selector", required=True)
    parser.add_argument("--model-selector", required=True)
    parser.add_argument("--scope-selector", required=True)
    parser.add_argument("--now-utc", required=True)
    parser.add_argument("--runtime-context", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        exit_code, response = run(_parser().parse_args(raw_argv))
    except Exception as exc:
        response = {
            "behavior_result": {
                "overall_status": "BLOCKED",
                "summary": f"行为审计预执行失败: {exc}",
            },
            "execution_records": [],
            "evidence_list": [],
            "regression_record": [],
        }
        exit_code = 2
    print(json.dumps(response, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
