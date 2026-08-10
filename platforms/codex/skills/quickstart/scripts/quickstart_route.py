#!/usr/bin/env python3
"""识别审计意图，并把 Audit 领域方法接到 Foundation Quickstart 信封。"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any


INTENTS = {
    "conformance": ("规范检查", "规范符合", "conformance"),
    "behavior": ("行为验证", "行为检查", "behavior"),
    "runtime": ("运行时审计", "runtime"),
    "release": ("发布审计", "release"),
}
METHODS = {
    "conformance": "skill-family-audit:conformance-audit",
    "behavior": "skill-family-audit:behavior-audit",
    "runtime": "skill-family-audit:runtime-audit",
    "release": "skill-family-audit:release-audit",
}
SCRIPT_NAMES = {
    "conformance": "conformance_workflow.py",
    "behavior": "behavior_audit.py",
    "runtime": "runtime_audit.py",
    "release": "release_audit.py",
}
METHOD_CLI_TO_PARAM_MAPPING: dict[str, dict[str, str]] = {
    "conformance": {
        "target": "target_project_path",
        "target-type": "scope_selector",
    },
    "behavior": {
        "target-project": "target_project_path",
        "fixture-manifest": "fixture_manifest",
    },
    "runtime": {
        "target-project": "target_project_path",
        "runtime-evidence": "runtime_evidence_ref",
        "maturity-level": "maturity_level",
    },
    "release": {
        "target-project": "target_project_path",
        "assessments-ref": "assessments_ref",
    },
}

_FOUNDATION_CALL = r"""
import { pathToFileURL } from "node:url";
let raw = "";
for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
const api = await import(pathToFileURL(input.runner).href);
let value;
if (input.action === "create-task") {
  value = await api.createQuickstartTask(input.payload);
} else if (input.action === "wrap-result") {
  value = api.wrapQuickstartResult(input.payload);
} else if (input.action === "assert-exchange") {
  value = await api.assertQuickstartExchange(input.payload);
} else {
  throw new Error(`unknown Foundation action: ${input.action}`);
}
process.stdout.write(`${JSON.stringify(value)}\n`);
"""


class RouteError(RuntimeError):
    pass


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RouteError("JSON 顶层必须是对象")
    return value


def select_intent(request: str) -> str:
    matches = [
        name
        for name, terms in INTENTS.items()
        if any(term.lower() in request.lower() for term in terms)
    ]
    if len(matches) != 1:
        raise RouteError("INTENT_AMBIGUOUS" if matches else "INTENT_UNRECOGNIZED")
    return matches[0]


def parse_method_args(method_args: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    index = 0
    while index < len(method_args):
        item = method_args[index]
        if item.startswith("--") and index + 1 < len(method_args):
            parsed[item[2:]] = method_args[index + 1]
            index += 2
        else:
            index += 1
    return parsed


def extract_business_parameters(intent: str, method_args: list[str]) -> dict[str, Any]:
    parsed = parse_method_args(method_args)
    parameters: dict[str, Any] = {}
    for cli_name, field in METHOD_CLI_TO_PARAM_MAPPING[intent].items():
        if cli_name not in parsed:
            continue
        value: Any = parsed[cli_name]
        if field == "fixture_manifest":
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = load(Path(value).resolve(strict=True))
        parameters[field] = value
    if intent == "conformance" and "scope_selector" in parameters:
        parameters["scope_selector"] = {
            "single_skill": "skill",
            "family_source": "plugin",
            "project_adoption": "plugin",
            "release_artifact": "release",
        }.get(parameters["scope_selector"], parameters["scope_selector"])
    if intent == "behavior" and isinstance(parameters.get("fixture_manifest"), dict):
        parameters["isolation_profile"] = parameters["fixture_manifest"].get(
            "isolation_profile", {}
        )
    if intent == "release":
        unit_id = parsed.get("unit-id")
        version = parsed.get("target-version")
        if not unit_id or not version:
            raise RouteError("METHOD_PARAM_MISSING:candidate_release_ref")
        parameters["candidate_release_ref"] = f"{unit_id}:{version}"
    return parameters


def find_platform_manifest(explicit: str | None = None) -> Path:
    if explicit:
        path = Path(explicit).resolve(strict=True)
        if path.is_symlink() or not path.is_file():
            raise RouteError("PLATFORM_MANIFEST_INVALID")
        return path
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "platform-manifest.json"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise RouteError("PLATFORM_MANIFEST_MISSING")


def find_foundation_runner(
    explicit: str | None = None, *, platform_root: Path | None = None
) -> Path:
    raw = explicit or os.environ.get("SFA_FOUNDATION_RUNNER_REF")
    if raw:
        runner = Path(raw).resolve(strict=True)
        if runner.is_symlink() or not runner.is_file():
            raise RouteError("FOUNDATION_RUNNER_INVALID")
        return runner
    if platform_root is not None:
        runner = platform_root / "foundation/quickstart-profile/runner.mjs"
        if runner.is_file() and not runner.is_symlink():
            return runner.resolve()
    raise RouteError("FOUNDATION_RUNNER_MISSING")


def call_foundation(
    runner: Path, action: str, payload: dict[str, Any]
) -> dict[str, Any]:
    completed = subprocess.run(
        ["node", "--input-type=module", "--eval", _FOUNDATION_CALL],
        input=json.dumps(
            {"runner": str(runner), "action": action, "payload": payload},
            ensure_ascii=False,
        ),
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RouteError(f"FOUNDATION_{action.upper().replace('-', '_')}_FAILED:{detail}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise RouteError("FOUNDATION_RESULT_INVALID")
    return value


def create_foundation_task(
    runner: Path,
    observation: Path,
    *,
    operation_id: str,
    method: str,
    parameters: dict[str, Any],
    run: str,
    stage: str,
    attempt: int = 1,
) -> dict[str, Any]:
    observation = observation.resolve(strict=True)
    return call_foundation(
        runner,
        "create-task",
        {
            "root": str(observation.parent),
            "observationPath": observation.name,
            "observationId": "plugin-project-observation",
            "operationId": operation_id,
            "method": method,
            "parameters": parameters,
            "run": run,
            "stage": stage,
            "attempt": attempt,
        },
    )


def wrap_foundation_result(
    runner: Path,
    task: dict[str, Any],
    *,
    domain_result: dict[str, Any],
    succeeded: bool,
    summary: str,
) -> dict[str, Any]:
    errors = [] if succeeded else [{
        "code": "SFC2004",
        "message": "Audit domain method did not complete successfully.",
    }]
    return call_foundation(
        runner,
        "wrap-result",
        {
            "task": task,
            "state": "succeeded" if succeeded else "failed",
            "summary": summary,
            "outputs": [],
            "evidence": [],
            "domainResult": domain_result,
            "errors": errors,
        },
    )


def assert_foundation_exchange(
    runner: Path,
    observation_root: Path,
    task: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    return call_foundation(
        runner,
        "assert-exchange",
        {"root": str(observation_root.resolve()), "task": task, "result": result},
    )


def resolve_method_script(
    intent: str, platform: str, manifest_path: Path
) -> Path:
    manifest = load(manifest_path)
    if manifest.get("platformId") != platform:
        raise RouteError("PLATFORM_PACKAGE_MISMATCH")
    method_id = METHODS[intent]
    mappings = [
        item
        for item in manifest.get("logicalMappings", [])
        if isinstance(item, dict) and item.get("logicalName") == method_id
    ]
    if len(mappings) != 1:
        raise RouteError("METHOD_MAPPING_INVALID")
    skill_path = mappings[0].get("path")
    if not isinstance(skill_path, str) or not skill_path.endswith("/SKILL.md"):
        raise RouteError("METHOD_MAPPING_INVALID")
    script = manifest_path.parent / Path(skill_path).parent / "scripts" / SCRIPT_NAMES[intent]
    if script.is_symlink() or not script.is_file():
        raise RouteError("METHOD_IMPLEMENTATION_MISSING")
    return script


def run(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = Path(args.output_dir).resolve()
    if output_dir.exists():
        raise RouteError("ROUTE_OUTPUT_ALREADY_EXISTS")
    if not output_dir.parent.is_dir():
        raise RouteError("ROUTE_OUTPUT_PARENT_MISSING")

    intent = select_intent(args.request)
    method_args = json.loads(args.method_args_json)
    if not isinstance(method_args, list) or any(
        not isinstance(item, str) for item in method_args
    ):
        raise RouteError("METHOD_ARGS_INVALID")
    manifest_path = find_platform_manifest(args.platform_manifest)
    script = resolve_method_script(intent, args.platform, manifest_path)
    runner = find_foundation_runner(
        args.foundation_runner, platform_root=manifest_path.parent
    )
    observation = Path(args.plugin_project_observation).resolve(strict=True)
    parameters = extract_business_parameters(intent, method_args)
    stage = f"{intent}-audit"
    task = create_foundation_task(
        runner,
        observation,
        operation_id=args.run_id,
        method=f"{intent}-audit",
        parameters=parameters,
        run=args.run_id,
        stage=stage,
    )

    completed = subprocess.run(
        ["python3", str(script), *method_args],
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "SFA_PLUGIN_PROJECT_OBSERVATION_REF": str(observation),
        },
    )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError:
        response = {"raw_stdout": completed.stdout[:1000]}
    if not isinstance(response, dict):
        response = {"value": response}
    status = response.get("execution_status")
    succeeded = completed.returncode == 0 and (
        not isinstance(status, str) or status.startswith("SUCCEEDED")
    )
    summary = response.get("summary")
    if not isinstance(summary, str) or not summary:
        summary = f"{METHODS[intent]} {'completed' if succeeded else 'failed'}"
    result = wrap_foundation_result(
        runner,
        task,
        domain_result=response,
        succeeded=succeeded,
        summary=summary,
    )
    assert_foundation_exchange(runner, observation.parent, task, result)

    output_dir.mkdir(parents=True, exist_ok=False)
    task_path = output_dir / "task.json"
    result_path = output_dir / "result.json"
    task_path.write_text(
        json.dumps(task, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result_path.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt = {
        "execution_status": "SUCCEEDED" if succeeded else "FAILED",
        "intent": intent,
        "method_id": METHODS[intent],
        "method_exit_code": completed.returncode,
        "task_path": str(task_path),
        "result_path": str(result_path),
        "result": result,
    }
    (output_dir / "route-result.json").write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return receipt


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--request", required=True)
    value.add_argument("--platform", required=True)
    value.add_argument("--authorization")
    value.add_argument("--method-args-json", required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--workspace-root")
    value.add_argument("--output-dir", required=True)
    value.add_argument("--platform-manifest")
    value.add_argument("--plugin-project-observation", required=True)
    value.add_argument("--foundation-runner")
    return value


def main() -> int:
    try:
        result = run(parser().parse_args())
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["execution_status"] == "SUCCEEDED" else 1
    except (RouteError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"execution_status": "BLOCKED", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
