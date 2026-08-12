#!/usr/bin/env python3
"""识别审计意图，并把 Audit 领域方法接到 Foundation Quickstart Profile v2 信封。

四方法唯一的 Task/Result 交接点：PluginProject 观察对象由 Audit 权威
inspector（``conformance_workflow.py --observe-only``）从受检目标机械投影；
调用方自带观察对象时必须与权威投影语义一致，否则以
``PLUGIN_PROJECT_OBSERVATION_MISMATCH`` 拒绝。参数与领域结果先由受管
Bundle 的 ``validators.mjs`` 按方法合同 ``$id`` 校验；Task 创建、三态
Result 包装和 exchange 复验全部调用 Bundle ``runner.mjs``。Audit 不复制
Foundation 的 canonical JSON、摘要、资源闭包或绑定算法。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
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
FOUNDATION_PROFILE_EXPECTED = {
    "id": "quickstart-profile",
    "version": 2,
    "taskContract": (
        "https://contracts.skill-family.example/candidate/"
        "quickstart-profile/v2/task.json"
    ),
    "resultContract": (
        "https://contracts.skill-family.example/candidate/"
        "quickstart-profile/v2/result.json"
    ),
}
FOUNDATION_SOURCE_EXPECTED = {
    "repository": "skill-family-foundation-workspace",
    "baseCommit": "d7f0d506a58ccef282d4def5b4542c0f8f589f04",
}
OBSERVATION_SCHEMA_ID = (
    "https://contracts.skill-family.example/skill-family-audit/"
    "candidate/v2/plugin-project-observation.json"
)

_FOUNDATION_CALL = r"""
import { pathToFileURL } from "node:url";
let raw = "";
for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
const api = await import(pathToFileURL(input.module).href);
let value;
if (input.action === "create-task") {
  value = await api.createQuickstartTask(input.payload);
} else if (input.action === "wrap-result") {
  value = api.wrapQuickstartResult(input.payload);
} else if (input.action === "assert-exchange") {
  value = await api.assertQuickstartExchange(input.payload);
} else if (input.action === "validate") {
  value = api.validateBySchemaId(input.payload.schemaId, input.payload.document);
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
        raw = Path(explicit)
        if raw.is_symlink():
            raise RouteError("PLATFORM_MANIFEST_INVALID")
        path = raw.resolve(strict=True)
        if path.is_symlink() or not path.is_file():
            raise RouteError("PLATFORM_MANIFEST_INVALID")
        return path
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "platform-manifest.json"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise RouteError("PLATFORM_MANIFEST_MISSING")


def _reject_symlink(raw: Path, code: str) -> None:
    if raw.is_symlink():
        raise RouteError(code)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_foundation_bundle(runner_ref: str) -> Path:
    """Validate a runner reference into a fully bound managed Bundle.

    The raw caller path is checked for symlinks before any resolution.  The
    runner must then sit next to ``validators.mjs`` and
    ``foundation-projection.json``; the provenance must carry the frozen
    profile and source identity; every payload member must exist with its
    recorded SHA-256 and no extra member may be present.  When a hand-off
    receipt exists next to the Bundle, its payload and provenance digests
    must also match.  Any hostile same-name runner in an arbitrary
    directory fails these checks.
    """
    raw = Path(runner_ref)
    _reject_symlink(raw, "FOUNDATION_RUNNER_SYMLINK")
    if not raw.is_file() or raw.name != "runner.mjs":
        raise RouteError("FOUNDATION_RUNNER_INVALID")
    runner = raw.resolve(strict=True)
    if runner.is_symlink() or not runner.is_file():
        raise RouteError("FOUNDATION_RUNNER_INVALID")

    bundle_root = runner.parent
    provenance_raw = bundle_root / "foundation-projection.json"
    validators_raw = bundle_root / "validators.mjs"
    for member in (provenance_raw, validators_raw):
        _reject_symlink(member, "FOUNDATION_BUNDLE_MEMBER_SYMLINK")
        if not member.is_file():
            raise RouteError("FOUNDATION_BUNDLE_MEMBER_MISSING")

    provenance = load(provenance_raw.resolve(strict=True))
    if provenance.get("kind") != "skill-family.foundation-projection":
        raise RouteError("FOUNDATION_BUNDLE_PROVENANCE_INVALID")
    profile = provenance.get("profile")
    if (
        not isinstance(profile, dict)
        or profile.get("id") != FOUNDATION_PROFILE_EXPECTED["id"]
        or profile.get("version") != FOUNDATION_PROFILE_EXPECTED["version"]
    ):
        raise RouteError("FOUNDATION_BUNDLE_PROVENANCE_INVALID")
    source = provenance.get("source")
    if (
        not isinstance(source, dict)
        or source.get("repository") != FOUNDATION_SOURCE_EXPECTED["repository"]
        or source.get("baseCommit") != FOUNDATION_SOURCE_EXPECTED["baseCommit"]
    ):
        raise RouteError("FOUNDATION_BUNDLE_SOURCE_INVALID")

    payload = provenance.get("payload")
    files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(files, list) or not files:
        raise RouteError("FOUNDATION_BUNDLE_PAYLOAD_INVALID")
    declared: dict[str, str] = {}
    for entry in files:
        relative = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or relative in declared
        ):
            raise RouteError("FOUNDATION_BUNDLE_PAYLOAD_INVALID")
        declared[relative] = digest
    actual = {
        path.relative_to(bundle_root).as_posix()
        for path in bundle_root.rglob("*")
        if path.is_file()
    }
    if actual != set(declared) | {"foundation-projection.json"}:
        raise RouteError("FOUNDATION_BUNDLE_MEMBERSHIP_INVALID")
    for relative, digest in declared.items():
        member = bundle_root / relative
        _reject_symlink(member, "FOUNDATION_BUNDLE_MEMBER_SYMLINK")
        if not member.is_file():
            raise RouteError("FOUNDATION_BUNDLE_MEMBER_MISSING")
        if _sha256(member) != digest:
            raise RouteError("FOUNDATION_BUNDLE_MEMBER_DIGEST_MISMATCH")

    receipt_raw = bundle_root.parent / "foundation-handoff.json"
    if receipt_raw.is_symlink():
        raise RouteError("FOUNDATION_RECEIPT_INVALID")
    if receipt_raw.is_file():
        receipt = load(receipt_raw)
        provenance_digest = _sha256(provenance_raw)
        if (
            receipt.get("payloadDigest") != payload.get("digest")
            or receipt.get("provenanceDigest") != provenance_digest
        ):
            raise RouteError("FOUNDATION_RECEIPT_INVALID")
    return runner


def find_foundation_runner(
    explicit: str | None = None, *, platform_root: Path | None = None
) -> Path:
    raw = explicit or os.environ.get("SFA_FOUNDATION_RUNNER_REF")
    if not raw and platform_root is not None:
        candidate = platform_root / "foundation/quickstart-profile/runner.mjs"
        if candidate.is_file() or candidate.is_symlink():
            raw = str(candidate)
    if not raw:
        raise RouteError("FOUNDATION_RUNNER_MISSING")
    return verify_foundation_bundle(raw)


def find_foundation_validators(runner: Path) -> Path:
    validators = runner.parent / "validators.mjs"
    if validators.is_symlink() or not validators.is_file():
        raise RouteError("FOUNDATION_VALIDATORS_MISSING")
    return validators


def call_foundation(
    module: Path, action: str, payload: dict[str, Any]
) -> dict[str, Any]:
    completed = subprocess.run(
        ["node", "--input-type=module", "--eval", _FOUNDATION_CALL],
        input=json.dumps(
            {"module": str(module), "action": action, "payload": payload},
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


def validate_by_schema_id(
    validators: Path, schema_id: str, document: Any
) -> dict[str, Any]:
    outcome = call_foundation(
        validators, "validate", {"schemaId": schema_id, "document": document}
    )
    if not isinstance(outcome.get("valid"), bool):
        raise RouteError("FOUNDATION_VALIDATION_INVALID")
    return outcome


def resolve_method_contract(platform_root: Path, intent: str) -> tuple[str, str]:
    contract_path = platform_root / "shared" / "methods" / f"{intent}-audit.json"
    if contract_path.is_symlink() or not contract_path.is_file():
        raise RouteError("METHOD_CONTRACT_MISSING")
    binding = load(contract_path).get("strictIOBinding")
    if not isinstance(binding, dict):
        raise RouteError("METHOD_CONTRACT_INVALID")
    if binding.get("foundationProfile") != FOUNDATION_PROFILE_EXPECTED:
        raise RouteError("METHOD_CONTRACT_INVALID")
    parameter_ref = binding.get("parameterSchema", {}).get("$ref")
    result_ref = binding.get("outputSchema", {}).get("$ref")
    if not isinstance(parameter_ref, str) or not isinstance(result_ref, str):
        raise RouteError("METHOD_CONTRACT_INVALID")
    return parameter_ref, result_ref


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
    state: str,
    summary: str = "",
    domain_result: Any = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"task": task, "state": state, "errors": errors or []}
    if state == "succeeded":
        payload.update(
            {
                "summary": summary,
                "outputs": [],
                "evidence": [],
                "domainResult": domain_result,
            }
        )
    return call_foundation(runner, "wrap-result", payload)


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


def observation_derivation_inputs(
    method_args: list[str], fallback_target_type: str | None
) -> tuple[str | None, str | None]:
    parsed = parse_method_args(method_args)
    target = parsed.get("target") or parsed.get("target-project")
    target_type = parsed.get("target-type") or fallback_target_type
    return target, target_type


def _python_binary() -> str:
    return os.environ.get("SFA_PYTHON_BIN") or sys.executable or "python3"


def derive_authoritative_observation(
    inspector: Path, runner: Path, target: str, target_type: str
) -> tuple[dict[str, Any], bytes]:
    """Project the target through the Audit-authority PluginProject inspector.

    The same ``conformance_workflow.py --observe-only`` entry point that the
    conformance domain re-verifies against produces the observation, so the
    Resource bound to the Foundation Task and the domain rescan cannot drift.
    """
    completed = subprocess.run(
        [
            _python_binary(),
            str(inspector),
            "--observe-only",
            "--target",
            target,
            "--target-type",
            target_type,
        ],
        capture_output=True,
        env={**os.environ, "SFA_FOUNDATION_RUNNER_REF": str(runner)},
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", "replace"
        ).strip()
        raise RouteError(f"OBSERVATION_DERIVATION_FAILED:{detail[:512]}")
    raw = completed.stdout
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RouteError("OBSERVATION_DERIVATION_INVALID") from exc
    if not isinstance(document, dict):
        raise RouteError("OBSERVATION_DERIVATION_INVALID")
    return document, raw


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
    platform_root = manifest_path.parent
    script = resolve_method_script(intent, args.platform, manifest_path)
    runner = find_foundation_runner(
        args.foundation_runner, platform_root=platform_root
    )
    validators = find_foundation_validators(runner)
    parameter_schema_id, result_schema_id = resolve_method_contract(
        platform_root, intent
    )
    inspector = resolve_method_script("conformance", args.platform, manifest_path)
    target_value, target_type_value = observation_derivation_inputs(
        method_args, args.observation_target_type
    )
    if not target_value or not target_type_value:
        raise RouteError("OBSERVATION_INPUT_MISSING")
    derived_document, derived_bytes = derive_authoritative_observation(
        inspector, runner, target_value, target_type_value
    )
    if args.plugin_project_observation:
        raw_observation = Path(args.plugin_project_observation)
        if raw_observation.is_symlink():
            raise RouteError("OBSERVATION_INVALID")
        observation = raw_observation.resolve(strict=True)
        observation_document = load(observation)
        observation_outcome = validate_by_schema_id(
            validators, OBSERVATION_SCHEMA_ID, observation_document
        )
        if not observation_outcome["valid"]:
            raise RouteError(
                "OBSERVATION_SCHEMA_INVALID:"
                + json.dumps(observation_outcome["errors"], ensure_ascii=False)
            )
        if observation_document != derived_document:
            raise RouteError(
                "PLUGIN_PROJECT_OBSERVATION_MISMATCH:"
                "传入观察对象与受检目标的权威投影不一致"
            )
    else:
        observation = output_dir.parent / (
            output_dir.name + ".plugin-project-observation.json"
        )
        if observation.exists() or observation.is_symlink():
            raise RouteError("ROUTE_OUTPUT_ALREADY_EXISTS")
        observation.write_bytes(derived_bytes)
        observation_document = derived_document
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

    parameter_outcome = validate_by_schema_id(
        validators, parameter_schema_id, parameters
    )
    if not parameter_outcome["valid"]:
        result = wrap_foundation_result(
            runner,
            task,
            state="rejected",
            errors=[{
                "code": "SFC2003",
                "message": "Method parameters violate the Audit domain contract.",
                "details": {"schemaId": parameter_schema_id,
                            "errors": parameter_outcome["errors"]},
            }],
        )
        assert_foundation_exchange(runner, observation.parent, task, result)
        return _write_route_outputs(output_dir, intent, task, result, {
            "execution_status": "REJECTED",
            "intent": intent,
            "method_id": METHODS[intent],
            "method_exit_code": None,
            "result_state": "rejected",
        })

    completed = subprocess.run(
        [_python_binary(), str(script), *method_args],
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
    domain_succeeded = completed.returncode == 0 and (
        not isinstance(status, str) or status.startswith("SUCCEEDED")
    )
    summary = response.get("summary")
    if not isinstance(summary, str) or not summary:
        summary = f"{METHODS[intent]} {'completed' if domain_succeeded else 'failed'}"

    state = "failed"
    errors: list[dict[str, Any]] = []
    domain_result: Any = None
    if domain_succeeded:
        result_outcome = validate_by_schema_id(
            validators, result_schema_id, response
        )
        if result_outcome["valid"]:
            state = "succeeded"
            domain_result = response
        else:
            errors = [{
                "code": "SFC2004",
                "message": "Audit domain result violates the method contract.",
                "details": {"schemaId": result_schema_id,
                            "errors": result_outcome["errors"]},
            }]
    else:
        errors = [{
            "code": "SFC2004",
            "message": "Audit domain method did not complete successfully.",
        }]
    result = wrap_foundation_result(
        runner,
        task,
        state=state,
        summary=summary,
        domain_result=domain_result,
        errors=errors,
    )
    assert_foundation_exchange(runner, observation.parent, task, result)
    return _write_route_outputs(output_dir, intent, task, result, {
        "execution_status": "SUCCEEDED" if state == "succeeded" else "FAILED",
        "intent": intent,
        "method_id": METHODS[intent],
        "method_exit_code": completed.returncode,
        "result_state": state,
    })


def _write_route_outputs(
    output_dir: Path,
    intent: str,
    task: dict[str, Any],
    result: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
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
    receipt.update({
        "task_path": str(task_path),
        "result_path": str(result_path),
        "result": result,
    })
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
    value.add_argument("--plugin-project-observation")
    value.add_argument("--observation-target-type")
    value.add_argument("--foundation-runner")
    return value


def main() -> int:
    try:
        result = run(parser().parse_args())
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if result["execution_status"] == "SUCCEEDED":
            return 0
        if result["execution_status"] == "REJECTED":
            return 2
        return 1
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
