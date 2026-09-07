#!/usr/bin/env python3
"""把两个只读 Audit 方法接到 Foundation Quickstart Profile v2。

Quickstart 只绑定调用方已经提供的证据文件。它可以启动 Audit 自身的领域
方法进程，但不得启动、观察、恢复、续接或调度受检目标。Task 创建、Result
包装与交换复验全部委托候选内的 Foundation runner；结果只经 stdout 或宿主
Result 返回，不创建任务、结果或路由收据目录。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


INTENTS = {
    "conformance": ("规范检查", "规范符合", "conformance"),
    "release": ("发布审计", "release"),
}
HUMAN_CONFORMANCE_INTENTS = (
    "准备发布",
    "发布准备",
    "冻结候选",
    "完整审计",
    "全量规范",
    "完整规范",
)
METHODS = {
    "conformance": "skill-family-audit:conformance-audit",
    "release": "skill-family-audit:release-audit",
}
SCRIPT_NAMES = {
    "conformance": "conformance_workflow.py",
    "release": "release_audit.py",
}
FORBIDDEN_METHOD_OPTIONS = {
    "fixture-manifest",
    "foundation-task-digest",
    "isolation-profile",
    "maturity-level",
    "observation-target-type",
    "observer",
    "output-dir",
    "plugin-project-observation",
    "profile-selection-reason",
    "recovery",
    "resume",
    "runtime-evidence",
    "runtime-schema-provider-root",
    "semantic-review-preflight",
    "semantic-review-stdin",
}
HUMAN_ROUTE_OPTIONS = {
    "execution-profile",
    "semantic-group-id",
    "semantic-selector",
}
METHOD_CLI_TO_PARAM_MAPPING: dict[str, dict[str, str]] = {
    "conformance": {
        "target": "target_project_path",
        "target-type": "scope_selector",
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
        "https://contracts.skill-family.example/"
        "quickstart-profile/v2/task.json"
    ),
    "resultContract": (
        "https://contracts.skill-family.example/"
        "quickstart-profile/v2/result.json"
    ),
}


class RouteError(RuntimeError):
    """请求无法形成合法的只读 Audit Task。"""


def _foundation_host(runner: Path | None = None):
    host = sys.modules.get("conformance_check")
    if host is None:
        raise RouteError("FOUNDATION_TRANSPORT_MISSING")
    return host.foundation_host_for(__file__, runner)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RouteError("JSON 顶层必须是对象")
    return value


def _trusted_input_file(value: str | None, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
    ):
        raise RouteError(f"{label} 必须是规范化绝对路径")
    raw = Path(value)
    if raw.is_symlink():
        raise RouteError(f"{label} 不得是符号链接")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise RouteError(f"{label} 不可用: {exc}") from exc
    if resolved != raw or not resolved.is_file():
        raise RouteError(f"{label} 必须是真实普通文件")
    return resolved


def select_intent(request: str) -> str:
    matches = [
        name
        for name, terms in INTENTS.items()
        if any(term.lower() in request.lower() for term in terms)
    ]
    if not matches and any(term in request.lower() for term in HUMAN_CONFORMANCE_INTENTS):
        return "conformance"
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


def _option_values(method_args: list[str], option: str) -> list[str]:
    """Return every value supplied for one value-taking CLI option."""
    values: list[str] = []
    index = 0
    expected = f"--{option}"
    while index < len(method_args):
        if method_args[index] == expected:
            if index + 1 >= len(method_args) or method_args[index + 1].startswith("--"):
                raise RouteError(f"METHOD_OPTION_VALUE_MISSING:{option}")
            values.append(method_args[index + 1])
            index += 2
        else:
            index += 1
    return values


def _without_options(method_args: list[str], options: set[str]) -> list[str]:
    """Remove Quickstart-only value options before invoking the domain method."""
    result: list[str] = []
    index = 0
    while index < len(method_args):
        item = method_args[index]
        if item.startswith("--") and item[2:] in options:
            if index + 1 >= len(method_args):
                raise RouteError(f"METHOD_OPTION_VALUE_MISSING:{item[2:]}")
            index += 2
        else:
            result.append(item)
            index += 1
    return result


def _foundation_strict_json(
    runner: Path, path: Path, label: str
) -> tuple[dict[str, Any], str]:
    try:
        receipt = call_foundation(
            runner,
            "read-file-strict",
            {"root": str(path.parent), "path": path.name, "encoding": "utf8"},
        )
        content = receipt.get("content")
        digest = receipt.get("sha256")
        if (
            not isinstance(content, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RouteError(f"{label}_STRICT_READ_INVALID")
        value = json.loads(content)
    except (OSError, json.JSONDecodeError, RouteError) as exc:
        if isinstance(exc, RouteError):
            raise
        raise RouteError(f"{label}_STRICT_READ_INVALID:{exc}") from exc
    if not isinstance(value, dict):
        raise RouteError(f"{label}_STRICT_READ_INVALID")
    return value, digest


def _load_human_route_module(
    runner: Path,
) -> tuple[Any, dict[str, Any], list[str], dict[str, str]]:
    """Load the conformance-owned route helpers and their managed authorities."""
    host = sys.modules.get("conformance_check")
    host_file = getattr(host, "__file__", None)
    if not isinstance(host_file, str):
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    scripts = Path(host_file).resolve().parent
    module_path = scripts / "conformance_human_route.py"
    refs = scripts.parent / "refs"
    registry_path = refs / "semantic-rule-groups.json"
    routing_path = refs / "method-assurance-trust-projection.json"
    if any(path.is_symlink() or not path.is_file() for path in (module_path, registry_path, routing_path)):
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    spec = importlib.util.spec_from_file_location(
        "skill_family_audit_conformance_human_route", module_path
    )
    if spec is None or spec.loader is None:
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    registry, registry_digest = _foundation_strict_json(
        runner, registry_path, "HUMAN_ROUTE_REGISTRY"
    )
    routing, routing_file_digest = _foundation_strict_json(
        runner, routing_path, "HUMAN_ROUTE_ROUTING"
    )
    trust_projection_digest = routing.get("projection_digest")
    if (
        not isinstance(trust_projection_digest, str)
        or len(trust_projection_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in trust_projection_digest
        )
    ):
        raise RouteError("HUMAN_ROUTE_ROUTING_INVALID")
    first_tier_static = routing.get("routing", {}).get("first_tier_static")
    if not isinstance(first_tier_static, list):
        raise RouteError("HUMAN_ROUTE_ROUTING_INVALID")
    deterministic_rule_ids = sorted({
        row.get("canonical_id")
        for row in first_tier_static
        if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
    })
    if len(deterministic_rule_ids) != len(first_tier_static):
        raise RouteError("HUMAN_ROUTE_ROUTING_INVALID")
    return module, registry, deterministic_rule_ids, {
        "registry_digest": registry_digest,
        "routing_file_digest": routing_file_digest,
        "trust_projection_digest": trust_projection_digest,
    }


def _human_intent(request: str) -> str:
    normalized = request.lower()
    if any(token in normalized for token in ("准备发布", "发布准备", "冻结候选")):
        return "release_preparation"
    if any(token in normalized for token in ("完整审计", "全量规范", "完整规范")):
        return "complete_audit"
    if any(token in normalized for token in ("确定性", "静态合同", "schema", "摘要")):
        return "deterministic_only"
    return "ordinary_conformance"


def _request_selectors(request: str, registry: dict[str, Any]) -> list[str]:
    """Extract only exact registered selector text from a human request."""
    candidates: list[str] = []
    for group in registry.get("groups", []):
        if not isinstance(group, dict):
            continue
        for value in (group.get("group_id"), group.get("name")):
            if isinstance(value, str) and value and value in request:
                candidates.append(value)
        for rule in group.get("rules", []):
            value = rule.get("canonical_id") if isinstance(rule, dict) else None
            if isinstance(value, str) and value and value in request:
                candidates.append(value)
    return candidates


def resolve_conformance_human_route(
    request: str, method_args: list[str], runner: Path
) -> tuple[dict[str, Any], dict[str, Any], Any, str, dict[str, str]]:
    """Materialize one human-facing profile before Task creation."""
    module, registry, deterministic_rule_ids, route_identity = (
        _load_human_route_module(runner)
    )
    profiles = _option_values(method_args, "execution-profile")
    if len(profiles) > 1:
        raise RouteError("HUMAN_ROUTE_PROFILE_AMBIGUOUS")
    selectors = [
        *_option_values(method_args, "semantic-selector"),
        *_option_values(method_args, "semantic-group-id"),
        *_request_selectors(request, registry),
    ]
    intent = _human_intent(request)
    try:
        route = module.resolve_human_route(
            profiles[0] if profiles else None,
            intent,
            selectors,
            registry,
            deterministic_rule_ids,
        )
    except ValueError as exc:
        raise RouteError(f"HUMAN_ROUTE_INVALID:{exc}") from exc
    return route, registry, module, intent, route_identity


def assert_release_preparation_input(
    method_args: list[str], evidence_set: list[dict[str, Any]]
) -> None:
    """准备发布只接受一个冻结候选源码树。"""
    parsed = parse_method_args(method_args)
    source_trees = [
        row
        for row in evidence_set
        if isinstance(row, dict) and row.get("kind") == "source_tree"
    ]
    if (
        parsed.get("target-type") != "release_artifact"
        or len(evidence_set) != 1
        or len(source_trees) != 1
        or parsed.get("target") != source_trees[0].get("path")
    ):
        raise RouteError(
            "RELEASE_PREPARATION_INPUT_INVALID:准备发布需要 release_artifact、"
            "唯一 source_tree，且 --target 必须绑定同一候选目录"
        )


def extract_execution_plan(stderr: str) -> dict[str, Any]:
    prefix = "SFA_EXECUTION_PLAN "
    rows = [line[len(prefix):] for line in stderr.splitlines() if line.startswith(prefix)]
    if len(rows) != 1:
        raise RouteError("EXECUTION_PLAN_EVENT_INVALID")
    try:
        event = json.loads(rows[0])
    except json.JSONDecodeError as exc:
        raise RouteError("EXECUTION_PLAN_EVENT_INVALID") from exc
    if not isinstance(event, dict):
        raise RouteError("EXECUTION_PLAN_EVENT_INVALID")
    return event


def assert_plan_event_binding(
    plan: dict[str, Any],
    domain: dict[str, Any],
    route_identity: dict[str, str],
) -> None:
    coverage = domain.get("coverage") or {}
    metrics = domain.get("execution_metrics") or {}
    assurance = domain.get("method_assurance")
    trusted_observation = (
        assurance.get("trusted_observation")
        if isinstance(assurance, dict)
        else None
    )
    selected_count = coverage.get("selected_count")
    deterministic_count = coverage.get("selected_deterministic_rule_count")
    selected_semantic_count = (
        selected_count - deterministic_count
        if isinstance(selected_count, int)
        and not isinstance(selected_count, bool)
        and isinstance(deterministic_count, int)
        and not isinstance(deterministic_count, bool)
        and selected_count >= deterministic_count
        else None
    )
    expected = {
        "kind": "skill-family-audit.execution-plan",
        "execution_profile": domain.get("execution_profile"),
        "target_digest": domain.get("target_digest"),
        "requested_semantic_group_ids": coverage.get(
            "requested_semantic_group_ids", []
        ),
        "selected_semantic_group_ids": coverage.get(
            "selected_semantic_group_ids", []
        ),
        "selected_deterministic_rule_count": coverage.get(
            "selected_deterministic_rule_count"
        ),
        "selected_semantic_rule_count": selected_semantic_count,
        "semantic_rules_skipped_missing_evidence_count": metrics.get(
            "semantic_rules_skipped_missing_evidence_count", 0
        ),
        "semantic_group_registry_digest": route_identity["registry_digest"],
        "routing_file_digest": route_identity["routing_file_digest"],
        "trust_projection_digest": route_identity["trust_projection_digest"],
    }
    plan_fields = set(expected) | {
        "selection_reason",
        "estimated_context_count",
        "estimated_input_tokens",
        "semantic_input_budget",
    }
    if (
        set(plan) != plan_fields
        or selected_semantic_count is None
        or any(plan.get(key) != value for key, value in expected.items())
    ):
        raise RouteError("PLAN_EVENT_BINDING_MISMATCH")
    semantic_rules_sent = metrics.get("semantic_rules_sent_to_model_count", 0)
    if (
        coverage.get("semantic_group_registry_digest")
        != route_identity["registry_digest"]
        or not isinstance(assurance, dict)
        or "trust_projection_digest" in assurance
        or not isinstance(trusted_observation, dict)
        or trusted_observation.get("trust_projection_digest")
        != route_identity["trust_projection_digest"]
        or not isinstance(plan.get("selection_reason"), str)
        or not plan["selection_reason"]
        or not isinstance(plan.get("estimated_context_count"), int)
        or isinstance(plan.get("estimated_context_count"), bool)
        or plan["estimated_context_count"] < metrics.get(
            "semantic_context_count", 0
        )
        or not isinstance(plan.get("estimated_input_tokens"), int)
        or isinstance(plan.get("estimated_input_tokens"), bool)
        or plan["estimated_input_tokens"] < metrics.get(
            "estimated_input_tokens", 0
        )
        or not (
            semantic_rules_sent is None
            or (
                isinstance(semantic_rules_sent, int)
                and not isinstance(semantic_rules_sent, bool)
            )
        )
        or (
            isinstance(semantic_rules_sent, int)
            and plan["selected_semantic_rule_count"] < semantic_rules_sent
        )
        or (
            plan.get("execution_profile") in {"mechanical", "economy"}
            and plan.get("semantic_input_budget") != 0
        )
    ):
        raise RouteError("PLAN_EVENT_BINDING_MISMATCH")


def transport_summary(intent: str, state: str) -> str:
    if state == "succeeded":
        if intent == "conformance":
            return (
                "Audit 领域结果已完成传输；请以 domainResult 与 human_summary "
                "判断审计结论。"
            )
        return f"{METHODS[intent]} completed"
    return f"{METHODS[intent]} failed"


def domain_result_summary(response: dict[str, Any]) -> dict[str, str]:
    """Keep a bounded diagnostic summary when a domain result is invalid."""
    domain = response.get("conformance_result")
    if not isinstance(domain, dict):
        return {}
    return {
        key: value
        for key in ("status", "reason_code", "summary")
        if isinstance((value := domain.get(key)), str) and value
    }


def execution_method_args(
    intent: str,
    method_args: list[str],
    operation_id: str,
    foundation_task_digest: str | None = None,
) -> list[str]:
    """Bind the conformance CLI identity to the enclosing Foundation Task."""
    if intent != "conformance":
        return list(method_args)
    declared = parse_method_args(method_args).get("run-id")
    if declared is not None and declared != operation_id:
        raise RouteError("METHOD_RUN_ID_MISMATCH")
    bound = list(method_args)
    if declared is None:
        bound.extend(["--run-id", operation_id])
    if foundation_task_digest is not None:
        if (
            not isinstance(foundation_task_digest, str)
            or len(foundation_task_digest) != 64
            or any(character not in "0123456789abcdef" for character in foundation_task_digest)
        ):
            raise RouteError("FOUNDATION_TASK_DIGEST_INVALID")
        bound.extend(["--foundation-task-digest", foundation_task_digest])
    return bound


def _conformance_evidence(path_value: str | None) -> tuple[Path, list[dict[str, Any]]]:
    path = _trusted_input_file(path_value, "evidence_set 文件")
    document = load(path)
    if set(document) != {"evidence_set"}:
        raise RouteError("EVIDENCE_SET_DOCUMENT_INVALID")
    evidence_set = document.get("evidence_set")
    if not isinstance(evidence_set, list) or not evidence_set:
        raise RouteError("EVIDENCE_SET_DOCUMENT_INVALID")
    return path, evidence_set


def extract_business_parameters(
    intent: str, method_args: list[str]
) -> tuple[dict[str, Any], Path]:
    parsed = parse_method_args(method_args)
    forbidden = sorted(set(parsed) & FORBIDDEN_METHOD_OPTIONS)
    if forbidden:
        raise RouteError(f"METHOD_OPTION_FORBIDDEN:{forbidden}")
    parameters: dict[str, Any] = {}
    for cli_name, field in METHOD_CLI_TO_PARAM_MAPPING[intent].items():
        if cli_name in parsed:
            parameters[field] = parsed[cli_name]

    if intent == "conformance":
        resource, evidence_set = _conformance_evidence(parsed.get("evidence-set"))
        parameters["evidence_set"] = evidence_set
        if "scope_selector" in parameters:
            parameters["scope_selector"] = {
                "single_skill": "skill",
                "family_source": "plugin",
                "project_adoption": "plugin",
                "release_artifact": "release",
            }.get(parameters["scope_selector"], parameters["scope_selector"])
        return parameters, resource

    resource = _trusted_input_file(parsed.get("assessments-ref"), "assessments 文件")
    unit_id = parsed.get("unit-id")
    version = parsed.get("target-version")
    if not unit_id or not version:
        raise RouteError("METHOD_PARAM_MISSING:candidate_release_ref")
    parameters["candidate_release_ref"] = f"{unit_id}:{version}"
    return parameters, resource


def find_platform_manifest(explicit: str | None = None) -> Path:
    if explicit:
        return _trusted_input_file(explicit, "platform manifest")
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "platform-manifest.json"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise RouteError("PLATFORM_MANIFEST_MISSING")


def find_foundation_runner(
    explicit: str | None = None, *, platform_root: Path | None = None
) -> Path:
    raw = explicit or os.environ.get("SFA_AUDIT_BUNDLE_RUNNER_REF")
    if not raw and platform_root is not None:
        candidate = platform_root / "foundation/quickstart-profile/runner.mjs"
        if candidate.is_file() or candidate.is_symlink():
            raw = str(candidate)
    if not raw:
        raise RouteError("FOUNDATION_RUNNER_MISSING")
    try:
        return _foundation_host(Path(raw)).verify_foundation_bundle(raw)
    except RuntimeError as exc:
        raise RouteError(str(exc)) from exc


def call_foundation(
    runner: Path, operation: str, payload: dict[str, Any]
) -> dict[str, Any]:
    try:
        return _foundation_host(runner).call_foundation_mechanism(
            runner, {"operation": operation, **payload}
        )
    except RuntimeError as exc:
        code = operation.upper().replace("-", "_")
        raise RouteError(f"FOUNDATION_{code}_FAILED:{exc}") from exc


def validate_by_schema_id(runner: Path, schema_id: str, document: Any) -> dict[str, Any]:
    """Validate one document through the ordered Foundation batch mechanism."""
    return validate_many_by_schema_id(runner, [(schema_id, document)])[0]


def validate_many_by_schema_id(
    runner: Path, requests: list[tuple[str, Any]]
) -> list[dict[str, Any]]:
    """Validate ordered consumer documents without copying Foundation validators."""
    if not requests or any(
        not isinstance(schema_id, str) or not schema_id
        for schema_id, _document in requests
    ):
        raise RouteError("FOUNDATION_VALIDATION_BATCH_INVALID")
    try:
        host = _foundation_host(runner)
        host.verify_foundation_bundle(str(runner.with_name("validators.mjs")))
        outcome = host.call_foundation_mechanism(
            runner,
            {
                "operation": "validate-many-by-schema-id",
                "requests": [
                    {"schemaId": schema_id, "document": document}
                    for schema_id, document in requests
                ],
            },
        )
    except RuntimeError as exc:
        raise RouteError(f"FOUNDATION_VALIDATE_FAILED:{exc}") from exc
    rows = outcome.get("results")
    if not isinstance(rows, list) or len(rows) != len(requests):
        raise RouteError("FOUNDATION_VALIDATION_BATCH_INVALID")
    results: list[dict[str, Any]] = []
    for index, (row, (schema_id, _document)) in enumerate(zip(rows, requests)):
        if (
            not isinstance(row, dict)
            or row.get("inputIndex") != index
            or row.get("schemaId") != schema_id
            or not isinstance(row.get("result"), dict)
            or not isinstance(row["result"].get("valid"), bool)
        ):
            raise RouteError("FOUNDATION_VALIDATION_BATCH_INVALID")
        results.append(row["result"])
    return results


def resolve_method_contract(platform_root: Path, intent: str) -> tuple[str, str]:
    contract_path = platform_root / "shared" / "methods" / f"{intent}-audit.json"
    if contract_path.is_symlink() or not contract_path.is_file():
        raise RouteError("METHOD_CONTRACT_MISSING")
    binding = load(contract_path).get("strictIOBinding")
    if (
        not isinstance(binding, dict)
        or binding.get("foundationProfile") != FOUNDATION_PROFILE_EXPECTED
    ):
        raise RouteError("METHOD_CONTRACT_INVALID")
    parameter_ref = binding.get("parameterSchema", {}).get("$ref")
    result_ref = binding.get("outputSchema", {}).get("$ref")
    if not isinstance(parameter_ref, str) or not isinstance(result_ref, str):
        raise RouteError("METHOD_CONTRACT_INVALID")
    return parameter_ref, result_ref


def create_foundation_task(
    runner: Path,
    resource: Path,
    *,
    operation_id: str,
    method: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    return call_foundation(
        runner,
        "create-task",
        {
            "root": str(resource.parent),
            "observationPath": resource.name,
            "observationId": f"{method}-input-evidence",
            "operationId": operation_id,
            "method": method,
            "parameters": parameters,
            "run": operation_id,
            "stage": method,
            "attempt": 1,
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
    resource_root: Path,
    task: dict[str, Any],
    result: dict[str, Any],
) -> None:
    outcome = call_foundation(
        runner,
        "verify-exchange",
        {"root": str(resource_root), "task": task, "result": result},
    )
    if outcome.get("valid") is not True:
        raise RouteError(
            "FOUNDATION_ASSERT_EXCHANGE_FAILED:"
            + json.dumps(outcome, ensure_ascii=False, sort_keys=True)
        )


def resolve_method_script(intent: str, platform: str, manifest_path: Path) -> Path:
    manifest = load(manifest_path)
    if manifest.get("platformId") != platform:
        raise RouteError("PLATFORM_PACKAGE_MISMATCH")
    mappings = [
        item
        for item in manifest.get("logicalMappings", [])
        if isinstance(item, dict) and item.get("logicalName") == METHODS[intent]
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


def _python_binary() -> str:
    return os.environ.get("SFA_PYTHON_BIN") or sys.executable or "python3"


def run(args: argparse.Namespace) -> dict[str, Any]:
    intent = select_intent(args.request)
    method_args = json.loads(args.method_args_json)
    if not isinstance(method_args, list) or any(
        not isinstance(item, str) for item in method_args
    ):
        raise RouteError("METHOD_ARGS_INVALID")

    manifest_path = find_platform_manifest(args.platform_manifest)
    platform_root = manifest_path.parent
    script = resolve_method_script(intent, args.platform, manifest_path)
    runner = find_foundation_runner(args.foundation_runner, platform_root=platform_root)
    parameter_schema_id, result_schema_id = resolve_method_contract(platform_root, intent)
    parameters, resource = extract_business_parameters(intent, method_args)
    human_route: dict[str, Any] | None = None
    human_registry: dict[str, Any] | None = None
    human_module: Any = None
    human_intent: str | None = None
    route_identity: dict[str, str] | None = None
    routed_method_args = list(method_args)
    if intent == "conformance":
        (
            human_route,
            human_registry,
            human_module,
            human_intent,
            route_identity,
        ) = resolve_conformance_human_route(args.request, method_args, runner)
        if human_intent == "release_preparation":
            assert_release_preparation_input(
                method_args, parameters["evidence_set"]
            )
        parameters["execution_profile"] = human_route["execution_profile"]
        if human_route["semantic_group_ids"]:
            parameters["semantic_group_ids"] = human_route["semantic_group_ids"]
        routed_method_args = _without_options(method_args, HUMAN_ROUTE_OPTIONS)
        routed_method_args.extend(
            ["--execution-profile", human_route["execution_profile"]]
        )
        for group_id in human_route["semantic_group_ids"]:
            routed_method_args.extend(["--semantic-group-id", group_id])
        routed_method_args.extend(
            ["--profile-selection-reason", human_route["selection_reason"]]
        )
    task = create_foundation_task(
        runner,
        resource,
        operation_id=args.run_id,
        method=f"{intent}-audit",
        parameters=parameters,
    )
    task_digest = call_foundation(
        runner,
        "digest-document",
        {"document": task},
    ).get("digest")
    invocation_args = execution_method_args(
        intent,
        routed_method_args,
        args.run_id,
        foundation_task_digest=task_digest,
    )

    parameter_outcome = validate_by_schema_id(runner, parameter_schema_id, parameters)
    if not parameter_outcome["valid"]:
        result = wrap_foundation_result(
            runner,
            task,
            state="rejected",
            errors=[{
                "code": "SFC2003",
                "message": "Method parameters violate the Audit domain contract.",
                "details": {
                    "schemaId": parameter_schema_id,
                    "errors": parameter_outcome["errors"],
                },
            }],
        )
        assert_foundation_exchange(runner, resource.parent, task, result)
        return {
            "execution_status": "REJECTED",
            "intent": intent,
            "method_id": METHODS[intent],
            "method_exit_code": None,
            "result_state": "rejected",
            "result": result,
        }

    completed = subprocess.run(
        [_python_binary(), str(script), *invocation_args],
        text=True,
        capture_output=True,
        env={**os.environ, "SFA_AUDIT_BUNDLE_RUNNER_REF": str(runner)},
        check=False,
    )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError:
        response = {"raw_stdout": completed.stdout[:1000]}
    if not isinstance(response, dict):
        response = {"value": response}
    execution_plan: dict[str, Any] | None = None
    if intent == "conformance":
        try:
            execution_plan = extract_execution_plan(
                completed.stderr if isinstance(completed.stderr, str) else ""
            )
        except RouteError:
            execution_plan = None
    state = "failed"
    errors: list[dict[str, Any]] = []
    domain_result: Any = None
    human_summary: Any = None
    if intent == "conformance":
        result_outcome = validate_by_schema_id(runner, result_schema_id, response)
        if result_outcome["valid"]:
            try:
                if execution_plan is None or route_identity is None:
                    raise RouteError("EXECUTION_PLAN_EVENT_INVALID")
                assert_plan_event_binding(
                    execution_plan,
                    response["conformance_result"],
                    route_identity,
                )
                if (
                    execution_plan.get("selection_reason")
                    != human_route["selection_reason"]
                ):
                    raise RouteError("PLAN_EVENT_BINDING_MISMATCH")
                human_summary = human_module.render_human_summary(
                    response["conformance_result"],
                    human_registry,
                    {"intent": human_intent},
                )
                state = "succeeded"
                domain_result = response
            except (KeyError, TypeError, ValueError, RouteError) as exc:
                state = "failed"
                domain_result = None
                errors = [{
                    "code": "SFC2004",
                    "message": "Audit domain result cannot render the required human summary.",
                    "details": {"error": str(exc)},
                }]
        else:
            details: dict[str, Any] = {
                "schemaId": result_schema_id,
                "errors": result_outcome["errors"],
            }
            diagnostic = domain_result_summary(response)
            if diagnostic:
                details["domainResultSummary"] = diagnostic
            errors = [{
                "code": "SFC2004",
                "message": "Audit domain result violates the method contract.",
                "details": details,
            }]
    else:
        status = response.get("execution_status")
        domain_succeeded = completed.returncode == 0 and (
            not isinstance(status, str) or status.startswith("SUCCEEDED")
        )
        if domain_succeeded:
            result_outcome = validate_by_schema_id(runner, result_schema_id, response)
            if result_outcome["valid"]:
                state = "succeeded"
                domain_result = response
            else:
                errors = [{
                    "code": "SFC2004",
                    "message": "Audit domain result violates the method contract.",
                    "details": {
                        "schemaId": result_schema_id,
                        "errors": result_outcome["errors"],
                    },
                }]
        else:
            errors = [{
                "code": "SFC2004",
                "message": "Audit domain method did not complete successfully.",
            }]
    summary = transport_summary(intent, state)
    result = wrap_foundation_result(
        runner,
        task,
        state=state,
        summary=summary,
        domain_result=domain_result,
        errors=errors,
    )
    assert_foundation_exchange(runner, resource.parent, task, result)
    response_payload = {
        "execution_status": "SUCCEEDED" if state == "succeeded" else "FAILED",
        "intent": intent,
        "method_id": METHODS[intent],
        "method_exit_code": completed.returncode,
        "result_state": state,
        "result": result,
    }
    if human_summary is not None:
        response_payload["human_summary"] = human_summary
    if execution_plan is not None:
        response_payload["execution_plan"] = execution_plan
    return response_payload


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--request", required=True)
    value.add_argument("--platform", required=True)
    value.add_argument("--method-args-json", required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--platform-manifest")
    value.add_argument("--foundation-runner")
    return value


def main() -> int:
    try:
        manifest_hint = next(
            (
                sys.argv[index + 1]
                for index, value in enumerate(sys.argv[:-1])
                if value == "--platform-manifest"
            ),
            None,
        )
        if manifest_hint:
            platform_root = Path(manifest_hint).resolve(strict=True).parent
            checker_dir = next(
                (
                    path.parent
                    for path in platform_root.glob(
                        "skills/*/scripts/conformance_check.py"
                    )
                    if path.is_file() and not path.is_symlink()
                ),
                None,
            )
            if checker_dir is not None and str(checker_dir) not in sys.path:
                sys.path.insert(0, str(checker_dir))
            __import__("conformance_check")
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
