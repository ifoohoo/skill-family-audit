#!/usr/bin/env python3
"""只做意图识别、Task 规范化、权限校验和四方法真实 CLI 路由。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
from datetime import datetime, timezone
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

# 各方法 CLI 参数名到 strictIOBinding.parameterSchema 业务字段的映射。
# CLI 参数使用 argparse 长选项名（去前缀 --），值来自 method_args。
METHOD_CLI_TO_PARAM_MAPPING: dict[str, dict[str, str]] = {
    "conformance": {
        "target": "target_project_path",
        "target-type": "scope_selector",
        "spec-package": "spec_version_ref",
        "platform": "platform_filter",
    },
    "behavior": {
        "artifact": "immutable_artifact_ref",
        "artifact-digest": "artifact_digest",
        "provider": "install_provider",
        "install-authorization": "install_authorization",
        "platform": "platform_selector",
        "target-project": "target_project_path",
        "platform-selector": "platform_selector",
        "scope-selector": "scope_selector",
        "model-selector": "model_selector",
        "fixture-manifest": "fixture_manifest",
    },
    "runtime": {
        "target-project": "target_project_path",
        "runtime-evidence": "runtime_evidence_ref",
        "maturity-level": "maturity_level",
        "platform": "platform_filter",
    },
    "release": {
        "target-project": "target_project_path",
        "assessments-ref": "assessments_ref",
    },
}


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
        raise RouteError(
            "INTENT_AMBIGUOUS" if matches else "INTENT_UNRECOGNIZED"
        )
    return matches[0]


def digest_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def verify_projection(manifest: dict[str, Any], manifest_path: Path) -> None:
    """独立重算平台投影树的文件集合与摘要，验证清单自报值。

    遍历 platform-manifest.json 所在目录，收集所有常规文件的相对路径，
    计算投影摘要（文件路径→内容哈希映射的 canonical JSON SHA-256），
    与清单声称的 ``files``、``fileCount`` 和 ``projectionDigest`` 逐项比对。

    投影摘要的计算方式与构建系统 ``tree_digest`` 一致：对排除清单自身
    后的文件树快照（路径→SHA-256 内容摘要）取 canonical JSON SHA-256。

    不信任清单自报摘要；任何不一致立即失败。
    """
    platform_root = manifest_path.parent
    IGNORED = {"__pycache__", ".DS_Store", ".pytest_cache"}
    manifest_name = manifest_path.name
    actual_files: list[str] = []
    tree_snapshot: dict[str, str] = {}
    for path in sorted(platform_root.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.suffix in {".pyc", ".pyo"}
        ):
            continue
        relative = path.relative_to(platform_root)
        rel_posix = relative.as_posix()
        # 清单自身不计入投影文件集
        if rel_posix == manifest_name and len(relative.parts) == 1:
            continue
        if any(part in IGNORED for part in relative.parts):
            continue
        actual_files.append(rel_posix)
        tree_snapshot[rel_posix] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    claimed_files = manifest.get("files")
    if not isinstance(claimed_files, list):
        raise RouteError("PROJECTION_FILES_INVALID")
    if sorted(claimed_files) != sorted(actual_files):
        raise RouteError("PROJECTION_FILES_MISMATCH")
    claimed_count = manifest.get("fileCount")
    if claimed_count != len(actual_files):
        raise RouteError("PROJECTION_FILE_COUNT_MISMATCH")
    # 投影摘要是文件树快照的 canonical JSON SHA-256（与构建系统一致）
    computed_digest = hashlib.sha256(
        json.dumps(
            tree_snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    claimed_digest = manifest.get("projectionDigest")
    if not isinstance(claimed_digest, str) or claimed_digest != computed_digest:
        raise RouteError("PROJECTION_DIGEST_MISMATCH")


def extract_business_parameters(
    intent: str, method_args: list[str]
) -> dict[str, Any]:
    """由真实方法 CLI 参数规范化出 strictIOBinding.parameterSchema 业务参数。

    使用 METHOD_CLI_TO_PARAM_MAPPING 将方法 CLI 长选项名映射到 parameterSchema
    字段名；CLI 参数使用 ``--key value`` 格式。未在映射中的参数被跳过。
    返回的字典键为 parameterSchema 字段名，值为对应 CLI 参数值。

    特殊处理：
    - conformance: platform_filter 缺失时默认 "all"
    - behavior: 解析 --invocation-args-json 内层参数，fixture_manifest 为对象
    - release: candidate_release_ref 从 plan/run/target-version 确定性绑定
    """
    mapping = METHOD_CLI_TO_PARAM_MAPPING.get(intent, {})
    if not mapping:
        raise RouteError("METHOD_PARAM_MAPPING_MISSING")
    parsed: dict[str, str] = {}
    i = 0
    while i < len(method_args):
        arg = method_args[i]
        if arg.startswith("--"):
            key = arg[2:]
            if i + 1 < len(method_args) and not method_args[i + 1].startswith("--"):
                parsed[key] = method_args[i + 1]
                i += 2
            else:
                parsed[key] = "true"
                i += 1
        else:
            i += 1
    parameters: dict[str, Any] = {}
    for cli_key, param_key in mapping.items():
        if cli_key in parsed:
            value = parsed[cli_key]
            # fixture_manifest 是对象参数：外层可直接传 JSON，已安装严格
            # 入口则传绝对文件路径；两种形态最终都绑定同一对象值。
            if param_key == "fixture_manifest":
                try:
                    parameters[param_key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    fixture_path = Path(value)
                    if not fixture_path.is_absolute():
                        raise RouteError("FIXTURE_MANIFEST_NOT_ABSOLUTE")
                    parameters[param_key] = load(
                        fixture_path.resolve(strict=True)
                    )
            else:
                parameters[param_key] = value

    if intent == "behavior" and "provider" in parsed and "provider-version" in parsed:
        parameters["install_provider"] = (
            f"{parsed['provider']}@{parsed['provider-version']}"
        )

    # behavior: 解析 invocation-args-json 内层参数
    if intent == "behavior" and "invocation-args-json" in parsed:
        try:
            inner_args = json.loads(parsed["invocation-args-json"])
            if isinstance(inner_args, list):
                inner_parsed: dict[str, str] = {}
                j = 0
                while j < len(inner_args):
                    arg = inner_args[j]
                    if isinstance(arg, str) and arg.startswith("--"):
                        key = arg[2:]
                        if j + 1 < len(inner_args) and isinstance(inner_args[j + 1], str) and not inner_args[j + 1].startswith("--"):
                            inner_parsed[key] = inner_args[j + 1]
                            j += 2
                        else:
                            inner_parsed[key] = "true"
                            j += 1
                    else:
                        j += 1
                # 内层参数只覆盖未由外层设置的字段
                for cli_key, param_key in mapping.items():
                    if cli_key in inner_parsed and param_key not in parameters:
                        value = inner_parsed[cli_key]
                        if param_key == "fixture_manifest":
                            fixture_path = Path(value)
                            if not fixture_path.is_absolute():
                                raise RouteError("FIXTURE_MANIFEST_NOT_ABSOLUTE")
                            parameters[param_key] = load(
                                fixture_path.resolve(strict=True)
                            )
                        else:
                            parameters[param_key] = value
        except (json.JSONDecodeError, TypeError):
            pass

    # conformance: platform_filter 缺失时默认 "all"
    if intent == "conformance" and "platform_filter" not in parameters:
        parameters["platform_filter"] = "all"

    # release: candidate_release_ref 从 plan/run/target-version 确定性绑定
    if intent == "release" and "candidate_release_ref" not in parameters:
        target_version = parsed.get("target-version")
        if not target_version:
            raise RouteError("METHOD_PARAM_MISSING:candidate_release_ref")
        parameters["candidate_release_ref"] = (
            f"skill-family-audit:{target_version}"
        )

    return parameters


def _resolve_candidate_release_ref() -> str:
    """从 release-plan 和当前版本确定性绑定 candidate_release_ref。"""
    # 尝试从 plugin-src/manifest.json 获取版本
    current = Path(__file__).resolve()
    for ancestor in current.parents:
        manifest_path = ancestor / "plugin-src" / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest = load(manifest_path)
                version = manifest.get("version", "")
                if version:
                    return f"skill-family-audit:{version}"
            except (RouteError, OSError):
                pass
    return "skill-family-audit:unknown"


def find_platform_manifest(explicit: str | None = None) -> Path:
    if explicit:
        manifest = Path(explicit).resolve(strict=True)
        if not manifest.is_file() or manifest.is_symlink():
            raise RouteError("PLATFORM_MANIFEST_INVALID")
        return manifest
    current = Path(__file__).resolve()
    for ancestor in current.parents:
        candidate = ancestor / "platform-manifest.json"
        if candidate.is_file():
            return candidate
    raise RouteError("PLATFORM_MANIFEST_MISSING")


def resolve_method_script(
    intent: str,
    platform: str,
    method_args: list[str],
    explicit_manifest: str | None = None,
) -> tuple[Path, dict[str, Any], Path]:
    manifest_path = find_platform_manifest(explicit_manifest)
    manifest = load(manifest_path)
    if manifest.get("platformId") != platform:
        raise RouteError("PLATFORM_PACKAGE_MISMATCH")
    # 独立重算投影树，不信任清单自报摘要
    verify_projection(manifest, manifest_path)
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
    script_name = SCRIPT_NAMES[intent]
    # Behavior 的外层公开调用接受不可变发行物与安装授权，必须先走真实
    # provider 安装闭环；安装后的公开入口不再携带 --artifact，因而路由到
    # 严格 behavior_audit.py，避免递归安装。
    if intent == "behavior" and "--artifact" in method_args:
        script_name = "behavior_install.py"
    script_relative = (
        Path(skill_path).parent / "scripts" / script_name
    ).as_posix()
    if script_relative not in manifest.get("files", []):
        raise RouteError("METHOD_IMPLEMENTATION_UNDECLARED")
    script = manifest_path.parent / script_relative
    if not script.is_file() or script.is_symlink():
        raise RouteError("METHOD_IMPLEMENTATION_MISSING")
    return script, manifest, manifest_path


def validate_authorization(
    authorization: dict[str, Any],
    *,
    method_id: str,
    platform: str,
    candidate_digest: str,
    method_args_digest: str,
    expected_write_set: list[str],
) -> None:
    expires_at = authorization.get("expires_at")
    try:
        expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RouteError("METHOD_AUTHORIZATION_INVALID") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise RouteError("METHOD_AUTHORIZATION_EXPIRED")
    if (
        authorization.get("granted") is not True
        or authorization.get("method_id") != method_id
        or authorization.get("platform") != platform
        or authorization.get("candidate_digest") != candidate_digest
        or authorization.get("method_args_digest") != method_args_digest
        or authorization.get("write_set") != expected_write_set
        or not isinstance(authorization.get("authorized_by"), str)
        or not authorization["authorized_by"]
    ):
        raise RouteError("METHOD_AUTHORIZATION_MISSING")


def _load_result_contracts(script: Path):
    platform_root = next(
        (
            ancestor
            for ancestor in script.parents
            if (ancestor / "platform-manifest.json").is_file()
        ),
        None,
    )
    if platform_root is None:
        raise RouteError("PLATFORM_MANIFEST_MISSING")
    manifest = load(platform_root / "platform-manifest.json")
    runtime_mapping = next(
        (
            item
            for item in manifest.get("logicalMappings", [])
            if isinstance(item, dict)
            and item.get("logicalName")
            == "skill-family-audit:runtime-audit"
        ),
        None,
    )
    runtime_skill = (
        runtime_mapping.get("path")
        if isinstance(runtime_mapping, dict)
        else None
    )
    if not isinstance(runtime_skill, str) or not runtime_skill.endswith(
        "/SKILL.md"
    ):
        raise RouteError("RESULT_VALIDATOR_MISSING")
    contracts_path = (
        platform_root
        / Path(runtime_skill).parent
        / "scripts/runtime_contracts.py"
    )
    if not contracts_path.is_file():
        raise RouteError("RESULT_VALIDATOR_MISSING")
    module_spec = importlib.util.spec_from_file_location(
        "quickstart_runtime_contracts", contracts_path
    )
    if module_spec is None or module_spec.loader is None:
        raise RouteError("RESULT_VALIDATOR_MISSING")
    contracts = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(contracts)
    return contracts


def validated_result(
    response: dict[str, Any], script: Path, expected_binding: dict[str, Any]
) -> dict[str, Any]:
    contracts = _load_result_contracts(script)
    candidates = [response]
    nested_result = response.get("result")
    if isinstance(nested_result, dict):
        candidates.insert(0, nested_result)
    output_dir = response.get("output_dir")
    if isinstance(output_dir, str) and Path(output_dir).is_absolute():
        result_path = Path(output_dir) / "result.json"
        if result_path.is_file() and not result_path.is_symlink():
            candidates.insert(0, load(result_path))
    binding_mismatch = False
    for candidate in candidates:
        errors = contracts.validate_contract(candidate, "result")
        if not errors:
            bindings = [
                item
                for item in candidate.get("extensions", [])
                if isinstance(item, dict)
                and item.get("extension_id")
                == "skill-family-audit:quickstart-task-binding"
            ]
            if bindings != [expected_binding]:
                binding_mismatch = True
                continue
            return candidate
    if binding_mismatch:
        raise RouteError("METHOD_TASK_BINDING_INVALID")
    raise RouteError(f"METHOD_RESULT_SCHEMA_INVALID:{errors[0]}")


def _load_method_spec(intent: str, platform_manifest_path: Path) -> dict[str, Any]:
    """加载方法规范 JSON，用于 strictIOBinding 参数校验。

    从平台树已验证投影 shared/methods/ 加载，不信任外部 spec/methods/。
    """
    platform_root = platform_manifest_path.parent
    spec_path = platform_root / "shared" / "methods" / f"{intent}-audit.json"
    if spec_path.is_file():
        return load(spec_path)
    raise RouteError("METHOD_SPEC_MISSING")


def _compute_write_set(
    intent: str,
    method_spec: dict[str, Any],
    output_dir: str,
    method_args: list[str],
) -> list[str]:
    """根据方法 sideEffects 和路由输出计算预期 write_set。

    路由始终写 task.json、result.json、route-result.json 到 output_dir，
    因此 write_set 必须包含 output_dir 及这些精确路径，即使方法声明 read-only。
    有写副作用的方法还需额外写路径。
    """
    del method_spec  # 业务只读不等于不写方法收据；以真实 CLI 为准。
    parsed: dict[str, str] = {}
    index = 0
    while index < len(method_args):
        item = method_args[index]
        if item.startswith("--") and index + 1 < len(method_args):
            parsed[item[2:]] = method_args[index + 1]
            index += 2
        else:
            index += 1
    paths = {str(Path(output_dir).resolve())}
    if intent in {"conformance", "runtime"} and parsed.get("output-dir"):
        paths.add(str(Path(parsed["output-dir"]).resolve()))
    elif intent == "release" and parsed.get("runtime-context"):
        context = load(Path(parsed["runtime-context"]).resolve(strict=True))
        method_output = context.get("output_dir")
        if not isinstance(method_output, str) or not Path(method_output).is_absolute():
            raise RouteError("METHOD_WRITE_SET_INVALID")
        paths.add(str(Path(method_output).resolve()))
    elif intent == "behavior":
        if parsed.get("artifact"):
            for key in ("isolation-root", "receipt-output"):
                value = parsed.get(key)
                if not value or not Path(value).is_absolute():
                    raise RouteError("METHOD_WRITE_SET_INVALID")
                paths.add(str(Path(value).resolve()))
        else:
            runtime_context = parsed.get("runtime-context")
            if not runtime_context:
                raise RouteError("METHOD_WRITE_SET_INVALID")
            context = load(Path(runtime_context).resolve(strict=True))
            method_output = context.get("output_dir")
            if (
                not isinstance(method_output, str)
                or not Path(method_output).is_absolute()
            ):
                raise RouteError("METHOD_WRITE_SET_INVALID")
            paths.add(str(Path(method_output).resolve()))
    return sorted(paths)


def run(args: argparse.Namespace) -> dict[str, Any]:
    # ── 第一阶段：输入验证（无副作用） ──
    output_dir = Path(args.output_dir).resolve()
    if output_dir.exists():
        raise RouteError("ROUTE_OUTPUT_ALREADY_EXISTS")
    if not output_dir.parent.is_dir():
        raise RouteError("ROUTE_OUTPUT_PARENT_MISSING")
    if not args.run_id or len(args.run_id) < 8:
        raise RouteError("RUN_ID_INVALID")
    intent = select_intent(args.request)
    method_id = METHODS[intent]
    authorization_path = Path(args.authorization).resolve(strict=True)
    authorization = load(authorization_path)
    if (
        authorization.get("granted") is not True
        or authorization.get("method_id") != method_id
    ):
        raise RouteError("METHOD_AUTHORIZATION_MISSING")
    platform = args.platform
    if platform not in {"codex", "claude-code", "kimi-code", "workbuddy"}:
        raise RouteError("PLATFORM_UNSUPPORTED")
    method_args = json.loads(args.method_args_json)
    if not isinstance(method_args, list) or any(
        not isinstance(item, str) for item in method_args
    ):
        raise RouteError("METHOD_ARGS_INVALID")

    # ── 第二阶段：投影验证与方法解析（含独立重算） ──
    script, platform_manifest, platform_manifest_path = resolve_method_script(
        intent,
        platform,
        method_args,
        getattr(args, "platform_manifest", None),
    )
    candidate_digest = platform_manifest.get("projectionDigest")
    if not isinstance(candidate_digest, str) or not candidate_digest:
        raise RouteError("CANDIDATE_IDENTITY_MISSING")
    method_args_digest = digest_json(method_args)

    # ── 第三阶段：strictIOBinding 业务参数规范化 ──
    business_params = extract_business_parameters(intent, method_args)
    method_spec = _load_method_spec(intent, platform_manifest_path)
    io_binding = method_spec.get("strictIOBinding", {})
    param_schema = io_binding.get("parameterSchema", {})
    if intent == "behavior" and script.name == "behavior_audit.py":
        installed_invocation = io_binding.get("installedInvocation", {})
        param_schema = installed_invocation.get("parameterSchema", {})
        if installed_invocation.get("script") != script.name or not param_schema:
            raise RouteError("METHOD_INSTALLED_INVOCATION_BINDING_MISSING")
    required_params = param_schema.get("required", [])
    for field in required_params:
        if field not in business_params:
            raise RouteError(f"METHOD_PARAM_MISSING:{field}")

    # 完整 Draft 2020-12 校验（pattern/type/enum/additionalProperties 等）
    contracts_for_params = _load_result_contracts(script)
    param_errors = contracts_for_params.validate_method_parameters(
        business_params, param_schema
    )
    if param_errors:
        raise RouteError(f"METHOD_PARAMETER_SCHEMA_INVALID:{param_errors[0]}")

    # ── 第四阶段：write_set 覆盖校验 ──
    expected_write_set = _compute_write_set(
        intent, method_spec, str(output_dir), method_args
    )
    validate_authorization(
        authorization,
        method_id=method_id,
        platform=platform,
        candidate_digest=candidate_digest,
        method_args_digest=method_args_digest,
        expected_write_set=expected_write_set,
    )

    # ── 第五阶段：构建 Task 并校验 Schema（仍在创建目录前） ──
    # Task.parameters 只含 parameterSchema 业务字段，路由元数据单独存放
    platform_manifest_digest = hashlib.sha256(
        platform_manifest_path.read_bytes()
    ).hexdigest()

    task = {
        "schema_version": "1.1.0-candidate",
        "run_id": args.run_id,
        "method_id": method_id,
        "operation_id": intent,
        "stage_id": intent,
        "attempt": 1,
        "target": {
            "skill": "skill-family-audit:quickstart",
            "method_ref": method_id,
            "script_id": script.name,
        },
        "workspace_root": args.workspace_root,
        "parameters": business_params,
        "routing_metadata": {
            "original_request": args.request,
            "platform": platform,
            "selected_intent": intent,
            "candidate_digest": candidate_digest,
            "method_args_digest": method_args_digest,
            "platform_manifest_digest": platform_manifest_digest,
        },
        "inputs": [],
        "expected_outputs": [],
        "output_dir": str(output_dir),
        "write_set": expected_write_set,
        "authorization_ref": str(Path(args.authorization).resolve()),
        "acceptance_ref": f"spec/methods/{intent}-audit.json",
        "required_extensions": [],
        "budget": {
            "model_context_limit_tokens": 1000,
            "skill_warning_tokens": 2000,
            "skill_intervention_tokens": 2400,
            "context_observation_threshold": 400,
            "context_static_split_threshold": 480,
            "reserved_output_tokens": 100,
            "measurement_policy": "estimated",
        },
        "control_channel": {
            "run_id": args.run_id,
            "process_id": "quickstart",
            "cancel_sequence": [
                "STOP_DISPATCH",
                "PROPAGATE_CANCEL",
                "GRACEFUL_STOP",
            ],
            "lease_deadline": "2099-01-01T00:00:00Z",
            "cancel_acknowledged": False,
            "pre_submit_auth_recheck": True,
            "late_result_disposition": "discard",
        },
    }

    # Task Schema 校验（在创建目录前完成）
    contracts = _load_result_contracts(script)
    task_errors = contracts.validate_contract(task, "task")
    if task_errors:
        raise RouteError(f"NORMALIZED_TASK_SCHEMA_INVALID:{task_errors[0]}")

    # ── 第六阶段：创建目录并写入 Task（所有验证已完成） ──
    output_dir.mkdir(parents=True, exist_ok=False)
    task_bytes = json.dumps(
        task, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    task_path = output_dir / "task.json"
    task_path.write_bytes(task_bytes + b"\n")

    expected_binding = {
        "extension_id": "skill-family-audit:quickstart-task-binding",
        "task_ref": str(task_path),
        "task_digest": hashlib.sha256(task_bytes).hexdigest(),
        "run_id": task["run_id"],
        "method_id": method_id,
        "script_id": script.name,
        "method_args_digest": method_args_digest,
        "candidate_digest": candidate_digest,
        "platform_manifest_digest": platform_manifest_digest,
    }
    # ── 第七阶段：执行前重新读取授权、subprocess 调用、Result 验证 ──
    # 任何异常或无效结果都进入同一持久化兜底。
    method_result = None
    completed = None
    result = None
    fallback_detail = "方法未返回合法 Result 信封"
    try:
        # 执行前重新读取同一授权，防止 Task 固化后授权被替换。
        validate_authorization(
            load(authorization_path),
            method_id=method_id,
            platform=platform,
            candidate_digest=candidate_digest,
            method_args_digest=method_args_digest,
            expected_write_set=expected_write_set,
        )
        completed = subprocess.run(
            ["python3", str(script), *method_args],
            text=True,
            capture_output=True,
            env={
                **os.environ,
                "SFA_NORMALIZED_TASK_REF": str(task_path),
                "SFA_PLATFORM_MANIFEST_REF": str(platform_manifest_path),
                "SFA_RUNTIME_CONTRACTS_REF": str(Path(contracts.__file__).resolve()),
            },
        )
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            result = None
        if not isinstance(result, dict):
            result = None

        if result is not None:
            method_result = validated_result(result, script, expected_binding)
        if method_result is None:
            raise RouteError("METHOD_RESULT_SCHEMA_INVALID")
        status = method_result.get("execution_status")
        if status not in {
            "SUCCEEDED", "SUCCEEDED_WITH_WARNINGS", "FAILED", "BLOCKED",
            "NEEDS_INPUT", "SKIPPED", "CANCELLED",
        }:
            raise RouteError("METHOD_RESULT_SCHEMA_INVALID")
        if (completed.returncode == 0) != status.startswith("SUCCEEDED"):
            raise RouteError("METHOD_EXIT_STATUS_MISMATCH")
    except Exception as exc:
        fallback_detail = str(exc) or type(exc).__name__
        method_result = None

    if method_result is None:
        # ── 兜底 Result：方法未能返回合法 Result ──
        # 只要 task.json 已写入，任何方法失败都必须在同一输出目录生成
        # 符合 result.schema.json 的规范化 Result 和 route-result.json。
        fallback_error = {
            "error_code": "QUICKSTART.METHOD_RESULT_INVALID",
            "category": "CONTRACT_INCOMPATIBLE",
            "stage_id": intent,
            "message": (
                f"方法执行或 Result 协议失败: {fallback_detail}; "
                f"stdout={completed.stdout[:200] if completed and completed.stdout else '(未执行或空输出)'}"
            ),
            "affected_resources": [str(script)],
            "evidence": [],
            "side_effect_status": "UNKNOWN",
            "retry_possible": False,
            "remediation": "检查方法脚本是否正确输出符合 result.schema.json 的 JSON 到 stdout",
        }
        fallback_result = {
            "schema_version": "1.1.0-candidate",
            "run_id": task["run_id"],
            "stage_id": intent,
            "attempt": 1,
            "execution_status": "BLOCKED",
            "summary": f"Quickstart 兜底：方法 {intent} 未返回合法 Result",
            "outputs": [],
            "domain_results": [],
            "evidence": [],
            "missing_inputs": [],
            "warnings": [],
            "errors": [fallback_error],
            "side_effects": [],
            "producer": {
                "skill": method_id,
                "worker": "skill-family-audit:quickstart",
                "method_ref": method_id,
                "script_id": script.name,
            },
            "usage": {"measurement_method": "unavailable", "context_limit_tokens": 1},
            "extensions": [expected_binding],
        }
        # 写入前用公共 Result Schema 和 expected_binding 重新验证
        contracts_for_fallback = _load_result_contracts(script)
        fallback_errors = contracts_for_fallback.validate_contract(
            fallback_result, "result"
        )
        if fallback_errors:
            raise RouteError(f"FALLBACK_RESULT_SCHEMA_INVALID:{fallback_errors[0]}")
        fallback_bindings = [
            item
            for item in fallback_result.get("extensions", [])
            if isinstance(item, dict)
            and item.get("extension_id")
            == "skill-family-audit:quickstart-task-binding"
        ]
        if fallback_bindings != [expected_binding]:
            raise RouteError("FALLBACK_RESULT_BINDING_INVALID")
        fallback_bytes = json.dumps(
            fallback_result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode() + b"\n"
        normalized_result_path = output_dir / "result.json"
        normalized_result_path.write_bytes(fallback_bytes)
        receipt = {
            "execution_status": "BLOCKED",
            "intent": intent,
            "method_id": method_id,
            "task_digest": hashlib.sha256(task_bytes).hexdigest(),
            "method_script": str(script),
            "method_exit_code": completed.returncode if completed else -1,
            "method_response": result if result is not None else {"raw_stdout": completed.stdout[:500] if completed else "(未执行)"},
            "result": fallback_result,
            "result_path": str(normalized_result_path),
            "result_digest": hashlib.sha256(fallback_bytes).hexdigest(),
            "business_logic_in_router": False,
        }
        (output_dir / "route-result.json").write_text(
            json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return receipt

    normalized_result_path = output_dir / "result.json"
    normalized_result_bytes = (
        json.dumps(
            method_result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    normalized_result_path.write_bytes(normalized_result_bytes)
    receipt = {
        "execution_status": status,
        "intent": intent,
        "method_id": method_id,
        "task_digest": hashlib.sha256(task_bytes).hexdigest(),
        "method_script": str(script),
        "method_exit_code": completed.returncode,
        "method_response": result,
        "result": method_result,
        "result_path": str(normalized_result_path),
        "result_digest": hashlib.sha256(
            normalized_result_bytes
        ).hexdigest(),
        "business_logic_in_router": False,
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
    value.add_argument("--authorization", required=True)
    value.add_argument("--method-args-json", required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--workspace-root", required=True)
    value.add_argument("--output-dir", required=True)
    value.add_argument("--platform-manifest")
    return value


def main() -> int:
    try:
        result = run(parser().parse_args())
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["execution_status"].startswith("SUCCEEDED") else 1
    except (RouteError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "execution_status": "BLOCKED",
            "error": str(exc),
        }, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
