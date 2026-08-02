"""runtime-audit 公共信封适配器。

为 runtime-audit 方法构造符合本仓公共 task / result / evidence 合同的信封，
并提供完整 Draft 2020-12 JSON Schema 校验。

本模块不读取墙钟、PID、环境变量或随机源；调用方传入所有运行时值。
本模块不写文件、不执行命令、不访问网络、不读外部仓库。
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 固定业务值（来自权威计划）
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "1.1.0-candidate"
_METHOD_ID = "skill-family-audit:runtime-audit"
_TARGET: dict[str, str] = {
    "skill": "runtime-audit",
    "method_ref": "skill-family-audit:runtime-audit",
    "script_id": "runtime_audit.py",
}
_AUTHORIZATION_REF = (
    "spec/user-decisions/current-spec-governance-approval-receipt.json"
)
_ACCEPTANCE_REF = "spec/contracts/result.schema.json"
_CANCEL_SEQUENCE: list[str] = [
    "STOP_DISPATCH",
    "PROPAGATE_CANCEL",
    "GRACEFUL_STOP",
]
_USAGE: dict[str, Any] = {
    "measurement_method": "unavailable",
    "context_limit_tokens": 200000,
}
_BUDGET: dict[str, Any] = {
    "model_context_limit_tokens": 200000,
    "skill_warning_tokens": 2000,
    "skill_intervention_tokens": 2400,
    "context_observation_threshold": 80000,
    "context_static_split_threshold": 96000,
    "reserved_output_tokens": 4000,
    "measurement_policy": "estimated",
}

# ---------------------------------------------------------------------------
# Schema 名称与路径
# ---------------------------------------------------------------------------

CONTRACT_SCHEMA_NAMES: list[str] = [
    "task",
    "result",
    "evidence-ref",
    "error",
    "resource",
    "side-effect",
    "usage",
    "budget",
    "control-channel",
]

def contract_root() -> Path:
    """解析公共合同根，不依赖 cwd 或机器绝对路径。"""

    script_path = Path(__file__).resolve()
    for root in script_path.parents:
        projected = root / "shared" / "contracts"
        if (root / "platform-manifest.json").is_file() and projected.is_dir():
            return projected
    source_root = script_path.parents[4] / "spec" / "contracts"
    if source_root.is_dir():
        return source_root
    raise FileNotFoundError("无法定位公共合同根（shared/contracts 或 spec/contracts）")

# ---------------------------------------------------------------------------
# 自定义异常
# ---------------------------------------------------------------------------


class EnvelopeValidationError(Exception):
    """信封校验失败时抛出，包含每项错误的 Schema 名称与 JSON 路径。"""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(
            f"信封校验失败（{len(errors)} 项错误）:\n" + "\n".join(errors)
        )


class NormalizedTaskBindingError(RuntimeError):
    """Quickstart Task 无法由真实方法入口验证时抛出。"""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _trusted_file(raw_path: str, label: str) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        raise NormalizedTaskBindingError(f"{label}_NOT_ABSOLUTE")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise NormalizedTaskBindingError(f"{label}_MISSING") from exc
    if resolved != path or path.is_symlink() or not resolved.is_file():
        raise NormalizedTaskBindingError(f"{label}_INVALID")
    return resolved


# 各方法 CLI 参数名到 strictIOBinding.parameterSchema 业务字段的映射。
# 与 quickstart_route.py 保持一致；runtime_contracts 独立维护，不依赖导入。
_METHOD_CLI_TO_PARAM_MAPPING: dict[str, dict[str, str]] = {
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


def _extract_business_parameters(
    intent: str, argv: list[str]
) -> dict[str, Any]:
    """由真实方法 CLI 参数独立重算 strictIOBinding.parameterSchema 业务参数。

    与 quickstart_route.extract_business_parameters 逻辑一致但独立实现。
    """
    mapping = _METHOD_CLI_TO_PARAM_MAPPING.get(intent, {})
    parsed: dict[str, str] = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--"):
            key = arg[2:]
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                parsed[key] = argv[i + 1]
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
            if param_key == "fixture_manifest":
                try:
                    parameters[param_key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    fixture_path = Path(value)
                    if not fixture_path.is_absolute():
                        raise NormalizedTaskBindingError(
                            "FIXTURE_MANIFEST_NOT_ABSOLUTE"
                        )
                    try:
                        loaded = json.loads(
                            fixture_path.resolve(strict=True).read_text(
                                encoding="utf-8"
                            )
                        )
                    except (OSError, json.JSONDecodeError) as exc:
                        raise NormalizedTaskBindingError(
                            "FIXTURE_MANIFEST_INVALID"
                        ) from exc
                    if not isinstance(loaded, dict):
                        raise NormalizedTaskBindingError(
                            "FIXTURE_MANIFEST_INVALID"
                        )
                    parameters[param_key] = loaded
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
                for cli_key, param_key in mapping.items():
                    if cli_key in inner_parsed and param_key not in parameters:
                        value = inner_parsed[cli_key]
                        if param_key == "fixture_manifest":
                            fixture_path = Path(value)
                            if not fixture_path.is_absolute():
                                raise NormalizedTaskBindingError(
                                    "FIXTURE_MANIFEST_NOT_ABSOLUTE"
                                )
                            try:
                                loaded = json.loads(
                                    fixture_path.resolve(strict=True).read_text(
                                        encoding="utf-8"
                                    )
                                )
                            except (OSError, json.JSONDecodeError) as exc:
                                raise NormalizedTaskBindingError(
                                    "FIXTURE_MANIFEST_INVALID"
                                ) from exc
                            if not isinstance(loaded, dict):
                                raise NormalizedTaskBindingError(
                                    "FIXTURE_MANIFEST_INVALID"
                                )
                            parameters[param_key] = loaded
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
            raise NormalizedTaskBindingError(
                "CANDIDATE_RELEASE_REF_MISSING"
            )
        parameters["candidate_release_ref"] = (
            f"skill-family-audit:{target_version}"
        )

    return parameters


def validate_method_parameters(
    parameters: dict[str, Any],
    parameter_schema: dict[str, Any],
) -> list[str]:
    """验证 Task parameters 是否符合 strictIOBinding.parameterSchema。

    独立于 Quickstart 路由，由真实方法调用以逐项比对业务参数。

    Args:
        parameters: Task 中的 parameters 字段。
        parameter_schema: 方法规范中的 strictIOBinding.parameterSchema。

    Returns:
        错误字符串列表；空列表表示通过。
    """
    _ensure_dependencies()
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(parameter_schema)
    errors: list[str] = []
    for error in sorted(
        validator.iter_errors(parameters), key=lambda e: list(e.absolute_path)
    ):
        path_str = _format_json_path(error.absolute_path)
        errors.append(f"[parameterSchema] {path_str}: {error.message}")
    return errors


def consume_normalized_task(
    *, method_id: str, script_path: str, argv: list[str]
) -> dict[str, Any] | None:
    """由真实方法消费并验证 Quickstart 生成的同一 Task。

    直接调用方法时环境变量全部缺失，返回 ``None``。一旦 Quickstart Task
    存在，其 Schema、方法、参数、候选与平台清单绑定必须全部成立。
    """

    names = (
        "SFA_NORMALIZED_TASK_REF",
        "SFA_PLATFORM_MANIFEST_REF",
    )
    values = {name: os.environ.get(name) for name in names}
    if not any(values.values()):
        return None
    if not all(values.values()):
        raise NormalizedTaskBindingError("NORMALIZED_TASK_CONTEXT_INCOMPLETE")

    task_path = _trusted_file(values[names[0]] or "", "NORMALIZED_TASK")
    manifest_path = _trusted_file(
        values[names[1]] or "", "PLATFORM_MANIFEST"
    )
    try:
        task = json.loads(task_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NormalizedTaskBindingError("NORMALIZED_TASK_CONTEXT_INVALID") from exc
    if not isinstance(task, dict) or not isinstance(manifest, dict):
        raise NormalizedTaskBindingError("NORMALIZED_TASK_CONTEXT_INVALID")
    task_errors = validate_contract(task, "task")
    if task_errors:
        raise NormalizedTaskBindingError(
            f"NORMALIZED_TASK_SCHEMA_INVALID:{task_errors[0]}"
        )

    # 路由元数据在 routing_metadata 中，不在 parameters 中
    routing_metadata = task.get("routing_metadata", {})
    parameters = task.get("parameters", {})
    target = task.get("target", {})
    expected_args_digest = hashlib.sha256(_canonical_json(argv)).hexdigest()
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    expected_script = Path(script_path).resolve().name
    if (
        task.get("method_id") != method_id
        or target.get("method_ref") != method_id
        or target.get("script_id") != expected_script
        or routing_metadata.get("method_args_digest") != expected_args_digest
        or routing_metadata.get("platform") != manifest.get("platformId")
        or routing_metadata.get("candidate_digest")
        != manifest.get("projectionDigest")
        or routing_metadata.get("platform_manifest_digest") != manifest_digest
    ):
        raise NormalizedTaskBindingError("NORMALIZED_TASK_BINDING_MISMATCH")

    # 独立从 argv 重算业务参数并与 Task.parameters 精确比对
    intent = routing_metadata.get("selected_intent", "")
    recomputed_params = _extract_business_parameters(intent, argv)
    if recomputed_params != parameters:
        raise NormalizedTaskBindingError("NORMALIZED_TASK_PARAMETERS_MISMATCH")

    task_bytes = task_path.read_bytes()
    return {
        "extension_id": "skill-family-audit:quickstart-task-binding",
        "task_ref": str(task_path),
        "task_digest": hashlib.sha256(task_bytes.rstrip(b"\n")).hexdigest(),
        "run_id": task["run_id"],
        "method_id": method_id,
        "script_id": expected_script,
        "method_args_digest": expected_args_digest,
        "candidate_digest": routing_metadata["candidate_digest"],
        "platform_manifest_digest": manifest_digest,
    }


def publish_bound_failure_result(
    binding: dict[str, Any], result: dict[str, Any]
) -> str:
    """把有效 Quickstart Task 下的方法失败 Result 写入唯一方法输出目录。"""

    task_path = _trusted_file(binding.get("task_ref", ""), "NORMALIZED_TASK")
    task = json.loads(task_path.read_text(encoding="utf-8"))
    errors = validate_contract(result, "result")
    if errors:
        raise NormalizedTaskBindingError(
            f"BOUND_FAILURE_RESULT_INVALID:{errors[0]}"
        )

    route_output = Path(task["output_dir"])
    write_set = task.get("write_set", [])
    method_outputs = [
        Path(value)
        for value in write_set
        if isinstance(value, str) and Path(value) != route_output
    ]
    if len(method_outputs) != 1:
        raise NormalizedTaskBindingError(
            "BOUND_FAILURE_METHOD_OUTPUT_NOT_UNIQUE"
        )
    output_dir = method_outputs[0]
    if (
        not output_dir.is_absolute()
        or os.path.normpath(str(output_dir)) != str(output_dir)
        or output_dir.is_symlink()
    ):
        raise NormalizedTaskBindingError("BOUND_FAILURE_OUTPUT_INVALID")
    if output_dir.exists():
        if not output_dir.is_dir() or any(output_dir.iterdir()):
            raise NormalizedTaskBindingError("BOUND_FAILURE_OUTPUT_NOT_EMPTY")
    else:
        output_dir.mkdir(parents=True)
    if output_dir.resolve(strict=True) != output_dir:
        raise NormalizedTaskBindingError("BOUND_FAILURE_OUTPUT_NOT_REALPATH")

    payload = (
        json.dumps(
            result,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    temporary = output_dir / ".result.json.tmp"
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    target = output_dir / "result.json"
    os.replace(temporary, target)
    return str(target)


# ---------------------------------------------------------------------------
# Schema 加载与注册表
# ---------------------------------------------------------------------------


def load_contract_schemas() -> dict[str, dict]:
    """加载 spec/contracts/ 下所有公共合同 Schema。

    Returns:
        以 Schema 短名为键、Schema JSON 为值的字典。

    Raises:
        RuntimeError: jsonschema 或 referencing 不可用。
        FileNotFoundError: Schema 文件缺失。
        RuntimeError: Schema 文件无法解析。
    """
    _ensure_dependencies()
    schemas: dict[str, dict] = {}
    for name in CONTRACT_SCHEMA_NAMES:
        path = contract_root() / f"{name}.schema.json"
        if not path.is_file():
            raise FileNotFoundError(f"Schema 文件缺失: {path}")
        try:
            schemas[name] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Schema 文件无法解析: {path}: {exc}") from exc
    return schemas


def build_contract_registry(schemas: dict[str, dict]):
    """从提供的 Schema 字典构建 referencing Registry，用于 $ref 解析。

    Args:
        schemas: 以 Schema 短名为键的字典，通常来自 load_contract_schemas()。

    Returns:
        referencing.Registry 实例。

    Raises:
        ImportError: referencing 不可用。
        RuntimeError: $ref 目标不在 schemas 中。
    """
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    def _retrieve(uri: str):
        name = uri.split("/")[-1].replace(".schema.json", "")
        if name in schemas:
            return Resource.from_contents(schemas[name], DRAFT202012)
        raise RuntimeError(f"无法解析 $ref: {uri}（未在 schemas 中找到 '{name}'）")

    return Registry(retrieve=_retrieve)


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------


def validate_contract(
    instance: Any,
    schema_name: str,
    schemas: dict[str, dict] | None = None,
    registry: Any | None = None,
) -> list[str]:
    """对 instance 执行指定 Schema 的 Draft 2020-12 校验。

    Args:
        instance: 待校验的 JSON 对象。
        schema_name: CONTRACT_SCHEMA_NAMES 中的 Schema 短名。
        schemas: 可选，Schema 字典；为 None 时自动加载。
        registry: 可选，referencing.Registry；为 None 时自动构建。

    Returns:
        错误字符串列表，每项包含 Schema 名称与 JSON 路径；空列表表示通过。
    """
    from jsonschema import Draft202012Validator

    if schemas is None:
        schemas = load_contract_schemas()
    if registry is None:
        registry = build_contract_registry(schemas)

    if schema_name not in schemas:
        raise KeyError(f"未知 Schema 名称: {schema_name}")

    schema = schemas[schema_name]
    validator = Draft202012Validator(schema, registry=registry)
    errors: list[str] = []
    for error in sorted(
        validator.iter_errors(instance), key=lambda e: list(e.absolute_path)
    ):
        path_str = _format_json_path(error.absolute_path)
        errors.append(f"[{schema_name}] {path_str}: {error.message}")
    return errors


# ---------------------------------------------------------------------------
# 信封构造
# ---------------------------------------------------------------------------


def build_task_envelope(
    *,
    run_id: str,
    operation_id: str,
    stage_id: str,
    workspace_root: str,
    output_dir: str,
    parameters: dict,
    inputs: list,
    expected_outputs: list,
    process_id: str,
    lease_deadline: str,
) -> dict:
    """构造符合 task.schema.json 的任务信封。

    固定值由本模块填充；运行时值（run_id、时间、进程标识）由调用方传入。

    Returns:
        完整任务信封字典。
    """
    return {
        "schema_version": _SCHEMA_VERSION,
        "run_id": run_id,
        "method_id": _METHOD_ID,
        "operation_id": operation_id,
        "stage_id": stage_id,
        "attempt": 1,
        "target": dict(_TARGET),
        "workspace_root": workspace_root,
        "parameters": parameters,
        "inputs": inputs,
        "expected_outputs": expected_outputs,
        "output_dir": output_dir,
        "write_set": [],
        "authorization_ref": _AUTHORIZATION_REF,
        "acceptance_ref": _ACCEPTANCE_REF,
        "required_extensions": [],
        "budget": dict(_BUDGET),
        "control_channel": {
            "run_id": run_id,
            "process_id": process_id,
            "cancel_sequence": list(_CANCEL_SEQUENCE),
            "lease_deadline": lease_deadline,
            "cancel_acknowledged": False,
            "pre_submit_auth_recheck": False,
            "late_result_disposition": "discard",
        },
    }


def build_result_envelope(
    *,
    run_id: str,
    stage_id: str,
    execution_status: str,
    summary: str,
    outputs: list,
    domain_results: list,
    evidence: list,
    missing_inputs: list,
    warnings: list,
    errors: list,
) -> dict:
    """构造符合 result.schema.json 的结果信封。

    Returns:
        完整结果信封字典。
    """
    return {
        "schema_version": _SCHEMA_VERSION,
        "run_id": run_id,
        "stage_id": stage_id,
        "attempt": 1,
        "execution_status": execution_status,
        "summary": summary,
        "outputs": outputs,
        "domain_results": domain_results,
        "evidence": evidence,
        "missing_inputs": missing_inputs,
        "warnings": warnings,
        "errors": errors,
        "side_effects": [],
        "producer": {
            "skill": _TARGET["skill"],
            "method_ref": _TARGET["method_ref"],
            "script_id": _TARGET["script_id"],
        },
        "usage": dict(_USAGE),
    }


def build_error(
    *,
    error_code: str,
    category: str,
    stage_id: str,
    message: str,
    affected_resources: tuple = (),
    evidence: tuple = (),
    retry_possible: bool = False,
    remediation: str,
) -> dict:
    """构造符合 error.schema.json 的结构化错误。

    Returns:
        完整错误对象字典。
    """
    return {
        "error_code": error_code,
        "category": category,
        "stage_id": stage_id,
        "message": message,
        "affected_resources": list(affected_resources),
        "evidence": list(evidence),
        "side_effect_status": "NONE",
        "retry_possible": retry_possible,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# 断言校验
# ---------------------------------------------------------------------------


def assert_valid_envelope(
    task: dict,
    result: dict,
    evidence_items: list,
) -> None:
    """使用完整公共 Schema 注册表校验 task、result 和每条 evidence。

    任一校验失败时抛出 EnvelopeValidationError，包含 Schema 名称和 JSON 路径。
    不允许警告后继续。

    Args:
        task: 任务信封（待校验 task.schema.json）。
        result: 结果信封（待校验 result.schema.json）。
        evidence_items: 证据引用列表（每项待校验 evidence-ref.schema.json）。

    Raises:
        EnvelopeValidationError: 任一校验项存在错误。
    """
    schemas = load_contract_schemas()
    registry = build_contract_registry(schemas)

    all_errors: list[str] = []

    # 校验任务信封
    all_errors.extend(validate_contract(task, "task", schemas, registry))

    # 校验结果信封
    all_errors.extend(validate_contract(result, "result", schemas, registry))

    # 校验每条证据引用
    for idx, evidence in enumerate(evidence_items):
        item_errors = validate_contract(evidence, "evidence-ref", schemas, registry)
        for err in item_errors:
            all_errors.append(f"[evidence_items[{idx}]] {err}")

    if all_errors:
        raise EnvelopeValidationError(all_errors)


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------


def _ensure_dependencies() -> None:
    """确保 jsonschema 和 referencing 可用。

    Raises:
        RuntimeError: 依赖不可用。
    """
    try:
        import jsonschema  # noqa: F401
        import referencing  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema 和 referencing 是 runtime_contracts 的必需依赖，"
            "请安装后重试。"
        ) from exc


def _format_json_path(path) -> str:
    """将 jsonschema.ValidationError 的路径 deque 格式化为 JSON 路径字符串。

    Examples:
        deque()                    -> "$"
        deque(["field"])           -> "$.field"
        deque(["field", "sub"])    -> "$.field.sub"
        deque(["field", 0])        -> "$.field[0]"
        deque(["field", 0, "sub"]) -> "$.field[0].sub"
    """
    parts: list[str] = []
    for segment in path:
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
        else:
            parts.append(f".{segment}")
    return "$" + "".join(parts)
