"""behavior-audit 公共信封适配器。

为 behavior-audit 方法构造符合本仓公共 task / result / evidence 合同的信封，
并提供完整 Draft 2020-12 JSON Schema 校验。

本模块不读取墙钟、PID、环境变量或随机源；调用方传入所有运行时值。
本模块不写文件、不执行命令、不访问网络、不读外部仓库。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 固定业务值（来自权威计划）
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "1.1.0-candidate"
_METHOD_ID = "skill-family-audit:behavior-audit"
_TARGET: dict[str, str] = {
    "skill": "behavior-audit",
    "method_ref": "skill-family-audit:behavior-audit",
    "script_id": "behavior_audit.py",
}
_CANCEL_SEQUENCE: list[str] = [
    "STOP_DISPATCH",
    "PROPAGATE_CANCEL",
    "GRACEFUL_STOP",
]

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
    """解析公共合同根，不依赖 cwd 或机器绝对路径。

    安装投影以 platform-manifest.json 为根标记并携带 shared/contracts；
    源码态仅回退到当前仓库的 spec/contracts。
    """

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
    authorization_ref: str,
    acceptance_ref: str,
    isolation_profile: dict,
    workspace_root: str,
    output_dir: str,
    write_set: list,
    budget: dict,
    parameters: dict,
    inputs: list,
    expected_outputs: list,
    process_id: str,
    lease_deadline: str,
) -> dict:
    """构造符合 task.schema.json 的任务信封。

    固定值由本模块填充；authorization_ref、isolation_profile、write_set 及
    其他运行时值由调用方传入，不硬编码。

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
        "isolation_profile": isolation_profile,
        "parameters": parameters,
        "inputs": inputs,
        "expected_outputs": expected_outputs,
        "output_dir": output_dir,
        "write_set": list(write_set),
        "authorization_ref": authorization_ref,
        "acceptance_ref": acceptance_ref,
        "required_extensions": [],
        "budget": dict(budget),
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
    side_effects: list,
    usage: dict,
) -> dict:
    """构造符合 result.schema.json 的结果信封。

    side_effects 和 usage 由调用方传入真实值，不使用本模块硬编码的
    空列表或固定模板。

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
        "side_effects": list(side_effects),
        "producer": {
            "skill": _TARGET["skill"],
            "method_ref": _TARGET["method_ref"],
            "script_id": _TARGET["script_id"],
        },
        "usage": dict(usage),
    }


def build_error(
    *,
    error_code: str,
    category: str,
    stage_id: str,
    message: str,
    affected_resources: tuple = (),
    evidence: tuple = (),
    side_effect_status: str = "NONE",
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
        "side_effect_status": side_effect_status,
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
            "jsonschema 和 referencing 是 behavior_contracts 的必需依赖，"
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
