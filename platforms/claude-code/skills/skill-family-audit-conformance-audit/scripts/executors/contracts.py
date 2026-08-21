"""执行器共享上下文与治理声明文档合同。

目标项目治理声明的唯一机械位置是
``<target>/.skill-family-audit/governance/<document>.json``（采用锁的同级目录）。
每个文档都有严格字段合同：形状非法即失败关闭，绝不猜测语义。

文档缺省语义分两类（逐规则在各模块注明）：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 要求"必须声明"的规则：文档缺失本身即违反 → FAIL。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

HEX64_LEN = 64

#: 四个必需平台（SFA-PLAT-035/039 消费）。
REQUIRED_PLATFORMS = ("claude-code", "codex", "kimi-code", "workbuddy")

#: 人类固定入口（SFA-ENTRY-003 消费）。
FIXED_HUMAN_ENTRIES = ("help", "setup", "quickstart")

#: violation_impact 词表（SFA-RULE-005 消费）。
VIOLATION_IMPACT_VOCABULARY = ("block", "error", "warning", "observe")

#: 评估行状态词表（M4 消费）。
EVALUATION_ROW_STATUSES = (
    "PASS", "FAIL", "BLOCKED", "NOT_RUN", "EVIDENCE_MISSING", "NOT_APPLICABLE",
    "TIMEOUT", "CANCELLED", "EXCEPTION",
)

#: 隔离策略必须覆盖的维度（SFA-ISOLATION-002~007 对应字段）。
ISOLATION_DIMENSIONS = (
    "run_environment",
    "credential_inheritance",
    "credentials",
    "network",
    "mounts",
    "limits",
)

#: 自愈政策必须预先声明的字段（SFA-SELFHEAL-001）。
SELFHEAL_POLICY_FIELDS = (
    "allowed_actions",
    "max_technical_retries",
    "max_business_rework_rounds",
    "resource_budget",
    "termination_conditions",
    "escalation_conditions",
)


class ExecutorEvidenceError(ValueError):
    """治理声明形状非法等失败关闭情形。"""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def governance_dir(ctx: dict[str, Any]) -> Path:
    return Path(ctx["target"]) / ".skill-family-audit" / "governance"


def load_governance_document(
    ctx: dict[str, Any], name: str, *, required_fields: tuple[str, ...] = ()
) -> dict[str, Any] | None:
    """读取一个治理声明文档；缺失返回 None；形状非法失败关闭。"""
    path = governance_dir(ctx) / f"{name}.json"
    if not path.is_file():
        return None
    if path.is_symlink():
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_SYMLINK", f"治理声明不得是符号链接: {name}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"治理声明无法解析: {name}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"治理声明顶层必须是对象: {name}"
        )
    missing = [field for field in required_fields if field not in value]
    if missing:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INCOMPLETE",
            f"治理声明 {name} 缺少必需字段: {missing}",
        )
    return value


def rows_of(document: dict[str, Any], key: str, name: str) -> list[dict[str, Any]]:
    rows = document.get(key)
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(item, dict) for item in rows):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"治理声明 {name} 的 {key} 必须是对象数组"
        )
    return rows


def is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == HEX64_LEN
        and all(ch in "0123456789abcdef" for ch in value)
    )


def project_profile(ctx: dict[str, Any]) -> dict[str, Any]:
    profile = ctx.get("scope", {}).get("project_profile_document")
    if not isinstance(profile, dict):
        raise ExecutorEvidenceError("PROJECT_PROFILE_MISSING", "项目 Profile 不在执行上下文内")
    return profile


def observation(ctx: dict[str, Any]) -> dict[str, Any]:
    value = ctx.get("scope", {}).get("plugin_project")
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "PLUGIN_PROJECT_OBSERVATION_MISSING", "观察投影不在执行上下文内"
        )
    return value


def result(status: str, **evidence: Any) -> dict[str, Any]:
    return {"status": status, "evidence": dict(evidence)}
