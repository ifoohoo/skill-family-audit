"""W2 第一档机械执行器包。

按执行族分模块组织真实检查实现，按授权批次前缀分派：

- ``w2b1:``  W2-B1 批 86 条 block 级机械候选规则（六族）
    - m1_rule_governance  M1 规则治理与不可豁免（7 条）
    - m2_entry_platform   M2 人类入口与平台投影（19 条）
    - m3_path_program     M3 路径收容与确定性程序（7 条）
    - m4_eval_evidence    M4 评估证据与门禁（20 条）
    - m5_context_isolation M5 上下文/隔离/自愈/运行框架（29 条）
    - m7_registry         M7 方法注册表（4 条）
- ``w2b2:``  W2-B2 批 violation_impact=error 机械候选规则（分子批接力）
    - m1_rule_governance_b2  M1 规则治理/制品图/权威/身份/关系（87 条）
    - m3_path_program_b2     M3 路径/程序/运行状态/任务结果/错误契约（75 条）
    - m2_entry_platform_b2   M2 人类入口/命名/平台投影/发行包/源码/摘要链（70 条）
    - m5_context_isolation_b2 M5 上下文/隔离/自愈/观察器/三档验证（57 条）
    - m4_eval_evidence_b2    M4 评估证据/判例/门禁/历史/档位（35 条）
    - m7_registry_b2         M7 方法注册表/制品方法/模板覆盖（23 条）
- ``w2b3:``  W2-B3 批 violation_impact=warning/observe 机械候选规则（33 条）
    - m5_context_isolation_b3 M5 上下文/隔离/运行框架/阶段隔离/第一档（14 条）
    - m3_path_program_b3     M3 目录职责扫描/运行状态/入口豁免（7 条）
    - m2_entry_platform_b3   M2 命名边界/词表扩展/平台模型/支持边界（6 条）
    - m7_registry_b3         M7 制品方法/注册对象/基础模板/覆盖（4 条）
    - m1_rule_governance_b3  M1 规则整改复验/外部组件条件规则（2 条）

设计边界（与任务书一致）：
- 只落真实机械断言；behavior_also_required 规则只覆盖机械半区，行为义务继续挂账。
- 执行器只消费目标事实：观察投影、采用锁、受检安装根、项目治理声明
  （``.skill-family-audit/governance/*.json``）、本次运行装载的规范包索引与自身不变量；
  绝不修改目标。
- 失败关闭：治理声明存在但形状非法 → FAIL/EVIDENCE_MISSING，不得静默放行。
"""
from __future__ import annotations

from typing import Any, Callable

from . import (
    m1_rule_governance,
    m1_rule_governance_b2,
    m1_rule_governance_b3,
    m2_entry_platform,
    m2_entry_platform_b2,
    m2_entry_platform_b3,
    m3_path_program,
    m3_path_program_b2,
    m3_path_program_b3,
    m4_eval_evidence,
    m4_eval_evidence_b2,
    m5_context_isolation,
    m5_context_isolation_b2,
    m5_context_isolation_b3,
    m7_registry,
    m7_registry_b2,
    m7_registry_b3,
)

RULE_PREFIX = "w2b1:"
B2_RULE_PREFIX = "w2b2:"
B3_RULE_PREFIX = "w2b3:"

_B1_MODULES = (
    m1_rule_governance,
    m2_entry_platform,
    m3_path_program,
    m4_eval_evidence,
    m5_context_isolation,
    m7_registry,
)
_B2_MODULES = (
    m1_rule_governance_b2,
    m3_path_program_b2,
    m2_entry_platform_b2,
    m5_context_isolation_b2,
    m4_eval_evidence_b2,
    m7_registry_b2,
)
_B3_MODULES = (
    m5_context_isolation_b3,
    m3_path_program_b3,
    m2_entry_platform_b3,
    m7_registry_b3,
    m1_rule_governance_b3,
)

CheckFn = Callable[[dict[str, Any]], dict[str, Any]]


def _collect(modules) -> dict[str, CheckFn]:
    checks: dict[str, CheckFn] = {}
    for module in modules:
        for canonical_id, check in module.CHECKS.items():
            if canonical_id in checks:
                raise ValueError(f"重复的执行器登记: {canonical_id}")
            checks[canonical_id] = check
    return checks


_REGISTRIES: dict[str, dict[str, CheckFn]] = {
    "w2b1": _collect(_B1_MODULES),
    "w2b2": _collect(_B2_MODULES),
    "w2b3": _collect(_B3_MODULES),
}

B1_RULE_COUNT = len(_REGISTRIES["w2b1"])
B2_RULE_COUNT = len(_REGISTRIES["w2b2"])
B3_RULE_COUNT = len(_REGISTRIES["w2b3"])
EXECUTOR_RULE_COUNT = B1_RULE_COUNT + B2_RULE_COUNT + B3_RULE_COUNT

_LEGAL_STATUSES = {"PASS", "FAIL", "EVIDENCE_MISSING", "NOT_APPLICABLE"}


def _registry_for(rule_id: str):
    """返回 (prefix, registry)；未命中任何批次前缀返回 (None, None)。"""
    if not isinstance(rule_id, str):
        return None, None
    for prefix, registry in _REGISTRIES.items():
        if rule_id.startswith(prefix + ":"):
            return prefix, registry
    return None, None


def supports(rule_id: str) -> bool:
    prefix, registry = _registry_for(rule_id)
    if registry is None:
        return False
    return rule_id[len(prefix) + 1:] in registry


def canonical_id_of(rule_id: str) -> str:
    prefix, registry = _registry_for(rule_id)
    if registry is None or rule_id[len(prefix) + 1:] not in registry:
        raise KeyError(rule_id)
    return rule_id[len(prefix) + 1:]


def execute(rule_id: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """执行单条 W2 第一档机械规则，返回 {status, evidence}。

    执行器抛出的异常由调用方（conformance_workflow）按失败关闭处理，
    不得在此吞掉异常伪装通过。
    """
    prefix, registry = _registry_for(rule_id)
    if registry is None or rule_id[len(prefix) + 1:] not in registry:
        raise KeyError(rule_id)
    check = registry[rule_id[len(prefix) + 1:]]
    outcome = check(ctx)
    if outcome.get("status") not in _LEGAL_STATUSES:
        raise ValueError(f"执行器返回非法状态: {rule_id} {outcome.get('status')!r}")
    if "evidence" not in outcome:
        raise ValueError(f"执行器缺少证据: {rule_id}")
    return outcome


def registered_canonical_ids(prefix: str = "w2b1") -> list[str]:
    """返回指定批次前缀下登记的 canonical 规则身份（默认 W2-B1，向后兼容）。"""
    if prefix not in _REGISTRIES:
        raise KeyError(prefix)
    return sorted(_REGISTRIES[prefix])
