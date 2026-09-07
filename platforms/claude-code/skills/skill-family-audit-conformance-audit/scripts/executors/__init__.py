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
候选模块 ``m1_rule_governance_gap``（W2-C2 候选批）保留在磁盘上，但不登记到
生产注册表：其九条规则尚未完成正式激活与实现绑定，不得进入生产路由闭包。

设计边界（与任务书一致）：
- 只落真实机械断言；behavior_also_required 规则只覆盖机械半区，行为义务继续挂账。
- 执行器只消费目标事实：观察投影、采用锁、受检安装根、项目治理声明
  （``.skill-family-audit/governance/*.json``）、本次运行装载的规范包索引与自身不变量；
  绝不修改目标。
- 失败关闭：治理声明存在但形状非法 → FAIL/EVIDENCE_MISSING，不得静默放行。
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (
    AGGREGATE_EVIDENCE_REFERENCE,
    ExecutorEvidenceError,
    validate_method_subresults,
)

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
_CANONICAL_CHECK_METHODS = {
    "behavior_verification",
    "digest_verification",
    "schema_validation",
    "semantic_review",
    "static_scan",
}
_MECHANICAL_CHECK_METHODS = {
    "digest_verification", "schema_validation", "static_scan",
}
_EXECUTOR_MODULE_FAMILIES = {
    "m1_": "M1",
    "m2_": "M2",
    "m3_": "M3",
    "m4_": "M4",
    "m5_": "M5",
    "m7_": "M7",
}


def _validate_method_route(route: Any) -> tuple[list[str], list[str]]:
    if not isinstance(route, dict):
        raise ValueError("执行器缺少受管 method route")
    methods = route.get("check_methods")
    required = route.get("required_mechanical_methods")
    revision_digest = route.get("revision_digest")
    if (
        not isinstance(methods, list)
        or not methods
        or len(methods) != len(set(methods))
        or any(method not in _CANONICAL_CHECK_METHODS for method in methods)
        or not isinstance(required, list)
        or not required
        or len(required) != len(set(required))
        or any(method not in _MECHANICAL_CHECK_METHODS for method in required)
        or sorted(set(methods) & _MECHANICAL_CHECK_METHODS) != sorted(required)
        or not isinstance(revision_digest, str)
        or len(revision_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in revision_digest)
    ):
        raise ValueError("受管 method route 非法")
    return methods, required


def _check_method_subresults(
    outcome: dict[str, Any], route: Any, *, require_multi_itemization: bool = False
) -> list[dict[str, Any]]:
    """Project method observations only from this actual executor call.

    Aggregate outcomes are attributable to one method only when the managed
    route requires exactly one mechanical method.  A multi-method dispatcher
    call must carry executor-owned, itemized observations for the entire
    managed mechanical method set.
    """
    methods, required = _validate_method_route(route)
    supplied = outcome.get("check_method_subresults")
    itemized = None
    if supplied is not None or (require_multi_itemization and len(required) > 1):
        itemized = validate_method_subresults(
            supplied,
            required_methods=required,
            aggregate_status=outcome["status"],
        )
    single = required[0] if len(required) == 1 and itemized is None else None
    itemized_by_method = {
        row["check_method"]: row for row in (itemized or [])
    }
    rows = []
    for method in sorted(methods):
        if method in itemized_by_method:
            rows.append(itemized_by_method[method])
        elif method == single:
            rows.append({
                "check_method": method,
                "status": outcome["status"],
                "observation_source": "executor_aggregate_single_mechanical_method",
                "evidence": dict(AGGREGATE_EVIDENCE_REFERENCE),
            })
        else:
            rows.append({
                "check_method": method,
                "status": "NOT_RUN",
                "observation_source": (
                    "executor_does_not_report_per_method"
                    if method in required
                    else "method_not_executed_by_mechanical_executor"
                ),
                "evidence": {
                    "kind": "method_not_executed",
                    "reason": (
                        "executor_does_not_report_per_method"
                        if method in required
                        else "non_mechanical_method"
                    ),
                },
            })
    return rows


def _failed_method_subresults(
    route: dict[str, Any], error: ExecutorEvidenceError
) -> list[dict[str, Any]]:
    """Produce explicit non-passing rows after an executor contract failure."""
    required = set(route["required_mechanical_methods"])
    rows = []
    for method in sorted(route["check_methods"]):
        if method in required:
            rows.append({
                "check_method": method,
                "status": "EVIDENCE_MISSING",
                "observation_source": "executor_method_subresults_invalid",
                "evidence": {
                    "kind": "executor_error_reference",
                    "field": "evidence",
                    "code": error.code,
                },
            })
        else:
            rows.append({
                "check_method": method,
                "status": "NOT_RUN",
                "observation_source": "method_not_executed_by_mechanical_executor",
                "evidence": {
                    "kind": "method_not_executed",
                    "reason": "non_mechanical_method",
                },
            })
    return rows


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


def executor_family_of(rule_id: str) -> str:
    """Derive the execution family from the actual registered check module."""
    prefix, registry = _registry_for(rule_id)
    if registry is None or rule_id[len(prefix) + 1:] not in registry:
        raise KeyError(rule_id)
    module_name = registry[rule_id[len(prefix) + 1:]].__module__.rsplit(".", 1)[-1]
    matches = [
        family for module_prefix, family in _EXECUTOR_MODULE_FAMILIES.items()
        if module_name.startswith(module_prefix)
    ]
    if len(matches) != 1:
        raise ValueError(f"执行器模块未绑定唯一 execution family: {rule_id}")
    return matches[0]


def execute(rule_id: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """执行单条 W2 第一档机械规则，返回 {status, evidence}。

    执行器抛出的异常由调用方（conformance_workflow）按失败关闭处理，
    不得在此吞掉异常伪装通过。
    """
    prefix, registry = _registry_for(rule_id)
    if registry is None or rule_id[len(prefix) + 1:] not in registry:
        raise KeyError(rule_id)
    route = ctx.get("method_route")
    if route is not None and (
        not isinstance(route, dict)
        or route.get("baseline_rule_id") != rule_id
        or route.get("canonical_id") != canonical_id_of(rule_id)
        or not isinstance(route.get("revision_digest"), str)
        or len(route["revision_digest"]) != 64
        or any(
            ch not in "0123456789abcdef"
            for ch in route["revision_digest"]
        )
    ):
        raise ValueError(f"执行器 method route 身份不匹配: {rule_id}")
    if route is not None:
        _validate_method_route(route)
    check = registry[rule_id[len(prefix) + 1:]]
    try:
        outcome = check(ctx)
    except ExecutorEvidenceError as exc:
        if ctx.get("method_route") is None:
            raise
        outcome = {
            "status": "EVIDENCE_MISSING",
            "evidence": {
                "reason": "executor_evidence_invalid",
                "code": getattr(exc, "code", type(exc).__name__),
                "detail": str(exc),
            },
        }
    if not isinstance(outcome, dict):
        raise ValueError(f"执行器返回值不是对象: {rule_id}")
    if outcome.get("status") not in _LEGAL_STATUSES:
        raise ValueError(f"执行器返回非法状态: {rule_id} {outcome.get('status')!r}")
    if "evidence" not in outcome:
        raise ValueError(f"执行器缺少证据: {rule_id}")
    # Only the conformance runner supplies the build-managed route.  Direct
    # executor unit calls remain aggregate-only and cannot masquerade as a
    # trusted method observation.
    if route is not None:
        outcome["executor_family"] = executor_family_of(rule_id)
        try:
            outcome["check_method_subresults"] = _check_method_subresults(
                outcome, route, require_multi_itemization=True
            )
        except ExecutorEvidenceError as exc:
            outcome = {
                "status": "EVIDENCE_MISSING",
                "evidence": {
                    "reason": "executor_method_subresults_invalid",
                    "code": exc.code,
                    "detail": str(exc),
                },
                "executor_family": executor_family_of(rule_id),
                "check_method_subresults": _failed_method_subresults(route, exc),
            }
    return outcome


def registered_canonical_ids(prefix: str = "w2b1") -> list[str]:
    """返回指定批次前缀下登记的 canonical 规则身份（默认 W2-B1，向后兼容）。"""
    if prefix not in _REGISTRIES:
        raise KeyError(prefix)
    return sorted(_REGISTRIES[prefix])
