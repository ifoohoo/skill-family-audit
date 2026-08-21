"""M1 执行族：规则治理（W2-B3 批，2 条）。

本模块覆盖 B3 批 execution_family=M1、violation_impact=warning 的 2 条规则，
全部被终态裁决为机械方法 digest_verification+schema_validation，且
behavior_verification_also_required=false、semantic_review_also_required=false；
机械断言即全部义务。

证据面（与 B1/B2 M1 一致，失败关闭）：
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/rule-definitions.json``：
  rules 轴的整改/复验字段（SFA-RULE-017）与 external_component_rules 新轴
  （SFA-RULE-040）。

治理声明缺省语义沿用 B1：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 文档存在但形状非法 → ExecutorEvidenceError（失败关闭，绝不静默放行）；
- 文档存在且出现结构性违反 → FAIL。

执行器只消费目标事实，绝不修改目标；不消费模型语义结论。
"""
from __future__ import annotations

from typing import Any

from .contracts import (
    ExecutorEvidenceError,
    load_governance_document,
    result,
    rows_of,
)

# ---------------------------------------------------------------------------
# 词表
# ---------------------------------------------------------------------------

#: SFA-RULE-040：触发条件规则的外部组件类别。
EXTERNAL_COMPONENT_KINDS = {
    "npm_package",
    "python_package",
    "command_line_program",
    "mcp_service",
    "app_connector",
}


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rules(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return None
    return rows_of(document, "rules", "rule-definitions")


def _rule_field_violations(
    rules: list[dict[str, Any]],
    predicate,
    reason: str,
) -> list[dict[str, Any]]:
    return [
        {"index": index, "rule_id": row.get("rule_id"), "reason": reason}
        for index, row in enumerate(rules)
        if not predicate(row)
    ]


def check_rule_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式规则声明整改和复验。

    机械断言：每条已声明正式规则必须声明整改方向、允许自动修复的边界
    以及整改后的复验要求。
    """
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)

    def declared(row: dict[str, Any]) -> bool:
        remediation = row.get("remediation_direction")
        boundary = row.get("auto_fix_boundary")
        revalidation = row.get("post_remediation_revalidation")
        boundary_ok = _nonempty_str(boundary) or (
            isinstance(boundary, dict) and bool(boundary)
        )
        return (
            _nonempty_str(remediation)
            and boundary_ok
            and _nonempty_str(revalidation)
        )

    violations = _rule_field_violations(
        rules, declared, "remediation_or_revalidation_undeclared"
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_040(ctx: dict[str, Any]) -> dict[str, Any]:
    """外部组件被采用后才触发条件规则。

    机械断言：每条已声明外部组件条件规则必须落在合法组件类别内；未被
    技能族采用的组件不得进入相应运行时、供应链、权限和发行条件规则。
    """
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return result("PASS", external_component_rules_declared=0)
    rows = rows_of(document, "external_component_rules", "rule-definitions")
    violations = []
    for index, row in enumerate(rows):
        kind = row.get("component_kind")
        if kind not in EXTERNAL_COMPONENT_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"rule-definitions.external_component_rules 第 {index} 行组件类别非法: {kind!r}",
            )
        problems = []
        adopted = row.get("adopted_by_family")
        if adopted is not True:
            triggered = row.get("conditional_rules_active")
            triggered_list = row.get("triggered_conditional_rules")
            if triggered is True or (
                isinstance(triggered_list, list) and bool(triggered_list)
            ):
                problems.append("conditional_rules_active_before_adoption")
        if problems:
            violations.append(
                {"index": index, "component": row.get("component_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", external_component_rules=len(rows))


CHECKS = {
    "SFA-RULE-017": check_rule_017,
    "SFA-RULE-040": check_rule_040,
}
