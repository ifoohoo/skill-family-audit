"""M7 执行族：方法注册表/制品方法/模板（W2-B3 批，4 条）。

本模块覆盖 B3 批 execution_family=M7、violation_impact=warning 的 4 条规则，
全部被终态裁决为机械方法 digest_verification+schema_validation，且
behavior_verification_also_required=false、semantic_review_also_required=false；
机械断言即全部义务。

证据面（扩展消费 B2 M7 既有文档，失败关闭）：
- artifact-method-runs.informal_capabilities（SFA-ARTMETHOD-003）
- method-registry-projection.business_objects（SFA-REGISTRY-006）
- template-overrides.base_templates（SFA-TEMPLATE-001）
- template-overrides.overrides 四字段（SFA-TEMPLATE-002，与 B2 TEMPLATE-003
  的基础契约断言互补，字段集合互不重叠）

治理声明缺省语义沿用 B1/M7：
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

#: SFA-ARTMETHOD-003：与正式制品无关的能力类别。
INFORMAL_CAPABILITY_KINDS = {
    "installation",
    "environment_diagnosis",
    "release_assistance",
    "plain_code_operation",
    "temporary_run_data",
}

#: SFA-TEMPLATE-002：项目模板覆盖必须记录的四类事实。
TEMPLATE_OVERRIDE_REQUIRED_FIELDS = (
    "applicable_artifact_types",
    "base_template_revision",
    "override_summary",
    "selection_conditions",
)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


# ---------------------------------------------------------------------------
# ARTMETHOD：非正式制品能力不强制接图（artifact-method-runs）
# ---------------------------------------------------------------------------


def check_artmethod_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """非正式制品能力不强制接图。

    机械断言：已声明与正式制品无关的能力不得仅为统一形式被强制接入制品
    图；其后满足提升判据的，必须经正式提升流程并留下判据与流程引用。
    """
    document = load_governance_document(ctx, "artifact-method-runs")
    if document is None:
        return result("PASS", informal_capabilities_declared=0)
    rows = rows_of(document, "informal_capabilities", "artifact-method-runs")
    violations = []
    for index, row in enumerate(rows):
        kind = row.get("capability_kind")
        if kind not in INFORMAL_CAPABILITY_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"artifact-method-runs.informal_capabilities 第 {index} 行能力类别非法: {kind!r}",
            )
        problems = []
        if row.get("forced_into_artifact_graph") is True:
            problems.append("forced_into_artifact_graph_for_uniformity")
        if row.get("promoted") is True and (
            row.get("promotion_criteria_met") is not True
            or not _nonempty_str(row.get("formal_promotion_ref"))
        ):
            problems.append("promoted_without_formal_process")
        if problems:
            violations.append(
                {"index": index, "capability": row.get("capability_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", informal_capabilities_forced_into_graph=violations)
    return result("PASS", informal_capabilities=len(rows))


# ---------------------------------------------------------------------------
# REGISTRY：注册业务对象的稳定语义与证据（method-registry-projection）
# ---------------------------------------------------------------------------


def check_registry_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册业务对象不限于图中正式制品。

    机械断言：已声明注册业务对象无论是否为制品图正式制品，必须具有稳定
    语义身份和实际证据引用。
    """
    document = load_governance_document(ctx, "method-registry-projection")
    if document is None:
        return result("PASS", business_objects_declared=0)
    rows = rows_of(document, "business_objects", "method-registry-projection")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if not _nonempty_str(row.get("stable_semantic_identity")):
            problems.append("stable_semantic_identity_missing")
        evidence = row.get("evidence_refs")
        if (
            not isinstance(evidence, list)
            or not evidence
            or not all(_nonempty_str(item) for item in evidence)
        ):
            problems.append("evidence_refs_missing")
        if problems:
            violations.append(
                {"index": index, "object": row.get("object_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", business_objects_without_semantics_or_evidence=violations)
    return result("PASS", business_objects=len(rows))


# ---------------------------------------------------------------------------
# TEMPLATE：公共基础模板与项目覆盖（template-overrides）
# ---------------------------------------------------------------------------


def check_template_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族可以提供公共基础模板。

    机械断言：已声明公共基础模板必须与精确制品契约修订绑定，且角色必须
    是创建辅助，不得声明为制品结构权威。
    """
    document = load_governance_document(ctx, "template-overrides")
    if document is None:
        return result("PASS", base_templates_declared=0)
    rows = rows_of(document, "base_templates", "template-overrides")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if not _nonempty_str(row.get("bound_artifact_contract_revision")):
            problems.append("bound_artifact_contract_revision_missing")
        if row.get("role") != "creation_aid":
            problems.append("role_not_creation_aid")
        if row.get("claims_artifact_structure_authority") is True:
            problems.append("claims_artifact_structure_authority")
        if problems:
            violations.append(
                {"index": index, "template": row.get("template_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", base_templates_claiming_structure_authority=violations)
    return result("PASS", base_templates=len(rows))


def check_template_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """目标项目可以声明模板覆盖。

    机械断言：已声明模板覆盖必须落在项目权威范围内，并记录适用制品类型、
    基础模板修订、覆盖摘要和选择条件四项事实。
    """
    document = load_governance_document(ctx, "template-overrides")
    if document is None:
        return result("PASS", template_overrides_declared=0)
    rows = rows_of(document, "overrides", "template-overrides")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("within_project_authority") is not True:
            problems.append("not_within_project_authority")
        for field in TEMPLATE_OVERRIDE_REQUIRED_FIELDS:
            value = row.get(field)
            if field == "applicable_artifact_types":
                if (
                    not isinstance(value, list)
                    or not value
                    or not all(_nonempty_str(item) for item in value)
                ):
                    problems.append(f"{field}_missing")
            elif not _nonempty_str(value):
                problems.append(f"{field}_missing")
        if problems:
            violations.append(
                {"index": index, "override": row.get("override_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", template_overrides_missing_required_facts=violations)
    return result("PASS", overrides=len(rows))


CHECKS = {
    "SFA-ARTMETHOD-003": check_artmethod_003,
    "SFA-REGISTRY-006": check_registry_006,
    "SFA-TEMPLATE-001": check_template_001,
    "SFA-TEMPLATE-002": check_template_002,
}
