"""M5 执行族：上下文/隔离/运行框架/阶段隔离/第一档（W2-B3 批，14 条）。

本模块覆盖 B3 批 execution_family=M5、violation_impact=warning/observe 的
14 条规则，全部被终态裁决为机械方法 static_scan 且
behavior_verification_also_required=true；执行器只覆盖机械半区
（evidence 携 mechanical_half=true），行为义务继续挂账。

证据面（与 B1/B2 M5 一致，失败关闭）：
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``：
  context-budget / run-record / harness-interfaces / isolation-policy /
  stage-isolation / tier1-runtime（B1 文档）+ stage-task-budget /
  runtime-observer（B2 文档）扩展消费本批新增轴：
  * context-budget.skill_content_sections（SFA-CONTEXT-032）
  * context-budget.detail_content_placements（SFA-CONTEXT-033）
  * context-budget.reference_navigations（SFA-CONTEXT-034）
  * stage-task-budget.stage_results 扩展（SFA-CONTEXT-006/019/026/027）
  * stage-task-budget.focused_observations（SFA-CONTEXT-020）
  * stage-task-budget.non_token_metrics（SFA-CONTEXT-029）
  * harness-interfaces.initial_version_interfaces（SFA-HARNESS-006）
  * isolation-policy.isolation_equivalences（SFA-ISOLATION-010）
  * stage-isolation.stages 入口会话行（SFA-STAGEISO-006）
  * tier1-runtime.advanced_governance_claims（SFA-TIER1-009）

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
from .m5_context_isolation import (
    AUTHORITATIVE_ESTIMATORS,
    _consume_token_estimate,
)

# ---------------------------------------------------------------------------
# 词表
# ---------------------------------------------------------------------------

#: SFA-CONTEXT-001：单个 SKILL.md 的上下文预算告警线（词元）。
CONTEXT_WARNING_TOKENS = 2000

#: SFA-CONTEXT-032：SKILL.md 允许保留的四类核心内容。
SKILL_CORE_CONTENT_CATEGORIES = {
    "trigger_conditions",
    "core_protocol",
    "safety_boundaries",
    "resource_navigation",
}

#: SFA-CONTEXT-033：必须进入按需参考资料的内容类别。
DETAIL_CONTENT_KINDS = {
    "detailed_domain_rules",
    "platform_differences",
    "long_examples",
    "structure_definitions",
}

#: SFA-CONTEXT-029：必须单独治理的非词元指标。
NON_TOKEN_METRIC_KINDS = {
    "input_file_size",
    "evidence_batch_count",
    "max_rounds",
    "concurrency",
    "silence_duration",
    "wall_clock_time",
}

#: SFA-HARNESS-006：初版允许只提供的八类接口。
INITIAL_VERSION_INTERFACE_KINDS = {
    "task_result",
    "budget",
    "evidence",
    "sample",
    "executor",
    "observer",
    "cleanup",
    "verification_record",
}

#: SFA-ISOLATION-010：允许的隔离机制类别（含未来机制）。
ISOLATION_MECHANISM_KINDS = {
    "container",
    "virtual_machine",
    "platform_sandbox",
    "remote_isolated_executor",
    "future_mechanism",
}

#: SFA-STAGEISO-006：入口会话直接执行必须逐项放行的五个维度。
ENTRY_SESSION_ALLOWANCE_FIELDS = (
    "tools_allowed",
    "permissions_allowed",
    "data_allowed",
    "writes_allowed",
    "context_budget_allowed",
)

#: SFA-TIER1-009：第一档不强制的高级运行治理项。
TIER1_ADVANCED_GOVERNANCE_ITEMS = {
    "exhaustive_failure_paths",
    "long_running_observation",
    "multi_round_auto_repair",
    "fault_injection",
    "model_matrix",
    "autonomous_rerun",
}


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# ---------------------------------------------------------------------------
# CONTEXT：上下文预算与记账（context-budget / stage-task-budget）
# ---------------------------------------------------------------------------


def check_context_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """单个 SKILL.md 达到 2000 词元必须产生上下文预算告警。

    机械断言（双口径取大，消费 B1 SG-33 冻结估算契约）：权威估算器口径
    达到告警线必须声明预算告警已产生；权威估算器落地前，启发式口径超限
    清单仅作证据，不作整改依据。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", measurements_declared=0, mechanical_half=True)
    rows = rows_of(document, "measurements", "context-budget")
    violations = []
    evidence_only = []
    for index, row in enumerate(rows):
        estimator = row.get("estimator_source")
        if not _nonempty_str(estimator):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"context-budget 第 {index} 行必须披露估算器来源（降级也不豁免）",
            )
        logical, _ = _consume_token_estimate(row.get("logical_source_tokens"))
        worst, _ = _consume_token_estimate(row.get("worst_projection_tokens"))
        decisive = max(logical, worst)
        if decisive < CONTEXT_WARNING_TOKENS:
            continue
        authoritative = estimator in AUTHORITATIVE_ESTIMATORS
        if authoritative:
            warning = row.get("budget_warning")
            if not isinstance(warning, dict) or warning.get("raised") is not True:
                violations.append(
                    {"index": index, "skill": row.get("skill"), "tokens": decisive}
                )
        else:
            evidence_only.append(
                {"index": index, "skill": row.get("skill"), "tokens": decisive}
            )
    if violations:
        return result(
            "FAIL",
            budget_warnings_missing=violations,
            warning_threshold=CONTEXT_WARNING_TOKENS,
            mechanical_half=True,
        )
    return result(
        "PASS",
        measurements=len(rows),
        evidence_only_over_warning_line=evidence_only,
        warning_threshold=CONTEXT_WARNING_TOKENS,
        mechanical_half=True,
    )


def _stage_results(ctx: dict[str, Any]) -> tuple[list[dict[str, Any]], str] | None:
    document = _doc(ctx, "stage-task-budget")
    if document is None:
        return None
    return rows_of(document, "stage_results", "stage-task-budget"), "stage-task-budget"


def _threshold_reached(row: dict[str, Any]) -> bool | None:
    """静态预计量是否达到单会话观察阈值；字段缺失返回 None。"""
    estimate = row.get("static_estimate")
    threshold = row.get("observation_threshold")
    if not _nonneg_int(estimate) or not _nonneg_int(threshold):
        return None
    return estimate >= threshold


def check_context_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """静态达到观察阈值优先拆分。

    机械断言：已声明阶段结果的静态预计量达到单会话观察阈值时，必须纳入
    重点观察并声明优先考虑拆分到不同会话或执行单元。
    """
    loaded = _stage_results(ctx)
    if loaded is None:
        return result("PASS", stage_results_declared=0, mechanical_half=True)
    rows, _ = loaded
    violations = []
    for index, row in enumerate(rows):
        reached = _threshold_reached(row)
        if reached is not True:
            continue
        problems = []
        if row.get("focused_observation") is not True:
            problems.append("not_placed_under_focused_observation")
        if row.get("split_prioritized") is not True:
            problems.append("split_not_prioritized")
        if problems:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", observation_threshold_without_focus_or_split=violations, mechanical_half=True
        )
    return result("PASS", stage_results=len(rows), mechanical_half=True)


def check_context_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """未命中失效模式可继续原子工作。

    机械断言：达到观察阈值但未命中失效模式的已声明阶段结果，续接必须
    声明为有界原子工作，不得据此开始新的大范围阶段。
    """
    loaded = _stage_results(ctx)
    if loaded is None:
        return result("PASS", stage_results_declared=0, mechanical_half=True)
    rows, _ = loaded
    violations = []
    for index, row in enumerate(rows):
        reached = _threshold_reached(row)
        if reached is not True:
            continue
        hits = row.get("failure_modes_hit")
        if hits is None:
            continue
        if not isinstance(hits, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "stage-task-budget.stage_results.failure_modes_hit 必须是数组",
            )
        if hits:
            continue
        problems = []
        if row.get("started_new_broad_stage") is True:
            problems.append("started_new_broad_stage")
        continuation = row.get("continuation_scope")
        if continuation is not None and continuation != "bounded_atomic":
            problems.append("continuation_not_bounded_atomic")
        if problems:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", threshold_continuation_exceeds_bounded_atomic=violations, mechanical_half=True
        )
    return result("PASS", stage_results=len(rows), mechanical_half=True)


def check_context_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """重点观察状态下进入下一阶段前重评。

    机械断言：已声明重点观察状态在加载新的大块输入或进入下一阶段前，
    必须记录失效模式与剩余容量的重新评估。
    """
    document = _doc(ctx, "stage-task-budget")
    if document is None:
        return result("PASS", focused_observations_declared=0, mechanical_half=True)
    rows = rows_of(document, "focused_observations", "stage-task-budget")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("failure_modes_reevaluated") is not True:
            problems.append("failure_modes_not_reevaluated")
        if row.get("remaining_capacity_reevaluated") is not True:
            problems.append("remaining_capacity_not_reevaluated")
        if row.get("reevaluated_before_new_load_or_stage") is not True:
            problems.append("reevaluation_not_before_new_load_or_stage")
        if problems:
            violations.append(
                {"index": index, "observation": row.get("observation_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", focused_observation_missing_reevaluation=violations, mechanical_half=True
        )
    return result("PASS", focused_observations=len(rows), mechanical_half=True)


def check_context_026(ctx: dict[str, Any]) -> dict[str, Any]:
    """真实观测与静态估算同时保留。

    机械断言：宿主能够提供实际上下文使用量（observed_usage 为非负整数）的
    已声明阶段结果，必须同时保留执行前静态预计量及二者差异。
    """
    loaded = _stage_results(ctx)
    if loaded is None:
        return result("PASS", stage_results_declared=0, mechanical_half=True)
    rows, _ = loaded
    violations = []
    for index, row in enumerate(rows):
        observed = row.get("observed_usage")
        if not _nonneg_int(observed):
            continue
        problems = []
        if not _nonneg_int(row.get("static_estimate")):
            problems.append("static_estimate_not_retained")
        if not _nonneg_int(row.get("estimate_observation_delta")):
            problems.append("estimate_observation_delta_not_retained")
        if problems:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", observed_usage_without_retained_estimate=violations, mechanical_half=True
        )
    return result("PASS", stage_results=len(rows), mechanical_half=True)


def check_context_027(ctx: dict[str, Any]) -> dict[str, Any]:
    """仅有估算时记录方法和安全余量。

    机械断言：无法获得真实观测（observed_usage 缺失或为 null）、只能估算的
    已声明阶段结果，必须记录估算器身份、版本和采用的安全余量。
    """
    loaded = _stage_results(ctx)
    if loaded is None:
        return result("PASS", stage_results_declared=0, mechanical_half=True)
    rows, _ = loaded
    violations = []
    for index, row in enumerate(rows):
        observed = row.get("observed_usage")
        if _nonneg_int(observed):
            continue
        problems = []
        if not _nonempty_str(row.get("estimator_identity")):
            problems.append("estimator_identity_missing")
        if not _nonempty_str(row.get("estimator_version")):
            problems.append("estimator_version_missing")
        margin = row.get("safety_margin")
        margin_ok = _nonempty_str(margin) or _nonneg_int(margin)
        if not margin_ok:
            problems.append("safety_margin_missing")
        if problems:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", estimate_only_without_method_or_margin=violations, mechanical_half=True
        )
    return result("PASS", stage_results=len(rows), mechanical_half=True)


def check_context_029(ctx: dict[str, Any]) -> dict[str, Any]:
    """非词元指标不得套用词元阈值。

    机械断言：已声明非词元指标治理必须逐指标给出独立阈值与单位，不得
    套用词元观察线或强制线。
    """
    document = _doc(ctx, "stage-task-budget")
    if document is None:
        return result("PASS", non_token_metrics_declared=0, mechanical_half=True)
    rows = rows_of(document, "non_token_metrics", "stage-task-budget")
    violations = []
    for index, row in enumerate(rows):
        kind = row.get("metric_kind")
        if kind not in NON_TOKEN_METRIC_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"stage-task-budget.non_token_metrics 第 {index} 行指标类别非法: {kind!r}",
            )
        problems = []
        threshold = row.get("own_threshold")
        if not _nonneg_int(threshold):
            problems.append("own_threshold_missing")
        if not _nonempty_str(row.get("threshold_unit")):
            problems.append("threshold_unit_missing")
        if row.get("applies_token_observation_line") is True:
            problems.append("applies_token_observation_line")
        if row.get("applies_token_intervention_line") is True:
            problems.append("applies_token_intervention_line")
        if problems:
            violations.append({"index": index, "metric": kind, "problems": problems})
    if violations:
        return result(
            "FAIL", non_token_metrics_using_token_lines=violations, mechanical_half=True
        )
    return result("PASS", non_token_metrics=len(rows), mechanical_half=True)


def check_context_032(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能说明只保留核心内容。

    机械断言：已声明技能正文构成必须把每个段落归类为触发条件、核心协议、
    安全边界或资源导航四类核心内容之一（正文实际内容的行为核验挂账）。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", content_sections_declared=0, mechanical_half=True)
    rows = rows_of(document, "skill_content_sections", "context-budget")
    violations = []
    for index, row in enumerate(rows):
        sections = row.get("sections")
        if not isinstance(sections, list) or not all(
            isinstance(item, dict) for item in sections
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "context-budget.skill_content_sections.sections 必须是对象数组",
            )
        outside = [
            {"section": section.get("section_id"), "category": section.get("category")}
            for section in sections
            if section.get("category") not in SKILL_CORE_CONTENT_CATEGORIES
        ]
        if outside:
            violations.append({"index": index, "skill": row.get("skill"), "outside": outside})
    if violations:
        return result(
            "FAIL", skill_content_outside_core_categories=violations, mechanical_half=True
        )
    return result("PASS", content_section_rows=len(rows), mechanical_half=True)


def check_context_033(ctx: dict[str, Any]) -> dict[str, Any]:
    """详细内容进入按需参考资料。

    机械断言：已声明详细内容项（详细领域规则、平台差异、长示例、结构定义）
    必须放置于按需加载的 references，且不得声明每次技能触发都加载。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", detail_placements_declared=0, mechanical_half=True)
    rows = rows_of(document, "detail_content_placements", "context-budget")
    violations = []
    for index, row in enumerate(rows):
        kind = row.get("content_kind")
        if kind not in DETAIL_CONTENT_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"context-budget.detail_content_placements 第 {index} 行内容类别非法: {kind!r}",
            )
        problems = []
        if row.get("placement") != "references_on_demand":
            problems.append("not_placed_in_references_on_demand")
        if row.get("loaded_on_every_trigger") is True:
            problems.append("loaded_on_every_trigger")
        if problems:
            violations.append({"index": index, "item": row.get("item_id"), "problems": problems})
    if violations:
        return result(
            "FAIL", detail_content_not_on_demand=violations, mechanical_half=True
        )
    return result("PASS", detail_placements=len(rows), mechanical_half=True)


def check_context_034(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能说明直接导航参考资料。

    机械断言：已声明按需参考资料必须直接列于技能说明并给出读取时机，
    不得声明需要多层引用追索。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", reference_navigations_declared=0, mechanical_half=True)
    rows = rows_of(document, "reference_navigations", "context-budget")
    violations = []
    for index, row in enumerate(rows):
        references = row.get("references")
        if not isinstance(references, list) or not all(
            isinstance(item, dict) for item in references
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "context-budget.reference_navigations.references 必须是对象数组",
            )
        problems = []
        for reference in references:
            if reference.get("directly_listed_in_skill") is not True:
                problems.append(
                    {"ref": reference.get("ref_id"), "problem": "not_directly_listed"}
                )
            elif not _nonempty_str(reference.get("read_timing")):
                problems.append(
                    {"ref": reference.get("ref_id"), "problem": "read_timing_missing"}
                )
            if reference.get("requires_multi_layer_chasing") is True:
                problems.append(
                    {"ref": reference.get("ref_id"), "problem": "multi_layer_chasing"}
                )
        if problems:
            violations.append({"index": index, "skill": row.get("skill"), "problems": problems})
    if violations:
        return result(
            "FAIL", reference_navigation_not_direct=violations, mechanical_half=True
        )
    return result("PASS", reference_navigations=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# HARNESS：初版接口范围（harness-interfaces）
# ---------------------------------------------------------------------------


def check_harness_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """初版预留接口不等于实现完整控制器。

    机械断言：已声明初版接口范围必须落在八类接口之内，且不得声明初版
    必须实现第三档全部运行控制器。
    """
    document = _doc(ctx, "harness-interfaces")
    if document is None:
        return result("PASS", harness_declared=False, mechanical_half=True)
    scope = document.get("initial_version_interfaces")
    if scope is None:
        return result("PASS", initial_version_scope_declared=False, mechanical_half=True)
    if not isinstance(scope, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "harness-interfaces.initial_version_interfaces 必须是对象",
        )
    kinds = scope.get("interface_kinds")
    if not isinstance(kinds, list) or not all(isinstance(item, str) for item in kinds):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "harness-interfaces.initial_version_interfaces.interface_kinds 必须是字符串数组",
        )
    problems = []
    outside = sorted(set(kinds) - INITIAL_VERSION_INTERFACE_KINDS)
    if outside:
        problems.append({"problem": "interface_kinds_outside_initial_scope", "kinds": outside})
    if scope.get("full_tier3_controller_required") is True:
        problems.append({"problem": "full_tier3_controller_required_for_initial_version"})
    if problems:
        return result("FAIL", initial_version_scope_violations=problems, mechanical_half=True)
    return result("PASS", interface_kinds=sorted(set(kinds)), mechanical_half=True)


# ---------------------------------------------------------------------------
# ISOLATION：等价隔离机制（isolation-policy）
# ---------------------------------------------------------------------------


def check_isolation_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """隔离允许满足同一画像的等价实现。

    机械断言：已声明隔离等价实现必须落在合法机制类别内，符合性依据必须
    绑定能力画像与实际证据，不得以产品名称作为符合性依据。
    """
    policy = _doc(ctx, "isolation-policy")
    if policy is None:
        return result("PASS", isolation_equivalences_declared=0, mechanical_half=True)
    rows = rows_of(policy, "isolation_equivalences", "isolation-policy")
    violations = []
    for index, row in enumerate(rows):
        mechanism = row.get("mechanism")
        if mechanism not in ISOLATION_MECHANISM_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"isolation-policy.isolation_equivalences 第 {index} 行机制类别非法: {mechanism!r}",
            )
        problems = []
        if not _nonempty_str(row.get("capability_profile_ref")):
            problems.append("capability_profile_ref_missing")
        if not _nonempty_str(row.get("evidence_ref")):
            problems.append("evidence_ref_missing")
        if row.get("product_name_as_conformance_basis") is True:
            problems.append("product_name_as_conformance_basis")
        if problems:
            violations.append(
                {"index": index, "equivalence": row.get("equivalence_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", isolation_conformance_by_product_name=violations, mechanical_half=True
        )
    return result("PASS", isolation_equivalences=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# STAGEISO：入口会话直接执行（stage-isolation）
# ---------------------------------------------------------------------------


def check_stageiso_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """无需隔离工序可以在入口会话执行。

    机械断言：已声明直接在入口会话执行的工序必须显式标记为无需隔离，
    逐项放行工具、权限、数据、写入和上下文预算，并记录实际执行身份。
    """
    document = _doc(ctx, "stage-isolation")
    if document is None:
        return result("PASS", stage_isolation_declared=False, mechanical_half=True)
    rows = rows_of(document, "stages", "stage-isolation")
    violations = []
    for index, row in enumerate(rows):
        if row.get("executed_within_entry") is not True:
            continue
        problems = []
        if row.get("isolation_level") != "none":
            problems.append("not_explicitly_marked_no_isolation")
        for field in ENTRY_SESSION_ALLOWANCE_FIELDS:
            if row.get(field) is not True:
                problems.append(f"allowance_missing:{field}")
        if not _nonempty_str(row.get("execution_identity")):
            problems.append("execution_identity_missing")
        if problems:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", entry_session_execution_without_full_clearance=violations,
            mechanical_half=True,
        )
    return result("PASS", stages=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# TIER1：高级运行治理非基线强制（tier1-runtime）
# ---------------------------------------------------------------------------


def check_tier1_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一档不强制高级运行治理。

    机械断言：已声明第一档高级运行治理项必须标记为项目政策按风险加严并
    给出风险依据，不得声明为第一档基线强制；文档级基线强制声明同样禁止。
    """
    document = _doc(ctx, "tier1-runtime")
    if document is None:
        return result("PASS", tier1_declared=False, mechanical_half=True)
    if document.get("advanced_governance_baseline_required") is True:
        return result(
            "FAIL",
            reason="advanced_governance_declared_tier1_baseline",
            mechanical_half=True,
        )
    rows = rows_of(document, "advanced_governance_claims", "tier1-runtime")
    violations = []
    for index, row in enumerate(rows):
        item = row.get("item")
        if item not in TIER1_ADVANCED_GOVERNANCE_ITEMS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"tier1-runtime.advanced_governance_claims 第 {index} 行治理项非法: {item!r}",
            )
        problems = []
        if row.get("policy_source") != "project_tightening":
            problems.append("not_declared_as_project_tightening")
        if not _nonempty_str(row.get("risk_basis")):
            problems.append("risk_basis_missing")
        if row.get("tier1_baseline_required") is True:
            problems.append("claimed_tier1_baseline")
        if problems:
            violations.append({"index": index, "item": item, "problems": problems})
    if violations:
        return result(
            "FAIL", advanced_governance_forced_as_tier1_baseline=violations,
            mechanical_half=True,
        )
    return result("PASS", advanced_governance_claims=len(rows), mechanical_half=True)


CHECKS = {
    "SFA-CONTEXT-001": check_context_001,
    "SFA-CONTEXT-006": check_context_006,
    "SFA-CONTEXT-019": check_context_019,
    "SFA-CONTEXT-020": check_context_020,
    "SFA-CONTEXT-026": check_context_026,
    "SFA-CONTEXT-027": check_context_027,
    "SFA-CONTEXT-029": check_context_029,
    "SFA-CONTEXT-032": check_context_032,
    "SFA-CONTEXT-033": check_context_033,
    "SFA-CONTEXT-034": check_context_034,
    "SFA-HARNESS-006": check_harness_006,
    "SFA-ISOLATION-010": check_isolation_010,
    "SFA-STAGEISO-006": check_stageiso_006,
    "SFA-TIER1-009": check_tier1_009,
}
