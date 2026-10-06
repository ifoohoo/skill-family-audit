"""A4 切片：人类入口的确定性路由、结果呈现与下一步选择内核。

本模块只提供四个固定纯函数（resolve_human_route、interpret_source_numbers、
choose_primary_next_action、render_human_summary）。函数只处理普通 Python 值
（字典/列表/字符串），不读取文件、不导入项目内模块、不调用模型、不接触 Foundation。

输入契约
--------
- explicit_profile：None，或 "mechanical"/"economy"/"targeted"/"full" 之一。
- intent：仅接受四个枚举：ordinary_conformance / deterministic_only /
  complete_audit / release_preparation。
- selectors：精确字符串列表。元素只能是精确 group ID、精确登记显示名称
  （display_name）或精确 canonical rule ID。本模块不做自然语言解析、
  模糊匹配或模型猜测。
- group_registry：A1 分组治理源/薄投影的普通 dict；顶层携带 schema_version、
  kind、status、groups，组行使用 group_id、name、rules[].canonical_id。
  group_id、name、canonical rule 成员全局唯一；结构非法、身份不符或版本过期
  视为无效/过期 Registry 输入。调用本模块的阶段 B 调用边界已完成当前 Registry 摘要验证；
  本模块不读取文件、不计算摘要，也不维护摘要副本。
- deterministic_rule_ids：已有确定性本地 executor 路由的 canonical rule ID
  集合（机械规则集合由调用方按 routing 派生，不在本模块复制任何固定计数）。
- source_dispositions：可选。canonical 库 source_dispositions 的公开投影行列表；
  每行至少携带非空 source_id 与 destination，合并行可再携带 carried_by 与
  carried_by_status，其余字段原样忽略。本模块只读消费调用方给出的投影，不读取
  私有库存、不复制任何编号映射。省略时按既有行为处理：未命中的请求仍以
  unresolved_selector 失败关闭。

旧编号解释
----------
请求的 selector 或 canonical_rule_id 未命中当前规则清单时，若调用方提供了去向投影：
- destination 为 merge_trace 且 carried_by_status 为 effective：按 carried_by
  的承接编号继续解析（承接编号必须命中当前清单，否则失败关闭）；
- 其余去向（移除、专业接线、项目或宿主职责、待决、承接尚未生效等）：只解释去向，
  跳过该编号，不运行旧检查、也不计入符合率。
投影中不存在的编号仍是未知编号，按 unresolved_selector 失败关闭。解释结果随路由
返回在 source_number_explanations 中（列表，按 source_id 排序；每行携带
source_id、disposition、destination、destination_label、successors、runnable、
detail）。

失败形态
--------
任何无法解析、歧义、重复或无效 Registry 输入都抛出 ValueError，消息以
"<error_code>: <detail>" 开头（例如 unresolved_selector、ambiguous_selector、
duplicate_selector、invalid_registry、invalid_intent、invalid_profile、
targeted_requires_group_ids、selectors_forbidden_for_non_targeted、
invalid_source_dispositions、source_number_successor_unresolved）。
绝不猜组、不模糊匹配、不调用模型、不自动改变 profile；也不猜测旧编号去向。

profile 选择优先级与 journey-contract.json selection_precedence 一致：
显式 profile > release_preparation > complete_audit > 精确 selector
（registered_group_name_group_id_or_canonical_rule_id）> deterministic_only
> ordinary_conformance。只含确定性 canonical rule 的选择解析为 mechanical；
含语义组的选择解析为 targeted（是否属语义组以 group_registry 登记为准）。

choose_primary_next_action 只对 domain_result 已有事实返回唯一主动作。发布意图、
机械影响是否未知和下一批准组通过可选 journey_facts 传入：journey_facts 必选字段
仍是 intent（四值枚举）/ mechanical_impact_unknown（布尔）/
next_approved_targeted_group_id（非空字符串或 None）。可选字段只接受宿主实际观察
的 semantic_model_call_count / semantic_context_count /
semantic_rules_sent_to_model_count（非负整数或 None）。对象结构、字段类型、
未知字段和 intent 枚举非法一律失败关闭。缺少 journey_facts 时保留现有保守默认：
不猜测用户意图、不自动执行下一 profile。下一步严格按 journey-contract.json
next_action_precedence 的九级顺序返回唯一 primary_action；任何分支都只返回动作，
不自动启动下一次运行。

render_human_summary 输出固定六段（列表，顺序即呈现顺序）：
run_identity → decision_scope → coverage → semantic_cost →
blocking_findings → next_action。PARTIAL 已开始检查时的 decision_scope 首句为：
"本次是部分检查，不能证明项目完整符合，也不能单独作为发布资格。"
零执行时明确说明尚未检查任何规则。
decision_scope.completion_state 区分尚未开始、检查未完成、选定范围已处理。
coverage 列出尚未审阅的规则。semantic_cost 优先使用 journey_facts 中的宿主观察；
领域 execution_metrics 里值为 None 的不可观察计数渲染为 unknown。不要用上下文数
或结果数量推算 semantic_model_call_count。缺失或 None 按现有合同表示为 unknown，
不用估算冒充实际调用。journey_facts 原样传给 choose_primary_next_action 并用于
渲染 next_action 段。
"""

_INTENTS = ("ordinary_conformance", "deterministic_only", "complete_audit", "release_preparation")
_EXECUTION_PROFILES = ("mechanical", "economy", "targeted", "full")

_PARTIAL_FIRST_SENTENCE = "本次是部分检查，不能证明项目完整符合，也不能单独作为发布资格。"
_PARTIAL_NOT_STARTED_FIRST_SENTENCE = "本次没有检查任何规则，不能证明项目完整符合，也不能单独作为发布资格。"

_COMPLETION_NOT_STARTED = "not_started"
_COMPLETION_INCOMPLETE = "incomplete"
_COMPLETION_SCOPE_PROCESSED = "scope_processed"
_COMPLETION_MEANING = {
    _COMPLETION_NOT_STARTED: "尚未开始检查",
    _COMPLETION_INCOMPLETE: "已经检查了一部分，但还没有完成",
    _COMPLETION_SCOPE_PROCESSED: "这次选定的范围已经处理完，发现了符合、不符合或缺证",
}
_HOST_OBSERVATION_FIELDS = (
    "semantic_model_call_count",
    "semantic_context_count",
    "semantic_rules_sent_to_model_count",
)

# 11-result-presentation.md 状态含义表（人类摘要必须使用的含义）。
_STATUS_MEANING = {
    "SUCCEEDED": "完整符合性审计已经通过。发布门禁和授权仍要单独核对。",
    "PARTIAL": "选定范围已经完成，但没有形成全量符合性结论。",
    "FAILED": "已证明至少有一条所选规则违规。",
    "BLOCKED": "所选范围里有缺证、待审，或执行合同上的问题。",
}
_PARTIAL_STATUS_MEANING = {
    _COMPLETION_NOT_STARTED: "本次还没有检查任何规则，也没有形成符合性结论。",
    _COMPLETION_INCOMPLETE: "本次检查还没完成，没有形成全量符合性结论。",
    _COMPLETION_SCOPE_PROCESSED: _STATUS_MEANING["PARTIAL"],
}

# blocking_findings 按状态排序：失败规则、缺证角色、仍需审阅。
_FINDING_STATUS_ORDER = {"FAIL": 0, "EVIDENCE_MISSING": 1, "REVIEW_REQUIRED": 2}

__all__ = [
    "resolve_human_route",
    "interpret_source_numbers",
    "choose_primary_next_action",
    "render_human_summary",
]

# 合并追溯但承接未生效、以及已退出/已迁出当前规则集合的去向，只解释、不执行。
_SOURCE_NUMBER_MERGED = "merged"
_SOURCE_NUMBER_MERGE_PENDING = "merge_pending"
_SOURCE_NUMBER_EXITED = "exited"


def interpret_source_numbers(source_ids, source_dispositions):
    """按公开去向投影解释来源编号：承接、退出或未知（普通字典，纯函数）。

    source_ids 是精确编号字符串列表；source_dispositions 是 canonical 库
    source_dispositions 的公开投影行列表。返回
    {"successors": {source_id: {"successors": [...], "destination": str,
    "destination_label": str}}, "exited": {同结构}, "unknown": [source_id],
    "explanations": [按 source_id 排序的解释行]}。结构非法一律抛 ValueError，
    消息以 "invalid_source_dispositions" 开头；绝不推定去向，也不复制编号映射。
    """
    table = _validate_source_dispositions(source_dispositions)
    return _interpret_source_numbers(source_ids, table)


def _interpret_source_numbers(source_ids, table):
    """已校验去向表上的解释内核（table 为 source_id → 行字典）。"""
    if not isinstance(source_ids, list):
        raise ValueError(
            "invalid_source_ids: source_ids 必须是精确编号字符串列表"
        )
    successors, exited, unknown, explanations = {}, {}, [], []
    for source_id in sorted(set(source_ids)):
        if not isinstance(source_id, str) or not source_id:
            raise ValueError("invalid_source_ids: 编号必须是非空字符串")
        row = table.get(source_id)
        if row is None:
            unknown.append(source_id)
            continue
        destination = row["destination"]
        label = row.get("destination_label") or destination
        carried_by = list(row.get("carried_by") or [])
        if destination == "merge_trace" and row.get("carried_by_status") == "effective" and carried_by:
            successors[source_id] = {
                "successors": carried_by,
                "destination": destination,
                "destination_label": label,
            }
            explanations.append({
                "source_id": source_id,
                "disposition": _SOURCE_NUMBER_MERGED,
                "destination": destination,
                "destination_label": label,
                "successors": carried_by,
                "runnable": True,
                "detail": (
                    "来源编号 {} 已合并到 {}。这次按承接规则执行，"
                    "不运行旧编号检查。".format(source_id, "、".join(carried_by))
                ),
            })
            continue
        if destination == "merge_trace":
            explanations.append({
                "source_id": source_id,
                "disposition": _SOURCE_NUMBER_MERGE_PENDING,
                "destination": destination,
                "destination_label": label,
                "successors": carried_by,
                "runnable": False,
                "detail": (
                    "来源编号 {} 的合并承接还没生效（状态：{}，候选承接：{}）。"
                    "这次不承接，也不运行旧检查。".format(
                        source_id,
                        row.get("carried_by_status") or "unknown",
                        "、".join(carried_by) or "无",
                    )
                ),
            })
            exited[source_id] = {
                "successors": [],
                "destination": destination,
                "destination_label": label,
            }
            continue
        exited[source_id] = {
            "successors": [],
            "destination": destination,
            "destination_label": label,
        }
        explanations.append({
            "source_id": source_id,
            "disposition": _SOURCE_NUMBER_EXITED,
            "destination": destination,
            "destination_label": label,
            "successors": [],
            "runnable": False,
            "detail": (
                "来源编号 {} 已不在当前规则集合（去向：{}）。"
                "不运行旧检查，也不计入符合率。".format(source_id, label)
            ),
        })
    return {
        "successors": successors,
        "exited": exited,
        "unknown": unknown,
        "explanations": explanations,
    }


def _build_execution_plan_event(
    profile_plan,
    semantic_preflight,
    semantic_context_plan,
    *,
    semantic_rules_skipped_missing_evidence_count,
    target_digest,
    selection_reason,
    routing_file_digest,
    trust_projection_digest,
):
    """从同一次领域运行的内存计划派生一条运行前事件。"""
    contexts = semantic_context_plan.get("contexts") or []
    profile = profile_plan["execution_profile"]
    budget = semantic_context_plan.get("semantic_input_budget", 0)
    if profile in ("mechanical", "economy"):
        budget = 0
    return {
        "kind": "skill-family-audit.execution-plan",
        "execution_profile": profile,
        "target_digest": target_digest,
        "selection_reason": selection_reason,
        "requested_semantic_group_ids": profile_plan[
            "requested_semantic_group_ids"
        ],
        "canonical_rule_ids": profile_plan.get(
            "requested_canonical_rule_ids", []
        ),
        "selected_semantic_group_ids": profile_plan[
            "selected_semantic_group_ids"
        ],
        "selected_deterministic_rule_count": profile_plan[
            "selected_deterministic_rule_count"
        ],
        "selected_semantic_rule_count": (
            len(profile_plan.get("selected_rule_ids") or [])
            - profile_plan["selected_deterministic_rule_count"]
        ),
        "semantic_rules_skipped_missing_evidence_count": (
            semantic_rules_skipped_missing_evidence_count
        ),
        "estimated_context_count": len(contexts),
        "estimated_input_tokens": semantic_context_plan.get(
            "estimated_input_tokens", 0
        ),
        "semantic_input_budget": budget,
        "semantic_group_registry_digest": profile_plan[
            "semantic_group_registry_digest"
        ],
        "routing_file_digest": routing_file_digest,
        "trust_projection_digest": trust_projection_digest,
    }


def resolve_human_route(
    explicit_profile,
    intent,
    selectors,
    group_registry,
    deterministic_rule_ids,
    canonical_rule_ids=None,
    source_dispositions=None,
):
    """按 journey-contract selection_precedence 解析人类入口的 profile 与语义组。

    返回 {"execution_profile": str, "semantic_group_ids": [...],
    "canonical_rule_ids": [...], "selection_reason": str,
    "source_number_explanations": [...]}。两种 ID 数组均排序，targeted 时互斥；
    非 targeted 时均为空列表。source_number_explanations 是旧编号解释行（按
    source_id 排序），未涉及旧编号时为空列表。失败关闭一律抛 ValueError。
    """
    if explicit_profile is not None and explicit_profile not in _EXECUTION_PROFILES:
        raise ValueError("invalid_profile: {!r}".format(explicit_profile))
    if intent not in _INTENTS:
        raise ValueError("invalid_intent: {!r}".format(intent))
    groups = _validate_registry(group_registry)
    selectors = _validate_selectors(selectors)
    dispositions = _validate_source_dispositions(source_dispositions)
    explanations: list = []
    exact_rule_ids = _normalize_canonical_rule_ids(
        canonical_rule_ids, groups, deterministic_rule_ids, dispositions, explanations
    )

    if explicit_profile is not None:
        return _resolve_with_explicit_profile(
            explicit_profile,
            selectors,
            groups,
            deterministic_rule_ids,
            exact_rule_ids,
            dispositions,
            explanations,
        )

    if intent == "release_preparation":
        return _route("full", [], "release_preparation", explanations=explanations)
    if intent == "complete_audit":
        return _route("full", [], "complete_audit", explanations=explanations)
    if exact_rule_ids:
        if selectors:
            raise ValueError(
                "targeted_selection_ambiguous: group selectors and canonical_rule_ids "
                "are mutually exclusive"
            )
        return _route(
            "targeted",
            [],
            "registered_group_name_group_id_or_canonical_rule_id",
            exact_rule_ids,
            explanations=explanations,
        )
    if selectors:
        return _resolve_from_selectors(
            selectors, groups, deterministic_rule_ids, dispositions, explanations
        )
    if intent == "deterministic_only":
        return _route("mechanical", [], "deterministic_only", explanations=explanations)
    return _route("economy", [], "ordinary_conformance", explanations=explanations)


def _primary_next_action_body(domain_result, journey_facts=None):
    """按 journey-contract next_action_precedence 返回唯一主动作（普通字典）。

    domain_result 是 conformance-result 合同中的 conformance_result 领域对象。
    journey_facts 可选；必选字段仍是 intent / mechanical_impact_unknown /
    next_approved_targeted_group_id，并可带宿主观察的实际模型执行指标。
    结构、类型与枚举非法一律失败关闭
    （ValueError，消息以 "invalid_journey_facts" 开头）。
    缺少 journey_facts 时保持现有保守默认，不猜测意图、不自动执行下一 profile。
    """
    journey_facts = _validate_journey_facts(journey_facts)
    status = domain_result.get("status")
    rule_rows = domain_result.get("rule_results") or []
    profile = domain_result.get("execution_profile")

    fail_ids = _rule_ids_with_status(rule_rows, "FAIL")
    if fail_ids:
        return {"primary_action": "fix_failed_rules", "rule_ids": fail_ids}

    missing_ids = _rule_ids_with_status(rule_rows, "EVIDENCE_MISSING")
    internal_ids = [
        rule_id
        for rule_id in missing_ids
        if _is_audit_internal_missing(_rule_row_by_id(rule_rows, rule_id))
    ]
    external_ids = [
        rule_id for rule_id in missing_ids if rule_id not in set(internal_ids)
    ]
    if external_ids:
        return {
            "primary_action": "supply_missing_evidence",
            "rule_ids": external_ids,
            "missing_evidence_roles": _missing_roles_by_rule(
                domain_result, external_ids
            ),
        }
    if internal_ids:
        return {
            "primary_action": "complete_or_rebind_pending_review",
            "rule_ids": internal_ids,
            "reason": "audit_executor_contract_failure",
        }

    review_ids = _rule_ids_with_status(rule_rows, "REVIEW_REQUIRED")
    if review_ids:
        return {"primary_action": "complete_or_rebind_pending_review", "rule_ids": review_ids}
    if status == "BLOCKED":
        # 无逐规则缺证/待审仍 BLOCKED → 执行/上下文合同错误
        return {
            "primary_action": "complete_or_rebind_pending_review",
            "rule_ids": [],
            "reason": "execution_or_context_contract_failure",
        }

    if profile == "economy" and status == "PARTIAL":
        group_ids = _recommended_group_ids(domain_result)
        if group_ids:
            return {"primary_action": "run_recommended_targeted_groups", "group_ids": group_ids}

    professional_followup = _professional_followup_action(domain_result)
    if professional_followup is not None:
        return professional_followup

    if status == "PARTIAL" and _completion_state(domain_result) == _COMPLETION_NOT_STARTED:
        return {
            "primary_action": "complete_or_rebind_pending_review",
            "rule_ids": [],
            "reason": "no_rules_executed",
        }

    if journey_facts is None:
        return {"primary_action": "no_additional_audit_for_current_daily_scope"}

    # 第 5 项：mechanical 部分检查完成且影响未知（第 5 项优先于第 6 项）
    if (
        profile == "mechanical"
        and status == "PARTIAL"
        and journey_facts["mechanical_impact_unknown"] is True
    ):
        return {"primary_action": "run_economy_when_mechanical_impact_is_unknown"}

    # 第 6 项：携带唯一批准 group ID（第 6 项优先于第 7/8 项）
    approved_group_id = journey_facts["next_approved_targeted_group_id"]
    if approved_group_id is not None:
        return {
            "primary_action": "continue_next_approved_targeted_group",
            "group_id": approved_group_id,
        }

    if journey_facts["intent"] == "release_preparation":
        # 第 7 项：release preparation 意图 + full + SUCCEEDED
        if profile == "full" and status == "SUCCEEDED":
            return {
                "primary_action":
                    "complete_remaining_release_preparation_gates_after_full_success"
            }
        # 第 8 项：release preparation 意图且当前结果仍为部分 profile
        return {"primary_action": "run_full_on_frozen_candidate_when_release_is_intended"}

    professional_followup = _professional_followup_action(domain_result)
    if professional_followup is not None:
        return professional_followup
    return {"primary_action": "no_additional_audit_for_current_daily_scope"}


def choose_primary_next_action(domain_result, journey_facts=None):
    """Keep the existing precedence and attach professional next steps."""
    action = _primary_next_action_body(domain_result, journey_facts)
    followup = _professional_followup_action(domain_result)
    steps = None if followup is None else followup.get("professional_next_steps")
    if steps and "professional_next_steps" not in action:
        action = {**action, "professional_next_steps": steps}
    return action


def render_human_summary(domain_result, group_registry, journey_facts=None):
    """按 11-result-presentation.md 固定六段顺序生成人类摘要（普通列表）。

    每段为 {"section": <段名>, ...}；group_registry 仅用于把 group ID 映射为
    显示名称，解析失败时宽限为 None，不影响呈现。journey_facts 原样传给
    choose_primary_next_action 并用于渲染 next_action 段；非法结构由该函数失败关闭。
    宿主观察的实际模型执行指标若出现在 journey_facts 中，semantic_cost 优先使用它们。
    领域指标为 None 时渲染 unknown；semantic_model_call_count 不得用上下文数或
    结果数量代替。
    """
    status = domain_result.get("status")
    coverage = domain_result.get("coverage") or {}
    semantic_binding = domain_result.get("semantic_review_binding") or {}
    metrics = domain_result.get("execution_metrics") or {}
    requested_groups = coverage.get("requested_semantic_group_ids") or []
    selected_groups = coverage.get("selected_semantic_group_ids") or []
    unselected_requested_groups = sorted(
        set(requested_groups) - set(selected_groups)
    )
    unselected_requested_explanation = (
        _unselected_requested_group_explanation(domain_result)
        if unselected_requested_groups else None
    )
    unreviewed_rule_ids = _unreviewed_rule_ids(domain_result)
    completion_state = _completion_state(domain_result)
    observed = _validate_journey_facts(journey_facts) or {}

    decision_scope = {
        "section": "decision_scope",
        "status": status,
        "status_meaning": (
            _PARTIAL_STATUS_MEANING[completion_state]
            if status == "PARTIAL" else _STATUS_MEANING.get(status)
        ),
        "completion_state": completion_state,
        "completion_meaning": _COMPLETION_MEANING[completion_state],
        "can_prove_complete_conformance": bool(
            status == "SUCCEEDED"
            and coverage.get("coverage_complete") is True
            and coverage.get("conclusion_complete") is True
        ),
    }
    if status == "PARTIAL":
        decision_scope["first_sentence"] = (
            _PARTIAL_NOT_STARTED_FIRST_SENTENCE
            if completion_state == _COMPLETION_NOT_STARTED
            else _PARTIAL_FIRST_SENTENCE
        )

    next_section = {"section": "next_action"}
    next_section.update(choose_primary_next_action(domain_result, journey_facts))
    if "group_ids" in next_section:
        next_section["recommended_groups"] = _recommended_group_details(
            next_section["group_ids"], domain_result, group_registry
        )

    return [
        {
            "section": "run_identity",
            "execution_profile": domain_result.get("execution_profile"),
            "target_type": domain_result.get("target_type"),
            "target_digest": domain_result.get("target_digest"),
            "evidence_set_digest": semantic_binding.get("evidence_set_digest"),
            "freshness_statement": (
                "本次结论只绑定当前的目标摘要和证据摘要；"
                "材料字节一变，旧结论就不能沿用。"
            ),
        },
        decision_scope,
        {
            "section": "coverage",
            "in_scope_count": coverage.get("in_scope_count"),
            "requested_semantic_group_ids": requested_groups,
            "selected_semantic_group_ids": selected_groups,
            "unselected_requested_semantic_group_ids": (
                unselected_requested_groups
            ),
            "unselected_requested_semantic_group_explanation": (
                unselected_requested_explanation
            ),
            "selected_rule_count": coverage.get("selected_count"),
            "attempted_count": coverage.get("attempted_count"),
            "not_run_count": coverage.get("not_run_count"),
            "not_applicable_count": _status_count(domain_result, "NOT_APPLICABLE"),
            "scope_rule_label": "范围内规则",
            "unreviewed_rule_ids": unreviewed_rule_ids,
            "coverage_complete": coverage.get("coverage_complete"),
            "professional_items": _professional_summary_items(domain_result),
        },
        {
            "section": "semantic_cost",
            "semantic_model_call_count": _observed_metric(
                observed, metrics, "semantic_model_call_count", default_unknown=True
            ),
            "semantic_context_count": _observed_metric(
                observed, metrics, "semantic_context_count"
            ),
            "semantic_rules_sent_to_model_count": _observed_metric(
                observed, metrics, "semantic_rules_sent_to_model_count",
                default_unknown=True,
            ),
            "estimated_input_tokens": metrics.get("estimated_input_tokens", 0),
        },
        {
            "section": "blocking_findings",
            "findings": _blocking_findings(domain_result),
        },
        next_section,
    ]


# --- 内部辅助（私有，非对外 API）----------------------------------------


def _validate_journey_facts(journey_facts):
    """失败关闭校验 journey_facts；None 原样返回（保守默认）。

    必选字段仍是 intent / mechanical_impact_unknown /
    next_approved_targeted_group_id。可选字段只接受宿主实际观察的
    semantic_model_call_count / semantic_context_count /
    semantic_rules_sent_to_model_count。对象结构、字段类型、未知字段和
    intent 枚举非法一律抛 ValueError，消息以 "invalid_journey_facts" 开头。
    缺失的必选字段使用保守默认值；可选观察字段仅在调用方给出时原样保留。
    校验通过后返回新字典，不修改原字典，也不要求全部字段出现。
    """
    if journey_facts is None:
        return None
    if not isinstance(journey_facts, dict):
        raise ValueError("invalid_journey_facts: journey_facts 必须是普通字典")
    allowed = {
        "intent",
        "mechanical_impact_unknown",
        "next_approved_targeted_group_id",
        *_HOST_OBSERVATION_FIELDS,
    }
    unknown = sorted(set(journey_facts) - allowed)
    if unknown:
        raise ValueError("invalid_journey_facts: 未知字段 {}".format(unknown))
    intent = journey_facts.get("intent", "ordinary_conformance")
    if intent not in _INTENTS:
        raise ValueError(
            "invalid_journey_facts: intent 必须是四值枚举之一，got {!r}".format(intent)
        )
    mechanical_impact_unknown = journey_facts.get("mechanical_impact_unknown", False)
    if not isinstance(mechanical_impact_unknown, bool):
        raise ValueError(
            "invalid_journey_facts: mechanical_impact_unknown 必须是布尔值，got {!r}".format(
                mechanical_impact_unknown
            )
        )
    approved_group_id = journey_facts.get("next_approved_targeted_group_id")
    if approved_group_id is not None and (
        not isinstance(approved_group_id, str) or not approved_group_id
    ):
        raise ValueError(
            "invalid_journey_facts: next_approved_targeted_group_id 必须是非空字符串或 "
            "None，got {!r}".format(approved_group_id)
        )
    normalized = {
        "intent": intent,
        "mechanical_impact_unknown": mechanical_impact_unknown,
        "next_approved_targeted_group_id": approved_group_id,
    }
    for name in _HOST_OBSERVATION_FIELDS:
        if name not in journey_facts:
            continue
        value = journey_facts[name]
        if value is None:
            normalized[name] = None
            continue
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise ValueError(
                "invalid_journey_facts: {} 必须是非负整数或 None，got {!r}".format(
                    name, value
                )
            )
        normalized[name] = value
    return normalized


def _completion_state(domain_result):
    """区分尚未开始、检查未完成、选定范围已处理。"""
    if domain_result.get("failure_stage") == "before_rule_selection":
        return _COMPLETION_NOT_STARTED
    rules = domain_result.get("rule_results") or []
    coverage = domain_result.get("coverage") or {}
    attempted = coverage.get("attempted_count")
    selected = coverage.get("selected_count")
    if not rules:
        if attempted in (None, 0):
            return _COMPLETION_NOT_STARTED
    if any(row.get("status") == "REVIEW_REQUIRED" for row in rules):
        return _COMPLETION_INCOMPLETE
    if (
        isinstance(attempted, int)
        and not isinstance(attempted, bool)
        and isinstance(selected, int)
        and not isinstance(selected, bool)
        and attempted < selected
    ):
        return _COMPLETION_INCOMPLETE
    if not rules:
        return _COMPLETION_NOT_STARTED
    return _COMPLETION_SCOPE_PROCESSED


def _unreviewed_rule_ids(domain_result):
    return sorted(
        row["rule_id"]
        for row in domain_result.get("rule_results") or []
        if row.get("status") == "REVIEW_REQUIRED"
        and isinstance(row.get("rule_id"), str)
    )


def _observed_metric(observed, metrics, name, *, default_unknown=False):
    if name in observed:
        value = observed[name]
        return "unknown" if value is None else value
    if name in metrics:
        value = metrics[name]
        return "unknown" if value is None else value
    return "unknown" if default_unknown else 0


def _route(profile, group_ids, reason, canonical_rule_ids=None, *, explanations=None):
    return {
        "execution_profile": profile,
        "semantic_group_ids": sorted(group_ids),
        "canonical_rule_ids": sorted(canonical_rule_ids or []),
        "selection_reason": reason,
        "source_number_explanations": sorted(
            explanations or [], key=lambda row: row["source_id"]
        ),
    }


def _resolve_with_explicit_profile(
    profile,
    selectors,
    group_registry,
    deterministic_rule_ids,
    canonical_rule_ids,
    source_dispositions=None,
    explanations=None,
):
    if profile == "targeted":
        if selectors and canonical_rule_ids:
            raise ValueError(
                "targeted_selection_ambiguous: group selectors and canonical_rule_ids "
                "are mutually exclusive"
            )
        if canonical_rule_ids:
            return _route(
                "targeted", [], "explicit_profile", canonical_rule_ids,
                explanations=explanations,
            )
        group_ids = _resolve_selectors(
            selectors, group_registry, deterministic_rule_ids, source_dispositions,
            explanations,
        )
        if not group_ids:
            raise ValueError("targeted_requires_group_ids: targeted 必须提供非空、可解析的语义组选择")
        return _route("targeted", group_ids, "explicit_profile", explanations=explanations)
    if selectors or canonical_rule_ids:
        raise ValueError(
            "selectors_forbidden_for_non_targeted: 非 targeted 显式 profile 不接受 group/rule 选择器"
        )
    return _route(profile, [], "explicit_profile", explanations=explanations)


def _resolve_from_selectors(
    selectors,
    group_registry,
    deterministic_rule_ids,
    source_dispositions=None,
    explanations=None,
):
    group_ids = _resolve_selectors(
        selectors, group_registry, deterministic_rule_ids, source_dispositions,
        explanations,
    )
    if group_ids:
        return _route(
            "targeted", group_ids,
            "registered_group_name_group_id_or_canonical_rule_id",
            explanations=explanations,
        )
    return _route(
        "mechanical", [], "registered_group_name_group_id_or_canonical_rule_id",
        explanations=explanations,
    )


def _validate_source_dispositions(source_dispositions):
    """失败关闭校验旧编号去向投影行列表；None 视为未提供投影（返回空表）。

    只接受字典列表：每行必须携带非空且全局唯一的 source_id 与非空 destination；
    destination_label（非空字符串）、carried_by（非空字符串列表）、
    carried_by_status（非空字符串）可选，其余字段原样忽略。返回
    source_id → {"destination", "destination_label", "carried_by",
    "carried_by_status"} 的表。结构非法抛 ValueError，消息以
    "invalid_source_dispositions" 开头；本函数不推定任何去向，也不复制编号映射。
    """
    if source_dispositions is None:
        return {}
    if not isinstance(source_dispositions, list):
        raise ValueError(
            "invalid_source_dispositions: source_dispositions 必须是投影行列表"
        )
    table = {}
    for row in source_dispositions:
        if not isinstance(row, dict):
            raise ValueError("invalid_source_dispositions: 每行必须是字典")
        source_id = row.get("source_id")
        destination = row.get("destination")
        if not isinstance(source_id, str) or not source_id:
            raise ValueError("invalid_source_dispositions: 行缺少非空 source_id")
        if not isinstance(destination, str) or not destination:
            raise ValueError(
                "invalid_source_dispositions: 行 {!r} 缺少非空 destination".format(
                    source_id
                )
            )
        if source_id in table:
            raise ValueError(
                "invalid_source_dispositions: source_id 重复 {!r}".format(source_id)
            )
        label = row.get("destination_label")
        if label is not None and (not isinstance(label, str) or not label):
            raise ValueError(
                "invalid_source_dispositions: 行 {!r} 的 destination_label 必须是非空"
                "字符串".format(source_id)
            )
        carried_by = row.get("carried_by")
        if carried_by is None:
            carried_by = []
        if not isinstance(carried_by, list) or any(
            not isinstance(value, str) or not value for value in carried_by
        ):
            raise ValueError(
                "invalid_source_dispositions: 行 {!r} 的 carried_by 必须是非空字符串"
                "列表".format(source_id)
            )
        carried_by_status = row.get("carried_by_status")
        if carried_by_status is not None and (
            not isinstance(carried_by_status, str) or not carried_by_status
        ):
            raise ValueError(
                "invalid_source_dispositions: 行 {!r} 的 carried_by_status 必须是非空"
                "字符串".format(source_id)
            )
        table[source_id] = {
            "destination": destination,
            "destination_label": label,
            "carried_by": carried_by,
            "carried_by_status": carried_by_status,
        }
    return table


def _validate_selectors(selectors):
    if not isinstance(selectors, list):
        raise ValueError("invalid_selectors: selectors 必须是字符串列表")
    seen = set()
    out = []
    for s in selectors:
        if not isinstance(s, str) or not s:
            raise ValueError("invalid_selectors: 选择器必须是非空字符串")
        if s in seen:
            raise ValueError("duplicate_selector: {!r}".format(s))
        seen.add(s)
        out.append(s)
    return out


def _normalize_canonical_rule_ids(
    canonical_rule_ids,
    group_registry,
    deterministic_rule_ids,
    source_dispositions=None,
    explanations=None,
):
    if canonical_rule_ids is None:
        return []
    if not isinstance(canonical_rule_ids, list):
        raise ValueError(
            "invalid_canonical_rule_ids: canonical_rule_ids 必须是字符串列表"
        )
    if any(not isinstance(value, str) or not value for value in canonical_rule_ids):
        raise ValueError(
            "invalid_canonical_rule_ids: canonical_rule_ids 必须只含非空字符串"
        )
    normalized = sorted(set(canonical_rule_ids))
    if not normalized:
        raise ValueError(
            "invalid_canonical_rule_ids: canonical_rule_ids 不得为空"
        )
    registered = set(deterministic_rule_ids or [])
    registered.update(
        rule["canonical_id"]
        for group in group_registry
        for rule in group["rules"]
    )
    table = source_dispositions or {}
    unknown = sorted(set(normalized) - registered)
    if not unknown:
        return normalized
    interpretation = _interpret_source_numbers(unknown, table)
    if explanations is not None:
        explanations.extend(interpretation["explanations"])
    resolved, unresolved = [], []
    for value in normalized:
        if value in registered:
            resolved.append(value)
            continue
        successors = (interpretation["successors"].get(value) or {}).get(
            "successors"
        ) or []
        if not successors:
            # 去向投影中不存在该编号 → 未知编号，失败关闭；有去向但不可运行
            # （已退出、或承接尚未生效）→ 只解释、跳过，不猜编号。
            if value in interpretation["unknown"]:
                unresolved.append(value)
            continue
        missing = sorted(set(successors) - registered)
        if missing:
            raise ValueError(
                "source_number_successor_unresolved: 来源编号 {!r} 的承接编号未命中当前"
                "规则清单 {!r}".format(value, missing)
            )
        resolved.extend(successors)
    if unresolved:
        raise ValueError(
            "unresolved_selector: canonical_rule_ids 未命中当前规则清单 {!r}".format(
                unresolved
            )
        )
    if not resolved:
        raise ValueError(
            "source_numbers_not_runnable: 请求的编号全部已退出或被承接尚未生效，"
            "本次没有可运行规则"
        )
    return sorted(set(resolved))


def _validate_registry(group_registry):
    if not isinstance(group_registry, dict):
        raise ValueError("invalid_registry: group_registry 必须是 A1 分组治理对象")
    if group_registry.get("schema_version") != "1.0.0":
        raise ValueError("invalid_registry: 不支持或过期的 schema_version")
    if group_registry.get("kind") != "skill-family-audit.semantic-rule-groups":
        raise ValueError("invalid_registry: kind 与 A1 分组治理合同不符")
    if group_registry.get("status") != "implementation-design-authority-for-sfa-814-goal":
        raise ValueError("invalid_registry: Registry 状态已过期或不受本切片支持")
    groups = group_registry.get("groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError("invalid_registry: groups 必须是非空组登记列表")
    ids, names, rule_ids = set(), set(), set()
    for entry in groups:
        if not isinstance(entry, dict):
            raise ValueError("invalid_registry: 每个组登记必须是字典")
        gid = entry.get("group_id")
        name = entry.get("name")
        rules = entry.get("rules")
        if not isinstance(gid, str) or not gid:
            raise ValueError("invalid_registry: 组登记缺少非空 group_id")
        if not isinstance(name, str) or not name:
            raise ValueError("invalid_registry: 组登记缺少非空 name")
        if not isinstance(rules, list) or not rules:
            raise ValueError("invalid_registry: rules 必须是非空规则对象数组")
        members = []
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError("invalid_registry: 每条规则登记必须是字典")
            canonical_id = rule.get("canonical_id")
            if not isinstance(canonical_id, str) or not canonical_id:
                raise ValueError("invalid_registry: 规则登记缺少非空 canonical_id")
            members.append(canonical_id)
        if gid in ids or name in names:
            raise ValueError("invalid_registry: group_id 或 name 重复")
        for r in members:
            if r in rule_ids:
                raise ValueError("invalid_registry: 规则 {!r} 被登记到多个组".format(r))
            rule_ids.add(r)
        ids.add(gid)
        names.add(name)
    return groups


def _resolve_selectors(
    selectors,
    group_registry,
    deterministic_rule_ids,
    source_dispositions=None,
    explanations=None,
):
    groups = list(group_registry)
    by_id = {g["group_id"]: g for g in groups}
    by_name = {}
    for g in groups:
        by_name.setdefault(g["name"], []).append(g)
    rule_to_group = {}
    for g in groups:
        for rule in g["rules"]:
            rule_to_group[rule["canonical_id"]] = g
    deterministic = set(deterministic_rule_ids or [])
    table = source_dispositions or {}

    def _add_rule(value):
        """把一个精确 canonical rule ID 记入已解析集合（确定性规则无需分组）。"""
        if value in rule_to_group:
            resolved_groups.add(rule_to_group[value]["group_id"])
            return True
        return value in deterministic

    resolved_groups = set()
    interpretation = None
    runnable_count = 0
    dropped_count = 0
    for s in selectors:
        matches = []
        if s in by_id:
            matches.append(by_id[s])
        if s in by_name:
            matches.extend(by_name[s])
        if s in rule_to_group:
            matches.append(rule_to_group[s])
        is_deterministic = s in deterministic
        if len(matches) == 0 and not is_deterministic:
            # 未命中当前清单：有去向投影时按旧编号解释处理，否则失败关闭。
            if interpretation is None:
                interpretation = _interpret_source_numbers(
                    [
                        value for value in selectors
                        if value not in by_id
                        and value not in by_name
                        and value not in rule_to_group
                        and value not in deterministic
                    ],
                    table,
                )
                if explanations is not None:
                    explanations.extend(interpretation["explanations"])
            successors = (interpretation["successors"].get(s) or {}).get(
                "successors"
            ) or []
            if successors:
                # 合并承接：按承接编号继续解析，不运行旧编号检查。
                unresolved = [
                    value for value in successors if not _add_rule(value)
                ]
                if unresolved:
                    raise ValueError(
                        "source_number_successor_unresolved: 来源编号 {!r} 的承接编号未"
                        "命中当前规则清单 {!r}".format(s, sorted(unresolved))
                    )
                continue
            if s in interpretation["unknown"]:
                raise ValueError(
                    "unresolved_selector: {!r} 未命中任何已登记 group/rule".format(s)
                )
            # 已退出或承接尚未生效：只解释去向，跳过该编号。
            dropped_count += 1
            continue
        if len(matches) > 1 or (len(matches) == 1 and is_deterministic):
            raise ValueError("ambiguous_selector: {!r} 存在多个命中或同时为确定性规则".format(s))
        runnable_count += 1
        if is_deterministic:
            continue
        resolved_groups.add(matches[0]["group_id"])
    if dropped_count and not runnable_count:
        raise ValueError(
            "source_numbers_not_runnable: 请求的选择器全部已退出或承接尚未生效，"
            "本次没有可运行规则"
        )
    return resolved_groups


_AUDIT_INTERNAL_EVIDENCE_REASONS = {
    "executor_method_subresults_invalid",
    "executor_evidence_invalid",
}


def _rule_ids_with_status(rule_rows, status):
    return sorted(
        r["rule_id"] for r in rule_rows
        if r.get("status") == status and isinstance(r.get("rule_id"), str)
    )


def _rule_row_by_id(rule_rows, rule_id):
    for row in rule_rows:
        if row.get("rule_id") == rule_id:
            return row
    return {}


def _is_audit_internal_missing(row):
    if not isinstance(row, dict):
        return False
    evidence = row.get("evidence")
    if not isinstance(evidence, dict):
        return False
    return (
        evidence.get("reason") in _AUDIT_INTERNAL_EVIDENCE_REASONS
        or evidence.get("reason_code") == "CANONICAL_EXECUTION_CARRIER_MISSING"
    )


def _status_count(domain_result, status):
    return sum(
        1
        for row in domain_result.get("rule_results") or []
        if row.get("status") == status
    )


def _missing_roles_by_rule(domain_result, rule_ids):
    roles_by_id = {}
    for row in domain_result.get("rule_results") or []:
        lineage = row.get("canonical_lineage") or {}
        canonical_id = lineage.get("canonical_id")
        rule_id = row.get("rule_id")
        roles = sorted(row.get("missing_evidence_roles") or [])
        if isinstance(canonical_id, str):
            roles_by_id[canonical_id] = roles
        if isinstance(rule_id, str):
            roles_by_id[rule_id] = roles
    return {rid: roles_by_id.get(rid, []) for rid in rule_ids}


def _recommended_group_ids(domain_result):
    preflight = domain_result.get("semantic_preflight") or {}
    return sorted(
        {
            group["group_id"]
            for group in preflight.get("groups") or []
            if group.get("review_required_rule_count", 0) > 0
            and isinstance(group.get("group_id"), str)
        }
    )


def _blocking_findings(domain_result):
    findings = []
    for row in domain_result.get("rule_results") or []:
        status = row.get("status")
        rule_id = row.get("rule_id")
        lineage = row.get("canonical_lineage") or {}
        canonical_id = lineage.get("canonical_id")
        if status in _FINDING_STATUS_ORDER and isinstance(rule_id, str):
            missing_roles = row.get("missing_evidence_roles")
            if not isinstance(missing_roles, list):
                missing_roles = []
            finding = {
                "rule_id": rule_id,
                "status": status,
                "missing_evidence_roles": sorted(missing_roles),
            }
            if isinstance(canonical_id, str):
                finding["canonical_id"] = canonical_id
            if _is_audit_internal_missing(row):
                finding["issue_type"] = "audit_executor_contract_failure"
                evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
                finding["reason"] = evidence.get("reason")
            findings.append(finding)
    findings.extend(_professional_blocking_findings(domain_result))
    findings.sort(
        key=lambda f: (
            _FINDING_STATUS_ORDER.get(f["status"], 9),
            f.get("rule_id") or f.get("provider_id") or "",
        )
    )
    if not findings and domain_result.get("status") == "BLOCKED":
        findings.append({
            "status": "BLOCKED",
            "issue_type": "execution_or_context_contract_failure",
            "reason_code": domain_result.get("reason_code"),
            "summary": domain_result.get("summary"),
        })
    return findings


def _professional_issue_type(item):
    mode = item.get("mode")
    reader_status = item.get("reader_status")
    if item.get("status") == "pass":
        return "professional_pass"
    if mode == "missing_entry":
        return "missing_entry"
    if mode == "missing_proof":
        return "missing_proof"
    if reader_status == "unavailable":
        return "reader_unavailable"
    if mode == "version_policy":
        return "version_policy"
    if mode == "not_selected":
        return "not_selected"
    conclusion = item.get("conclusion") if isinstance(item.get("conclusion"), dict) else {}
    outcome = conclusion.get("outcome") if isinstance(conclusion.get("outcome"), dict) else {}
    completion = outcome.get("completion")
    if isinstance(completion, str) and completion != "complete":
        return "professional_incomplete"
    if (
        reader_status == "not_pass"
        and mode in {"reused_proof", "scanned"}
        and conclusion
        and completion == "complete"
    ):
        return "professional_findings"
    return "missing_proof"


def _professional_next_step(item):
    issue = _professional_issue_type(item)
    entry = item.get("entry_ref") if isinstance(item.get("entry_ref"), str) else ""
    provider = item.get("provider_id") if isinstance(item.get("provider_id"), str) else ""
    if issue == "professional_pass":
        return "这个专业项已按证明或版本政策通过，并不表示其他领域通过。"
    if issue == "missing_entry":
        return (
            "等宿主找到 {} 的公开入口后，再扫描或读取。登记不等于已经安装或已经发布。"
            .format(entry or provider)
        )
    if issue == "reader_unavailable":
        reason = str(item.get("reason") or "")
        if reason.startswith("严格读取失败：证明不是合法 JSON"):
            return (
                "由 {} 修复或刷新损坏的证明，再从公开读取入口取得原始结果。"
                .format(provider or entry)
            )
        if reason.startswith("严格读取失败："):
            return (
                "由宿主核对证明的路径和能否读取，再经 {} 取得原始结果。"
                .format(entry or provider)
            )
        return (
            "由宿主找到 {} 的读取入口，并取得原始结果。Audit 不重做专业检查。"
            .format(entry or provider)
        )
    if issue == "professional_incomplete":
        return (
            "由 {} 完成未完成的范围，或刷新证明。Audit 不把未完成写成已证违规。"
            .format(provider or entry)
        )
    if issue == "professional_findings":
        return (
            "由 {} 按其发现处理。Audit 沿用原结论，不重做专业检查，也不鉴伪。"
            .format(provider or entry)
        )
    if issue == "version_policy":
        return "建议使用更新版本刷新证明，不强制升级。"
    return (
        "由宿主按 {} 取得能定位的证明或扫描结果。适用项缺证时，仍然未通过。"
        .format(entry or provider)
    )


def _professional_summary_items(domain_result):
    payload = domain_result.get("professional_consumption")
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        return []
    items = []
    for item in payload["items"]:
        if not isinstance(item, dict):
            continue
        issue = _professional_issue_type(item)
        conclusion = item.get("conclusion") if isinstance(item.get("conclusion"), dict) else None
        outcome = conclusion.get("outcome") if isinstance(conclusion, dict) else None
        scope = conclusion.get("scope") if isinstance(conclusion, dict) else None
        items.append({
            "provider_id": item.get("provider_id"),
            "status": item.get("status"),
            "mode": item.get("mode"),
            "reason": item.get("reason"),
            "issue_type": issue,
            "passed": item.get("status") == "pass",
            "version_relation": item.get("version_relation"),
            "reader_status": item.get("reader_status"),
            "entry_ref": item.get("entry_ref"),
            "refresh_suggested": item.get("refresh_suggested") is True,
            "next_step": _professional_next_step(item),
            "conclusion": conclusion,
            "subject": None if conclusion is None else conclusion.get("subject"),
            "scope": scope,
            "outcome": outcome,
            "findings": None if not isinstance(outcome, dict) else outcome.get("findings"),
            "limitations": None if not isinstance(scope, dict) else scope.get("limitations"),
        })
    return items


def _professional_followup_action(domain_result):
    items = [
        item
        for item in _professional_summary_items(domain_result)
        if item.get("status") == "not_pass"
    ]
    if not items:
        return None
    issues = {item.get("issue_type") for item in items}
    primary = (
        "complete_or_rebind_pending_review"
        if issues == {"professional_findings"}
        else "supply_missing_evidence"
    )
    return {
        "primary_action": primary,
        "rule_ids": [],
        "missing_evidence_roles": {},
        "professional_next_steps": [
            {
                "provider_id": item.get("provider_id"),
                "issue_type": item.get("issue_type"),
                "next_step": item.get("next_step"),
            }
            for item in items
        ],
    }


def _professional_blocking_findings(domain_result):
    findings = []
    for item in _professional_summary_items(domain_result):
        if item.get("status") == "pass":
            continue
        issue = item.get("issue_type")
        findings.append({
            "status": (
                "REVIEW_REQUIRED"
                if issue == "professional_findings"
                else "EVIDENCE_MISSING"
            ),
            "issue_type": issue,
            "provider_id": item.get("provider_id"),
            "reason": item.get("reason"),
            "refresh_suggested": item.get("refresh_suggested") is True,
            "next_step": item.get("next_step"),
            "reader_status": item.get("reader_status"),
            "mode": item.get("mode"),
        })
    return findings


def _unselected_requested_group_explanation(domain_result):
    return (
        "已识别请求组，但当前生产生命周期里没有 executable 成员。"
        "这次未执行这些组，也不能判断这些组或对应整改包的语义结论是否已经收敛。"
    )


def _recommended_group_details(group_ids, domain_result, group_registry):
    groups = {}
    if isinstance(group_registry, dict) and isinstance(group_registry.get("groups"), list):
        for entry in group_registry["groups"]:
            if isinstance(entry, dict):
                gid = entry.get("group_id")
                if isinstance(gid, str):
                    groups[gid] = entry
    preflight = domain_result.get("semantic_preflight") or {}
    summaries = {
        row["group_id"]: row
        for row in preflight.get("groups") or []
        if isinstance(row, dict) and isinstance(row.get("group_id"), str)
    }

    details = []
    for gid in group_ids:
        entry = groups.get(gid) or {}
        details.append({
            "group_id": gid,
            "display_name": entry.get("name"),
            "preflight_summary": summaries.get(gid),
        })
    return details
