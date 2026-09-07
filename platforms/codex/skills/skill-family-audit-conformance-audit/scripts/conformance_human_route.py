"""A4 切片：人类入口的确定性路由、结果呈现与下一步选择内核。

本模块只提供三个固定纯函数（resolve_human_route、choose_primary_next_action、
render_human_summary）。函数只处理普通 Python 值（字典/列表/字符串），
不读取文件、不导入项目内模块、不调用模型、不接触 Foundation。

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

失败形态
--------
任何无法解析、歧义、重复或无效 Registry 输入都抛出 ValueError，消息以
"<error_code>: <detail>" 开头（例如 unresolved_selector、ambiguous_selector、
duplicate_selector、invalid_registry、invalid_intent、invalid_profile、
targeted_requires_group_ids、selectors_forbidden_for_non_targeted）。
绝不猜组、不模糊匹配、不调用模型、不自动改变 profile。

profile 选择优先级与 journey-contract.json selection_precedence 一致：
显式 profile > release_preparation > complete_audit > 精确 selector
（registered_group_name_group_id_or_canonical_rule_id）> deterministic_only
> ordinary_conformance。只含确定性 canonical rule 的选择解析为 mechanical；
含语义组的选择解析为 targeted（是否属语义组以 group_registry 登记为准）。

choose_primary_next_action 只对 domain_result 已有事实返回唯一主动作。发布意图、
机械影响是否未知和下一批准组通过可选 journey_facts 传入：journey_facts 只接受
intent（四值枚举）/ mechanical_impact_unknown（布尔）/
next_approved_targeted_group_id（非空字符串或 None）三字段，对象结构、字段类型、
未知字段和 intent 枚举非法一律失败关闭。缺少 journey_facts 时保留现有保守默认：
不猜测用户意图、不自动执行下一 profile。下一步严格按 journey-contract.json
next_action_precedence 的九级顺序返回唯一 primary_action；任何分支都只返回动作，
不自动启动下一次运行。

render_human_summary 输出固定六段（列表，顺序即呈现顺序）：
run_identity → decision_scope → coverage → semantic_cost →
blocking_findings → next_action。PARTIAL 的 decision_scope 固定携带首句：
"本次为部分检查，不能证明项目完整符合，也不能单独作为发布资格。"
journey_facts 原样传给 choose_primary_next_action 并用于渲染 next_action 段。
"""

_INTENTS = ("ordinary_conformance", "deterministic_only", "complete_audit", "release_preparation")
_EXECUTION_PROFILES = ("mechanical", "economy", "targeted", "full")

_PARTIAL_FIRST_SENTENCE = "本次为部分检查，不能证明项目完整符合，也不能单独作为发布资格。"

# 11-result-presentation.md 状态含义表（人类摘要必须使用的含义）。
_STATUS_MEANING = {
    "SUCCEEDED": "完整符合性审计已通过；仍需独立核对发布门禁和授权",
    "PARTIAL": "选定范围已经完成；没有形成全量符合性结论",
    "FAILED": "已证明至少一条所选规则违规",
    "BLOCKED": "所选范围存在缺证、待审或执行合同问题",
}

# blocking_findings 按状态排序：失败规则、缺证角色、仍需审阅。
_FINDING_STATUS_ORDER = {"FAIL": 0, "EVIDENCE_MISSING": 1, "REVIEW_REQUIRED": 2}

__all__ = ["resolve_human_route", "choose_primary_next_action", "render_human_summary"]


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


def resolve_human_route(explicit_profile, intent, selectors, group_registry, deterministic_rule_ids):
    """按 journey-contract selection_precedence 解析人类入口的 profile 与语义组。

    返回 {"execution_profile": str, "semantic_group_ids": [...],
    "selection_reason": str}。semantic_group_ids 为唯一、排序后的 group ID
    数组，非 targeted 时为空列表。失败关闭一律抛 ValueError。
    """
    if explicit_profile is not None and explicit_profile not in _EXECUTION_PROFILES:
        raise ValueError("invalid_profile: {!r}".format(explicit_profile))
    if intent not in _INTENTS:
        raise ValueError("invalid_intent: {!r}".format(intent))
    groups = _validate_registry(group_registry)
    selectors = _validate_selectors(selectors)

    if explicit_profile is not None:
        return _resolve_with_explicit_profile(explicit_profile, selectors, groups, deterministic_rule_ids)

    if intent == "release_preparation":
        return _route("full", [], "release_preparation")
    if intent == "complete_audit":
        return _route("full", [], "complete_audit")
    if selectors:
        return _resolve_from_selectors(selectors, groups, deterministic_rule_ids)
    if intent == "deterministic_only":
        return _route("mechanical", [], "deterministic_only")
    return _route("economy", [], "ordinary_conformance")


def choose_primary_next_action(domain_result, journey_facts=None):
    """按 journey-contract next_action_precedence 返回唯一主动作（普通字典）。

    domain_result 是 conformance-result 合同中的 conformance_result 领域对象。
    journey_facts 可选；只接受 intent / mechanical_impact_unknown /
    next_approved_targeted_group_id 三字段，结构、类型与枚举非法一律失败关闭
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
    if missing_ids:
        return {
            "primary_action": "supply_missing_evidence",
            "rule_ids": missing_ids,
            "missing_evidence_roles": _missing_roles_by_rule(domain_result, missing_ids),
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

    return {"primary_action": "no_additional_audit_for_current_daily_scope"}


def render_human_summary(domain_result, group_registry, journey_facts=None):
    """按 11-result-presentation.md 固定六段顺序生成人类摘要（普通列表）。

    每段为 {"section": <段名>, ...}；group_registry 仅用于把 group ID 映射为
    显示名称，解析失败时宽限为 None，不影响呈现。journey_facts 原样传给
    choose_primary_next_action 并用于渲染 next_action 段；非法结构由该函数失败关闭。
    """
    status = domain_result.get("status")
    coverage = domain_result.get("coverage") or {}
    preflight = domain_result.get("semantic_preflight") or {}
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

    decision_scope = {
        "section": "decision_scope",
        "status": status,
        "status_meaning": _STATUS_MEANING.get(status),
        "can_prove_complete_conformance": bool(
            status == "SUCCEEDED"
            and coverage.get("coverage_complete") is True
            and coverage.get("conclusion_complete") is True
        ),
    }
    if status == "PARTIAL":
        decision_scope["first_sentence"] = _PARTIAL_FIRST_SENTENCE

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
                "本次结论只绑定当前目标摘要与证据摘要；"
                "材料字节变化后，旧结论不能沿用。"
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
            "coverage_complete": coverage.get("coverage_complete"),
        },
        {
            "section": "semantic_cost",
            "semantic_model_call_count": (
                "unknown"
                if metrics.get("semantic_model_call_count") is None
                else metrics.get("semantic_model_call_count", 0)
            ),
            "semantic_context_count": metrics.get("semantic_context_count", 0),
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

    只接受 intent / mechanical_impact_unknown / next_approved_targeted_group_id
    三字段：对象结构、字段类型、未知字段和 intent 枚举非法一律抛 ValueError，
    消息以 "invalid_journey_facts" 开头。缺失字段使用保守默认值；
    校验通过后返回包含三个规范值的新字典，不修改原字典，也不要求三字段全部出现。
    """
    if journey_facts is None:
        return None
    if not isinstance(journey_facts, dict):
        raise ValueError("invalid_journey_facts: journey_facts 必须是普通字典")
    allowed = {"intent", "mechanical_impact_unknown", "next_approved_targeted_group_id"}
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
    return {
        "intent": intent,
        "mechanical_impact_unknown": mechanical_impact_unknown,
        "next_approved_targeted_group_id": approved_group_id,
    }


def _route(profile, group_ids, reason):
    return {
        "execution_profile": profile,
        "semantic_group_ids": sorted(group_ids),
        "selection_reason": reason,
    }


def _resolve_with_explicit_profile(profile, selectors, group_registry, deterministic_rule_ids):
    if profile == "targeted":
        group_ids = _resolve_selectors(selectors, group_registry, deterministic_rule_ids)
        if not group_ids:
            raise ValueError("targeted_requires_group_ids: targeted 必须提供非空、可解析的语义组选择")
        return _route("targeted", group_ids, "explicit_profile")
    if selectors:
        raise ValueError(
            "selectors_forbidden_for_non_targeted: 非 targeted 显式 profile 不接受 group/rule 选择器"
        )
    return _route(profile, [], "explicit_profile")


def _resolve_from_selectors(selectors, group_registry, deterministic_rule_ids):
    group_ids = _resolve_selectors(selectors, group_registry, deterministic_rule_ids)
    if group_ids:
        return _route("targeted", group_ids, "registered_group_name_group_id_or_canonical_rule_id")
    return _route("mechanical", [], "registered_group_name_group_id_or_canonical_rule_id")


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


def _resolve_selectors(selectors, group_registry, deterministic_rule_ids):
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

    resolved_groups = set()
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
            raise ValueError("unresolved_selector: {!r} 未命中任何已登记 group/rule".format(s))
        if len(matches) > 1 or (len(matches) == 1 and is_deterministic):
            raise ValueError("ambiguous_selector: {!r} 存在多个命中或同时为确定性规则".format(s))
        if is_deterministic:
            continue
        resolved_groups.add(matches[0]["group_id"])
    return resolved_groups


def _rule_ids_with_status(rule_rows, status):
    return sorted(
        r["rule_id"] for r in rule_rows
        if r.get("status") == status and isinstance(r.get("rule_id"), str)
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
            findings.append(finding)
    findings.sort(key=lambda f: (_FINDING_STATUS_ORDER[f["status"]], f["rule_id"]))
    if not findings and domain_result.get("status") == "BLOCKED":
        findings.append({
            "status": "BLOCKED",
            "issue_type": "execution_or_context_contract_failure",
            "reason_code": domain_result.get("reason_code"),
            "summary": domain_result.get("summary"),
        })
    return findings


def _unselected_requested_group_explanation(domain_result):
    return (
        "已识别请求组，但当前生产生命周期没有 executable 成员；"
        "本次未执行这些组；不能判断这些组或对应整改包的语义结论是否已收敛。"
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
