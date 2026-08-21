"""M1 执行族：规则治理 / 制品图 / 权威 / 身份 / 关系（W2-B2 子批 M1，87 条）。

本模块覆盖 B2 批 execution_family=M1、violation_impact=error 的 87 条规则，
全部被终态裁决为机械方法（schema_validation + digest_verification）。

证据面（与 B1 M1 一致，失败关闭）：
- 本次运行装载的规范包索引 ``ctx["spec_index"]``（authority-index.json）；
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``。

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
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

# ---------------------------------------------------------------------------
# 词表（各状态轴 / 效力 / 权威来源 / 生命周期 / 检查方式 / 实现状态）
# ---------------------------------------------------------------------------

EFFECT_VOCABULARY = {"mandatory", "recommended", "experimental"}
AUTHORITY_SOURCE_VOCABULARY = {
    "general_spec",
    "skill_dev_domain_spec",
    "platform_additional",
    "project_tightening",
}
VIOLATION_IMPACT_VOCABULARY = {"block", "error", "warning", "observe"}
RULE_LIFECYCLE_VOCABULARY = {"draft", "experimental", "effective", "superseded", "deprecated"}
CHECK_METHOD_VOCABULARY = {
    "static_scan",
    "schema_validation",
    "digest_verification",
    "relation",
    "semantic_review",
    "behavior_verification",
    "runtime_observation",
}
IMPL_STATUS_VOCABULARY = {"unimplemented", "experimental", "verified", "withdrawn"}
RELEASE_STATUS_VOCABULARY = {"planned", "candidate", "published", "withdrawn"}
RELATION_TYPE_VOCABULARY = {
    "equivalent",
    "overlap",
    "contains",
    "derives",
    "supersedes",
    "conflicts",
}
FINDING_DISPOSITION_VOCABULARY = {"false_positive", "not_applicable", "duplicate", "fixed"}

STATUS_AXES: dict[str, tuple[str, set[str]]] = {
    # axis_key -> (canonical_id, vocabulary)
    "artifact_review": ("SFA-GRAPH-011", {"draft", "accepted", "superseded", "deprecated"}),
    "family_maturity": ("SFA-GRAPH-012", {"experimental", "incubating", "stable", "deprecated"}),
    "capability_support": ("SFA-GRAPH-013", {"planned", "supported", "experimental", "deprecated"}),
    "rule_lifecycle": ("SFA-GRAPH-014", RULE_LIFECYCLE_VOCABULARY),
    "evaluation_conclusion": (
        "SFA-GRAPH-015",
        {"not_run", "pass", "fail", "blocked", "conditional_pass", "not_applicable"},
    ),
    "release_lifecycle": ("SFA-GRAPH-016", RELEASE_STATUS_VOCABULARY),
    "platform_support": ("SFA-GRAPH-017", {"supported", "experimental", "pending", "deprecated"}),
    "exception_lifecycle": (
        "SFA-GRAPH-018",
        {"pending_approval", "active", "expired", "revoked", "remediated"},
    ),
}

LOCK_AXES: dict[str, str] = {
    # lock_key -> canonical_id（七类锁与摘要）
    "domain_spec_selection": "SFA-GRAPH-028",
    "relation_freshness": "SFA-GRAPH-029",
    "spec_adoption": "SFA-GRAPH-030",
    "method_run": "SFA-GRAPH-031",
    "skill_release_summary": "SFA-GRAPH-032",
    "spec_release_summary": "SFA-GRAPH-033",
    "eval_env_summary": "SFA-GRAPH-034",
}

SKILL_RELEASE_REQUIRED_MEMBERS = {
    "family_version",
    "capability_revisions",
    "platform_packages",
    "runtime_summary",
    "evaluations",
    "spec_release",
}

STATE_FACT_REQUIRED_FIELDS = (
    "event_type",
    "object_id",
    "prev_digest",
    "idempotency_key",
    "trusted_time",
    "signer",
    "authority_basis",
    "merger_version",
)


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _require_dict(value: Any, name: str, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"{name}.{field} 必须是对象"
        )
    return value


# ---------------------------------------------------------------------------
# AUTHORITY：机器权威索引
# ---------------------------------------------------------------------------


def check_authority_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次正式规范发布必须提供机器可读权威索引，唯一解析发布身份/版本/摘要与规则修订。

    机械断言：本次装载的规范包索引（spec_index）必须携带唯一 activeSpecRelease，
    其 releaseId、contentDigest、ruleManifestDigest 齐备且摘要为 64 位十六进制，
    且 recordedDigests 明示各权威制品摘要，使消费者无需自行拼接第二套有效规则集合。
    """
    index = ctx.get("spec_index")
    if not isinstance(index, dict):
        return result("EVIDENCE_MISSING", reason="spec_index_not_in_context")
    release = index.get("activeSpecRelease")
    if not isinstance(release, dict):
        return result("FAIL", reason="active_spec_release_missing")
    release_id = release.get("releaseId")
    if not isinstance(release_id, str) or not release_id:
        return result("FAIL", reason="release_id_missing")
    bad_digests = [
        field
        for field in ("contentDigest", "ruleManifestDigest")
        if not is_hex64(release.get(field))
    ]
    if bad_digests:
        return result("FAIL", reason="authority_index_digest_invalid", fields=bad_digests)
    recorded = index.get("recordedDigests")
    if not isinstance(recorded, dict) or not recorded:
        return result("FAIL", reason="recorded_digests_missing")
    return result(
        "PASS",
        releaseId=release_id,
        recorded_digest_fields=sorted(recorded),
    )


def check_authority_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式规则包生效后，旧材料只能作为来源/迁移/历史证据，退出当前规则权威。

    机械断言：项目声明的 ``rule-authority-index.superseded_materials`` 中，
    每条旧材料必须标记 authority_exited=true；未声明者无违反事实。
    """
    document = _doc(ctx, "rule-authority-index")
    if document is None:
        return result("PASS", declared_superseded=0)
    materials = rows_of(document, "superseded_materials", "rule-authority-index")
    violations = [
        {"index": index, "ref": row.get("ref")}
        for index, row in enumerate(materials)
        if row.get("authority_exited") is not True
    ]
    if violations:
        return result("FAIL", superseded_still_in_authority=violations)
    return result("PASS", declared_superseded=len(materials))


# ---------------------------------------------------------------------------
# GRAPH-006 / 规范发布引用精确规则修订（rule-authority-index）
# ---------------------------------------------------------------------------


def check_graph_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次规范发布必须引用实际包含的精确规则修订，不得只引用名称或宽泛版本范围。

    机械断言：``rule-authority-index.rule_revisions`` 每条必须携带精确 revision（整数）
    与 revision_digest（64 位十六进制）；只给名称或范围即违反。
    """
    document = _doc(ctx, "rule-authority-index")
    if document is None:
        return result("PASS", declared_rule_revisions=0)
    revisions = rows_of(document, "rule_revisions", "rule-authority-index")
    if not revisions:
        return result("FAIL", reason="rule_revisions_empty")
    violations = []
    for index, row in enumerate(revisions):
        revision = row.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            violations.append({"index": index, "rule_id": row.get("rule_id"), "reason": "revision_not_exact"})
        elif not is_hex64(row.get("revision_digest")):
            violations.append({"index": index, "rule_id": row.get("rule_id"), "reason": "revision_digest_invalid"})
    if violations:
        return result("FAIL", imprecise_rule_references=violations)
    return result("PASS", declared_rule_revisions=len(revisions))


# ---------------------------------------------------------------------------
# GRAPH 拓扑与链接（graph-links）
# ---------------------------------------------------------------------------


def check_graph_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范治理链与技能交付链可相交，但不得合并为同一权威链。

    机械断言：``graph-links.authority_chains`` 声明的两条权威链必须不同源，
    且 merged_into_single_authority 必须为 false。
    """
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_authority_chains=False)
    chains = _require_dict(document.get("authority_chains"), "graph-links", "authority_chains")
    spec_chain = chains.get("spec_chain")
    delivery_chain = chains.get("delivery_chain")
    if chains.get("merged_into_single_authority") is True:
        return result("FAIL", reason="authority_chains_merged")
    if not isinstance(spec_chain, str) or not isinstance(delivery_chain, str) or not spec_chain or not delivery_chain:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "graph-links.authority_chains 必须声明两条非空权威链"
        )
    if spec_chain == delivery_chain:
        return result("FAIL", reason="authority_chains_identical")
    return result("PASS", spec_chain=spec_chain, delivery_chain=delivery_chain)


def check_graph_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个严格方法契约必须直接指向其实现的一个或多个业务能力修订。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_method_contracts=0)
    contracts = rows_of(document, "method_contracts", "graph-links")
    violations = []
    for index, row in enumerate(contracts):
        capabilities = row.get("capability_revisions")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or not all(isinstance(item, dict) and item.get("capability") and item.get("revision") for item in capabilities)
        ):
            violations.append({"index": index, "contract_id": row.get("contract_id")})
    if violations:
        return result("FAIL", method_contracts_without_capability_revisions=violations)
    return result("PASS", declared_method_contracts=len(contracts))


def check_graph_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """每项技能评估必须直接指向被评估对象及其精确修订。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_evaluations=0)
    evaluations = rows_of(document, "evaluations", "graph-links")
    violations = [
        {"index": index, "evaluation_id": row.get("evaluation_id")}
        for index, row in enumerate(evaluations)
        if not (isinstance(row.get("target_id"), str) and row["target_id"]
                and isinstance(row.get("target_revision"), str) and row["target_revision"])
    ]
    if violations:
        return result("FAIL", evaluations_without_target=violations)
    return result("PASS", declared_evaluations=len(evaluations))


def check_graph_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条规范规则必须直接指向所属技能族规范根。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_rule_spec_roots=0)
    roots = rows_of(document, "rule_spec_roots", "graph-links")
    if not roots:
        return result("FAIL", reason="rule_spec_roots_empty")
    violations = [
        {"index": index, "rule_id": row.get("rule_id")}
        for index, row in enumerate(roots)
        if not (isinstance(row.get("spec_root"), str) and row["spec_root"])
    ]
    if violations:
        return result("FAIL", rules_without_spec_root=violations)
    return result("PASS", declared_rule_spec_roots=len(roots))


def check_graph_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目加严声明必须指向被加严的上级规则及其修订，并声明条件单调收紧。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_tightenings=0)
    tightenings = rows_of(document, "tightenings", "graph-links")
    violations = []
    for index, row in enumerate(tightenings):
        parent_rule = row.get("parent_rule_id")
        parent_revision = row.get("parent_revision")
        if (
            not (isinstance(parent_rule, str) and parent_rule)
            or not (isinstance(parent_revision, str) and parent_revision)
            or row.get("monotonic") is not True
        ):
            violations.append({"index": index, "override_id": row.get("override_id")})
    if violations:
        return result("FAIL", tightenings_not_bound_to_parent=violations)
    return result("PASS", declared_tightenings=len(tightenings))


def check_graph_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条例外必须指向精确规则修订以及适用的技能族、版本、平台和范围。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_exception_targets=0)
    targets = rows_of(document, "exception_targets", "graph-links")
    required_scopes = {"family", "version", "platform", "range"}
    violations = []
    for index, row in enumerate(targets):
        scopes = row.get("scopes")
        scope_ok = isinstance(scopes, list) and required_scopes.issubset(set(scopes))
        if (
            not (isinstance(row.get("rule_id"), str) and row["rule_id"])
            or not is_hex64(row.get("revision_digest"))
            or not scope_ok
        ):
            violations.append({"index": index, "exception_id": row.get("exception_id")})
    if violations:
        return result("FAIL", exceptions_not_bound_to_exact_rule=violations)
    return result("PASS", declared_exception_targets=len(targets))


def check_graph_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """入口、技能、检查器等必须连接与其职责最近的权威制品，不得全挂技能族根。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_attachments=0)
    attachments = rows_of(document, "attachments", "graph-links")
    violations = [
        {"index": index, "unit_id": row.get("unit_id")}
        for index, row in enumerate(attachments)
        if row.get("attached_to_nearest_authority") is not True
        or row.get("dumped_at_family_root") is True
    ]
    if violations:
        return result("FAIL", attachments_not_nearest_authority=violations)
    return result("PASS", declared_attachments=len(attachments))


def check_graph_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族根不得罗列项目内全部物理文件。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_root_inventory=False)
    if document.get("family_root_lists_all_files") is True:
        return result("FAIL", reason="family_root_is_physical_file_inventory")
    return result("PASS", family_root_lists_all_files=False)


def check_graph_025(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则或发布政策必须声明例外批准主体、委托链、适用范围、发布影响和职责分离。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return result("PASS", declared_exception_approval_policy=False)
    policy = document.get("exception_approval_policy")
    if policy is None:
        return result("PASS", declared_exception_approval_policy=False)
    policy = _require_dict(policy, "graph-links", "exception_approval_policy")
    missing = [
        field
        for field in ("approver", "delegation_chain", "scope", "release_impact")
        if not policy.get(field)
    ]
    if missing or policy.get("separation_of_duties") is not True:
        return result(
            "FAIL",
            reason="exception_approval_policy_boundary_incomplete",
            missing=missing,
            separation_of_duties=policy.get("separation_of_duties"),
        )
    return result("PASS", exception_approval_policy_declared=True)


# ---------------------------------------------------------------------------
# GRAPH 状态轴（status-axes）：GRAPH-011 ~ GRAPH-018
# ---------------------------------------------------------------------------


def _axis_check(ctx: dict[str, Any], axis_key: str) -> dict[str, Any]:
    document = _doc(ctx, "status-axes")
    if document is None:
        return result("PASS", declared_axis=False, axis=axis_key)
    vocabulary = STATUS_AXES[axis_key][1]
    values = document.get(axis_key)
    if values is None:
        return result("PASS", declared_axis=False, axis=axis_key)
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"status-axes.{axis_key} 必须是字符串数组"
        )
    out_of_vocabulary = sorted({value for value in values if value not in vocabulary})
    if out_of_vocabulary:
        return result(
            "FAIL",
            axis=axis_key,
            out_of_vocabulary=out_of_vocabulary,
            vocabulary=sorted(vocabulary),
        )
    return result("PASS", axis=axis_key, recorded=len(values))


def check_graph_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """通用制品审阅状态轴限定为草拟/已接受/已取代/已废弃。"""
    return _axis_check(ctx, "artifact_review")


def check_graph_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族成熟度状态轴限定为实验/孵化/稳定/已废弃。"""
    return _axis_check(ctx, "family_maturity")


def check_graph_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """能力与方法支持状态轴限定为规划中/受支持/实验/已废弃。"""
    return _axis_check(ctx, "capability_support")


def check_graph_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范规则生命周期状态轴限定为草拟/实验/已生效/已取代/已废弃。"""
    return _axis_check(ctx, "rule_lifecycle")


def check_graph_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """评估结论状态轴限定为未运行/通过/失败/受阻/例外条件下通过/不适用。"""
    return _axis_check(ctx, "evaluation_conclusion")


def check_graph_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """发布生命周期状态轴限定为计划/候选/已发布/已撤回。

    本条以 ``release-graph`` 中实际发布记录为证据面（较 status-axes 更贴近发布事实）。
    """
    document = _doc(ctx, "release-graph")
    if document is None:
        return result("PASS", declared_releases=0)
    releases = rows_of(document, "releases", "release-graph")
    violations = [
        {"index": index, "release_id": row.get("release_id"), "status": row.get("status")}
        for index, row in enumerate(releases)
        if row.get("status") not in RELEASE_STATUS_VOCABULARY
    ]
    if violations:
        return result("FAIL", release_status_out_of_axis=violations, axis=sorted(RELEASE_STATUS_VOCABULARY))
    return result("PASS", declared_releases=len(releases))


def check_graph_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台支持状态轴限定为受支持/实验/暂缺/已废弃。"""
    return _axis_check(ctx, "platform_support")


def check_graph_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则例外生命周期状态轴限定为待批准/有效/已到期/已撤销/已完成整改。"""
    return _axis_check(ctx, "exception_lifecycle")


# ---------------------------------------------------------------------------
# GRAPH 发布不可变与追加式（release-graph）
# ---------------------------------------------------------------------------


def _releases(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "release-graph")
    if document is None:
        return None
    return rows_of(document, "releases", "release-graph")


def check_graph_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能发布必须指向技能族版本、能力与方法修订、四平台包、运行时摘要、有效评估和采用的规范发布。"""
    releases = _releases(ctx)
    if releases is None:
        return result("PASS", declared_releases=0)
    violations = []
    for index, row in enumerate(releases):
        if row.get("kind") != "skill":
            continue
        members = row.get("members")
        present = (
            {member.get("member") for member in members if isinstance(member, dict)}
            if isinstance(members, list)
            else set()
        )
        if not SKILL_RELEASE_REQUIRED_MEMBERS.issubset(present):
            violations.append(
                {"index": index, "release_id": row.get("release_id"),
                 "missing": sorted(SKILL_RELEASE_REQUIRED_MEMBERS - present)}
            )
    if violations:
        return result("FAIL", skill_releases_incomplete_composition=violations)
    return result("PASS", declared_releases=len(releases))


def check_graph_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """已发布规范和技能发布的组成与摘要不可修改。"""
    releases = _releases(ctx)
    if releases is None:
        return result("PASS", declared_releases=0)
    violations = [
        {"index": index, "release_id": row.get("release_id")}
        for index, row in enumerate(releases)
        if row.get("status") == "published" and row.get("composition_locked") is not True
    ]
    if violations:
        return result("FAIL", published_composition_not_locked=violations)
    return result("PASS", declared_releases=len(releases))


def check_graph_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """撤回只能追加可用性变化和撤回证据，不得覆盖原始发布组成、摘要或历史验证。"""
    releases = _releases(ctx)
    if releases is None:
        return result("PASS", declared_releases=0)
    violations = []
    for index, row in enumerate(releases):
        if row.get("status") != "withdrawn":
            continue
        withdrawal = row.get("withdrawal")
        if (
            not isinstance(withdrawal, dict)
            or withdrawal.get("appends_only") is not True
            or withdrawal.get("preserves_composition") is not True
        ):
            violations.append({"index": index, "release_id": row.get("release_id")})
    if violations:
        return result("FAIL", withdrawal_overrides_composition=violations)
    return result("PASS", declared_releases=len(releases))


def check_graph_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """发布与例外的状态变化必须通过追加新事实表达，不得原地改写历史事实。"""
    releases = _releases(ctx)
    if releases is None:
        return result("PASS", declared_releases=0)
    violations = [
        {"index": index, "release_id": row.get("release_id")}
        for index, row in enumerate(releases)
        if row.get("history_rewritten") is True
    ]
    if violations:
        return result("FAIL", history_rewritten_in_place=violations)
    return result("PASS", declared_releases=len(releases))


def check_graph_040(ctx: dict[str, Any]) -> dict[str, Any]:
    """契约、实现、规则或例外变化只影响新候选与后续发布，不得修改已发布历史事实。"""
    releases = _releases(ctx)
    if releases is None:
        return result("PASS", declared_releases=0)
    violations = [
        {"index": index, "release_id": row.get("release_id")}
        for index, row in enumerate(releases)
        if row.get("status") == "published"
        and (row.get("history_rewritten") is True or not is_hex64(row.get("composition_digest")))
    ]
    if violations:
        return result("FAIL", published_history_modified=violations)
    return result("PASS", declared_releases=len(releases))


# ---------------------------------------------------------------------------
# GRAPH 状态事实与归并（state-facts）
# ---------------------------------------------------------------------------


def check_graph_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条状态事实必须记录事件类型、对象身份、前序摘要、幂等键、可信时间、签署主体、权限依据和归并器版本。"""
    document = _doc(ctx, "state-facts")
    if document is None:
        return result("PASS", declared_state_facts=0)
    facts = rows_of(document, "facts", "state-facts")
    violations = []
    for index, row in enumerate(facts):
        missing = [field for field in STATE_FACT_REQUIRED_FIELDS if not row.get(field)]
        if missing:
            violations.append({"index": index, "object_id": row.get("object_id"), "missing": missing})
    if violations:
        return result("FAIL", state_facts_missing_contract_fields=violations)
    return result("PASS", declared_state_facts=len(facts))


def check_graph_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """状态归并算法必须定义合法转换和确定性排序规则（相同事实集合得到相同当前状态）。"""
    document = _doc(ctx, "state-facts")
    if document is None:
        return result("PASS", declared_merge_policy=False)
    policy = _require_dict(document.get("merge_policy"), "state-facts", "merge_policy")
    if policy.get("legal_transitions_defined") is not True or policy.get("deterministic_ordering_defined") is not True:
        return result("FAIL", reason="merge_policy_not_deterministic")
    return result("PASS", merge_policy_defined=True)


def check_graph_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """同一前序存在两个有效后继且无法依权威顺序确定先后时，状态归并必须受阻。"""
    document = _doc(ctx, "state-facts")
    if document is None:
        return result("PASS", declared_successor_conflicts=0)
    conflicts = rows_of(document, "successor_conflicts", "state-facts")
    violations = [
        {"index": index, "predecessor": row.get("predecessor")}
        for index, row in enumerate(conflicts)
        if row.get("orderable") is False and row.get("blocked") is not True
    ]
    if violations:
        return result("FAIL", unorderable_successors_not_blocked=violations)
    return result("PASS", declared_successor_conflicts=len(conflicts))


# ---------------------------------------------------------------------------
# GRAPH 七类锁与摘要（governance-locks）：GRAPH-028 ~ GRAPH-035
# ---------------------------------------------------------------------------


def _lock_check(ctx: dict[str, Any], lock_key: str, extra_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    document = _doc(ctx, "governance-locks")
    if document is None:
        return result("PASS", declared_lock=False, lock=lock_key)
    lock = document.get(lock_key)
    if lock is None:
        return result("PASS", declared_lock=False, lock=lock_key)
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"governance-locks.{lock_key} 必须是对象"
        )
    if lock.get("locked") is not True or not is_hex64(lock.get("content_digest")):
        return result("FAIL", lock=lock_key, reason="lock_not_sealed")
    missing = [field for field in extra_fields if not lock.get(field)]
    if missing:
        return result("FAIL", lock=lock_key, reason="lock_missing_fields", missing=missing)
    return result("PASS", lock=lock_key, sealed=True)


def check_graph_028(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目必须锁定采用的每个领域图规范版本和内容摘要。"""
    return _lock_check(ctx, "domain_spec_selection", extra_fields=("version",))


def check_graph_029(ctx: dict[str, Any]) -> dict[str, Any]:
    """制品关系新鲜度锁必须证明权威制品与实现、检查、测试的追溯仍与当前内容一致。"""
    document = _doc(ctx, "governance-locks")
    if document is None:
        return result("PASS", declared_lock=False, lock="relation_freshness")
    lock = document.get("relation_freshness")
    if lock is None:
        return result("PASS", declared_lock=False, lock="relation_freshness")
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "governance-locks.relation_freshness 必须是对象"
        )
    if lock.get("locked") is not True or not is_hex64(lock.get("content_digest")) or lock.get("fresh") is not True:
        return result("FAIL", lock="relation_freshness", reason="freshness_lock_stale_or_unsealed")
    return result("PASS", lock="relation_freshness", fresh=True)


def check_graph_030(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族或目标项目必须锁定实际采用的技能族规范发布身份和内容摘要。"""
    return _lock_check(ctx, "spec_adoption", extra_fields=("release_id",))


def check_graph_031(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次严格方法执行必须锁定实际解析的方法提供方、方法修订和实现提供物。"""
    return _lock_check(ctx, "method_run", extra_fields=("provider", "revision"))


def check_graph_032(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能发布摘要必须锁定四平台发行物、运行时、方法契约和其他实际发布字节。"""
    document = _doc(ctx, "governance-locks")
    if document is None:
        return result("PASS", declared_lock=False, lock="skill_release_summary")
    lock = document.get("skill_release_summary")
    if lock is None:
        return result("PASS", declared_lock=False, lock="skill_release_summary")
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "governance-locks.skill_release_summary 必须是对象"
        )
    if lock.get("locked") is not True or not is_hex64(lock.get("content_digest")):
        return result("FAIL", lock="skill_release_summary", reason="summary_not_sealed")
    platforms = lock.get("platforms_locked")
    if not isinstance(platforms, list) or len(platforms) != 4 or len(set(platforms)) != 4:
        return result("FAIL", lock="skill_release_summary", reason="platforms_not_fully_locked")
    return result("PASS", lock="skill_release_summary", platforms_locked=platforms)


def check_graph_033(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范发布摘要必须锁定实际包含的精确规则修订集合。"""
    document = _doc(ctx, "governance-locks")
    if document is None:
        return result("PASS", declared_lock=False, lock="spec_release_summary")
    lock = document.get("spec_release_summary")
    if lock is None:
        return result("PASS", declared_lock=False, lock="spec_release_summary")
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "governance-locks.spec_release_summary 必须是对象"
        )
    if lock.get("locked") is not True or not is_hex64(lock.get("content_digest")):
        return result("FAIL", lock="spec_release_summary", reason="summary_not_sealed")
    rule_revisions = lock.get("rule_revisions_locked")
    if (
        not isinstance(rule_revisions, list)
        or not rule_revisions
        or not all(is_hex64(item) for item in rule_revisions)
    ):
        return result("FAIL", lock="spec_release_summary", reason="rule_revisions_not_locked")
    return result("PASS", lock="spec_release_summary", rule_revisions_locked=len(rule_revisions))


def check_graph_034(ctx: dict[str, Any]) -> dict[str, Any]:
    """评估环境摘要必须锁定平台、模型、运行器、夹具、输入和目标实现。"""
    return _lock_check(
        ctx, "eval_env_summary",
        extra_fields=("platform", "model", "runner", "fixtures", "inputs", "target_implementation"),
    )


def check_graph_035(ctx: dict[str, Any]) -> dict[str, Any]:
    """七类锁和摘要必须分别验证，不得用其中一个替代另一个。"""
    document = _doc(ctx, "governance-locks")
    if document is None:
        return result("PASS", declared_locks=0)
    missing_or_shared = []
    seen_digests: dict[str, str] = {}
    for lock_key in LOCK_AXES:
        lock = document.get(lock_key)
        if not isinstance(lock, dict) or lock.get("locked") is not True or not is_hex64(lock.get("content_digest")):
            missing_or_shared.append({"lock": lock_key, "reason": "not_independently_sealed"})
            continue
        digest = lock["content_digest"]
        if digest in seen_digests:
            missing_or_shared.append(
                {"lock": lock_key, "reason": "digest_substitutes", "substitutes": seen_digests[digest]}
            )
        else:
            seen_digests[digest] = lock_key
    if missing_or_shared:
        return result("FAIL", locks_not_independent=missing_or_shared)
    return result("PASS", declared_locks=len(LOCK_AXES))


# ---------------------------------------------------------------------------
# GRAPH 失效与到期（invalidation-ledger）
# ---------------------------------------------------------------------------


def check_graph_036(ctx: dict[str, Any]) -> dict[str, Any]:
    """业务能力或方法契约变化后，引用旧契约摘要的评估和候选发布必须失效并重新验证。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return result("PASS", declared_contract_changes=0)
    changes = rows_of(document, "contract_changes", "invalidation-ledger")
    violations = [
        {"index": index, "change_id": row.get("change_id")}
        for index, row in enumerate(changes)
        if row.get("dependents_invalidated") is not True or row.get("revalidated") is not True
    ]
    if violations:
        return result("FAIL", stale_dependents_not_invalidated=violations)
    return result("PASS", declared_contract_changes=len(changes))


def check_graph_037(ctx: dict[str, Any]) -> dict[str, Any]:
    """内部技能、平台投影或运行时代码变化后，相关关系新鲜度锁必须标记陈旧并触发复验。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return result("PASS", declared_implementation_changes=0)
    changes = rows_of(document, "implementation_changes", "invalidation-ledger")
    violations = [
        {"index": index, "change_id": row.get("change_id")}
        for index, row in enumerate(changes)
        if row.get("affected_locks_marked_stale") is not True or row.get("reverified") is not True
    ]
    if violations:
        return result("FAIL", relation_locks_not_marked_stale=violations)
    return result("PASS", declared_implementation_changes=len(changes))


def check_graph_038(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则修订必须形成新规范发布；仍锁定旧规范发布的项目不得被静默改用新规则重判。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return result("PASS", declared_rule_changes=0)
    changes = rows_of(document, "rule_changes", "invalidation-ledger")
    violations = [
        {"index": index, "change_id": row.get("change_id")}
        for index, row in enumerate(changes)
        if not (isinstance(row.get("new_spec_release_id"), str) and row["new_spec_release_id"])
        or row.get("old_locked_projects_rerated_silently") is True
    ]
    if violations:
        return result("FAIL", old_locked_projects_silently_rerated=violations)
    return result("PASS", declared_rule_changes=len(changes))


def check_graph_039(ctx: dict[str, Any]) -> dict[str, Any]:
    """例外到期、撤销或失效后，采用检查必须重新报告原强制规则违规。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return result("PASS", declared_exception_expiries=0)
    expiries = rows_of(document, "exception_expiries", "invalidation-ledger")
    violations = [
        {"index": index, "exception_id": row.get("exception_id")}
        for index, row in enumerate(expiries)
        if row.get("expired") is True and row.get("original_violation_rereported") is not True
    ]
    if violations:
        return result("FAIL", expired_exceptions_not_rereported=violations)
    return result("PASS", declared_exception_expiries=len(expiries))


# ---------------------------------------------------------------------------
# NONWAIVE：不可豁免映射（release-policy）
# ---------------------------------------------------------------------------


def check_nonwaive_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """release_policy 中每项不可豁免边界必须列出精确规则身份、修订和内容摘要。"""
    document = _doc(ctx, "release-policy")
    if document is None:
        return result("PASS", declared_boundaries=0)
    policy = _require_dict(document.get("release_policy"), "release-policy", "release_policy")
    boundaries = rows_of(policy, "non_waivable_boundaries", "release-policy.non_waivable_boundaries")
    if not boundaries:
        return result("FAIL", reason="non_waivable_boundaries_empty")
    violations = []
    for index, row in enumerate(boundaries):
        revision = row.get("revision")
        if (
            not (isinstance(row.get("rule_id"), str) and row["rule_id"])
            or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1
            or not is_hex64(row.get("revision_digest"))
            or not is_hex64(row.get("content_digest"))
        ):
            violations.append({"index": index, "policy_name": row.get("policy_name")})
    if violations:
        return result("FAIL", boundaries_without_exact_rule_mapping=violations)
    return result("PASS", declared_boundaries=len(boundaries))


def check_nonwaive_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """不可豁免映射变化必须发布新的发布政策修订并重新批准，不得静默改变。"""
    document = _doc(ctx, "release-policy")
    if document is None:
        return result("PASS", declared_release_policy=False)
    policy = _require_dict(document.get("release_policy"), "release-policy", "release_policy")
    revision = policy.get("revision")
    if (
        not isinstance(revision, int) or isinstance(revision, bool) or revision < 1
        or policy.get("approved") is not True
        or policy.get("changes_require_new_revision") is not True
    ):
        return result("FAIL", reason="non_waivable_mapping_change_not_reapproved")
    return result("PASS", policy_revision=revision)


# ---------------------------------------------------------------------------
# RULE / RULEID：规则定义与身份（rule-definitions）
# ---------------------------------------------------------------------------


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


def check_rule_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则效力、权威来源、适用条件、违规影响和例外必须分别记录，不得混入一个等级字段。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    required_axes = ("effect", "authority_source", "applicability_conditions", "violation_impact", "exception_policy")
    violations = _rule_field_violations(
        rules,
        lambda row: all(row.get(axis) is not None for axis in required_axes) and "level" not in row,
        "governance_axes_not_orthogonal",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则效力必须明确为强制、推荐或实验之一。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules, lambda row: row.get("effect") in EFFECT_VOCABULARY, "effect_out_of_vocabulary"
    )
    if violations:
        return result("FAIL", violations=violations, vocabulary=sorted(EFFECT_VOCABULARY))
    return result("PASS", declared_rules=len(rules))


def check_rule_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则权威来源必须区分通用规范、技能开发领域规范、平台附加规则和项目加严规则。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("authority_source") in AUTHORITY_SOURCE_VOCABULARY,
        "authority_source_out_of_vocabulary",
    )
    if violations:
        return result("FAIL", violations=violations, vocabulary=sorted(AUTHORITY_SOURCE_VOCABULARY))
    return result("PASS", declared_rules=len(rules))


def check_rule_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则必须独立声明受约束对象、平台、成熟度、发布阶段和其他条件表达。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    required_conditions = ("subject", "platform", "maturity", "release_stage")

    def independent(row: dict[str, Any]) -> bool:
        conditions = row.get("applicability_conditions")
        return (
            isinstance(conditions, dict)
            and all(isinstance(conditions.get(key), str) and conditions[key] for key in required_conditions)
        )

    violations = _rule_field_violations(rules, independent, "applicability_conditions_not_independent")
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则例外必须通过独立批准记录声明，不得修改原规则正文。"""
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return result("PASS", declared_exception_records=0)
    records = rows_of(document, "exception_records", "rule-definitions.exception_records")
    violations = []
    for index, row in enumerate(records):
        if (
            not (isinstance(row.get("rule_id"), str) and row["rule_id"])
            or not row.get("approver")
            or not row.get("expiry_condition")
            or row.get("modifies_rule_body") is True
        ):
            violations.append({"index": index, "rule_id": row.get("rule_id")})
    if violations:
        return result("FAIL", exception_records_not_independent=violations)
    return result("PASS", declared_exception_records=len(records))


def check_rule_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """有效例外只能形成"在已批准例外条件下通过"的结论，不得报告无条件完整符合。"""
    document = _doc(ctx, "findings-registry")
    if document is None:
        return result("PASS", declared_findings=0)
    findings = rows_of(document, "findings", "findings-registry")
    violations = [
        {"index": index, "finding_id": row.get("finding_id")}
        for index, row in enumerate(findings)
        if row.get("has_active_exception") is True and row.get("verdict") != "conditional_pass"
    ]
    if violations:
        return result("FAIL", exception_findings_reported_unconditional=violations)
    return result("PASS", declared_findings=len(findings))


def check_rule_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须具有稳定规则身份、中文名称、所属专题和权威来源。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: all(
            isinstance(row.get(field), str) and row[field]
            for field in ("rule_id", "name", "topic", "authority_source")
        ),
        "stable_identity_metadata_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须说明它要防止的失败或要建立的可验证保证（结构字段齐备）。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("purpose"), str) and row["purpose"].strip(),
        "purpose_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须说明受约束对象以及何时适用（结构字段齐备）。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: all(isinstance(row.get(field), str) and row[field].strip() for field in ("subject", "trigger")),
        "subject_or_trigger_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须分别声明规则效力和违规影响。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("effect") in EFFECT_VOCABULARY
        and row.get("violation_impact") in VIOLATION_IMPACT_VOCABULARY,
        "effect_or_violation_impact_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须给出可通过证据判断符合/不符合/不适用的预期状态（结构字段齐备）。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("expected_state"), str) and row["expected_state"].strip(),
        "expected_state_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须引用可定位的来源、修订和证据位置。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("source_refs"), list)
        and row["source_refs"]
        and all(isinstance(ref, str) and ref for ref in row["source_refs"]),
        "locatable_source_refs_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则至少必须声明一种检查方式。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)

    def declared(row: dict[str, Any]) -> bool:
        methods = row.get("check_methods")
        return (
            isinstance(methods, list)
            and bool(methods)
            and all(method in CHECK_METHOD_VOCABULARY for method in methods)
        )

    violations = _rule_field_violations(rules, declared, "check_methods_missing_or_invalid")
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须声明旧版本兼容方式以及是否允许、由谁允许何种例外。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("compat_policy"), str) and row["compat_policy"]
        and isinstance(row.get("exception_policy"), str) and row["exception_policy"],
        "compat_or_exception_policy_missing",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须声明生命周期状态。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("lifecycle") in RULE_LIFECYCLE_VOCABULARY,
        "lifecycle_missing_or_invalid",
    )
    if violations:
        return result("FAIL", violations=violations, vocabulary=sorted(RULE_LIFECYCLE_VOCABULARY))
    return result("PASS", declared_rules=len(rules))


def check_rule_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有适用条件、证据、检查方式、违规影响和整改复验均明确后，规则才可成为正式强制规则。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)

    def admission(row: dict[str, Any]) -> bool:
        if row.get("effect") != "mandatory":
            return True
        return (
            isinstance(row.get("applicability_conditions"), dict)
            and isinstance(row.get("check_methods"), list) and bool(row.get("check_methods"))
            and row.get("violation_impact") in VIOLATION_IMPACT_VOCABULARY
            and isinstance(row.get("expected_state"), str) and bool(row.get("expected_state"))
        )

    violations = _rule_field_violations(rules, admission, "mandatory_admission_incomplete")
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """暂时无法稳定验证的判断不得直接作为强制门禁（强制规则必须含可稳定验证的机械检查方式）。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    mechanical = {"static_scan", "schema_validation", "digest_verification", "relation", "runtime_observation"}

    def stable(row: dict[str, Any]) -> bool:
        if row.get("effect") != "mandatory":
            return True
        methods = row.get("check_methods")
        return isinstance(methods, list) and any(method in mechanical for method in methods)

    violations = _rule_field_violations(rules, stable, "mandatory_without_stable_verification")
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_rule_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则权威定义必须独立于检查技能和检查程序。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("definition_independent_of_checker") is True,
        "definition_embedded_in_checker_only",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def _version_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return None
    policy = document.get("version_policy")
    if policy is None:
        return {}
    return _require_dict(policy, "rule-definitions", "version_policy")


def _version_policy_check(ctx: dict[str, Any], field: str, reason: str) -> dict[str, Any]:
    policy = _version_policy(ctx)
    if policy is None:
        return result("PASS", declared_version_policy=False)
    if policy.get(field) is not True:
        return result("FAIL", reason=reason, field=field)
    return result("PASS", field=field)


def check_rule_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """改变符合结论（新增强制规则、扩大强制范围、提高门禁、改变核心契约）必须发布新主版本。"""
    return _version_policy_check(ctx, "conclusion_change_bumps_major", "conclusion_change_without_major_version")


def check_rule_025(ctx: dict[str, Any]) -> dict[str, Any]:
    """新增推荐/实验规则或向后兼容的可选能力必须升级次版本。"""
    return _version_policy_check(ctx, "compatible_optional_bumps_minor", "compatible_change_without_minor_version")


def check_rule_026(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有不改变规则语义和符合结论的修复才能只升级修订版本。"""
    return _version_policy_check(ctx, "nonsemantic_fix_bumps_revision", "nonsemantic_fix_not_revision_only")


def check_rule_027(ctx: dict[str, Any]) -> dict[str, Any]:
    """普通新规则默认先经实验和推荐阶段，满足强制准入后才能在下一主版本成为强制规则。"""
    return _version_policy_check(ctx, "normal_evolution_staged", "normal_rule_not_staged")


def check_rule_028(ctx: dict[str, Any]) -> dict[str, Any]:
    """紧急安全规则可以加速评审，但仍必须发布新主版本和安全公告。"""
    return _version_policy_check(ctx, "emergency_security_explicit_major", "emergency_security_silent_revision")


def check_rule_029(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查结果必须区分对当前锁定规范版本的符合结论和对目标新版本的升级准备结论。"""
    return _version_policy_check(
        ctx, "current_conformance_separate_from_upgrade_readiness", "conclusion_not_separated"
    )


def check_rule_030(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则废弃或被取代后必须保留原定义、替代规则、迁移期限和旧报告解释所需的历史谱系。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)

    def retained(row: dict[str, Any]) -> bool:
        if row.get("lifecycle") not in {"deprecated", "superseded"}:
            return True
        lineage = row.get("historical_lineage")
        return (
            isinstance(lineage, dict)
            and bool(lineage.get("original_definition"))
            and bool(lineage.get("successor_or_migration"))
        )

    violations = _rule_field_violations(rules, retained, "deprecated_history_not_retained")
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def _scope_claims(ctx: dict[str, Any]) -> dict[str, Any] | None:
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return None
    claims = document.get("scope_claims")
    if claims is None:
        return {}
    return _require_dict(claims, "rule-definitions", "scope_claims")


def _scope_claim_check(ctx: dict[str, Any], field: str, expected: Any, reason: str) -> dict[str, Any]:
    claims = _scope_claims(ctx)
    if claims is None:
        return result("PASS", declared_scope_claims=False)
    if claims.get(field) != expected:
        return result("FAIL", reason=reason, field=field, expected=expected, actual=claims.get(field))
    return result("PASS", field=field)


def check_rule_031(ctx: dict[str, Any]) -> dict[str, Any]:
    """对单个独立技能只检查轻量基础项。"""
    return _scope_claim_check(ctx, "single_skill_check_depth", "lightweight", "single_skill_over_checked")


def check_rule_032(ctx: dict[str, Any]) -> dict[str, Any]:
    """单个独立技能不得被强制补齐技能族固定入口、严格方法和四平台发行物。"""
    return _scope_claim_check(ctx, "single_skill_forced_full_family", False, "single_skill_forced_full_family")


def check_rule_033(ctx: dict[str, Any]) -> dict[str, Any]:
    """仅完成单技能轻量检查不得报告技能族完整符合。"""
    return _scope_claim_check(
        ctx, "single_skill_reports_full_family_conformance", False, "single_skill_reports_full_family"
    )


def check_rule_034(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族源码工程和发行工程必须接受完整的技能族符合性检查。"""
    return _scope_claim_check(ctx, "family_source_check_depth", "complete", "family_source_under_checked")


def check_rule_035(ctx: dict[str, Any]) -> dict[str, Any]:
    """工程已具备技能族事实时必须报告为技能族候选，不得以缺少自我声明规避检查。"""
    return _scope_claim_check(
        ctx, "de_facto_family_candidates_reported", True, "de_facto_family_candidates_evade_check"
    )


def check_rule_036(ctx: dict[str, Any]) -> dict[str, Any]:
    """使用某技能族的目标项目只检查采用相关事项。"""
    return _scope_claim_check(ctx, "target_project_check_scope", "adoption", "target_project_over_scoped")


def check_rule_037(ctx: dict[str, Any]) -> dict[str, Any]:
    """目标项目不得因采用技能族而承担该技能族的源码结构和联合发布责任。"""
    return _scope_claim_check(
        ctx, "target_project_bears_source_release", False, "target_project_bears_source_release"
    )


def check_rule_038(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有发行包而无源码时，只检查发行物相关的有限范围。"""
    return _scope_claim_check(
        ctx, "release_artifact_no_source_scope", "limited", "release_artifact_over_scoped"
    )


def check_rule_039(ctx: dict[str, Any]) -> dict[str, Any]:
    """无源码时不得声称源码结构、源码规则实现或源码测试已经通过。"""
    return _scope_claim_check(
        ctx, "release_artifact_claims_source_pass", False, "release_artifact_impersonates_source_check"
    )


# ---------------------------------------------------------------------------
# RULEID：规则逻辑身份（rule-definitions）
# ---------------------------------------------------------------------------


def check_ruleid_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式规则逻辑身份必须由权威命名空间、所属专题和稳定语义名称三部分组成。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: all(
            isinstance(row.get(field), str) and row[field]
            for field in ("namespace", "topic", "semantic_name")
        ),
        "identity_not_three_part",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_ruleid_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则效力、违规影响、版本、修订、生命周期等可变治理字段不得进入规则逻辑身份。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("identity_excludes_mutable_fields") is True,
        "identity_contains_mutable_fields",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_ruleid_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """各权威只能在自身命名空间创建规则身份，不得占用或伪装另一权威的身份。"""
    rules = _rules(ctx)
    if rules is None:
        return result("PASS", declared_rules=0)
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("namespace_owned_by_own_authority") is True,
        "namespace_not_own_authority",
    )
    if violations:
        return result("FAIL", violations=violations)
    return result("PASS", declared_rules=len(rules))


def check_ruleid_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """非语义变化必须保持规则逻辑身份，并通过新修订和内容摘要记录变化。"""
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return result("PASS", declared_identity_continuity=0)
    continuity = rows_of(document, "identity_continuity", "rule-definitions.identity_continuity")
    violations = [
        {"index": index, "rule_id": row.get("rule_id")}
        for index, row in enumerate(continuity)
        if row.get("kept_identity") is not True or not is_hex64(row.get("new_revision_digest"))
    ]
    if violations:
        return result("FAIL", nonsemantic_change_broke_identity=violations)
    return result("PASS", declared_identity_continuity=len(continuity))


def check_ruleid_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """核心语义变化必须创建新规则身份，并声明与旧规则的取代/包含/冲突/迁移关系。"""
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return result("PASS", declared_semantic_changes=0)
    changes = rows_of(document, "semantic_changes", "rule-definitions.semantic_changes")
    violations = [
        {"index": index, "old_rule_id": row.get("old_rule_id")}
        for index, row in enumerate(changes)
        if not (isinstance(row.get("new_rule_id"), str) and row["new_rule_id"])
        or row.get("new_rule_id") == row.get("old_rule_id")
        or row.get("relation_declared") is not True
    ]
    if violations:
        return result("FAIL", semantic_change_kept_identity_silently=violations)
    return result("PASS", declared_semantic_changes=len(changes))


# ---------------------------------------------------------------------------
# CHECKIMPL：检查实现绑定（check-implementations）
# ---------------------------------------------------------------------------


def _implementations(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "check-implementations")
    if document is None:
        return None
    return rows_of(document, "implementations", "check-implementations")


def check_checkimpl_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """同一精确规则修订可绑定多个实现；多个实现不得改变规则权威正文，也不得互相覆盖执行证据。"""
    implementations = _implementations(ctx)
    if implementations is None:
        return result("PASS", declared_implementations=0)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    violations = []
    for index, row in enumerate(implementations):
        if row.get("modifies_rule_authority") is True:
            violations.append({"index": index, "rule_id": row.get("rule_id"), "reason": "modifies_rule_authority"})
            continue
        key = (row.get("rule_id"), row.get("revision_digest"))
        groups.setdefault(key, []).append(row)
    for (rule_id, revision_digest), rows in groups.items():
        checker_ids = [row.get("checker_id") for row in rows]
        if len(checker_ids) != len(set(checker_ids)):
            violations.append({"rule_id": rule_id, "revision_digest": revision_digest, "reason": "implementations_override_each_other"})
    if violations:
        return result("FAIL", implementation_binding_violations=violations)
    return result("PASS", declared_implementations=len(implementations), multi_bound_rules=sum(1 for rows in groups.values() if len(rows) > 1))


def check_checkimpl_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个规则实现绑定必须分别记录检查器身份、版本、内容摘要、适用平台、检查方式和状态。"""
    implementations = _implementations(ctx)
    if implementations is None:
        return result("PASS", declared_implementations=0)
    violations = []
    for index, row in enumerate(implementations):
        platforms = row.get("platforms")
        ok = (
            isinstance(row.get("checker_id"), str) and row["checker_id"]
            and isinstance(row.get("version"), str) and row["version"]
            and is_hex64(row.get("content_digest"))
            and isinstance(platforms, list) and bool(platforms)
            and isinstance(row.get("check_method"), str) and row["check_method"]
            and row.get("status") in IMPL_STATUS_VOCABULARY
        )
        if not ok:
            violations.append({"index": index, "checker_id": row.get("checker_id")})
    if violations:
        return result("FAIL", implementation_bindings_incomplete=violations)
    return result("PASS", declared_implementations=len(implementations))


# ---------------------------------------------------------------------------
# FINDING / RULEREL：发现与规则关系
# ---------------------------------------------------------------------------


def _findings(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "findings-registry")
    if document is None:
        return None
    return rows_of(document, "findings", "findings-registry")


def check_finding_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条检查发现必须引用完整规则上下文；缺少任一适用上下文时不得用于正式门禁。"""
    findings = _findings(ctx)
    if findings is None:
        return result("PASS", declared_findings=0)
    required_context = (
        "spec_release_id",
        "spec_release_version",
        "rule_id",
        "rule_revision_digest",
        "rule_content_digest",
        "authority_source",
        "implementation_id",
        "evidence",
    )
    violations = []
    for index, row in enumerate(findings):
        missing = [
            field for field in required_context
            if not row.get(field)
            or (field in ("rule_revision_digest", "rule_content_digest") and not is_hex64(row.get(field)))
        ]
        if missing and row.get("usable_for_gate") is True:
            violations.append({"index": index, "finding_id": row.get("finding_id"), "missing": missing})
    if violations:
        return result("FAIL", findings_used_for_gate_without_context=violations)
    return result("PASS", declared_findings=len(findings))


def check_rulerel_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """同一根因的多条发现可以聚类展示，但必须保留每条原始发现，不能用聚类覆盖。"""
    document = _doc(ctx, "findings-registry")
    if document is None:
        return result("PASS", declared_clusters=0)
    findings = rows_of(document, "findings", "findings-registry")
    clusters = rows_of(document, "clusters", "findings-registry.clusters")
    finding_ids = {row.get("finding_id") for row in findings}
    violations = []
    for index, cluster in enumerate(clusters):
        member_ids = cluster.get("finding_ids")
        if not isinstance(member_ids, list) or not member_ids:
            violations.append({"index": index, "cluster_id": cluster.get("cluster_id"), "reason": "cluster_has_no_members"})
            continue
        missing = [member for member in member_ids if member not in finding_ids]
        if missing:
            violations.append({"index": index, "cluster_id": cluster.get("cluster_id"), "missing_originals": missing})
    if violations:
        return result("FAIL", clusters_drop_original_findings=violations)
    return result("PASS", declared_clusters=len(clusters))


def check_rulerel_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """误报/不适用/重复/已修复是单次发现处置，与正式规则例外必须使用不同状态空间。"""
    findings = _findings(ctx)
    if findings is None:
        return result("PASS", declared_findings=0)
    violations = [
        {"index": index, "finding_id": row.get("finding_id"), "disposition": row.get("disposition")}
        for index, row in enumerate(findings)
        if row.get("disposition") is not None
        and row.get("disposition") not in FINDING_DISPOSITION_VOCABULARY
    ]
    if violations:
        return result("FAIL", disposition_uses_exception_state_space=violations)
    return result("PASS", declared_findings=len(findings))


def check_rulerel_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则语义关系必须绑定两端精确规则修订、方向、适用范围和证明证据。"""
    document = _doc(ctx, "rule-relations")
    if document is None:
        return result("PASS", declared_relations=0)
    relations = rows_of(document, "relations", "rule-relations")
    violations = []
    for index, row in enumerate(relations):
        ok = (
            is_hex64(row.get("from_revision_digest"))
            and is_hex64(row.get("to_revision_digest"))
            and row.get("relation_type") in RELATION_TYPE_VOCABULARY
            and isinstance(row.get("direction"), str) and row["direction"]
            and isinstance(row.get("scope"), str) and row["scope"]
            and bool(row.get("proof"))
            and "stale" in row
        )
        if not ok:
            violations.append({"index": index, "from_rule_id": row.get("from_rule_id")})
    if violations:
        return result("FAIL", relations_not_bound_to_exact_revisions=violations)
    return result("PASS", declared_relations=len(relations))


# ---------------------------------------------------------------------------
# 登记
# ---------------------------------------------------------------------------

CHECKS = {
    "SFA-AUTHORITY-001": check_authority_001,
    "SFA-AUTHORITY-002": check_authority_002,
    "SFA-CHECKIMPL-001": check_checkimpl_001,
    "SFA-CHECKIMPL-002": check_checkimpl_002,
    "SFA-FINDING-001": check_finding_001,
    "SFA-GRAPH-001": check_graph_001,
    "SFA-GRAPH-002": check_graph_002,
    "SFA-GRAPH-003": check_graph_003,
    "SFA-GRAPH-004": check_graph_004,
    "SFA-GRAPH-005": check_graph_005,
    "SFA-GRAPH-006": check_graph_006,
    "SFA-GRAPH-007": check_graph_007,
    "SFA-GRAPH-008": check_graph_008,
    "SFA-GRAPH-009": check_graph_009,
    "SFA-GRAPH-010": check_graph_010,
    "SFA-GRAPH-011": check_graph_011,
    "SFA-GRAPH-012": check_graph_012,
    "SFA-GRAPH-013": check_graph_013,
    "SFA-GRAPH-014": check_graph_014,
    "SFA-GRAPH-015": check_graph_015,
    "SFA-GRAPH-016": check_graph_016,
    "SFA-GRAPH-017": check_graph_017,
    "SFA-GRAPH-018": check_graph_018,
    "SFA-GRAPH-019": check_graph_019,
    "SFA-GRAPH-020": check_graph_020,
    "SFA-GRAPH-021": check_graph_021,
    "SFA-GRAPH-022": check_graph_022,
    "SFA-GRAPH-023": check_graph_023,
    "SFA-GRAPH-024": check_graph_024,
    "SFA-GRAPH-025": check_graph_025,
    "SFA-GRAPH-028": check_graph_028,
    "SFA-GRAPH-029": check_graph_029,
    "SFA-GRAPH-030": check_graph_030,
    "SFA-GRAPH-031": check_graph_031,
    "SFA-GRAPH-032": check_graph_032,
    "SFA-GRAPH-033": check_graph_033,
    "SFA-GRAPH-034": check_graph_034,
    "SFA-GRAPH-035": check_graph_035,
    "SFA-GRAPH-036": check_graph_036,
    "SFA-GRAPH-037": check_graph_037,
    "SFA-GRAPH-038": check_graph_038,
    "SFA-GRAPH-039": check_graph_039,
    "SFA-GRAPH-040": check_graph_040,
    "SFA-NONWAIVE-001": check_nonwaive_001,
    "SFA-NONWAIVE-002": check_nonwaive_002,
    "SFA-RULE-001": check_rule_001,
    "SFA-RULE-002": check_rule_002,
    "SFA-RULE-003": check_rule_003,
    "SFA-RULE-004": check_rule_004,
    "SFA-RULE-006": check_rule_006,
    "SFA-RULE-008": check_rule_008,
    "SFA-RULE-010": check_rule_010,
    "SFA-RULE-011": check_rule_011,
    "SFA-RULE-012": check_rule_012,
    "SFA-RULE-013": check_rule_013,
    "SFA-RULE-014": check_rule_014,
    "SFA-RULE-015": check_rule_015,
    "SFA-RULE-016": check_rule_016,
    "SFA-RULE-018": check_rule_018,
    "SFA-RULE-019": check_rule_019,
    "SFA-RULE-020": check_rule_020,
    "SFA-RULE-021": check_rule_021,
    "SFA-RULE-022": check_rule_022,
    "SFA-RULE-024": check_rule_024,
    "SFA-RULE-025": check_rule_025,
    "SFA-RULE-026": check_rule_026,
    "SFA-RULE-027": check_rule_027,
    "SFA-RULE-028": check_rule_028,
    "SFA-RULE-029": check_rule_029,
    "SFA-RULE-030": check_rule_030,
    "SFA-RULE-031": check_rule_031,
    "SFA-RULE-032": check_rule_032,
    "SFA-RULE-033": check_rule_033,
    "SFA-RULE-034": check_rule_034,
    "SFA-RULE-035": check_rule_035,
    "SFA-RULE-036": check_rule_036,
    "SFA-RULE-037": check_rule_037,
    "SFA-RULE-038": check_rule_038,
    "SFA-RULE-039": check_rule_039,
    "SFA-RULEID-001": check_ruleid_001,
    "SFA-RULEID-002": check_ruleid_002,
    "SFA-RULEID-003": check_ruleid_003,
    "SFA-RULEID-004": check_ruleid_004,
    "SFA-RULEID-005": check_ruleid_005,
    "SFA-RULEREL-001": check_rulerel_001,
    "SFA-RULEREL-002": check_rulerel_002,
    "SFA-RULEREL-003": check_rulerel_003,
}
