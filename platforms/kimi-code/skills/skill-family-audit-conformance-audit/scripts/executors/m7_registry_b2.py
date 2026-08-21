"""M7 执行族：方法注册表与制品方法治理（W2-B2 共 23 条，violation_impact=error）。

本批 23 条全部 methods=(digest_verification, schema_validation)、
behavior_also_required=false、semantic_also_required=false，机械断言即全部义务。
域分布：ARTMETHOD 15 / REGISTRY 5 / TEMPLATE 3。

证据面（约束"已声明者"；缺失 = 无可判违反事实 → PASS；形状非法失败关闭）：

- 本批新增文档 artifact-method-runs（严格方法运行声明：方法运行、正式追溯结果、
  quickstart 路由、契约选择、旧版转换、受阻输入、基础/项目校验、关系证据、
  版本锁一致性、步骤顺序、编写/修复/审阅/转换结果报告）；
- 扩展消费 B1 M7 既有文档 method-registry-projection（协议依赖、投影字段、
  非空业务对象、注册表/制品图职责边界）；
- 本批新增文档 template-overrides（项目模板覆盖、结构定义引用、模板变化复验）。

与 B1 m7_registry（SFA-REGISTRY-002/004/007/010）零交集，互为补集。
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

_STEP_SEQUENCE = (
    "contract_selection",
    "legacy_conversion",
    "base_validation",
    "project_strengthening",
    "relation_evidence",
    "lock_consistency",
)
_RELATION_KINDS = (
    "upstream",
    "downstream",
    "supersedes",
    "implements",
    "evaluates",
    "releases",
)
_REGISTRY_PROJECTION_FIELDS = (
    "method_id",
    "provider",
    "method_kind",
    "digest",
    "matching_domain",
    "business_object_or_artifact_type",
    "intent",
    "receives",
    "produces",
    "side_effects",
)
_REGISTRY_OWNED_DUTIES = (
    "provider_verification",
    "project_overlay",
    "query_resolution",
    "run_locks",
)
_GRAPH_OWNED_DUTIES = (
    "contract_and_capability_traceability",
    "implementation_traceability",
    "evaluation_traceability",
    "release_traceability",
)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _nonempty_str_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_nonempty_str(item) for item in value)


def _artifact_method_runs(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "artifact-method-runs")


def check_artmethod_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """操作正式制品的方法引用精确契约。

    机械断言：每条已声明方法运行必须引用适用制品类型、契约主版本与
    精确内容摘要（64 位十六进制）。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "runs", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if not _nonempty_str(row.get("artifact_type")):
            reasons.append("artifact_type_missing")
        if not _nonempty_str(row.get("contract_major_version")):
            reasons.append("contract_major_version_missing")
        if not is_hex64(row.get("contract_content_digest")):
            reasons.append("contract_content_digest_invalid")
        if reasons:
            violations.append({"run_id": row.get("run_id"), "reasons": reasons})
    if violations:
        return result("FAIL", runs_without_precise_contract=violations)
    return result("PASS", runs_checked=len(rows))


def check_artmethod_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式追溯结果接入制品图。

    机械断言：每条已声明正式结果必须写入权威制品图、记录来源关系并
    刷新关系锁。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "formal_results", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("written_to_authoritative_graph") is not True:
            reasons.append("not_written_to_graph")
        if row.get("source_relations_recorded") is not True:
            reasons.append("source_relations_missing")
        if row.get("relation_lock_refreshed") is not True:
            reasons.append("relation_lock_not_refreshed")
        if reasons:
            violations.append({"result_id": row.get("result_id"), "reasons": reasons})
    if violations:
        return result("FAIL", formal_results_not_in_graph=violations)
    return result("PASS", results_checked=len(rows))


def check_artmethod_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """快速入口不直接拥有制品契约。

    机械断言：每条 quickstart 路由不得登记或重新解释制品契约，被路由的
    严格方法必须承担全部契约与图关系义务。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "quickstart_routes", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("owns_artifact_contract") is True:
            reasons.append("quickstart_owns_contract")
        if row.get("registers_or_reinterprets_contract") is True:
            reasons.append("quickstart_registers_or_reinterprets_contract")
        if not _nonempty_str(row.get("routed_method")):
            reasons.append("routed_method_missing")
        if row.get("routed_method_assumes_contract_obligations") is not True:
            reasons.append("routed_method_obligations_missing")
        if reasons:
            violations.append({"route_id": row.get("route_id"), "reasons": reasons})
    if violations:
        return result("FAIL", quickstart_owning_contracts=violations)
    return result("PASS", routes_checked=len(rows))


def check_artmethod_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """先选择契约主版本和精确内容。

    机械断言：每条契约选择必须依据制品身份/采用锁/兼容政策确定主版本，
    用不可变内容摘要固定内容；不得使用漂移版本名或"最新"。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "contract_selections", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        for field in ("artifact_identity", "adoption_lock_ref", "compatibility_policy_ref"):
            if not _nonempty_str(row.get(field)):
                reasons.append(f"{field}_missing")
        if not _nonempty_str(row.get("contract_major_version")):
            reasons.append("contract_major_version_missing")
        if not is_hex64(row.get("fixed_content_digest")):
            reasons.append("fixed_content_digest_invalid")
        if row.get("uses_drifting_version_name") is True:
            reasons.append("uses_drifting_version_name")
        if row.get("uses_latest") is True:
            reasons.append("uses_latest")
        if reasons:
            violations.append({"selection_id": row.get("selection_id"), "reasons": reasons})
    if violations:
        return result("FAIL", contract_selections_not_fixed=violations)
    return result("PASS", selections_checked=len(rows))


def check_artmethod_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """可兼容旧版无损转换为统一表示。

    机械断言：每条旧版转换必须在字段/语义/身份/关系四轴无损，且记录
    来源版本、转换器与前后摘要。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "legacy_conversions", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        for axis in ("fields", "semantics", "identity", "relations"):
            if row.get(f"lossless_{axis}") is not True:
                reasons.append(f"lossy_{axis}")
        if not _nonempty_str(row.get("source_version")):
            reasons.append("source_version_missing")
        if not _nonempty_str(row.get("converter")):
            reasons.append("converter_missing")
        if not is_hex64(row.get("before_digest")):
            reasons.append("before_digest_invalid")
        if not is_hex64(row.get("after_digest")):
            reasons.append("after_digest_invalid")
        if reasons:
            violations.append({"conversion_id": row.get("conversion_id"), "reasons": reasons})
    if violations:
        return result("FAIL", legacy_conversions_lossy_or_unrecorded=violations)
    return result("PASS", conversions_checked=len(rows))


def check_artmethod_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """无法安全转换时停止且不猜测。

    机械断言：每条不可安全处理输入必须受阻，保留原输入与诊断，不得
    猜测、补造或静默丢弃。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "blocked_inputs", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("blocked") is not True:
            reasons.append("not_blocked")
        if row.get("retains_original_input") is not True:
            reasons.append("original_input_not_retained")
        if row.get("retains_diagnosis") is not True:
            reasons.append("diagnosis_not_retained")
        if row.get("guesses_or_fabricates_or_silently_drops") is True:
            reasons.append("guesses_or_fabricates_or_silently_drops")
        if reasons:
            violations.append({"input_id": row.get("input_id"), "reasons": reasons})
    if violations:
        return result("FAIL", unsafe_inputs_not_blocked=violations)
    return result("PASS", blocked_inputs_checked=len(rows))


def check_artmethod_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """先执行基础制品契约校验。

    机械断言：每条基础校验必须覆盖权威领域规范定义的结构/字段/身份/
    不变量；基础校验未通过不得进入成功结论。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "base_validations", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        for aspect in ("structure", "fields", "identity", "invariants"):
            if row.get(f"validated_{aspect}") is not True:
                reasons.append(f"{aspect}_not_validated")
        if row.get("entered_success_on_base_failure") is True:
            reasons.append("entered_success_on_base_failure")
        if reasons:
            violations.append({"validation_id": row.get("validation_id"), "reasons": reasons})
    if violations:
        return result("FAIL", base_validations_incomplete=violations)
    return result("PASS", validations_checked=len(rows))


def check_artmethod_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """再执行项目单调加严校验。

    机械断言：每条项目加严必须在基础校验通过后执行，覆盖必填/取值/
    关系/质量四类约束，且只单调加严。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "project_strengthenings", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("after_base_validation") is not True:
            reasons.append("not_after_base_validation")
        for constraint in ("required_fields", "values", "relations", "quality"):
            if row.get(f"covers_{constraint}") is not True:
                reasons.append(f"{constraint}_uncovered")
        if row.get("monotonic_strengthening_only") is not True:
            reasons.append("not_monotonic")
        if row.get("loosens_base_rules") is True:
            reasons.append("loosens_base_rules")
        if reasons:
            violations.append({"strengthening_id": row.get("strengthening_id"), "reasons": reasons})
    if violations:
        return result("FAIL", project_strengthenings_invalid=violations)
    return result("PASS", strengthenings_checked=len(rows))


def check_artmethod_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """校验制品关系追溯和证据完整性。

    机械断言：每条关系证据校验必须覆盖六类必需关系，且存在、身份一致、
    仍然新鲜。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "relation_evidence_checks", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        covered: set[str] = set()
        relations = row.get("relations")
        if not isinstance(relations, list) or not all(isinstance(item, dict) for item in relations):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "artifact-method-runs.relation_evidence_checks.relations 必须是对象数组",
            )
        for relation in relations:
            kind = relation.get("kind")
            if kind not in _RELATION_KINDS:
                reasons.append(f"unknown_relation_kind:{kind}")
                continue
            for aspect in ("present", "identity_consistent", "fresh"):
                if relation.get(aspect) is not True:
                    reasons.append(f"{kind}:{aspect}_failed")
            covered.add(kind)
        missing = sorted(set(_RELATION_KINDS) - covered)
        if missing:
            reasons.append(f"relation_kinds_uncovered:{','.join(missing)}")
        if reasons:
            violations.append({"check_id": row.get("check_id"), "reasons": reasons})
    if violations:
        return result("FAIL", relation_evidence_incomplete=violations)
    return result("PASS", checks_checked=len(rows))


def check_artmethod_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """校验制品锁与当前内容一致。

    机械断言：每条锁一致性校验必须核对契约摘要与关系新鲜度锁和当前
    内容一致；锁陈旧/用途错误/被代替时必须受阻。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "lock_consistency_checks", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if not is_hex64(row.get("adopted_contract_digest")):
            reasons.append("adopted_contract_digest_invalid")
        if row.get("matches_current_content") is not True:
            reasons.append("content_mismatch")
        if row.get("relation_freshness_lock_valid") is not True:
            reasons.append("relation_freshness_lock_invalid")
        stale = (
            row.get("lock_stale") is True
            or row.get("lock_misused") is True
            or row.get("lock_supplanted_by_other_lock") is True
        )
        if stale and row.get("blocked") is not True:
            reasons.append("stale_or_misused_lock_not_blocked")
        if reasons:
            violations.append({"check_id": row.get("check_id"), "reasons": reasons})
    if violations:
        return result("FAIL", lock_consistency_broken=violations)
    return result("PASS", checks_checked=len(rows))


def check_artmethod_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """六步校验顺序不得跳跃。

    机械断言：每条步骤序列必须含六步且索引严格递增；后一步通过不得
    覆盖前一步失败或未运行。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "step_sequences", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        steps = row.get("steps")
        if not isinstance(steps, list) or not all(isinstance(item, dict) for item in steps):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "artifact-method-runs.step_sequences.steps 必须是对象数组",
            )
        kinds = [step.get("kind") for step in steps]
        if sorted(kinds) != sorted(_STEP_SEQUENCE):
            reasons.append("steps_incomplete_or_unknown")
        else:
            positions = {step.get("kind"): index for index, step in enumerate(steps)}
            ordered = [positions[kind] for kind in _STEP_SEQUENCE]
            if ordered != sorted(ordered):
                reasons.append("steps_out_of_order")
        for step in steps:
            if step.get("passed") is True and step.get("overrides_preceding_failure_or_not_run") is True:
                reasons.append(f"overrides_preceding:{step.get('kind')}")
        if reasons:
            violations.append({"sequence_id": row.get("sequence_id"), "reasons": reasons})
    if violations:
        return result("FAIL", step_sequences_skipped=violations)
    return result("PASS", sequences_checked=len(rows))


def check_artmethod_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """编写方法通过全部确定性校验后成功。

    机械断言：每条编写结果报告必须声明本次全部正式制品完成有序校验，
    且不存在未验证正式输出。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "author_reports", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("all_outputs_order_validated") is not True:
            reasons.append("outputs_not_all_order_validated")
        if row.get("unvalidated_formal_outputs") is True:
            reasons.append("unvalidated_formal_outputs")
        if row.get("reported_success") is not True:
            reasons.append("success_report_missing")
        if reasons:
            violations.append({"report_id": row.get("report_id"), "reasons": reasons})
    if violations:
        return result("FAIL", author_success_reports_unverified=violations)
    return result("PASS", reports_checked=len(rows))


def check_artmethod_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """修复方法保留原审阅关系并复验。

    机械断言：每条修复结果报告必须完成有序校验、逐项处置发现、保留
    未解决发现可见性，并保持与原审阅结果和修复任务的关系。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "repair_reports", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("revalidated_in_order") is not True:
            reasons.append("not_revalidated_in_order")
        if row.get("findings_disposed_itemwise") is not True:
            reasons.append("findings_not_disposed_itemwise")
        if row.get("unresolved_findings_visible") is not True:
            reasons.append("unresolved_findings_not_visible")
        if not _nonempty_str(row.get("original_review_ref")):
            reasons.append("original_review_ref_missing")
        if not _nonempty_str(row.get("repair_task_ref")):
            reasons.append("repair_task_ref_missing")
        if reasons:
            violations.append({"report_id": row.get("report_id"), "reasons": reasons})
    if violations:
        return result("FAIL", repair_reports_untraceable=violations)
    return result("PASS", reports_checked=len(rows))


def check_artmethod_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """审阅接收不合规输入但不得假通过。

    机械断言：每条审阅报告必须先运行适用确定性校验并把结构/关系问题
    写入标准审阅结果；基础校验失败或必需检查未运行时不得报告通过。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "review_reports", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        if row.get("ran_applicable_deterministic_checks") is not True:
            reasons.append("deterministic_checks_not_ran")
        if row.get("structural_and_relation_issues_in_standard_result") is not True:
            reasons.append("issues_not_in_standard_result")
        if row.get("reported_pass") is True and (
            row.get("base_validation_failed") is True
            or row.get("required_checks_not_run") is True
        ):
            reasons.append("false_pass")
        if reasons:
            violations.append({"report_id": row.get("report_id"), "reasons": reasons})
    if violations:
        return result("FAIL", review_false_passes=violations)
    return result("PASS", reports_checked=len(rows))


def check_artmethod_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """旧版转换只有无损且复验后成功。

    机械断言：每条转换结果报告必须无损、通过当前契约校验、前后来源
    关系完整且转换记录可重建；否则必须受阻而非产出猜测版本。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return result("PASS", artifact_method_runs_declared=False)
    rows = rows_of(document, "conversion_reports", "artifact-method-runs")
    violations = []
    for row in rows:
        reasons = []
        lossless = row.get("lossless") is True
        contract_ok = row.get("current_contract_validation_passed") is True
        lineage_ok = row.get("source_lineage_complete") is True
        reconstructable = row.get("conversion_record_reconstructable") is True
        if row.get("reported_success") is True:
            if not lossless:
                reasons.append("success_despite_lossy")
            if not contract_ok:
                reasons.append("success_despite_contract_failure")
            if not lineage_ok:
                reasons.append("success_despite_lineage_incomplete")
            if not reconstructable:
                reasons.append("success_despite_unreconstructable_record")
        else:
            if row.get("blocked") is not True:
                reasons.append("neither_success_nor_blocked")
            if row.get("produced_guessed_version") is True:
                reasons.append("produced_guessed_version")
        if reasons:
            violations.append({"report_id": row.get("report_id"), "reasons": reasons})
    if violations:
        return result("FAIL", conversion_reports_invalid=violations)
    return result("PASS", reports_checked=len(rows))


def _registry_projection(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "method-registry-projection")


def check_registry_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """只依赖已发布注册协议。

    机械断言：每条协议依赖必须 status=published 且锁定精确版本；
    draft 或未锁定即违反。
    """
    document = _registry_projection(ctx)
    if document is None:
        return result("PASS", registry_declared=False)
    rows = rows_of(document, "protocol_dependencies", "method-registry-projection")
    violations = []
    for row in rows:
        reasons = []
        if row.get("status") != "published":
            reasons.append("not_published")
        if not _nonempty_str(row.get("locked_version")):
            reasons.append("version_not_locked")
        if row.get("draft") is True:
            reasons.append("draft_dependency")
        if reasons:
            violations.append({"protocol": row.get("protocol"), "reasons": reasons})
    if violations:
        return result("FAIL", unpublished_or_unlocked_protocol_dependencies=violations)
    return result("PASS", dependencies_checked=len(rows))


def check_registry_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册投影具有完整匹配字段。

    机械断言：每条注册投影条目必须含稳定方法身份/提供方/方法种类/摘要/
    匹配域/业务对象或制品类型/意图/接收对象/产出对象/粗粒度副作用十项，
    摘要为 64 位十六进制。
    """
    document = _registry_projection(ctx)
    if document is None:
        return result("PASS", registry_declared=False)
    rows = rows_of(document, "entries", "method-registry-projection")
    violations = []
    for row in rows:
        reasons = []
        for field in _REGISTRY_PROJECTION_FIELDS:
            value = row.get(field)
            if field == "digest":
                if not is_hex64(value):
                    reasons.append("digest_invalid")
            elif field == "side_effects":
                if not isinstance(value, list) or not all(_nonempty_str(item) for item in value):
                    reasons.append("side_effects_invalid")
            elif not _nonempty_str(value):
                reasons.append(f"{field}_missing")
        if reasons:
            violations.append({"entry": row.get("method_id"), "reasons": reasons})
    if violations:
        return result("FAIL", projection_fields_incomplete=violations)
    return result("PASS", entries_checked=len(rows))


def check_registry_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册方法遵守非空业务对象要求。

    机械断言：锁定协议要求业务对象或制品类型非空时，每条注册条目必须
    提供非空标签，且有权威契约与实际输入输出证据支持。
    """
    document = _registry_projection(ctx)
    if document is None:
        return result("PASS", registry_declared=False)
    required = document.get("locked_protocol_requires_nonempty_business_object")
    if required is not True:
        return result("PASS", nonempty_business_object_not_required=True)
    rows = rows_of(document, "entries", "method-registry-projection")
    violations = []
    for row in rows:
        reasons = []
        label = row.get("business_object_or_artifact_type")
        if not _nonempty_str(label):
            reasons.append("business_object_empty")
        if row.get("backed_by_authoritative_contract") is not True:
            reasons.append("not_backed_by_authoritative_contract")
        if not _nonempty_str(row.get("input_output_evidence_ref")):
            reasons.append("input_output_evidence_missing")
        if reasons:
            violations.append({"entry": row.get("method_id"), "reasons": reasons})
    if violations:
        return result("FAIL", nonempty_business_object_unsatisfied=violations)
    return result("PASS", entries_checked=len(rows))


def check_registry_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """方法注册表拥有解析运行职责。

    机械断言：注册表职责边界行必须拥有提供方验证/项目叠加/查询解析/
    运行锁四项，且不拥有方法的领域制品关系。
    """
    document = _registry_projection(ctx)
    if document is None:
        return result("PASS", registry_declared=False)
    rows = rows_of(document, "responsibility_boundaries", "method-registry-projection")
    registry_rows = [row for row in rows if row.get("owner") == "agent-method-registry"]
    if not registry_rows:
        return result("FAIL", reason="agent-method-registry_boundary_missing")
    violations = []
    for row in registry_rows:
        reasons = []
        for duty in _REGISTRY_OWNED_DUTIES:
            if row.get(f"owns_{duty}") is not True:
                reasons.append(f"duty_missing:{duty}")
        if row.get("owns_method_domain_artifact_relations") is True:
            reasons.append("owns_domain_artifact_relations")
        if reasons:
            violations.append({"owner": row.get("owner"), "reasons": reasons})
    if violations:
        return result("FAIL", registry_responsibilities_invalid=violations)
    return result("PASS", boundaries_checked=len(registry_rows))


def check_registry_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能制品图拥有方法追溯职责。

    机械断言：制品图职责边界行必须拥有契约与能力/内部实现/评估/发布
    四项追溯，且不负责任解析本次方法提供方。
    """
    document = _registry_projection(ctx)
    if document is None:
        return result("PASS", registry_declared=False)
    rows = rows_of(document, "responsibility_boundaries", "method-registry-projection")
    graph_rows = [row for row in rows if row.get("owner") == "skill-artifact-graph"]
    if not graph_rows:
        return result("FAIL", reason="skill-artifact-graph_boundary_missing")
    violations = []
    for row in graph_rows:
        reasons = []
        for duty in _GRAPH_OWNED_DUTIES:
            if row.get(f"owns_{duty}") is not True:
                reasons.append(f"duty_missing:{duty}")
        if row.get("resolves_method_provider_for_run") is True:
            reasons.append("resolves_method_provider_for_run")
        if reasons:
            violations.append({"owner": row.get("owner"), "reasons": reasons})
    if violations:
        return result("FAIL", graph_responsibilities_invalid=violations)
    return result("PASS", boundaries_checked=len(graph_rows))


def _template_overrides(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "template-overrides")


def check_template_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目模板覆盖仍满足基础契约。

    机械断言：每条覆盖声明不得删除或放宽上级强制语义，生成结果仍满足
    基础制品契约。
    """
    document = _template_overrides(ctx)
    if document is None:
        return result("PASS", template_overrides_declared=False)
    rows = rows_of(document, "overrides", "template-overrides")
    violations = []
    for row in rows:
        reasons = []
        if row.get("removes_or_loosens_upstream_mandatory_semantics") is True:
            reasons.append("loosens_upstream_mandatory_semantics")
        if row.get("generated_result_satisfies_base_contract") is not True:
            reasons.append("base_contract_not_satisfied")
        if reasons:
            violations.append({"override_id": row.get("override_id"), "reasons": reasons})
    if violations:
        return result("FAIL", overrides_breaking_base_contract=violations)
    return result("PASS", overrides_checked=len(rows))


def check_template_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族不得复制制品结构定义。

    机械断言：每条结构定义行必须引用权威契约而非复制可独立演进的
    结构定义；模板只保存填充结构与默认内容。
    """
    document = _template_overrides(ctx)
    if document is None:
        return result("PASS", template_overrides_declared=False)
    rows = rows_of(document, "structure_definitions", "template-overrides")
    violations = []
    for row in rows:
        reasons = []
        if row.get("copied_independently_evolving_structure") is True:
            reasons.append("copied_structure_definition")
        if not _nonempty_str(row.get("authoritative_contract_ref")):
            reasons.append("authoritative_contract_ref_missing")
        if row.get("holds_only_fill_and_defaults") is not True:
            reasons.append("holds_beyond_fill_and_defaults")
        if reasons:
            violations.append({"definition_id": row.get("definition_id"), "reasons": reasons})
    if violations:
        return result("FAIL", duplicated_structure_definitions=violations)
    return result("PASS", definitions_checked=len(rows))


def check_template_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """模板变化重跑契约和代表生成测试。

    机械断言：每条模板变化必须对绑定契约重跑结构校验/代表生成/项目
    加严/关系验证，且旧测试结果随模板摘要变化失效。
    """
    document = _template_overrides(ctx)
    if document is None:
        return result("PASS", template_overrides_declared=False)
    rows = rows_of(document, "template_changes", "template-overrides")
    violations = []
    for row in rows:
        reasons = []
        for rerun in (
            "structure_validation",
            "representative_generation",
            "project_strengthening",
            "relation_validation",
        ):
            if row.get(f"reran_{rerun}") is not True:
                reasons.append(f"rerun_missing:{rerun}")
        if not is_hex64(row.get("template_digest_after_change")):
            reasons.append("template_digest_invalid")
        if row.get("old_results_invalidated_on_digest_change") is not True:
            reasons.append("old_results_not_invalidated")
        if reasons:
            violations.append({"change_id": row.get("change_id"), "reasons": reasons})
    if violations:
        return result("FAIL", template_changes_not_revalidated=violations)
    return result("PASS", changes_checked=len(rows))


CHECKS = {
    "SFA-ARTMETHOD-001": check_artmethod_001,
    "SFA-ARTMETHOD-002": check_artmethod_002,
    "SFA-ARTMETHOD-004": check_artmethod_004,
    "SFA-ARTMETHOD-005": check_artmethod_005,
    "SFA-ARTMETHOD-006": check_artmethod_006,
    "SFA-ARTMETHOD-007": check_artmethod_007,
    "SFA-ARTMETHOD-008": check_artmethod_008,
    "SFA-ARTMETHOD-009": check_artmethod_009,
    "SFA-ARTMETHOD-010": check_artmethod_010,
    "SFA-ARTMETHOD-011": check_artmethod_011,
    "SFA-ARTMETHOD-012": check_artmethod_012,
    "SFA-ARTMETHOD-013": check_artmethod_013,
    "SFA-ARTMETHOD-014": check_artmethod_014,
    "SFA-ARTMETHOD-015": check_artmethod_015,
    "SFA-ARTMETHOD-016": check_artmethod_016,
    "SFA-REGISTRY-001": check_registry_001,
    "SFA-REGISTRY-003": check_registry_003,
    "SFA-REGISTRY-005": check_registry_005,
    "SFA-REGISTRY-008": check_registry_008,
    "SFA-REGISTRY-009": check_registry_009,
    "SFA-TEMPLATE-003": check_template_003,
    "SFA-TEMPLATE-004": check_template_004,
    "SFA-TEMPLATE-005": check_template_005,
}
