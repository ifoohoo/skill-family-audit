"""M5 执行族：上下文/隔离/自愈/运行框架/三档验证（W2-B2 子批 M5，57 条）。

本模块覆盖 B2 批 execution_family=M5、violation_impact=error 的 57 条规则，
全部被终态裁决为机械方法 static_scan 且
behavior_verification_also_required=true；执行器只覆盖机械半区
（evidence 携 mechanical_half=true），行为义务继续挂账。

证据面（与 B1 M5 / B2 M1/M3/M2 一致，失败关闭）：
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``：
  context-budget / run-record / isolation-policy / selfheal-policy /
  stage-isolation / tier1-runtime（B1 文档扩展消费）+
  stage-task-budget / runtime-observer / tier2-behavior /
  tier3-runtime-observation（本批新增）。

治理声明缺省语义沿用 B1：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 文档存在但形状非法 → ExecutorEvidenceError（失败关闭，绝不静默放行）；
- 文档存在且出现结构性违反 → FAIL。

执行器只消费目标事实，绝不修改目标；不消费模型语义结论。
"""
from __future__ import annotations

from typing import Any

from .contracts import (
    REQUIRED_PLATFORMS,
    ExecutorEvidenceError,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

# ---------------------------------------------------------------------------
# 词表
# ---------------------------------------------------------------------------

#: SFA-CONTEXT-003：超干预线减量/拆分的受控去向。
REDUCTION_RELOCATION_TARGETS = {
    "on_demand_reference",
    "skill_scripts",
    "responsibility_split",
}

#: SFA-CONTEXT-005：单会话观察阈值公式常量（40% 与 100K 词元取小）。
OBSERVATION_TOKEN_CAP = 100_000

#: SFA-CONTEXT-010~017：失效模式检查必须覆盖的判断维度（规则→字段）。
FAILURE_MODE_COVERAGE_FIELDS = {
    "SFA-CONTEXT-010": "goal_boundary_acceptance_loss",
    "SFA-CONTEXT-011": "repeated_work_without_new_evidence",
    "SFA-CONTEXT-012": "process_responsibility_drift",
    "SFA-CONTEXT-013": "upstream_facts_expired_or_unlocatable",
    "SFA-CONTEXT-014": "contract_authorization_inconsistency",
    "SFA-CONTEXT-015": "remaining_capacity_insufficient",
    "SFA-CONTEXT-016": "tool_log_flooding_and_abnormal_repetition",
    "SFA-CONTEXT-017": "safe_continuation_point_check",
}

#: SFA-CONTEXT-030：阶段任务预算契约必须记录的字段。
STAGE_BUDGET_CONTRACT_FIELDS = (
    "model_context_limit",
    "skill_warning_line",
    "skill_intervention_line",
    "session_observation_line",
    "static_split_line",
    "reserved_output",
    "measurement_policy",
    "failure_mode_reference",
    "split_strategy",
    "runtime_observer",
)

#: SFA-CONTEXT-031：阶段结果必须记录的上下文使用量字段。
STAGE_RESULT_FIELDS = (
    "measurement_method",
    "measurement_source",
    "estimator_version",
    "context_limit",
    "static_estimate",
    "observed_usage",
    "observation_threshold",
    "failure_modes_checked",
    "failure_modes_hit",
    "split_decision",
    "interventions",
)

#: SFA-ISOLATION-008：运行隔离机器证明必须绑定的事实。
ISOLATION_ATTESTATION_FIELDS = (
    "environment_identity",
    "isolation_policy",
    "credentials",
    "network",
    "mounts",
    "resource_limits",
    "destruction_result",
)

#: SFA-RUNTIMEOBS-001：运行控制器负责的续接职责。
RUNTIME_CONTROLLER_OWNERSHIPS = (
    "single_session_observation",
    "failure_mode_detection",
    "checkpointing",
    "recovery_orchestration",
    "clean_session_continuation",
)

#: SFA-STAGEISO-001：工序隔离必须分别说明的七个维度。
STAGE_ISOLATION_DIMENSIONS = (
    "context",
    "execution_process",
    "filesystem",
    "tool_permissions",
    "network_credentials",
    "write_set",
    "result_channel",
)

#: SFA-STAGEISO-001：隔离等级词表。
STAGE_ISOLATION_LEVELS = {"required", "preferred", "none"}

#: SFA-STAGEISO-004：降级替代路径允许的两种执行形态。
STAGE_ALTERNATIVE_EXECUTION_FORMS = {"serial", "within_entry"}

#: SFA-STAGEISO-004：契约等价必须保持的六个面。
STAGE_EQUIVALENCE_FIELDS = (
    "inputs_outputs",
    "permissions",
    "security_boundary",
    "write_set",
    "context_budget",
    "acceptance_conditions",
)

#: SFA-TIER1-004：三个固定人类入口各自必须验证的承诺。
TIER1_ENTRY_COMMITMENTS = {
    "help": "read_only",
    "setup": "authorization_change",
    "quickstart": "formal_business_routing",
}

#: SFA-TIER2-001：第二档行为矩阵必须覆盖的行为类型。
TIER2_BEHAVIOR_KINDS = (
    "positive",
    "negative",
    "boundary",
    "missing_input",
    "no_permission",
    "failure",
    "blocked",
    "waiting",
    "skip",
    "degraded",
)

#: SFA-TIER2-004：行为验证必须锁定的可重放条件。
TIER2_REPLAY_LOCK_FIELDS = (
    "input_sample",
    "expected_result",
    "executor",
    "model",
    "platform_and_client_version",
    "target_package_digest",
    "method_contract_digest",
    "result_evidence",
)

#: SFA-TIER2-006：第二档必须验证的兼容范围。
TIER2_COMPATIBILITY_SCOPES = (
    "old_contract_adaptation",
    "extension_fields",
    "cross_platform_projection",
    "version_upgrade",
)

#: SFA-TIER3-001：第三档必须记录的运行观察事实。
TIER3_OBSERVATION_FACT_FIELDS = (
    "stream_events_with_time_and_process_identity",
    "heartbeats",
    "stage_artifacts",
    "verification_processes",
    "long_tool_leases",
    "business_progress",
)

#: SFA-TIER3-002：第三档必须给出机器结论的主要运行异常类别。
TIER3_ANOMALY_CATEGORIES = (
    "silent_stall",
    "context_failure",
    "tool_anomaly",
    "partial_output",
    "permission_denied",
    "contract_drift",
    "platform_capability_missing",
    "write_conflict",
)

#: SFA-TIER3-003：第三档恢复机制集合。
TIER3_RECOVERY_MECHANISMS = (
    "checkpoint",
    "clean_session_continuation",
    "bounded_technical_retry",
    "business_rework_lineage",
    "cancel",
    "rollback",
    "crash_recovery",
)

#: SFA-TIER3-004：受控故障注入的故障类别。
TIER3_FAULT_KINDS = (
    "timeout",
    "tool_failure",
    "partial_output",
    "permission_denied",
    "contract_drift",
    "platform_capability_missing",
    "write_conflict",
)

#: SFA-TIER3-005：并发/降级/恢复验证必须成立的属性。
TIER3_CONCURRENCY_FIELDS = (
    "write_sets_no_conflict",
    "confluence_results_complete",
    "degradation_semantics_clear",
    "rollback_effective",
    "repeated_recovery_idempotent",
)

#: SFA-TIER3-006：持续回归矩阵的行维度。
TIER3_REGRESSION_MATRIX_FIELDS = (
    "family_version",
    "target_release_digest",
    "platform",
    "model",
    "runner",
    "test_sample",
    "last_valid_evidence",
)

#: SFA-SELFHEAL-010：重试/返工因果证据必须记录的字段。
SELFHEAL_CAUSAL_EVIDENCE_FIELDS = (
    "trigger_reason",
    "classification",
    "actions_taken",
    "input_authorization_freshness",
    "before_evidence",
    "after_evidence",
    "independent_reverification_result",
)


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _object_field(
    row: dict[str, Any], key: str, where: str
) -> dict[str, Any] | None:
    value = row.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"{where}.{key} 必须是对象"
        )
    return value


# ---------------------------------------------------------------------------
# CONTEXT：上下文预算与运行记录（context-budget / run-record / stage-task-budget）
# ---------------------------------------------------------------------------


def check_context_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能说明超量采用受控减量。

    机械断言：已声明超过强制干预线的减量必须把内容迁入受控去向
    （按需参考资料/所属技能脚本/职责拆分），不得声明超线却无去向。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", reductions_declared=0, mechanical_half=True)
    rows = rows_of(document, "reductions", "context-budget")
    violations = []
    over_line = 0
    for index, row in enumerate(rows):
        if row.get("trigger") != "over_intervention_line":
            continue
        over_line += 1
        targets = row.get("relocation_targets")
        if targets is None:
            targets = []
        if not isinstance(targets, list) or not all(
            isinstance(item, str) for item in targets
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "context-budget.reductions.relocation_targets 必须是字符串数组",
            )
        unknown = sorted(set(targets) - REDUCTION_RELOCATION_TARGETS)
        problems = []
        if not targets:
            problems.append("relocation_targets_empty")
        if unknown:
            problems.append(f"uncontrolled_relocation_targets:{unknown}")
        if problems:
            violations.append(
                {"index": index, "reduction": row.get("reduction_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", over_line_reduction_violations=violations, mechanical_half=True)
    return result("PASS", over_intervention_line_reductions=over_line, mechanical_half=True)


def check_context_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """单会话观察阈值公式。

    机械断言：已声明观察阈值必须等于 min(模型上下文上限×40%, 100000)。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", session_thresholds_declared=False, mechanical_half=True)
    thresholds = document.get("session_thresholds")
    if thresholds is None:
        return result("PASS", session_thresholds_declared=False, mechanical_half=True)
    if not isinstance(thresholds, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "context-budget.session_thresholds 必须是对象"
        )
    limit = thresholds.get("model_context_limit")
    observation = thresholds.get("observation_threshold")
    if not _positive_int(limit):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "context-budget.session_thresholds.model_context_limit 必须是正整数",
        )
    if not _nonneg_int(observation):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "context-budget.session_thresholds.observation_threshold 必须是非负整数",
        )
    expected = min(limit * 2 // 5, OBSERVATION_TOKEN_CAP)
    if observation != expected:
        return result(
            "FAIL",
            declared_threshold=observation,
            expected_threshold=expected,
            mechanical_half=True,
        )
    return result("PASS", observation_threshold=observation, mechanical_half=True)


def check_context_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """静态超过观察阈值两成强制拆分。

    机械断言：已声明静态估算达到观察阈值 120% 的会话/执行单元必须声明
    执行前拆分。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", static_estimates_declared=0, mechanical_half=True)
    rows = rows_of(document, "static_estimates", "context-budget")
    violations = []
    for index, row in enumerate(rows):
        static_tokens = row.get("static_tokens")
        threshold = row.get("observation_threshold")
        if not _nonneg_int(static_tokens):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "context-budget.static_estimates.static_tokens 必须是非负整数",
            )
        if not _nonneg_int(threshold):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "context-budget.static_estimates.observation_threshold 必须是非负整数",
            )
        if static_tokens * 5 >= threshold * 6 and row.get("split_before_execution") is not True:
            violations.append(
                {"index": index, "subject": row.get("subject"),
                 "static_tokens": static_tokens, "threshold": threshold}
            )
    if violations:
        return result("FAIL", oversized_static_without_split=violations, mechanical_half=True)
    return result("PASS", static_estimates=len(rows), mechanical_half=True)


def check_context_028(ctx: dict[str, Any]) -> dict[str, Any]:
    """词元计量方法版本化且不得混用。

    机械断言：已声明词元计量必须记录估算器名称与版本；同一比较不得声明
    混用不同估算方法。
    """
    document = _doc(ctx, "context-budget")
    if document is None:
        return result("PASS", token_metering_declared=False, mechanical_half=True)
    metering = document.get("token_metering")
    if metering is None:
        return result("PASS", token_metering_declared=False, mechanical_half=True)
    if not isinstance(metering, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "context-budget.token_metering 必须是对象"
        )
    problems = []
    if not _nonempty_str(metering.get("estimator_name")):
        problems.append("estimator_name_empty")
    if not _nonempty_str(metering.get("estimator_version")):
        problems.append("estimator_version_empty")
    comparisons = rows_of(metering, "comparisons", "context-budget.token_metering")
    for index, row in enumerate(comparisons):
        if not _nonempty_str(row.get("estimator_identity")):
            problems.append(f"comparison[{index}].estimator_identity_empty")
        if row.get("estimators_mixed") is True:
            problems.append(f"comparison[{index}].estimators_mixed")
    if problems:
        return result("FAIL", token_metering_problems=problems, mechanical_half=True)
    return result("PASS", comparisons=len(comparisons), mechanical_half=True)


def _run_record(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "run-record")


def check_context_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行达到观察阈值必须检查失效模式。

    机械断言：已声明达到观察阈值的阈值事件必须执行失效模式检查，且不得
    声明仅因数值达到阈值就机械终止。
    """
    record = _run_record(ctx)
    if record is None:
        return result("PASS", threshold_events_declared=0, mechanical_half=True)
    rows = rows_of(record, "threshold_events", "run-record")
    violations = []
    reached = 0
    for index, row in enumerate(rows):
        if row.get("reached_observation_threshold") is not True:
            continue
        reached += 1
        problems = []
        if row.get("failure_mode_check_executed") is not True:
            problems.append("failure_mode_check_not_executed")
        if row.get("mechanical_termination_only") is True:
            problems.append("mechanical_termination_only")
        if problems:
            violations.append({"index": index, "session": row.get("session"), "problems": problems})
    if violations:
        return result("FAIL", threshold_event_handling_violations=violations, mechanical_half=True)
    return result("PASS", threshold_reached_events=reached, mechanical_half=True)


def check_context_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """静态与运行触发职责分离。

    机械断言：已声明职责划分必须分别给出静态预算责任方与运行观察责任方，
    且两者不得为同一主体。
    """
    record = _run_record(ctx)
    if record is None:
        return result("PASS", responsibility_separation_declared=False, mechanical_half=True)
    separation = record.get("responsibility_separation")
    if separation is None:
        return result("PASS", responsibility_separation_declared=False, mechanical_half=True)
    if not isinstance(separation, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "run-record.responsibility_separation 必须是对象"
        )
    static_owner = separation.get("static_budget_owner")
    runtime_owner = separation.get("runtime_observation_owner")
    problems = []
    if not _nonempty_str(static_owner):
        problems.append("static_budget_owner_empty")
    if not _nonempty_str(runtime_owner):
        problems.append("runtime_observation_owner_empty")
    if _nonempty_str(static_owner) and static_owner == runtime_owner:
        problems.append("static_and_runtime_owner_identical")
    if problems:
        return result("FAIL", responsibility_separation_problems=problems, mechanical_half=True)
    return result(
        "PASS", static_budget_owner=static_owner, runtime_observation_owner=runtime_owner,
        mechanical_half=True,
    )


def _failure_mode_coverage_field(canonical_id: str) -> str:
    return FAILURE_MODE_COVERAGE_FIELDS[canonical_id]


def _check_failure_mode_coverage(canonical_id: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """CONTEXT-010~017 共用：已声明失效模式检查覆盖必须包含对应判断维度。"""
    record = _run_record(ctx)
    if record is None:
        return result("PASS", failure_mode_checks_declared=False, mechanical_half=True)
    coverage = record.get("failure_mode_coverage")
    if coverage is None:
        return result("PASS", failure_mode_checks_declared=False, mechanical_half=True)
    if not isinstance(coverage, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "run-record.failure_mode_coverage 必须是对象"
        )
    field = _failure_mode_coverage_field(canonical_id)
    if coverage.get(field) is not True:
        return result("FAIL", failure_mode_coverage_missing=field, mechanical_half=True)
    return result("PASS", failure_mode_coverage_field=field, mechanical_half=True)


def check_context_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查目标边界和验收遗失。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-010", ctx)


def check_context_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查重复工作且没有新增证据。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-011", ctx)


def check_context_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查流程和职责漂移。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-012", ctx)


def check_context_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查上游事实过期或不可定位。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-013", ctx)


def check_context_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查契约状态和授权不一致。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-014", ctx)


def check_context_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查剩余上下文容量不足。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-015", ctx)


def check_context_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查工具日志淹没和异常重复。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-016", ctx)


def check_context_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """检查安全续接点是否存在。"""
    return _check_failure_mode_coverage("SFA-CONTEXT-017", ctx)


def check_context_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范不得复制第二套运行状态机。

    机械断言：已声明运行状态机归属必须指向非空运行控制器，且规范侧不得
    声明复制竞争的运行控制状态机。
    """
    record = _run_record(ctx)
    if record is None:
        return result("PASS", runtime_state_machine_declared=False, mechanical_half=True)
    machine = record.get("runtime_state_machine")
    if machine is None:
        return result("PASS", runtime_state_machine_declared=False, mechanical_half=True)
    if not isinstance(machine, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "run-record.runtime_state_machine 必须是对象"
        )
    problems = []
    if not _nonempty_str(machine.get("runtime_controller")):
        problems.append("runtime_controller_empty")
    if machine.get("spec_duplicates_runtime_state_machine") is True:
        problems.append("spec_duplicates_runtime_state_machine")
    if problems:
        return result("FAIL", duplicated_state_machine_problems=problems, mechanical_half=True)
    return result("PASS", runtime_controller=machine.get("runtime_controller"), mechanical_half=True)


def _context_accounting(ctx: dict[str, Any]) -> dict[str, Any] | None | str:
    """返回 context_accounting 对象；文档缺失返回 None；键缺失返回 'absent'。"""
    record = _run_record(ctx)
    if record is None:
        return None
    accounting = record.get("context_accounting")
    if accounting is None:
        return "absent"
    if not isinstance(accounting, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "run-record.context_accounting 必须是对象"
        )
    return accounting


def check_context_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """当前上下文与累计用量分开记录。

    机械断言：已声明上下文记账必须分别记录当前会话占用与整次运行累计
    用量，且累计计费用量不得用于判断单会话失效。
    """
    accounting = _context_accounting(ctx)
    if accounting in (None, "absent"):
        return result("PASS", context_accounting_declared=False, mechanical_half=True)
    problems = []
    if accounting.get("current_session_usage_recorded") is not True:
        problems.append("current_session_usage_not_recorded")
    if accounting.get("cumulative_run_usage_recorded") is not True:
        problems.append("cumulative_run_usage_not_recorded")
    if accounting.get("cumulative_billing_used_for_session_failure_judgement") is True:
        problems.append("cumulative_billing_used_for_session_failure_judgement")
    if problems:
        return result("FAIL", context_accounting_problems=problems, mechanical_half=True)
    return result("PASS", usage_streams_separated=True, mechanical_half=True)


def check_context_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """磁盘工件加载后才计入上下文。

    机械断言：已声明上下文记账必须声明磁盘工件仅在实际读取/内联/回传后
    计入当前上下文占用。
    """
    accounting = _context_accounting(ctx)
    if accounting in (None, "absent"):
        return result("PASS", context_accounting_declared=False, mechanical_half=True)
    if accounting.get("disk_artifacts_counted_only_when_loaded") is not True:
        return result(
            "FAIL", reason="disk_artifacts_counted_before_loading", mechanical_half=True
        )
    return result("PASS", disk_artifacts_counted_only_when_loaded=True, mechanical_half=True)


def check_context_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """缓存读取和创建计入上下文。

    机械断言：已声明上下文记账必须把缓存读取与缓存创建计入当前上下文
    使用证据。
    """
    accounting = _context_accounting(ctx)
    if accounting in (None, "absent"):
        return result("PASS", context_accounting_declared=False, mechanical_half=True)
    if accounting.get("cache_reads_and_creations_counted") is not True:
        return result("FAIL", reason="cache_usage_excluded_from_context", mechanical_half=True)
    return result("PASS", cache_reads_and_creations_counted=True, mechanical_half=True)


def check_context_025(ctx: dict[str, Any]) -> dict[str, Any]:
    """大型结果落盘且父入口只收短返回。

    机械断言：已声明大型结果转移必须写入文件，父入口只接收运行状态、
    结果路径与预算约束的短摘要。
    """
    record = _run_record(ctx)
    if record is None:
        return result("PASS", large_result_transfers_declared=0, mechanical_half=True)
    rows = rows_of(record, "large_result_transfers", "run-record")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("written_to_file") is not True:
            problems.append("not_written_to_file")
        if row.get("parent_received_short_return") is not True:
            problems.append("parent_did_not_receive_short_return")
        if row.get("short_summary_budget_constrained") is not True:
            problems.append("short_summary_not_budget_constrained")
        if problems:
            violations.append(
                {"index": index, "result": row.get("result_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", large_result_transfer_violations=violations, mechanical_half=True)
    return result("PASS", large_result_transfers=len(rows), mechanical_half=True)


def _stage_task_budget(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "stage-task-budget")


def check_context_030(ctx: dict[str, Any]) -> dict[str, Any]:
    """阶段任务记录预算契约。

    机械断言：已声明阶段任务必须记录预算契约十字段（模型上下文上限、
    告警/干预线、观察/静态拆分线、预留输出、测量政策、失效模式引用、
    拆分策略、运行观察器）。
    """
    document = _stage_task_budget(ctx)
    if document is None:
        return result("PASS", stage_tasks_declared=0, mechanical_half=True)
    rows = rows_of(document, "stage_tasks", "stage-task-budget")
    violations = []
    for index, row in enumerate(rows):
        contract = _object_field(row, "budget_contract", "stage-task-budget.stage_tasks")
        if contract is None:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problem": "budget_contract_missing"}
            )
            continue
        missing = [field for field in STAGE_BUDGET_CONTRACT_FIELDS if field not in contract]
        if missing:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "missing": missing}
            )
    if violations:
        return result("FAIL", budget_contract_violations=violations, mechanical_half=True)
    return result("PASS", stage_tasks=len(rows), mechanical_half=True)


def check_context_031(ctx: dict[str, Any]) -> dict[str, Any]:
    """阶段结果记录上下文使用量。

    机械断言：已声明阶段结果必须记录测量方法与来源、估算器版本、上下文
    上限、静态预计量、真实观测量、观察阈值、失效模式检查与命中、拆分
    决定和干预。
    """
    document = _stage_task_budget(ctx)
    if document is None:
        return result("PASS", stage_results_declared=0, mechanical_half=True)
    rows = rows_of(document, "stage_results", "stage-task-budget")
    violations = []
    for index, row in enumerate(rows):
        missing = [field for field in STAGE_RESULT_FIELDS if field not in row]
        if missing:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "missing": missing}
            )
    if violations:
        return result("FAIL", stage_result_violations=violations, mechanical_half=True)
    return result("PASS", stage_results=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# ISOLATION：控制面机器可验证隔离证明（isolation-policy）
# ---------------------------------------------------------------------------


def check_isolation_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """控制面出具机器可验证隔离证明。

    机械断言：已声明者必须为每次运行出具绑定环境身份、隔离策略、凭据、
    网络、挂载、资源限制和销毁结果的机器可验证证明（附证明摘要）。
    """
    policy = _doc(ctx, "isolation-policy")
    if policy is None:
        return result("PASS", isolation_attestations_declared=0, mechanical_half=True)
    rows = rows_of(policy, "run_attestations", "isolation-policy")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        attestation = _object_field(row, "attestation", "isolation-policy.run_attestations")
        if attestation is None:
            problems.append("attestation_missing")
        else:
            missing = [
                field for field in ISOLATION_ATTESTATION_FIELDS if field not in attestation
            ]
            if missing:
                problems.append(f"attestation_fields_missing:{missing}")
        if row.get("machine_verifiable") is not True:
            problems.append("not_machine_verifiable")
        if not is_hex64(row.get("attestation_digest")):
            problems.append("attestation_digest_invalid")
        if problems:
            violations.append(
                {"index": index, "run": row.get("run_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", isolation_attestation_violations=violations, mechanical_half=True)
    return result("PASS", run_attestations=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# RUNTIMEOBS：运行观察器与第三档职责（runtime-observer）
# ---------------------------------------------------------------------------


def _runtime_observer(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "runtime-observer")


def check_runtimeobs_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行中的观察恢复续接由运行控制器负责。

    机械断言：已声明者必须把单会话观察、失效模式检测、检查点、恢复编排
    与干净会话续接全部归于非空运行控制器；规范检查技能不得实现第二套
    运行控制状态机。
    """
    document = _runtime_observer(ctx)
    if document is None:
        return result("PASS", runtime_control_declared=False, mechanical_half=True)
    control = document.get("runtime_control")
    if control is None:
        return result("PASS", runtime_control_declared=False, mechanical_half=True)
    if not isinstance(control, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "runtime-observer.runtime_control 必须是对象"
        )
    problems = []
    controller = control.get("runtime_controller")
    if not _nonempty_str(controller):
        problems.append("runtime_controller_empty")
    for ownership in RUNTIME_CONTROLLER_OWNERSHIPS:
        if control.get(ownership + "_owner") != "runtime_controller":
            problems.append(f"{ownership}_owner_not_runtime_controller")
    if control.get("spec_check_skill_implements_second_state_machine") is True:
        problems.append("spec_check_skill_implements_second_state_machine")
    if problems:
        return result("FAIL", runtime_control_problems=problems, mechanical_half=True)
    return result("PASS", runtime_controller=controller, mechanical_half=True)


def check_runtimeobs_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范检查技能只验证第三档声明和证据。

    机械断言：已声明规范检查角色必须限于验证观察器绑定、能力声明、统一
    证据结构与第三档证据；不得以静态扫描或自身轮询冒充真实运行健康。
    """
    document = _runtime_observer(ctx)
    if document is None:
        return result("PASS", spec_check_role_declared=False, mechanical_half=True)
    role = document.get("spec_check_role")
    if role is None:
        return result("PASS", spec_check_role_declared=False, mechanical_half=True)
    if not isinstance(role, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "runtime-observer.spec_check_role 必须是对象"
        )
    problems = []
    for field in (
        "verifies_observer_binding",
        "verifies_capability_declarations",
        "verifies_unified_evidence_structure",
        "verifies_third_tier_evidence",
    ):
        if role.get(field) is not True:
            problems.append(f"{field}_not_declared")
    if role.get("impersonates_runtime_health_with_static_scan_or_polling") is True:
        problems.append("impersonates_runtime_health")
    if problems:
        return result("FAIL", spec_check_role_problems=problems, mechanical_half=True)
    return result("PASS", spec_check_role_limited_to_verification=True, mechanical_half=True)


def check_runtimeobs_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族不得复制不兼容观察器。

    机械断言：已声明技能族观察器必须兼容统一协议；不兼容时必须通过版本化
    适配器输出统一证据与状态。
    """
    document = _runtime_observer(ctx)
    if document is None:
        return result("PASS", family_observers_declared=0, mechanical_half=True)
    rows = rows_of(document, "family_observers", "runtime-observer")
    violations = []
    for index, row in enumerate(rows):
        if row.get("compatible_with_unified_protocol") is True:
            continue
        problems = []
        if row.get("uses_versioned_adapter") is not True:
            problems.append("no_versioned_adapter")
        if row.get("emits_unified_evidence") is not True:
            problems.append("no_unified_evidence")
        if row.get("emits_unified_status") is not True:
            problems.append("no_unified_status")
        if problems:
            violations.append(
                {"index": index, "family": row.get("family"), "problems": problems}
            )
    if violations:
        return result("FAIL", incompatible_observers_without_adapter=violations, mechanical_half=True)
    return result("PASS", family_observers=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# SELFHEAL：重试返工因果证据与恢复后复验（selfheal-policy）
# ---------------------------------------------------------------------------


def check_selfheal_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次重试返工保留因果证据。

    机械断言：已声明重试/返工记录必须携带触发原因、分类、采取动作、
    输入与授权新鲜度、前后证据和独立复验结果。
    """
    policy = _doc(ctx, "selfheal-policy")
    if policy is None:
        return result("PASS", retry_rework_records_declared=0, mechanical_half=True)
    rows = rows_of(policy, "retry_rework_records", "selfheal-policy")
    violations = []
    for index, row in enumerate(rows):
        missing = [
            field for field in SELFHEAL_CAUSAL_EVIDENCE_FIELDS if field not in row
        ]
        if missing:
            violations.append(
                {"index": index, "record": row.get("record_id"), "missing": missing}
            )
    if violations:
        return result("FAIL", causal_evidence_incomplete=violations, mechanical_half=True)
    return result("PASS", retry_rework_records=len(rows), mechanical_half=True)


def check_selfheal_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """恢复后重跑受影响的低档位验证。

    机械断言：已声明完成的恢复动作必须重跑受影响的第一档正常路径与第二档
    行为样例；不得把恢复命令成功退出直接视为业务已经恢复。
    """
    policy = _doc(ctx, "selfheal-policy")
    if policy is None:
        return result("PASS", completed_recoveries_declared=0, mechanical_half=True)
    rows = rows_of(policy, "completed_recoveries", "selfheal-policy")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("reran_affected_tier1_normal_paths") is not True:
            problems.append("tier1_normal_paths_not_rerun")
        if row.get("reran_affected_tier2_behavior_samples") is not True:
            problems.append("tier2_behavior_samples_not_rerun")
        if row.get("treats_successful_exit_as_business_recovered") is True:
            problems.append("successful_exit_treated_as_business_recovered")
        if problems:
            violations.append(
                {"index": index, "recovery": row.get("recovery_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", recovery_reverification_violations=violations, mechanical_half=True)
    return result("PASS", completed_recoveries=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# STAGEISO：工序隔离等级与受控降级（stage-isolation）
# ---------------------------------------------------------------------------


def _stage_isolation(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "stage-isolation")


def check_stageiso_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个内部工序声明隔离等级和维度。

    机械断言：已声明工序必须给出 required/preferred/none 之一的隔离等级，
    并分别说明七个隔离维度的要求。
    """
    document = _stage_isolation(ctx)
    if document is None:
        return result("PASS", stages_declared=0, mechanical_half=True)
    rows = rows_of(document, "stages", "stage-isolation")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        level = row.get("isolation_level")
        if level not in STAGE_ISOLATION_LEVELS:
            problems.append(f"isolation_level_invalid:{level!r}")
        requirements = _object_field(row, "dimension_requirements", "stage-isolation.stages")
        if requirements is None:
            problems.append("dimension_requirements_missing")
        else:
            missing = [
                dimension
                for dimension in STAGE_ISOLATION_DIMENSIONS
                if not _nonempty_str(requirements.get(dimension))
                and not _nonempty_list(requirements.get(dimension))
                and not (
                    isinstance(requirements.get(dimension), dict)
                    and requirements.get(dimension)
                )
            ]
            if missing:
                problems.append(f"dimension_requirements_missing:{missing}")
        if problems:
            violations.append(
                {"index": index, "stage": row.get("stage_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", stage_isolation_declaration_violations=violations, mechanical_half=True)
    return result("PASS", stages=len(rows), mechanical_half=True)


def _preferred_alternative_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if row.get("isolation_level") == "preferred"
        and row.get("alternative_path_used") is True
    ]


def check_stageiso_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """优先隔离只能在契约等价时降级。

    机械断言：已声明采用替代路径的优先隔离工序必须在串行或入口内执行，且
    保持输入输出、权限、安全边界、写入集合、上下文预算和验收标准。
    """
    document = _stage_isolation(ctx)
    if document is None:
        return result("PASS", stages_declared=0, mechanical_half=True)
    rows = rows_of(document, "stages", "stage-isolation")
    violations = []
    for row in _preferred_alternative_rows(rows):
        problems = []
        if row.get("execution_form") not in STAGE_ALTERNATIVE_EXECUTION_FORMS:
            problems.append(f"execution_form_invalid:{row.get('execution_form')!r}")
        equivalence = _object_field(row, "contract_equivalence", "stage-isolation.stages")
        if equivalence is None:
            problems.append("contract_equivalence_missing")
        else:
            missing = [
                field for field in STAGE_EQUIVALENCE_FIELDS if equivalence.get(field) is not True
            ]
            if missing:
                problems.append(f"equivalence_not_preserved:{missing}")
        if problems:
            violations.append({"stage": row.get("stage_id"), "problems": problems})
    if violations:
        return result("FAIL", preferred_isolation_downgrade_violations=violations, mechanical_half=True)
    return result("PASS", preferred_alternative_paths=len(_preferred_alternative_rows(rows)), mechanical_half=True)


def check_stageiso_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """优先隔离降级形成结构化事实。

    机械断言：已声明采用替代路径的优先隔离工序必须记录缺失能力、实际执行
    形态、保持与变化的隔离维度、语义影响及验证证据；不得只写普通警告。
    """
    document = _stage_isolation(ctx)
    if document is None:
        return result("PASS", stages_declared=0, mechanical_half=True)
    rows = rows_of(document, "stages", "stage-isolation")
    violations = []
    for row in _preferred_alternative_rows(rows):
        if row.get("recorded_as_plain_warning") is True:
            violations.append({"stage": row.get("stage_id"), "problem": "plain_warning_only"})
            continue
        record = _object_field(row, "downgrade_record", "stage-isolation.stages")
        if record is None:
            violations.append({"stage": row.get("stage_id"), "problem": "downgrade_record_missing"})
            continue
        missing = [
            field
            for field in (
                "missing_capabilities",
                "actual_execution_form",
                "preserved_dimensions",
                "changed_dimensions",
                "semantic_impact",
                "verification_evidence",
            )
            if field not in record
        ]
        if missing:
            violations.append({"stage": row.get("stage_id"), "missing": missing})
    if violations:
        return result("FAIL", downgrade_record_violations=violations, mechanical_half=True)
    return result("PASS", preferred_alternative_paths=len(_preferred_alternative_rows(rows)), mechanical_half=True)


# ---------------------------------------------------------------------------
# TIER1：第一档真实运行（tier1-runtime）
# ---------------------------------------------------------------------------


def _tier1_runtime(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "tier1-runtime")


def check_tier1_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一档必须真实运行主要正常路径。

    机械断言：已声明第一档运行必须使用最小但真实的有界运行器，对实际发行
    物完成打包、安装、发现、最小调用和主要正常业务路径；不得把目录结构
    符合当作第一档证明。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", tier1_runs_declared=False, mechanical_half=True)
    runs = document.get("main_normal_path_runs")
    if runs is None:
        return result("PASS", tier1_runs_declared=False, mechanical_half=True)
    if not isinstance(runs, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "tier1-runtime.main_normal_path_runs 必须是对象"
        )
    problems = []
    if runs.get("bounded_runner") is not True:
        problems.append("bounded_runner_missing")
    if runs.get("executed_on_real_release_artifact") is not True:
        problems.append("not_executed_on_real_release_artifact")
    for field in (
        "covers_packaging",
        "covers_install",
        "covers_discovery",
        "covers_minimal_invocation",
        "covers_main_normal_business_path",
    ):
        if runs.get(field) is not True:
            problems.append(f"{field}_not_declared")
    if runs.get("directory_conformance_treated_as_tier1_proof") is True:
        problems.append("directory_conformance_treated_as_tier1_proof")
    if problems:
        return result("FAIL", tier1_real_run_problems=problems, mechanical_half=True)
    return result("PASS", main_normal_path_runs_declared=True, mechanical_half=True)


def check_tier1_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """确定性检查是第一档前置而非替代。

    机械断言：已声明第一档必须先行完成全部适用强制规则的确定性检查，
    失败阻止不安全运行，且检查通过不得替代正常路径执行。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", deterministic_precheck_declared=False, mechanical_half=True)
    precheck = document.get("deterministic_precheck")
    if precheck is None:
        return result("PASS", deterministic_precheck_declared=False, mechanical_half=True)
    if not isinstance(precheck, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "tier1-runtime.deterministic_precheck 必须是对象"
        )
    problems = []
    if precheck.get("all_applicable_mandatory_rules_checked_before_run") is not True:
        problems.append("mandatory_rules_not_all_checked_before_run")
    if precheck.get("failed_precheck_blocks_unsafe_run") is not True:
        problems.append("failed_precheck_does_not_block_run")
    if precheck.get("passed_precheck_substitutes_normal_path_execution") is True:
        problems.append("precheck_substitutes_normal_path_execution")
    if problems:
        return result("FAIL", deterministic_precheck_problems=problems, mechanical_half=True)
    return result("PASS", deterministic_precheck_is_prerequisite=True, mechanical_half=True)


def check_tier1_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一档运行已有确定性和合同测试。

    机械断言：已声明者必须把目标技能族已声明的确定性脚本测试、结构测试
    和合同测试在第一档环境中真实执行；不得只检查测试文件存在。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", declared_test_executions=0, mechanical_half=True)
    rows = rows_of(document, "declared_test_executions", "tier1-runtime")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("test_kind") not in {"deterministic_script", "structural", "contract"}:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"tier1-runtime.declared_test_executions 第 {index} 行 test_kind 非法: "
                f"{row.get('test_kind')!r}",
            )
        if row.get("actually_executed_in_tier1") is not True:
            problems.append("not_actually_executed_in_tier1")
        if row.get("file_existence_check_only") is True:
            problems.append("file_existence_check_only")
        if problems:
            violations.append(
                {"index": index, "test": row.get("test_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", declared_tests_not_executed=violations, mechanical_half=True)
    return result("PASS", declared_test_executions=len(rows), mechanical_half=True)


def check_tier1_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一档覆盖三个固定人类入口。

    机械断言：平台和依赖可用时，已声明者必须真实执行 help/setup/quickstart
    的主要正常路径，并分别验证只读、授权变更和正式业务路由承诺。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", fixed_entry_runs_declared=False, mechanical_half=True)
    if document.get("platforms_and_dependencies_available") is not True:
        return result("PASS", platforms_and_dependencies_available=False, mechanical_half=True)
    rows = rows_of(document, "fixed_entry_runs", "tier1-runtime")
    by_entry = {}
    for index, row in enumerate(rows):
        entry = row.get("entry")
        if entry not in TIER1_ENTRY_COMMITMENTS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"tier1-runtime.fixed_entry_runs 第 {index} 行 entry 非法: {entry!r}",
            )
        by_entry[entry] = row
    violations = []
    for entry, commitment in TIER1_ENTRY_COMMITMENTS.items():
        row = by_entry.get(entry)
        if row is None:
            violations.append({"entry": entry, "problem": "not_executed"})
            continue
        problems = []
        if row.get("executed_main_normal_path") is not True:
            problems.append("main_normal_path_not_executed")
        if row.get("verified_commitment") != commitment:
            problems.append(f"commitment_not_verified:{commitment}")
        if problems:
            violations.append({"entry": entry, "problems": problems})
    if violations:
        return result("FAIL", fixed_entry_run_violations=violations, mechanical_half=True)
    return result("PASS", fixed_entries_executed=sorted(by_entry), mechanical_half=True)


def _sample_count(row: dict[str, Any], key: str, where: str) -> int:
    value = row.get(key)
    if not _nonneg_int(value):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"{where}.{key} 必须是非负整数"
        )
    return value


def check_tier1_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """每项稳定公共能力至少执行一个代表样例。

    机械断言：已声明稳定公共能力与不能由能力样例覆盖的严格方法必须各自
    至少一个代表性正常业务样例。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", capability_samples_declared=0, mechanical_half=True)
    violations = []
    capability_rows = rows_of(document, "capability_samples", "tier1-runtime")
    for index, row in enumerate(capability_rows):
        if _sample_count(row, "representative_samples", "tier1-runtime.capability_samples") < 1:
            violations.append(
                {"kind": "capability", "index": index, "subject": row.get("capability")}
            )
    method_rows = rows_of(document, "uncovered_strict_method_samples", "tier1-runtime")
    for index, row in enumerate(method_rows):
        if (
            _sample_count(
                row, "representative_samples", "tier1-runtime.uncovered_strict_method_samples"
            )
            < 1
        ):
            violations.append(
                {"kind": "strict_method", "index": index, "subject": row.get("method")}
            )
    if violations:
        return result("FAIL", subjects_without_representative_sample=violations, mechanical_half=True)
    return result(
        "PASS", capabilities=len(capability_rows), strict_methods=len(method_rows),
        mechanical_half=True,
    )


def check_tier1_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """联合发布使用同目标同验收跨平台正常样例。

    机械断言：已声明四平台联合发布样例必须覆盖共同业务能力、四个必需
    平台，且使用相同业务目标与验收条件。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", joint_release_samples_declared=0, mechanical_half=True)
    rows = rows_of(document, "joint_release_samples", "tier1-runtime")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if not _nonempty_list(row.get("common_capabilities")):
            problems.append("common_capabilities_empty")
        platforms = row.get("platforms")
        if not isinstance(platforms, list) or not all(
            isinstance(item, str) for item in platforms
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "tier1-runtime.joint_release_samples.platforms 必须是字符串数组",
            )
        missing_platforms = sorted(set(REQUIRED_PLATFORMS) - set(platforms))
        if missing_platforms:
            problems.append(f"missing_required_platforms:{missing_platforms}")
        if row.get("same_business_goal") is not True:
            problems.append("business_goal_diverges")
        if row.get("same_acceptance_conditions") is not True:
            problems.append("acceptance_conditions_diverge")
        if problems:
            violations.append({"index": index, "problems": problems})
    if violations:
        return result("FAIL", joint_release_sample_violations=violations, mechanical_half=True)
    return result("PASS", joint_release_samples=len(rows), mechanical_half=True)


def check_tier1_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一档逐项记录证据和未运行原因。

    机械断言：已声明第一档结果必须逐项给出身份、环境、证据位置与结论；
    未运行/受阻/不适用必须给出原因，通过结论必须附证据位置。
    """
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", tier1_results_declared=0, mechanical_half=True)
    rows = rows_of(document, "tier1_results", "tier1-runtime")
    violations = []
    for index, row in enumerate(rows):
        conclusion = row.get("conclusion")
        if conclusion not in {"PASS", "FAIL", "NOT_RUN", "BLOCKED", "NOT_APPLICABLE"}:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"tier1-runtime.tier1_results 第 {index} 行 conclusion 非法: {conclusion!r}",
            )
        problems = []
        if not _nonempty_str(row.get("subject_id")):
            problems.append("subject_id_empty")
        if conclusion in {"PASS", "FAIL"} and not _nonempty_str(row.get("evidence_location")):
            problems.append("evidence_location_empty")
        if conclusion in {"NOT_RUN", "BLOCKED", "NOT_APPLICABLE"} and not _nonempty_str(
            row.get("not_run_reason")
        ):
            problems.append("not_run_reason_empty")
        if problems:
            violations.append({"index": index, "subject": row.get("subject_id"), "problems": problems})
    if violations:
        return result("FAIL", tier1_result_record_violations=violations, mechanical_half=True)
    return result("PASS", tier1_results=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# TIER2：第二档行为验证（tier2-behavior）
# ---------------------------------------------------------------------------


def _tier2_behavior(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "tier2-behavior")


def check_tier2_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档覆盖每项稳定公共能力的行为矩阵。

    机械断言：已声明能力行为矩阵必须为十类行为逐一给出样例或基于方法
    契约的不适用理由。
    """
    document = _tier2_behavior(ctx)
    if document is None:
        return result("PASS", capability_matrices_declared=0, mechanical_half=True)
    rows = rows_of(document, "capability_matrices", "tier2-behavior")
    violations = []
    for index, row in enumerate(rows):
        behaviors = _object_field(row, "behaviors", "tier2-behavior.capability_matrices")
        if behaviors is None:
            violations.append(
                {"index": index, "capability": row.get("capability"),
                 "problem": "behaviors_missing"}
            )
            continue
        problems = []
        for kind in TIER2_BEHAVIOR_KINDS:
            cell = behaviors.get(kind)
            if not isinstance(cell, dict):
                problems.append(f"{kind}:cell_missing")
                continue
            samples = cell.get("samples")
            if not _nonneg_int(samples):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    f"tier2-behavior.capability_matrices.behaviors.{kind}.samples 必须是非负整数",
                )
            if samples < 1 and not _nonempty_str(cell.get("not_applicable_reason")):
                problems.append(f"{kind}:no_sample_and_no_contract_reason")
        if problems:
            violations.append(
                {"index": index, "capability": row.get("capability"), "problems": problems}
            )
    if violations:
        return result("FAIL", behavior_matrix_violations=violations, mechanical_half=True)
    return result("PASS", capability_matrices=len(rows), mechanical_half=True)


def check_tier2_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档四平台使用共同业务验收黑盒执行。

    机械断言：已声明跨平台行为执行必须覆盖四个必需平台、使用相同业务
    验收条件、黑盒执行，且不得读取目标内部实现来改变验收。
    """
    document = _tier2_behavior(ctx)
    if document is None:
        return result("PASS", cross_platform_execution_declared=False, mechanical_half=True)
    execution = document.get("cross_platform_execution")
    if execution is None:
        return result("PASS", cross_platform_execution_declared=False, mechanical_half=True)
    if not isinstance(execution, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier2-behavior.cross_platform_execution 必须是对象",
        )
    problems = []
    platforms = execution.get("platforms")
    if not isinstance(platforms, list) or not all(isinstance(item, str) for item in platforms):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier2-behavior.cross_platform_execution.platforms 必须是字符串数组",
        )
    missing_platforms = sorted(set(REQUIRED_PLATFORMS) - set(platforms))
    if missing_platforms:
        problems.append(f"missing_required_platforms:{missing_platforms}")
    if execution.get("same_business_acceptance") is not True:
        problems.append("business_acceptance_diverges")
    if execution.get("black_box_execution") is not True:
        problems.append("not_black_box")
    if execution.get("reads_target_internals_to_change_acceptance") is True:
        problems.append("reads_target_internals_to_change_acceptance")
    if problems:
        return result("FAIL", cross_platform_execution_problems=problems, mechanical_half=True)
    return result("PASS", platforms=sorted(set(platforms)), mechanical_half=True)


def _behavior_runs(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _tier2_behavior(ctx)
    if document is None:
        return None
    return rows_of(document, "behavior_runs", "tier2-behavior")


def check_tier2_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档分离执行者与独立审阅者。

    机械断言：已声明行为运行必须给出执行者与独立审阅者；执行者不得作为
    唯一审阅者，自报结果不得独立证明成功。
    """
    rows = _behavior_runs(ctx)
    if rows is None:
        return result("PASS", behavior_runs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if not _nonempty_str(row.get("executor")):
            problems.append("executor_empty")
        if not _nonempty_str(row.get("independent_reviewer")):
            problems.append("independent_reviewer_empty")
        if row.get("executor_is_sole_reviewer") is True:
            problems.append("executor_is_sole_reviewer")
        if row.get("self_report_only") is True:
            problems.append("self_report_only")
        if problems:
            violations.append({"index": index, "run": row.get("run_id"), "problems": problems})
    if violations:
        return result("FAIL", reviewer_independence_violations=violations, mechanical_half=True)
    return result("PASS", behavior_runs=len(rows), mechanical_half=True)


def check_tier2_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档锁定可重放执行条件。

    机械断言：已声明行为运行必须锁定输入样例、预期结果、执行器、模型、
    平台及客户端版本、目标包摘要、方法契约摘要和结果证据。
    """
    rows = _behavior_runs(ctx)
    if rows is None:
        return result("PASS", behavior_runs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        lock = _object_field(row, "replay_lock", "tier2-behavior.behavior_runs")
        if lock is None:
            violations.append(
                {"index": index, "run": row.get("run_id"), "problem": "replay_lock_missing"}
            )
            continue
        missing = [field for field in TIER2_REPLAY_LOCK_FIELDS if field not in lock]
        if missing:
            violations.append(
                {"index": index, "run": row.get("run_id"), "missing": missing}
            )
    if violations:
        return result("FAIL", replay_lock_violations=violations, mechanical_half=True)
    return result("PASS", behavior_runs=len(rows), mechanical_half=True)


def check_tier2_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档记录预期与实际结果差异。

    机械断言：已声明行为运行必须保存可重放输入、环境、预期结果、实际
    结果、差异判定和证据位置；只保存最终通过标签不构成行为证据。
    """
    rows = _behavior_runs(ctx)
    if rows is None:
        return result("PASS", behavior_runs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("final_pass_label_only") is True:
            violations.append(
                {"index": index, "run": row.get("run_id"), "problem": "final_pass_label_only"}
            )
            continue
        missing = [
            field
            for field in (
                "replayable_input",
                "environment",
                "expected_result",
                "actual_result",
                "difference_judgement",
                "evidence_location",
            )
            if field not in row
        ]
        if missing:
            violations.append(
                {"index": index, "run": row.get("run_id"), "missing": missing}
            )
    if violations:
        return result("FAIL", behavior_record_violations=violations, mechanical_half=True)
    return result("PASS", behavior_runs=len(rows), mechanical_half=True)


def check_tier2_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档验证兼容和受控扩展。

    机械断言：已声明兼容验证必须覆盖四类承诺范围；未承诺的兼容范围必须
    明确标记。
    """
    document = _tier2_behavior(ctx)
    if document is None:
        return result("PASS", compatibility_verifications_declared=0, mechanical_half=True)
    rows = rows_of(document, "compatibility_verifications", "tier2-behavior")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        scope = row.get("scope")
        if scope not in TIER2_COMPATIBILITY_SCOPES:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"tier2-behavior.compatibility_verifications 第 {index} 行 scope 非法: {scope!r}",
            )
        if row.get("verified_in_scope") is not True:
            problems.append("not_verified_in_scope")
        if row.get("uncommitted_scope_marked") is not True:
            problems.append("uncommitted_scope_not_marked")
        if problems:
            violations.append({"index": index, "scope": scope, "problems": problems})
    if violations:
        return result("FAIL", compatibility_verification_violations=violations, mechanical_half=True)
    return result("PASS", compatibility_verifications=len(rows), mechanical_half=True)


def check_tier2_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档每轮隔离或清理副作用。

    机械断言：已声明行为运行必须使用干净隔离环境，或在结束后完成声明的
    清理与回滚；后续样例不得读取未声明残留。
    """
    rows = _behavior_runs(ctx)
    if rows is None:
        return result("PASS", behavior_runs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        problems = []
        isolated = row.get("clean_isolated_environment") is True
        cleanup = (
            row.get("cleanup_completed") is True and row.get("rollback_completed") is True
        )
        if not isolated and not cleanup:
            problems.append("neither_isolated_nor_cleaned")
        if row.get("reads_undeclared_residue") is True:
            problems.append("reads_undeclared_residue")
        if problems:
            violations.append({"index": index, "run": row.get("run_id"), "problems": problems})
    if violations:
        return result("FAIL", side_effect_handling_violations=violations, mechanical_half=True)
    return result("PASS", behavior_runs=len(rows), mechanical_half=True)


def check_tier2_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档必须具有回归证据。

    机械断言：已通过独立审阅的行为运行必须进入绑定技能族版本、平台和
    目标包摘要的回归集合，且契约或实现变化后按影响关系重新执行。
    """
    rows = _behavior_runs(ctx)
    if rows is None:
        return result("PASS", behavior_runs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("passed_independent_review") is not True:
            continue
        problems = []
        regression = _object_field(row, "regression_set", "tier2-behavior.behavior_runs")
        if regression is None:
            problems.append("regression_set_missing")
        else:
            missing = [
                field
                for field in ("bound_family_version", "bound_platform", "bound_target_package_digest")
                if not _nonempty_str(regression.get(field))
            ]
            if missing:
                problems.append(f"regression_bindings_missing:{missing}")
        if row.get("rerun_on_contract_or_implementation_change") is not True:
            problems.append("no_rerun_on_change")
        if problems:
            violations.append({"index": index, "run": row.get("run_id"), "problems": problems})
    if violations:
        return result("FAIL", regression_evidence_violations=violations, mechanical_half=True)
    return result("PASS", behavior_runs=len(rows), mechanical_half=True)


def check_tier2_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """第二档结论只适用于锁定条件。

    机械断言：已声明第二档结论必须限于锁定版本、平台、模型、样例和执行
    条件；不得外推为所有模型、平台、输入或未来版本同等语义质量。
    """
    document = _tier2_behavior(ctx)
    if document is None:
        return result("PASS", conclusion_scope_declared=False, mechanical_half=True)
    scope = document.get("conclusion_scope")
    if scope is None:
        return result("PASS", conclusion_scope_declared=False, mechanical_half=True)
    if not isinstance(scope, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "tier2-behavior.conclusion_scope 必须是对象"
        )
    problems = []
    if scope.get("limited_to_locked_conditions") is not True:
        problems.append("not_limited_to_locked_conditions")
    if scope.get("extrapolates_beyond_locked_conditions") is True:
        problems.append("extrapolates_beyond_locked_conditions")
    if problems:
        return result("FAIL", conclusion_scope_problems=problems, mechanical_half=True)
    return result("PASS", conclusion_scope_limited=True, mechanical_half=True)


# ---------------------------------------------------------------------------
# TIER3：第三档运行观察与韧性（tier3-runtime-observation）
# ---------------------------------------------------------------------------


def _tier3(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "tier3-runtime-observation")


def check_tier3_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档记录完整运行观察事实。

    机械断言：已声明者必须记录带时间和进程身份的流事件、心跳、阶段制品、
    验证进程、长工具租约和业务进展；不得以最终日志或目标自报代替。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", observation_facts_declared=False, mechanical_half=True)
    facts = document.get("observation_facts")
    if facts is None:
        return result("PASS", observation_facts_declared=False, mechanical_half=True)
    if not isinstance(facts, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier3-runtime-observation.observation_facts 必须是对象",
        )
    problems = [
        field for field in TIER3_OBSERVATION_FACT_FIELDS if facts.get(field) is not True
    ]
    if facts.get("final_log_or_self_report_only") is True:
        problems.append("final_log_or_self_report_only")
    if problems:
        return result("FAIL", observation_fact_problems=problems, mechanical_half=True)
    return result("PASS", observation_facts_declared=True, mechanical_half=True)


def check_tier3_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档对主要运行异常给出机器结论。

    机械断言：已声明者必须对八类主要运行异常声明机器可判定的异常类别、
    证据和处置状态。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", anomaly_machine_conclusions_declared=False, mechanical_half=True)
    conclusions = document.get("anomaly_machine_conclusions")
    if conclusions is None:
        return result("PASS", anomaly_machine_conclusions_declared=False, mechanical_half=True)
    if not isinstance(conclusions, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier3-runtime-observation.anomaly_machine_conclusions 必须是对象",
        )
    missing = [
        category for category in TIER3_ANOMALY_CATEGORIES if conclusions.get(category) is not True
    ]
    if missing:
        return result("FAIL", anomaly_conclusions_missing=missing, mechanical_half=True)
    return result("PASS", anomaly_categories=len(TIER3_ANOMALY_CATEGORIES), mechanical_half=True)


def check_tier3_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档具备完整恢复机制集合。

    机械断言：已声明者必须支持七类恢复机制；不适用的机制必须记录方法级
    理由。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", recovery_mechanisms_declared=False, mechanical_half=True)
    mechanisms = document.get("recovery_mechanisms")
    if mechanisms is None:
        return result("PASS", recovery_mechanisms_declared=False, mechanical_half=True)
    if not isinstance(mechanisms, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier3-runtime-observation.recovery_mechanisms 必须是对象",
        )
    problems = []
    for mechanism in TIER3_RECOVERY_MECHANISMS:
        cell = mechanisms.get(mechanism)
        if cell is True:
            continue
        if not isinstance(cell, dict) or not _nonempty_str(cell.get("not_applicable_reason")):
            problems.append(f"{mechanism}:unsupported_without_method_level_reason")
    if problems:
        return result("FAIL", recovery_mechanism_problems=problems, mechanical_half=True)
    return result("PASS", recovery_mechanisms=len(TIER3_RECOVERY_MECHANISMS), mechanical_half=True)


def check_tier3_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档执行受控故障注入。

    机械断言：已声明故障注入必须在隔离环境中执行、与方法风险相符，并验证
    预期检测与处置；故障类别取七类词表。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", fault_injections_declared=0, mechanical_half=True)
    rows = rows_of(document, "fault_injections", "tier3-runtime-observation")
    violations = []
    for index, row in enumerate(rows):
        kind = row.get("fault_kind")
        if kind not in TIER3_FAULT_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"tier3-runtime-observation.fault_injections 第 {index} 行 fault_kind 非法: {kind!r}",
            )
        problems = []
        if row.get("environment_isolated") is not True:
            problems.append("environment_not_isolated")
        if row.get("risk_proportionate") is not True:
            problems.append("risk_not_proportionate")
        if row.get("detection_verified") is not True:
            problems.append("detection_not_verified")
        if row.get("disposition_verified") is not True:
            problems.append("disposition_not_verified")
        if problems:
            violations.append({"index": index, "fault_kind": kind, "problems": problems})
    if violations:
        return result("FAIL", fault_injection_violations=violations, mechanical_half=True)
    return result("PASS", fault_injections=len(rows), mechanical_half=True)


def check_tier3_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档验证并发降级回滚和幂等。

    机械断言：已声明并发/降级/恢复验证必须成立写入集合不冲突、汇合结果
    完整、降级语义明确、回滚有效、重复恢复幂等。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", concurrency_verifications_declared=0, mechanical_half=True)
    rows = rows_of(document, "concurrency_degradation_verifications", "tier3-runtime-observation")
    violations = []
    for index, row in enumerate(rows):
        missing = [
            field for field in TIER3_CONCURRENCY_FIELDS if row.get(field) is not True
        ]
        if missing:
            violations.append(
                {"index": index, "capability": row.get("capability"), "missing": missing}
            )
    if violations:
        return result("FAIL", concurrency_verification_violations=violations, mechanical_half=True)
    return result("PASS", concurrency_verifications=len(rows), mechanical_half=True)


def check_tier3_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档维护持续回归矩阵。

    机械断言：已声明回归矩阵必须按技能族版本、目标发行物摘要、平台、
    模型、运行器和测试样例维护，并记录每个组合的最后有效证据。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", regression_matrix_declared=0, mechanical_half=True)
    rows = rows_of(document, "regression_matrix", "tier3-runtime-observation")
    violations = []
    for index, row in enumerate(rows):
        missing = [field for field in TIER3_REGRESSION_MATRIX_FIELDS if not row.get(field)]
        if missing:
            violations.append({"index": index, "missing": missing})
    if violations:
        return result("FAIL", regression_matrix_violations=violations, mechanical_half=True)
    return result("PASS", regression_matrix_rows=len(rows), mechanical_half=True)


def check_tier3_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档识别不稳定退化和证据过期。

    机械断言：已声明者必须声明识别同条件重复结果不稳定、相对历史版本
    退化和证据因依赖变化过期；不得用一次偶然成功覆盖失败历史。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", stability_detection_declared=False, mechanical_half=True)
    detection = document.get("stability_degradation_detection")
    if detection is None:
        return result("PASS", stability_detection_declared=False, mechanical_half=True)
    if not isinstance(detection, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier3-runtime-observation.stability_degradation_detection 必须是对象",
        )
    problems = []
    for field in (
        "detects_unstable_repetition",
        "detects_regression_vs_history",
        "detects_expired_evidence",
    ):
        if detection.get(field) is not True:
            problems.append(f"{field}_not_declared")
    if detection.get("accidental_success_overrides_failure_history") is True:
        problems.append("accidental_success_overrides_failure_history")
    if problems:
        return result("FAIL", stability_detection_problems=problems, mechanical_half=True)
    return result("PASS", stability_detection_declared=True, mechanical_half=True)


def check_tier3_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """自学习评估与目标运行上下文隔离。

    机械断言：已声明接入技能自学习必须隔离评估材料、隐藏验收、审阅依据
    和目标技能运行上下文；完成失败归因后才能决定修复目标。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", self_learning_isolation_declared=False, mechanical_half=True)
    isolation = document.get("self_learning_isolation")
    if isolation is None:
        return result("PASS", self_learning_isolation_declared=False, mechanical_half=True)
    if not isinstance(isolation, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier3-runtime-observation.self_learning_isolation 必须是对象",
        )
    problems = []
    for field in (
        "evaluation_materials_isolated",
        "hidden_acceptance_isolated",
        "review_basis_isolated",
        "run_context_isolated",
    ):
        if isolation.get(field) is not True:
            problems.append(f"{field}_not_declared")
    if isolation.get("failure_attribution_completed_before_fix_decision") is not True:
        problems.append("fix_decision_before_failure_attribution")
    if problems:
        return result("FAIL", self_learning_isolation_problems=problems, mechanical_half=True)
    return result("PASS", self_learning_isolation_declared=True, mechanical_half=True)


def check_tier3_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """长耗时本身不构成运行失败。

    机械断言：已声明长任务政策不得只因整体耗时判定失败；无进展判定必须
    依据连续静默且缺少事件/心跳/阶段制品/验证进程/有效长工具租约的证据。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", long_task_policy_declared=False, mechanical_half=True)
    policy = document.get("long_task_policy")
    if policy is None:
        return result("PASS", long_task_policy_declared=False, mechanical_half=True)
    if not isinstance(policy, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "tier3-runtime-observation.long_task_policy 必须是对象",
        )
    problems = []
    if policy.get("fails_on_duration_alone") is True:
        problems.append("fails_on_duration_alone")
    if policy.get("no_progress_judgement_requires_silence_evidence") is not True:
        problems.append("no_progress_judgement_without_silence_evidence")
    if problems:
        return result("FAIL", long_task_policy_problems=problems, mechanical_half=True)
    return result("PASS", long_task_policy_declared=True, mechanical_half=True)


def check_tier3_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """第三档至少证明一次完整故障恢复闭环。

    机械断言：每项声明第三档韧性的能力必须至少一次受控故障被检测、执行
    有界恢复、清理副作用并通过独立复验的端到端记录。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", resilience_claims_declared=0, mechanical_half=True)
    claims = rows_of(document, "resilience_claims", "tier3-runtime-observation")
    loops = rows_of(document, "recovery_closed_loops", "tier3-runtime-observation")
    loops_by_capability: dict[str, list[dict[str, Any]]] = {}
    for loop in loops:
        capability = loop.get("capability")
        if not _nonempty_str(capability):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "tier3-runtime-observation.recovery_closed_loops.capability 必须是非空字符串",
            )
        loops_by_capability.setdefault(capability, []).append(loop)
    violations = []
    for claim in claims:
        capability = claim.get("capability")
        if not _nonempty_str(capability):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "tier3-runtime-observation.resilience_claims.capability 必须是非空字符串",
            )
        candidates = [
            loop
            for loop in loops_by_capability.get(capability, [])
            if loop.get("fault_detected") is True
            and loop.get("bounded_recovery_executed") is True
            and loop.get("side_effects_cleaned") is True
            and loop.get("independent_reverification_passed") is True
        ]
        if not candidates:
            violations.append({"capability": capability, "problem": "no_complete_recovery_loop"})
    if violations:
        return result("FAIL", resilience_claims_without_closed_loop=violations, mechanical_half=True)
    return result("PASS", resilience_claims=len(claims), mechanical_half=True)


def check_tier3_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """监控或重试脚本存在不能证明第三档。

    机械断言：已声明第三档证明必须携带真实异常、恢复和复验证据；只凭
    机制候选（文件/监控器/重试脚本/恢复命令存在）不得声明第三档已证明。
    """
    document = _tier3(ctx)
    if document is None:
        return result("PASS", tier3_proof_claims_declared=0, mechanical_half=True)
    rows = rows_of(document, "tier3_proof_claims", "tier3-runtime-observation")
    violations = []
    for index, row in enumerate(rows):
        if row.get("claims_tier3_proven") is not True:
            continue
        problems = []
        if row.get("has_real_anomaly_evidence") is not True:
            problems.append("no_real_anomaly_evidence")
        if row.get("has_recovery_evidence") is not True:
            problems.append("no_recovery_evidence")
        if row.get("has_reverification_evidence") is not True:
            problems.append("no_reverification_evidence")
        if row.get("evidence_is_mechanism_candidate_only") is True:
            problems.append("mechanism_candidate_only")
        if problems:
            violations.append(
                {"index": index, "capability": row.get("capability"), "problems": problems}
            )
    if violations:
        return result("FAIL", tier3_proofs_without_real_evidence=violations, mechanical_half=True)
    return result("PASS", tier3_proof_claims=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# 登记
# ---------------------------------------------------------------------------

CHECKS = {
    "SFA-CONTEXT-003": check_context_003,
    "SFA-CONTEXT-005": check_context_005,
    "SFA-CONTEXT-007": check_context_007,
    "SFA-CONTEXT-008": check_context_008,
    "SFA-CONTEXT-009": check_context_009,
    "SFA-CONTEXT-010": check_context_010,
    "SFA-CONTEXT-011": check_context_011,
    "SFA-CONTEXT-012": check_context_012,
    "SFA-CONTEXT-013": check_context_013,
    "SFA-CONTEXT-014": check_context_014,
    "SFA-CONTEXT-015": check_context_015,
    "SFA-CONTEXT-016": check_context_016,
    "SFA-CONTEXT-017": check_context_017,
    "SFA-CONTEXT-021": check_context_021,
    "SFA-CONTEXT-022": check_context_022,
    "SFA-CONTEXT-023": check_context_023,
    "SFA-CONTEXT-024": check_context_024,
    "SFA-CONTEXT-025": check_context_025,
    "SFA-CONTEXT-028": check_context_028,
    "SFA-CONTEXT-030": check_context_030,
    "SFA-CONTEXT-031": check_context_031,
    "SFA-ISOLATION-008": check_isolation_008,
    "SFA-RUNTIMEOBS-001": check_runtimeobs_001,
    "SFA-RUNTIMEOBS-002": check_runtimeobs_002,
    "SFA-RUNTIMEOBS-003": check_runtimeobs_003,
    "SFA-SELFHEAL-010": check_selfheal_010,
    "SFA-SELFHEAL-011": check_selfheal_011,
    "SFA-STAGEISO-001": check_stageiso_001,
    "SFA-STAGEISO-004": check_stageiso_004,
    "SFA-STAGEISO-005": check_stageiso_005,
    "SFA-TIER1-001": check_tier1_001,
    "SFA-TIER1-002": check_tier1_002,
    "SFA-TIER1-003": check_tier1_003,
    "SFA-TIER1-004": check_tier1_004,
    "SFA-TIER1-005": check_tier1_005,
    "SFA-TIER1-006": check_tier1_006,
    "SFA-TIER1-007": check_tier1_007,
    "SFA-TIER2-001": check_tier2_001,
    "SFA-TIER2-002": check_tier2_002,
    "SFA-TIER2-003": check_tier2_003,
    "SFA-TIER2-004": check_tier2_004,
    "SFA-TIER2-005": check_tier2_005,
    "SFA-TIER2-006": check_tier2_006,
    "SFA-TIER2-007": check_tier2_007,
    "SFA-TIER2-008": check_tier2_008,
    "SFA-TIER2-009": check_tier2_009,
    "SFA-TIER3-001": check_tier3_001,
    "SFA-TIER3-002": check_tier3_002,
    "SFA-TIER3-003": check_tier3_003,
    "SFA-TIER3-004": check_tier3_004,
    "SFA-TIER3-005": check_tier3_005,
    "SFA-TIER3-006": check_tier3_006,
    "SFA-TIER3-007": check_tier3_007,
    "SFA-TIER3-008": check_tier3_008,
    "SFA-TIER3-009": check_tier3_009,
    "SFA-TIER3-010": check_tier3_010,
    "SFA-TIER3-011": check_tier3_011,
}
