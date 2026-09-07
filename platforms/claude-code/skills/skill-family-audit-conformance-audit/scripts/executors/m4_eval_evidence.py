"""M4 执行族：评估证据与门禁（W2-B1 共 20 条）。

证据面：项目治理声明 evaluation-report.json（逐规则评估行）与
gate-policy.json（门禁政策）。两类文档均约束"已声明者"：缺失 = 无可判
违反事实 → PASS；形状非法失败关闭。

评估行状态词表沿用 contracts.EVALUATION_ROW_STATUSES；所有 PASS 行必须
携带真实运行证据摘要（SFA-ASSESSMENT-004 的执行证据义务）。
"""
from __future__ import annotations

import hashlib
from typing import Any

from .contracts import (
    EVALUATION_ROW_STATUSES,
    ExecutorEvidenceError,
    governance_dir,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

_NON_PASS_EXECUTION = {
    "BLOCKED", "NOT_RUN", "EVIDENCE_MISSING", "TIMEOUT", "CANCELLED", "EXCEPTION",
}
_NA_BASIS_KINDS = {"locked_rule", "versioned_policy", "verifiable_target_fact"}


# ---------------------------------------------------------------------------
# 逐方法子结果（受管机械方法 digest_verification + schema_validation）
# ---------------------------------------------------------------------------


def _method_row(method: str, status: str, source: str, **evidence: Any) -> dict[str, Any]:
    return {
        "check_method": method,
        "status": status,
        "observation_source": source,
        "evidence": evidence or {"reason": status.lower()},
    }


def _finish(rows: list[dict[str, Any]], **evidence: Any) -> dict[str, Any]:
    """从逐方法行确定性推导聚合状态，与 contracts.validate_method_subresults 一致。"""
    statuses = {row["status"] for row in rows}
    if "FAIL" in statuses:
        status = "FAIL"
    elif "EVIDENCE_MISSING" in statuses or "NOT_RUN" in statuses:
        status = "EVIDENCE_MISSING"
    elif statuses == {"NOT_APPLICABLE"}:
        status = "NOT_APPLICABLE"
    elif statuses == {"PASS"}:
        status = "PASS"
    else:
        raise ExecutorEvidenceError(
            "METHOD_RESULT_COMBINATION_INVALID", repr(sorted(statuses))
        )
    return {
        "status": status,
        "evidence": dict(evidence),
        "check_method_subresults": rows,
    }


def _schema_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "schema_validation", status, "executor_schema_validation_observation", **evidence
    )


def _digest_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "digest_verification", status, "executor_digest_verification_observation", **evidence
    )


def _doc_digest_row(
    ctx: dict[str, Any], names: tuple[str, ...], status: str = "PASS", **evidence: Any
) -> dict[str, Any]:
    """字节级完整性观察：本次执行真实读取的治理声明文档（存在性与 sha256）。"""
    observations = []
    for name in names:
        path = governance_dir(ctx) / f"{name}.json"
        if path.is_file() and not path.is_symlink():
            observations.append({
                "document": name,
                "present": True,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
        else:
            observations.append({"document": name, "present": False})
    return _digest_row(status, documents=observations, **evidence)


def _report_rows(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "evaluation-report")
    if document is None:
        return None
    rows = rows_of(document, "rows", "evaluation-report")
    for row in rows:
        if row.get("status") not in EVALUATION_ROW_STATUSES:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"evaluation-report 行状态非法: {row.get('status')!r}",
            )
    return rows


def _gate_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "gate-policy")


def check_assessment_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """未实际运行的检查项不得报告通过。

    机械断言：评估行 status=PASS 必须携带 64 位十六进制 run_evidence_digest；
    无运行证据的 PASS 即违反。
    """
    rows = _report_rows(ctx)
    if rows is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    violations = [
        {"rule_id": row.get("rule_id")}
        for row in rows
        if row.get("status") == "PASS" and not is_hex64(row.get("run_evidence_digest"))
    ]
    if violations:
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
                _digest_row(
                    "FAIL",
                    reason="digest_violations",
                    violations=violations,
                ),
            ],
            pass_without_run_evidence=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
            _digest_row("PASS", reason="digest_checks_passed", rows_checked=len(rows)),
        ],
        rows_checked=len(rows),
    )


def check_case_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """高风险语义结论必须由异源复核。

    机械断言：标记 high_risk_semantic_conclusion=true 的行必须声明
    independent_review，且复核来源与产生来源不同；同源或缺失即违反。
    """
    rows = _report_rows(ctx)
    if rows is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    violations = []
    for row in rows:
        if row.get("high_risk_semantic_conclusion") is not True:
            continue
        review = row.get("independent_review")
        if not isinstance(review, dict):
            violations.append({"rule_id": row.get("rule_id"), "reason": "review_missing"})
            continue
        if (
            not isinstance(review.get("source"), str)
            or not review.get("source")
            or review.get("source") == row.get("producer_source")
        ):
            violations.append({"rule_id": row.get("rule_id"), "reason": "same_source_review"})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            high_risk_conclusions_unreviewed=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        rows_checked=len(rows),
    )


def check_case_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """判例泄漏后本轮有效性评估必须作废并更换材料重跑。

    机械断言：声明 leaked_materials 非空时，受影响轮次必须 invalidated=true
    且 re_run_with_new_materials=true。
    """
    document = load_governance_document(ctx, "evaluation-report")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    leaked = document.get("leaked_materials")
    if leaked is None:
        leaked = []
    if not isinstance(leaked, list):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "evaluation-report.leaked_materials 必须是数组"
        )
    if not leaked:
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed", leaked_materials=0),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            leaked_materials=0,
        )
    rounds = rows_of(document, "affected_rounds", "evaluation-report")
    violations = [
        {"round": row.get("round_id")}
        for row in rounds
        if row.get("invalidated") is not True or row.get("re_run_with_new_materials") is not True
    ]
    if violations or not rounds:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            leaked_rounds_not_invalidated=violations,
            affected_round_count=len(rounds),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", invalidated_rounds=len(rounds)
            ),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        invalidated_rounds=len(rounds),
    )


def check_eval_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """执行异常不等同于规则失败，也不得转换为通过。

    机械断言：执行状态处于异常/超时/取消/未运行/证据不足类的行，verdict
    必须 ∈ {blocked, not_run}；判为 fail 或 pass 即违反。
    """
    rows = _report_rows(ctx)
    if rows is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    violations = []
    for row in rows:
        status = row.get("status")
        if status not in _NON_PASS_EXECUTION:
            continue
        if row.get("verdict") not in {"blocked", "not_run"}:
            violations.append({"rule_id": row.get("rule_id"), "status": status, "verdict": row.get("verdict")})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            execution_exceptions_misjudged=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        rows_checked=len(rows),
    )


def check_eval_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """被测项目不得自行决定必需规则不适用。

    机械断言：status=NOT_APPLICABLE 的行必须携带 basis_kind ∈ 锁定规则 /
    版本化政策 / 可验证目标事实；self_declared 或缺失即违反。
    """
    rows = _report_rows(ctx)
    if rows is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    violations = [
        {"rule_id": row.get("rule_id"), "basis_kind": row.get("basis_kind")}
        for row in rows
        if row.get("status") == "NOT_APPLICABLE" and row.get("basis_kind") not in _NA_BASIS_KINDS
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            self_declared_not_applicable=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        rows_checked=len(rows),
    )


def check_eval_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """空发现不得推导规则通过。

    机械断言：findings_count=0 的行给出 verdict=pass 时，必须同时声明
    applicability_confirmed / implementation_valid / execution_complete /
    evidence_satisfied 四项为 true。
    """
    rows = _report_rows(ctx)
    if rows is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    required_flags = (
        "applicability_confirmed",
        "implementation_valid",
        "execution_complete",
        "evidence_satisfied",
    )
    violations = [
        {"rule_id": row.get("rule_id"), "missing_flags": [flag for flag in required_flags if row.get(flag) is not True]}
        for row in rows
        if row.get("findings_count") == 0
        and row.get("verdict") == "pass"
        and not all(row.get(flag) is True for flag in required_flags)
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            empty_findings_derived_pass=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        rows_checked=len(rows),
    )


def check_eval_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """评估必须冻结适用规则分母，后续不得静默改变。

    机械断言：报告必须声明 frozen_denominator（目标/规范发布/平台/对象
    类型/政策/规则集合六要素），且 filters 与 gates 段引用的分母摘要一致。
    """
    document = load_governance_document(ctx, "evaluation-report")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    denominator = document.get("frozen_denominator")
    if not isinstance(denominator, dict):
        return _finish(
            [
                _schema_row("FAIL", reason="frozen_denominator_missing"),
                _digest_row("PASS", reason="no_declared_denominator_digest"),
            ],
            reason="frozen_denominator_missing",
        )
    required = {"target_digest", "spec_release", "platform", "object_type", "policy_digest", "rule_set"}
    missing = sorted(required - set(denominator))
    if missing:
        return _finish(
            [
                _schema_row("FAIL", reason="denominator_fields_missing", fields=missing),
                _digest_row("PASS", reason="no_declared_denominator_digest"),
            ],
            denominator_fields_missing=missing,
        )
    denominator_digest = denominator.get("digest")
    if not is_hex64(denominator_digest):
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed", fields=len(required)),
                _digest_row("FAIL", reason="denominator_digest_invalid"),
            ],
            reason="denominator_digest_invalid",
        )
    drift = [
        section
        for section in ("filters", "gates")
        for row in rows_of(document, section, "evaluation-report")
        if row.get("denominator_digest") not in (None, denominator_digest)
    ]
    if drift:
        return _finish(
            [
                _schema_row("FAIL", reason="denominator_drift", drift_in=drift),
                _digest_row(
                    "PASS",
                    reason="digest_checks_passed",
                    consumed_denominator_digest=denominator_digest,
                ),
            ],
            denominator_drift_in=drift,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", fields=len(required)),
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                consumed_denominator_digest=denominator_digest,
            ),
        ],
        denominator_digest=denominator_digest,
    )


def check_gate_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """空分母、未知规则、全跳过或全误标不适用不得产生通过。

    机械断言：门禁声明 outcome=pass 时，denominator_size 必须 >0、
    unknown_rules 为空且不得 all_skipped/all_not_applicable。
    """
    policy = _gate_policy(ctx)
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_gate_policy"),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_declared=False,
        )
    decisions = rows_of(policy, "decisions", "gate-policy")
    violations = []
    for index, row in enumerate(decisions):
        if row.get("outcome") != "pass":
            continue
        reasons = []
        if not isinstance(row.get("denominator_size"), int) or row.get("denominator_size") <= 0:
            reasons.append("empty_denominator")
        unknown = row.get("unknown_rules") or []
        if not isinstance(unknown, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "gate-policy.unknown_rules 必须是数组"
            )
        if unknown:
            reasons.append("unknown_rules_present")
        if row.get("all_skipped") is True or row.get("all_not_applicable") is True:
            reasons.append("all_skipped_or_not_applicable")
        if row.get("filter_error") is True:
            reasons.append("filter_error")
        if reasons:
            violations.append({"index": index, "gate": row.get("gate_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            pass_from_invalid_denominator=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", decisions_checked=len(decisions)),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        decisions_checked=len(decisions),
    )


def check_gate_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """结果冲突或关键身份缺失时门禁必须受阻。

    机械断言：声明存在冲突/非法状态/非法阈值/缺失摘要/缺失修订/政策不明/
    消费者版本未知之一而 outcome!=blocked 即违反。
    """
    policy = _gate_policy(ctx)
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_gate_policy"),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_declared=False,
        )
    decisions = rows_of(policy, "decisions", "gate-policy")
    defect_flags = (
        "duplicate_conflict",
        "invalid_status",
        "invalid_threshold",
        "missing_rule_digest",
        "missing_implementation_digest",
        "missing_rule_revision",
        "gate_policy_unclear",
        "consumer_version_unknown",
    )
    violations = []
    for index, row in enumerate(decisions):
        defects = [flag for flag in defect_flags if row.get(flag) is True]
        if defects and row.get("outcome") != "blocked":
            violations.append({"index": index, "gate": row.get("gate_id"), "defects": defects})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_not_blocked_on_defects=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", decisions_checked=len(decisions)),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        decisions_checked=len(decisions),
    )


def check_gate_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """展示过滤不得改变门禁输入与冻结分母。

    机械断言：已声明展示过滤器必须 affects_denominator=false；声明改变
    分母即违反。
    """
    policy = _gate_policy(ctx)
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_gate_policy"),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_declared=False,
        )
    filters = rows_of(policy, "display_filters", "gate-policy")
    violations = [
        {"filter": row.get("filter_id")}
        for row in filters
        if row.get("affects_denominator") is not False
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            display_filters_mutate_denominator=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", display_filters_checked=len(filters)
            ),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        display_filters_checked=len(filters),
    )


def _run_record(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "run-record")


def check_observe_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """观察器必须使用专属身份且只追加证据。

    机械断言：已声明观察器身份必须与执行主体不同、write_mode=append_only，
    且不得声明修改/删除既有事件。
    """
    record = _run_record(ctx)
    if record is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_run_record"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_record_declared=False,
        )
    observer = record.get("observer")
    if not isinstance(observer, dict):
        return _finish(
            [
                _schema_row("PASS", reason="observer_not_declared"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            observer_declared=False,
        )
    violations = []
    if (
        not isinstance(observer.get("identity"), str)
        or not observer.get("identity")
        or observer.get("identity") == record.get("executor_identity")
    ):
        violations.append("observer_identity_not_distinct")
    if observer.get("write_mode") != "append_only":
        violations.append("write_mode_not_append_only")
    if observer.get("mutates_existing_events") is True:
        violations.append("mutates_existing_events")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            observer_boundary_violations=violations,
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                observer_identity=observer.get("identity"),
            ),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        observer_identity=observer.get("identity"),
        mechanical_half=True,
    )


def check_observe_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行身份必须由控制面生成、不可预测且绑定任务与候选。

    机械断言：已声明运行身份 generated_by=control_plane、unpredictable=true
    且绑定 task 与 candidate。
    """
    record = _run_record(ctx)
    if record is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_run_record"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_record_declared=False,
        )
    run_identity = record.get("run_identity")
    if not isinstance(run_identity, dict):
        return _finish(
            [
                _schema_row("PASS", reason="run_identity_not_declared"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_identity_declared=False,
        )
    violations = []
    if run_identity.get("generated_by") != "control_plane":
        violations.append("not_control_plane_generated")
    if run_identity.get("unpredictable") is not True:
        violations.append("predictable_or_reusable")
    if not run_identity.get("task") or not run_identity.get("candidate"):
        violations.append("task_candidate_binding_missing")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_identity_violations=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", generated_by="control_plane"),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        generated_by="control_plane",
    )


def check_observe_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """原始事件必须进入目标不可写的追加存储。

    机械断言：已声明证据存储 target_writable=false、observer_append_only=true、
    control_plane_seals=true；以中间文件替代原始事件流即违反。
    """
    record = _run_record(ctx)
    if record is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_run_record"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_record_declared=False,
        )
    storage = record.get("evidence_storage")
    if not isinstance(storage, dict):
        return _finish(
            [
                _schema_row("PASS", reason="evidence_storage_not_declared"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            evidence_storage_declared=False,
        )
    violations = []
    if storage.get("target_writable") is not False:
        violations.append("target_writable")
    if storage.get("observer_append_only") is not True:
        violations.append("observer_not_append_only")
    if storage.get("control_plane_seals") is not True:
        violations.append("control_plane_does_not_seal")
    if storage.get("raw_stream_is_intermediate_file") is True:
        violations.append("intermediate_file_replaces_raw_stream")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            evidence_storage_violations=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", storage="append_only_sealed"),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        storage="append_only_sealed",
    )


def check_observe_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """观察证据完整性异常时依赖行为必须受阻。

    机械断言：已声明完整性异常（序号断裂/摘要不符/身份不可验证/绑定不完整/
    存储被修改）时，dependent_actions 必须全部 blocked。
    """
    record = _run_record(ctx)
    if record is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_run_record"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_record_declared=False,
        )
    integrity = record.get("evidence_integrity")
    if not isinstance(integrity, dict):
        return _finish(
            [
                _schema_row("PASS", reason="integrity_not_declared"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            integrity_declared=False,
        )
    anomalies = [
        field
        for field in (
            "sequence_gap",
            "digest_mismatch",
            "identity_unverifiable",
            "run_binding_incomplete",
            "storage_modified",
        )
        if integrity.get(field) is True
    ]
    if not anomalies:
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed", anomalies=0),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            anomalies=0,
        )
    actions = rows_of(record, "dependent_actions", "run-record")
    unblocked = [
        {"action": row.get("action_id")}
        for row in actions
        if row.get("state") != "blocked"
    ]
    if unblocked or not actions:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=unblocked),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            anomalies=anomalies,
            unblocked_dependent_actions=unblocked,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                anomalies=anomalies,
                blocked_actions=len(actions),
            ),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        anomalies=anomalies,
        blocked_actions=len(actions),
    )


def check_observe_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """观察证据只在精确匹配且有效时复用。

    机械断言：已声明证据复用必须六轴全部 match、immutable=true 且
    within_validity=true；任一缺失或不符即违反。
    """
    record = _run_record(ctx)
    if record is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_run_record"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            run_record_declared=False,
        )
    reuse = record.get("evidence_reuse")
    if not isinstance(reuse, dict):
        return _finish(
            [
                _schema_row("PASS", reason="reuse_not_declared"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            reuse_declared=False,
        )
    axes = (
        "candidate_artifact",
        "task",
        "isolation_policy",
        "observer",
        "execution_environment",
        "policy_digest",
    )
    violations = [axis for axis in axes if reuse.get(axis) != "match"]
    if reuse.get("immutable") is not True:
        violations.append("not_immutable")
    if reuse.get("within_validity") is not True:
        violations.append("outside_validity")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            reuse_conditions_unmet=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", reuse_axes_matched=list(axes)
            ),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        reuse_axes_matched=list(axes),
    )


def _proof_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "proof-policy")


def check_proof_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """不得把所有阻断升级为架构分析。

    机械断言：已声明阻断处置映射中，仅根因属职责/权威/边界/不可逆结构
    变化者可携带 architecture_analysis=true；其余携带即违反。
    """
    policy = _proof_policy(ctx)
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_proof_policy"),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            proof_policy_declared=False,
        )
    rows = rows_of(policy, "block_handling", "proof-policy")
    structural = {"responsibility", "authority", "boundary", "irreversible_structure"}
    violations = [
        {"block": row.get("block_id"), "root_cause": row.get("root_cause")}
        for row in rows
        if row.get("architecture_analysis") is True and row.get("root_cause") not in structural
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            over_escalated_blocks=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", block_handling_rows=len(rows)
            ),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        block_handling_rows=len(rows),
    )


def check_proof_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """不稳定启发式只能作为实验信号，不得直接阻断发布。

    机械断言：声明不稳定（不可复现/误报边界不清/仅经验相关）的启发式发现
    必须 signal_kind=experimental 且携带置信度与证据，release_blocker!=true。
    """
    policy = _proof_policy(ctx)
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_proof_policy"),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            proof_policy_declared=False,
        )
    rows = rows_of(policy, "heuristic_findings", "proof-policy")
    violations = []
    for index, row in enumerate(rows):
        unstable = (
            row.get("reproducible") is False
            or row.get("false_positive_boundary_unclear") is True
            or row.get("correlation_only") is True
        )
        if not unstable:
            continue
        if (
            row.get("signal_kind") != "experimental"
            or row.get("confidence") is None
            or not row.get("evidence")
            or row.get("release_blocker") is True
        ):
            violations.append({"index": index, "finding": row.get("finding_id")})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            unstable_heuristics_used_as_blockers=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", heuristic_findings=len(rows)
            ),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        heuristic_findings=len(rows),
    )


def check_proof_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """粗粒度总分不得决定规范与发布门禁。

    机械断言：门禁政策不得声明总分/字母等级/整类统一严重性作为门禁输入；
    初版不得提供发布总分。
    """
    policy = _gate_policy(ctx)
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_gate_policy"),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_declared=False,
        )
    violations = [
        field
        for field in ("total_score_gate", "letter_grade_gate", "uniform_severity_gate")
        if policy.get(field) is True
    ]
    if policy.get("release_total_score_provided") is True:
        violations.append("release_total_score")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            coarse_score_gates=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", gate_inputs_rule_level=True),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        gate_inputs_rule_level=True,
    )


def _qualification(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "qualification-claims")


def check_qualify_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """局部高档位不得抬高总体声明，也不得掩盖缺证范围。

    机械断言：总体档位声明必须等于各必需范围档位的最小值；存在缺证范围
    而总体声明高于最小值即违反。
    """
    claims = _qualification(ctx)
    if claims is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_qualification"),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            qualification_declared=False,
        )
    scopes = rows_of(claims, "scopes", "qualification-claims")
    required_scopes = [row for row in scopes if row.get("required") is True]
    if not required_scopes:
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed", required_scopes=0),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            required_scopes=0,
        )
    levels = []
    for row in required_scopes:
        level = row.get("level")
        if not isinstance(level, int):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "qualification-claims.scopes.level 必须是整数"
            )
        levels.append(level)
    overall = claims.get("overall_level")
    if not isinstance(overall, int):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "qualification-claims.overall_level 必须是整数"
        )
    if overall > min(levels):
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations"),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            overall_level=overall,
            min_scope_level=min(levels),
            missing_evidence_scopes=[
                row.get("scope_id") for row in required_scopes if row.get("evidence") in (None, "", [])
            ],
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                overall_level=overall,
                min_scope_level=min(levels),
            ),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        overall_level=overall,
        min_scope_level=min(levels),
    )


def check_qualify_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目政策只能加严验证档位，不得降低最低档位。

    机械断言：已声明项目政策档位必须 ≥ 规范政策最低档位；低于即违反。
    """
    claims = _qualification(ctx)
    if claims is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_qualification"),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            qualification_declared=False,
        )
    project_level = claims.get("project_policy_level")
    minimum_level = claims.get("spec_minimum_level")
    if project_level is None and minimum_level is None:
        return _finish(
            [
                _schema_row("PASS", reason="policy_levels_not_declared"),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            policy_levels_declared=False,
        )
    if not isinstance(project_level, int) or not isinstance(minimum_level, int):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "qualification-claims 项目政策档位与最低档位必须是整数",
        )
    if project_level < minimum_level:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations"),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            project_level=project_level,
            spec_minimum_level=minimum_level,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                project_level=project_level,
                spec_minimum_level=minimum_level,
            ),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        project_level=project_level,
        spec_minimum_level=minimum_level,
    )


CHECKS = {
    "SFA-ASSESSMENT-004": check_assessment_004,
    "SFA-CASE-004": check_case_004,
    "SFA-CASE-006": check_case_006,
    "SFA-EVAL-002": check_eval_002,
    "SFA-EVAL-003": check_eval_003,
    "SFA-EVAL-004": check_eval_004,
    "SFA-EVAL-005": check_eval_005,
    "SFA-GATE-001": check_gate_001,
    "SFA-GATE-002": check_gate_002,
    "SFA-GATE-003": check_gate_003,
    "SFA-OBSERVE-001": check_observe_001,
    "SFA-OBSERVE-002": check_observe_002,
    "SFA-OBSERVE-004": check_observe_004,
    "SFA-OBSERVE-007": check_observe_007,
    "SFA-OBSERVE-008": check_observe_008,
    "SFA-PROOF-005": check_proof_005,
    "SFA-PROOF-007": check_proof_007,
    "SFA-PROOF-008": check_proof_008,
    "SFA-QUALIFY-005": check_qualify_005,
    "SFA-QUALIFY-007": check_qualify_007,
}
