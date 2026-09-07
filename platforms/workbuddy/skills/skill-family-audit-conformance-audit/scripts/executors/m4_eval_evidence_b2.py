"""M4 执行族：评估证据与门禁（W2-B2 共 35 条，violation_impact=error）。

本批 35 条全部 methods=(digest_verification, schema_validation)、
behavior_also_required=false、semantic_also_required=false，机械断言即全部义务。

证据面：项目治理声明文档（约束"已声明者"；缺失 = 无可判违反事实 → PASS；
形状非法失败关闭）：

- 复用 B1 M4 既有文档：evaluation-report（独立报告段与逐规则评估行）、
  gate-policy（重试/消费表面/门禁输出）、run-record（观察事件/目标声明/
  观察器记录）、proof-policy（质量证明反模式）、qualification-claims（档位声明）；
- 本批新增文档：rule-cases（判例合同）、evidence-cache（证据缓存）、
  external-evidence（外部证据台账）、evaluation-history（评估历史）、
  verification-levels（验证档位轴）。

PROOF-009 约束外部产品分层不得映射验证档位，其机械事实落在
verification-levels（档位声明轴），故由该文档承载。
"""
from __future__ import annotations

import hashlib
from typing import Any

from .contracts import (
    REQUIRED_PLATFORMS,
    ExecutorEvidenceError,
    governance_dir,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

_VERDICTS = {"pass", "fail", "blocked", "not_run"}
_EXTRAPOLATION_TARGETS = {
    "behavior_verification",
    "run_governance",
    "model_semantic_quality",
}
_CASE_KINDS = ("pass", "fail", "boundary", "not_applicable")
_HELD_OUT_KINDS = (
    "held_out_cases",
    "semantic_equivalence_transforms",
    "mutations",
    "fault_injections",
)
_REVALIDATION_TRIGGERS = (
    "rule",
    "check_implementation",
    "case",
    "gate",
    "exception",
    "platform_fact",
    "release_candidate",
)
_CACHE_INPUT_AXES = (
    "target_input",
    "rule_revision",
    "implementation",
    "prompt",
    "model",
    "platform",
    "cases",
    "environment",
    "applicable_policy_digest",
)
_FAILED_CACHE_STATES = {
    "failed", "cancelled", "timeout", "empty_response", "incomplete_evidence",
}
_SOURCE_FACT_FIELDS = (
    "source_identity",
    "acquisition_method",
    "authority_type",
    "producer",
    "integrity_status",
    "cross_corroboration_status",
)
_RECORD_SUMMARY_FIELDS = (
    "target_digest",
    "scope_digest",
    "rule_set_digest",
    "implementation_digest",
    "policy_digest",
    "platform_digest",
    "environment_digest",
)
_EVENT_BINDING_FIELDS = (
    "candidate_artifact",
    "task",
    "isolation_environment",
    "execution_environment",
    "process_identity",
    "observer_version",
    "run_id",
)
_OBSERVER_FACT_KINDS = (
    "run_start_and_exit",
    "process_tree",
    "resource_usage",
    "actual_write_set",
    "network_connections",
    "cleanup_result",
)
_PREFERENCE_KINDS = {
    "role_table",
    "fixed_section_names",
    "three_part_layout",
    "chinese_filename_ban",
    "other_expression_preference",
}
_SCOPE_KINDS = ("platform", "stable_public_entry", "strict_method", "public_capability")
_EXCLUSION_MARKS = {"experimental", "absent", "out_of_stable_support"}
_GATE_SURFACES = {"cli", "ci", "packaging", "release", "ui"}


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


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


def _split_violations(
    violations: list[dict[str, Any]], digest_reasons: tuple[str, ...]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """把 violations（每行含 reasons 列表）按原因归属拆分为 schema 侧与 digest 侧。

    一行同时含两类原因时两侧都计入；任一侧为空时对应方法行取 PASS。
    """
    schema_side: list[dict[str, Any]] = []
    digest_side: list[dict[str, Any]] = []
    for row in violations:
        reasons = row.get("reasons", [])
        if any(reason in digest_reasons for reason in reasons):
            digest_side.append(row)
        if not all(reason in digest_reasons for reason in reasons):
            schema_side.append(row)
    return schema_side, digest_side


def _report_document(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "evaluation-report")


def _section(document: dict[str, Any], section_id: str) -> dict[str, Any] | None:
    sections = rows_of(document, "report_sections", "evaluation-report")
    for section in sections:
        if section.get("section_id") == section_id:
            return section
    return None


def check_assessment_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """确定性符合结论独立报告。

    机械断言：已声明评估报告必须含独立的 deterministic_conformance 段，
    reports_independently=true 且结论携带 64 位十六进制摘要。
    """
    document = _report_document(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    section = _section(document, "deterministic_conformance")
    if section is None:
        return _finish(
            [
                _schema_row("FAIL", reason="deterministic_conformance_section_missing"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            reason="deterministic_conformance_section_missing",
        )
    schema_reasons = []
    digest_reasons = []
    if section.get("reports_independently") is not True:
        schema_reasons.append("not_independent")
    if not is_hex64(section.get("conclusion_digest")):
        digest_reasons.append("conclusion_digest_invalid")
    if schema_reasons or digest_reasons:
        violations = [{"reasons": schema_reasons + digest_reasons}]
        schema_side, digest_side = _split_violations(
            violations, ("conclusion_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            deterministic_conformance_section_violations=schema_reasons + digest_reasons,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", section="deterministic_conformance"),
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                consumed_conclusion_digest=section.get("conclusion_digest"),
            ),
        ],
        section="deterministic_conformance",
    )


def check_assessment_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """行为验证结论独立报告。

    机械断言：已声明评估报告必须含独立的 behavior_verification 段，锁定
    平台/模型/样例/执行器/目标发行物/限制六要素，结论携带摘要。
    """
    document = _report_document(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    section = _section(document, "behavior_verification")
    if section is None:
        return _finish(
            [
                _schema_row("FAIL", reason="behavior_verification_section_missing"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            reason="behavior_verification_section_missing",
        )
    schema_reasons = []
    digest_reasons = []
    if section.get("reports_independently") is not True:
        schema_reasons.append("not_independent")
    if not is_hex64(section.get("conclusion_digest")):
        digest_reasons.append("conclusion_digest_invalid")
    locked = section.get("locked_conditions")
    if not isinstance(locked, dict):
        schema_reasons.append("locked_conditions_missing")
    else:
        missing = [
            field
            for field in ("platform", "model", "samples", "executor", "target_release", "limitations")
            if not _nonempty_str(locked.get(field)) and not isinstance(locked.get(field), list)
        ]
        if missing:
            schema_reasons.append(f"locked_conditions_missing:{','.join(missing)}")
    if schema_reasons or digest_reasons:
        violations = [{"reasons": schema_reasons + digest_reasons}]
        schema_side, digest_side = _split_violations(
            violations, ("conclusion_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            behavior_verification_section_violations=schema_reasons + digest_reasons,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", section="behavior_verification"),
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                consumed_conclusion_digest=section.get("conclusion_digest"),
            ),
        ],
        section="behavior_verification",
    )


def check_assessment_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行治理结论独立报告。

    机械断言：已声明评估报告必须含独立的 run_governance 段，能力覆盖
    上下文观察/心跳/长工具租约/失败识别/检查点/恢复/取消/副作用清理。
    """
    document = _report_document(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    section = _section(document, "run_governance")
    if section is None:
        return _finish(
            [
                _schema_row("FAIL", reason="run_governance_section_missing"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            reason="run_governance_section_missing",
        )
    schema_reasons = []
    digest_reasons = []
    if section.get("reports_independently") is not True:
        schema_reasons.append("not_independent")
    if not is_hex64(section.get("conclusion_digest")):
        digest_reasons.append("conclusion_digest_invalid")
    coverage = section.get("capability_coverage")
    if not isinstance(coverage, dict):
        schema_reasons.append("capability_coverage_missing")
    else:
        missing = [
            capability
            for capability in (
                "context_observation", "heartbeats", "long_tool_leases",
                "failure_detection", "checkpoints", "recovery", "cancellation",
                "side_effect_cleanup",
            )
            if coverage.get(capability) is not True
        ]
        if missing:
            schema_reasons.append(f"capabilities_uncovered:{','.join(missing)}")
    if schema_reasons or digest_reasons:
        violations = [{"reasons": schema_reasons + digest_reasons}]
        schema_side, digest_side = _split_violations(
            violations, ("conclusion_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            run_governance_section_violations=schema_reasons + digest_reasons,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", section="run_governance"),
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                consumed_conclusion_digest=section.get("conclusion_digest"),
            ),
        ],
        section="run_governance",
    )


def check_assessment_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """静态符合不得外推行为质量。

    机械断言：deterministic_conformance 段不得声明外推至行为验证/运行治理/
    模型语义质量；报告级外推标志必须为 false。
    """
    document = _report_document(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    section = _section(document, "deterministic_conformance")
    if section is None:
        return _finish(
            [
                _schema_row("FAIL", reason="deterministic_conformance_section_missing"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            reason="deterministic_conformance_section_missing",
        )
    violations = []
    extrapolates = section.get("extrapolates_to")
    if extrapolates is None:
        extrapolates = []
    if not isinstance(extrapolates, list):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "evaluation-report 段 extrapolates_to 必须是数组",
        )
    hit = sorted(set(extrapolates) & _EXTRAPOLATION_TARGETS)
    if hit:
        violations.append(f"extrapolates_to:{','.join(hit)}")
    if document.get("static_conformance_extrapolated_to_behavior_quality") is True:
        violations.append("report_level_extrapolation")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            static_conformance_extrapolations=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", extrapolation_targets=0),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        extrapolation_targets=0,
    )


def check_eval_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """单次评估分别记录适用、执行、裁决和治理影响。

    机械断言：每条评估行必须分别携带 applicable / executed /
    execution_complete / verdict / governance_impact，不得压成单一总状态。
    """
    document = _report_document(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_report"),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            report_declared=False,
        )
    rows = rows_of(document, "rows", "evaluation-report")
    violations = []
    for row in rows:
        reasons = []
        for field in ("applicable", "executed", "execution_complete"):
            if not isinstance(row.get(field), bool):
                reasons.append(f"{field}_missing")
        if row.get("verdict") not in _VERDICTS:
            reasons.append("verdict_invalid")
        if not _nonempty_str(row.get("governance_impact")):
            reasons.append("governance_impact_missing")
        if "collapsed_status" in row:
            reasons.append("collapsed_status_present")
        if reasons:
            violations.append({"rule_id": row.get("rule_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-report",)),
            ],
            evaluation_rows_collapsed=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", rows_checked=len(rows)),
            _doc_digest_row(ctx, ("evaluation-report",)),
        ],
        rows_checked=len(rows),
    )


def _rule_cases(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "rule-cases")


def check_case_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """强制确定性规则具有四类可执行判例。

    机械断言：每条已声明强制规则的判例行必须含 pass/fail/boundary/
    not_applicable 各至少一例，且模糊预期清单为空。
    """
    document = _rule_cases(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_rule_cases"),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            rule_cases_declared=False,
        )
    rows = rows_of(document, "mandatory_rule_cases", "rule-cases")
    violations = []
    for row in rows:
        reasons = []
        kinds = row.get("case_kinds")
        if not isinstance(kinds, dict):
            reasons.append("case_kinds_missing")
        else:
            missing = [
                kind for kind in _CASE_KINDS
                if not isinstance(kinds.get(kind), int) or kinds.get(kind) < 1
            ]
            if missing:
                reasons.append(f"kinds_missing:{','.join(missing)}")
        ambiguous = row.get("ambiguous_expectations")
        if ambiguous is None:
            ambiguous = []
        if not isinstance(ambiguous, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "rule-cases.ambiguous_expectations 必须是数组",
            )
        if ambiguous:
            reasons.append("ambiguous_expectations_present")
        if reasons:
            violations.append({"rule_id": row.get("rule_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            mandatory_cases_incomplete=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", mandatory_rules_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("rule-cases",)),
        ],
        mandatory_rules_checked=len(rows),
    )


def check_case_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """公开回归之外使用隔离保留和变异集。

    机械断言：已声明保留集必须 collectively 覆盖 held_out_cases /
    semantic_equivalence_transforms / mutations / fault_injections，
    且与实现提示隔离。
    """
    document = _rule_cases(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_rule_cases"),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            rule_cases_declared=False,
        )
    rows = rows_of(document, "held_out_sets", "rule-cases")
    covered: set[str] = set()
    violations = []
    for row in rows:
        if row.get("isolated_from_implementation_hints") is not True:
            violations.append({"set_id": row.get("set_id"), "reason": "not_isolated"})
            continue
        kinds = row.get("kinds")
        if not isinstance(kinds, dict):
            violations.append({"set_id": row.get("set_id"), "reason": "kinds_missing"})
            continue
        covered.update(kind for kind in _HELD_OUT_KINDS if kinds.get(kind) is True)
    missing = sorted(set(_HELD_OUT_KINDS) - covered)
    if missing:
        violations.append({"reason": f"kinds_uncovered:{','.join(missing)}"})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            held_out_sets_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", held_out_kinds_covered=sorted(covered)
            ),
            _doc_digest_row(ctx, ("rule-cases",)),
        ],
        held_out_kinds_covered=sorted(covered),
    )


def check_case_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """普通语义规则采用独立干净上下文审阅。

    机械断言：每条已声明语义审阅必须使用与执行者不同的独立身份、干净上下文、
    锁定的目标输入/规则修订/判例；审阅者不得修改实现或验收标准。
    """
    document = _rule_cases(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_rule_cases"),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            rule_cases_declared=False,
        )
    rows = rows_of(document, "semantic_reviews", "rule-cases")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        reviewer = row.get("reviewer_identity")
        if not _nonempty_str(reviewer) or reviewer == row.get("executor_identity"):
            schema_reasons.append("reviewer_not_independent")
        if row.get("clean_context") is not True:
            schema_reasons.append("context_not_clean")
        if not _nonempty_str(row.get("locked_target_input")):
            schema_reasons.append("target_input_not_locked")
        if not is_hex64(row.get("locked_rule_revision")):
            digest_reasons.append("rule_revision_not_locked")
        if not _nonempty_str(row.get("locked_cases")) and not isinstance(row.get("locked_cases"), list):
            schema_reasons.append("cases_not_locked")
        if row.get("reviewer_modifies_implementation") is True:
            schema_reasons.append("reviewer_modifies_implementation")
        if row.get("reviewer_modifies_acceptance") is True:
            schema_reasons.append("reviewer_modifies_acceptance")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "review_id": row.get("review_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("rule_revision_not_locked",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            semantic_reviews_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", semantic_reviews_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("rule-cases",)),
        ],
        semantic_reviews_checked=len(rows),
    )


def check_case_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """相关治理对象变化触发检查器反向验证。

    机械断言：已声明重验政策必须覆盖七类治理对象变化，且每类触发重跑合同
    判例与反向判例，不得只依赖固定周期复查。
    """
    document = _rule_cases(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_rule_cases"),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            rule_cases_declared=False,
        )
    rows = rows_of(document, "revalidation_triggers", "rule-cases")
    covered: set[str] = set()
    violations = []
    for row in rows:
        trigger = row.get("trigger_kind")
        if trigger not in _REVALIDATION_TRIGGERS:
            violations.append({"trigger_kind": trigger, "reason": "unknown_trigger"})
            continue
        reasons = []
        if row.get("reran_contract_cases") is not True:
            reasons.append("contract_cases_not_reran")
        if row.get("reran_reverse_cases") is not True:
            reasons.append("reverse_cases_not_reran")
        if row.get("relies_only_on_periodic_review") is True:
            reasons.append("periodic_review_only")
        if reasons:
            violations.append({"trigger_kind": trigger, "reasons": reasons})
        else:
            covered.add(trigger)
    missing = sorted(set(_REVALIDATION_TRIGGERS) - covered)
    if missing:
        violations.append({"reason": f"triggers_uncovered:{','.join(missing)}"})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-cases",)),
            ],
            revalidation_policy_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", triggers_covered=len(covered)
            ),
            _doc_digest_row(ctx, ("rule-cases",)),
        ],
        triggers_covered=len(covered),
    )


def _evidence_cache(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "evidence-cache")


def check_evcache_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """语义与运行证据缓存锁定完整输入。

    机械断言：每条成功缓存条目必须绑定九轴输入（目标输入/规则修订/实现/
    提示/模型/平台/判例/环境/适用政策摘要），值携带摘要。
    """
    document = _evidence_cache(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_evidence_cache"),
                _doc_digest_row(ctx, ("evidence-cache",)),
            ],
            evidence_cache_declared=False,
        )
    rows = rows_of(document, "entries", "evidence-cache")
    violations = []
    for row in rows:
        if row.get("result_state") in _FAILED_CACHE_STATES:
            continue
        schema_reasons = []
        digest_reasons = []
        bindings = row.get("key_bindings")
        if not isinstance(bindings, dict):
            schema_reasons.append("key_bindings_missing")
        else:
            missing = [axis for axis in _CACHE_INPUT_AXES if not _nonempty_str(bindings.get(axis))]
            if missing:
                schema_reasons.append(f"axes_missing:{','.join(missing)}")
        if not is_hex64(row.get("value_digest")):
            digest_reasons.append("value_digest_invalid")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "cache_id": row.get("cache_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("value_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            cache_input_bindings_incomplete=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", entries_checked=len(rows)),
            _doc_digest_row(ctx, ("evidence-cache",)),
        ],
        entries_checked=len(rows),
    )


def check_evcache_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """失败空响应和不完整证据不得缓存为无发现。

    机械断言：失败/取消/超时/空响应/证据不完整的条目必须保存带失败状态的
    尝试证据，不得缓存为无发现或通过。
    """
    document = _evidence_cache(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_evidence_cache"),
                _doc_digest_row(ctx, ("evidence-cache",)),
            ],
            evidence_cache_declared=False,
        )
    rows = rows_of(document, "entries", "evidence-cache")
    violations = []
    for row in rows:
        if row.get("result_state") not in _FAILED_CACHE_STATES:
            continue
        reasons = []
        if row.get("stored_as_no_finding") is True:
            reasons.append("stored_as_no_finding")
        if row.get("cached_conclusion") in {"no_finding", "pass"}:
            reasons.append("cached_as_pass_or_no_finding")
        if not _nonempty_str(row.get("attempt_evidence")):
            reasons.append("attempt_evidence_missing")
        if reasons:
            violations.append({"cache_id": row.get("cache_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evidence-cache",)),
            ],
            failed_attempts_cached_as_findings=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", entries_checked=len(rows)),
            _doc_digest_row(ctx, ("evidence-cache",)),
        ],
        entries_checked=len(rows),
    )


def _external_evidence(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "external-evidence")


def check_evidence_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """外部证据逐项保留来源事实。

    机械断言：每条外部证据条目必须逐项记录来源身份/获取方式/权威类型/
    内容摘要/生成者/完整性状态/交叉印证状态。
    """
    document = _external_evidence(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_external_evidence"),
                _doc_digest_row(ctx, ("external-evidence",)),
            ],
            external_evidence_declared=False,
        )
    rows = rows_of(document, "items", "external-evidence")
    violations = []
    for row in rows:
        schema_reasons = [
            f"{field}_missing"
            for field in _SOURCE_FACT_FIELDS
            if not _nonempty_str(row.get(field))
        ]
        digest_reasons = []
        if not is_hex64(row.get("content_digest")):
            digest_reasons.append("content_digest_invalid")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "evidence_id": row.get("evidence_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("content_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            source_facts_incomplete=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", items_checked=len(rows)),
            _doc_digest_row(ctx, ("external-evidence",)),
        ],
        items_checked=len(rows),
    )


def check_evidence_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """单一分值不得替代来源事实。

    机械断言：文档不得声明以可信等级/固定权重/综合分值替代逐项来源事实，
    条目不得以单一分值顶替来源；预设权重不得自动压过可验证冲突事实。
    """
    document = _external_evidence(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_external_evidence"),
                _doc_digest_row(ctx, ("external-evidence",)),
            ],
            external_evidence_declared=False,
        )
    violations = []
    if document.get("trust_score_replaces_source_facts") is True:
        violations.append("trust_score_replaces_source_facts")
    if document.get("fixed_weight_overrides_conflicting_verifiable_facts") is True:
        violations.append("fixed_weight_overrides_conflicts")
    for row in rows_of(document, "items", "external-evidence"):
        if row.get("single_score_replaces_source_facts") is True:
            violations.append(f"item:{row.get('evidence_id')}")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("external-evidence",)),
            ],
            score_substitutions=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", score_substitution=False),
            _doc_digest_row(ctx, ("external-evidence",)),
        ],
        score_substitution=False,
    )


def _gate_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "gate-policy")


def check_gate_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """重试保留全部尝试并按预定策略裁决。

    机械断言：每条重试记录必须保留每次尝试的输入/状态/证据/结果，归并
    政策运行前声明，不得只选最好一次结果。
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
    rows = rows_of(policy, "retries", "gate-policy")
    violations = []
    for row in rows:
        reasons = []
        attempts = rows_of(row, "attempts", "gate-policy.retries") if isinstance(row.get("attempts"), list) else None
        if attempts is None or not attempts:
            reasons.append("attempts_missing")
        else:
            incomplete = [
                index
                for index, attempt in enumerate(attempts)
                if any(key not in attempt for key in ("input", "state", "evidence", "result"))
            ]
            if incomplete:
                reasons.append(f"attempts_incomplete:{incomplete}")
        if row.get("merge_policy_declared_before_run") is not True:
            reasons.append("merge_policy_not_predeclared")
        if row.get("selects_best_result_only") is True:
            reasons.append("selects_best_result_only")
        if reasons:
            violations.append({"retry_id": row.get("retry_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            retries_not_fully_retained=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", retries_checked=len(rows)),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        retries_checked=len(rows),
    )


def check_gate_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """所有消费表面使用同一结构化门禁判定器。

    机械断言：已声明门禁消费表面必须消费同一版本化判定器，不得各自重算、
    过滤或覆盖。
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
    rows = rows_of(policy, "gate_consumers", "gate-policy")
    violations = []
    identities: set[tuple] = set()
    for row in rows:
        reasons = []
        if row.get("surface") not in _GATE_SURFACES:
            reasons.append("surface_unknown")
        if not _nonempty_str(row.get("adjudicator_identity")):
            reasons.append("adjudicator_identity_missing")
        if not _nonempty_str(row.get("adjudicator_version")):
            reasons.append("adjudicator_version_missing")
        if row.get("single_source") is not True:
            reasons.append("not_single_source")
        if row.get("recomputes_result") is True:
            reasons.append("recomputes_result")
        if row.get("filters_or_overrides_result") is True:
            reasons.append("filters_or_overrides_result")
        if reasons:
            violations.append({"surface": row.get("surface"), "reasons": reasons})
        else:
            identities.add((row.get("adjudicator_identity"), row.get("adjudicator_version")))
    if len(identities) > 1:
        violations.append({"reason": "consumers_use_distinct_adjudicators"})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_consumers_diverged=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", consumers_checked=len(rows)),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        consumers_checked=len(rows),
    )


def check_gate_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """初版门禁只输出逐规则和描述性结果。

    机械断言：已声明门禁输出必须逐规则/维度状态/证据完整性/描述性统计/
    阻断原因，不提供总分；统计不得抵消阻断规则。
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
    rows = rows_of(policy, "gate_outputs", "gate-policy")
    violations = []
    for row in rows:
        reasons = []
        for field in (
            "per_rule_results",
            "dimension_status",
            "evidence_completeness",
            "descriptive_statistics",
            "block_reasons",
        ):
            if row.get(field) is not True:
                reasons.append(f"{field}_missing")
        if row.get("provides_total_score") is True:
            reasons.append("provides_total_score")
        if row.get("statistics_offset_blocking_rules") is True:
            reasons.append("statistics_offset_blocking_rules")
        if reasons:
            violations.append({"output_id": row.get("output_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("gate-policy",)),
            ],
            gate_outputs_beyond_rule_level=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", outputs_checked=len(rows)),
            _doc_digest_row(ctx, ("gate-policy",)),
        ],
        outputs_checked=len(rows),
    )


def _evaluation_history(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "evaluation-history")


def _record_side_violations(side: Any) -> tuple[list[str], list[str]]:
    """返回 (schema 侧原因, digest 侧原因)；摘要类缺陷归 digest 方法。"""
    if not isinstance(side, dict):
        return ["record_missing"], []
    schema_reasons = []
    digest_reasons = []
    if side.get("immutable") is not True:
        schema_reasons.append("record_mutable")
    if not _nonempty_str(side.get("record_ref")):
        schema_reasons.append("record_ref_missing")
    missing = [field for field in _RECORD_SUMMARY_FIELDS if not is_hex64(side.get(field))]
    if missing:
        digest_reasons.append(f"summaries_invalid:{','.join(missing)}")
    return schema_reasons, digest_reasons


def check_history_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """历史差异从两个不可变评估记录重建。

    机械断言：每条差异必须引用两个不可变记录及七类摘要；条件不兼容时
    必须标记不可比较。
    """
    document = _evaluation_history(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_evaluation_history"),
                _doc_digest_row(ctx, ("evaluation-history",)),
            ],
            evaluation_history_declared=False,
        )
    rows = rows_of(document, "diffs", "evaluation-history")
    violations = []
    for row in rows:
        left_schema, left_digest = _record_side_violations(row.get("left"))
        right_schema, right_digest = _record_side_violations(row.get("right"))
        schema_reasons = [f"left:{reason}" for reason in left_schema]
        schema_reasons += [f"right:{reason}" for reason in right_schema]
        digest_reasons = [f"left:{reason}" for reason in left_digest]
        digest_reasons += [f"right:{reason}" for reason in right_digest]
        if row.get("compatible") is False and row.get("marked_not_comparable") is not True:
            schema_reasons.append("incompatible_not_marked")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "diff_id": row.get("diff_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("left:summaries_invalid", "right:summaries_invalid")
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=(
                        "schema_violations" if schema_side else "schema_checks_passed"
                    ),
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason=(
                        "digest_violations" if digest_side else "digest_checks_passed"
                    ),
                    violations=digest_side,
                ),
            ],
            diffs_not_reconstructable=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", diffs_checked=len(rows)),
            _doc_digest_row(ctx, ("evaluation-history",)),
        ],
        diffs_checked=len(rows),
    )


def check_history_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """最新评估只能作为可重建索引。

    机械断言：latest 索引必须指向不可变评估记录且只含摘要，不得成为
    权威内容。
    """
    document = _evaluation_history(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_evaluation_history"),
                _doc_digest_row(ctx, ("evaluation-history",)),
            ],
            evaluation_history_declared=False,
        )
    latest = document.get("latest_index")
    if latest is None:
        return _finish(
            [
                _schema_row("PASS", reason="latest_index_not_declared"),
                _doc_digest_row(ctx, ("evaluation-history",)),
            ],
            latest_index_declared=False,
        )
    if not isinstance(latest, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "evaluation-history.latest_index 必须是对象"
        )
    violations = []
    if latest.get("points_to_immutable_record") is not True:
        violations.append("does_not_point_to_immutable_record")
    if latest.get("authoritative_content") is True:
        violations.append("authoritative_content")
    if not _nonempty_str(latest.get("record_ref")):
        violations.append("record_ref_missing")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("evaluation-history",)),
            ],
            latest_index_violations=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", latest_index="reconstructable"),
            _doc_digest_row(ctx, ("evaluation-history",)),
        ],
        latest_index="reconstructable",
    )


def _verification_levels(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "verification-levels")


def check_level_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """验证能力与生命周期发布状态分轴。

    机械断言：每条轴记录必须分别记录验证档位、生命周期阶段、能力支持状态、
    发布状态，且不得从其他轴自动推导。
    """
    document = _verification_levels(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_verification_levels"),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            verification_levels_declared=False,
        )
    rows = rows_of(document, "axes", "verification-levels")
    violations = []
    for row in rows:
        reasons = []
        if not isinstance(row.get("verification_level"), int):
            reasons.append("verification_level_missing")
        for field in ("lifecycle_stage", "support_status", "release_status"):
            if not _nonempty_str(row.get(field)):
                reasons.append(f"{field}_missing")
        if row.get("derived_from_other_axis") is True:
            reasons.append("derived_from_other_axis")
        if reasons:
            violations.append({"subject": row.get("subject"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            axes_not_separated=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", axes_checked=len(rows)),
            _doc_digest_row(ctx, ("verification-levels",)),
        ],
        axes_checked=len(rows),
    )


def check_level_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """三个验证档位逐级继承。

    机械断言：第二档必须满足第一档全部适用规则，第三档必须满足第一、二档；
    不得以另一套检查表绕过低档位。
    """
    document = _verification_levels(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_verification_levels"),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            verification_levels_declared=False,
        )
    rows = rows_of(document, "level_inheritance", "verification-levels")
    violations = []
    for row in rows:
        level = row.get("level")
        if not isinstance(level, int) or level not in (1, 2, 3):
            violations.append({"subject": row.get("subject"), "reasons": ["level_invalid"]})
            continue
        reasons = []
        if level >= 2 and row.get("satisfies_level1_applicable_rules") is not True:
            reasons.append("level1_rules_not_satisfied")
        if level == 3 and row.get("satisfies_level2_applicable_rules") is not True:
            reasons.append("level2_rules_not_satisfied")
        if row.get("bypasses_lower_level_checklist") is True:
            reasons.append("bypasses_lower_level_checklist")
        if reasons:
            violations.append({"subject": row.get("subject"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            level_inheritance_broken=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", inheritance_rows_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("verification-levels",)),
        ],
        inheritance_rows_checked=len(rows),
    )


def check_level_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """档位声明绑定版本平台和公共能力。

    机械断言：每条档位声明必须绑定技能族版本、目标平台、稳定公共入口、
    严格方法和业务能力范围。
    """
    document = _verification_levels(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_verification_levels"),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            verification_levels_declared=False,
        )
    rows = rows_of(document, "level_claims", "verification-levels")
    violations = []
    for row in rows:
        reasons = []
        if not _nonempty_str(row.get("family_version")):
            reasons.append("family_version_missing")
        if not _nonempty_str(row.get("platform")):
            reasons.append("platform_missing")
        entries = row.get("stable_public_entries")
        if not isinstance(entries, list) or not entries or not all(_nonempty_str(item) for item in entries):
            reasons.append("stable_public_entries_missing")
        methods = row.get("strict_methods")
        if not isinstance(methods, list) or not methods or not all(_nonempty_str(item) for item in methods):
            reasons.append("strict_methods_missing")
        if not _nonempty_str(row.get("business_capability_scope")):
            reasons.append("business_capability_scope_missing")
        if reasons:
            violations.append({"claim_id": row.get("claim_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            level_claims_unbound=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", claims_checked=len(rows)),
            _doc_digest_row(ctx, ("verification-levels",)),
        ],
        claims_checked=len(rows),
    )


def check_proof_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """外部产品分层不得映射验证能力档位。

    机械断言：已声明外部映射不得直接映射为验证档位，必须按本规范真实
    证据逐项判定。
    """
    document = _verification_levels(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_verification_levels"),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            verification_levels_declared=False,
        )
    rows = rows_of(document, "external_mappings", "verification-levels")
    violations = []
    for row in rows:
        reasons = []
        if row.get("mapped_to_verification_level") is True:
            reasons.append("mapped_to_verification_level")
        if row.get("judged_by_real_spec_evidence_itemwise") is not True:
            reasons.append("not_judged_itemwise")
        if reasons:
            violations.append({"source": row.get("source"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("verification-levels",)),
            ],
            external_tiers_mapped_to_levels=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", mappings_checked=len(rows)),
            _doc_digest_row(ctx, ("verification-levels",)),
        ],
        mappings_checked=len(rows),
    )


def _run_record(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "run-record")


def check_observe_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个观察事件绑定完整运行身份。

    机械断言：每个观察事件必须绑定候选发行物/任务/隔离环境/执行环境/
    进程/观察器版本/单次运行标识与单调序号（严格递增）。
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
    events = rows_of(record, "observation_events", "run-record")
    violations = []
    last_sequence = None
    for event in events:
        reasons = [
            f"{field}_missing"
            for field in _EVENT_BINDING_FIELDS
            if not _nonempty_str(event.get(field))
        ]
        sequence = event.get("monotonic_sequence")
        if not isinstance(sequence, int):
            reasons.append("monotonic_sequence_invalid")
        elif last_sequence is not None and sequence <= last_sequence:
            reasons.append("sequence_not_monotonic")
        if isinstance(sequence, int):
            last_sequence = sequence
        if reasons:
            violations.append({"event_id": event.get("event_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            observation_events_unbound=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", events_checked=len(events)),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        events_checked=len(events),
    )


def check_observe_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """目标心跳和结果只能作为目标声明。

    机械断言：目标进程产生的心跳/日志/状态/结果必须标记 target_claim，
    不得在缺少独立观察事实时单独证明行为。
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
    rows = rows_of(record, "target_claims", "run-record")
    violations = []
    for row in rows:
        reasons = []
        if row.get("marked_as") != "target_claim":
            reasons.append("not_marked_target_claim")
        if row.get("used_as_sole_proof") is True:
            reasons.append("used_as_sole_proof")
        if reasons:
            violations.append({"claim_id": row.get("claim_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            target_claims_overstated=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", claims_checked=len(rows)),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        claims_checked=len(rows),
    )


def check_observe_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """观察器独立记录关键执行事实。

    机械断言：已声明观察器记录必须覆盖运行开始与退出/进程树/资源使用/
    实际写入集合/网络连接/清理结果。
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
    observer_records = record.get("observer_records")
    if observer_records is None:
        return _finish(
            [
                _schema_row("PASS", reason="observer_records_not_declared"),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            observer_records_declared=False,
        )
    if not isinstance(observer_records, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "run-record.observer_records 必须是对象"
        )
    missing = [kind for kind in _OBSERVER_FACT_KINDS if observer_records.get(kind) is not True]
    if missing:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=missing),
                _doc_digest_row(ctx, ("run-record",)),
            ],
            observer_fact_kinds_missing=missing,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                fact_kinds_covered=list(_OBSERVER_FACT_KINDS),
            ),
            _doc_digest_row(ctx, ("run-record",)),
        ],
        fact_kinds_covered=list(_OBSERVER_FACT_KINDS),
    )


def _proof_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "proof-policy")


def check_proof_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """排版与命名偏好不能单独证明质量。

    机械断言：表达偏好类证明不得作为通用强制质量证明；声明领域价值者
    必须携带规则目的与证据，且只作推荐或领域规则。
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
    rows = rows_of(policy, "expression_preference_proofs", "proof-policy")
    violations = []
    for row in rows:
        reasons = []
        if row.get("proof_kind") not in _PREFERENCE_KINDS:
            reasons.append("proof_kind_unknown")
        if row.get("used_as_general_mandatory_quality_proof") is True:
            reasons.append("used_as_general_mandatory_proof")
        if row.get("domain_value") is True:
            if not _nonempty_str(row.get("rule_purpose")):
                reasons.append("rule_purpose_missing")
            if not _nonempty_str(row.get("evidence")) and not isinstance(row.get("evidence"), list):
                reasons.append("evidence_missing")
            if row.get("strength") not in {"recommended", "domain_rule"}:
                reasons.append("strength_not_recommended_or_domain")
        if reasons:
            violations.append({"proof_id": row.get("proof_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            preference_proofs_overstated=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", preference_proofs_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        preference_proofs_checked=len(rows),
    )


def check_proof_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """数量和快速耗时不能替代覆盖与证据。

    机械断言：数值类指标不得单独证明质量；作为参数必须由风险/方法/平台
    政策提供依据。
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
    rows = rows_of(policy, "numeric_metric_proofs", "proof-policy")
    violations = []
    for row in rows:
        reasons = []
        if row.get("used_alone_as_quality_proof") is True:
            reasons.append("used_alone_as_quality_proof")
        justification = row.get("justified_by")
        if justification is None:
            justification = []
        if not isinstance(justification, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "proof-policy justified_by 必须是数组"
            )
        if not set(justification) & {"risk_policy", "method_policy", "platform_policy"}:
            reasons.append("no_policy_justification")
        if reasons:
            violations.append({"metric": row.get("metric"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            numeric_metrics_as_quality_proof=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", metrics_checked=len(rows)),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        metrics_checked=len(rows),
    )


def check_proof_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """特定模型或执行拓扑不能单独证明质量。

    机械断言：模型/拓扑选择必须验证实际契约、隔离和结果，不得作为通用
    质量证明。
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
    rows = rows_of(policy, "model_topology_proofs", "proof-policy")
    violations = []
    for row in rows:
        reasons = []
        if row.get("used_as_general_quality_proof") is True:
            reasons.append("used_as_general_quality_proof")
        for field in ("verifies_actual_contract", "verifies_isolation", "verifies_results"):
            if row.get(field) is not True:
                reasons.append(f"{field}_missing")
        if reasons:
            violations.append({"claim_id": row.get("claim_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            model_topology_as_quality_proof=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", topology_claims_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        topology_claims_checked=len(rows),
    )


def check_proof_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """关键词或文件存在不能推导规则通过。

    机械断言：存在类事实只能作为候选事实；推导规则通过必须已验证内容、
    调用和行为。
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
    rows = rows_of(policy, "existence_facts", "proof-policy")
    violations = []
    for row in rows:
        reasons = []
        if row.get("treated_as") != "candidate_fact":
            reasons.append("not_treated_as_candidate_fact")
        if row.get("derives_rule_pass") is True:
            missing = [
                field
                for field in ("verified_content", "verified_invocation", "verified_behavior")
                if row.get(field) is not True
            ]
            if missing:
                reasons.append(f"unverified_derivation:{','.join(missing)}")
        if reasons:
            violations.append({"fact_id": row.get("fact_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            existence_derives_pass=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", existence_facts_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        existence_facts_checked=len(rows),
    )


def check_proof_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台加载要求只能来自版本化平台附加规则。

    机械断言：平台要求必须绑定官方来源、客户端版本与真实探测，不得提升
    为跨平台通用结构证明。
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
    rows = rows_of(policy, "platform_requirements", "proof-policy")
    violations = []
    for row in rows:
        reasons = []
        if not _nonempty_str(row.get("official_source")):
            reasons.append("official_source_missing")
        if not _nonempty_str(row.get("client_version")):
            reasons.append("client_version_missing")
        if row.get("real_probe") is not True:
            reasons.append("real_probe_missing")
        if row.get("elevated_to_cross_platform_universal_proof") is True:
            reasons.append("elevated_to_cross_platform_proof")
        if reasons:
            violations.append({"requirement_id": row.get("requirement_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("proof-policy",)),
            ],
            platform_requirements_unversioned=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", requirements_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("proof-policy",)),
        ],
        requirements_checked=len(rows),
    )


def _qualification(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "qualification-claims")


def check_qualify_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有第一档不得声明稳定支持。

    机械断言：仅达第一档的发布声明不得 claims_stable_support=true
    （实验/预览轨可以）。
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
    rows = rows_of(claims, "release_claims", "qualification-claims")
    violations = []
    for row in rows:
        level = row.get("level")
        if not isinstance(level, int):
            violations.append({"family_version": row.get("family_version"), "reasons": ["level_invalid"]})
            continue
        if level <= 1 and row.get("claims_stable_support") is True:
            violations.append({"family_version": row.get("family_version"), "level": level})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            tier1_claims_stable_support=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", release_claims_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        release_claims_checked=len(rows),
    )


def check_qualify_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """稳定联合发布最低达到第二档。

    机械断言：稳定联合发布声明必须 level≥2、覆盖四个必需平台，入口/方法/
    能力证据齐备且未过期。
    """
    claims = _qualification(ctx)
    if claims is None:
        raise ExecutorEvidenceError(
            "QUALIFICATION_CLAIMS_MISSING",
            "稳定联合发布资格无法在 qualification-claims 缺失时判定",
        )
    rows = rows_of(claims, "stable_joint_releases", "qualification-claims")
    if not rows:
        raise ExecutorEvidenceError(
            "STABLE_JOINT_RELEASES_MISSING",
            "稳定联合发布资格至少需要一条 stable_joint_releases 证据",
        )
    violations = []
    for row in rows:
        reasons = []
        level = row.get("level")
        if not isinstance(level, int) or level < 2:
            reasons.append("level_below_tier2")
        platforms = row.get("platforms")
        if not isinstance(platforms, list):
            reasons.append("platforms_missing")
        else:
            missing = sorted(set(REQUIRED_PLATFORMS) - set(platforms))
            if missing:
                reasons.append(f"platforms_missing:{','.join(missing)}")
        for scope in ("stable_public_entries", "strict_methods", "public_capabilities"):
            evidence = row.get(scope)
            if not isinstance(evidence, dict):
                reasons.append(f"{scope}_evidence_missing")
                continue
            if not _nonempty_str(evidence.get("evidence_ref")):
                reasons.append(f"{scope}_evidence_ref_missing")
            if evidence.get("expired") is True:
                reasons.append(f"{scope}_evidence_expired")
        if reasons:
            violations.append({"release_id": row.get("release_id"), "reasons": reasons})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            stable_joint_releases_unqualified=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", releases_checked=len(rows)),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        releases_checked=len(rows),
    )


def check_qualify_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有韧性承诺强制达到第三档。

    机械断言：承诺长任务/自治运行/故障恢复/自愈的能力必须 level=3；
    短流程或完全确定性能力不统一强制。
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
    rows = rows_of(claims, "capability_commitments", "qualification-claims")
    violations = []
    resilience_flags = (
        "promises_long_task",
        "promises_autonomous_run",
        "promises_fault_recovery",
        "promises_self_heal",
    )
    for row in rows:
        promises = [flag for flag in resilience_flags if row.get(flag) is True]
        if not promises:
            continue
        level = row.get("level")
        if not isinstance(level, int) or level != 3:
            violations.append({
                "capability": row.get("capability"),
                "promises": promises,
                "level": level,
            })
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            resilience_commitments_below_tier3=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", commitments_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        commitments_checked=len(rows),
    )


def check_qualify_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """总体档位取必需范围最低值。

    机械断言：必需范围必须覆盖四个必需平台，入口/方法/能力范围不得被
    静默排除，总体档位等于各必需范围档位最低值。
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
    violations = []
    denominator_levels: list[int] = []
    platform_coverage: set[str] = set()
    for row in scopes:
        kind = row.get("scope_kind")
        if kind not in _SCOPE_KINDS:
            continue
        if row.get("required") is not True:
            violations.append({"scope_id": row.get("scope_id"), "reason": "silently_excluded_from_denominator"})
            continue
        level = row.get("level")
        if not isinstance(level, int):
            violations.append({"scope_id": row.get("scope_id"), "reason": "level_invalid"})
            continue
        denominator_levels.append(level)
        if kind == "platform" and _nonempty_str(row.get("platform")):
            platform_coverage.add(row.get("platform"))
    missing_platforms = sorted(set(REQUIRED_PLATFORMS) - platform_coverage)
    if missing_platforms:
        violations.append({"reason": f"required_platforms_missing:{','.join(missing_platforms)}"})
    overall = claims.get("overall_level")
    if denominator_levels:
        if not isinstance(overall, int):
            violations.append({"reason": "overall_level_invalid"})
        elif overall != min(denominator_levels):
            violations.append({
                "reason": "overall_not_min_of_required_scopes",
                "overall_level": overall,
                "min_scope_level": min(denominator_levels),
            })
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            overall_level_denominator_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", denominator_scopes=len(denominator_levels)
            ),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        denominator_scopes=len(denominator_levels),
    )


def check_qualify_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """未达整体门槛的范围必须显式排除。

    机械断言：低于稳定门槛的范围必须携带实验/暂缺/不在本次稳定支持标记，
    不得被稳定版本静默包含。
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
    threshold = claims.get("stable_threshold", 2)
    if not isinstance(threshold, int):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "qualification-claims.stable_threshold 必须是整数"
        )
    scopes = rows_of(claims, "scopes", "qualification-claims")
    violations = []
    for row in scopes:
        level = row.get("level")
        if not isinstance(level, int):
            violations.append({"scope_id": row.get("scope_id"), "reason": "level_invalid"})
            continue
        if level >= threshold:
            continue
        if row.get("explicit_exclusion_mark") not in _EXCLUSION_MARKS:
            violations.append({"scope_id": row.get("scope_id"), "reason": "exclusion_mark_missing"})
        if row.get("silently_included_in_stable") is True:
            violations.append({"scope_id": row.get("scope_id"), "reason": "silently_included_in_stable"})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("qualification-claims",)),
            ],
            below_threshold_scopes_not_excluded=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", scopes_checked=len(scopes)),
            _doc_digest_row(ctx, ("qualification-claims",)),
        ],
        scopes_checked=len(scopes),
    )


CHECKS = {
    "SFA-ASSESSMENT-001": check_assessment_001,
    "SFA-ASSESSMENT-002": check_assessment_002,
    "SFA-ASSESSMENT-003": check_assessment_003,
    "SFA-ASSESSMENT-005": check_assessment_005,
    "SFA-CASE-001": check_case_001,
    "SFA-CASE-002": check_case_002,
    "SFA-CASE-003": check_case_003,
    "SFA-CASE-005": check_case_005,
    "SFA-EVAL-001": check_eval_001,
    "SFA-EVCACHE-001": check_evcache_001,
    "SFA-EVCACHE-002": check_evcache_002,
    "SFA-EVIDENCE-001": check_evidence_001,
    "SFA-EVIDENCE-002": check_evidence_002,
    "SFA-GATE-004": check_gate_004,
    "SFA-GATE-005": check_gate_005,
    "SFA-GATE-006": check_gate_006,
    "SFA-HISTORY-001": check_history_001,
    "SFA-HISTORY-002": check_history_002,
    "SFA-LEVEL-001": check_level_001,
    "SFA-LEVEL-002": check_level_002,
    "SFA-LEVEL-003": check_level_003,
    "SFA-OBSERVE-003": check_observe_003,
    "SFA-OBSERVE-005": check_observe_005,
    "SFA-OBSERVE-006": check_observe_006,
    "SFA-PROOF-001": check_proof_001,
    "SFA-PROOF-002": check_proof_002,
    "SFA-PROOF-003": check_proof_003,
    "SFA-PROOF-004": check_proof_004,
    "SFA-PROOF-006": check_proof_006,
    "SFA-PROOF-009": check_proof_009,
    "SFA-QUALIFY-001": check_qualify_001,
    "SFA-QUALIFY-002": check_qualify_002,
    "SFA-QUALIFY-003": check_qualify_003,
    "SFA-QUALIFY-004": check_qualify_004,
    "SFA-QUALIFY-006": check_qualify_006,
}
