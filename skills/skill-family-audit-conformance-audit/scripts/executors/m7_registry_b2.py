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

import base64
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any

from .contracts import (
    FIXED_HUMAN_ENTRIES,
    ExecutorEvidenceError,
    governance_dir,
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


def _static_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "static_scan", status, "executor_static_scan_observation", **evidence
    )


def _target_file(ctx: dict[str, Any], relative: str) -> Path | None:
    """目标真实文件（只读）；不存在、不可读或符号链接返回 None。"""
    path = Path(ctx["target"], *relative.split("/"))
    if not path.is_file() or path.is_symlink():
        return None
    return path


def _pinned_version(value: Any) -> bool:
    """精确钉扎版本判定：拒绝 ^/~/latest/x/* 等浮动或通配标记。"""
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip().lower()
    if any(marker in text for marker in ("^", "~", "*", "latest", "x")):
        return False
    return True


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
    rows = rows_of(document, "runs", "artifact-method-runs")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        if not _nonempty_str(row.get("artifact_type")):
            schema_reasons.append("artifact_type_missing")
        if not _nonempty_str(row.get("contract_major_version")):
            schema_reasons.append("contract_major_version_missing")
        if not is_hex64(row.get("contract_content_digest")):
            digest_reasons.append("contract_content_digest_invalid")
        if schema_reasons or digest_reasons:
            violations.append(
                {"run_id": row.get("run_id"), "reasons": schema_reasons + digest_reasons}
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("contract_content_digest_invalid",)
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
            runs_without_precise_contract=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", runs_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        runs_checked=len(rows),
    )


def check_artmethod_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式追溯结果接入制品图。

    机械断言：每条已声明正式结果必须写入权威制品图、记录来源关系并
    刷新关系锁。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            formal_results_not_in_graph=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", results_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        results_checked=len(rows),
    )


def check_artmethod_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """快速入口不直接拥有制品契约。

    机械断言：每条 quickstart 路由不得登记或重新解释制品契约，被路由的
    严格方法必须承担全部契约与图关系义务。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            quickstart_owning_contracts=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", routes_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        routes_checked=len(rows),
    )


def check_artmethod_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """先选择契约主版本和精确内容。

    机械断言：每条契约选择必须依据制品身份/采用锁/兼容政策确定主版本，
    用不可变内容摘要固定内容；不得使用漂移版本名或"最新"。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
    rows = rows_of(document, "contract_selections", "artifact-method-runs")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        for field in ("artifact_identity", "adoption_lock_ref", "compatibility_policy_ref"):
            if not _nonempty_str(row.get(field)):
                schema_reasons.append(f"{field}_missing")
        if not _nonempty_str(row.get("contract_major_version")):
            schema_reasons.append("contract_major_version_missing")
        if not is_hex64(row.get("fixed_content_digest")):
            digest_reasons.append("fixed_content_digest_invalid")
        if row.get("uses_drifting_version_name") is True:
            schema_reasons.append("uses_drifting_version_name")
        if row.get("uses_latest") is True:
            schema_reasons.append("uses_latest")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "selection_id": row.get("selection_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("fixed_content_digest_invalid",)
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
            contract_selections_not_fixed=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", selections_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        selections_checked=len(rows),
    )


def check_artmethod_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """可兼容旧版无损转换为统一表示。

    机械断言：每条旧版转换必须在字段/语义/身份/关系四轴无损，且记录
    来源版本、转换器与前后摘要。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
    rows = rows_of(document, "legacy_conversions", "artifact-method-runs")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        for axis in ("fields", "semantics", "identity", "relations"):
            if row.get(f"lossless_{axis}") is not True:
                schema_reasons.append(f"lossy_{axis}")
        if not _nonempty_str(row.get("source_version")):
            schema_reasons.append("source_version_missing")
        if not _nonempty_str(row.get("converter")):
            schema_reasons.append("converter_missing")
        if not is_hex64(row.get("before_digest")):
            digest_reasons.append("before_digest_invalid")
        if not is_hex64(row.get("after_digest")):
            digest_reasons.append("after_digest_invalid")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "conversion_id": row.get("conversion_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("before_digest_invalid", "after_digest_invalid")
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
            legacy_conversions_lossy_or_unrecorded=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", conversions_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        conversions_checked=len(rows),
    )


def check_artmethod_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """无法安全转换时停止且不猜测。

    机械断言：每条不可安全处理输入必须受阻，保留原输入与诊断，不得
    猜测、补造或静默丢弃。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            unsafe_inputs_not_blocked=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", blocked_inputs_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        blocked_inputs_checked=len(rows),
    )


def check_artmethod_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """先执行基础制品契约校验。

    机械断言：每条基础校验必须覆盖权威领域规范定义的结构/字段/身份/
    不变量；基础校验未通过不得进入成功结论。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            base_validations_incomplete=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", validations_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        validations_checked=len(rows),
    )


def check_artmethod_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """再执行项目单调加严校验。

    机械断言：每条项目加严必须在基础校验通过后执行，覆盖必填/取值/
    关系/质量四类约束，且只单调加严。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            project_strengthenings_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", strengthenings_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        strengthenings_checked=len(rows),
    )


def check_artmethod_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """校验制品关系追溯和证据完整性。

    机械断言：每条关系证据校验必须覆盖六类必需关系，且存在、身份一致、
    仍然新鲜。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            relation_evidence_incomplete=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", checks_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        checks_checked=len(rows),
    )


def check_artmethod_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """校验制品锁与当前内容一致。

    机械断言：每条锁一致性校验必须核对契约摘要与关系新鲜度锁和当前
    内容一致；锁陈旧/用途错误/被代替时必须受阻。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
    rows = rows_of(document, "lock_consistency_checks", "artifact-method-runs")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        if not is_hex64(row.get("adopted_contract_digest")):
            digest_reasons.append("adopted_contract_digest_invalid")
        if row.get("matches_current_content") is not True:
            schema_reasons.append("content_mismatch")
        if row.get("relation_freshness_lock_valid") is not True:
            schema_reasons.append("relation_freshness_lock_invalid")
        stale = (
            row.get("lock_stale") is True
            or row.get("lock_misused") is True
            or row.get("lock_supplanted_by_other_lock") is True
        )
        if stale and row.get("blocked") is not True:
            schema_reasons.append("stale_or_misused_lock_not_blocked")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "check_id": row.get("check_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("adopted_contract_digest_invalid",)
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
            lock_consistency_broken=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", checks_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        checks_checked=len(rows),
    )


def check_artmethod_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """六步校验顺序不得跳跃。

    机械断言：每条步骤序列必须含六步且索引严格递增；后一步通过不得
    覆盖前一步失败或未运行。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            step_sequences_skipped=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", sequences_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        sequences_checked=len(rows),
    )


def check_artmethod_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """编写方法通过全部确定性校验后成功。

    机械断言：每条编写结果报告必须声明本次全部正式制品完成有序校验，
    且不存在未验证正式输出。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            author_success_reports_unverified=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", reports_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        reports_checked=len(rows),
    )


def check_artmethod_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """修复方法保留原审阅关系并复验。

    机械断言：每条修复结果报告必须完成有序校验、逐项处置发现、保留
    未解决发现可见性，并保持与原审阅结果和修复任务的关系。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            repair_reports_untraceable=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", reports_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        reports_checked=len(rows),
    )


def check_artmethod_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """审阅接收不合规输入但不得假通过。

    机械断言：每条审阅报告必须先运行适用确定性校验并把结构/关系问题
    写入标准审阅结果；基础校验失败或必需检查未运行时不得报告通过。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            review_false_passes=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", reports_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        reports_checked=len(rows),
    )


def check_artmethod_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """旧版转换只有无损且复验后成功。

    机械断言：每条转换结果报告必须无损、通过当前契约校验、前后来源
    关系完整且转换记录可重建；否则必须受阻而非产出猜测版本。
    """
    document = _artifact_method_runs(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_artifact_method_runs"),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            artifact_method_runs_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("artifact-method-runs",)),
            ],
            conversion_reports_invalid=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", reports_checked=len(rows)),
            _doc_digest_row(ctx, ("artifact-method-runs",)),
        ],
        reports_checked=len(rows),
    )


def _registry_projection(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "method-registry-projection")


def check_registry_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """只依赖已发布注册协议。

    机械断言：每条协议依赖必须 status=published 且锁定精确版本；
    draft 或未锁定即违反。
    """
    document = _registry_projection(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_registry"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            registry_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            unpublished_or_unlocked_protocol_dependencies=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", dependencies_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("method-registry-projection",)),
        ],
        dependencies_checked=len(rows),
    )


def check_registry_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册投影具有完整匹配字段。

    机械断言：每条注册投影条目必须含稳定方法身份/提供方/方法种类/摘要/
    匹配域/业务对象或制品类型/意图/接收对象/产出对象/粗粒度副作用十项，
    摘要为 64 位十六进制。
    """
    document = _registry_projection(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_registry"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            registry_declared=False,
        )
    rows = rows_of(document, "entries", "method-registry-projection")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        for field in _REGISTRY_PROJECTION_FIELDS:
            value = row.get(field)
            if field == "digest":
                if not is_hex64(value):
                    digest_reasons.append("digest_invalid")
            elif field == "side_effects":
                if not isinstance(value, list) or not all(_nonempty_str(item) for item in value):
                    schema_reasons.append("side_effects_invalid")
            elif not _nonempty_str(value):
                schema_reasons.append(f"{field}_missing")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "entry": row.get("method_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("digest_invalid",)
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
            projection_fields_incomplete=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", entries_checked=len(rows)),
            _doc_digest_row(ctx, ("method-registry-projection",)),
        ],
        entries_checked=len(rows),
    )


def check_registry_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册方法遵守非空业务对象要求。

    机械断言：锁定协议要求业务对象或制品类型非空时，每条注册条目必须
    提供非空标签，且有权威契约与实际输入输出证据支持。
    """
    document = _registry_projection(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_registry"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            registry_declared=False,
        )
    required = document.get("locked_protocol_requires_nonempty_business_object")
    if required is not True:
        return _finish(
            [
                _schema_row("PASS", reason="nonempty_business_object_not_required"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            nonempty_business_object_not_required=True,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            nonempty_business_object_unsatisfied=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", entries_checked=len(rows)),
            _doc_digest_row(ctx, ("method-registry-projection",)),
        ],
        entries_checked=len(rows),
    )


def check_registry_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """方法注册表拥有解析运行职责。

    机械断言：注册表职责边界行必须拥有提供方验证/项目叠加/查询解析/
    运行锁四项，且不拥有方法的领域制品关系。
    """
    document = _registry_projection(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_registry"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            registry_declared=False,
        )
    rows = rows_of(document, "responsibility_boundaries", "method-registry-projection")
    registry_rows = [row for row in rows if row.get("owner") == "agent-method-registry"]
    if not registry_rows:
        return _finish(
            [
                _schema_row("FAIL", reason="agent-method-registry_boundary_missing"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            reason="agent-method-registry_boundary_missing",
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            registry_responsibilities_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", boundaries_checked=len(registry_rows)
            ),
            _doc_digest_row(ctx, ("method-registry-projection",)),
        ],
        boundaries_checked=len(registry_rows),
    )


def check_registry_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能制品图拥有方法追溯职责。

    机械断言：制品图职责边界行必须拥有契约与能力/内部实现/评估/发布
    四项追溯，且不负责任解析本次方法提供方。
    """
    document = _registry_projection(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_registry"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            registry_declared=False,
        )
    rows = rows_of(document, "responsibility_boundaries", "method-registry-projection")
    graph_rows = [row for row in rows if row.get("owner") == "skill-artifact-graph"]
    if not graph_rows:
        return _finish(
            [
                _schema_row("FAIL", reason="skill-artifact-graph_boundary_missing"),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            reason="skill-artifact-graph_boundary_missing",
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("method-registry-projection",)),
            ],
            graph_responsibilities_invalid=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", boundaries_checked=len(graph_rows)
            ),
            _doc_digest_row(ctx, ("method-registry-projection",)),
        ],
        boundaries_checked=len(graph_rows),
    )


def _template_overrides(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "template-overrides")


def check_template_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目模板覆盖仍满足基础契约。

    机械断言：每条覆盖声明不得删除或放宽上级强制语义，生成结果仍满足
    基础制品契约。
    """
    document = _template_overrides(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_template_overrides"),
                _doc_digest_row(ctx, ("template-overrides",)),
            ],
            template_overrides_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("template-overrides",)),
            ],
            overrides_breaking_base_contract=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", overrides_checked=len(rows)),
            _doc_digest_row(ctx, ("template-overrides",)),
        ],
        overrides_checked=len(rows),
    )


def check_template_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族不得复制制品结构定义。

    机械断言：每条结构定义行必须引用权威契约而非复制可独立演进的
    结构定义；模板只保存填充结构与默认内容。
    """
    document = _template_overrides(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_template_overrides"),
                _doc_digest_row(ctx, ("template-overrides",)),
            ],
            template_overrides_declared=False,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("template-overrides",)),
            ],
            duplicated_structure_definitions=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", definitions_checked=len(rows)
            ),
            _doc_digest_row(ctx, ("template-overrides",)),
        ],
        definitions_checked=len(rows),
    )


def check_template_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """模板变化重跑契约和代表生成测试。

    机械断言：每条模板变化必须对绑定契约重跑结构校验/代表生成/项目
    加严/关系验证，且旧测试结果随模板摘要变化失效。
    """
    document = _template_overrides(ctx)
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_template_overrides"),
                _doc_digest_row(ctx, ("template-overrides",)),
            ],
            template_overrides_declared=False,
        )
    rows = rows_of(document, "template_changes", "template-overrides")
    violations = []
    for row in rows:
        schema_reasons = []
        digest_reasons = []
        for rerun in (
            "structure_validation",
            "representative_generation",
            "project_strengthening",
            "relation_validation",
        ):
            if row.get(f"reran_{rerun}") is not True:
                schema_reasons.append(f"rerun_missing:{rerun}")
        if not is_hex64(row.get("template_digest_after_change")):
            digest_reasons.append("template_digest_invalid")
        if row.get("old_results_invalidated_on_digest_change") is not True:
            schema_reasons.append("old_results_not_invalidated")
        if schema_reasons or digest_reasons:
            violations.append(
                {
                    "change_id": row.get("change_id"),
                    "reasons": schema_reasons + digest_reasons,
                }
            )
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("template_digest_invalid",)
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
            template_changes_not_revalidated=violations,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", changes_checked=len(rows)),
            _doc_digest_row(ctx, ("template-overrides",)),
        ],
        changes_checked=len(rows),
    )


# ---------------------------------------------------------------------------
# P4-D1：REGISTRY-011..015（注册边界/升格形态/引用层钉扎/投影定性，
# 机械执行器；只读目标树，逐机械方法独立 subresult）
# ---------------------------------------------------------------------------


def _catalog_entries(ctx: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]] | None:
    """读取真实 agent-methods/catalog.yaml 的注册条目最小事实面。"""
    path = _target_file(ctx, "agent-methods/catalog.yaml")
    if path is None:
        return None
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    current: dict[str, Any] | None = None
    item_indent: int | None = None
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        match = re.match(r"^(\s*)-\s+ref:\s*(.*?)\s*$", line)
        if match:
            if current is not None:
                entries.append(current)
            scalar = match.group(2).strip()
            if len(scalar) >= 2 and scalar[0] == scalar[-1] and scalar[0] in "\"'":
                scalar = scalar[1:-1]
            if not scalar or any(char in scalar for char in "{}[]|>&*! "):
                errors.append(f"catalog_ref_invalid:{line_no}")
                current = None
                item_indent = None
                continue
            current = {"ref": scalar, "line": line_no}
            item_indent = len(match.group(1))
            continue
        if current is not None:
            next_item = re.match(r"^(\s*)-\s+", line)
            if next_item and len(next_item.group(1)) <= (item_indent or 0):
                entries.append(current)
                current = None
                item_indent = None
                continue
            kind = re.match(r"^\s+kind:\s*(.*?)\s*$", line)
            if kind:
                scalar = kind.group(1).strip()
                if len(scalar) >= 2 and scalar[0] == scalar[-1] and scalar[0] in "\"'":
                    scalar = scalar[1:-1]
                if not scalar or any(char in scalar for char in "{}[]|>&*! "):
                    errors.append(f"catalog_kind_invalid:{line_no}")
                elif "kind" in current:
                    errors.append(f"catalog_kind_duplicate:{line_no}")
                else:
                    current["kind"] = scalar
    if current is not None:
        entries.append(current)
    if not entries:
        errors.append("catalog_entries_unparseable")
    elif any("kind" not in entry for entry in entries):
        errors.append("catalog_entry_kind_missing")
    return entries, errors


def _registration_boundary_authority(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """读取随当前 SFA 包分发的注册边界真源。

    受检目标里的同名文件不是 Audit 的 Oracle，不能覆盖规则含义。源码布局与
    四宿主生成布局都从执行器自身向上定位包根 ``spec/``。
    """
    authority_path = None
    for base in Path(__file__).resolve().parents:
        for relative in (
            "spec/methods/registration-boundary.json",
            "shared/methods/registration-boundary.json",
        ):
            candidate = base / relative
            if candidate.is_file() and not candidate.is_symlink():
                authority_path = candidate
                break
        if authority_path is not None:
            break
    if authority_path is None:
        return None
    try:
        value = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError("AUDIT_AUTHORITY_INVALID", f"注册边界真源无法解析: {exc}") from exc
    return value if isinstance(value, dict) else None


def _registration_implementation(
    ctx: dict[str, Any], relative: str
) -> tuple[dict[str, Any] | None, str]:
    """读取受检 SFA 的真实 registry implementation 投影。

    ``registration-boundary`` 只定义边界，不证明目标已经完成注册。本函数只
    读取边界显式引用的目标文件；平台包沿用既有 ``shared/methods`` 投影路径。
    """
    path = _target_file(ctx, relative)
    resolved_relative = relative
    if path is None and relative.startswith("spec/methods/"):
        resolved_relative = "shared/methods/" + relative.removeprefix("spec/methods/")
        path = _target_file(ctx, resolved_relative)
    if path is None:
        return None, resolved_relative
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(
            "TARGET_REGISTRY_IMPLEMENTATION_INVALID",
            f"注册实现投影无法解析: {resolved_relative}: {exc}",
        ) from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "TARGET_REGISTRY_IMPLEMENTATION_INVALID",
            f"注册实现投影必须是对象: {resolved_relative}",
        )
    return value, resolved_relative


def _sfa_product_gate(ctx: dict[str, Any]) -> dict[str, Any] | None:
    scope = ctx.get("scope")
    plugin_project = scope.get("plugin_project") if isinstance(scope, dict) else None
    plugin = plugin_project.get("plugin") if isinstance(plugin_project, dict) else None
    plugin_id = plugin.get("id") if isinstance(plugin, dict) else None
    if not _nonempty_str(plugin_id):
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="target_plugin_identity_unconfirmed")],
            target_plugin_id=None,
        )
    if plugin_id != "skill-family-audit":
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="target_plugin_is_not_skill_family_audit",
                         target_plugin_id=plugin_id)],
            target_plugin_id=plugin_id,
        )
    return None


_REGISTRY_VERSION = "0.2.2"
_REGISTRY_API_ID = "io.github.mzdbxqh.skill-family-audit-family"
_REGISTRY_IMPLEMENTATION_ID = "io.github.mzdbxqh.skill-family-audit"
_REGISTRY_SERVICE_PREFIX = "io.github.mzdbxqh.skill-family-audit."


def _audit_registry_adapter_authority(
    version: str = _REGISTRY_VERSION,
) -> dict[str, Any] | None:
    """读取随当前 Audit 包分发的精确版本 adapter 权威，不信任受检目标自报。"""
    name = f"agent-method-registry-{version}.json"
    for base in Path(__file__).resolve().parents:
        for relative in (
            f"spec/external-adapters/{name}",
            f"shared/external-adapters/{name}",
        ):
            candidate = base / relative
            if not candidate.is_file() or candidate.is_symlink():
                continue
            try:
                value = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ExecutorEvidenceError(
                    "AUDIT_AUTHORITY_INVALID", f"Registry adapter 权威无法解析: {exc}"
                ) from exc
            return value if isinstance(value, dict) else None
    return None


def _released_registry_runtime(ctx: dict[str, Any] | None = None) -> Path | None:
    """定位精确 0.2.2 的公开 Node 包；只消费其公开 API 与 protocol 子路径。

    候选 Skill 自身不携带 Registry 依赖；真实消费事实位于受检项目的安装闭包。
    因此先沿目标项目向上查找，再兼容仓内执行器自身的安装闭包。
    """
    bases: list[Path] = []
    if isinstance(ctx, dict):
        target = ctx.get("target")
        if isinstance(target, (str, Path)):
            resolved_target = Path(target).resolve()
            bases.extend((resolved_target, *resolved_target.parents))
    bases.extend(Path(__file__).resolve().parents)
    seen: set[Path] = set()
    for base in bases:
        if base in seen:
            continue
        seen.add(base)
        candidate = base / "node_modules" / "agent-method-registry"
        package_path = candidate / "package.json"
        if not package_path.is_file() or package_path.is_symlink():
            continue
        try:
            package = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if package.get("name") == "agent-method-registry" and package.get("version") == _REGISTRY_VERSION:
            return candidate
    return None


def _strict_target_bytes(
    ctx: dict[str, Any], relative: str
) -> tuple[str, bytes | None, str | None]:
    """经既有 Foundation strict-read 读取目标字节，返回 PASS/FAIL/EM。"""
    import conformance_check

    try:
        observed = conformance_check._foundation(
            {"operation": "read-file-strict", "root": str(ctx["target"]), "path": relative}
        )
    except OSError:
        return "EVIDENCE_MISSING", None, "target_byte_evidence_missing"
    except Exception as exc:
        try:
            envelope = json.loads(str(exc))
        except (TypeError, json.JSONDecodeError):
            envelope = None
        error = envelope.get("error") if isinstance(envelope, dict) else None
        details = error.get("details") if isinstance(error, dict) else None
        kind = details.get("kind") if isinstance(details, dict) else None
        if kind in {"missing-resource", "read-failed", "unsafe-state-entry"}:
            return "EVIDENCE_MISSING", None, "target_byte_evidence_missing"
        return "FAIL", None, "target_path_not_strictly_readable"
    content = observed.get("content") if isinstance(observed, dict) else None
    data = content.get("data") if isinstance(content, dict) else None
    if (
        not isinstance(content, dict)
        or content.get("type") != "Buffer"
        or not isinstance(data, list)
        or any(type(item) is not int or item < 0 or item > 255 for item in data)
    ):
        return "FAIL", None, "foundation_read_file_strict_invalid_response"
    return "PASS", bytes(data), None


def _registry_release_evidence(
    ctx: dict[str, Any], version: str = _REGISTRY_VERSION, *,
    require_audit_authority: bool = True,
) -> dict[str, Any]:
    """证明目标采用的 adapter、tarball、Schema 与被调用公开 runtime 同版。"""
    cache = ctx.setdefault("_m7_registry_release_evidence_by_version", {})
    if not isinstance(cache, dict):
        return {"status": "FAIL", "reason": "registry_release_cache_invalid"}
    cache_key = f"{version}:audit-authority={str(require_audit_authority).lower()}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return cached

    def finish(evidence: dict[str, Any]) -> dict[str, Any]:
        cache[cache_key] = evidence
        return evidence

    authority = _audit_registry_adapter_authority(version)
    if require_audit_authority and not isinstance(authority, dict):
        return finish({
            "status": "EVIDENCE_MISSING",
            "reason": "registry_adapter_authority_missing",
            "version": version,
        })
    adapter_relative = f"spec/external-adapters/agent-method-registry-{version}.json"
    adapter_path = _target_file(ctx, adapter_relative)
    if adapter_path is None:
        adapter_relative = f"shared/external-adapters/agent-method-registry-{version}.json"
        adapter_path = _target_file(ctx, adapter_relative)
    if adapter_path is None:
        return finish({
            "status": "EVIDENCE_MISSING",
            "reason": "target_registry_adapter_missing",
            "version": version,
        })
    try:
        adapter = json.loads(adapter_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return finish({
            "status": "FAIL",
            "reason": "target_registry_adapter_unparseable",
            "version": version,
        })
    if require_audit_authority and adapter != authority:
        return finish({
            "status": "FAIL",
            "reason": "target_registry_adapter_authority_mismatch",
            "version": version,
        })
    if adapter.get("version") != version:
        return finish({
            "status": "FAIL",
            "reason": "registry_adapter_version_mismatch",
            "version": version,
        })
    public_api = adapter.get("stableRuntimeApiWhitelist")
    if not isinstance(public_api, list) or "validateCatalog" not in public_api:
        return finish({
            "status": "FAIL",
            "reason": "registry_v1_validation_api_not_declared",
            "version": version,
        })
    tarball_relative = adapter.get("tarballPath")
    if not isinstance(tarball_relative, str) or not tarball_relative:
        return finish({
            "status": "FAIL",
            "reason": "registry_tarball_reference_invalid",
            "version": version,
        })
    read_status, tarball_bytes, read_reason = _strict_target_bytes(ctx, tarball_relative)
    if read_status != "PASS" or tarball_bytes is None:
        return finish({
            "status": read_status,
            "reason": read_reason,
            "path": tarball_relative,
            "version": version,
        })
    observed_sha256 = hashlib.sha256(tarball_bytes).hexdigest()
    observed_integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(tarball_bytes).digest()
    ).decode("ascii")
    if observed_sha256 != adapter.get("packageTarballSha256") or observed_integrity != adapter.get("npmIntegrity"):
        return finish({
            "status": "FAIL",
            "reason": "registry_tarball_digest_mismatch",
            "version": version,
        })
    runtime = _released_registry_runtime(ctx)
    if runtime is None:
        return finish({
            "status": "EVIDENCE_MISSING",
            "reason": "released_registry_runtime_missing",
            "version": version,
        })
    schema_digests = adapter.get("v2Surface", {}).get("v2SchemaDigests")
    if not isinstance(schema_digests, dict) or not schema_digests:
        return finish({
            "status": "FAIL",
            "reason": "registry_schema_digest_authority_missing",
            "version": version,
        })
    required_members = {
        "package/package.json": runtime / "package.json",
        "package/protocol/canonical-json-v1.mjs": runtime / "protocol" / "canonical-json-v1.mjs",
        "package/schemas/catalog.schema.json": runtime / "schemas" / "catalog.schema.json",
    }
    required_members.update({
        f"package/schemas/{name}": runtime / "schemas" / name for name in schema_digests
    })
    try:
        with tarfile.open(fileobj=BytesIO(tarball_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            # The public entrypoint imports the generated chunks.  Compare
            # every distributed JS/MJS member, not only package metadata and
            # schemas, so a tampered installed validator cannot report a
            # fabricated PASS while the release evidence remains green.
            required_members.update({
                member.name: runtime / member.name.removeprefix("package/")
                for member in members
                if member.name.startswith("package/dist/")
                and member.name.endswith((".js", ".mjs"))
            })
            for member_name, runtime_path in required_members.items():
                matches = [member for member in members if member.name == member_name]
                if len(matches) != 1 or not matches[0].isfile() or matches[0].issym() or matches[0].islnk():
                    raise ValueError(f"invalid member: {member_name}")
                stream = archive.extractfile(matches[0])
                if stream is None:
                    raise FileNotFoundError(member_name)
                member_bytes = stream.read()
                # 当前安装版继续逐字节绑定安装态；历史精确版本直接执行已核验
                # tarball，不把当前安装态误当成历史版本字节。
                if version == _REGISTRY_VERSION:
                    if not runtime_path.is_file() or runtime_path.is_symlink():
                        raise FileNotFoundError(member_name)
                    if runtime_path.read_bytes() != member_bytes:
                        raise ValueError(f"runtime mismatch: {member_name}")
                if member_name == "package/package.json":
                    package = json.loads(member_bytes)
                    if package.get("name") != "agent-method-registry" or package.get("version") != version:
                        raise ValueError("tarball package identity mismatch")
                if member_name == "package/schemas/catalog.schema.json":
                    catalog_schema = json.loads(member_bytes)
                    if not isinstance(catalog_schema, dict):
                        raise ValueError("catalog schema invalid")
                if member_name.startswith("package/schemas/"):
                    schema_name = member_name.rsplit("/", 1)[-1]
                    expected_schema_digest = schema_digests.get(schema_name)
                    if expected_schema_digest is not None and hashlib.sha256(member_bytes).hexdigest() != expected_schema_digest:
                        raise ValueError(f"schema digest mismatch: {schema_name}")
    except FileNotFoundError:
        return finish({
            "status": "EVIDENCE_MISSING",
            "reason": "released_registry_runtime_incomplete",
            "version": version,
        })
    except (json.JSONDecodeError, tarfile.TarError, OSError, EOFError, ValueError) as exc:
        return finish({
            "status": "FAIL",
            "reason": "released_registry_bytes_mismatch",
            "detail": str(exc),
            "version": version,
        })
    tarballs = ctx.setdefault("_m7_registry_tarball_bytes_by_version", {})
    if not isinstance(tarballs, dict):
        return finish({"status": "FAIL", "reason": "registry_tarball_cache_invalid"})
    tarballs[version] = tarball_bytes
    evidence = {
        "status": "PASS",
        "reason": "released_registry_bytes_verified",
        "version": version,
        "tarball_sha256": observed_sha256,
        "runtime": str(runtime),
        "catalog_schema_member": "package/schemas/catalog.schema.json",
    }
    return finish(evidence)


def _extract_registry_tarball(tarball_bytes: bytes, destination: Path) -> None:
    """Extract only safe regular package members for exact runtime execution."""
    destination = destination.resolve()
    with tarfile.open(fileobj=BytesIO(tarball_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            name = member.name
            relative = Path(name)
            if (
                not name.startswith("package/")
                or relative.is_absolute()
                or ".." in relative.parts
                or not member.isfile()
                or member.issym()
                or member.islnk()
            ):
                raise ValueError(f"unsafe registry tarball member: {name}")
            target = (destination / relative).resolve()
            if not target.is_relative_to(destination):
                raise ValueError(f"registry tarball member escapes destination: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"registry tarball member unreadable: {name}")
            target.write_bytes(stream.read())


def _validate_with_released_registry(
    ctx: dict[str, Any], document: Any, digest_payload: dict[str, Any] | None = None,
    document_format: str = "json", source_bytes: bytes | None = None,
    version: str = _REGISTRY_VERSION,
    require_audit_authority: bool = True,
) -> dict[str, Any]:
    """直接调用已核验精确版本 tarball 的公共 validateCatalog。"""
    release = _registry_release_evidence(
        ctx, version, require_audit_authority=require_audit_authority
    )
    if release.get("status") != "PASS":
        return release
    runtime = Path(str(release["runtime"]))
    tarballs = ctx.get("_m7_registry_tarball_bytes_by_version")
    tarball_bytes = tarballs.get(version) if isinstance(tarballs, dict) else None
    if not isinstance(tarball_bytes, bytes):
        return {"status": "EVIDENCE_MISSING", "reason": "released_registry_tarball_unavailable"}
    # Production workers intentionally do not inherit an ambient Node PATH.
    # Reuse the consumer's already-centralised Foundation runtime binding so
    # Registry validation executes under the same explicit, verified Node 22
    # byte path as every other public Bundle invocation.
    try:
        import conformance_check

        node_path, _node_version = conformance_check.foundation_node_runtime()
    except (ImportError, AttributeError):
        ambient_node = shutil.which("node")
        if ambient_node is None:
            return {"status": "EVIDENCE_MISSING", "reason": "node_runtime_missing"}
        node_path = Path(ambient_node)
    except Exception as exc:
        return {
            "status": "EVIDENCE_MISSING",
            "reason": "node_runtime_missing",
            "detail": type(exc).__name__,
        }
    node = str(node_path)
    request = {
        "document": document,
        "documentFormat": document_format,
        "digestPayload": digest_payload,
    }
    script = """
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const packageRequire = createRequire(pathToFileURL(input.runtimePackageJson).href);
const { validateCatalog } = await import(pathToFileURL(input.runtimeEntry).href);
let document = input.document;
try {
  if (input.documentFormat === 'yaml') {
    document = packageRequire('yaml').parse(input.document);
  }
} catch (error) {
  process.stdout.write(JSON.stringify({ parseError: String(error) }));
  process.exit(0);
}
const validation = validateCatalog(document);
let apiRevisionDigest = null;
if (input.digestPayload !== null) {
    const { canonicalStringify } = await import(
      pathToFileURL(input.protocolEntry).href
    );
  apiRevisionDigest = 'sha256:' + createHash('sha256')
    .update(canonicalStringify(input.digestPayload)).digest('hex');
}
process.stdout.write(JSON.stringify({ validation, apiRevisionDigest }));
"""
    with tempfile.TemporaryDirectory(prefix="sfa-registry-runtime-") as temporary:
        package_root = Path(temporary) / "package"
        try:
            _extract_registry_tarball(tarball_bytes, Path(temporary))
        except (tarfile.TarError, OSError, ValueError) as exc:
            return {
                "status": "FAIL",
                "reason": "released_registry_tarball_extract_failed",
                "detail": str(exc),
            }
        # pnpm keeps the package's dependency symlinks beside the installed
        # package.  Reuse that dependency directory only for dependencies;
        # the public Registry entrypoint/chunks themselves come from the
        # verified tarball extracted above.
        dependencies = runtime.resolve().parent
        if not dependencies.is_dir() or dependencies.is_symlink():
            return {
                "status": "EVIDENCE_MISSING",
                "reason": "released_registry_runtime_dependencies_missing",
            }
        (package_root / "node_modules").symlink_to(dependencies, target_is_directory=True)
        request["runtimeEntry"] = str(package_root / "dist/index.js")
        request["protocolEntry"] = str(package_root / "protocol/canonical-json-v1.mjs")
        request["runtimePackageJson"] = str(package_root / "package.json")
        try:
            completed = subprocess.run(
                [node, "--input-type=module", "-e", script],
                input=json.dumps(request, ensure_ascii=False),
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                cwd=str(runtime.parents[1]),
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"status": "EVIDENCE_MISSING", "reason": "released_registry_execution_failed"}
    if completed.returncode != 0:
        return {
            "status": "EVIDENCE_MISSING",
            "reason": "released_registry_execution_failed",
            "stderr": completed.stderr[-1000:],
        }
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "EVIDENCE_MISSING", "reason": "released_registry_response_invalid"}
    validation = response.get("validation") if isinstance(response, dict) else None
    if isinstance(response, dict) and _nonempty_str(response.get("parseError")):
        return {
            "status": "FAIL",
            "reason": "released_registry_document_parse_failed",
            "detail": response["parseError"],
        }
    if not isinstance(validation, dict) or not isinstance(validation.get("ok"), bool):
        return {"status": "EVIDENCE_MISSING", "reason": "released_registry_response_invalid"}
    return {
        "status": "PASS" if validation["ok"] else "FAIL",
        "reason": "released_registry_validation_passed" if validation["ok"] else "released_registry_validation_failed",
        "diagnostics": validation.get("diagnostics", []),
        "data": validation.get("data"),
        "api_revision_digest": response.get("apiRevisionDigest"),
        "registry_version": version,
        "tarball_sha256": release.get("tarball_sha256"),
        "catalog_schema_member": release.get("catalog_schema_member"),
        "document_sha256": hashlib.sha256(
            source_bytes
            if source_bytes is not None
            else (
                document.encode("utf-8")
                if isinstance(document, str)
                else json.dumps(
                    document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
        ).hexdigest(),
    }

def check_registry_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册边界真源确认。

    机械断言：注册条目必须落在注册边界真源（spec/methods/
    registration-boundary.json）允许的严格业务方法集合内；人类正式入口
    （help/setup/quickstart，含其前缀子域）与内部能力不得进入注册。
    """
    applicability = _sfa_product_gate(ctx)
    if applicability is not None:
        return applicability
    document = _registry_projection(ctx)
    catalog = _catalog_entries(ctx)
    catalog_entries: list[dict[str, Any]] = []
    if catalog is not None:
        catalog_entries, catalog_errors = catalog
        if catalog_errors:
            return _finish(
                [_static_row("EVIDENCE_MISSING", reason="catalog_registration_surface_unparseable",
                             errors=catalog_errors)],
                catalog_path="agent-methods/catalog.yaml",
            )
    projection_entries = (
        rows_of(document, "entries", "method-registry-projection")
        if document is not None
        else []
    )
    fixed_human_ids = set(FIXED_HUMAN_ENTRIES)
    fixed_violations = []
    for index, row in enumerate(projection_entries):
        method_id = row.get("method_id")
        tail = method_id.rsplit(".", 1)[-1].rsplit(":", 1)[-1] if isinstance(method_id, str) else ""
        if tail in fixed_human_ids or row.get("human_entry") is True:
            fixed_violations.append({"surface": "projection", "index": index,
                                     "method_id": method_id,
                                     "problem": "human_entry_registered"})
    for row in catalog_entries:
        ref = row.get("ref")
        tail = ref.rsplit(".", 1)[-1] if isinstance(ref, str) else ""
        if tail in fixed_human_ids or row.get("kind") in {"human_formal_entry", "human_entry"}:
            fixed_violations.append({"surface": "catalog", "ref": ref,
                                     "kind": row.get("kind"), "line": row.get("line"),
                                     "problem": "human_entry_registered"})
    if fixed_violations:
        return _finish(
            [_static_row("FAIL", reason="registration_entries_outside_boundary",
                         violations=fixed_violations)],
            authority="fixed_human_entries",
        )
    boundary = _registration_boundary_authority(ctx)
    if not isinstance(boundary, dict):
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="registration_boundary_authority_missing")],
            registry_declared=document is not None,
        )
    human_entries = boundary.get("humanEntries")
    strict_methods = boundary.get("strictMethods")
    internal = boundary.get("internalCapabilities")
    if (
        not isinstance(human_entries, list)
        or not isinstance(strict_methods, dict)
        or not isinstance(strict_methods.get("methods"), list)
        or not _nonempty_str(strict_methods.get("registryImplementation"))
        or not isinstance(internal, dict)
        or not isinstance(internal.get("kinds"), list)
    ):
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="registration_boundary_shape_incomplete")],
            registry_declared=True,
        )
    human_ids = {item.get("entryId") for item in human_entries if isinstance(item, dict)}
    strict_rows = strict_methods["methods"]
    strict_io_authority = strict_methods.get("strictIOAuthority")
    implementation_ref = strict_methods["registryImplementation"]
    if (
        not strict_rows
        or not all(_nonempty_str(item) for item in strict_rows)
        or len(strict_rows) != len(set(strict_rows))
        or not _nonempty_str(strict_io_authority)
    ):
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="strict_method_authority_material_missing")],
            registry_declared=document is not None,
        )
    if "{method}" not in strict_io_authority or not strict_io_authority.endswith("#/strictIOBinding"):
        return _finish(
            [_static_row("FAIL", reason="strict_io_authority_contract_invalid",
                         strict_io_authority=strict_io_authority)],
            registry_declared=document is not None,
        )
    strict_ids = set(strict_rows)
    internal_kinds = set(internal["kinds"])
    violations = []
    missing_material = []
    for method_id in sorted(strict_ids):
        if not method_id.startswith("skill-family-audit:"):
            violations.append({"method_id": method_id, "problem": "strict_method_outside_audit_family"})
            continue
        method_name = method_id.rsplit(":", 1)[-1]
        relative_with_fragment = strict_io_authority.replace("{method}", method_name)
        relative, _, fragment = relative_with_fragment.partition("#")
        path = _target_file(ctx, relative)
        if path is None and relative.startswith("spec/methods/"):
            # 平台包沿用既有 ``shared/methods`` 资源投影；正式候选根与源码树
            # 仍按 authority 中的 ``spec/methods`` 原路径解析。
            path = _target_file(ctx, "shared/methods/" + relative.removeprefix("spec/methods/"))
        if path is None:
            missing_material.append({"method_id": method_id, "path": relative,
                                     "problem": "strict_io_authority_file_missing"})
            continue
        try:
            method_document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            violations.append({"method_id": method_id, "path": relative,
                               "problem": "strict_io_authority_file_invalid"})
            continue
        binding = method_document.get("strictIOBinding") if isinstance(method_document, dict) else None
        if not isinstance(binding, dict) or not binding:
            missing_material.append({"method_id": method_id, "path": relative,
                                     "problem": "strict_io_binding_missing"})
            continue
        if method_document.get("methodId") != method_id or fragment != "/strictIOBinding":
            violations.append({"method_id": method_id, "path": relative,
                               "problem": "strict_io_authority_binding_mismatch"})
        for field in ("foundationProfile", "parameterSchema", "outputSchema"):
            if not isinstance(binding.get(field), dict) or not binding[field]:
                missing_material.append({"method_id": method_id, "path": relative,
                                         "problem": f"{field}_missing"})

    implementation, implementation_path = _registration_implementation(
        ctx, implementation_ref
    )
    implementation_entries: list[dict[str, Any]] = []
    if implementation is not None:
        mappings = strict_methods.get("v2ServiceMappings")
        services = implementation.get("services")
        if implementation.get("pluginId") != "skill-family-audit":
            violations.append({
                "surface": "registry_implementation",
                "path": implementation_path,
                "problem": "registry_implementation_plugin_identity_mismatch",
            })
        if not isinstance(mappings, list) or not isinstance(services, dict) or not services:
            violations.append({
                "surface": "registry_implementation",
                "path": implementation_path,
                "problem": "registry_implementation_shape_invalid",
            })
        else:
            mapped_service_ids: set[str] = set()
            for index, mapping in enumerate(mappings):
                if not isinstance(mapping, dict):
                    violations.append({
                        "surface": "registry_implementation",
                        "index": index,
                        "problem": "service_mapping_invalid",
                    })
                    continue
                method_id = mapping.get("logicalMethodId")
                service_id = mapping.get("serviceId")
                if not _nonempty_str(method_id) or not _nonempty_str(service_id):
                    violations.append({
                        "surface": "registry_implementation",
                        "index": index,
                        "method_id": method_id,
                        "service_id": service_id,
                        "problem": "service_mapping_invalid",
                    })
                    continue
                mapped_service_ids.add(service_id)
                service = services.get(service_id)
                implementation_entries.append({
                    "method_id": method_id,
                    "service_id": service_id,
                    "service": service,
                })
                problems = []
                if method_id not in strict_ids:
                    problems.append("method_not_in_strict_registration_boundary")
                if not isinstance(service, dict):
                    problems.append("registered_service_missing")
                elif service.get("serviceImplementationId") != service_id:
                    problems.append("service_implementation_identity_mismatch")
                elif not _nonempty_str(service.get("skill")):
                    problems.append("registered_service_skill_missing")
                if problems:
                    violations.append({
                        "surface": "registry_implementation",
                        "index": index,
                        "method_id": method_id,
                        "service_id": service_id,
                        "problems": problems,
                    })
            for service_id in sorted(set(services) - mapped_service_ids):
                violations.append({
                    "surface": "registry_implementation",
                    "service_id": service_id,
                    "problem": "service_not_declared_by_registration_boundary",
                })
    for index, row in enumerate(projection_entries):
        problems = []
        method_id = row.get("method_id")
        kind = row.get("method_kind")
        tail = method_id.rsplit(".", 1)[-1].rsplit(":", 1)[-1] if isinstance(method_id, str) else ""
        if tail in human_ids:
            problems.append("human_entry_registered")
        elif method_id not in strict_ids:
            problems.append("method_not_in_strict_registration_boundary")
        if kind in internal_kinds:
            problems.append("internal_capability_registered")
        if row.get("human_entry") is True:
            problems.append("human_entry_marker_registered")
        if problems:
            violations.append({"index": index, "method_id": method_id, "problems": problems})
    for row in catalog_entries:
        ref = row.get("ref")
        problems = []
        catalog_method_id = (
            ref.replace("skill-family-audit.", "skill-family-audit:", 1)
            if isinstance(ref, str) and ref.startswith("skill-family-audit.")
            else ref
        )
        if catalog_method_id not in strict_ids:
            problems.append("method_not_in_strict_registration_boundary")
        if row.get("kind") in internal_kinds:
            problems.append("internal_capability_registered")
        if problems:
            violations.append({"ref": ref, "line": row.get("line"), "problems": problems})
    if violations:
        return _finish(
            [_static_row("FAIL", reason="registration_entries_outside_boundary", violations=violations)],
            registry_declared=True,
        )
    if missing_material:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="strict_io_authority_material_missing",
                         missing=missing_material)],
            registry_declared=document is not None,
        )

    actual_surface_count = (
        len(projection_entries) + len(catalog_entries) + len(implementation_entries)
    )
    if actual_surface_count == 0:
        return _finish(
            [_static_row(
                "EVIDENCE_MISSING",
                reason="actual_registration_projection_missing",
                expected_registry_implementation=implementation_path,
            )],
            registry_declared=False,
            entries_checked=0,
        )

    registered_ids = {
        row.get("method_id")
        for row in projection_entries
        if _nonempty_str(row.get("method_id"))
    }
    registered_ids.update(
        row["ref"].replace("skill-family-audit.", "skill-family-audit:", 1)
        for row in catalog_entries
        if _nonempty_str(row.get("ref"))
        and row["ref"].startswith("skill-family-audit.")
    )
    registered_ids.update(
        row["method_id"]
        for row in implementation_entries
        if _nonempty_str(row.get("method_id")) and isinstance(row.get("service"), dict)
    )
    unregistered_strict_methods = sorted(strict_ids - registered_ids)
    if unregistered_strict_methods:
        return _finish(
            [_static_row(
                "FAIL",
                reason="strict_methods_not_registered",
                methods=unregistered_strict_methods,
            )],
            registry_declared=True,
            entries_checked=actual_surface_count,
        )
    return _finish(
        [_static_row("PASS", reason="registration_boundary_and_strict_io_closed",
                     strict_methods_checked=len(strict_ids),
                     entries_checked=actual_surface_count)],
        registry_declared=True,
    )


def check_registry_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """registry-projection v2 升格形态裁决。

    机械断言：v2 升格活动必须声明 v2 文档集形态（apiId/serviceId 前缀/
    严格方法集合）并引用协议权威（钉扎 v2 schema 摘要）；不得采用
    v1+映射并行形态，不得把样例文档当作第二份协议真源。
    """
    applicability = _sfa_product_gate(ctx)
    if applicability is not None:
        return applicability
    boundary = _registration_boundary_authority(ctx)
    if not isinstance(boundary, dict):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="registration_boundary_authority_missing")],
            v2_upgrade_activity=True,
        )
    strict = boundary.get("strictMethods")
    implementation_ref = strict.get("registryImplementation") if isinstance(strict, dict) else None
    mappings = strict.get("v2ServiceMappings") if isinstance(strict, dict) else None
    strict_methods = strict.get("methods") if isinstance(strict, dict) else None
    if (
        not _nonempty_str(implementation_ref)
        or not isinstance(mappings, list)
        or not isinstance(strict_methods, list)
    ):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="registration_boundary_shape_incomplete")],
            v2_upgrade_activity=True,
        )
    implementation, resolved_ref = _registration_implementation(ctx, implementation_ref)
    document = _registry_projection(ctx)
    adjudication = load_governance_document(ctx, "upgrade-adjudication")
    adapter_present = any(
        _target_file(ctx, relative) is not None
        for relative in (
            f"spec/external-adapters/agent-method-registry-{_REGISTRY_VERSION}.json",
            f"shared/external-adapters/agent-method-registry-{_REGISTRY_VERSION}.json",
        )
    )
    if implementation is None and document is None and adjudication is None and not adapter_present:
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="no_v2_upgrade_activity")],
            v2_upgrade_activity=False,
        )
    if implementation is None:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="registry_implementation_missing",
                         expected_path=resolved_ref)],
            v2_upgrade_activity=True,
        )
    legacy_paths = [
        relative
        for relative in (
            "spec/methods/registry-projection.json",
            "shared/methods/registry-projection.json",
        )
        if _target_file(ctx, relative) is not None
    ]
    if legacy_paths:
        return _finish(
            [_schema_row("FAIL", reason="v1_parallel_form_with_mapping", paths=legacy_paths)],
            v2_upgrade_activity=True,
        )

    expected_mappings = {
        "skill-family-audit:conformance-audit":
            "io.github.mzdbxqh.skill-family-audit.conformance-audit",
        "skill-family-audit:release-audit":
            "io.github.mzdbxqh.skill-family-audit.release-audit",
    }
    observed_mappings = {
        row.get("logicalMethodId"): row.get("serviceId")
        for row in mappings
        if isinstance(row, dict)
    }
    problems: list[str] = []
    if set(strict_methods) != set(expected_mappings) or observed_mappings != expected_mappings:
        problems.append("strict_method_mapping_mismatch")
    implements = implementation.get("implements")
    services = implementation.get("services")
    if implementation.get("familyImplementationId") != _REGISTRY_IMPLEMENTATION_ID:
        problems.append("family_implementation_id_mismatch")
    if implementation.get("pluginId") != "skill-family-audit":
        problems.append("plugin_id_mismatch")
    if not isinstance(implements, dict) or implements.get("apiId") != _REGISTRY_API_ID:
        problems.append("api_id_mismatch")
    if not isinstance(implements, dict) or implements.get("apiMajor") != 1:
        problems.append("api_major_mismatch")
    if not isinstance(services, dict) or set(services) != set(expected_mappings.values()):
        problems.append("strict_service_set_mismatch")
    elif any(
        not service_id.startswith(_REGISTRY_SERVICE_PREFIX)
        or not isinstance(service, dict)
        or service.get("serviceImplementationId") != service_id
        for service_id, service in services.items()
    ):
        problems.append("service_identity_mismatch")

    api_services = []
    for logical_id, service_id in expected_mappings.items():
        method_name = logical_id.split(":", 1)[1]
        relative = f"spec/methods/{method_name}.json"
        path = _target_file(ctx, relative)
        if path is None:
            relative = f"shared/methods/{method_name}.json"
            path = _target_file(ctx, relative)
        if path is None:
            return _finish(
                [_schema_row("EVIDENCE_MISSING", reason="strict_method_contract_missing",
                             method_id=logical_id)],
                v2_upgrade_activity=True,
            )
        try:
            method_bytes = path.read_bytes()
            method_contract = json.loads(method_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return _finish(
                [_schema_row("FAIL", reason="strict_method_contract_unparseable",
                             method_id=logical_id)],
                v2_upgrade_activity=True,
            )
        capability = method_contract.get("capability") if isinstance(method_contract, dict) else None
        summary = capability.get("methodSlice") if isinstance(capability, dict) else None
        if not _nonempty_str(summary):
            return _finish(
                [_schema_row("FAIL", reason="strict_method_contract_slice_missing",
                             method_id=logical_id)],
                v2_upgrade_activity=True,
            )
        api_services.append({
            "id": service_id,
            "kind": "workflow",
            "intents": ["audit"],
            "summary": summary,
            "sideEffectCeiling": "read-only",
            "mixSafe": False,
            "methodContractRef": relative,
            "methodContractDigest": "sha256:" + hashlib.sha256(method_bytes).hexdigest(),
        })
    api_payload = {"api": {"id": _REGISTRY_API_ID, "major": 1}, "services": api_services}
    implementation_path = _target_file(ctx, resolved_ref)
    if implementation_path is None:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="registry_implementation_bytes_missing")],
            v2_upgrade_activity=True,
        )
    validation = _validate_with_released_registry(
        ctx, implementation, api_payload, source_bytes=implementation_path.read_bytes()
    )
    if validation.get("status") != "PASS":
        return _finish(
            [_schema_row(
                validation.get("status", "EVIDENCE_MISSING"),
                reason=validation.get("reason", "released_registry_validation_unavailable"),
                diagnostics=validation.get("diagnostics", []),
            )],
            v2_upgrade_activity=True,
        )
    if not isinstance(implements, dict) or implements.get("apiRevisionDigest") != validation.get(
        "api_revision_digest"
    ):
        problems.append("api_revision_digest_mismatch")
    if problems:
        return _finish(
            [_schema_row("FAIL", reason="registry_v2_identity_or_digest_mismatch",
                         problems=problems)],
            v2_upgrade_activity=True,
        )
    return _finish(
        [_schema_row(
            "PASS",
            reason="registry_v2_document_set_validated",
            registry_version=validation["registry_version"],
            implementation_path=resolved_ref,
            implementation_sha256=validation["document_sha256"],
            api_revision_digest=validation["api_revision_digest"],
            methods_checked=len(expected_mappings),
        )],
        v2_upgrade_activity=True,
    )


def check_registry_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """协议引用层为审计消费者引用关系。

    机械断言：external-adapters 登记文件必须钉扎精确版本与
    tarball/schema 摘要并声明 API/CLI 白名单；tarball 字节证据
    （冻结副本）sha256 与 npm integrity 重算比对一致。
    """
    import conformance_check

    target_value = ctx.get("target")
    if not isinstance(target_value, (str, Path)) or not Path(target_value).is_dir():
        return _finish(
            [
                _static_row("NOT_APPLICABLE", reason="target_not_observable"),
                _digest_row("NOT_APPLICABLE", reason="target_not_observable"),
            ],
            adapter_registration=False,
        )
    target_root = Path(target_value)
    adapters_dir = target_root / "spec" / "external-adapters"
    files = []
    if adapters_dir.is_dir():
        files = sorted(
            path.name
            for path in adapters_dir.glob("agent-method-registry-*.json")
            if path.is_file() and not path.is_symlink()
        )
    if not files:
        return _finish(
            [
                _static_row("NOT_APPLICABLE", reason="no_adapter_registration_files"),
                _digest_row("NOT_APPLICABLE", reason="no_adapter_registration_files"),
            ],
            adapter_registration=False,
        )
    static_fail = []
    digest_fail = []
    digest_missing = []
    versions = []
    legacy_fields = {
        "api_whitelist",
        "cli_whitelist",
        "npm_integrity",
        "tarball_sha256",
        "schema_digest",
        "tarball_ref",
    }
    for name in files:
        path = adapters_dir / name
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            static_fail.append({"file": name, "problems": ["registration_file_unparseable"]})
            digest_missing.append({"file": name, "problems": ["pinned_declaration_unavailable"]})
            continue
        if not isinstance(value, dict):
            static_fail.append({"file": name, "problems": ["registration_file_not_object"]})
            digest_missing.append({"file": name, "problems": ["pinned_declaration_unavailable"]})
            continue
        static_problems = []
        version = value.get("version")
        version_parts = version.split(".") if isinstance(version, str) else []
        if (
            not _pinned_version(version)
            or len(version_parts) != 3
            or any(not part.isdigit() for part in version_parts)
        ):
            static_problems.append("unpinned_version_reference")
        elif version in versions:
            static_problems.append("duplicate_version_reference")
        else:
            versions.append(version)
        if value.get("status") == "draft" or value.get("draft") is True:
            static_problems.append("draft_protocol_reference")
        if any(field in value for field in legacy_fields):
            static_problems.append("legacy_parallel_adapter_contract")
        if value.get("adapterId") != "agent-method-registry-v1":
            static_problems.append("adapter_identity_invalid")
        if value.get("package") != "agent-method-registry":
            static_problems.append("registered_package_invalid")
        whitelists = (value.get("stableRuntimeApiWhitelist"), value.get("cliWhitelist"))
        if not all(
            _nonempty_str_list(entry)
            and len(entry) == len(set(entry))
            for entry in whitelists
        ):
            static_problems.append("protocol_reference_scope_missing")
        declared_sha256 = value.get("packageTarballSha256")
        integrity = value.get("npmIntegrity")
        tarball_path = value.get("tarballPath")
        v2_surface = value.get("v2Surface")
        schema_digests = v2_surface.get("v2SchemaDigests") if isinstance(v2_surface, dict) else None
        if not is_hex64(declared_sha256):
            static_problems.append("package_tarball_sha256_pin_invalid")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            static_problems.append("npm_integrity_pin_invalid")
        else:
            try:
                if not base64.b64decode(integrity[7:], validate=True):
                    raise ValueError("empty integrity")
            except (ValueError, TypeError):
                static_problems.append("npm_integrity_pin_invalid")
        if not isinstance(tarball_path, str) or not tarball_path:
            static_problems.append("tarball_path_pin_missing")
        if (
            not isinstance(schema_digests, dict)
            or not schema_digests
            or any(
                not _nonempty_str(schema_name) or not is_hex64(schema_digest)
                for schema_name, schema_digest in (
                    schema_digests.items() if isinstance(schema_digests, dict) else ()
                )
            )
        ):
            static_problems.append("schema_digest_pins_invalid")
        if static_problems:
            static_fail.append({"file": name, "problems": static_problems})
        if not isinstance(tarball_path, str) or not tarball_path:
            digest_missing.append({"file": name, "problems": ["frozen_tarball_evidence_missing"]})
            continue
        if Path(tarball_path).is_absolute():
            digest_fail.append({"file": name, "problems": ["tarball_path_outside_target"]})
            continue
        try:
            observed = conformance_check._foundation(
                {"operation": "read-file-strict", "root": str(target_root), "path": tarball_path}
            )
        except OSError:
            digest_missing.append({"file": name, "problems": ["frozen_tarball_evidence_missing"]})
            continue
        except Exception as exc:
            try:
                envelope = json.loads(str(exc))
            except (TypeError, json.JSONDecodeError):
                envelope = None
            error = envelope.get("error") if isinstance(envelope, dict) and envelope.get("ok") is False else None
            details = error.get("details") if isinstance(error, dict) else None
            kind = details.get("kind") if isinstance(details, dict) else None
            if isinstance(error, dict) and error.get("code") == "SFC2004" and isinstance(details, dict):
                if kind in {"path-traversal", "realpath-escape", "symlink-escape"}:
                    digest_fail.append({"file": name, "problems": ["tarball_path_outside_target"]})
                elif kind in {"missing-resource", "read-failed", "unsafe-state-entry"}:
                    digest_missing.append({"file": name, "problems": ["frozen_tarball_evidence_missing"]})
                else:
                    digest_fail.append({"file": name, "problems": ["foundation_read_file_strict_failed"]})
            else:
                digest_fail.append({"file": name, "problems": ["foundation_read_file_strict_failed"]})
            continue
        content = observed.get("content") if isinstance(observed, dict) else None
        if (
            not isinstance(content, dict)
            or content.get("type") != "Buffer"
            or not isinstance(content.get("data"), list)
            or any(type(item) is not int or item < 0 or item > 255 for item in content["data"])
        ):
            digest_fail.append({"file": name, "problems": ["foundation_read_file_strict_invalid_response"]})
            continue
        payload = bytes(content["data"])
        digest_problems = []
        if hashlib.sha256(payload).hexdigest() != declared_sha256:
            digest_problems.append("tarball_sha256_mismatch")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            digest_problems.append("npm_integrity_format_invalid")
        else:
            expected = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
            if integrity != expected:
                digest_problems.append("npm_integrity_mismatch")
        if digest_problems:
            digest_fail.append({"file": name, "problems": digest_problems})
    return _finish(
        [
            _static_row(
                "FAIL" if static_fail else "PASS",
                reason="adapter_registration_shape_invalid" if static_fail else "adapter_registration_shape_valid",
                violations=static_fail,
            ),
            _digest_row(
                "FAIL" if digest_fail else ("EVIDENCE_MISSING" if digest_missing else "PASS"),
                reason=(
                    "tarball_digest_mismatch"
                    if digest_fail
                    else ("frozen_tarball_evidence_missing" if digest_missing else "tarball_digest_verified")
                ),
                violations=digest_fail or digest_missing,
            ),
        ],
        adapter_registration=True,
        files_checked=len(files),
    )


def check_registry_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """bundled 投影定性与 human_entry 协议外。

    机械断言：bundled catalog / family implementation descriptor 必须经
    钉扎版本的已发布 registry 校验（冻结结果）且引用钉扎协议 schema；
    human_entry 不得作为机器标记写入协议文档。
    """
    applicability = _sfa_product_gate(ctx)
    if applicability is not None:
        return applicability
    boundary = _registration_boundary_authority(ctx)
    strict = boundary.get("strictMethods") if isinstance(boundary, dict) else None
    implementation_ref = strict.get("registryImplementation") if isinstance(strict, dict) else None
    if not _nonempty_str(implementation_ref):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="registration_boundary_authority_missing")],
            registry_projection=False,
        )
    implementation, resolved_ref = _registration_implementation(ctx, implementation_ref)
    catalog_path = _target_file(ctx, "agent-methods/catalog.yaml")
    if implementation is None and catalog_path is None:
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="no_registry_projection_material")],
            registry_projection=False,
        )
    validations = []
    if implementation is not None:
        implementation_path = _target_file(ctx, resolved_ref)
        if implementation_path is None:
            validations.append(("family_implementation_descriptor", resolved_ref, {
                "status": "EVIDENCE_MISSING", "reason": "registry_implementation_bytes_missing",
            }))
        else:
            validations.append(("family_implementation_descriptor", resolved_ref,
                                _validate_with_released_registry(
                                    ctx, implementation, source_bytes=implementation_path.read_bytes()
                                )))
    if catalog_path is not None:
        read_status, catalog_bytes, read_reason = _strict_target_bytes(ctx, "agent-methods/catalog.yaml")
        if read_status != "PASS" or catalog_bytes is None:
            validations.append(("bundled_catalog", "agent-methods/catalog.yaml", {
                "status": read_status, "reason": read_reason,
            }))
        else:
            try:
                catalog_text = catalog_bytes.decode("utf-8")
            except UnicodeDecodeError:
                validations.append(("bundled_catalog", "agent-methods/catalog.yaml", {
                    "status": "FAIL", "reason": "bundled_catalog_not_utf8",
                }))
            else:
                validations.append(("bundled_catalog", "agent-methods/catalog.yaml",
                                    _validate_with_released_registry(
                                        ctx, catalog_text, document_format="yaml",
                                        source_bytes=catalog_bytes,
                                    )))
    failures = []
    missing = []
    checked = []
    for kind, path, validation in validations:
        status = validation.get("status")
        finding = {
            "kind": kind,
            "path": path,
            "reason": validation.get("reason"),
            "diagnostics": validation.get("diagnostics", []),
        }
        if status == "FAIL":
            failures.append(finding)
            continue
        if status != "PASS":
            missing.append(finding)
            continue
        data = validation.get("data")
        if kind == "bundled_catalog" and (
            not isinstance(data, dict)
            or not isinstance(data.get("entries"), list)
            or not data["entries"]
        ):
            failures.append({**finding, "reason": "bundled_catalog_entries_empty"})
            continue
        checked.append({
            "kind": kind,
            "path": path,
            "sha256": validation.get("document_sha256"),
            "registry_version": validation.get("registry_version"),
        })
    if failures:
        return _finish(
            [_schema_row("FAIL", reason="registry_public_validation_failed",
                         violations=failures)],
            registry_projection=True,
        )
    if missing:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="registry_public_validation_unavailable",
                         missing=missing)],
            registry_projection=True,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="registry_projection_validated_by_released_registry",
                documents=checked,
            )
        ],
        registry_projection=True,
    )


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
    "SFA-REGISTRY-011": check_registry_011,
    "SFA-REGISTRY-012": check_registry_012,
    "SFA-REGISTRY-013": check_registry_013,
    "SFA-REGISTRY-015": check_registry_015,
    "SFA-TEMPLATE-003": check_template_003,
    "SFA-TEMPLATE-004": check_template_004,
    "SFA-TEMPLATE-005": check_template_005,
}
