"""M7 执行族：方法注册表（W2-B1 共 4 条）。

证据面：项目治理声明 method-registry-projection.json（注册投影与登记
状态）与 authority-contracts.json（权威方法契约消费声明）。约束"已声明者"：
文档缺失 = 无可判违反事实 → PASS；形状非法失败关闭。
"""
from __future__ import annotations

import hashlib
from typing import Any

from .contracts import (
    ExecutorEvidenceError,
    governance_dir,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)


def _registry_rows(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "method-registry-projection")
    if document is None:
        return None
    return rows_of(document, "entries", "method-registry-projection")


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


def _mechanical_methods_to_run(ctx: dict[str, Any]) -> frozenset[str] | None:
    """None means unmanaged compatibility; empty means semantic-only."""
    route = ctx.get("method_route")
    if not isinstance(route, dict):
        return None
    required = route.get("required_mechanical_methods")
    if not isinstance(required, list):
        return None
    return frozenset(required)


def _should_run(ctx: dict[str, Any], method: str) -> bool:
    selected = _mechanical_methods_to_run(ctx)
    return selected is None or method in selected


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


def _completed(rows: list[dict[str, Any]], **evidence: Any) -> dict[str, Any]:
    if not rows:
        return {"status": "PASS", "evidence": dict(evidence)}
    return _finish(rows, **evidence)


def _schema_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "schema_validation", status, "executor_schema_validation_observation", **evidence
    )


def _digest_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "digest_verification", status, "executor_digest_verification_observation", **evidence
    )


def _documents_observed(
    ctx: dict[str, Any], names: tuple[str, ...]
) -> list[dict[str, Any]]:
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
    return observations


def _doc_digest_row(
    ctx: dict[str, Any], names: tuple[str, ...], status: str = "PASS", **evidence: Any
) -> dict[str, Any]:
    return _digest_row(status, documents=_documents_observed(ctx, names), **evidence)


def check_registry_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """未发布的注册协议草案不得作为规范事实或稳定依赖。

    机械断言：已声明注册条目引用协议来源为 draft 时，不得标记
    normative=true 或 stability=stable。
    """
    run_schema = _should_run(ctx, "schema_validation")
    run_digest = _should_run(ctx, "digest_verification")
    if not run_schema and not run_digest:
        return {"status": "PASS", "evidence": {"mechanical_methods_not_in_route": True}}
    rows = _registry_rows(ctx)
    result_rows: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    if run_schema:
        if rows is None:
            result_rows.append(_schema_row("PASS", reason="no_declared_registry"))
            evidence["registry_declared"] = False
        else:
            violations = [
                {"entry": row.get("method_id")}
                for row in rows
                if row.get("protocol_source") == "draft"
                and (row.get("normative") is True or row.get("stability") == "stable")
            ]
            if violations:
                result_rows.append(
                    _schema_row("FAIL", reason="schema_violations", violations=violations)
                )
                evidence["draft_protocol_used_as_normative"] = violations
            else:
                result_rows.append(
                    _schema_row(
                        "PASS",
                        reason="schema_checks_passed",
                        entries_checked=len(rows),
                    )
                )
                evidence["entries_checked"] = len(rows)
    if run_digest:
        result_rows.append(_doc_digest_row(ctx, ("method-registry-projection",)))
        if rows is None:
            evidence.setdefault("registry_declared", False)
    return _completed(result_rows, **evidence)


def check_registry_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册投影不得少报权威方法契约声明的能力、输入输出或副作用。

    机械断言：每个已登记方法的投影能力/输入/输出/副作用集合必须覆盖
    权威契约声明集合（按已声明契约消费声明比对）。
    """
    run_schema = _should_run(ctx, "schema_validation")
    run_digest = _should_run(ctx, "digest_verification")
    if not run_schema and not run_digest:
        return {"status": "PASS", "evidence": {"mechanical_methods_not_in_route": True}}
    rows = _registry_rows(ctx)
    result_rows: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    if run_schema:
        if rows is None:
            result_rows.append(_schema_row("PASS", reason="no_declared_registry"))
            evidence["registry_declared"] = False
        else:
            contracts_document = load_governance_document(ctx, "authority-contracts")
            contracts = {}
            if contracts_document is not None:
                for row in rows_of(
                    contracts_document, "contracts", "authority-contracts"
                ):
                    method_id = row.get("method_id")
                    if not isinstance(method_id, str) or not method_id:
                        raise ExecutorEvidenceError(
                            "GOVERNANCE_DOCUMENT_INVALID",
                            "authority-contracts.contracts.method_id 必须是非空字符串",
                        )
                    contracts[method_id] = row
            violations = []
            for row in rows:
                contract = contracts.get(row.get("method_id"))
                if contract is None:
                    continue
                for field in ("capabilities", "inputs", "outputs", "side_effects"):
                    declared = set(contract.get(field) or [])
                    projected = set(row.get(field) or [])
                    if not isinstance(contract.get(field, []), list) or not isinstance(
                        row.get(field, []), list
                    ):
                        raise ExecutorEvidenceError(
                            "GOVERNANCE_DOCUMENT_INVALID",
                            f"method-registry-projection {field} 必须是数组",
                        )
                    missing = sorted(declared - projected)
                    if missing:
                        violations.append(
                            {
                                "entry": row.get("method_id"),
                                "field": field,
                                "missing": missing,
                            }
                        )
            if violations:
                result_rows.append(
                    _schema_row("FAIL", reason="schema_violations", violations=violations)
                )
                evidence["projection_underreports_contract"] = violations
            else:
                result_rows.append(
                    _schema_row(
                        "PASS",
                        reason="schema_checks_passed",
                        entries_checked=len(rows),
                        contracts_bound=len(contracts),
                    )
                )
                evidence["entries_checked"] = len(rows)
                evidence["contracts_bound"] = len(contracts)
    if run_digest:
        result_rows.append(
            _doc_digest_row(ctx, ("method-registry-projection", "authority-contracts"))
        )
        if rows is None:
            evidence.setdefault("registry_declared", False)
    return _completed(result_rows, **evidence)


def check_registry_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """稳定协议无法真实表达的方法必须保持未注册或实验。

    机械断言：声明 expressible_by_stable_protocol=false 的方法状态必须 ∈
    {unregistered, experimental}；伪造 registered/stable 即违反。
    """
    run_schema = _should_run(ctx, "schema_validation")
    run_digest = _should_run(ctx, "digest_verification")
    if not run_schema and not run_digest:
        return {"status": "PASS", "evidence": {"mechanical_methods_not_in_route": True}}
    rows = _registry_rows(ctx)
    result_rows: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    if run_schema:
        if rows is None:
            result_rows.append(_schema_row("PASS", reason="no_declared_registry"))
            evidence["registry_declared"] = False
        else:
            violations = [
                {"entry": row.get("method_id"), "status": row.get("status")}
                for row in rows
                if row.get("expressible_by_stable_protocol") is False
                and row.get("status") not in {"unregistered", "experimental"}
            ]
            if violations:
                result_rows.append(
                    _schema_row("FAIL", reason="schema_violations", violations=violations)
                )
                evidence["inexpressible_methods_registered"] = violations
            else:
                result_rows.append(
                    _schema_row(
                        "PASS",
                        reason="schema_checks_passed",
                        entries_checked=len(rows),
                    )
                )
                evidence["entries_checked"] = len(rows)
    if run_digest:
        result_rows.append(_doc_digest_row(ctx, ("method-registry-projection",)))
        if rows is None:
            evidence.setdefault("registry_declared", False)
    return _completed(result_rows, **evidence)


def check_registry_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册表与技能制品图必须消费同一权威方法契约或其确定性投影。

    机械断言：已声明的注册表消费契约摘要与制品图消费契约摘要必须一致，
    且均为 64 位十六进制；manual_second_source=true 即违反。
    """
    run_schema = _should_run(ctx, "schema_validation")
    run_digest = _should_run(ctx, "digest_verification")
    if not run_schema and not run_digest:
        return {"status": "PASS", "evidence": {"mechanical_methods_not_in_route": True}}
    document = load_governance_document(ctx, "method-registry-projection")
    result_rows: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    digest_violations: list[str] = []
    schema_violations: list[str] = []
    if document is None:
        if run_schema:
            result_rows.append(_schema_row("PASS", reason="no_declared_registry"))
        if run_digest:
            result_rows.append(_doc_digest_row(ctx, ("method-registry-projection",)))
        return _completed(result_rows, registry_declared=False)
    if run_digest:
        registry_digest = document.get("consumed_contract_digest")
        graph_digest = document.get("artifact_graph_consumed_contract_digest")
        if not is_hex64(registry_digest):
            digest_violations.append("registry_contract_digest_invalid")
        if not is_hex64(graph_digest):
            digest_violations.append("artifact_graph_contract_digest_invalid")
        if not digest_violations and registry_digest != graph_digest:
            digest_violations.append("contract_digests_diverge")
        result_rows.append(
            _digest_row(
                "FAIL" if digest_violations else "PASS",
                reason=(
                    "digest_violations" if digest_violations else "digest_checks_passed"
                ),
                violations=digest_violations,
                consumed_contract_digest=registry_digest,
                documents=_documents_observed(ctx, ("method-registry-projection",)),
            )
        )
        if not digest_violations:
            evidence["consumed_contract_digest"] = registry_digest
    if run_schema:
        if document.get("manual_second_source") is True:
            schema_violations.append("manual_second_source")
        result_rows.append(
            _schema_row(
                "FAIL" if schema_violations else "PASS",
                reason=(
                    "schema_violations" if schema_violations else "schema_checks_passed"
                ),
                violations=schema_violations,
            )
        )
    combined = digest_violations + schema_violations
    if combined:
        evidence["dual_source_contract_violations"] = combined
    return _completed(result_rows, **evidence)


CHECKS = {
    "SFA-REGISTRY-002": check_registry_002,
    "SFA-REGISTRY-004": check_registry_004,
    "SFA-REGISTRY-007": check_registry_007,
    "SFA-REGISTRY-010": check_registry_010,
}
