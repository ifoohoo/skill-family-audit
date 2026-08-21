"""M7 执行族：方法注册表（W2-B1 共 4 条）。

证据面：项目治理声明 method-registry-projection.json（注册投影与登记
状态）与 authority-contracts.json（权威方法契约消费声明）。约束"已声明者"：
文档缺失 = 无可判违反事实 → PASS；形状非法失败关闭。
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


def _registry_rows(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "method-registry-projection")
    if document is None:
        return None
    return rows_of(document, "entries", "method-registry-projection")


def check_registry_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """未发布的注册协议草案不得作为规范事实或稳定依赖。

    机械断言：已声明注册条目引用协议来源为 draft 时，不得标记
    normative=true 或 stability=stable。
    """
    rows = _registry_rows(ctx)
    if rows is None:
        return result("PASS", registry_declared=False)
    violations = [
        {"entry": row.get("method_id")}
        for row in rows
        if row.get("protocol_source") == "draft"
        and (row.get("normative") is True or row.get("stability") == "stable")
    ]
    if violations:
        return result("FAIL", draft_protocol_used_as_normative=violations)
    return result("PASS", entries_checked=len(rows))


def check_registry_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册投影不得少报权威方法契约声明的能力、输入输出或副作用。

    机械断言：每个已登记方法的投影能力/输入/输出/副作用集合必须覆盖
    权威契约声明集合（按已声明契约消费声明比对）。
    """
    rows = _registry_rows(ctx)
    if rows is None:
        return result("PASS", registry_declared=False)
    contracts_document = load_governance_document(ctx, "authority-contracts")
    contracts = {}
    if contracts_document is not None:
        for row in rows_of(contracts_document, "contracts", "authority-contracts"):
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
                    {"entry": row.get("method_id"), "field": field, "missing": missing}
                )
    if violations:
        return result("FAIL", projection_underreports_contract=violations)
    return result("PASS", entries_checked=len(rows), contracts_bound=len(contracts))


def check_registry_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """稳定协议无法真实表达的方法必须保持未注册或实验。

    机械断言：声明 expressible_by_stable_protocol=false 的方法状态必须 ∈
    {unregistered, experimental}；伪造 registered/stable 即违反。
    """
    rows = _registry_rows(ctx)
    if rows is None:
        return result("PASS", registry_declared=False)
    violations = [
        {"entry": row.get("method_id"), "status": row.get("status")}
        for row in rows
        if row.get("expressible_by_stable_protocol") is False
        and row.get("status") not in {"unregistered", "experimental"}
    ]
    if violations:
        return result("FAIL", inexpressible_methods_registered=violations)
    return result("PASS", entries_checked=len(rows))


def check_registry_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """注册表与技能制品图必须消费同一权威方法契约或其确定性投影。

    机械断言：已声明的注册表消费契约摘要与制品图消费契约摘要必须一致，
    且均为 64 位十六进制；manual_second_source=true 即违反。
    """
    document = load_governance_document(ctx, "method-registry-projection")
    if document is None:
        return result("PASS", registry_declared=False)
    registry_digest = document.get("consumed_contract_digest")
    graph_digest = document.get("artifact_graph_consumed_contract_digest")
    violations = []
    if not is_hex64(registry_digest):
        violations.append("registry_contract_digest_invalid")
    if not is_hex64(graph_digest):
        violations.append("artifact_graph_contract_digest_invalid")
    if not violations and registry_digest != graph_digest:
        violations.append("contract_digests_diverge")
    if document.get("manual_second_source") is True:
        violations.append("manual_second_source")
    if violations:
        return result("FAIL", dual_source_contract_violations=violations)
    return result("PASS", consumed_contract_digest=registry_digest)


CHECKS = {
    "SFA-REGISTRY-002": check_registry_002,
    "SFA-REGISTRY-004": check_registry_004,
    "SFA-REGISTRY-007": check_registry_007,
    "SFA-REGISTRY-010": check_registry_010,
}
