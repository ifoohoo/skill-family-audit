#!/usr/bin/env python3
"""共享执行族的领域中性归一化器。

本模块不选择规则终态，也不把 implementation binding 当作激活授权。
只有调用方提供与规则精确修订匹配的 ACTIVE terminal record 时才输出执行 finding；
否则一律返回 PREPARED_NOT_AUTHORIZED / UNDETERMINED。
"""
from __future__ import annotations

from typing import Any


FINDING_STATUSES = ("PASS", "FAIL", "UNDETERMINED")
ACTIVE_TERMINALS = {"ACTIVE_MECHANICAL", "ACTIVE_SEMANTIC"}


class ExecutionFamilyError(ValueError):
    """执行族合同或输入不满足失败关闭条件。"""


def _non_empty_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExecutionFamilyError(code)
    return value


def validate_contract(contract: dict[str, Any]) -> None:
    family_id = _non_empty_string(contract.get("family_id"), "FAMILY_ID_MISSING")
    if family_id[0] not in {"M", "S"} or not family_id[1:].isdigit():
        raise ExecutionFamilyError("FAMILY_ID_INVALID")
    expected_mode = "mechanical" if family_id.startswith("M") else "semantic"
    if contract.get("execution_mode") != expected_mode:
        raise ExecutionFamilyError("FAMILY_MODE_MISMATCH")
    domains = contract.get("domains")
    if (
        not isinstance(domains, list)
        or not domains
        or len(domains) != len(set(domains))
        or not all(isinstance(item, str) and item for item in domains)
    ):
        raise ExecutionFamilyError("FAMILY_DOMAINS_INVALID")
    authorization = contract.get("authorization")
    if not isinstance(authorization, dict) or authorization != {
        "activation_required": True,
        "implementation_binding_is_not_activation": True,
        "pending_rules_remain_non_executable": True,
    }:
        raise ExecutionFamilyError("FAMILY_AUTHORIZATION_INVALID")


def _validate_rule(rule: dict[str, Any], contract: dict[str, Any]) -> None:
    _non_empty_string(rule.get("canonical_id"), "RULE_ID_MISSING")
    _non_empty_string(rule.get("revision_digest"), "RULE_REVISION_DIGEST_MISSING")
    if rule.get("domain") not in contract["domains"]:
        raise ExecutionFamilyError("RULE_DOMAIN_FAMILY_MISMATCH")


def _validate_binding(binding: dict[str, Any], rule: dict[str, Any]) -> None:
    if (
        binding.get("canonical_rule_id") != rule["canonical_id"]
        or binding.get("canonical_revision_digest") != rule["revision_digest"]
    ):
        raise ExecutionFamilyError("IMPLEMENTATION_BINDING_RULE_MISMATCH")
    if binding.get("status") not in {"experimental", "verified"}:
        raise ExecutionFamilyError("IMPLEMENTATION_BINDING_NOT_EXECUTABLE")
    _non_empty_string(binding.get("binding_id"), "IMPLEMENTATION_BINDING_ID_MISSING")


def _authorized(
    activation: dict[str, Any] | None,
    rule: dict[str, Any],
    contract: dict[str, Any],
) -> bool:
    if activation is None:
        return False
    expected_terminal = (
        "ACTIVE_MECHANICAL"
        if contract["execution_mode"] == "mechanical"
        else "ACTIVE_SEMANTIC"
    )
    return (
        activation.get("canonical_id") == rule["canonical_id"]
        and activation.get("revision_digest") == rule["revision_digest"]
        and activation.get("terminal") == expected_terminal
    )


def _finding_status(contract: dict[str, Any], facts: dict[str, Any]) -> tuple[str, str]:
    if contract["execution_mode"] == "mechanical":
        if facts.get("complete") is not True:
            return "UNDETERMINED", "MECHANICAL_FACTS_INCOMPLETE"
        violations = facts.get("violations")
        if not isinstance(violations, list):
            return "UNDETERMINED", "MECHANICAL_VIOLATIONS_INVALID"
        return ("FAIL", "MECHANICAL_VIOLATION") if violations else ("PASS", "MECHANICAL_CHECK_PASS")
    review_status = facts.get("review_status")
    if review_status == "PASS":
        return "PASS", "SEMANTIC_REVIEW_PASS"
    if review_status == "FAIL":
        return "FAIL", "SEMANTIC_REVIEW_FAIL"
    return "UNDETERMINED", "SEMANTIC_REVIEW_MISSING"


def run_execution_family(
    contract: dict[str, Any],
    rule: dict[str, Any],
    facts: dict[str, Any],
    *,
    implementation_binding: dict[str, Any] | None = None,
    activation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """归一化一个共享执行族结果；缺少权威激活时不执行。"""
    validate_contract(contract)
    _validate_rule(rule, contract)
    if not isinstance(facts, dict):
        raise ExecutionFamilyError("FAMILY_FACTS_INVALID")
    if implementation_binding is not None:
        _validate_binding(implementation_binding, rule)
    binding_id = (
        implementation_binding.get("binding_id")
        if implementation_binding is not None
        else None
    )
    base = {
        "canonical_rule_id": rule["canonical_id"],
        "revision_digest": rule["revision_digest"],
        "family_id": contract["family_id"],
        "implementation_binding_id": binding_id,
    }
    if not _authorized(activation, rule, contract):
        return {
            "execution_state": "PREPARED_NOT_AUTHORIZED",
            "executable": False,
            "finding": {
                **base,
                "status": "UNDETERMINED",
                "evidence": [],
                "reason_code": "TERMINAL_ACTIVATION_REQUIRED",
            },
        }
    status, reason_code = _finding_status(contract, facts)
    evidence = facts.get("evidence", [])
    if not isinstance(evidence, list):
        raise ExecutionFamilyError("FAMILY_EVIDENCE_INVALID")
    return {
        "execution_state": "EXECUTED",
        "executable": True,
        "finding": {
            **base,
            "status": status,
            "evidence": evidence,
            "reason_code": reason_code,
        },
    }
