"""M1 执行族：规则治理与不可豁免（W2-B1 共 7 条）。

证据面：
- 项目治理声明：exceptions.json / rule-overrides.json / release-gate-results.json /
  non-waivable-baselines.json；
- 本次运行装载的规范清单（ctx["manifest"]）与规范包索引（ctx["spec_index"]）。

不可豁免规则身份不由执行器硬编码（non-exempt-baselines 精确映射仍待用户内容
确认）；执行器消费项目自己声明的 ``non-waivable-baselines.json.rule_ids`` 作为
判定集合，未声明者按"未声明不可豁免集合"处理。
"""
from __future__ import annotations

import re
from typing import Any

from .contracts import (
    VIOLATION_IMPACT_VOCABULARY,
    ExecutorEvidenceError,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

_OVERRIDE_ACTIONS = {"add_independent_rule", "tighten", "close", "override", "loosen", "waive"}
_FORBIDDEN_OVERRIDE_ACTIONS = {"close", "override", "loosen", "waive"}
_RELEASE_ID_RE = re.compile(r"^[^@\s]+@\d+\.\d+\.\d+$")
_NON_PASS_STATUSES = {"FAIL", "BLOCKED", "NOT_RUN", "EVIDENCE_MISSING", "TIMEOUT", "CANCELLED", "EXCEPTION"}


def _non_waivable_ids(ctx: dict[str, Any]) -> set[str]:
    document = load_governance_document(ctx, "non-waivable-baselines")
    if document is None:
        return set()
    ids = document.get("rule_ids")
    if not isinstance(ids, list) or not all(isinstance(item, str) and item for item in ids):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "non-waivable-baselines.rule_ids 必须是唯一非空字符串数组",
        )
    if len(ids) != len(set(ids)):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "non-waivable-baselines.rule_ids 存在重复"
        )
    return set(ids)


def _exceptions(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "exceptions")
    if document is None:
        return None
    return rows_of(document, "exceptions", "exceptions")


def check_graph_026(ctx: dict[str, Any]) -> dict[str, Any]:
    """目标项目不得自行批准对上级强制规则的豁免。

    机械断言：任何已声明的豁免记录必须携带非空外部权威引用 authority_ref，
    且 approver 不得是目标项目自身。未声明任何豁免则无违反事实。
    """
    exceptions = _exceptions(ctx)
    if exceptions is None:
        return result("PASS", declared_exceptions=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(exceptions):
        authority_ref = row.get("authority_ref")
        approver = row.get("approver")
        self_approved = (
            not isinstance(authority_ref, str)
            or not authority_ref
            or approver in {"target_project", "project_self", "self"}
        )
        if self_approved:
            violations.append({"index": index, "rule_id": row.get("rule_id")})
    if violations:
        return result("FAIL", self_approved_exceptions=violations, mechanical_half=True)
    return result("PASS", declared_exceptions=len(exceptions), mechanical_half=True)


def check_graph_027(ctx: dict[str, Any]) -> dict[str, Any]:
    """被标记为不可豁免的规则不得接受项目、技能族或发布政策例外。

    机械断言：已声明豁免不得覆盖项目自己声明的不可豁免规则集合。
    """
    exceptions = _exceptions(ctx)
    if exceptions is None:
        return result("PASS", declared_exceptions=0, mechanical_half=True)
    non_waivable = _non_waivable_ids(ctx)
    violations = [
        {"index": index, "rule_id": row.get("rule_id")}
        for index, row in enumerate(exceptions)
        if isinstance(row.get("rule_id"), str) and row["rule_id"] in non_waivable
    ]
    if violations:
        return result(
            "FAIL",
            non_waivable_exceptions=violations,
            non_waivable_count=len(non_waivable),
            mechanical_half=True,
        )
    return result(
        "PASS",
        declared_exceptions=len(exceptions),
        non_waivable_count=len(non_waivable),
        mechanical_half=True,
    )


def check_nonwaive_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """不可豁免规则失败/未运行/证据不足时必须阻断正式发布；项目加严和普通例外无权放行。

    机械断言：
    1. 已声明门禁结果中，不可豁免规则处于非通过状态时必须 publication_blocked=true
       且 released!=true；
    2. 已声明豁免不得覆盖该规则（与 GRAPH-027 的不可豁免集合同源）。
    """
    document = load_governance_document(ctx, "release-gate-results")
    exceptions = _exceptions(ctx) or []
    non_waivable = _non_waivable_ids(ctx)
    if document is None:
        if non_waivable and exceptions:
            covered = [
                row.get("rule_id")
                for row in exceptions
                if isinstance(row.get("rule_id"), str) and row["rule_id"] in non_waivable
            ]
            if covered:
                return result(
                    "FAIL",
                    waived_non_waivable=sorted(set(covered)),
                    gate_results_declared=False,
                    mechanical_half=True,
                )
        return result(
            "PASS",
            gate_results_declared=False,
            non_waivable_count=len(non_waivable),
            mechanical_half=True,
        )
    rows = rows_of(document, "results", "release-gate-results")
    violations = []
    for index, row in enumerate(rows):
        rule_id = row.get("rule_id")
        status = row.get("status")
        is_non_waive = row.get("non_waivable") is True or (
            isinstance(rule_id, str) and rule_id in non_waivable
        )
        if not is_non_waive:
            continue
        if status in _NON_PASS_STATUSES and (
            row.get("publication_blocked") is not True or row.get("released") is True
        ):
            violations.append({"index": index, "rule_id": rule_id, "status": status})
    if violations:
        return result("FAIL", released_non_waivable_failures=violations, mechanical_half=True)
    return result("PASS", gate_results=len(rows), non_waivable_count=len(non_waivable), mechanical_half=True)


def check_rule_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则违规影响必须明确为阻断、错误、告警或观察之一。

    机械断言：本次装载的规范清单中，canonical 终态规则实现
    （terminalRuleImplementations）的 failureImpact 必须在四值词表内，
    且全部规则定义（ruleCategories 与 terminalRuleImplementations）的
    revisionDigest 为 64 位十六进制。ruleCategories 是兼容检查器自身的
    基线结构规则，其修订锁定定义使用检查器独立的 critical/high 影响词表，
    不属于 canonical violation_impact 的约束对象。
    """
    manifest = ctx.get("manifest")
    if not isinstance(manifest, dict):
        return result("EVIDENCE_MISSING", reason="manifest_not_in_context")
    violations = []
    checked = 0
    for category in manifest.get("ruleCategories", []):
        for rule in category.get("rules", []):
            checked += 1
            if not is_hex64(rule.get("revisionDigest")):
                violations.append(
                    {"rule_id": rule.get("ruleId"), "reason": "revision_digest_invalid"}
                )
    for rule in manifest.get("terminalRuleImplementations", []):
        checked += 1
        if rule.get("failureImpact") not in VIOLATION_IMPACT_VOCABULARY:
            violations.append(
                {"rule_id": rule.get("ruleId"), "failureImpact": rule.get("failureImpact")}
            )
        if not is_hex64(rule.get("revisionDigest")):
            violations.append(
                {"rule_id": rule.get("ruleId"), "reason": "revision_digest_invalid"}
            )
    if checked == 0:
        return result("FAIL", reason="rule_manifest_empty")
    if violations:
        return result("FAIL", violations=violations, checked=checked)
    return result("PASS", checked=checked, vocabulary=list(VIOLATION_IMPACT_VOCABULARY))


def check_rule_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目只能新增独立规则或收紧上级规则，不得关闭、覆盖或放宽上级强制规则。

    机械断言：已声明规则覆盖动作只允许 add_independent_rule / tighten；
    出现 close / override / loosen / waive 即违反。
    """
    document = load_governance_document(ctx, "rule-overrides")
    if document is None:
        return result("PASS", declared_overrides=0, mechanical_half=True)
    rows = rows_of(document, "overrides", "rule-overrides")
    violations = []
    for index, row in enumerate(rows):
        action = row.get("action")
        if action not in _OVERRIDE_ACTIONS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"rule-overrides 第 {index} 行动作非法: {action!r}",
            )
        if action in _FORBIDDEN_OVERRIDE_ACTIONS:
            violations.append({"index": index, "rule_id": row.get("rule_id"), "action": action})
    if violations:
        return result("FAIL", forbidden_overrides=violations, mechanical_half=True)
    return result("PASS", declared_overrides=len(rows), mechanical_half=True)


def check_rule_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """适用的不可豁免规则失败时必须阻断其约束的操作；项目和普通例外均不得放行。

    机械断言：与 NONWAIVE-003 同源事实，另外要求门禁结果行携带规则修订摘要
    （缺失修订的行不得声明放行）。
    """
    document = load_governance_document(ctx, "release-gate-results")
    non_waivable = _non_waivable_ids(ctx)
    exceptions = _exceptions(ctx) or []
    waived = sorted(
        {
            row.get("rule_id")
            for row in exceptions
            if isinstance(row.get("rule_id"), str) and row["rule_id"] in non_waivable
        }
    )
    if waived:
        return result("FAIL", waived_non_waivable=waived, mechanical_half=True)
    if document is None:
        return result(
            "PASS",
            gate_results_declared=False,
            non_waivable_count=len(non_waivable),
            mechanical_half=True,
        )
    rows = rows_of(document, "results", "release-gate-results")
    violations = []
    for index, row in enumerate(rows):
        rule_id = row.get("rule_id")
        is_non_waive = row.get("non_waivable") is True or (
            isinstance(rule_id, str) and rule_id in non_waivable
        )
        if not is_non_waive:
            continue
        if row.get("status") in _NON_PASS_STATUSES:
            if row.get("operation_blocked") is not True or row.get("released") is True:
                violations.append({"index": index, "rule_id": rule_id})
            continue
        if row.get("status") == "PASS" and not is_hex64(row.get("revision_digest")):
            violations.append(
                {"index": index, "rule_id": rule_id, "reason": "revision_digest_missing"}
            )
    if violations:
        return result("FAIL", unblocked_non_waivable=violations, mechanical_half=True)
    return result("PASS", gate_results=len(rows), mechanical_half=True)


def check_rule_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次规范发布必须具有主/次/修订版本，并以不可变内容摘要锁定规则修订集合。

    机械断言：规范包索引的 activeSpecRelease.releaseId 必须形如
    ``<name>@<major>.<minor>.<revision>``，且 contentDigest 与
    ruleManifestDigest 均为 64 位十六进制摘要。
    """
    index = ctx.get("spec_index")
    if not isinstance(index, dict):
        return result("EVIDENCE_MISSING", reason="spec_index_not_in_context")
    release = index.get("activeSpecRelease")
    if not isinstance(release, dict):
        return result("FAIL", reason="active_spec_release_missing")
    release_id = release.get("releaseId")
    if not isinstance(release_id, str) or not _RELEASE_ID_RE.fullmatch(release_id):
        return result(
            "FAIL",
            reason="release_id_not_semver_triple",
            releaseId=release_id,
        )
    digest_errors = [
        field
        for field in ("contentDigest", "ruleManifestDigest")
        if not is_hex64(release.get(field))
    ]
    if digest_errors:
        return result("FAIL", reason="release_digest_invalid", fields=digest_errors)
    return result(
        "PASS",
        releaseId=release_id,
        locked_digests=["contentDigest", "ruleManifestDigest"],
    )


CHECKS = {
    "SFA-GRAPH-026": check_graph_026,
    "SFA-GRAPH-027": check_graph_027,
    "SFA-NONWAIVE-003": check_nonwaive_003,
    "SFA-RULE-005": check_rule_005,
    "SFA-RULE-007": check_rule_007,
    "SFA-RULE-009": check_rule_009,
    "SFA-RULE-023": check_rule_023,
}
