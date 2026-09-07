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

import ast
import base64
import binascii
import hashlib
import json
import os
import re
import tarfile
from pathlib import Path
from typing import Any

import conformance_check

from .contracts import (
    ExecutorEvidenceError,
    governance_dir,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
    validate_method_subresults,
)
import foundation_adoption_verifier as fal

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


def _split_violations(
    violations: list[dict[str, Any]], digest_reasons: tuple[str, ...]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """把 violations（每行含 reasons 列表）按原因归属拆分为 schema 侧与 digest 侧。
    一行同时含两类原因时两侧都计入；任一侧为空时对应方法行取 PASS。"""
    schema_side: list[dict[str, Any]] = []
    digest_side: list[dict[str, Any]] = []
    for row in violations:
        reasons = row.get("reasons", [])
        if any(reason in digest_reasons for reason in reasons):
            digest_side.append(row)
        if not all(reason in digest_reasons for reason in reasons):
            schema_side.append(row)
    return schema_side, digest_side


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
        return _finish(
            [
                _schema_row("EVIDENCE_MISSING", reason="spec_index_not_in_context"),
                _digest_row("EVIDENCE_MISSING", reason="spec_index_not_in_context"),
            ],
            reason="spec_index_not_in_context",
        )
    release = index.get("activeSpecRelease")
    if not isinstance(release, dict):
        return _finish(
            [
                _schema_row("FAIL", reason="active_spec_release_missing"),
                _digest_row("PASS", reason="no_declared_release_digests"),
            ],
            reason="active_spec_release_missing",
        )
    release_id = release.get("releaseId")
    if not isinstance(release_id, str) or not release_id:
        return _finish(
            [
                _schema_row("FAIL", reason="release_id_missing"),
                _digest_row("PASS", reason="no_release_digests"),
            ],
            reason="release_id_missing",
        )
    bad_digests = [
        field
        for field in ("contentDigest", "ruleManifestDigest")
        if not is_hex64(release.get(field))
    ]
    if bad_digests:
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed"),
                _digest_row(
                    "FAIL", reason="authority_index_digest_invalid", fields=bad_digests
                ),
            ],
            reason="authority_index_digest_invalid",
            fields=bad_digests,
        )
    recorded = index.get("recordedDigests")
    if not isinstance(recorded, dict) or not recorded:
        return _finish(
            [
                _schema_row("FAIL", reason="recorded_digests_missing"),
                _digest_row(
                    "PASS",
                    reason="digest_checks_passed",
                    content_digest=release.get("contentDigest"),
                    rule_manifest_digest=release.get("ruleManifestDigest"),
                ),
            ],
            reason="recorded_digests_missing",
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                recorded_digest_fields=sorted(recorded),
            ),
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                content_digest=release.get("contentDigest"),
                rule_manifest_digest=release.get("ruleManifestDigest"),
            ),
        ],
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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-authority-index",)),
            ],
            declared_superseded=0,
        )
    materials = rows_of(document, "superseded_materials", "rule-authority-index")
    violations = [
        {"index": index, "ref": row.get("ref")}
        for index, row in enumerate(materials)
        if row.get("authority_exited") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-authority-index",)),
            ],
            superseded_still_in_authority=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_superseded=len(materials)
            ),
            _doc_digest_row(ctx, ("rule-authority-index",)),
        ],
        declared_superseded=len(materials),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-authority-index",)),
            ],
            declared_rule_revisions=0,
        )
    revisions = rows_of(document, "rule_revisions", "rule-authority-index")
    if not revisions:
        return _finish(
            [
                _schema_row("FAIL", reason="rule_revisions_empty"),
                _doc_digest_row(ctx, ("rule-authority-index",)),
            ],
            reason="rule_revisions_empty",
        )
    violations = []
    for index, row in enumerate(revisions):
        revision = row.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            violations.append({"index": index, "rule_id": row.get("rule_id"), "reasons": ["revision_not_exact"]})
        elif not is_hex64(row.get("revision_digest")):
            violations.append({"index": index, "rule_id": row.get("rule_id"), "reasons": ["revision_digest_invalid"]})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("revision_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            imprecise_rule_references=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rule_revisions=len(revisions)
            ),
            _doc_digest_row(ctx, ("rule-authority-index",)),
        ],
        declared_rule_revisions=len(revisions),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_authority_chains=False,
        )
    chains = _require_dict(document.get("authority_chains"), "graph-links", "authority_chains")
    spec_chain = chains.get("spec_chain")
    delivery_chain = chains.get("delivery_chain")
    if chains.get("merged_into_single_authority") is True:
        return _finish(
            [
                _schema_row("FAIL", reason="authority_chains_merged"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            reason="authority_chains_merged",
        )
    if not isinstance(spec_chain, str) or not isinstance(delivery_chain, str) or not spec_chain or not delivery_chain:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "graph-links.authority_chains 必须声明两条非空权威链"
        )
    if spec_chain == delivery_chain:
        return _finish(
            [
                _schema_row("FAIL", reason="authority_chains_identical"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            reason="authority_chains_identical",
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", spec_chain=spec_chain, delivery_chain=delivery_chain
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        spec_chain=spec_chain,
        delivery_chain=delivery_chain,
    )


def check_graph_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个严格方法契约必须直接指向其实现的一个或多个业务能力修订。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_method_contracts=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            method_contracts_without_capability_revisions=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_method_contracts=len(contracts)
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        declared_method_contracts=len(contracts),
    )


def check_graph_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """每项技能评估必须直接指向被评估对象及其精确修订。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_evaluations=0,
        )
    evaluations = rows_of(document, "evaluations", "graph-links")
    violations = [
        {"index": index, "evaluation_id": row.get("evaluation_id")}
        for index, row in enumerate(evaluations)
        if not (isinstance(row.get("target_id"), str) and row["target_id"]
                and isinstance(row.get("target_revision"), str) and row["target_revision"])
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            evaluations_without_target=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_evaluations=len(evaluations)
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        declared_evaluations=len(evaluations),
    )


def check_graph_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条规范规则必须直接指向所属技能族规范根。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_rule_spec_roots=0,
        )
    roots = rows_of(document, "rule_spec_roots", "graph-links")
    if not roots:
        return _finish(
            [
                _schema_row("FAIL", reason="rule_spec_roots_empty"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            reason="rule_spec_roots_empty",
        )
    violations = [
        {"index": index, "rule_id": row.get("rule_id")}
        for index, row in enumerate(roots)
        if not (isinstance(row.get("spec_root"), str) and row["spec_root"])
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            rules_without_spec_root=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rule_spec_roots=len(roots)
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        declared_rule_spec_roots=len(roots),
    )


def check_graph_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目加严声明必须指向被加严的上级规则及其修订，并声明条件单调收紧。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_tightenings=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            tightenings_not_bound_to_parent=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_tightenings=len(tightenings)
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        declared_tightenings=len(tightenings),
    )


def check_graph_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条例外必须指向精确规则修订以及适用的技能族、版本、平台和范围。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_exception_targets=0,
        )
    targets = rows_of(document, "exception_targets", "graph-links")
    required_scopes = {"family", "version", "platform", "range"}
    violations = []
    for index, row in enumerate(targets):
        reasons = []
        if not (isinstance(row.get("rule_id"), str) and row["rule_id"]):
            reasons.append("rule_id_missing")
        if not is_hex64(row.get("revision_digest")):
            reasons.append("revision_digest_invalid")
        scopes = row.get("scopes")
        if not (isinstance(scopes, list) and required_scopes.issubset(set(scopes))):
            reasons.append("scopes_incomplete")
        if reasons:
            violations.append({"index": index, "exception_id": row.get("exception_id"), "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("revision_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            exceptions_not_bound_to_exact_rule=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_exception_targets=len(targets)
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        declared_exception_targets=len(targets),
    )


def check_graph_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """入口、技能、检查器等必须连接与其职责最近的权威制品，不得全挂技能族根。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_attachments=0,
        )
    attachments = rows_of(document, "attachments", "graph-links")
    violations = [
        {"index": index, "unit_id": row.get("unit_id")}
        for index, row in enumerate(attachments)
        if row.get("attached_to_nearest_authority") is not True
        or row.get("dumped_at_family_root") is True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            attachments_not_nearest_authority=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_attachments=len(attachments)
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        declared_attachments=len(attachments),
    )


def check_graph_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族根不得罗列项目内全部物理文件。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_root_inventory=False,
        )
    if document.get("family_root_lists_all_files") is True:
        return _finish(
            [
                _schema_row("FAIL", reason="family_root_is_physical_file_inventory"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            reason="family_root_is_physical_file_inventory",
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", family_root_lists_all_files=False
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        family_root_lists_all_files=False,
    )


def check_graph_025(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则或发布政策必须声明例外批准主体、委托链、适用范围、发布影响和职责分离。"""
    document = _doc(ctx, "graph-links")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_exception_approval_policy=False,
        )
    policy = document.get("exception_approval_policy")
    if policy is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_policy"),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            declared_exception_approval_policy=False,
        )
    policy = _require_dict(policy, "graph-links", "exception_approval_policy")
    missing = [
        field
        for field in ("approver", "delegation_chain", "scope", "release_impact")
        if not policy.get(field)
    ]
    if missing or policy.get("separation_of_duties") is not True:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="exception_approval_policy_boundary_incomplete",
                    missing=missing,
                    separation_of_duties=policy.get("separation_of_duties"),
                ),
                _doc_digest_row(ctx, ("graph-links",)),
            ],
            reason="exception_approval_policy_boundary_incomplete",
            missing=missing,
            separation_of_duties=policy.get("separation_of_duties"),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", exception_approval_policy_declared=True
            ),
            _doc_digest_row(ctx, ("graph-links",)),
        ],
        exception_approval_policy_declared=True,
    )


# ---------------------------------------------------------------------------
# GRAPH 状态轴（status-axes）：GRAPH-011 ~ GRAPH-018
# ---------------------------------------------------------------------------


def _axis_check(ctx: dict[str, Any], axis_key: str) -> dict[str, Any]:
    document = _doc(ctx, "status-axes")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_axis", axis=axis_key),
                _doc_digest_row(ctx, ("status-axes",), axis=axis_key),
            ],
            declared_axis=False,
            axis=axis_key,
        )
    vocabulary = STATUS_AXES[axis_key][1]
    values = document.get(axis_key)
    if values is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_axis", axis=axis_key),
                _doc_digest_row(ctx, ("status-axes",), axis=axis_key),
            ],
            declared_axis=False,
            axis=axis_key,
        )
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"status-axes.{axis_key} 必须是字符串数组"
        )
    out_of_vocabulary = sorted({value for value in values if value not in vocabulary})
    if out_of_vocabulary:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="out_of_vocabulary",
                    axis=axis_key,
                    out_of_vocabulary=out_of_vocabulary,
                    vocabulary=sorted(vocabulary),
                ),
                _doc_digest_row(ctx, ("status-axes",), axis=axis_key),
            ],
            axis=axis_key,
            out_of_vocabulary=out_of_vocabulary,
            vocabulary=sorted(vocabulary),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", axis=axis_key, recorded=len(values)
            ),
            _doc_digest_row(ctx, ("status-axes",), axis=axis_key),
        ],
        axis=axis_key,
        recorded=len(values),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            declared_releases=0,
        )
    releases = rows_of(document, "releases", "release-graph")
    violations = [
        {"index": index, "release_id": row.get("release_id"), "status": row.get("status")}
        for index, row in enumerate(releases)
        if row.get("status") not in RELEASE_STATUS_VOCABULARY
    ]
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="schema_violations",
                    violations=violations,
                    axis=sorted(RELEASE_STATUS_VOCABULARY),
                ),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            release_status_out_of_axis=violations,
            axis=sorted(RELEASE_STATUS_VOCABULARY),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_releases=len(releases)
            ),
            _doc_digest_row(ctx, ("release-graph",)),
        ],
        declared_releases=len(releases),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            declared_releases=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            skill_releases_incomplete_composition=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_releases=len(releases)
            ),
            _doc_digest_row(ctx, ("release-graph",)),
        ],
        declared_releases=len(releases),
    )


def check_graph_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """已发布规范和技能发布的组成与摘要不可修改。"""
    releases = _releases(ctx)
    if releases is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            declared_releases=0,
        )
    violations = [
        {"index": index, "release_id": row.get("release_id")}
        for index, row in enumerate(releases)
        if row.get("status") == "published" and row.get("composition_locked") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            published_composition_not_locked=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_releases=len(releases)
            ),
            _doc_digest_row(ctx, ("release-graph",)),
        ],
        declared_releases=len(releases),
    )


def check_graph_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """撤回只能追加可用性变化和撤回证据，不得覆盖原始发布组成、摘要或历史验证。"""
    releases = _releases(ctx)
    if releases is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            declared_releases=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            withdrawal_overrides_composition=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_releases=len(releases)
            ),
            _doc_digest_row(ctx, ("release-graph",)),
        ],
        declared_releases=len(releases),
    )


def check_graph_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """发布与例外的状态变化必须通过追加新事实表达，不得原地改写历史事实。"""
    releases = _releases(ctx)
    if releases is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            declared_releases=0,
        )
    violations = [
        {"index": index, "release_id": row.get("release_id")}
        for index, row in enumerate(releases)
        if row.get("history_rewritten") is True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            history_rewritten_in_place=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_releases=len(releases)
            ),
            _doc_digest_row(ctx, ("release-graph",)),
        ],
        declared_releases=len(releases),
    )


def check_graph_040(ctx: dict[str, Any]) -> dict[str, Any]:
    """契约、实现、规则或例外变化只影响新候选与后续发布，不得修改已发布历史事实。"""
    releases = _releases(ctx)
    if releases is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-graph",)),
            ],
            declared_releases=0,
        )
    violations = []
    for index, row in enumerate(releases):
        if row.get("status") != "published":
            continue
        reasons = []
        if row.get("history_rewritten") is True:
            reasons.append("history_rewritten")
        if not is_hex64(row.get("composition_digest")):
            reasons.append("composition_digest_invalid")
        if reasons:
            violations.append({"index": index, "release_id": row.get("release_id"), "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("composition_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            published_history_modified=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_releases=len(releases)
            ),
            _doc_digest_row(ctx, ("release-graph",)),
        ],
        declared_releases=len(releases),
    )


# ---------------------------------------------------------------------------
# GRAPH 状态事实与归并（state-facts）
# ---------------------------------------------------------------------------


def check_graph_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条状态事实必须记录事件类型、对象身份、前序摘要、幂等键、可信时间、签署主体、权限依据和归并器版本。"""
    document = _doc(ctx, "state-facts")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("state-facts",)),
            ],
            declared_state_facts=0,
        )
    facts = rows_of(document, "facts", "state-facts")
    violations = []
    for index, row in enumerate(facts):
        missing = [field for field in STATE_FACT_REQUIRED_FIELDS if not row.get(field)]
        if missing:
            violations.append({"index": index, "object_id": row.get("object_id"), "missing": missing})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("state-facts",)),
            ],
            state_facts_missing_contract_fields=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_state_facts=len(facts)
            ),
            _doc_digest_row(ctx, ("state-facts",)),
        ],
        declared_state_facts=len(facts),
    )


def check_graph_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """状态归并算法必须定义合法转换和确定性排序规则（相同事实集合得到相同当前状态）。"""
    document = _doc(ctx, "state-facts")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("state-facts",)),
            ],
            declared_merge_policy=False,
        )
    policy = _require_dict(document.get("merge_policy"), "state-facts", "merge_policy")
    if policy.get("legal_transitions_defined") is not True or policy.get("deterministic_ordering_defined") is not True:
        return _finish(
            [
                _schema_row("FAIL", reason="merge_policy_not_deterministic"),
                _doc_digest_row(ctx, ("state-facts",)),
            ],
            reason="merge_policy_not_deterministic",
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", merge_policy_defined=True),
            _doc_digest_row(ctx, ("state-facts",)),
        ],
        merge_policy_defined=True,
    )


def check_graph_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """同一前序存在两个有效后继且无法依权威顺序确定先后时，状态归并必须受阻。"""
    document = _doc(ctx, "state-facts")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("state-facts",)),
            ],
            declared_successor_conflicts=0,
        )
    conflicts = rows_of(document, "successor_conflicts", "state-facts")
    violations = [
        {"index": index, "predecessor": row.get("predecessor")}
        for index, row in enumerate(conflicts)
        if row.get("orderable") is False and row.get("blocked") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("state-facts",)),
            ],
            unorderable_successors_not_blocked=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_successor_conflicts=len(conflicts)
            ),
            _doc_digest_row(ctx, ("state-facts",)),
        ],
        declared_successor_conflicts=len(conflicts),
    )


# ---------------------------------------------------------------------------
# GRAPH 七类锁与摘要（governance-locks）：GRAPH-028 ~ GRAPH-035
# ---------------------------------------------------------------------------


def _lock_check(ctx: dict[str, Any], lock_key: str, extra_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    document = _doc(ctx, "governance-locks")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock=lock_key),
                _doc_digest_row(ctx, ("governance-locks",), lock=lock_key),
            ],
            declared_lock=False,
            lock=lock_key,
        )
    lock = document.get(lock_key)
    if lock is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock=lock_key),
                _doc_digest_row(ctx, ("governance-locks",), lock=lock_key),
            ],
            declared_lock=False,
            lock=lock_key,
        )
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"governance-locks.{lock_key} 必须是对象"
        )
    reasons = []
    if lock.get("locked") is not True:
        reasons.append("lock_not_sealed")
    if not is_hex64(lock.get("content_digest")):
        reasons.append("lock_digest_invalid")
    if reasons:
        entry = {"lock": lock_key, "reasons": reasons}
        schema_side, digest_side = _split_violations([entry], ("lock_digest_invalid",))
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="lock_not_sealed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            lock=lock_key,
            reason="lock_not_sealed",
        )
    missing = [field for field in extra_fields if not lock.get(field)]
    if missing:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="lock_missing_fields",
                    missing=missing,
                    lock=lock_key,
                ),
                _doc_digest_row(ctx, ("governance-locks",), lock=lock_key),
            ],
            lock=lock_key,
            reason="lock_missing_fields",
            missing=missing,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", lock=lock_key, sealed=True),
            _doc_digest_row(ctx, ("governance-locks",), lock=lock_key, sealed=True),
        ],
        lock=lock_key,
        sealed=True,
    )


def check_graph_028(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目必须锁定采用的每个领域图规范版本和内容摘要。"""
    return _lock_check(ctx, "domain_spec_selection", extra_fields=("version",))


def check_graph_029(ctx: dict[str, Any]) -> dict[str, Any]:
    """制品关系新鲜度锁必须证明权威制品与实现、检查、测试的追溯仍与当前内容一致。"""
    document = _doc(ctx, "governance-locks")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock="relation_freshness"),
                _doc_digest_row(ctx, ("governance-locks",), lock="relation_freshness"),
            ],
            declared_lock=False,
            lock="relation_freshness",
        )
    lock = document.get("relation_freshness")
    if lock is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock="relation_freshness"),
                _doc_digest_row(ctx, ("governance-locks",), lock="relation_freshness"),
            ],
            declared_lock=False,
            lock="relation_freshness",
        )
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "governance-locks.relation_freshness 必须是对象"
        )
    reasons = []
    if lock.get("locked") is not True:
        reasons.append("lock_not_sealed")
    if lock.get("fresh") is not True:
        reasons.append("freshness_stale")
    if not is_hex64(lock.get("content_digest")):
        reasons.append("lock_digest_invalid")
    if reasons:
        entry = {"lock": "relation_freshness", "reasons": reasons}
        schema_side, digest_side = _split_violations([entry], ("lock_digest_invalid",))
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="freshness_lock_stale_or_unsealed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            lock="relation_freshness",
            reason="freshness_lock_stale_or_unsealed",
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", lock="relation_freshness"
            ),
            _doc_digest_row(
                ctx, ("governance-locks",), lock="relation_freshness", fresh=True
            ),
        ],
        lock="relation_freshness",
        fresh=True,
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock="skill_release_summary"),
                _doc_digest_row(ctx, ("governance-locks",), lock="skill_release_summary"),
            ],
            declared_lock=False,
            lock="skill_release_summary",
        )
    lock = document.get("skill_release_summary")
    if lock is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock="skill_release_summary"),
                _doc_digest_row(ctx, ("governance-locks",), lock="skill_release_summary"),
            ],
            declared_lock=False,
            lock="skill_release_summary",
        )
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "governance-locks.skill_release_summary 必须是对象"
        )
    reasons = []
    if lock.get("locked") is not True:
        reasons.append("summary_not_sealed")
    if not is_hex64(lock.get("content_digest")):
        reasons.append("summary_digest_invalid")
    if not reasons:
        platforms = lock.get("platforms_locked")
        if not isinstance(platforms, list) or len(platforms) != 4 or len(set(platforms)) != 4:
            reasons.append("platforms_not_fully_locked")
    if reasons:
        entry = {"lock": "skill_release_summary", "reasons": reasons}
        schema_side, digest_side = _split_violations(
            [entry], ("summary_digest_invalid",)
        )
        reason = (
            "summary_not_sealed"
            if ("summary_not_sealed" in reasons or "summary_digest_invalid" in reasons)
            else "platforms_not_fully_locked"
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=reason,
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            lock="skill_release_summary",
            reason=reason,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", lock="skill_release_summary"
            ),
            _doc_digest_row(
                ctx, ("governance-locks",), lock="skill_release_summary", platforms_locked=platforms
            ),
        ],
        lock="skill_release_summary",
        platforms_locked=platforms,
    )


def check_graph_033(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范发布摘要必须锁定实际包含的精确规则修订集合。"""
    document = _doc(ctx, "governance-locks")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock="spec_release_summary"),
                _doc_digest_row(ctx, ("governance-locks",), lock="spec_release_summary"),
            ],
            declared_lock=False,
            lock="spec_release_summary",
        )
    lock = document.get("spec_release_summary")
    if lock is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_lock", lock="spec_release_summary"),
                _doc_digest_row(ctx, ("governance-locks",), lock="spec_release_summary"),
            ],
            declared_lock=False,
            lock="spec_release_summary",
        )
    if not isinstance(lock, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "governance-locks.spec_release_summary 必须是对象"
        )
    reasons = []
    if lock.get("locked") is not True:
        reasons.append("summary_not_sealed")
    if not is_hex64(lock.get("content_digest")):
        reasons.append("summary_digest_invalid")
    if not reasons:
        rule_revisions = lock.get("rule_revisions_locked")
        if (
            not isinstance(rule_revisions, list)
            or not rule_revisions
            or not all(is_hex64(item) for item in rule_revisions)
        ):
            reasons.append("rule_revisions_not_locked")
    if reasons:
        entry = {"lock": "spec_release_summary", "reasons": reasons}
        schema_side, digest_side = _split_violations(
            [entry], ("summary_digest_invalid", "rule_revisions_not_locked")
        )
        reason = (
            "summary_not_sealed"
            if ("summary_not_sealed" in reasons or "summary_digest_invalid" in reasons)
            else "rule_revisions_not_locked"
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason=reason,
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            lock="spec_release_summary",
            reason=reason,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", lock="spec_release_summary"
            ),
            _doc_digest_row(
                ctx, ("governance-locks",), lock="spec_release_summary", rule_revisions_locked=len(rule_revisions)
            ),
        ],
        lock="spec_release_summary",
        rule_revisions_locked=len(rule_revisions),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("governance-locks",)),
            ],
            declared_locks=0,
        )
    missing_or_shared = []
    seen_digests: dict[str, str] = {}
    for lock_key in LOCK_AXES:
        lock = document.get(lock_key)
        if not isinstance(lock, dict) or lock.get("locked") is not True:
            missing_or_shared.append({"lock": lock_key, "reasons": ["not_independently_sealed"]})
            continue
        digest = lock.get("content_digest")
        if not is_hex64(digest):
            missing_or_shared.append({"lock": lock_key, "reasons": ["lock_digest_invalid"]})
            continue
        if digest in seen_digests:
            missing_or_shared.append(
                {"lock": lock_key, "reasons": ["digest_substitutes"], "substitutes": seen_digests[digest]}
            )
        else:
            seen_digests[digest] = lock_key
    if missing_or_shared:
        schema_side, digest_side = _split_violations(
            missing_or_shared, ("lock_digest_invalid", "digest_substitutes")
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="locks_not_independent",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            locks_not_independent=missing_or_shared,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_locks=len(LOCK_AXES)
            ),
            _doc_digest_row(ctx, ("governance-locks",)),
        ],
        declared_locks=len(LOCK_AXES),
    )


# ---------------------------------------------------------------------------
# GRAPH 失效与到期（invalidation-ledger）
# ---------------------------------------------------------------------------


def check_graph_036(ctx: dict[str, Any]) -> dict[str, Any]:
    """业务能力或方法契约变化后，引用旧契约摘要的评估和候选发布必须失效并重新验证。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            declared_contract_changes=0,
        )
    changes = rows_of(document, "contract_changes", "invalidation-ledger")
    violations = [
        {"index": index, "change_id": row.get("change_id")}
        for index, row in enumerate(changes)
        if row.get("dependents_invalidated") is not True or row.get("revalidated") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            stale_dependents_not_invalidated=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_contract_changes=len(changes)
            ),
            _doc_digest_row(ctx, ("invalidation-ledger",)),
        ],
        declared_contract_changes=len(changes),
    )


def check_graph_037(ctx: dict[str, Any]) -> dict[str, Any]:
    """内部技能、平台投影或运行时代码变化后，相关关系新鲜度锁必须标记陈旧并触发复验。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            declared_implementation_changes=0,
        )
    changes = rows_of(document, "implementation_changes", "invalidation-ledger")
    violations = [
        {"index": index, "change_id": row.get("change_id")}
        for index, row in enumerate(changes)
        if row.get("affected_locks_marked_stale") is not True or row.get("reverified") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            relation_locks_not_marked_stale=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_implementation_changes=len(changes)
            ),
            _doc_digest_row(ctx, ("invalidation-ledger",)),
        ],
        declared_implementation_changes=len(changes),
    )


def check_graph_038(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则修订必须形成新规范发布；仍锁定旧规范发布的项目不得被静默改用新规则重判。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            declared_rule_changes=0,
        )
    changes = rows_of(document, "rule_changes", "invalidation-ledger")
    violations = [
        {"index": index, "change_id": row.get("change_id")}
        for index, row in enumerate(changes)
        if not (isinstance(row.get("new_spec_release_id"), str) and row["new_spec_release_id"])
        or row.get("old_locked_projects_rerated_silently") is True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            old_locked_projects_silently_rerated=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rule_changes=len(changes)
            ),
            _doc_digest_row(ctx, ("invalidation-ledger",)),
        ],
        declared_rule_changes=len(changes),
    )


def check_graph_039(ctx: dict[str, Any]) -> dict[str, Any]:
    """例外到期、撤销或失效后，采用检查必须重新报告原强制规则违规。"""
    document = _doc(ctx, "invalidation-ledger")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            declared_exception_expiries=0,
        )
    expiries = rows_of(document, "exception_expiries", "invalidation-ledger")
    violations = [
        {"index": index, "exception_id": row.get("exception_id")}
        for index, row in enumerate(expiries)
        if row.get("expired") is True and row.get("original_violation_rereported") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("invalidation-ledger",)),
            ],
            expired_exceptions_not_rereported=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_exception_expiries=len(expiries)
            ),
            _doc_digest_row(ctx, ("invalidation-ledger",)),
        ],
        declared_exception_expiries=len(expiries),
    )


# ---------------------------------------------------------------------------
# NONWAIVE：不可豁免映射（release-policy）
# ---------------------------------------------------------------------------


def check_nonwaive_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """release_policy 中每项不可豁免边界必须列出精确规则身份、修订和内容摘要。"""
    document = _doc(ctx, "release-policy")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-policy",)),
            ],
            declared_boundaries=0,
        )
    policy = _require_dict(document.get("release_policy"), "release-policy", "release_policy")
    boundaries = rows_of(policy, "non_waivable_boundaries", "release-policy.non_waivable_boundaries")
    if not boundaries:
        return _finish(
            [
                _schema_row("FAIL", reason="non_waivable_boundaries_empty"),
                _doc_digest_row(ctx, ("release-policy",)),
            ],
            reason="non_waivable_boundaries_empty",
        )
    violations = []
    for index, row in enumerate(boundaries):
        reasons = []
        if not (isinstance(row.get("rule_id"), str) and row["rule_id"]):
            reasons.append("rule_id_missing")
        revision = row.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            reasons.append("revision_not_exact")
        if not is_hex64(row.get("revision_digest")):
            reasons.append("revision_digest_invalid")
        if not is_hex64(row.get("content_digest")):
            reasons.append("content_digest_invalid")
        if reasons:
            violations.append({"index": index, "policy_name": row.get("policy_name"), "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("revision_digest_invalid", "content_digest_invalid")
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            boundaries_without_exact_rule_mapping=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_boundaries=len(boundaries)
            ),
            _doc_digest_row(ctx, ("release-policy",)),
        ],
        declared_boundaries=len(boundaries),
    )


def check_nonwaive_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """不可豁免映射变化必须发布新的发布政策修订并重新批准，不得静默改变。"""
    document = _doc(ctx, "release-policy")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("release-policy",)),
            ],
            declared_release_policy=False,
        )
    policy = _require_dict(document.get("release_policy"), "release-policy", "release_policy")
    revision = policy.get("revision")
    if (
        not isinstance(revision, int) or isinstance(revision, bool) or revision < 1
        or policy.get("approved") is not True
        or policy.get("changes_require_new_revision") is not True
    ):
        return _finish(
            [
                _schema_row("FAIL", reason="non_waivable_mapping_change_not_reapproved"),
                _doc_digest_row(ctx, ("release-policy",)),
            ],
            reason="non_waivable_mapping_change_not_reapproved",
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", policy_revision=revision),
            _doc_digest_row(ctx, ("release-policy",)),
        ],
        policy_revision=revision,
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    required_axes = ("effect", "authority_source", "applicability_conditions", "violation_impact", "exception_policy")
    violations = _rule_field_violations(
        rules,
        lambda row: all(row.get(axis) is not None for axis in required_axes) and "level" not in row,
        "governance_axes_not_orthogonal",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则效力必须明确为强制、推荐或实验之一。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules, lambda row: row.get("effect") in EFFECT_VOCABULARY, "effect_out_of_vocabulary"
    )
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="schema_violations",
                    violations=violations,
                    vocabulary=sorted(EFFECT_VOCABULARY),
                ),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
            vocabulary=sorted(EFFECT_VOCABULARY),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则权威来源必须区分通用规范、技能开发领域规范、平台附加规则和项目加严规则。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("authority_source") in AUTHORITY_SOURCE_VOCABULARY,
        "authority_source_out_of_vocabulary",
    )
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="schema_violations",
                    violations=violations,
                    vocabulary=sorted(AUTHORITY_SOURCE_VOCABULARY),
                ),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
            vocabulary=sorted(AUTHORITY_SOURCE_VOCABULARY),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则必须独立声明受约束对象、平台、成熟度、发布阶段和其他条件表达。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    required_conditions = ("subject", "platform", "maturity", "release_stage")

    def independent(row: dict[str, Any]) -> bool:
        conditions = row.get("applicability_conditions")
        return (
            isinstance(conditions, dict)
            and all(isinstance(conditions.get(key), str) and conditions[key] for key in required_conditions)
        )

    violations = _rule_field_violations(rules, independent, "applicability_conditions_not_independent")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则例外必须通过独立批准记录声明，不得修改原规则正文。"""
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_exception_records=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            exception_records_not_independent=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_exception_records=len(records)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_exception_records=len(records),
    )


def check_rule_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """有效例外只能形成"在已批准例外条件下通过"的结论，不得报告无条件完整符合。"""
    document = _doc(ctx, "findings-registry")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            declared_findings=0,
        )
    findings = rows_of(document, "findings", "findings-registry")
    violations = [
        {"index": index, "finding_id": row.get("finding_id")}
        for index, row in enumerate(findings)
        if row.get("has_active_exception") is True and row.get("verdict") != "conditional_pass"
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            exception_findings_reported_unconditional=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_findings=len(findings)
            ),
            _doc_digest_row(ctx, ("findings-registry",)),
        ],
        declared_findings=len(findings),
    )


def check_rule_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须具有稳定规则身份、中文名称、所属专题和权威来源。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: all(
            isinstance(row.get(field), str) and row[field]
            for field in ("rule_id", "name", "topic", "authority_source")
        ),
        "stable_identity_metadata_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须说明它要防止的失败或要建立的可验证保证（结构字段齐备）。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("purpose"), str) and row["purpose"].strip(),
        "purpose_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须说明受约束对象以及何时适用（结构字段齐备）。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: all(isinstance(row.get(field), str) and row[field].strip() for field in ("subject", "trigger")),
        "subject_or_trigger_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须分别声明规则效力和违规影响。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("effect") in EFFECT_VOCABULARY
        and row.get("violation_impact") in VIOLATION_IMPACT_VOCABULARY,
        "effect_or_violation_impact_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须给出可通过证据判断符合/不符合/不适用的预期状态（结构字段齐备）。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("expected_state"), str) and row["expected_state"].strip(),
        "expected_state_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须引用可定位的来源、修订和证据位置。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("source_refs"), list)
        and row["source_refs"]
        and all(isinstance(ref, str) and ref for ref in row["source_refs"]),
        "locatable_source_refs_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则至少必须声明一种检查方式。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )

    def declared(row: dict[str, Any]) -> bool:
        methods = row.get("check_methods")
        return (
            isinstance(methods, list)
            and bool(methods)
            and all(method in CHECK_METHOD_VOCABULARY for method in methods)
        )

    violations = _rule_field_violations(rules, declared, "check_methods_missing_or_invalid")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须声明旧版本兼容方式以及是否允许、由谁允许何种例外。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: isinstance(row.get("compat_policy"), str) and row["compat_policy"]
        and isinstance(row.get("exception_policy"), str) and row["exception_policy"],
        "compat_or_exception_policy_missing",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """每条正式规则必须声明生命周期状态。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("lifecycle") in RULE_LIFECYCLE_VOCABULARY,
        "lifecycle_missing_or_invalid",
    )
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="schema_violations",
                    violations=violations,
                    vocabulary=sorted(RULE_LIFECYCLE_VOCABULARY),
                ),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
            vocabulary=sorted(RULE_LIFECYCLE_VOCABULARY),
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有适用条件、证据、检查方式、违规影响和整改复验均明确后，规则才可成为正式强制规则。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )

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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """暂时无法稳定验证的判断不得直接作为强制门禁（强制规则必须含可稳定验证的机械检查方式）。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    mechanical = {"static_scan", "schema_validation", "digest_verification", "relation", "runtime_observation"}

    def stable(row: dict[str, Any]) -> bool:
        if row.get("effect") != "mandatory":
            return True
        methods = row.get("check_methods")
        return isinstance(methods, list) and any(method in mechanical for method in methods)

    violations = _rule_field_violations(rules, stable, "mandatory_without_stable_verification")
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_rule_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则权威定义必须独立于检查技能和检查程序。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("definition_independent_of_checker") is True,
        "definition_embedded_in_checker_only",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_version_policy"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_version_policy=False,
        )
    if policy.get(field) is not True:
        return _finish(
            [
                _schema_row("FAIL", reason=reason, field=field),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            reason=reason,
            field=field,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", field=field),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        field=field,
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )

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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_scope_claims"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_scope_claims=False,
        )
    if claims.get(field) != expected:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason=reason,
                    field=field,
                    expected=expected,
                    actual=claims.get(field),
                ),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            reason=reason,
            field=field,
            expected=expected,
            actual=claims.get(field),
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", field=field),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        field=field,
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: all(
            isinstance(row.get(field), str) and row[field]
            for field in ("namespace", "topic", "semantic_name")
        ),
        "identity_not_three_part",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_ruleid_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则效力、违规影响、版本、修订、生命周期等可变治理字段不得进入规则逻辑身份。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("identity_excludes_mutable_fields") is True,
        "identity_contains_mutable_fields",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_ruleid_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """各权威只能在自身命名空间创建规则身份，不得占用或伪装另一权威的身份。"""
    rules = _rules(ctx)
    if rules is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_rules=0,
        )
    violations = _rule_field_violations(
        rules,
        lambda row: row.get("namespace_owned_by_own_authority") is True,
        "namespace_not_own_authority",
    )
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_rules=len(rules)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_rules=len(rules),
    )


def check_ruleid_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """非语义变化必须保持规则逻辑身份，并通过新修订和内容摘要记录变化。"""
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_identity_continuity=0,
        )
    continuity = rows_of(document, "identity_continuity", "rule-definitions.identity_continuity")
    violations = []
    for index, row in enumerate(continuity):
        reasons = []
        if row.get("kept_identity") is not True:
            reasons.append("kept_identity_false")
        if not is_hex64(row.get("new_revision_digest")):
            reasons.append("new_revision_digest_invalid")
        if reasons:
            violations.append({"index": index, "rule_id": row.get("rule_id"), "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("new_revision_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            nonsemantic_change_broke_identity=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_identity_continuity=len(continuity)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_identity_continuity=len(continuity),
    )


def check_ruleid_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """核心语义变化必须创建新规则身份，并声明与旧规则的取代/包含/冲突/迁移关系。"""
    document = _doc(ctx, "rule-definitions")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            declared_semantic_changes=0,
        )
    changes = rows_of(document, "semantic_changes", "rule-definitions.semantic_changes")
    violations = [
        {"index": index, "old_rule_id": row.get("old_rule_id")}
        for index, row in enumerate(changes)
        if not (isinstance(row.get("new_rule_id"), str) and row["new_rule_id"])
        or row.get("new_rule_id") == row.get("old_rule_id")
        or row.get("relation_declared") is not True
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-definitions",)),
            ],
            semantic_change_kept_identity_silently=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_semantic_changes=len(changes)
            ),
            _doc_digest_row(ctx, ("rule-definitions",)),
        ],
        declared_semantic_changes=len(changes),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("check-implementations",)),
            ],
            declared_implementations=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("check-implementations",)),
            ],
            implementation_binding_violations=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                declared_implementations=len(implementations),
                multi_bound_rules=sum(1 for rows in groups.values() if len(rows) > 1),
            ),
            _doc_digest_row(ctx, ("check-implementations",)),
        ],
        declared_implementations=len(implementations),
        multi_bound_rules=sum(1 for rows in groups.values() if len(rows) > 1),
    )


def check_checkimpl_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个规则实现绑定必须分别记录检查器身份、版本、内容摘要、适用平台、检查方式和状态。"""
    implementations = _implementations(ctx)
    if implementations is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("check-implementations",)),
            ],
            declared_implementations=0,
        )
    violations = []
    for index, row in enumerate(implementations):
        reasons = []
        if not (isinstance(row.get("checker_id"), str) and row["checker_id"]):
            reasons.append("checker_id_missing")
        if not (isinstance(row.get("version"), str) and row["version"]):
            reasons.append("version_missing")
        if not is_hex64(row.get("content_digest")):
            reasons.append("content_digest_invalid")
        platforms = row.get("platforms")
        if not (isinstance(platforms, list) and bool(platforms)):
            reasons.append("platforms_missing")
        if not (isinstance(row.get("check_method"), str) and row["check_method"]):
            reasons.append("check_method_missing")
        if row.get("status") not in IMPL_STATUS_VOCABULARY:
            reasons.append("status_out_of_vocabulary")
        if reasons:
            violations.append({"index": index, "checker_id": row.get("checker_id"), "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("content_digest_invalid",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            implementation_bindings_incomplete=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_implementations=len(implementations)
            ),
            _doc_digest_row(ctx, ("check-implementations",)),
        ],
        declared_implementations=len(implementations),
    )


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
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            declared_findings=0,
        )
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
    digest_context_fields = {"rule_revision_digest", "rule_content_digest"}
    violations = []
    for index, row in enumerate(findings):
        missing = [
            field for field in required_context
            if not row.get(field)
            or (field in ("rule_revision_digest", "rule_content_digest") and not is_hex64(row.get(field)))
        ]
        if missing and row.get("usable_for_gate") is True:
            reasons = []
            if any(field in digest_context_fields for field in missing):
                reasons.append("context_digest_missing")
            if any(field not in digest_context_fields for field in missing):
                reasons.append("context_fields_missing")
            violations.append({"index": index, "finding_id": row.get("finding_id"), "missing": missing, "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("context_digest_missing",)
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            findings_used_for_gate_without_context=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_findings=len(findings)
            ),
            _doc_digest_row(ctx, ("findings-registry",)),
        ],
        declared_findings=len(findings),
    )


def check_rulerel_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """同一根因的多条发现可以聚类展示，但必须保留每条原始发现，不能用聚类覆盖。"""
    document = _doc(ctx, "findings-registry")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            declared_clusters=0,
        )
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
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            clusters_drop_original_findings=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_clusters=len(clusters)
            ),
            _doc_digest_row(ctx, ("findings-registry",)),
        ],
        declared_clusters=len(clusters),
    )


def check_rulerel_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """误报/不适用/重复/已修复是单次发现处置，与正式规则例外必须使用不同状态空间。"""
    findings = _findings(ctx)
    if findings is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            declared_findings=0,
        )
    violations = [
        {"index": index, "finding_id": row.get("finding_id"), "disposition": row.get("disposition")}
        for index, row in enumerate(findings)
        if row.get("disposition") is not None
        and row.get("disposition") not in FINDING_DISPOSITION_VOCABULARY
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("findings-registry",)),
            ],
            disposition_uses_exception_state_space=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_findings=len(findings)
            ),
            _doc_digest_row(ctx, ("findings-registry",)),
        ],
        declared_findings=len(findings),
    )


def check_rulerel_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则语义关系必须绑定两端精确规则修订、方向、适用范围和证明证据。"""
    document = _doc(ctx, "rule-relations")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_document"),
                _doc_digest_row(ctx, ("rule-relations",)),
            ],
            declared_relations=0,
        )
    relations = rows_of(document, "relations", "rule-relations")
    violations = []
    for index, row in enumerate(relations):
        reasons = []
        if not is_hex64(row.get("from_revision_digest")):
            reasons.append("from_revision_digest_invalid")
        if not is_hex64(row.get("to_revision_digest")):
            reasons.append("to_revision_digest_invalid")
        if row.get("relation_type") not in RELATION_TYPE_VOCABULARY:
            reasons.append("relation_type_out_of_vocabulary")
        if not (isinstance(row.get("direction"), str) and row["direction"]):
            reasons.append("direction_missing")
        if not (isinstance(row.get("scope"), str) and row["scope"]):
            reasons.append("scope_missing")
        if not bool(row.get("proof")):
            reasons.append("proof_missing")
        if "stale" not in row:
            reasons.append("staleness_undeclared")
        if reasons:
            violations.append({"index": index, "from_rule_id": row.get("from_rule_id"), "reasons": reasons})
    if violations:
        schema_side, digest_side = _split_violations(
            violations, ("from_revision_digest_invalid", "to_revision_digest_invalid")
        )
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_side else "PASS",
                    reason="schema_violations" if schema_side else "schema_checks_passed",
                    violations=schema_side,
                ),
                _digest_row(
                    "FAIL" if digest_side else "PASS",
                    reason="digest_violations" if digest_side else "digest_checks_passed",
                    violations=digest_side,
                ),
            ],
            relations_not_bound_to_exact_revisions=violations,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_relations=len(relations)
            ),
            _doc_digest_row(ctx, ("rule-relations",)),
        ],
        declared_relations=len(relations),
    )


# ---------------------------------------------------------------------------
# FOUNDATION: Batch C explicit evidence rules（历史注释——候选批五条已全部注册）
# ---------------------------------------------------------------------------
#
# 本批候选函数（SFA-FOUNDATION-008/010/012/014/015）原为「候选，不得登记进
# CHECKS」，该前提已随后续激活裁决全部落空：008/012/014/015 注册于本模块 b2
# CHECKS（见本文件登记表）；010 注册于 legacy m1_rule_governance.py CHECKS
# L830（w2b1 域，不在本模块 b2 表内）。2026-09-05 缩小裁决另注册 017/018；
# SFA-FOUNDATION-011 由 2026-09-06 H02 窄修批注册于本模块——011 不得再列于
# 任何禁注册清单，本注释不构成禁注册依据。执行器纪律不变：同形返回 {status,
# evidence, check_method_subresults}，逐方法行由 _finish/_schema_row/_digest_row
# 派生，四态语义见交接单 4.1-4.5；只消费 conformance_workflow 投影的已验证
# 证据与 Foundation 0.15.0 公开根入口（经 foundation_adoption_verifier 固定
# 调用），不复制 Schema、能力清单、对象清单、mandatory rules、路径常量或摘要
# 算法。
# ---------------------------------------------------------------------------

# Foundation 验证基础设施失败关闭码（验证器自身稳定码，非 SPI_RESULT_CODES 副本）
_FOUNDATION_VERIFICATION_INFRA_CODES = frozenset({
    "FOUNDATION_PROFILE_SPI_MISSING",
    "FOUNDATION_PROFILE_SPI_PATH_SYMLINK",
    "FOUNDATION_NODE_UNAVAILABLE",
    "FOUNDATION_PROFILE_SPI_FAILED",
    "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
    "PROJECT_PROFILE_MISSING",
    "PROJECT_PROFILE_SYMLINK",
    "PROJECT_PROFILE_INVALID",
})

_FOUNDATION_PACKAGE_NAMES = (
    "skill-family-harness-node",
    "skill-family-contracts",
    "skill-family-engineering-kit",
)
_FOUNDATION_CLASSIFICATION_SCHEMA_ID = (
    "https://contracts.skill-family.example/skill-family-audit/candidate/v2/"
    "foundation-consumption-classification.json"
)
_FOUNDATION_CLASSIFICATION_CARRIERS = (
    "foundation-consumption-classification.json",
    ".skill-family-audit/governance/foundation-consumption-classification.json",
)
_SOURCE_SUFFIXES = (".mjs", ".js", ".cjs", ".mts", ".ts", ".py")
_JS_IMPORT_RE = re.compile(
    r"""(?:from\s+|import\s*\(|import\s+["']|require\s*\()["']([^"']+)["']"""
)
_PY_STRING_RE = re.compile(r"""["']([^"']{0,400})["']""")


def _static_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "static_scan", status, "executor_static_scan_observation", **evidence
    )


def _target_source_files(target: Path) -> list[Path]:
    """目标源码清单：排除 node_modules 与治理目录，保证扫描面确定性。"""
    files = []
    for suffix in _SOURCE_SUFFIXES:
        for path in target.rglob(f"*{suffix}"):
            if not path.is_file() or path.is_symlink():
                continue
            parts = path.relative_to(target).parts
            if "node_modules" in parts or ".skill-family-audit" in parts:
                continue
            files.append(path)
    return files


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(f"invalid {label}: {path}") from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(f"invalid {label}: expected object")
    return value


def check_depend_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """独立检查测试依赖、公开载荷边界和用途声明。"""
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish([_static_row("NOT_APPLICABLE", reason="target_not_observable")], mechanical_half=True)
    root = Path(target)
    manifest_path = root / "package.json"
    if not manifest_path.is_file():
        return _finish([_static_row("NOT_APPLICABLE", reason="manifest_absent")], mechanical_half=True)
    manifest = _load_json(manifest_path, "package.json")
    dev = manifest.get("devDependencies", {})
    prod = set((manifest.get("dependencies", {}) or {}))
    floating = [name for name, version in dev.items() if isinstance(version, str) and any(ch in version for ch in "^~*xX")]
    if not floating:
        return _finish([_static_row("NOT_APPLICABLE", reason="no_private_test_floating_dependency")], mechanical_half=True)
    direct_violations = sorted(set(floating) & prod)
    declaration = root / ".audit/dependencies-governance.json"
    violations = []
    violations.extend(f"production_dependency:{name}" for name in direct_violations)
    if declaration.is_file():
        governance = _load_json(declaration, "dependencies-governance.json")
        if governance.get("scope") not in (None, "private_test_only"):
            violations.append("usage_scope")
        if governance.get("scope") == "private_test_only" and not isinstance(governance.get("intended_usage"), list):
            violations.append("usage_declaration")
    if violations:
        return _finish([_static_row("FAIL", reason="dependency_boundary_violation", violations=violations)], mechanical_half=True)
    return _finish([_static_row("EVIDENCE_MISSING", reason="dependency_lineage_not_verified", dependencies=floating)], mechanical_half=True)


_KIT_PUBLIC_ROOT = "skill-family-engineering-kit"
_KIT_COMMAND_BOUNDARY_EXPORTS = (
    "FORBIDDEN_SIDE_EFFECTS",
    "COMMAND_SIDE_EFFECTS",
    "KIT_EXIT_CODES",
)
_FOUNDATION_SOURCE_AUTHORITY_KIND = "skill-family.source-authority-receipt"
_FOUNDATION_KIT_RECEIPT_SUBJECT = "skill-family-engineering-kit"
_FOUNDATION_KIT_RECEIPT_VERSION = "0.15.0"

# F018 活跃规范面（spec/policies、governance/rules 与目标内 docs/specs）：
# 历史修订、证据与来源 shard 不适用（canonical r6 适用条件逐字）。排除段用
# relative parts 判段名，避免把证据/历史容器误当当前正式规范。
_FOUNDATION_ACTIVE_SPEC_ROOTS = ("spec/policies", "governance/rules", "docs/specs")
_FOUNDATION_ACTIVE_SPEC_SUFFIXES = (".json", ".md")
_FOUNDATION_SPEC_EXCLUDED_PARTS = {
    "evidence", "history", "_archives", "artifacts", "source-shards",
    "node_modules", ".skill-family-audit", "generated",
}
# 私有 FND 坐标：包名必须是坐标起点（FND/packages/… 仓库路径中缀与本机绝对
# 路径描述不算说明符引用，不误伤 provenance 文本），后接 /src/ 或 /./src/。
_FOUNDATION_FND_ALTERNATION = (
    "skill-family-(?:engineering-kit|harness-node|contracts)"
)
_FND_PRIVATE_COORDINATE_RE = re.compile(
    rf"(?:^|[\s\"'`=(\[{{]){_FOUNDATION_FND_ALTERNATION}"
    rf"(?:@[^/\"'\s]*)?(?:/\.)?/src/"
)


def _foundation_active_spec_files(root: Path) -> list[Path]:
    """活跃规范面文件清单：当前正式规范文件集（历史/证据/来源 shard 排除）。"""
    files: list[Path] = []
    for sub in _FOUNDATION_ACTIVE_SPEC_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for suffix in _FOUNDATION_ACTIVE_SPEC_SUFFIXES:
            for path in base.rglob(f"*{suffix}"):
                if not path.is_file() or path.is_symlink():
                    continue
                parts = path.relative_to(root).parts
                if any(part in _FOUNDATION_SPEC_EXCLUDED_PARTS for part in parts):
                    continue
                files.append(path)
    return files


def _foundation_evidence_entries(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    """evidence-set 既有条目通道（ctx 或 scope 内嵌 entries；缺失返回 None）。"""
    entries = ctx.get("evidence_set")
    if entries is None:
        entries = _scope(ctx).get("evidence_set")
    return entries if isinstance(entries, list) else None


def _foundation_entry_bytes(entry: dict[str, Any]) -> bytes | None:
    """evidence-set 条目存在性 + 摘要闭合核验；不合法返回 None（不计证据、不阻断）。

    与 _governance_gate_behavior 同款：普通文件、非符号链接、hex64 摘要与实际
    字节一致才可作证据；不合法条目只被忽略，不成为 FAIL 依据。
    """
    if not isinstance(entry, dict):
        return None
    path_value = entry.get("path")
    expected = entry.get("sha256")
    if not isinstance(path_value, str) or not isinstance(expected, str):
        return None
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        return None
    if not is_hex64(expected):
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if _sha256_bytes(raw) != expected:
        return None
    return raw


def check_foundation_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """engineering-kit 命令边界与退出码引用纪律（FCR-010 缩小实现）。

    机械半区（static_scan）只做引用形态与材料存在性核对：
    - 引用面沿 FOUNDATION-012 同款说明符/具名导出匹配（不解析 import 语义、
      不复制能力或值清单）：目标源码把命令边界三常量（FORBIDDEN_SIDE_EFFECTS
      / COMMAND_SIDE_EFFECTS / KIT_EXIT_CODES）绑定到 0.15.0 公共根之外的
      说明符、或出现对 engineering-kit 私有源码坐标的引用字面量，均为 FAIL；
    - 公共声明侧沿 evidence-set 既有 receipt 条目只读核对 source-authority
      receipt（存在性 + 摘要闭合 + 0.15.0 engineering-kit subject），不新增
      收据类型；
    - target_command_observation 沿 evidence-set 既有 log/receipt 条目只读
      核对真实结构化命令结果；核验深度按 2026-09-05 裁决 OI-3 限于存在性 +
      摘要闭合 + receipt 目标绑定核对级，更深字段级形态待真实材料到位后裁决；
    - 声称实际无副作用必须有真实行为材料，自报不构成证明。
    未引用 engineering-kit 命令边界为 NOT_APPLICABLE；触发后缺材料保持
    EVIDENCE_MISSING（reason 按缩小裁决语义，不再引用等待新 API）。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="target_not_observable")],
            mechanical_half=True,
        )
    root = Path(target)
    import_references: list[dict[str, str]] = []
    named_bindings: list[dict[str, str]] = []
    py_mentions: list[dict[str, str]] = []
    for path in _target_source_files(root):
        content = path.read_text(encoding="utf8", errors="replace")
        relative = str(path.relative_to(root))
        if path.suffix == ".py":
            # Python 目标中裸包名字符串是说明性常量/检查器自身文本，不构成
            # import 触发；具名导出只能绑定到与导出名同字面量的说明符。
            for binding in _foundation_named_export_references(
                path, content, _KIT_COMMAND_BOUNDARY_EXPORTS
            ):
                if binding["specifier"].startswith(_KIT_PUBLIC_ROOT):
                    named_bindings.append({
                        "file": relative,
                        "specifier": binding["specifier"],
                        "export_name": binding["export_name"],
                    })
            for specifier in _foundation_reference_specifiers(path, content):
                if specifier.startswith(_KIT_PUBLIC_ROOT):
                    py_mentions.append({"file": relative, "specifier": specifier})
        else:
            for specifier in _foundation_reference_specifiers(path, content):
                if specifier.startswith(_KIT_PUBLIC_ROOT):
                    import_references.append({"file": relative, "specifier": specifier})
            for binding in _foundation_named_export_references(
                path, content, _KIT_COMMAND_BOUNDARY_EXPORTS
            ):
                if binding["specifier"].startswith(_KIT_PUBLIC_ROOT):
                    named_bindings.append({
                        "file": relative,
                        "specifier": binding["specifier"],
                        "export_name": binding["export_name"],
                    })
    private_imports = [
        reference
        for reference in import_references
        if "/src/" in reference["specifier"]
    ] + [
        mention
        for mention in py_mentions
        if "/src/" in mention["specifier"]
    ]
    bypassed_exports = [
        binding
        for binding in named_bindings
        if binding["specifier"] != _KIT_PUBLIC_ROOT
    ]
    if private_imports or bypassed_exports:
        return _finish(
            [
                _static_row(
                    "FAIL",
                    reason="kit_command_boundary_reference_violation",
                    private_imports=private_imports,
                    bypassed_exports=bypassed_exports,
                )
            ],
            private_imports=private_imports,
            bypassed_exports=bypassed_exports,
            mechanical_half=True,
        )
    if not import_references and not named_bindings:
        return _finish(
            [
                _static_row(
                    "NOT_APPLICABLE",
                    reason="no_kit_command_boundary_consumer",
                )
            ],
            mechanical_half=True,
        )
    entries = _foundation_evidence_entries(ctx)
    if entries is None:
        return _finish(
            [
                _static_row(
                    "EVIDENCE_MISSING",
                    reason="target_command_observation_missing",
                    missing=["target_command_observation", "source_authority_receipt"],
                )
            ],
            missing=["target_command_observation", "source_authority_receipt"],
            mechanical_half=True,
        )
    declaration_id: str | None = None
    observation_ids: list[str] = []
    log_ids: list[str] = []
    bound_receipt_ids: list[str] = []
    for entry in entries:
        raw = _foundation_entry_bytes(entry)
        if raw is None or entry.get("kind") not in {"log", "receipt"}:
            continue
        if entry.get("kind") == "log":
            log_ids.append(entry["evidence_id"])
            continue
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        if value.get("kind") == _FOUNDATION_SOURCE_AUTHORITY_KIND:
            subjects = value.get("subjects")
            if isinstance(subjects, list) and any(
                isinstance(subject, dict)
                and subject.get("packageName") == _FOUNDATION_KIT_RECEIPT_SUBJECT
                and subject.get("version") == _FOUNDATION_KIT_RECEIPT_VERSION
                for subject in subjects
            ):
                declaration_id = entry["evidence_id"]
        binding = value.get("binding")
        if (
            isinstance(binding, dict)
            and isinstance(binding.get("target_version"), str)
            and binding["target_version"]
            and is_hex64(binding.get("target_digest"))
        ):
            bound_receipt_ids.append(entry["evidence_id"])
    if log_ids and bound_receipt_ids:
        observation_ids = [log_ids[0], bound_receipt_ids[0]]
    missing = []
    if not observation_ids:
        missing.append("target_command_observation")
    if declaration_id is None:
        missing.append("source_authority_receipt")
    if missing:
        reason = (
            "target_command_observation_missing"
            if "target_command_observation" in missing
            else "source_authority_receipt_missing"
        )
        return _finish(
            [
                _static_row(
                    "EVIDENCE_MISSING",
                    reason=reason,
                    missing=missing,
                    declaration_evidence_id=declaration_id,
                    log_evidence_ids=log_ids,
                    bound_receipt_evidence_ids=bound_receipt_ids,
                )
            ],
            missing=missing,
            declaration_evidence_id=declaration_id,
            log_evidence_ids=log_ids,
            bound_receipt_evidence_ids=bound_receipt_ids,
            mechanical_half=True,
        )
    return _finish(
        [
            _static_row(
                "PASS",
                reason="static_checks_passed",
                import_references=len(import_references),
                named_bindings=len(named_bindings),
                declaration_evidence_id=declaration_id,
                observation_evidence_ids=observation_ids,
            )
        ],
        import_references=len(import_references),
        named_bindings=len(named_bindings),
        declaration_evidence_id=declaration_id,
        observation_evidence_ids=observation_ids,
        mechanical_half=True,
    )


def check_foundation_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """Foundation 公共机器能力引用纪律（FCR-011 缩小实现）。

    机械半区（static_scan）只核对活跃规范面（当前正式规范文件集；历史修订、
    证据与来源 shard 不适用——canonical r6 适用条件逐字）：
    - 无私有 FND 坐标：坐标起点（非仓库路径中缀、非本机绝对路径描述）后接
      /src/ 的引用说明符形态为 FAIL；
    - 无 Foundation 能力清单/机器声明复制：只检测复制形态，不比对清单内容
      本身——本实现不携带任何 Foundation 能力值、导出名或摘要副本；活跃规范
      文件内嵌 Foundation source-authority receipt 机器声明载体即复制形态
      FAIL；
    - 机器声明不得替代 Audit 业务裁决属语义半区（semantic_review），机械半区
      不裁决。
    活跃规范面无正向 Foundation 引用为 NOT_APPLICABLE；全干净为 PASS。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="target_not_observable")],
            mechanical_half=True,
        )
    root = Path(target)
    spec_files = _foundation_active_spec_files(root)
    if not spec_files:
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="no_active_spec_surface")],
            mechanical_half=True,
        )
    private_coordinates: list[dict[str, str]] = []
    manifest_copies: list[dict[str, str]] = []
    surface_files: list[str] = []
    for path in sorted(spec_files):
        text = path.read_text(encoding="utf8", errors="replace")
        if not any(package in text for package in _FOUNDATION_PACKAGE_NAMES):
            continue
        relative = str(path.relative_to(root))
        surface_files.append(relative)
        for match in _FND_PRIVATE_COORDINATE_RE.finditer(text):
            private_coordinates.append({
                "file": relative,
                "coordinate": match.group(0).strip()[:120],
            })
        if _FOUNDATION_SOURCE_AUTHORITY_KIND in text:
            manifest_copies.append({"file": relative})
    if not surface_files:
        return _finish(
            [
                _static_row(
                    "NOT_APPLICABLE",
                    reason="no_positive_foundation_reference_surface",
                )
            ],
            mechanical_half=True,
        )
    if private_coordinates or manifest_copies:
        return _finish(
            [
                _static_row(
                    "FAIL",
                    reason="active_spec_surface_reference_violation",
                    private_coordinates=private_coordinates,
                    manifest_copies=manifest_copies,
                )
            ],
            private_coordinates=private_coordinates,
            manifest_copies=manifest_copies,
            mechanical_half=True,
        )
    return _finish(
        [
            _static_row(
                "PASS",
                reason="static_checks_passed",
                files_scanned=len(spec_files),
                surface_files=len(surface_files),
            )
        ],
        files_scanned=len(spec_files),
        surface_files=len(surface_files),
        mechanical_half=True,
    )


def check_foundation_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """Foundation 0.15.0 骨架与采用草稿 lineage 的窄失败关闭实现（revision 6，
    对齐 canonical r6 digest 668fcc06…，revision_basis 0.15.0）。

    三个独立子主张：
    ① 当前树静态事实：有效 Project Profile（含 null 的采用草稿不作为有效
       声明）与 0.15.0 公共导出 scaffoldTarget/planAdoption/buildProfileDraft/
       describeSkeletonFiles 的真实存在性——后者经 profile.json foundation_pin
       指向的真实 0.15.0 tarball 本地实测（字节 sha256 与根入口导出面），
       核验通过才给出真实结果，绝不从文本声明自推导；
    ② 调用来源：已认可执行职责/CI 保存的该次原始调用记录、公共根导入代码
       与包解析来源——只能来自审计上下文认可的外部材料；
    ③ 历史非覆盖：该次执行的独立行为记录——外部材料缺失时保持
       EVIDENCE_MISSING（reason 精确到子主张），绝不接受目标自行生成的收据。
    树内私有 /src/ 坐标引用直接 FAIL；任一子主张缺证时整条不得 PASS。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish([
            _method_row("schema_validation", "NOT_APPLICABLE", "foundation-011-current-state"),
            _method_row("static_scan", "NOT_APPLICABLE", "foundation-011-current-state"),
            _method_row("behavior_verification", "NOT_APPLICABLE", "foundation-011-historical-behavior"),
        ], revision=6, mechanical_half=True)
    root = Path(target)
    raw_scope = ctx.get("scope")
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    schema_status, schema_reason, schema_evidence = _foundation_011_current_state(root, scope)
    static_status, static_reason, static_evidence = _foundation_011_call_provenance(root)
    return _finish([
        _schema_row(schema_status, reason=schema_reason, **schema_evidence),
        _static_row(static_status, reason=static_reason, **static_evidence),
        _behavior_row("EVIDENCE_MISSING", reason="foundation_011_independent_history_missing"),
    ], revision=6, mechanical_half=True)


# ---------------------------------------------------------------------------
# FOUNDATION-011 子主张①本地核验支撑（真实 0.15.0 tarball 导出面实测）
# ---------------------------------------------------------------------------
_FOUNDATION_011_KIT_VERSION = "0.15.0"
_FOUNDATION_011_ROOT_EXPORTS = (
    "scaffoldTarget",
    "planAdoption",
    "buildProfileDraft",
    "describeSkeletonFiles",
)
_FOUNDATION_011_EXPORT_GROUP_RE = re.compile(r"\bexport\s*\{([^}]*)\}", re.S)
_FOUNDATION_011_EXPORT_KW_RE = re.compile(
    r"\bexport\s+(?:const|function|class)\s+([A-Za-z_$][\w$]*)"
)


def _foundation_011_root_export_names(
    tarball: Path,
) -> tuple[dict[str, Any], list[str]] | None:
    """真实 tarball 根入口具名导出面实测：以 package.json ``exports["."]`` 定位
    根入口，提取 ESM 具名导出（``export {...}`` 组内条目取 ``as`` 右端，加上
    ``export const/function/class`` 声明名）。读取失败或形状异常返回 None。"""
    try:
        with tarfile.open(tarball, "r:*") as archive:
            manifest_member = archive.extractfile("package/package.json")
            if manifest_member is None:
                return None
            try:
                manifest = json.loads(manifest_member.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None
            if not isinstance(manifest, dict):
                return None
            exports = manifest.get("exports")
            entry_rel = exports.get(".") if isinstance(exports, dict) else None
            if not isinstance(entry_rel, str) or not entry_rel.startswith("./"):
                return None
            member_name = "package/" + entry_rel[2:]
            entry_member = archive.extractfile(member_name)
            if entry_member is None:
                return None
            text = entry_member.read().decode("utf-8", errors="replace")
    except (OSError, tarfile.TarError, EOFError):
        return None
    export_names: set[str] = set()
    for group in _FOUNDATION_011_EXPORT_GROUP_RE.findall(text):
        for raw_item in group.split(","):
            item = re.split(r"\bas\b", raw_item.strip())[-1].strip()
            item = item.removeprefix("type ").strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", item):
                export_names.add(item)
    for name in _FOUNDATION_011_EXPORT_KW_RE.findall(text):
        export_names.add(name)
    return {"entry": member_name, "export_count": len(export_names)}, sorted(export_names)


def _foundation_011_current_state(
    root: Path, scope: dict[str, Any]
) -> tuple[str, str, dict[str, Any]]:
    """子主张①本地核验：真实 profile.json 静态事实 + 0.15.0 公共导出实测 +
    verifyProjectProfile 投影。返回 (status, reason, evidence)。"""
    profile_json = root / "profile.json"
    if profile_json.is_symlink():
        return "FAIL", "foundation_011_profile_carrier_is_symlink", {}
    if not profile_json.is_file():
        return "EVIDENCE_MISSING", "foundation_011_profile_carrier_missing", {}
    try:
        document = json.loads(profile_json.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return "EVIDENCE_MISSING", "foundation_011_profile_document_unparsable", {
            "error": str(exc)[:200]
        }
    except OSError as exc:
        return "EVIDENCE_MISSING", "foundation_011_profile_document_unreadable", {
            "error": str(exc)[:200]
        }
    if not isinstance(document, dict):
        return "EVIDENCE_MISSING", "foundation_011_profile_document_not_object", {}
    if _has_null(document):
        # 含 null 的采用草稿不作为有效声明：无法据此核验子主张①（失败关闭）。
        return "EVIDENCE_MISSING", "foundation_011_null_draft_not_valid_declaration", {}
    if document.get("kind") != "skill-family.project-profile":
        return "EVIDENCE_MISSING", "foundation_011_profile_kind_unexpected", {
            "kind": str(document.get("kind"))
        }
    adoption = document.get("adoption")
    if not isinstance(adoption, dict):
        return "EVIDENCE_MISSING", "foundation_011_adoption_declaration_missing", {}
    pin = adoption.get("foundation_pin")
    packages = pin.get("packages") if isinstance(pin, dict) else None
    kit_pin = packages.get("skill-family-engineering-kit") if isinstance(packages, dict) else None
    declared_version = None
    if isinstance(kit_pin, dict) and isinstance(kit_pin.get("version"), str):
        declared_version = kit_pin["version"]
    elif isinstance(adoption.get("foundation"), str):
        declared_version = adoption["foundation"]
    if declared_version != _FOUNDATION_011_KIT_VERSION:
        if declared_version is None:
            return "EVIDENCE_MISSING", "foundation_011_adoption_version_unavailable", {}
        return "FAIL", "foundation_011_adoption_version_not_current", {
            "declared_version": declared_version
        }
    if not isinstance(kit_pin, dict):
        return "EVIDENCE_MISSING", "foundation_011_kit_pin_unavailable", {}
    pin_rel = kit_pin.get("path")
    pin_digest = kit_pin.get("sha256")
    if not isinstance(pin_rel, str) or not pin_rel or not isinstance(pin_digest, str):
        return "EVIDENCE_MISSING", "foundation_011_kit_pin_identity_incomplete", {}
    tarball = root / pin_rel
    if tarball.is_symlink():
        return "FAIL", "foundation_011_kit_tarball_is_symlink", {"path": pin_rel}
    if not tarball.is_file():
        return "EVIDENCE_MISSING", "foundation_011_kit_tarball_unavailable", {"path": pin_rel}
    try:
        observed_digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    except OSError as exc:
        return "EVIDENCE_MISSING", "foundation_011_kit_tarball_unreadable", {
            "error": str(exc)[:200]
        }
    if observed_digest != pin_digest:
        return "FAIL", "foundation_011_kit_pin_digest_mismatch", {
            "declared_sha256": pin_digest, "observed_sha256": observed_digest
        }
    measured = _foundation_011_root_export_names(tarball)
    if measured is None:
        return "EVIDENCE_MISSING", "foundation_011_root_export_surface_unverifiable", {
            "path": pin_rel
        }
    export_detail, export_names = measured
    missing_exports = [
        name for name in _FOUNDATION_011_ROOT_EXPORTS if name not in export_names
    ]
    if missing_exports:
        return "FAIL", "foundation_011_root_export_names_missing", {
            "missing": missing_exports, "path": pin_rel
        }
    foundation_profile = scope.get("foundation_profile")
    code = foundation_profile.get("code") if isinstance(foundation_profile, dict) else None
    if not isinstance(code, str) or not code:
        return "EVIDENCE_MISSING", "foundation_011_schema_validation_result_missing", {}
    if code == "SPE0000":
        if foundation_profile.get("foundation_profile_complete") is True:
            return "PASS", "foundation_011_current_state_verified", {
                "kit_root_exports": export_detail
            }
        return "FAIL", "foundation_011_verification_result_contradicts_success", {}
    if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
        return "EVIDENCE_MISSING", "foundation_011_verification_unavailable", {"code": code}
    return "FAIL", "foundation_011_profile_schema_rejected", {"code": code}


def _foundation_011_call_provenance(root: Path) -> tuple[str, str, dict[str, Any]]:
    """子主张②：调用来源。树内源码引用 kit 私有 /src/ 坐标→FAIL；扫描面有
    文件不可读→EM（扫描不完整）；否则该次调用来源的原始记录属审计上下文认可
    的外部材料，本批无此类材料→EVIDENCE_MISSING（reason 精确子主张②）。"""
    private_references: list[dict[str, str]] = []
    unreadable: list[str] = []
    for path in _target_source_files(root):
        relative = str(path.relative_to(root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            unreadable.append(f"{relative}: {exc}")
            continue
        for specifier in _foundation_reference_specifiers(path, content):
            if _KIT_PUBLIC_ROOT in specifier and "/src/" in specifier:
                private_references.append({"file": relative, "specifier": specifier})
    if private_references:
        return "FAIL", "foundation_011_private_kit_coordinate_reference", {
            "private_imports": private_references
        }
    if unreadable:
        return "EVIDENCE_MISSING", "foundation_011_call_provenance_scan_incomplete", {
            "unreadable_files": unreadable
        }
    return "EVIDENCE_MISSING", "foundation_011_call_provenance_missing", {}


def _has_null(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        return any(_has_null(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_null(item) for item in value)
    return False


def _foundation_reference_specifiers(
    path: Path, content: str
) -> list[str]:
    """抽取文件中 Foundation 相关引用说明符（不做路径判断，只做文本识别）。"""
    if path.suffix == ".py":
        return [
            literal
            for literal in _PY_STRING_RE.findall(content)
            if any(package in literal for package in _FOUNDATION_PACKAGE_NAMES)
        ]
    return [
        specifier
        for specifier in _JS_IMPORT_RE.findall(content)
        if any(package in specifier for package in _FOUNDATION_PACKAGE_NAMES)
    ]


def _foundation_named_export_references(
    path: Path, content: str, export_names: tuple[str, ...]
) -> list[dict[str, str]]:
    """把 FOUNDATION-012 关心的具名导出绑定到取得它的具体说明符。"""
    matches: list[dict[str, str]] = []

    def add(specifier: str, names: set[str]) -> None:
        if not any(package in specifier for package in _FOUNDATION_PACKAGE_NAMES):
            return
        for name in export_names:
            if name in names:
                matches.append({"specifier": specifier, "export_name": name})

    if path.suffix == ".py":
        # Python 目标以字符串字段承载 JS 包说明符与内嵌导入片段。具名导出只能
        # 绑定到与导出名同处一个字符串字面量的说明符（同一内嵌 import 片段），
        # 不能把散落在文件别处（例如检查器自身实现文本、说明性常量）的导出名
        # 反推给该说明符——那会把实现提到某包的文字本身误判为消费该包。
        for line in content.splitlines():
            for literal in _PY_STRING_RE.findall(line):
                if any(package in literal for package in _FOUNDATION_PACKAGE_NAMES):
                    add(
                        literal,
                        {
                            name
                            for name in export_names
                            if re.search(rf"\b{name}\b", literal)
                        },
                    )
        return matches

    def imported_names(raw: str, alias_separator: str) -> set[str]:
        names = set()
        for item in raw.split(","):
            imported = item.strip().removeprefix("type ").strip()
            if not imported:
                continue
            imported = imported.split(alias_separator, 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", imported):
                names.add(imported)
        return names

    # ESM named import/re-export: the braces and the following ``from`` form
    # one binding, so another import in the same file cannot borrow its names.
    for found in re.finditer(
        r"(?:import|export)\s*(?:type\s+)?"
        r"(?:(?:[A-Za-z_$][\w$]*)\s*,\s*)?"
        r"\{(?P<names>[^}]*)\}\s*from\s*[\"'](?P<specifier>[^\"']+)[\"']",
        content,
        re.DOTALL,
    ):
        add(found.group("specifier"), imported_names(found.group("names"), " as "))

    # CommonJS and dynamic-import destructuring bind object properties to one
    # concrete require/import call.
    for found in re.finditer(
        r"(?:const|let|var)\s*\{(?P<names>[^}]*)\}\s*=\s*(?:await\s*)?"
        r"(?:require|import)\s*\(\s*[\"'](?P<specifier>[^\"']+)[\"']\s*\)",
        content,
        re.DOTALL,
    ):
        add(found.group("specifier"), imported_names(found.group("names"), ":"))

    # Namespace bindings remain associated with their own import/require even
    # when several Foundation paths occur in one source file.
    namespace_patterns = (
        r"import\s+\*\s+as\s+(?P<alias>[A-Za-z_$][\w$]*)\s+from\s*[\"'](?P<specifier>[^\"']+)[\"']",
        r"(?:const|let|var)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*[\"'](?P<specifier>[^\"']+)[\"']\s*\)",
    )
    for pattern in namespace_patterns:
        for found in re.finditer(pattern, content):
            alias = re.escape(found.group("alias"))
            add(
                found.group("specifier"),
                {
                    name
                    for name in export_names
                    if re.search(rf"\b{alias}\s*\.\s*{name}\b", content)
                },
            )

    # Direct property extraction, e.g. ``const estimate = require('pkg').estimateTokens``.
    for found in re.finditer(
        r"(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*require\s*\(\s*"
        r"[\"'](?P<specifier>[^\"']+)[\"']\s*\)\s*\.\s*(?P<name>[A-Za-z_$][\w$]*)",
        content,
    ):
        add(found.group("specifier"), {found.group("name")})
    return matches


def check_foundation_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """Project Profile 标准差异载体（已注册 w2b2 CHECKS）。

    机械断言（schema_validation）：只消费 scope.foundation_profile、真实
    ``profile.json`` 与 verifyProjectProfile 结构化结果；真实载体存在且 SPI
    返回 SPE0000（且完整）才机械 PASS；载体存在但 Schema、pin 或 override
    校验失败为 FAIL；触发后缺真实载体或验证结果为 EVIDENCE_MISSING；
    无项目采用声明才是 NOT_APPLICABLE。绝不从文本声明自行推导 SPE0000。
    """
    target = ctx.get("target")
    raw_scope = ctx.get("scope")
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    if not isinstance(target, (str, Path)) or not str(target):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="target_not_observable")],
            mechanical_half=True,
        )
    root = Path(target)
    try:
        target_is_dir = root.is_dir()
    except OSError:
        target_is_dir = False
    if not target_is_dir:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="target_not_observable")],
            mechanical_half=True,
        )
    profile_json = root / "profile.json"
    foundation_profile = scope.get("foundation_profile")
    projected_code = (
        foundation_profile.get("code")
        if isinstance(foundation_profile, dict)
        else None
    )
    adoption_evidence = scope.get("project_adoption_evidence")
    carrier = (
        adoption_evidence.get("profile_carrier")
        if isinstance(adoption_evidence, dict)
        else None
    )
    if carrier is not None and carrier != "profile.json":
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_path_mismatch", claimed=carrier)],
            mechanical_half=True,
        )
    if profile_json.is_symlink():
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_is_symlink")],
            mechanical_half=True,
        )
    # 无项目采用声明才是 NOT_APPLICABLE：只认真实载体或明确声明；
    # 工作流对缺失 profile.json 恒投影 PROJECT_PROFILE_MISSING code，
    # code 存在性不能构成采用声明（否则 N/A 在生产形状下不可达）。
    try:
        profile_present = profile_json.exists()
    except OSError:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="profile_carrier_observation_unavailable")],
            mechanical_half=True,
        )
    if not profile_present and not carrier:
        return _finish(
            [
                _schema_row(
                    "NOT_APPLICABLE",
                    reason="no_project_profile_adoption_declared",
                )
            ],
            mechanical_half=True,
        )
    if not profile_present:
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="profile_carrier_declared_but_file_missing",
                )
            ],
            mechanical_half=True,
        )
    if not profile_json.is_file():
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_not_regular_file")],
            mechanical_half=True,
        )
    try:
        document = json.loads(profile_json.read_text(encoding="utf-8"))
    except OSError as exc:
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="profile_document_unreadable",
                    error=str(exc)[:256],
                )
            ],
            mechanical_half=True,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="profile_document_invalid_json",
                    error=str(exc)[:256],
                )
            ],
            mechanical_half=True,
        )
    if not isinstance(document, dict):
        return _finish(
            [_schema_row("FAIL", reason="profile_document_not_object")],
            mechanical_half=True,
        )
    expected_digest = scope.get("project_profile_digest")
    if expected_digest is not None:
        if not is_hex64(expected_digest):
            return _finish(
                [_schema_row("FAIL", reason="project_profile_digest_invalid")],
                mechanical_half=True,
            )
        try:
            actual_digest = hashlib.sha256(profile_json.read_bytes()).hexdigest()
        except OSError as exc:
            return _finish(
                [
                    _schema_row(
                        "EVIDENCE_MISSING",
                        reason="profile_document_unreadable",
                        error=str(exc)[:256],
                    )
                ],
                mechanical_half=True,
            )
        if actual_digest != expected_digest:
            return _finish(
                [
                    _schema_row(
                        "FAIL",
                        reason="project_profile_digest_mismatch",
                        expected=expected_digest,
                        computed=actual_digest,
                    )
                ],
                mechanical_half=True,
            )
    kind = document.get("kind")
    if kind == "skill-family.profile-descriptor":
        if carrier:
            return _finish(
                [_schema_row("FAIL", reason="project_adoption_uses_provider_carrier")],
                mechanical_half=True,
            )
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="provider_profile_is_not_project_adoption")],
            mechanical_half=True,
        )
    if kind != "skill-family.project-profile":
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_kind_unknown", kind=kind)],
            mechanical_half=True,
        )
    if (
        not isinstance(foundation_profile, dict)
        or not foundation_profile
        or not isinstance(projected_code, str)
        or not projected_code
    ):
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="verify_project_profile_result_missing",
                )
            ],
            mechanical_half=True,
        )
    if projected_code == "SPE0000":
        if foundation_profile.get("foundation_profile_complete") is True:
            return _finish(
                [
                    _schema_row(
                        "PASS",
                        reason="schema_checks_passed",
                        code=projected_code,
                    )
                ],
                mechanical_half=True,
            )
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="verification_result_contradicts_success_code",
                )
            ],
            mechanical_half=True,
        )
    if projected_code in _FOUNDATION_VERIFICATION_INFRA_CODES:
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="foundation_verification_unavailable",
                    code=projected_code,
                )
            ],
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row(
                "FAIL",
                reason="profile_schema_pin_or_override_rejected",
                code=projected_code,
            )
        ],
        mechanical_half=True,
    )


def check_foundation_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """Harness 公开能力权威（已注册 w2b2 CHECKS；M1 实现批激活 ACTIVE_MECHANICAL，静态半区真实字节执行）。

    机械断言（static_scan）：公开根导入检查与真实 estimateTokens 重放。
    - 目标源码引用 Harness 包或产生 token estimate 记录时触发；
    - 导入私有 ``/src/`` 路径为 FAIL；
    - 每条估算记录用真实 estimateTokens 重放输入，估算器身份（id/version）、
      算法与 tokens 必须与真实输出一致，伪造或漂移为 FAIL；
    - 触发后缺源码或估算记录为 EVIDENCE_MISSING；
    - 未消费相关能力时为 NOT_APPLICABLE。
    不复制能力或排除项数组，不扫描硬编码的 21/6 项列表。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="target_not_observable")],
            mechanical_half=True,
        )
    target_root = Path(target)
    source_files = _target_source_files(target_root)
    governance = load_governance_document(ctx, "token-estimation")
    references = [
        {
            "file": str(path.relative_to(target_root)),
            "specifier": specifier,
        }
        for path in source_files
        for specifier in _foundation_reference_specifiers(
            path, path.read_text(encoding="utf8", errors="replace")
        )
        if any(package in specifier for package in _FOUNDATION_PACKAGE_NAMES)
    ]
    harness_root_references = [
        reference
        for reference in references
        if reference["specifier"] == "skill-family-harness-node"
    ]
    harness_subpath_references = [
        reference
        for reference in references
        if reference["specifier"].startswith("skill-family-harness-node/")
    ]
    named_harness_exports = [
        {
            "file": str(path.relative_to(target_root)),
            "specifier": binding["specifier"],
            "export_name": binding["export_name"],
        }
        for path in source_files
        for binding in _foundation_named_export_references(
            path,
            path.read_text(encoding="utf8", errors="replace"),
            ("HARNESS_CAPABILITIES", "HARNESS_EXCLUSIONS", "estimateTokens"),
        )
        if binding["specifier"].startswith("skill-family-harness-node")
    ]
    named_subpath_references = [
        reference
        for reference in named_harness_exports
        if reference["specifier"] != "skill-family-harness-node"
    ]
    private_imports = [
        reference
        for reference in harness_subpath_references
        if "/src/" in reference["specifier"]
    ]
    bypassed_exports = [
        reference
        for reference in named_harness_exports
        if reference["specifier"] != "skill-family-harness-node"
    ]
    if private_imports or bypassed_exports:
        return _finish(
            [
                _static_row(
                    "FAIL",
                    reason="private_source_path_import",
                    private_imports=private_imports,
                    bypassed_exports=bypassed_exports,
                )
            ],
            private_imports=private_imports,
            bypassed_exports=bypassed_exports,
            mechanical_half=True,
        )
    if not harness_root_references and not named_subpath_references and governance is None:
        return _finish(
            [
                _static_row(
                    "NOT_APPLICABLE",
                    reason="no_harness_capability_or_estimate_consumption",
                )
            ],
            mechanical_half=True,
        )
    if not source_files:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="harness_consumer_source_missing")],
            mechanical_half=True,
        )
    if governance is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="token_estimate_record_missing")],
            mechanical_half=True,
        )
    if not harness_root_references:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="harness_public_root_reference_missing")],
            mechanical_half=True,
        )
    records = rows_of(governance, "estimates", "token-estimation")
    if not records:
        return _finish(
            [
                _static_row(
                    "EVIDENCE_MISSING",
                    reason="token_estimates_array_empty",
                )
            ],
            mechanical_half=True,
        )
    replay_failures: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        input_text = record.get("input")
        estimator_id = record.get("estimatorId")
        estimator_version = record.get("estimatorVersion")
        declared_tokens = record.get("tokens")
        if (
            not isinstance(input_text, str)
            or not input_text
            or not isinstance(estimator_id, str)
            or not estimator_id
            or not isinstance(estimator_version, str)
            or not estimator_version
            or not isinstance(declared_tokens, int)
            or not isinstance(record.get("algorithm"), str)
            or not record.get("algorithm")
        ):
            return _finish(
                [
                    _static_row(
                        "EVIDENCE_MISSING",
                        reason="token_estimate_identity_incomplete",
                        record=index,
                    )
                ],
                mechanical_half=True,
            )
        replay = fal.estimate_tokens(input_text)
        if not isinstance(replay, dict) or replay.get("authority_ok") is not True:
            code = replay.get("code") if isinstance(replay, dict) else "UNKNOWN"
            if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
                return _finish(
                    [
                        _static_row(
                            "EVIDENCE_MISSING",
                            reason="foundation_estimation_unavailable",
                            code=code,
                        )
                    ],
                    mechanical_half=True,
                )
            return _finish(
                [
                    _static_row(
                        "FAIL",
                        reason="estimate_replay_unavailable",
                        code=code,
                    )
                ],
                mechanical_half=True,
            )
        estimator = replay.get("estimator")
        mismatches = []
        if not isinstance(estimator, dict) or estimator.get("id") != estimator_id:
            mismatches.append("estimatorId")
        if not isinstance(estimator, dict) or estimator.get("version") != estimator_version:
            mismatches.append("estimatorVersion")
        if replay.get("tokens") != declared_tokens:
            mismatches.append("tokens")
        declared_algorithm = record["algorithm"]
        if replay.get("algorithm") != declared_algorithm:
            mismatches.append("algorithm")
        if mismatches:
            replay_failures.append({"record": index, "mismatches": mismatches})
    if replay_failures:
        return _finish(
            [
                _static_row(
                    "FAIL",
                    reason="token_estimate_replay_mismatch",
                    failures=replay_failures,
                )
            ],
            replay_failures=replay_failures,
            mechanical_half=True,
        )
    return _finish(
        [
            _static_row(
                "PASS",
                reason="static_checks_passed",
                source_files=len(source_files),
                records_replayed=len(records),
            )
        ],
        source_files=len(source_files),
        records_replayed=len(records),
        mechanical_half=True,
    )


def check_foundation_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """Contracts registry 与 mandatory rules 权威（已注册 w2b2 CHECKS）。

    机械断言（schema_validation）：调用公开 Contracts registry/check 并比较
    真实调用参数，不复制对象清单或 mandatory rules：
    - 消费者声明的 objectRefs 必须都在真实 registry 中（对象来源错误为 FAIL）；
    - appliedMandatoryRuleIds 必须与真实 mandatory rules 精确一致
      （必选规则减少为 FAIL）；
    - checkCalls 逐条调用真实 checkOperation，参数漂移为 FAIL；
    - 触发后缺真实输出或消费者参数为 EVIDENCE_MISSING；
    - 未消费 Contracts 时为 NOT_APPLICABLE。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="target_not_observable")],
            mechanical_half=True,
        )
    target_root = Path(target)
    governance = load_governance_document(ctx, "contracts-consumption")
    source_refs = [
        specifier
        for path in _target_source_files(target_root)
        for specifier in _foundation_reference_specifiers(
            path, path.read_text(encoding="utf8", errors="replace")
        )
        if "skill-family-contracts" in specifier
    ]
    if governance is None and not source_refs:
        return _finish(
            [
                _schema_row(
                    "NOT_APPLICABLE",
                    reason="no_contracts_consumption_declared",
                )
            ],
            mechanical_half=True,
        )
    if governance is None:
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="contracts_consumption_declaration_missing",
                )
            ],
            mechanical_half=True,
        )
    parameters = governance.get("consumerParameters")
    if not isinstance(parameters, dict):
        return _finish(
            [_schema_row("FAIL", reason="consumer_parameters_shape_invalid")],
            mechanical_half=True,
        )
    object_refs = parameters.get("objectRefs")
    applied = parameters.get("appliedMandatoryRuleIds")
    check_calls = parameters.get("checkCalls")
    groups = [object_refs, applied, check_calls]
    group_names = ("objectRefs", "appliedMandatoryRuleIds", "checkCalls")
    shape_violations = [
        {"kind": "parameter_group_shape_invalid", "group": name}
        for name, group in zip(group_names, groups)
        if group is not None and not isinstance(group, list)
    ]
    missing_groups = [
        name
        for name, group in zip(group_names, groups)
        if group is None or not group
    ]
    violations: list[dict[str, Any]] = list(shape_violations)
    mechanism_errors: list[dict[str, Any]] = []
    # 只有存在可核对的非空组时才调用 authority；纯缺组输入直接缺证，避免
    # 为无法形成判断的载体启动 Foundation。
    if not violations and not any(isinstance(group, list) and group for group in groups):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="consumer_parameters_missing")],
            missing_groups=missing_groups,
            mechanical_half=True,
        )
    authority: dict[str, Any] | None = None
    try:
        observed_authority = fal.contracts_authority()
    except Exception as exc:
        observed_authority = None
        mechanism_errors.append({
            "phase": "contracts_authority",
            "reason": "contracts_authority_exception",
            "error_type": type(exc).__name__,
        })
    if isinstance(observed_authority, dict) and observed_authority.get("authority_ok") is True:
        authority = observed_authority
    elif not mechanism_errors:
        code = observed_authority.get("code") if isinstance(observed_authority, dict) else "UNKNOWN"
        if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
            mechanism_errors.append({"phase": "contracts_authority", "reason": "contracts_authority_unavailable", "code": code})
        else:
            violations.append({"kind": "contracts_authority_call_failed", "code": code})
    if authority is not None:
        real_schemas = {
            entry.get("object"): entry
            for entry in authority.get("schemas", [])
            if isinstance(entry, dict)
        }
        real_mandatory = set(authority.get("mandatoryRuleIds", []))
        if isinstance(object_refs, list):
            if not all(isinstance(item, str) for item in object_refs):
                violations.append({"kind": "object_refs_shape_invalid"})
            for ref in (item for item in object_refs if isinstance(item, str)):
                if ref not in real_schemas:
                    violations.append({"kind": "unknown_registry_object", "object": ref})
        if isinstance(applied, list):
            if not all(isinstance(item, str) for item in applied):
                violations.append({"kind": "applied_mandatory_rule_ids_shape_invalid"})
            else:
                applied_set = set(applied)
                if applied_set != real_mandatory:
                    violations.append({
                        "kind": "mandatory_rules_drift",
                        "missing": sorted(real_mandatory - applied_set),
                        "extra": sorted(applied_set - real_mandatory),
                    })
        if isinstance(check_calls, list):
            for index, call in enumerate(check_calls):
                if not isinstance(call, dict):
                    violations.append({"kind": "check_call_shape_invalid", "index": index})
                    continue
                operation = call.get("operation")
                params = call.get("params")
                if not isinstance(operation, str) or not operation or not isinstance(params, dict):
                    violations.append({"kind": "check_call_shape_invalid", "index": index})
                    continue
                try:
                    observed = fal.check_contracts_operation(operation, params)
                except Exception as exc:
                    mechanism_errors.append({
                        "phase": "check_contracts_operation",
                        "index": index,
                        "reason": "contracts_check_exception",
                        "error_type": type(exc).__name__,
                    })
                    continue
                if not isinstance(observed, dict) or observed.get("authority_ok") is not True:
                    code = observed.get("code") if isinstance(observed, dict) else "UNKNOWN"
                    if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
                        mechanism_errors.append({"phase": "check_contracts_operation", "index": index, "reason": "contracts_check_unavailable", "code": code})
                    else:
                        violations.append({"kind": "contracts_check_call_failed", "index": index, "code": code})
                    continue
                if observed.get("ok") is not True:
                    violations.append({"kind": "check_parameter_drift", "index": index, "operation": operation, "code": observed.get("code")})
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="contracts_authority_mismatch",
                    violations=violations,
                    mechanism_errors=mechanism_errors,
                    missing_groups=missing_groups,
                )
            ],
            violations=violations,
            missing_groups=missing_groups,
            mechanism_errors=mechanism_errors,
            mechanical_half=True,
        )
    if mechanism_errors:
        mechanism_reason = (
            "contracts_check_unavailable"
            if any(item.get("phase") == "check_contracts_operation" for item in mechanism_errors)
            else "contracts_authority_unavailable"
        )
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason=mechanism_reason, mechanism_errors=mechanism_errors)],
            missing_groups=missing_groups,
            mechanism_errors=mechanism_errors,
            mechanical_half=True,
        )
    if missing_groups:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="consumer_parameters_missing")],
            missing_groups=missing_groups,
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                contractsVersion=authority.get("contractsVersion"),
                mandatoryRules=len(real_mandatory),
            )
        ],
        mechanical_half=True,
    )


_PIN_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def check_foundation_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """Audit Surface 三坐标与 baseline pin（已注册 w2b2 CHECKS）。

    机械断言（digest_verification）：调用 describeAuditSurface、
    digestAuditSurface、describeBaselinePin、verifyBaselinePin；摘要一律由
    Foundation 计算，本地不实现 canonical JSON 或 digest：
    - 声明三坐标（contractsVersion/auditSurfaceVersion/surfaceDigest）与真实
      输出一致，且真实 pin 校验通过才机械 PASS；
    - 坐标不一致、pin 非法或失败被放行为 FAIL；
    - 触发后缺 Surface、pin 或验证输出为 EVIDENCE_MISSING；
    - 没有相关声明时为 NOT_APPLICABLE。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish(
            [_digest_row("NOT_APPLICABLE", reason="target_not_observable")],
            mechanical_half=True,
        )
    target_root = Path(target)
    governance = load_governance_document(ctx, "audit-surface-declaration")
    # 源码级引用信号：文件内容出现 Audit Surface API 或 pin 合同名即视为
    # 声明引用了该权威（与说明符无关，因为导入面是裸包说明符）。
    source_refs = [
        str(path.relative_to(target_root))
        for path in _target_source_files(target_root)
        if any(
            marker in path.read_text(encoding="utf8", errors="replace")
            for marker in (
                "audit-baseline-pin",
                "describeBaselinePin",
                "verifyBaselinePin",
                "describeAuditSurface",
            )
        )
    ]
    if governance is None and not source_refs:
        return _finish(
            [
                _digest_row(
                    "NOT_APPLICABLE",
                    reason="no_audit_surface_or_pin_declared",
                )
            ],
            mechanical_half=True,
        )
    if governance is None:
        return _finish(
            [
                _digest_row(
                    "EVIDENCE_MISSING",
                    reason="audit_surface_declaration_missing",
                )
            ],
            mechanical_half=True,
        )
    surface = governance.get("auditSurface")
    if not isinstance(surface, dict):
        return _finish(
            [
                _digest_row(
                    "EVIDENCE_MISSING",
                    reason="audit_surface_coordinates_missing",
                )
            ],
            mechanical_half=True,
        )
    if "baselinePin" not in governance:
        return _finish(
            [_digest_row("EVIDENCE_MISSING", reason="baseline_pin_missing")],
            mechanical_half=True,
        )
    pin = governance.get("baselinePin")
    if not isinstance(pin, dict):
        return _finish(
            [_digest_row("FAIL", reason="baseline_pin_malformed")],
            mechanical_half=True,
        )
    real = fal.describe_audit_surface()
    if not isinstance(real, dict) or real.get("authority_ok") is not True:
        code = real.get("code") if isinstance(real, dict) else "UNKNOWN"
        if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
            return _finish(
                [
                    _digest_row(
                        "EVIDENCE_MISSING",
                        reason="audit_surface_authority_unavailable",
                        code=code,
                    )
                ],
                mechanical_half=True,
            )
        return _finish(
            [
                _digest_row(
                    "FAIL",
                    reason="audit_surface_call_failed",
                    code=code,
                )
            ],
            mechanical_half=True,
        )
    _SURFACE_COORDINATES = ("contractsVersion", "auditSurfaceVersion", "surfaceDigest")
    missing_coordinates = [
        coordinate
        for coordinate in _SURFACE_COORDINATES
        if surface.get(coordinate) in (None, "")
    ]
    if missing_coordinates:
        return _finish(
            [
                _digest_row(
                    "EVIDENCE_MISSING",
                    reason="audit_surface_coordinates_missing",
                    missing_coordinates=missing_coordinates,
                )
            ],
            mechanical_half=True,
        )
    coordinate_failures = [
        coordinate
        for coordinate in _SURFACE_COORDINATES
        if surface.get(coordinate) != real.get(coordinate)
    ]
    if coordinate_failures:
        return _finish(
            [
                _digest_row(
                    "FAIL",
                    reason="audit_surface_coordinate_mismatch",
                    coordinate_failures=coordinate_failures,
                    declared={
                        coordinate: surface.get(coordinate)
                        for coordinate in coordinate_failures
                    },
                )
            ],
            mechanical_half=True,
        )
    frozen_at = pin.get("frozenAt")
    note = pin.get("note")
    if (
        not isinstance(frozen_at, str)
        or not _PIN_DATE_RE.fullmatch(frozen_at)
        or not isinstance(note, str)
        or not note
    ):
        return _finish(
            [_digest_row("FAIL", reason="baseline_pin_envelope_incomplete")],
            mechanical_half=True,
        )
    verification = fal.verify_baseline_pin(pin)
    if not isinstance(verification, dict) or verification.get("authority_ok") is not True:
        code = verification.get("code") if isinstance(verification, dict) else "UNKNOWN"
        if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
            return _finish(
                [
                    _digest_row(
                        "EVIDENCE_MISSING",
                        reason="baseline_verification_unavailable",
                        code=code,
                    )
                ],
                mechanical_half=True,
            )
        return _finish(
            [
                _digest_row(
                    "FAIL",
                    reason="baseline_verification_call_failed",
                    code=code,
                )
            ],
            mechanical_half=True,
        )
    if verification.get("ok") is not True:
        return _finish(
            [
                _digest_row(
                    "FAIL",
                    reason="baseline_pin_verification_failed",
                    findings=verification.get("findings", []),
                )
            ],
            mechanical_half=True,
        )
    described = fal.describe_baseline_pin(
        frozen_at,
        note,
        supersedes=pin.get("supersedes"),
        provenance=pin.get("provenance"),
    )
    if not isinstance(described, dict) or described.get("authority_ok") is not True:
        code = described.get("code") if isinstance(described, dict) else "UNKNOWN"
        if code in _FOUNDATION_VERIFICATION_INFRA_CODES:
            return _finish(
                [
                    _digest_row(
                        "EVIDENCE_MISSING",
                        reason="baseline_pin_description_unavailable",
                        code=code,
                    )
                ],
                mechanical_half=True,
            )
        return _finish(
            [
                _digest_row(
                    "FAIL",
                    reason="baseline_pin_description_failed",
                    code=code,
                )
            ],
            mechanical_half=True,
        )
    # 用 Foundation 物化的规范 pin 交叉核对声明 pin 的坐标。kind 不参与比较：
    # BASELINE_PIN_KINDS 中两种拼写都是合法 kind，且 verifyBaselinePin 已按
    # Foundation 词表校验；其余坐标必须与真实物化结果一致。
    pin_coordinate_failures = [
        coordinate
        for coordinate in (
            "digestAlgorithm",
            "contractsVersion",
            "auditSurfaceVersion",
            "surfaceDigest",
        )
        if pin.get(coordinate) != described.get(coordinate)
    ]
    if pin_coordinate_failures:
        return _finish(
            [
                _digest_row(
                    "FAIL",
                    reason="baseline_pin_coordinate_mismatch",
                    pin_coordinate_failures=pin_coordinate_failures,
                )
            ],
            mechanical_half=True,
        )
    return _finish(
        [
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                contractsVersion=real.get("contractsVersion"),
                auditSurfaceVersion=real.get("auditSurfaceVersion"),
                surfaceDigest=real.get("surfaceDigest"),
            )
        ],
        mechanical_half=True,
    )


# ---------------------------------------------------------------------------
# P4-D1: 第二批机械规则执行器
# （SFA-GOVERNANCE-001..003 / SFA-DEPEND-012..013 / SFA-FOUNDATION-001..007 /
#  SFA-FOUNDATION-020/021/023/024，共 16 条）
# ---------------------------------------------------------------------------
#
# 四态语义遵循 P4-D1 合同：PASS（positive_example）、FAIL（counterexample）、
# EVIDENCE_MISSING（trigger 为真但证据缺失或基础设施 closed）、
# NOT_APPLICABLE（trigger 为假，严格遵循合同 not_applicable_boundary，禁止用
# '无 CI' 等扩展 N/A）。每条规则在返回前调用 contracts.validate_method_subresults
# 校验逐方法子结果与聚合状态一致（失败关闭）。behavior_verification 只消费
# evidence-set 中冻结的原始门禁收据，绝不执行受检目标、绝不自行生成运行证据。
# 纯 stdlib 实现（package.json 零依赖），不复制任何权威 Schema 子集。
#
# 载体约定（本批新增，均以 <target>/.skill-family-audit/governance/<name>.json
# 承载，复用 load_governance_document 惯例；缺失语义逐规则注明）：
# - gate-scope-declaration / gate-commands（GOVERNANCE-001）
# - exception-register（GOVERNANCE-002）、exception-records / waivers-register
#   （GOVERNANCE-003）
# - foundation-pin（FOUNDATION-001/002/005/020 采用声明；consumptionForm +
#   version + digest + pins[{package,version,path,sha256}] 字节钉扎）
# - foundation-adoption-exemption（FOUNDATION-001/003/004/006 豁免登记册；
#   records 数组，单条记录形状以权威 spec/contracts/
#   foundation-adoption-exemption.schema.json 为准）
# - compatibility-fact-check / adjudication-record（DEPEND-013）
# - pin-update-record（FOUNDATION-005）、release-state（FOUNDATION-020）
# - compatibility-conclusion（FOUNDATION-021）
# - upgrade-batch（FOUNDATION-023）、baseline-pin-inventory（FOUNDATION-024）

_BEHAVIOR_OBSERVATION_SOURCE = "executor_behavior_verification_observation"
_SKILL_RULE_EXCEPTION_SCHEMA_ID = (
    "spec/packages/skill-development/schemas/skill_rule_exception.schema.json"
)
_EXCEPTION_STATUS_VOCABULARY = frozenset(
    {"pending_approval", "active", "expired", "revoked"}
)
_GATE_IDS = ("artifact_drift", "entry_contract", "public_boundary")
_GOVERNANCE_GATE_SCHEMA_ID = (
    "https://contracts.skill-family.example/skill-family-audit/candidate/v2/"
    "governance-gate-run-evidence.json"
)
_FLOATING_PREFIXES = ("^", "~")
_FLOATING_MARKERS = ("latest", "最新")
_CONSUMPTION_FORMS = frozenset(
    {"npm_exact_pin", "vendored_bundle", "bundle_projection"}
)
_NOTE_ELEMENTS = (
    "fact_statement",
    "risk_acceptance",
    "pin_discipline",
    "risk_assumption",
    "upgrade_commitment",
)
_ADOPTION_CLOSED_KEYS = frozenset(
    {"foundation_profile", "foundation_pin", "adopted_at"}
)
_UPGRADE_SIDES = ("audit_pin", "projection", "baseline_pin")
def _behavior_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "behavior_verification", status, _BEHAVIOR_OBSERVATION_SOURCE, **evidence
    )


def _validate_governance_gate_receipt_schema(
    receipt: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Use the bound Foundation schema validator for each matching receipt."""
    try:
        host = conformance_check.foundation_host_for(__file__)
    except Exception as exc:
        return "EVIDENCE_MISSING", {
            "reason": "foundation_schema_mechanism_unavailable",
            "detail": type(exc).__name__,
        }
    try:
        response = host._foundation({
            "operation": "validate-by-schema-id",
            "schemaId": _GOVERNANCE_GATE_SCHEMA_ID,
            "document": receipt,
        })
    except Exception as exc:
        return "EVIDENCE_MISSING", {
            "reason": "foundation_schema_mechanism_unavailable",
            "detail": type(exc).__name__,
        }
    if not isinstance(response, dict) or not isinstance(response.get("valid"), bool):
        return "EVIDENCE_MISSING", {
            "reason": "foundation_schema_response_unjudgable",
        }
    if response["valid"] is False:
        return "FAIL", {
            "reason": "governance_gate_receipt_schema_rejected",
            "errors": response.get("errors"),
        }
    return "PASS", {"reason": "governance_gate_receipt_schema_validated"}


def _aggregate_status(rows: list[dict[str, Any]]) -> str:
    statuses = {row["status"] for row in rows}
    if "FAIL" in statuses:
        return "FAIL"
    if "EVIDENCE_MISSING" in statuses or "NOT_RUN" in statuses:
        return "EVIDENCE_MISSING"
    if statuses == {"NOT_APPLICABLE"}:
        return "NOT_APPLICABLE"
    if statuses == {"PASS"}:
        return "PASS"
    raise ExecutorEvidenceError(
        "METHOD_RESULT_COMBINATION_INVALID", repr(sorted(statuses))
    )


def _finish_validated(
    rows: list[dict[str, Any]],
    required_methods: list[str],
    **evidence: Any,
) -> dict[str, Any]:
    """先按 contracts 校验逐方法子结果与聚合状态一致，再推导聚合结果。"""
    aggregate = _aggregate_status(rows)
    validate_method_subresults(
        rows, required_methods=required_methods, aggregate_status=aggregate
    )
    return _finish(rows, **evidence)


def _scope(ctx: dict[str, Any]) -> dict[str, Any]:
    value = ctx.get("scope")
    return value if isinstance(value, dict) else {}


def _scope_flag(ctx: dict[str, Any], name: str) -> bool:
    evidence = _scope(ctx).get("project_adoption_evidence")
    return isinstance(evidence, dict) and evidence.get(name) is True


def _observable_target_root(ctx: dict[str, Any]) -> Path | None:
    """把调用方 target 收窄为当前进程可读取、可遍历的真实目录。"""
    target = ctx.get("target")
    if not isinstance(target, (str, os.PathLike)):
        return None
    try:
        root = Path(target)
        if not root.is_dir() or not os.access(root, os.R_OK | os.X_OK):
            return None
    except (OSError, TypeError, ValueError):
        return None
    return root


def _foundation_error_details(exc: Exception) -> tuple[str | None, str | None]:
    """只解包 Foundation 稳定错误 envelope，不自行解释其内部算法。"""
    try:
        envelope = json.loads(str(exc))
    except (TypeError, json.JSONDecodeError):
        return None, None
    error = envelope.get("error") if isinstance(envelope, dict) else None
    details = error.get("details") if isinstance(error, dict) else None
    return (
        error.get("code") if isinstance(error, dict) else None,
        details.get("kind") if isinstance(details, dict) else None,
    )


def _foundation_read_unavailable(exc: BaseException) -> bool:
    """区分载体不可读与已读到但内容确定非法。"""
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, (OSError, UnicodeError)):
            return True
        current = current.__cause__
    return False


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _project_profile_document(
    ctx: dict[str, Any], target_root: Path
) -> dict[str, Any] | None:
    """scope.project_profile_document 投影优先，否则真实 profile.json；均无返回 None。"""
    profile = _scope(ctx).get("project_profile_document")
    if isinstance(profile, dict):
        return profile
    path = target_root / "profile.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(
            "PROFILE_DOCUMENT_INVALID", f"profile.json 无法解析: {exc}"
        ) from exc
    return value if isinstance(value, dict) else None


def _validate_exception_entries(
    entries: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    """通过 Foundation 校验真实例外载体，不复制权威 Schema 的 Oracle。"""
    violations: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        try:
            response = conformance_check._foundation(
                {
                    "operation": "validate-by-schema-id",
                    "schemaId": _SKILL_RULE_EXCEPTION_SCHEMA_ID,
                    "document": entry,
                }
            )
        except Exception as exc:
            return "EVIDENCE_MISSING", {
                "reason": "foundation_schema_mechanism_unavailable",
                "detail": type(exc).__name__,
                "schema_id": _SKILL_RULE_EXCEPTION_SCHEMA_ID,
                "failed_index": index,
            }
        if not isinstance(response, dict) or not isinstance(
            response.get("valid"), bool
        ):
            return "EVIDENCE_MISSING", {
                "reason": "foundation_schema_response_unjudgable",
                "schema_id": _SKILL_RULE_EXCEPTION_SCHEMA_ID,
                "failed_index": index,
            }
        if response["valid"] is False:
            violations.append(
                {
                    "index": index,
                    "reason": "exception_schema_rejected",
                    "errors": response.get("errors"),
                }
            )
    if violations:
        return "FAIL", {
            "reason": "exception_record_schema_invalid",
            "schema_id": _SKILL_RULE_EXCEPTION_SCHEMA_ID,
            "violations": violations,
        }
    return "PASS", {
        "reason": "exception_records_schema_validated",
        "schema_id": _SKILL_RULE_EXCEPTION_SCHEMA_ID,
        "records": len(entries),
    }


def _adoption_declaration(
    ctx: dict[str, Any], target_root: Path
) -> tuple[dict[str, Any] | None, str]:
    """返回 (adoption 段或 None, 载体名)；scope.foundation_profile.adoption 优先。"""
    foundation_profile = _scope(ctx).get("foundation_profile")
    if isinstance(foundation_profile, dict) and isinstance(
        foundation_profile.get("adoption"), dict
    ):
        return foundation_profile["adoption"], "scope_foundation_profile"
    profile = _project_profile_document(ctx, target_root)
    if profile is not None:
        adoption = profile.get("adoption")
        if isinstance(adoption, dict):
            return adoption, "profile_json"
    return None, "missing"


def _is_floating_version(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    return (
        value.startswith(_FLOATING_PREFIXES)
        or value in _FLOATING_MARKERS
        or value.lower().endswith(".x")
    )


def _registration_files(target_root: Path) -> list[Path]:
    base = target_root / "spec" / "external-adapters"
    if not base.is_dir():
        return []
    return sorted(
        path
        for path in base.glob("agent-method-registry-*.json")
        if path.is_file() and not path.is_symlink()
    )


def _foundation_import_specifiers(target_root: Path) -> list[str]:
    return [
        specifier
        for path in _target_source_files(target_root)
        for specifier in _foundation_reference_specifiers(
            path, path.read_text(encoding="utf8", errors="replace")
        )
        if any(package in specifier for package in _FOUNDATION_PACKAGE_NAMES)
    ]


_FOUNDATION_001_JS_FROM_RE = re.compile(
    r'''(?ms)^\s*(?:import|export)\b(?:(?!;).)*?\bfrom\s*["']([^"']+)["']'''
)
_FOUNDATION_001_JS_SIDE_EFFECT_RE = re.compile(
    r'''(?m)^\s*import\s*["']([^"']+)["']'''
)
_FOUNDATION_001_JS_CALL_RE = re.compile(
    r'''\b(?:require|import)\s*\(\s*["']([^"']+)["']\s*\)'''
)


def _foundation_001_js_code_mask(content: str) -> list[bool]:
    """标记 JS 代码字符，排除字符串、模板字符串和注释内的示例文本。"""
    mask = [False] * len(content)
    index = 0
    state = "code"
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if state == "code":
            if char in {"'", '"', "`"}:
                state = {"'": "single", '"': "double", "`": "template"}[char]
            elif char == "/" and following == "/":
                state = "line-comment"
                index += 1
            elif char == "/" and following == "*":
                state = "block-comment"
                index += 1
            else:
                mask[index] = True
        elif state == "line-comment":
            if char == "\n":
                state = "code"
                mask[index] = True
        elif state == "block-comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        else:
            delimiter = {"single": "'", "double": '"', "template": "`"}[state]
            if char == "\\":
                index += 1
            elif char == delimiter:
                state = "code"
        index += 1
    return mask


def _foundation_001_import_specifiers(target_root: Path) -> list[str]:
    """只识别 001 合同列明的真实 Python/JS 导入语法。"""
    python_packages = {
        package.replace("-", "_"): package for package in _FOUNDATION_PACKAGE_NAMES
    }
    specifiers: list[str] = []
    for path in _target_source_files(target_root):
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            try:
                tree = ast.parse(content, filename=str(path))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    root_name = name.split(".", 1)[0]
                    package = python_packages.get(root_name)
                    if package is not None:
                        specifiers.append(package)
            continue
        code_mask = _foundation_001_js_code_mask(content)
        for pattern in (
            _FOUNDATION_001_JS_FROM_RE,
            _FOUNDATION_001_JS_SIDE_EFFECT_RE,
            _FOUNDATION_001_JS_CALL_RE,
        ):
            specifiers.extend(
                match.group(1)
                for match in pattern.finditer(content)
                if code_mask[match.start()]
            )
    return [
        specifier
        for specifier in specifiers
        if any(
            specifier == package or specifier.startswith(f"{package}/")
            for package in _FOUNDATION_PACKAGE_NAMES
        )
    ]


def _verify_pin_bytes(
    target_root: Path, pins: Any
) -> list[dict[str, Any]]:
    """逐 pin 从真实字节重算 sha256；返回核对行（status: PASS/FAIL/EM）。"""
    findings = []
    if not isinstance(pins, list):
        return findings
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict):
            findings.append({"index": index, "reason": "pin_not_object", "status": "FAIL"})
            continue
        package = pin.get("package")
        path = pin.get("path")
        sha256 = pin.get("sha256")
        if not isinstance(path, str) or not path:
            findings.append({"index": index, "package": package, "reason": "pin_path_missing", "status": "FAIL"})
            continue
        file = target_root / path
        if file.is_dir():
            findings.append({"index": index, "package": package, "path": path, "reason": "vendored_bundle_digest_boundary_undetermined", "status": "EM"})
            continue
        if not file.is_file() or file.is_symlink():
            findings.append({"index": index, "package": package, "path": path, "reason": "pinned_content_missing", "status": "EM"})
            continue
        computed = _sha256_bytes(file.read_bytes())
        if not is_hex64(sha256) or computed != sha256:
            findings.append({"index": index, "package": package, "path": path, "reason": "pinned_digest_mismatch", "declared": sha256, "computed": computed, "status": "FAIL"})
        else:
            findings.append({"index": index, "package": package, "path": path, "reason": "digest_recomputed_from_bytes", "status": "PASS"})
    return findings


def _digest_row_from_findings(
    findings: list[dict[str, Any]], fallback_reason: str = "no_pinned_content_to_recompute"
) -> dict[str, Any]:
    if not findings:
        return _digest_row("EVIDENCE_MISSING", reason=fallback_reason)
    if any(finding.get("status") == "FAIL" for finding in findings):
        return _digest_row("FAIL", reason="pinned_digest_mismatch", findings=findings)
    if any(finding.get("status") == "EM" for finding in findings):
        return _digest_row(
            "EVIDENCE_MISSING", reason="pinned_content_evidence_unavailable", findings=findings
        )
    return _digest_row("PASS", reason="digest_checks_passed", pins=len(findings))


def _evidence_refs(record: Any) -> list[str]:
    refs: list[str] = []
    boundary = record.get("boundaryEvidence") if isinstance(record, dict) else None
    if isinstance(boundary, list):
        for item in boundary:
            if isinstance(item, dict):
                refs.extend(item.get("evidenceRefs") or [])
    return [ref for ref in refs if isinstance(ref, str) and ref]


def _reference_resolves(target_root: Path, ref: Any) -> bool:
    """项目内相对引用必须解析为真实文件；外部 URL 不执行下载（格式性可解析）。"""
    if not isinstance(ref, str) or not ref:
        return False
    if ref.startswith(("http://", "https://")):
        return True
    path = target_root / ref
    return path.is_file() and not path.is_symlink()


def _exemption_carrier_path(ctx: dict[str, Any]) -> Path | None:
    """Resolve the one accepted exemption carrier; ambiguity fails closed."""
    target_root = Path(ctx["target"])
    candidates = [
        target_root / "foundation-adoption-exemption.json",
        governance_dir(ctx) / "foundation-adoption-exemption.json",
    ]
    present = [path for path in candidates if path.exists()]
    if len(present) > 1:
        raise ExecutorEvidenceError(
            "FOUNDATION_EXEMPTION_CARRIER_AMBIGUOUS",
            "根目录与治理目录不得同时提供 foundation-adoption-exemption.json",
        )
    if not present:
        return None
    path = present[0]
    if path.is_symlink():
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_SYMLINK", f"豁免载体不得是符号链接: {path}"
        )
    return path


def _exemption_records(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    path = _exemption_carrier_path(ctx)
    if path is None:
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"豁免载体无法解析: {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError("GOVERNANCE_DOCUMENT_INVALID", "豁免载体顶层必须是对象")
    # 根目录载体是单条真实记录；治理目录载体才是 records 列表。
    if path.parent == Path(ctx["target"]):
        if "exemptionId" in value:
            return [value]
        if "records" not in value:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "根目录豁免载体必须是单条记录"
            )
    return rows_of(value, "records", "foundation-adoption-exemption")


def _governance_gate_behavior(ctx: dict[str, Any], gate_objects: list[dict[str, Any]]) -> dict[str, Any]:
    """消费 evidence-set 中已冻结的三项门禁原始运行观察。

    运行收据由调用方在 evidence-set 中以 ``receipt`` 条目提供；这里仅重算
    证据文件摘要、读取其原始 argv/cwd/env/输入引用/输出/退出码，并不会执行
    门禁命令或接受 scope 中的自填观察。合法但与本规则无关的 opaque receipt
    只被忽略。
    """
    if not gate_objects:
        return _behavior_row("NOT_APPLICABLE", reason="no_gate_objects_observable")
    entries = ctx.get("evidence_set")
    if entries is None:
        entries = _scope(ctx).get("evidence_set")
    if not isinstance(entries, list):
        return _behavior_row("EVIDENCE_MISSING", reason="evidence_set_missing")
    evidence_by_id = {
        entry.get("evidence_id"): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("evidence_id"), str)
    }
    evidence_ids = set(evidence_by_id)
    candidates: list[tuple[str, dict[str, Any]]] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kind") != "receipt":
            continue
        evidence_id = entry.get("evidence_id")
        path_value = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(evidence_id, str) or not isinstance(path_value, str):
            continue
        path = Path(path_value)
        if not path.is_file() or path.is_symlink():
            continue
        try:
            raw = path.read_bytes()
            if not is_hex64(expected) or _sha256_bytes(raw) != expected:
                continue
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            # receipt 是可被其他审计消费的 opaque 字节；非 JSON 不得阻断本规则。
            continue
        if (
            isinstance(value, dict)
            and value.get("kind") == "skill-family-audit.governance-gate-run-evidence"
        ):
            candidates.append((evidence_id, value))
    if not candidates:
        return _behavior_row("EVIDENCE_MISSING", reason="gate_run_evidence_missing")

    failures: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    successful_bindings: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    for evidence_id, receipt in candidates:
        if receipt.get("ruleId") != "SFA-GOVERNANCE-001":
            continue
        schema_status, schema_evidence = _validate_governance_gate_receipt_schema(receipt)
        if schema_status == "FAIL":
            failures.append({"evidence_id": evidence_id, **schema_evidence})
        elif schema_status == "EVIDENCE_MISSING":
            missing.append({"evidence_id": evidence_id, **schema_evidence})
        binding = receipt.get("binding")
        gates = receipt.get("gates")
        if not isinstance(binding, dict) or not isinstance(gates, list) or not gates:
            missing.append({"evidence_id": evidence_id, "reason": "receipt_shape_incomplete"})
            continue
        binding_keys = ("target_version", "target_digest", "task_id", "platform", "environment")
        if not all(isinstance(binding.get(key), str) and binding.get(key) for key in binding_keys):
            missing.append({"evidence_id": evidence_id, "reason": "binding_incomplete"})
            continue
        if not is_hex64(binding.get("target_digest")):
            missing.append({"evidence_id": evidence_id, "reason": "target_digest_invalid"})
            continue
        seen: set[str] = set()
        gate_failures: list[dict[str, Any]] = []
        gate_missing: list[dict[str, Any]] = []
        for gate in gates:
            if not isinstance(gate, dict):
                gate_missing.append({"reason": "gate_observation_invalid"})
                continue
            gate_id = gate.get("id")
            if gate_id in seen or gate_id not in _GATE_IDS:
                gate_failures.append({"gate": gate_id, "reason": "gate_id_invalid_or_duplicate"})
                continue
            seen.add(gate_id)
            required = ("ran", "argv", "cwd", "env", "input_refs", "stdout", "stderr", "exit_code", "conclusion")
            if any(key not in gate for key in required):
                gate_missing.append({"gate": gate_id, "reason": "raw_observation_incomplete"})
                continue
            if not isinstance(gate.get("ran"), bool):
                gate_missing.append({"gate": gate_id, "reason": "ran_invalid"})
            elif gate.get("ran") is False:
                gate_failures.append({"gate": gate_id, "reason": "gate_explicitly_not_run"})
            if (
                not isinstance(gate.get("argv"), list)
                or not gate["argv"]
                or not all(isinstance(item, str) and item for item in gate["argv"])
                or not isinstance(gate.get("cwd"), str)
                or not gate["cwd"]
                or not isinstance(gate.get("env"), dict)
                or not all(isinstance(key, str) and isinstance(value, str) for key, value in gate["env"].items())
                or not isinstance(gate.get("input_refs"), list)
                or not gate["input_refs"]
                or not all(isinstance(item, str) and item for item in gate["input_refs"])
                or not isinstance(gate.get("stdout"), str)
                or not isinstance(gate.get("stderr"), str)
                or not isinstance(gate.get("exit_code"), int)
                or isinstance(gate.get("exit_code"), bool)
            ):
                gate_missing.append({"gate": gate_id, "reason": "raw_observation_invalid"})
                continue
            missing_refs = sorted(set(gate["input_refs"]) - evidence_ids)
            if evidence_id in gate["input_refs"]:
                gate_failures.append({"gate": gate_id, "reason": "input_reference_self"})
            for input_ref in gate["input_refs"]:
                referenced_entry = evidence_by_id.get(input_ref)
                referenced_path = (
                    referenced_entry.get("path")
                    if isinstance(referenced_entry, dict)
                    else None
                )
                try:
                    same_receipt_path = (
                        isinstance(referenced_path, str)
                        and os.path.samefile(referenced_path, path)
                    )
                except OSError:
                    same_receipt_path = False
                if same_receipt_path:
                    gate_failures.append({"gate": gate_id, "reason": "input_reference_self_alias"})
            if missing_refs:
                gate_missing.append({"gate": gate_id, "reason": "input_reference_missing", "refs": missing_refs})
            gate_binding = gate.get("binding")
            if gate_binding is not None and gate_binding != binding:
                gate_failures.append({"gate": gate_id, "reason": "binding_conflict"})
            if gate.get("conclusion") not in {"pass", "fail", "not_run", "undetermined"}:
                gate_failures.append({"gate": gate_id, "reason": "conclusion_not_deterministic"})
            elif gate.get("conclusion") != "pass":
                gate_failures.append({"gate": gate_id, "reason": "gate_conclusion_not_pass"})
            elif gate.get("exit_code") != 0:
                gate_failures.append({"gate": gate_id, "reason": "pass_exit_code_nonzero"})
            observed.append({"evidence_id": evidence_id, "gate": gate_id, "ran": gate.get("ran"), "argv": gate.get("argv"), "cwd": gate.get("cwd"), "env": gate.get("env"), "input_refs": gate.get("input_refs"), "stdout": gate.get("stdout"), "stderr": gate.get("stderr"), "exit_code": gate.get("exit_code"), "conclusion": gate.get("conclusion")})
        missing_ids = sorted(set(_GATE_IDS) - seen)
        if missing_ids:
            gate_missing.append({"reason": "gate_observation_incomplete", "missing": missing_ids})
        if gate_failures:
            failures.extend(gate_failures)
        if gate_missing:
            missing.extend(gate_missing)
        successful_bindings.append(binding)
    if not successful_bindings:
        if failures:
            return _behavior_row("FAIL", reason="gate_run_evidence_invalid", violations=failures, missing=missing)
        return _behavior_row("EVIDENCE_MISSING", reason="gate_run_evidence_invalid", missing=missing)
    first_binding = successful_bindings[0]
    if any(binding != first_binding for binding in successful_bindings[1:]):
        failures.append({"reason": "binding_conflict"})
    expected_binding = ctx.get("gate_binding")
    if expected_binding is None:
        expected_binding = _scope(ctx).get("gate_binding")
    if not isinstance(expected_binding, dict) or not all(
        isinstance(expected_binding.get(key), str) and expected_binding.get(key)
        for key in ("target_version", "target_digest", "platform")
    ):
        if failures:
            return _behavior_row(
                "FAIL",
                reason="gate_run_observation_failed",
                violations=failures,
                missing=[*missing, {"reason": "expected_gate_binding_missing"}],
                observations=observed,
            )
        return _behavior_row(
            "EVIDENCE_MISSING", reason="expected_gate_binding_missing"
        )
    for key in ("target_version", "target_digest", "platform"):
        if first_binding.get(key) != expected_binding[key]:
            failures.append({"reason": "binding_conflict", "field": key})
    if failures:
        return _behavior_row("FAIL", reason="gate_run_observation_failed", violations=failures, observations=observed)
    if missing:
        return _behavior_row("EVIDENCE_MISSING", reason="gate_run_observation_incomplete", missing=missing, observations=observed)
    return _behavior_row("PASS", reason="gate_run_observation_complete", binding=first_binding, observations=observed)


def _deprecated_adoption_lock_residual(target_root: Path) -> list[str]:
    hits = []
    governance = target_root / ".skill-family-audit" / "governance"
    for path in list(governance.rglob("*.json")) + _target_source_files(target_root):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "adoption-lock" in content:
            hits.append(str(path.relative_to(target_root)))
    return sorted(hits)


def check_governance_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """最低确定性门禁三项（artifact_drift/entry_contract/public_boundary）。

    机械断言（static_scan + behavior_verification）：
    - 触发：受管生成物、公开载荷或平台入口投影任一存在（gate-scope-declaration
      声明或目标树 generated/、platforms/、.release-skill/ 信号）；
    - static_scan 只验证门禁命令本体存在与集合完整（三个门禁 id 齐备、脚本或
      可执行声明可定位、artifact_drift 绑定受管生成物）；有门禁对象却无命令
      声明为 EVIDENCE_MISSING；集合不全/命令缺失为 FAIL；
    - behavior_verification 只读 evidence-set 中已冻结的原始运行收据：无收据为
      EVIDENCE_MISSING；三项未全部实际运行、结论失败/不确定或绑定冲突为 FAIL；
    - 无任何门禁对象为 NOT_APPLICABLE；禁止以'无 CI 配置'作 N/A。
    绝不执行受检目标。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        outcome = _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="target_not_observable"),
            ],
            ["static_scan"],
            mechanical_half=True,
        )
        outcome["behavior_verification_result"] = _behavior_row(
            "NOT_APPLICABLE", reason="target_not_observable"
        )
        return outcome
    target_root = Path(target)
    scope_decl = _doc(ctx, "gate-scope-declaration")
    declared_objects: list[dict[str, Any]] = []
    if isinstance(scope_decl, dict):
        for key in ("managed_artifacts", "public_payloads", "platform_entry_projections"):
            items = scope_decl.get(key)
            if isinstance(items, list):
                declared_objects.extend(
                    {"kind": key, "object": item}
                    for item in items
                    if isinstance(item, str) and item
                )
    tree_signals = [
        name
        for name in ("generated", "platforms", ".release-skill")
        if (target_root / name).is_dir()
    ]
    if not declared_objects and not tree_signals:
        outcome = _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="no_gate_objects_observable"),
            ],
            ["static_scan"],
            gate_objects=[],
            tree_signals=[],
            mechanical_half=True,
        )
        outcome["behavior_verification_result"] = _behavior_row(
            "NOT_APPLICABLE", reason="no_gate_objects_observable"
        )
        return outcome
    commands = _doc(ctx, "gate-commands")
    if commands is None:
        static_row = _static_row(
            "EVIDENCE_MISSING",
            reason="gate_commands_declaration_missing",
            gate_objects=declared_objects,
            tree_signals=tree_signals,
        )
    else:
        gates = rows_of(commands, "gates", "gate-commands")
        declared_ids = [gate.get("id") for gate in gates]
        violations = []
        missing = [gate_id for gate_id in _GATE_IDS if gate_id not in declared_ids]
        if missing:
            violations.append({"reason": "gate_command_set_incomplete", "missing": missing})
        unexpected = sorted(set(declared_ids) - set(_GATE_IDS))
        if unexpected:
            violations.append({"reason": "gate_command_set_unexpected", "gate_ids": unexpected})
        duplicates = sorted({gate_id for gate_id in declared_ids if declared_ids.count(gate_id) > 1})
        if duplicates:
            violations.append({"reason": "gate_command_set_duplicate", "gate_ids": duplicates})
        if scope_decl is None:
            violations.append({"reason": "gate_scope_declaration_missing"})
        for gate in gates:
            gate_id = gate.get("id")
            command = gate.get("command")
            kind = gate.get("kind", "script")
            if not isinstance(command, str) or not command:
                violations.append({"reason": "gate_command_body_missing", "gate": gate_id})
            elif kind == "script" and not (target_root / command).is_file():
                violations.append(
                    {"reason": "gate_command_body_missing", "gate": gate_id, "command": command}
                )
            if gate_id == "artifact_drift" and not (
                isinstance(gate.get("bound_artifact"), str) and gate["bound_artifact"]
            ):
                violations.append({"reason": "drift_check_unbound", "gate": gate_id})
            elif gate_id == "artifact_drift" and declared_objects and gate.get("bound_artifact") not in {
                item["object"] for item in declared_objects if item["kind"] == "managed_artifacts"
            }:
                violations.append({"reason": "drift_check_bound_artifact_not_declared", "gate": gate_id})
        static_row = (
            _static_row(
                "FAIL", reason="gate_command_obligations_violated", violations=violations
            )
            if violations
            else _static_row("PASS", reason="gate_commands_complete", declared=len(gates))
        )
    outcome = _finish_validated(
        [static_row],
        ["static_scan"],
        gate_objects=declared_objects,
        tree_signals=tree_signals,
        mechanical_half=True,
    )
    outcome["behavior_verification_result"] = _governance_gate_behavior(ctx, declared_objects)
    return outcome


def check_governance_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """治理最低制品：例外登记与自加严的机器可读形态（schema_validation）。

    - 触发：例外登记条目、profile.json overrides 或例外使用事实任一存在；
    - FAIL：公共 Foundation Profile SPI 拒绝 overrides，或权威例外 Schema
      拒绝登记条目；
    - EVIDENCE_MISSING：例外使用事实存在但缺登记载体与自加严声明（有行为无载体）；
    - NOT_APPLICABLE：零例外零自加严（推荐口径）。
    例外登记载体与 FOUNDATION-003 的 foundation 豁免登记是不同对象，不得混用。

    overrides 的结构、规则身份和单调加严只由 target_scope 已调用的公共
    ``verifyProjectProfile`` 负责；这里仅消费 ``scope.foundation_profile`` 的结果，
    不复制 Profile SPI 的 Schema 或规则目录。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["schema_validation"],
            mechanical_half=True,
        )
    target_root = Path(target)
    register = _doc(ctx, "exception-register")
    entries = (
        rows_of(register, "entries", "exception-register") if register is not None else []
    )
    profile = _project_profile_document(ctx, target_root)
    overrides = None
    if profile is not None:
        if "overrides" in profile and not isinstance(profile["overrides"], list):
            raise ExecutorEvidenceError(
                "PROFILE_DOCUMENT_INVALID", "profile overrides 必须是数组"
            )
        overrides = profile.get("overrides")
    override_rows = overrides if isinstance(overrides, list) else []
    usage = _scope_flag(ctx, "exception_usage")
    if not entries and not override_rows and not usage:
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="no_exception_or_self_tightening")],
            ["schema_validation"],
            mechanical_half=True,
        )
    if usage and register is None and not override_rows:
        return _finish_validated(
            [_schema_row("EVIDENCE_MISSING", reason="exception_carrier_missing", usage=True)],
            ["schema_validation"],
            mechanical_half=True,
        )
    violations = []
    schema_status = "PASS"
    schema_evidence: dict[str, Any] = {}
    if entries:
        schema_status, schema_evidence = _validate_exception_entries(entries)
        if schema_status == "FAIL":
            violations.extend(schema_evidence.get("violations", []))
        elif schema_status == "EVIDENCE_MISSING":
            violations.append(schema_evidence)
    foundation_profile = _scope(ctx).get("foundation_profile")
    if override_rows:
        # target_scope 已经通过同一公共入口 verifyProjectProfile 生成该结果。
        # 缺失/基础设施故障不能被本地形状检查降级为通过；公共拒绝也不能由
        # Audit 自行解释成另一套 overrides 合同。
        if not isinstance(foundation_profile, dict) or not foundation_profile:
            violations.append({"reason": "verify_project_profile_result_missing"})
        else:
            profile_code = foundation_profile.get("code")
            profile_complete = (
                foundation_profile.get("foundation_profile_complete") is True
            )
            if not isinstance(profile_code, str) or not profile_code:
                violations.append({"reason": "verify_project_profile_result_missing"})
            elif profile_code == "SPE0000":
                if not profile_complete:
                    violations.append(
                        {"reason": "verification_result_contradicts_success_code"}
                    )
            elif profile_code in _FOUNDATION_VERIFICATION_INFRA_CODES:
                violations.append(
                    {
                        "reason": "foundation_verification_unavailable",
                        "code": profile_code,
                    }
                )
            else:
                violations.append(
                    {
                        "reason": "profile_schema_pin_or_override_rejected",
                        "code": profile_code,
                    }
                )
    if violations:
        unavailable = any(
            violation.get("reason")
            in {
                "verify_project_profile_result_missing",
                "foundation_verification_unavailable",
                "foundation_schema_mechanism_unavailable",
                "foundation_schema_response_unjudgable",
            }
            for violation in violations
        )
        # 基础设施缺失/未运行只能形成缺证；其余公共拒绝或例外形态问题为 FAIL。
        if unavailable and not any(
            violation.get("reason")
            not in {
                "verify_project_profile_result_missing",
                "foundation_verification_unavailable",
                "foundation_schema_mechanism_unavailable",
                "foundation_schema_response_unjudgable",
            }
            for violation in violations
        ):
            return _finish_validated(
                [
                    _schema_row(
                        "EVIDENCE_MISSING",
                        reason=(
                            next(
                                violation.get("reason")
                                for violation in violations
                                if violation.get("reason")
                                in {
                                    "verify_project_profile_result_missing",
                                    "foundation_verification_unavailable",
                                    "foundation_schema_mechanism_unavailable",
                                    "foundation_schema_response_unjudgable",
                                }
                            )
                        ),
                        violations=violations,
                    )
                ],
                ["schema_validation"],
                mechanical_half=True,
            )
        return _finish_validated(
            [
                _schema_row(
                    "FAIL",
                    reason="governance_artifacts_schema_invalid",
                    violations=violations,
                )
            ],
            ["schema_validation"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _schema_row(
                "PASS",
                reason="governance_artifacts_shape_valid",
                entries=len(entries),
                overrides=len(override_rows),
                schema_validation=schema_evidence if entries else None,
            )
        ],
        ["schema_validation"],
        mechanical_half=True,
    )


def check_governance_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """例外记录最低形态推广适用（schema_validation）。

    - 触发：任一载体出现例外条目，或存在例外使用事实；
    - FAIL：Foundation 权威例外 Schema 拒绝条目；
    - EVIDENCE_MISSING：存在例外使用事实但无法定位任何例外载体；
    - NOT_APPLICABLE：无任何例外记录（含 waivers 形态与项目侧载体均无）。
      撤销、过期与待审等追加式状态仍是需由权威 Schema 校验的例外记录；
      禁止以状态过滤或缺载体文件代替触发判断。
    字段、嵌套对象、数组、状态枚举和额外字段均由 Foundation 权威 Schema 判定。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["schema_validation"],
            mechanical_half=True,
        )
    records: list[tuple[dict[str, Any], str]] = []
    for name in ("exception-records", "waivers-register"):
        doc = _doc(ctx, name)
        if doc is None:
            continue
        for row in rows_of(doc, "records", name):
            records.append((row, name))
    usage = _scope_flag(ctx, "exception_usage")
    if not records:
        if usage:
            return _finish_validated(
                [_schema_row("EVIDENCE_MISSING", reason="exception_usage_without_carrier")],
                ["schema_validation"],
                mechanical_half=True,
            )
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="no_exception_records")],
            ["schema_validation"],
            mechanical_half=True,
        )
    schema_status, schema_evidence = _validate_exception_entries(
        [row for row, _carrier in records]
    )
    if schema_status == "FAIL":
        violations = [
            {"carrier": records[item["index"]][1], **item}
            for item in schema_evidence.get("violations", [])
        ]
    elif schema_status == "EVIDENCE_MISSING":
        return _finish_validated(
            [_schema_row("EVIDENCE_MISSING", **schema_evidence)],
            ["schema_validation"],
            mechanical_half=True,
        )
    else:
        violations = []
    if violations:
        return _finish_validated(
            [
                _schema_row(
                    "FAIL", reason="exception_record_schema_invalid", violations=violations
                )
            ],
            ["schema_validation"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _schema_row(
                "PASS",
                reason="exception_records_schema_valid",
                records=len(records),
                schema_validation=schema_evidence,
            )
        ],
        ["schema_validation"],
        mechanical_half=True,
    )


def check_depend_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """精确消费版本分别支持与不兼容升级重裁决（static_scan + digest_verification）。

    - 触发：spec/external-adapters/agent-method-registry-*.json 任一存在；
    - static_scan：登记文件集合 = 受支持版本集合（每文件唯一 version、跨文件
      不重复）；每个版本必须声明 packageTarballSha256、npmIntegrity、运行时/API
      白名单与 v2 schema 摘要；旧 sha256 若存在只能与新字段一致；
    - digest_verification：逐版本从显式 tarballPath 指向的真实字节重算摘要（并核对
      npmIntegrity）；字节缺失为 EVIDENCE_MISSING，不一致为 FAIL；
    - 无登记文件为 NOT_APPLICABLE。
    revision 3 只承认条文已裁决的 0.2.0 与 0.2.2 两版发布事实；新增版本
    必须先追加 adapter 并按 RPA-007 形成新裁决，不能由当前实现自动放行。
    """
    expected_api = (
        "validateCatalog",
        "validateProjectOverlay",
        "buildEffectiveIndex",
        "queryEffectiveIndex",
        "resolveEntry",
        "verifyProvider",
        "diagnoseRegistry",
    )
    expected_cli = ("validate", "index", "query", "resolve")
    expected_schema_digests = {
        "0.2.0": {
            "implementation.schema.json": "092ad286093434bafa7b94d49ca30e95d4184015ff53d97bc27f67b1cb756602",
            "inventory.schema.json": "8392249efdc0a660d5321cc834ef3dbda774f7c0031dc476d1c8bd16c09369c3",
            "binding.schema.json": "c0ce6192b34ff45cb46d44824b5d5f02bb6f968a6bdd4023b378ce3c186dd288",
            "projection.schema.json": "7b765598ffaf1a53d92f54d77955769fbeabe71f97a77f96ea9ce9ef5463537c",
            "method-query.schema.json": "a655208243ad3ac4946d93d7adfa98f7997f9341bf7ed95c8a6587264871255a",
            "run-lock.schema.json": "e0e8a9a15909cca2d42782ccce4039df09c452d14c722c6aa5b6f477661cf8d5",
        },
        "0.2.2": {
            "implementation.schema.json": "092ad286093434bafa7b94d49ca30e95d4184015ff53d97bc27f67b1cb756602",
            "inventory.schema.json": "8392249efdc0a660d5321cc834ef3dbda774f7c0031dc476d1c8bd16c09369c3",
            "binding.schema.json": "c0ce6192b34ff45cb46d44824b5d5f02bb6f968a6bdd4023b378ce3c186dd288",
            "projection.schema.json": "7b765598ffaf1a53d92f54d77955769fbeabe71f97a77f96ea9ce9ef5463537c",
            "method-query.schema.json": "32ef735242c7b522b425495398e7cff3ac819217429a6e60daeddfbd9c44d3fb",
            "run-lock.schema.json": "e0e8a9a15909cca2d42782ccce4039df09c452d14c722c6aa5b6f477661cf8d5",
        },
    }
    expected_tarball_pins = {
        "0.2.0": {
            "sha256": "960eb70d0d0c95b80a28bd5299f1e894a9c083ed049937be01fb6d0b2e06daef",
            "integrity": "sha512-jnlsKIbjduAUqiY9eRM0d/TpatvZOekiy0HYmIzF/NOswz65YyYnNgWTHTaafiKIvZj4DAiSenGWqydVDE/SWQ==",
        },
        "0.2.2": {
            "sha256": "76ce9a7f685068c0f91700c2db3bb94b13f82db357287ef28276dc76602b3244",
            "integrity": "sha512-uQbsnVLBkm2yeEIHdtHu8NUjgDgheYvNF8wZfvHpCSk7pnmGWW93P31fPmer9IowWmh2f55I5FguxX4czbxrvg==",
        },
    }
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="target_not_observable"),
                _digest_row("NOT_APPLICABLE", reason="target_not_observable"),
            ],
            ["static_scan", "digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    files = _registration_files(target_root)
    if not files:
        return _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="no_adapter_registration_files"),
                _digest_row("NOT_APPLICABLE", reason="no_adapter_registration_files"),
            ],
            ["static_scan", "digest_verification"],
            mechanical_half=True,
        )
    parsed: list[tuple[Path, dict[str, Any]]] = []
    static_violations = []
    for path in files:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            static_violations.append({"file": path.name, "reason": "registration_file_unparseable"})
            continue
        if not isinstance(value, dict):
            static_violations.append({"file": path.name, "reason": "registration_file_not_object"})
            continue
        parsed.append((path, value))
    versions: list[str] = []
    for path, value in parsed:
        version = value.get("version")
        version_valid = isinstance(version, str) and bool(version)
        package_name = value.get("package")
        package_sha256 = value.get("packageTarballSha256")
        legacy_sha256 = value.get("sha256")
        tarball_path = value.get("tarballPath")
        integrity = value.get("npmIntegrity")
        if not version_valid:
            static_violations.append({"file": path.name, "reason": "pinned_version_missing"})
        elif version in versions:
            static_violations.append(
                {"file": path.name, "reason": "version_claimed_by_multiple_files", "version": version}
            )
        else:
            versions.append(version)
        if not isinstance(package_name, str) or not package_name:
            static_violations.append({"file": path.name, "reason": "registered_package_missing"})
        if not isinstance(package_sha256, str) or not is_hex64(package_sha256):
            static_violations.append({"file": path.name, "reason": "package_tarball_sha256_shape_invalid"})
        if legacy_sha256 is not None and (
            not isinstance(legacy_sha256, str)
            or not is_hex64(legacy_sha256)
            or legacy_sha256 != package_sha256
        ):
            static_violations.append({"file": path.name, "reason": "legacy_sha256_conflicts_with_package_tarball_sha256"})
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            static_violations.append({"file": path.name, "reason": "npm_integrity_missing_or_invalid"})
        else:
            try:
                if not base64.b64decode(integrity[7:], validate=True):
                    raise ValueError("empty integrity")
            except (ValueError, binascii.Error):
                static_violations.append({"file": path.name, "reason": "npm_integrity_missing_or_invalid"})
        for field in ("stableRuntimeApiWhitelist", "cliWhitelist"):
            values = value.get(field)
            if not isinstance(values, list) or not values or any(
                not isinstance(item, str) or not item for item in values
            ):
                static_violations.append({"file": path.name, "reason": f"{field}_missing_or_invalid"})
        v2_surface = value.get("v2Surface")
        schema_digests = v2_surface.get("v2SchemaDigests") if isinstance(v2_surface, dict) else None
        if not isinstance(schema_digests, dict) or not schema_digests or any(
            not isinstance(key, str) or not key or not isinstance(digest, str) or not is_hex64(digest)
            for key, digest in (schema_digests.items() if isinstance(schema_digests, dict) else ())
        ):
            static_violations.append({"file": path.name, "reason": "v2_schema_digests_missing_or_invalid"})
        if not version_valid:
            continue
        expected_schemas = expected_schema_digests.get(version)
        expected_pin = expected_tarball_pins.get(version)
        if expected_schemas is None or expected_pin is None:
            static_violations.append(
                {"file": path.name, "reason": "version_not_adjudicated", "version": version}
            )
            continue
        if path.name != f"agent-method-registry-{version}.json":
            static_violations.append(
                {"file": path.name, "reason": "registration_filename_version_mismatch", "version": version}
            )
        if value.get("adapterId") != "agent-method-registry-v1":
            static_violations.append({"file": path.name, "reason": "adapter_identity_mismatch"})
        if package_name != "agent-method-registry":
            static_violations.append({"file": path.name, "reason": "registered_package_mismatch"})
        if package_sha256 != expected_pin["sha256"]:
            static_violations.append(
                {"file": path.name, "reason": "released_tarball_sha256_pin_mismatch", "version": version}
            )
        if integrity != expected_pin["integrity"]:
            static_violations.append(
                {"file": path.name, "reason": "released_npm_integrity_pin_mismatch", "version": version}
            )
        if value.get("stableRuntimeApiWhitelist") != list(expected_api):
            static_violations.append(
                {"file": path.name, "reason": "runtime_api_whitelist_mismatch", "version": version}
            )
        if value.get("cliWhitelist") != list(expected_cli):
            static_violations.append(
                {"file": path.name, "reason": "cli_whitelist_mismatch", "version": version}
            )
        if schema_digests != expected_schemas:
            static_violations.append(
                {"file": path.name, "reason": "v2_schema_digest_set_mismatch", "version": version}
            )
        if not isinstance(v2_surface, dict) or v2_surface.get("releasedInVersion") != "0.2.0":
            static_violations.append(
                {"file": path.name, "reason": "v2_release_fact_mismatch", "version": version}
            )
        if not isinstance(v2_surface, dict) or v2_surface.get("allowedAsDependency") is not True:
            static_violations.append(
                {"file": path.name, "reason": "precise_consumption_approval_missing", "version": version}
            )
    if set(versions) != set(expected_schema_digests):
        static_violations.append(
            {
                "reason": "adjudicated_version_set_mismatch",
                "expected": sorted(expected_schema_digests),
                "observed": sorted(set(versions)),
            }
        )
    static = (
        _static_row(
            "FAIL", reason="adapter_registration_shape_invalid", violations=static_violations
        )
        if static_violations
        else _static_row(
            "PASS",
            reason="adapter_registration_shape_valid",
            files=len(files),
            versions=versions,
        )
    )
    findings = []
    for path, value in parsed:
        version = value.get("version")
        tarball_path = value.get("tarballPath")
        declared_sha256 = value.get("packageTarballSha256")
        if not isinstance(tarball_path, str) or not tarball_path:
            findings.append(
                {
                    "version": version,
                    "path": tarball_path,
                    "reason": "tarball_byte_evidence_missing",
                    "status": "EM",
                }
            )
            continue
        if not isinstance(tarball_path, str) or not tarball_path or Path(tarball_path).is_absolute():
            findings.append({"version": version, "path": tarball_path, "reason": "tarball_path_outside_target", "status": "FAIL"})
            continue
        try:
            observed = conformance_check._foundation({
                "operation": "read-file-strict",
                "root": str(target_root),
                "path": tarball_path,
            })
        except OSError:
            findings.append({"version": version, "path": tarball_path, "reason": "tarball_byte_evidence_missing", "status": "EM"})
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
                    findings.append({"version": version, "path": tarball_path, "reason": "tarball_path_outside_target", "status": "FAIL"})
                elif kind in {"missing-resource", "read-failed", "unsafe-state-entry"}:
                    findings.append({"version": version, "path": tarball_path, "reason": "tarball_byte_evidence_missing", "status": "EM"})
                else:
                    findings.append({"version": version, "path": tarball_path, "reason": "foundation_read_file_strict_failed", "status": "FAIL"})
            else:
                findings.append({"version": version, "path": tarball_path, "reason": "foundation_read_file_strict_failed", "status": "FAIL"})
            continue
        content = observed.get("content") if isinstance(observed, dict) else None
        if not isinstance(content, dict) or content.get("type") != "Buffer" or not isinstance(content.get("data"), list) or any(
            type(item) is not int or item < 0 or item > 255 for item in content["data"]
        ):
            findings.append({"version": version, "path": tarball_path, "reason": "foundation_read_file_strict_invalid_response", "status": "FAIL"})
            continue
        bytes_ = bytes(content["data"])
        mismatch = []
        if computed := _sha256_bytes(bytes_):
            if computed != declared_sha256:
                mismatch.append("sha256")
        integrity = value.get("npmIntegrity")
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            computed_integrity = (
                "sha512-"
                + base64.b64encode(hashlib.sha512(bytes_).digest()).decode("ascii")
            )
            if computed_integrity != integrity:
                mismatch.append("npmIntegrity")
        if mismatch:
            findings.append(
                {"version": version, "path": tarball_path, "reason": "pinned_digest_mismatch", "fields": mismatch, "status": "FAIL"}
            )
        else:
            findings.append(
                {"version": version, "path": tarball_path, "reason": "digest_recomputed_from_bytes", "status": "PASS"}
            )
    if not parsed:
        digest = _digest_row("EVIDENCE_MISSING", reason="no_recomputable_pinned_declarations")
    else:
        digest = _digest_row_from_findings(findings)
    return _finish_validated(
        [static, digest],
        ["static_scan", "digest_verification"],
        registration_files=[path.name for path in files],
        mechanical_half=True,
    )


def check_depend_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """从两版真实 Registry 发布字节派生 Audit 消费侧兼容结论。"""
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    registration_files: list[Path] = []
    document_violations = []
    try:
        fact_check = _doc(ctx, "compatibility-fact-check")
    except ExecutorEvidenceError as exc:
        fact_check = None
        document_violations.append(
            {"document": "compatibility-fact-check", "error": str(exc)}
        )
    try:
        adjudication = _doc(ctx, "adjudication-record")
    except ExecutorEvidenceError as exc:
        adjudication = None
        document_violations.append(
            {"document": "adjudication-record", "error": str(exc)}
        )
    changed = _scope_flag(ctx, "adapter_registration_changed")
    if document_violations:
        return _finish_validated(
            [
                _digest_row(
                    "FAIL",
                    reason="governance_document_invalid",
                    violations=document_violations,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    if not changed and fact_check is None and adjudication is None:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_registration_change_or_adjudication")],
            ["digest_verification"],
            mechanical_half=True,
        )
    if fact_check is None:
        return _finish_validated(
            [_digest_row("EVIDENCE_MISSING", reason="compatibility_fact_check_missing")],
            ["digest_verification"],
            mechanical_half=True,
        )
    findings: list[dict[str, Any]] = []

    def add(status: str, reason: str, **details: Any) -> None:
        findings.append({"status": status, "reason": reason, **details})

    semver = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
    from_version = fact_check.get("from_version")
    to_version = fact_check.get("to_version")
    classification = fact_check.get("classification")
    version_parts: dict[str, tuple[int, int, int]] = {}
    for field, value in (("from_version", from_version), ("to_version", to_version)):
        match = semver.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            add("FAIL", "fact_check_version_invalid", field=field, value=value)
        else:
            version_parts[field] = tuple(int(part) for part in match.groups())
    if len(version_parts) == 2 and version_parts["from_version"] >= version_parts["to_version"]:
        add("FAIL", "fact_check_version_order_invalid")
    classification_valid = isinstance(classification, str) and classification in {
        "compatible", "incompatible"
    }
    if not classification_valid:
        add("FAIL", "fact_check_classification_invalid", value=classification)

    entries_value = fact_check.get("entries")
    entries = entries_value if isinstance(entries_value, list) else []
    if not isinstance(entries_value, list):
        add("FAIL", "fact_check_entries_not_array")
    elif len(entries) != 2:
        add("FAIL", "fact_check_entry_count_invalid", count=len(entries))

    expected_versions = (
        [from_version, to_version]
        if len(version_parts) == 2
        and version_parts["from_version"] < version_parts["to_version"]
        else []
    )
    entries_by_version: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            add("FAIL", "fact_check_entry_not_object", index=index)
            continue
        version = entry.get("version")
        file = entry.get("file")
        declared_digest = entry.get("sha256")
        if not isinstance(version, str) or not version:
            add("FAIL", "fact_check_entry_version_invalid", index=index)
            continue
        if version in entries_by_version:
            add("FAIL", "fact_check_entry_version_duplicate", version=version)
        else:
            entries_by_version[version] = entry
        expected_file = f"spec/external-adapters/agent-method-registry-{version}.json"
        if file != expected_file:
            add("FAIL", "fact_check_entry_file_mismatch", version=version, file=file)
        if not is_hex64(declared_digest):
            add("FAIL", "fact_check_entry_sha256_invalid", version=version)
    if expected_versions and set(entries_by_version) != set(expected_versions):
        add(
            "FAIL",
            "fact_check_version_set_mismatch",
            expected=sorted(expected_versions),
            observed=sorted(entries_by_version),
        )

    schema_names = {
        "implementation.schema.json",
        "inventory.schema.json",
        "binding.schema.json",
        "projection.schema.json",
        "method-query.schema.json",
        "run-lock.schema.json",
    }
    expected_api = [
        "validateCatalog",
        "validateProjectOverlay",
        "buildEffectiveIndex",
        "queryEffectiveIndex",
        "resolveEntry",
        "verifyProvider",
        "diagnoseRegistry",
    ]
    expected_cli = ["validate", "index", "query", "resolve"]
    surfaces: dict[str, dict[str, Any]] = {}
    for version in expected_versions:
        entry = entries_by_version.get(version)
        if entry is None:
            continue
        relative = f"spec/external-adapters/agent-method-registry-{version}.json"
        adapter_path = target_root / relative
        cursor = target_root
        symlink_in_chain = cursor.is_symlink()
        for part in Path(relative).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                symlink_in_chain = True
                break
        if symlink_in_chain:
            add("FAIL", "adapter_path_symlink_forbidden", version=version, path=relative)
            continue
        try:
            target_resolved = target_root.resolve(strict=True)
            adapter_resolved = adapter_path.resolve(strict=True)
            adapter_resolved.relative_to(target_resolved)
        except FileNotFoundError:
            add("EM", "adapter_byte_evidence_missing", version=version, path=relative)
            continue
        except (OSError, ValueError):
            add("FAIL", "adapter_path_outside_target", version=version, path=relative)
            continue
        if not adapter_resolved.is_file():
            add("EM", "adapter_byte_evidence_missing", version=version, path=relative)
            continue
        registration_files.append(adapter_path)
        try:
            adapter_bytes = adapter_path.read_bytes()
            adapter = json.loads(adapter_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            add("FAIL", "adapter_document_unparseable", version=version)
            continue
        if _sha256_bytes(adapter_bytes) != entry.get("sha256"):
            add("FAIL", "fact_check_adapter_digest_mismatch", version=version)
        if not isinstance(adapter, dict):
            add("FAIL", "adapter_document_not_object", version=version)
            continue

        if adapter.get("package") != "agent-method-registry":
            add("FAIL", "adapter_package_mismatch", version=version)
        if adapter.get("version") != version:
            add("FAIL", "adapter_version_mismatch", version=version)
        api = adapter.get("stableRuntimeApiWhitelist")
        cli = adapter.get("cliWhitelist")
        v2_surface = adapter.get("v2Surface")
        schemas = v2_surface.get("v2SchemaDigests") if isinstance(v2_surface, dict) else None
        api_valid = (
            isinstance(api, list)
            and bool(api)
            and all(isinstance(item, str) and bool(item) for item in api)
            and len(api) == len(set(api))
        )
        cli_valid = (
            isinstance(cli, list)
            and bool(cli)
            and all(isinstance(item, str) and bool(item) for item in cli)
            and len(cli) == len(set(cli))
        )
        schemas_valid = (
            isinstance(schemas, dict)
            and set(schemas) == schema_names
            and all(isinstance(name, str) and is_hex64(digest) for name, digest in schemas.items())
        )
        if not api_valid:
            add("FAIL", "adapter_runtime_api_invalid", version=version)
        elif api != expected_api:
            add("FAIL", "adapter_runtime_api_authority_mismatch", version=version)
        if not cli_valid:
            add("FAIL", "adapter_cli_invalid", version=version)
        elif cli != expected_cli:
            add("FAIL", "adapter_cli_authority_mismatch", version=version)
        if not schemas_valid:
            add("FAIL", "adapter_schema_digests_invalid", version=version)

        tarball_path = adapter.get("tarballPath")
        declared_sha256 = adapter.get("packageTarballSha256")
        integrity = adapter.get("npmIntegrity")
        if not isinstance(tarball_path, str) or not tarball_path:
            add("FAIL", "adapter_tarball_path_invalid", version=version)
            continue
        path_parts = Path(tarball_path).parts
        if Path(tarball_path).is_absolute() or ".." in path_parts:
            add("FAIL", "tarball_path_outside_target", version=version, path=tarball_path)
            continue
        if not is_hex64(declared_sha256):
            add("FAIL", "adapter_tarball_sha256_invalid", version=version)
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            add("FAIL", "adapter_npm_integrity_invalid", version=version)

        try:
            observed = conformance_check._foundation(
                {"operation": "read-file-strict", "root": str(target_root), "path": tarball_path}
            )
        except OSError:
            add("FAIL", "foundation_read_file_strict_failed", version=version, path=tarball_path)
            continue
        except Exception as exc:
            try:
                envelope = json.loads(str(exc))
            except (TypeError, json.JSONDecodeError):
                envelope = None
            error = envelope.get("error") if isinstance(envelope, dict) and envelope.get("ok") is False else None
            details = error.get("details") if isinstance(error, dict) else None
            kind = details.get("kind") if isinstance(details, dict) else None
            if isinstance(error, dict) and error.get("code") == "SFC2004" and kind in {
                "missing-resource", "read-failed", "unsafe-state-entry"
            }:
                add("EM", "tarball_byte_evidence_missing", version=version, path=tarball_path, kind=kind)
            elif isinstance(error, dict) and error.get("code") == "SFC2004" and kind in {
                "path-traversal", "realpath-escape", "symlink-escape"
            }:
                add("FAIL", "tarball_path_outside_target", version=version, path=tarball_path, kind=kind)
            else:
                add("FAIL", "foundation_read_file_strict_failed", version=version, path=tarball_path)
            continue
        content = observed.get("content") if isinstance(observed, dict) else None
        data_values = content.get("data") if isinstance(content, dict) else None
        if (
            not isinstance(content, dict)
            or content.get("type") != "Buffer"
            or not isinstance(data_values, list)
            or any(type(item) is not int or item < 0 or item > 255 for item in data_values)
        ):
            add("FAIL", "foundation_read_file_strict_invalid_response", version=version)
            continue
        tarball_bytes = bytes(data_values)
        if is_hex64(declared_sha256) and _sha256_bytes(tarball_bytes) != declared_sha256:
            add("FAIL", "tarball_sha256_mismatch", version=version)
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            computed_integrity = "sha512-" + base64.b64encode(
                hashlib.sha512(tarball_bytes).digest()
            ).decode("ascii")
            if computed_integrity != integrity:
                add("FAIL", "tarball_npm_integrity_mismatch", version=version)

        io_module = __import__("io")
        tarfile_module = __import__("tarfile")
        try:
            with tarfile_module.open(fileobj=io_module.BytesIO(tarball_bytes), mode="r:gz") as archive:
                members = archive.getmembers()
                required = ["package/package.json"] + [
                    f"package/schemas/{name}" for name in sorted(schema_names)
                ]
                extracted: dict[str, bytes] = {}
                for member_name in required:
                    matches = [member for member in members if member.name == member_name]
                    if len(matches) != 1:
                        add("FAIL", "tarball_member_cardinality_invalid", version=version, member=member_name, count=len(matches))
                        continue
                    member = matches[0]
                    if not member.isfile() or member.issym() or member.islnk():
                        add("FAIL", "tarball_member_not_regular", version=version, member=member_name)
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        add("FAIL", "tarball_member_unreadable", version=version, member=member_name)
                        continue
                    extracted[member_name] = stream.read()
        except (tarfile_module.TarError, OSError, EOFError):
            add("FAIL", "tarball_archive_invalid", version=version)
            continue
        package_bytes = extracted.get("package/package.json")
        if package_bytes is None:
            continue
        try:
            package = json.loads(package_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            add("FAIL", "tarball_package_json_invalid", version=version)
            continue
        if not isinstance(package, dict) or package.get("name") != "agent-method-registry":
            add("FAIL", "tarball_package_name_mismatch", version=version)
        if not isinstance(package, dict) or package.get("version") != version:
            add("FAIL", "tarball_package_version_mismatch", version=version)
        actual_schemas = {}
        for name in schema_names:
            schema_bytes = extracted.get(f"package/schemas/{name}")
            if schema_bytes is None:
                continue
            digest = _sha256_bytes(schema_bytes)
            actual_schemas[name] = digest
            if isinstance(schemas, dict) and schemas.get(name) != digest:
                add("FAIL", "tarball_schema_digest_mismatch", version=version, schema=name)
        if api_valid and cli_valid and schemas_valid and len(actual_schemas) == len(schema_names):
            surfaces[version] = {
                "api": frozenset(api),
                "cli": frozenset(cli),
                "schemas": dict(schemas),
            }

    derived = None
    if len(expected_versions) == 2 and all(
        version in surfaces for version in expected_versions
    ):
        before = surfaces[from_version]
        after = surfaces[to_version]
        changed_surface = (
            version_parts["from_version"][0] != version_parts["to_version"][0]
            or before["api"] != after["api"]
            or before["cli"] != after["cli"]
            or before["schemas"] != after["schemas"]
        )
        derived = "incompatible" if changed_surface else "compatible"
        if classification_valid and classification != derived:
            add("FAIL", "compatibility_classification_mismatch", declared=classification, derived=derived)

    if classification == "incompatible":
        if adjudication is None:
            add("EM", "registry_readjudication_missing")
        else:
            expected_adjudication = {
                "from_version": from_version,
                "to_version": to_version,
                "decision": "incompatible",
                "domain": "REGISTRY",
                "rule_ref": "SFA-DEPEND-013",
                "registry_reopened": True,
            }
            for field, expected in expected_adjudication.items():
                if adjudication.get(field) != expected:
                    add("FAIL", "registry_readjudication_field_mismatch", field=field)
            ref = adjudication.get("adjudication_ref")
            if not isinstance(ref, str) or not ref:
                add("FAIL", "registry_readjudication_ref_missing")
    elif classification == "compatible" and adjudication is not None:
        if (
            adjudication.get("from_version") != from_version
            or adjudication.get("to_version") != to_version
            or adjudication.get("decision") != "compatible"
        ):
            add("FAIL", "compatible_adjudication_mismatch")

    if any(item["status"] == "FAIL" for item in findings):
        status = "FAIL"
        reason = "compatibility_fact_check_failed"
    elif any(item["status"] == "EM" for item in findings):
        status = "EVIDENCE_MISSING"
        reason = "compatibility_evidence_missing"
    else:
        status = "PASS"
        reason = "compatibility_derived_from_release_bytes"
    return _finish_validated(
        [_digest_row(status, reason=reason, derived=derived, findings=findings)],
        ["digest_verification"],
        registration_files=[str(path.relative_to(target_root)) for path in registration_files],
        mechanical_half=True,
    )


def check_foundation_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """以真实 Profile、具名 import 与 active exemption 核对三包覆盖。"""
    target_root = _observable_target_root(ctx)
    if target_root is None:
        return _finish_validated(
            [_static_row("EVIDENCE_MISSING", reason="target_not_observable")],
            ["static_scan"],
            mechanical_half=True,
        )

    failures: list[dict[str, Any]] = []
    mechanism_errors: list[dict[str, Any]] = []
    scope = _scope(ctx)
    raw_scope = ctx.get("scope")
    if raw_scope is not None and not isinstance(raw_scope, dict):
        failures.append({"reason": "scope_carrier_invalid"})
    adoption_evidence = scope.get("project_adoption_evidence")
    if adoption_evidence is not None and not isinstance(adoption_evidence, dict):
        failures.append({"reason": "project_adoption_evidence_carrier_invalid"})
    capability_need = (
        isinstance(adoption_evidence, dict)
        and adoption_evidence.get("capability_need") is True
    )

    try:
        imports = _foundation_001_import_specifiers(target_root)
    except (OSError, UnicodeError) as exc:
        imports = []
        mechanism_errors.append(
            {"reason": "target_source_observation_unavailable", "detail": type(exc).__name__}
        )
    imported_packages = {
        package
        for specifier in imports
        for package in _FOUNDATION_PACKAGE_NAMES
        if specifier == package or specifier.startswith(f"{package}/")
    }

    try:
        legacy_pin = _doc(ctx, "foundation-pin")
    except ExecutorEvidenceError as exc:
        legacy_pin = None
        failures.append({"reason": "legacy_foundation_pin_carrier_invalid", "code": exc.code})
    try:
        exemption_records = _exemption_records(ctx)
    except ExecutorEvidenceError as exc:
        exemption_records = []
        failures.append({"reason": "foundation_exemption_carrier_invalid", "code": exc.code})

    exempted_packages: set[str] = set()
    for index, record in enumerate(exemption_records):
        if not isinstance(record, dict):
            failures.append({"reason": "exemption_record_not_object", "index": index})
            continue
        if record.get("status") != "active":
            continue
        packages = record.get("exemptedPackages")
        if (
            not isinstance(packages, list)
            or not packages
            or any(package not in _FOUNDATION_PACKAGE_NAMES for package in packages)
            or len(packages) != len(set(packages))
        ):
            failures.append({"reason": "active_exemption_packages_invalid", "index": index})
            continue
        exempted_packages.update(packages)

    profile_path = target_root / "profile.json"
    profile_present = profile_path.exists() or profile_path.is_symlink()
    actual_profile: dict[str, Any] | None = None
    if profile_present:
        if profile_path.is_symlink() or not profile_path.is_file():
            failures.append({"reason": "project_profile_carrier_invalid"})
        else:
            try:
                profile_text = profile_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                mechanism_errors.append(
                    {"reason": "project_profile_read_unavailable", "detail": type(exc).__name__}
                )
            else:
                try:
                    parsed = json.loads(profile_text)
                except json.JSONDecodeError as exc:
                    failures.append(
                        {"reason": "project_profile_document_invalid", "detail": type(exc).__name__}
                    )
                else:
                    if isinstance(parsed, dict):
                        actual_profile = parsed
                    else:
                        failures.append({"reason": "project_profile_document_not_object"})

    projected_profile = scope.get("project_profile_document")
    if "project_profile_document" in scope and not isinstance(projected_profile, dict):
        failures.append({"reason": "project_profile_document_carrier_invalid"})
    elif isinstance(projected_profile, dict) and actual_profile is not None and projected_profile != actual_profile:
        failures.append({"reason": "project_profile_document_mismatch"})
    elif isinstance(projected_profile, dict) and actual_profile is None:
        mechanism_errors.append({"reason": "project_profile_bytes_missing"})

    adopted_packages: set[str] = set()
    foundation_profile = scope.get("foundation_profile")
    if "foundation_profile" in scope and not isinstance(foundation_profile, dict):
        failures.append({"reason": "foundation_profile_carrier_invalid"})
    elif actual_profile is not None:
        if not isinstance(foundation_profile, dict) or not foundation_profile:
            mechanism_errors.append({"reason": "foundation_profile_spi_result_missing"})
        else:
            code = foundation_profile.get("code")
            if code == "SPE0000" and foundation_profile.get("foundation_profile_complete") is True:
                adoption = actual_profile.get("adoption")
                pin = adoption.get("foundation_pin") if isinstance(adoption, dict) else None
                packages = pin.get("packages") if isinstance(pin, dict) else None
                if not isinstance(packages, dict):
                    failures.append({"reason": "verified_profile_packages_unavailable"})
                else:
                    adopted_packages.update(
                        package for package in packages if package in _FOUNDATION_PACKAGE_NAMES
                    )
            elif code == "SPE0000":
                failures.append({"reason": "foundation_profile_spi_success_incomplete"})
            elif code in _FOUNDATION_VERIFICATION_INFRA_CODES:
                mechanism_errors.append({"reason": "foundation_profile_spi_unavailable", "code": code})
            elif isinstance(code, str) and code:
                failures.append({"reason": "foundation_profile_spi_rejected", "code": code})
            else:
                mechanism_errors.append({"reason": "foundation_profile_spi_response_unjudgable"})
    elif isinstance(foundation_profile, dict) and foundation_profile:
        mechanism_errors.append({"reason": "foundation_profile_without_real_carrier"})

    observed = bool(
        imported_packages
        or profile_present
        or legacy_pin is not None
        or exemption_records
        or capability_need
        or "foundation_profile" in scope
        or "project_profile_document" in scope
        or mechanism_errors
    )
    if failures:
        return _finish_validated(
            [_static_row(
                "FAIL",
                reason="foundation_adoption_observation_invalid",
                violations=failures,
                mechanism_errors=mechanism_errors,
            )],
            ["static_scan"],
            mechanical_half=True,
        )
    if not observed:
        return _finish_validated(
            [_static_row("NOT_APPLICABLE", reason="no_foundation_adoption_observation")],
            ["static_scan"],
            mechanical_half=True,
        )

    if (
        capability_need
        and not imported_packages
        and not profile_present
        and legacy_pin is None
        and not exemption_records
    ):
        return _finish_validated(
            [_static_row(
                "EVIDENCE_MISSING",
                reason="capability_need_without_verifiable_carrier",
            )],
            ["static_scan"],
            mechanical_half=True,
        )

    covered = imported_packages | adopted_packages | exempted_packages
    uncovered = sorted(set(_FOUNDATION_PACKAGE_NAMES) - covered)
    if not uncovered and not mechanism_errors:
        return _finish_validated(
            [_static_row(
                "PASS",
                reason="foundation_packages_adopted_or_exempted",
                imported_packages=sorted(imported_packages),
                adopted_packages=sorted(adopted_packages),
                exempted_packages=sorted(exempted_packages),
            )],
            ["static_scan"],
            mechanical_half=True,
        )
    if mechanism_errors or (legacy_pin is not None and not imported_packages and not profile_present):
        return _finish_validated(
            [_static_row(
                "EVIDENCE_MISSING",
                reason="foundation_adoption_observation_incomplete",
                uncovered_packages=uncovered,
                mechanism_errors=mechanism_errors,
                legacy_foundation_pin=legacy_pin is not None,
            )],
            ["static_scan"],
            mechanical_half=True,
        )
    return _finish_validated(
        [_static_row(
            "FAIL",
            reason="foundation_package_coverage_incomplete",
            uncovered_packages=uncovered,
            imported_packages=sorted(imported_packages),
            adopted_packages=sorted(adopted_packages),
            exempted_packages=sorted(exempted_packages),
        )],
        ["static_scan"],
        mechanical_half=True,
    )


def check_foundation_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """以 Foundation Profile SPI 与独立消费分类共同判定采用身份。"""
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [
                _schema_row("NOT_APPLICABLE", reason="target_not_observable"),
                _digest_row("NOT_APPLICABLE", reason="target_not_observable"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    profile_path = target_root / "profile.json"
    profile = _project_profile_document(ctx, target_root)
    scoped_profile = _scope(ctx).get("project_profile_document")
    actual_profile: dict[str, Any] | None = None
    if profile_path.is_file() and not profile_path.is_symlink():
        try:
            parsed_profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            parsed_profile = None
        if isinstance(parsed_profile, dict):
            actual_profile = parsed_profile
            profile = parsed_profile
    profile_document_mismatch = (
        isinstance(scoped_profile, dict)
        and isinstance(actual_profile, dict)
        and scoped_profile != actual_profile
    )
    legacy = _doc(ctx, "foundation-pin")
    classification_paths = [
        target_root / relative for relative in _FOUNDATION_CLASSIFICATION_CARRIERS
    ]
    classification_paths = [path for path in classification_paths if path.exists()]
    imports = _foundation_import_specifiers(target_root)
    consumption = bool(profile_path.exists() or legacy or classification_paths or imports)
    if not consumption:
        return _finish_validated(
            [
                _schema_row("NOT_APPLICABLE", reason="no_foundation_consumption"),
                _digest_row("NOT_APPLICABLE", reason="no_foundation_consumption"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    if not profile_path.is_file() or profile_path.is_symlink() or not isinstance(profile, dict):
        if imports and not legacy:
            return _finish_validated(
                [
                    _schema_row("FAIL", reason="implicit_consumption_without_adoption_declaration"),
                    _digest_row("EVIDENCE_MISSING", reason="adoption_identity_missing"),
                ],
                ["schema_validation", "digest_verification"],
                mechanical_half=True,
            )
        if isinstance(legacy, dict):
            old_pins = legacy.get("pins")
            old_shape_valid = (
                legacy.get("consumptionForm") in _CONSUMPTION_FORMS
                and isinstance(legacy.get("version"), str)
                and bool(legacy.get("version"))
                and is_hex64(legacy.get("digest"))
                and isinstance(old_pins, list)
                and bool(old_pins)
            )
            old_findings = _verify_pin_bytes(target_root, old_pins)
            return _finish_validated(
                [
                    _schema_row(
                        "EVIDENCE_MISSING" if old_shape_valid else "FAIL",
                        reason="legacy_foundation_pin_without_profile" if old_shape_valid else "adoption_declaration_shape_invalid",
                    ),
                    _digest_row_from_findings(old_findings, "pinned_content_evidence_unavailable"),
                ],
                ["schema_validation", "digest_verification"],
                mechanical_half=True,
            )
        return _finish_validated(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="project_profile_adoption_identity_missing",
                    legacy_foundation_pin=bool(legacy),
                ),
                _digest_row(
                    "EVIDENCE_MISSING", reason="project_profile_adoption_identity_missing"
                ),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )

    scope = _scope(ctx)
    spi = scope.get("foundation_profile")
    if not isinstance(spi, dict) or not spi:
        spi_status, spi_reason = "EVIDENCE_MISSING", "foundation_profile_spi_result_missing"
    else:
        spi_code = spi.get("code")
        if spi_code == "SPE0000" and spi.get("foundation_profile_complete") is True:
            spi_status, spi_reason = "PASS", "foundation_profile_spi_verified"
        elif spi_code == "SPE0000":
            spi_status, spi_reason = "FAIL", "foundation_profile_spi_success_incomplete"
        elif spi_code in _FOUNDATION_VERIFICATION_INFRA_CODES or (
            spi_code == "SPE1006"
            and isinstance(spi.get("details"), dict)
            and spi["details"].get("containmentKind") == "missing-resource"
        ):
            spi_status, spi_reason = "EVIDENCE_MISSING", "foundation_profile_spi_unavailable"
        else:
            spi_status, spi_reason = "FAIL", "foundation_profile_spi_rejected"

    adoption = profile.get("adoption")
    pin_declaration = adoption.get("foundation_pin") if isinstance(adoption, dict) else None
    packages = pin_declaration.get("packages") if isinstance(pin_declaration, dict) else None
    if not isinstance(packages, dict) or not packages:
        digest_row = _digest_row("EVIDENCE_MISSING", reason="foundation_profile_pins_missing")
        allowed_refs: set[str] = {"profile.json"}
    else:
        findings: list[dict[str, Any]] = []
        allowed_refs = {"profile.json"}
        for name, pin in sorted(packages.items()):
            if not isinstance(pin, dict) or not isinstance(pin.get("path"), str):
                findings.append({"package": name, "status": "FAIL", "reason": "foundation_pin_shape_invalid"})
                continue
            relative = pin["path"]
            allowed_refs.add(relative)
            try:
                path = target_root / relative
                path.resolve().relative_to(target_root.resolve())
            except (OSError, ValueError):
                findings.append({"package": name, "status": "FAIL", "reason": "foundation_pin_path_invalid", "path": relative})
                continue
            if not path.is_file() or path.is_symlink():
                findings.append({"package": name, "status": "EM", "reason": "foundation_pin_bytes_missing", "path": relative})
                continue
            declared = pin.get("sha256")
            computed = _sha256_bytes(path.read_bytes())
            if not is_hex64(declared) or computed != declared:
                findings.append({"package": name, "status": "FAIL", "reason": "foundation_pin_digest_mismatch", "path": relative, "computed": computed})
            else:
                findings.append({"package": name, "status": "PASS", "reason": "foundation_pin_digest_verified", "path": relative})
        digest_row = _digest_row_from_findings(findings, "foundation_profile_pins_unverifiable")

    project_digest = scope.get("project_profile_digest")
    actual_profile_digest = _sha256_bytes(profile_path.read_bytes())
    if not is_hex64(project_digest) and digest_row["status"] != "FAIL":
        digest_row = _digest_row(
            "EVIDENCE_MISSING", reason="project_profile_digest_missing", computed=actual_profile_digest
        )
    elif project_digest != actual_profile_digest:
        digest_row = _digest_row(
            "FAIL", reason="project_profile_digest_mismatch", computed=actual_profile_digest
        )

    schema_status = "FAIL" if profile_document_mismatch else spi_status
    schema_reason: Any = spi_reason
    if profile_document_mismatch:
        schema_reason = "project_profile_document_mismatch"
    classification: dict[str, Any] | None = None
    classification_carrier: str | None = None
    if len(classification_paths) > 1:
        schema_status, schema_reason = "FAIL", "classification_authority_carrier_ambiguous"
    elif classification_paths:
        classification_path = classification_paths[0]
        classification_carrier = classification_path.relative_to(target_root).as_posix()
        if classification_path.is_symlink():
            if schema_status != "FAIL":
                schema_status, schema_reason = "EVIDENCE_MISSING", "classification_carrier_is_symlink"
        else:
            try:
                value = json.loads(classification_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                value = None
            if isinstance(value, dict):
                classification = value
            elif schema_status != "FAIL":
                schema_status, schema_reason = "EVIDENCE_MISSING", "classification_document_unreadable"
        if classification is not None:
            try:
                host = conformance_check.foundation_host_for(__file__)
                response = host._foundation({
                    "operation": "validate-by-schema-id",
                    "schemaId": _FOUNDATION_CLASSIFICATION_SCHEMA_ID,
                    "document": classification,
                })
            except Exception as exc:
                response = None
                if schema_status != "FAIL":
                    schema_status, schema_reason = "EVIDENCE_MISSING", f"classification_schema_mechanism_unavailable:{type(exc).__name__}"
            if response is None:
                if schema_status != "FAIL":
                    schema_status, schema_reason = "EVIDENCE_MISSING", "classification_schema_response_unjudgable"
            elif response is not None:
                if not isinstance(response, dict) or not isinstance(response.get("valid"), bool):
                    if schema_status != "FAIL":
                        schema_status, schema_reason = "EVIDENCE_MISSING", "classification_schema_response_unjudgable"
                elif response["valid"] is False:
                    schema_status, schema_reason = "FAIL", "classification_schema_rejected"
                elif response["valid"] is True and schema_status == "PASS":
                    schema_status, schema_reason = "PASS", "classification_schema_validated"
            refs = classification.get("evidenceRefs") if isinstance(classification, dict) else None
            if (
                not isinstance(refs, list)
                or not refs
                or not all(isinstance(reference, str) for reference in refs)
                or len(refs) != len(set(refs))
            ):
                schema_status, schema_reason = "FAIL", "classification_evidence_refs_invalid"
            else:
                for reference in refs:
                    if not isinstance(reference, str):
                        schema_status, schema_reason = "FAIL", "classification_evidence_ref_unbound"
                        continue
                    if reference not in allowed_refs:
                        reference_path = target_root / reference
                        if reference_path.exists():
                            schema_status, schema_reason = "FAIL", "classification_evidence_ref_unbound"
                        elif schema_status != "FAIL":
                            schema_status, schema_reason = "EVIDENCE_MISSING", "classification_evidence_ref_missing"
                        continue
                    reference_path = target_root / reference
                    if not reference_path.is_file() or reference_path.is_symlink():
                        if schema_status != "FAIL":
                            schema_status, schema_reason = "EVIDENCE_MISSING", "classification_evidence_ref_missing"
                        continue
    else:
        if schema_status != "FAIL":
            schema_status, schema_reason = "EVIDENCE_MISSING", "classification_missing"

    # 旧 foundation-pin 载体已经不承载 Foundation 身份；即使字节存在，也不准冒充通过。
    if (
        legacy
        and not profile.get("adoption")
        and schema_status != "FAIL"
        and digest_row["status"] != "FAIL"
    ):
        return _finish_validated(
            [
                _schema_row("EVIDENCE_MISSING", reason="legacy_foundation_pin_without_profile"),
                _digest_row("EVIDENCE_MISSING", reason="legacy_foundation_pin_without_profile"),
            ],
            ["schema_validation", "digest_verification"], mechanical_half=True
        )
    return _finish_validated(
        [_schema_row(schema_status, reason=schema_reason, carrier=classification_carrier, spi_code=spi.get("code") if isinstance(spi, dict) else None), digest_row],
        ["schema_validation", "digest_verification"],
        classification_carrier=classification_carrier,
        mechanical_half=True,
    )


def check_foundation_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """零消费豁免登记与机器审计（schema_validation）。

    - 触发：foundation 三包之一部或全部零消费（采用声明未钉扎且源码无具名
      import 的包存在缺口）；
    - PASS：缺口包全部被豁免记录覆盖，记录经权威
      spec/contracts/foundation-adoption-exemption.schema.json 机器校验通过，
      边界证据引用可解析；
    - FAIL：零消费缺口无豁免记录（未登记豁免的零消费视为违反 FADO-001）、
      记录形状非法（含证据引用不可解析）；
    - NOT_APPLICABLE：三包全部消费（无零消费缺口）；纯文档技能族无义务。
    不发明任何字段/ID 规则；exemptionId/schemaVersion 等约束以权威 schema 为准。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["schema_validation"],
            mechanical_half=True,
        )
    target_root = Path(target)
    source_files = _target_source_files(target_root)
    adoption = _doc(ctx, "foundation-pin")
    pinned: set[str] = set()
    if adoption is not None:
        pins = adoption.get("pins")
        if isinstance(pins, list):
            pinned = {
                pin.get("package")
                for pin in pins
                if isinstance(pin, dict) and isinstance(pin.get("package"), str)
            }
    scope = _scope(ctx)
    profile = _project_profile_document(ctx, target_root)
    profile_result = scope.get("foundation_profile")
    profile_digest = scope.get("project_profile_digest")
    profile_path = target_root / "profile.json"
    actual_profile: dict[str, Any] | None = None
    if profile_path.is_file() and not profile_path.is_symlink():
        try:
            parsed_profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            parsed_profile = None
        if isinstance(parsed_profile, dict):
            actual_profile = parsed_profile
    profile_document_matches = (
        isinstance(profile, dict)
        and isinstance(actual_profile, dict)
        and profile == actual_profile
    )
    actual_profile_digest = (
        _sha256_bytes(profile_path.read_bytes())
        if profile_path.is_file() and not profile_path.is_symlink()
        else None
    )
    profile_packages: set[str] = set()
    if (
        isinstance(profile, dict)
        and profile_document_matches
        and isinstance(profile_result, dict)
        and profile_result.get("code") == "SPE0000"
        and profile_result.get("foundation_profile_complete") is True
        and is_hex64(profile_digest)
        and profile_digest == actual_profile_digest
    ):
        adoption = profile.get("adoption")
        foundation_pin = adoption.get("foundation_pin") if isinstance(adoption, dict) else None
        packages = foundation_pin.get("packages") if isinstance(foundation_pin, dict) else None
        if isinstance(packages, dict):
            profile_packages = {name for name in packages if isinstance(name, str)}
    consumed = set(pinned) | profile_packages | set(_foundation_import_specifiers(target_root))
    if not consumed and not source_files and adoption is None and not _scope_flag(
        ctx, "capability_need"
    ):
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="no_engineering_project_foundation_obligation")],
            ["schema_validation"],
            mechanical_half=True,
        )
    gap = [package for package in _FOUNDATION_PACKAGE_NAMES if package not in consumed]
    if not gap:
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="all_foundation_packages_consumed")],
            ["schema_validation"],
            mechanical_half=True,
        )
    records = _exemption_records(ctx)
    if not records:
        return _finish_validated(
            [_schema_row("FAIL", reason="zero_consumption_without_exemption", gap=gap)],
            ["schema_validation"],
            mechanical_half=True,
        )
    violations = []
    schema_unavailable = False
    schema_id = "https://contracts.skill-family.example/skill-family-audit/candidate/v2/foundation-adoption-exemption.json"
    try:
        host = conformance_check.foundation_host_for(__file__)
    except Exception as exc:
        host = None
        schema_unavailable = True
        schema_reason = f"foundation_schema_mechanism_unavailable:{type(exc).__name__}"
    covered: set[str] = set()
    for index, record in enumerate(records):
        if host is None:
            # 未能启动公共校验机制时，不能把未经校验的记录当作覆盖依据。
            continue
        try:
            response = host._foundation(
                {
                    "operation": "validate-by-schema-id",
                    "schemaId": schema_id,
                    "document": record,
                }
            )
        except Exception as exc:
            response = None
            schema_unavailable = True
            schema_reason = f"foundation_schema_mechanism_unavailable:{type(exc).__name__}"
        if not isinstance(response, dict) or not isinstance(response.get("valid"), bool):
            # 未知公共返回不得参与后续集合运算，也不能覆盖既有缺证。
            schema_unavailable = True
            schema_reason = "foundation_schema_response_unjudgable"
            continue
        if response["valid"] is False:
            violations.append(
                {
                    "index": index,
                    "reason": "exemption_schema_rejected",
                    "errors": response.get("errors"),
                }
            )
            continue
        # 只有当前 active 记录可覆盖采用缺口；其他状态仍可被审计但不能
        # 充当现行豁免依据。
        if record.get("status") == "active":
            covered.update(record.get("exemptedPackages") or [])
        for ref in _evidence_refs(record):
            if not _reference_resolves(target_root, ref):
                violations.append(
                    {
                        "index": index,
                        "reason": "boundary_evidence_reference_unresolvable",
                        "reference": ref,
                    }
                )
    if not schema_unavailable:
        uncovered = [package for package in gap if package not in covered]
        if uncovered:
            violations.append({"reason": "exemption_coverage_incomplete", "uncovered": uncovered})
    if violations:
        return _finish_validated(
            [_schema_row("FAIL", reason="exemption_machine_audit_failed", violations=violations)],
            ["schema_validation"],
            mechanical_half=True,
        )
    if schema_unavailable:
        return _finish_validated(
            [_schema_row("EVIDENCE_MISSING", reason=schema_reason)],
            ["schema_validation"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _schema_row(
                "PASS",
                reason="exemption_machine_audit_passed",
                records=len(records),
                covered=sorted(covered),
            )
        ],
        ["schema_validation"],
        mechanical_half=True,
    )


def check_foundation_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """用 Foundation 公共 Schema 和 strict-read 核对豁免载体闭合。"""
    target_root = _observable_target_root(ctx)
    if target_root is None:
        return _finish_validated(
            [_schema_row("EVIDENCE_MISSING", reason="target_not_observable")],
            ["schema_validation"],
            mechanical_half=True,
        )
    try:
        records = _exemption_records(ctx)
    except UnicodeError as exc:
        return _finish_validated(
            [_schema_row(
                "EVIDENCE_MISSING",
                reason="exemption_carrier_read_unavailable",
                detail=type(exc).__name__,
            )],
            ["schema_validation"],
            mechanical_half=True,
        )
    except ExecutorEvidenceError as exc:
        if _foundation_read_unavailable(exc):
            return _finish_validated(
                [_schema_row(
                    "EVIDENCE_MISSING",
                    reason="exemption_carrier_read_unavailable",
                    detail=type(exc.__cause__).__name__,
                )],
                ["schema_validation"],
                mechanical_half=True,
            )
        return _finish_validated(
            [_schema_row(
                "FAIL",
                reason="exemption_carrier_invalid",
                violations=[{"reason": "exemption_carrier_invalid", "code": exc.code}],
            )],
            ["schema_validation"],
            mechanical_half=True,
        )
    if not records:
        return _finish_validated(
            [_schema_row("NOT_APPLICABLE", reason="no_exemption_records")],
            ["schema_validation"],
            mechanical_half=True,
        )
    violations: list[dict[str, Any]] = []
    mechanism_errors: list[dict[str, Any]] = []
    schema_id = (
        "https://contracts.skill-family.example/skill-family-audit/candidate/v2/"
        "foundation-adoption-exemption.json"
    )
    try:
        host = conformance_check.foundation_host_for(__file__)
    except Exception as exc:
        host = None
        mechanism_errors.append(
            {"reason": "foundation_mechanism_unavailable", "detail": type(exc).__name__}
        )

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            violations.append({"index": index, "reason": "record_not_object"})
            continue

        if host is not None:
            try:
                response = host._foundation({
                    "operation": "validate-by-schema-id",
                    "schemaId": schema_id,
                    "document": record,
                })
            except Exception as exc:
                mechanism_errors.append({
                    "index": index,
                    "reason": "foundation_schema_mechanism_unavailable",
                    "detail": type(exc).__name__,
                })
            else:
                if not isinstance(response, dict) or not isinstance(response.get("valid"), bool):
                    mechanism_errors.append({
                        "index": index,
                        "reason": "foundation_schema_response_unjudgable",
                    })
                elif response["valid"] is False:
                    violations.append({
                        "index": index,
                        "reason": "foundation_exemption_schema_rejected",
                        "errors": response.get("errors"),
                    })

        boundary = record.get("boundaryEvidence")
        for ref in _evidence_refs(record):
            if ref.startswith(("http://", "https://")):
                match = re.fullmatch(r"https?://[^\s/]+(?:/[^\s]*)?", ref)
                if match is None:
                    violations.append({
                        "index": index,
                        "reason": "boundary_evidence_url_invalid",
                        "reference": ref,
                    })
                continue
            if host is None:
                continue
            try:
                observed = host._foundation({
                    "operation": "read-file-strict",
                    "root": str(target_root),
                    "path": ref,
                })
            except Exception as exc:
                code, kind = _foundation_error_details(exc)
                if code == "SFC2004":
                    violations.append({
                        "index": index,
                        "reason": "boundary_evidence_reference_unresolvable",
                        "reference": ref,
                        "kind": kind,
                    })
                else:
                    mechanism_errors.append({
                        "index": index,
                        "reason": "foundation_strict_read_unavailable",
                        "reference": ref,
                        "detail": type(exc).__name__,
                    })
                continue
            content = observed.get("content") if isinstance(observed, dict) else None
            data = content.get("data") if isinstance(content, dict) else None
            if (
                not isinstance(observed, dict)
                or not is_hex64(observed.get("sha256"))
                or not isinstance(content, dict)
                or content.get("type") != "Buffer"
                or not isinstance(data, list)
                or any(type(item) is not int or item < 0 or item > 255 for item in data)
            ):
                mechanism_errors.append({
                    "index": index,
                    "reason": "foundation_strict_read_response_unjudgable",
                    "reference": ref,
                })

        if record.get("reasonCategory") == "temporary_migration_window":
            replacement = record.get("selfBuildReplacement")
            if not isinstance(replacement, dict) or not isinstance(
                replacement.get("description"), str
            ) or not replacement.get("description"):
                violations.append(
                    {
                        "index": index,
                        "reason": "migration_window_self_build_replacement_missing",
                    }
                )
            if not any(
                isinstance(item, dict) and item.get("kind") == "migration_plan"
                for item in boundary
                if isinstance(boundary, list)
            ):
                violations.append(
                    {"index": index, "reason": "migration_window_plan_evidence_missing"}
                )
    if violations:
        return _finish_validated(
            [_schema_row(
                "FAIL",
                reason="exemption_boundary_obligations_violated",
                violations=violations,
                mechanism_errors=mechanism_errors,
            )],
            ["schema_validation"],
            mechanical_half=True,
        )
    if mechanism_errors:
        return _finish_validated(
            [_schema_row(
                "EVIDENCE_MISSING",
                reason="foundation_exemption_mechanism_unavailable",
                mechanism_errors=mechanism_errors,
            )],
            ["schema_validation"],
            mechanical_half=True,
        )
    return _finish_validated(
        [_schema_row(
            "PASS",
            reason="exemption_boundary_obligations_satisfied",
            records=len(records),
        )],
        ["schema_validation"],
        mechanical_half=True,
    )


def check_foundation_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """采用声明与版本漂移政策联动（digest_verification）。

    - 触发：采用声明（foundation-pin）存在且发生钉扎更新事件（scope
      pin_update_event 或 pin-update-record 记录出现）；
    - EVIDENCE_MISSING：更新事件存在但无 pin-update-record 可对照漂移政策；
    - FAIL：钉扎版本与采用声明不一致、版本变化未触发政策记录（policy_triggered
      为假）、兼容判定用单坐标近似（compat_basis 非 three_coordinates）、
      钉扎内容摘要不一致；
    - NOT_APPLICABLE：未采用 foundation，或采用声明存在但无更新事件。
    本契约是政策联动义务，不重复钉扎纪律（020）/三坐标（021）/捆绑升级（023）/
    基线 pin（024）的具体检查。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    try:
        adoption = _doc(ctx, "foundation-pin")
        update_doc = _doc(ctx, "pin-update-record")
    except ExecutorEvidenceError as exc:
        return _finish_validated(
            [
                _digest_row(
                    "FAIL",
                    reason="governance_document_shape_invalid",
                    error_code=exc.code,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    if adoption is None:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_adoption_declaration")],
            ["digest_verification"],
            mechanical_half=True,
        )
    changed = _scope_flag(ctx, "pin_update_event")
    if not changed and update_doc is None:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_pin_update_event")],
            ["digest_verification"],
            mechanical_half=True,
        )
    if update_doc is None:
        return _finish_validated(
            [_digest_row("EVIDENCE_MISSING", reason="pin_update_fact_missing")],
            ["digest_verification"],
            mechanical_half=True,
        )
    pins = adoption.get("pins")
    if "pins" not in adoption or pins == []:
        return _finish_validated(
            [_digest_row("EVIDENCE_MISSING", reason="pin_evidence_missing")],
            ["digest_verification"],
            mechanical_half=True,
        )
    if not isinstance(pins, list):
        return _finish_validated(
            [_digest_row("FAIL", reason="pin_evidence_shape_invalid")],
            ["digest_verification"],
            mechanical_half=True,
        )
    safe_pins = []
    path_violations = []
    for index, pin in enumerate(pins):
        if isinstance(pin, dict):
            for field in ("package", "version"):
                value = pin.get(field)
                if not isinstance(value, str) or not value:
                    path_violations.append(
                        {
                            "index": index,
                            "field": field,
                            "reason": "pin_identity_field_invalid",
                        }
                    )
        path_value = pin.get("path") if isinstance(pin, dict) else None
        if not isinstance(path_value, str) or not path_value:
            safe_pins.append(pin)
            continue
        path = Path(path_value)
        try:
            candidate = target_root / path
            if path.is_absolute():
                raise ValueError("absolute path")
            candidate.resolve().relative_to(target_root.resolve())
        except (OSError, ValueError):
            path_violations.append(
                {"index": index, "path": path_value, "reason": "pin_path_outside_target"}
            )
            continue
        cursor = target_root
        path_has_symlink = False
        for part in path.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                path_has_symlink = True
                break
        if path_has_symlink:
            path_violations.append(
                {"index": index, "path": path_value, "reason": "pin_path_has_symlink"}
            )
            continue
        safe_pins.append(pin)
    findings = _verify_pin_bytes(target_root, safe_pins)
    violations = []
    current = update_doc.get("current_version")
    previous = update_doc.get("previous_version")
    declared_version = adoption.get("version")
    if not isinstance(current, str) or not current:
        violations.append({"reason": "current_version_missing"})
    if not isinstance(previous, str) or not previous:
        violations.append({"reason": "previous_version_missing"})
    if isinstance(current, str) and current and current != declared_version:
        violations.append(
            {
                "reason": "pin_version_inconsistent_with_declaration",
                "declared": declared_version,
                "current": current,
            }
        )
    if (
        isinstance(current, str)
        and isinstance(previous, str)
        and current
        and previous
        and previous != current
        and update_doc.get("policy_triggered") is not True
    ):
        violations.append(
            {"reason": "policy_trigger_not_recorded", "previous": previous, "current": current}
        )
    if update_doc.get("compat_basis") != "three_coordinates":
        violations.append(
            {"reason": "compatibility_basis_not_three_coordinates", "value": update_doc.get("compat_basis")}
        )
    violations.extend(path_violations)
    failed_findings = [finding for finding in findings if finding.get("status") == "FAIL"]
    missing_findings = [finding for finding in findings if finding.get("status") == "EM"]
    if violations or failed_findings:
        return _finish_validated(
            [
                _digest_row(
                    "FAIL",
                    reason="drift_policy_linkage_violated",
                    violations=violations,
                    findings=findings,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    if missing_findings:
        return _finish_validated(
            [
                _digest_row(
                    "EVIDENCE_MISSING",
                    reason="pinned_content_evidence_unavailable",
                    findings=missing_findings,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _digest_row(
                "PASS",
                reason="drift_policy_linkage_consistent",
                current_version=current,
                previous_version=previous,
                compat_basis=update_doc.get("compat_basis"),
            )
        ],
        ["digest_verification"],
        mechanical_half=True,
    )


def check_foundation_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """豁免登记追加式纪律（schema_validation + digest_verification）。

    - 触发：豁免记录存在且记录含状态或复审事实（status、statusEvents 或
      reviewEvents 出现）；
    - FAIL：状态事件链形状非法/连续性断裂（前后事件 to/from 不衔接）、当前
      status 与最后事件 to 不一致（原地改写）、事件缺 at/from/to/recordedBy
      任一；
    - EVIDENCE_MISSING：状态事实不可观察、公共 Schema 机制不可判，或当前
      豁免载体摘要未绑定；
    - NOT_APPLICABLE：无任何豁免记录或记录不含状态/复审事实；
    - digest_verification：豁免记录文件字节与当前冻结摘要绑定；匹配仅证明
      当前字节检查通过，不证明历史未被改写。
    不读取 git log、不用当前时钟（rejected_candidate_avoidance）。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [
                _schema_row("NOT_APPLICABLE", reason="target_not_observable"),
                _digest_row("NOT_APPLICABLE", reason="target_not_observable"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    records = _exemption_records(ctx)
    if not records:
        return _finish_validated(
            [
                _schema_row("NOT_APPLICABLE", reason="no_exemption_records"),
                _digest_row("NOT_APPLICABLE", reason="no_exemption_records"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    fact_records = [
        record
        for record in records
        if any(field in record for field in ("status", "statusEvents", "reviewEvents"))
    ]
    if not fact_records:
        return _finish_validated(
            [
                _schema_row("NOT_APPLICABLE", reason="no_status_or_review_facts"),
                _digest_row("NOT_APPLICABLE", reason="no_status_or_review_facts"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    schema_violations: list[dict[str, Any]] = []
    schema_mechanism_errors: list[dict[str, Any]] = []
    schema_unavailable = False
    schema_reason = "foundation_schema_mechanism_unavailable"
    schema_id = (
        "https://contracts.skill-family.example/skill-family-audit/candidate/v2/"
        "foundation-adoption-exemption.json"
    )
    try:
        host = conformance_check.foundation_host_for(__file__)
    except Exception as exc:
        host = None
        schema_unavailable = True
        schema_reason = f"foundation_schema_mechanism_unavailable:{type(exc).__name__}"
        schema_mechanism_errors.append(
            {
                "phase": "host_initialization",
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        )
    if host is not None:
        for index, record in enumerate(fact_records):
            try:
                response = host._foundation(
                    {
                        "operation": "validate-by-schema-id",
                        "schemaId": schema_id,
                        "document": record,
                    }
                )
            except Exception as exc:
                response = None
                schema_unavailable = True
                schema_reason = f"foundation_schema_mechanism_unavailable:{type(exc).__name__}"
                schema_mechanism_errors.append(
                    {
                        "index": index,
                        "phase": "schema_validation",
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    }
                )
            if not isinstance(response, dict) or not isinstance(
                response.get("valid"), bool
            ):
                schema_unavailable = True
                schema_reason = "foundation_schema_response_unjudgable"
                schema_mechanism_errors.append(
                    {
                        "index": index,
                        "phase": "schema_validation",
                        "reason": "foundation_schema_response_unjudgable",
                        "response_type": type(response).__name__,
                    }
                )
            elif response["valid"] is False:
                schema_violations.append(
                    {
                        "index": index,
                        "reason": "exemption_schema_rejected",
                        "errors": response.get("errors"),
                    }
                )
    violations = []
    chain_undecidable = False
    events_payload: list[Any] = []
    status_facts = [
        record
        for record in fact_records
        if "status" in record or "statusEvents" in record
    ]
    for index, record in enumerate(status_facts):
        events = record.get("statusEvents")
        status = record.get("status")
        if events is None:
            if "status" in record:
                chain_undecidable = True
            continue
        if not isinstance(events, list) or not events:
            violations.append({"index": index, "reason": "status_events_empty"})
            continue
        events_payload.append(events)
        previous_to = None
        for position, event in enumerate(events):
            if not isinstance(event, dict):
                violations.append({"index": index, "event": position, "reason": "status_event_not_object"})
                continue
            at = event.get("at")
            frm = event.get("from")
            to = event.get("to")
            recorded_by = event.get("recordedBy")
            if not isinstance(at, str) or not at:
                violations.append({"index": index, "event": position, "reason": "status_event_at_missing"})
            frm_is_known = isinstance(frm, str) and frm in _EXCEPTION_STATUS_VOCABULARY
            to_is_known = isinstance(to, str) and to in _EXCEPTION_STATUS_VOCABULARY
            if not frm_is_known or not to_is_known:
                violations.append(
                    {"index": index, "event": position, "reason": "status_event_vocabulary_invalid", "from": frm, "to": to}
                )
                continue
            if previous_to is not None and frm != previous_to:
                violations.append(
                    {
                        "index": index,
                        "event": position,
                        "reason": "status_event_chain_broken",
                        "expected_from": previous_to,
                        "actual_from": frm,
                    }
                )
            previous_to = to
            if not isinstance(recorded_by, str) or not recorded_by:
                violations.append({"index": index, "event": position, "reason": "status_event_recorded_by_missing"})
        if not isinstance(status, str) or status not in _EXCEPTION_STATUS_VOCABULARY:
            violations.append({"index": index, "reason": "status_vocabulary_invalid", "status": status})
        elif previous_to is not None and status != previous_to:
            violations.append(
                {
                    "index": index,
                    "reason": "terminal_status_inconsistent_with_last_event",
                    "status": status,
                    "last_event_to": previous_to,
                }
            )
    path = _exemption_carrier_path(ctx)
    record_sha256 = _sha256_bytes(path.read_bytes()) if path is not None else "unavailable"
    events_sha256 = _sha256_bytes(
        json.dumps(events_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    expected_digest = _scope(ctx).get("foundation_exemption_digest")
    if expected_digest is None:
        digest_status = "EVIDENCE_MISSING"
        digest_reason = "foundation_exemption_digest_missing"
    elif not is_hex64(expected_digest) or expected_digest != record_sha256:
        digest_status = "FAIL"
        digest_reason = "foundation_exemption_digest_mismatch"
    else:
        digest_status = "PASS"
        digest_reason = "foundation_exemption_digest_verified"
    digest = _digest_row(
        digest_status,
        reason=digest_reason,
        record_sha256=record_sha256,
        status_events_sha256=events_sha256,
    )
    if schema_violations:
        schema_status = "FAIL"
        schema_evidence = {
            "reason": "exemption_schema_rejected",
            "violations": schema_violations,
        }
    elif violations:
        schema_status = "FAIL"
        schema_evidence = {
            "reason": "status_event_chain_violated",
            "violations": violations,
        }
    elif schema_unavailable:
        schema_status = "EVIDENCE_MISSING"
        schema_evidence = {"reason": schema_reason}
    elif chain_undecidable:
        schema_status = "EVIDENCE_MISSING"
        schema_evidence = {"reason": "status_event_chain_undecidable"}
    else:
        schema_status = "PASS"
        schema_evidence = {
            "reason": "status_event_chain_consistent",
            "records": len(fact_records),
        }
    if schema_mechanism_errors:
        schema_evidence["mechanism_errors"] = schema_mechanism_errors
    if schema_violations and violations:
        schema_evidence["status_event_violations"] = violations
    if schema_status == "FAIL":
        return _finish_validated(
            [
                _schema_row(schema_status, **schema_evidence),
                digest,
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    if schema_status == "EVIDENCE_MISSING":
        return _finish_validated(
            [
                _schema_row(schema_status, **schema_evidence),
                digest,
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _schema_row(schema_status, **schema_evidence),
            digest,
        ],
        ["schema_validation", "digest_verification"],
        mechanical_half=True,
    )


def check_foundation_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """机械面只校验 candidate Profile SPI 结果与真实 profile 摘要绑定。"""
    target_root = _observable_target_root(ctx)
    if target_root is None:
        return _finish_validated(
            [
                _schema_row("EVIDENCE_MISSING", reason="target_not_observable"),
                _digest_row("EVIDENCE_MISSING", reason="target_not_observable"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )

    profile_path = target_root / "profile.json"
    if profile_path.is_symlink():
        return _finish_validated(
            [
                _schema_row("FAIL", reason="profile_carrier_is_symlink"),
                _digest_row("FAIL", reason="profile_carrier_is_symlink"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )
    if not profile_path.is_file():
        return _finish_validated(
            [
                _schema_row("EVIDENCE_MISSING", reason="profile_json_bytes_unavailable"),
                _digest_row("EVIDENCE_MISSING", reason="profile_json_bytes_unavailable"),
            ],
            ["schema_validation", "digest_verification"],
            mechanical_half=True,
        )

    try:
        profile_bytes = profile_path.read_bytes()
        profile = json.loads(profile_bytes.decode("utf-8"))
    except (OSError, UnicodeError) as exc:
        schema = _schema_row(
            "EVIDENCE_MISSING",
            reason="project_profile_read_unavailable",
            detail=type(exc).__name__,
        )
        profile = None
        profile_bytes = b""
    except json.JSONDecodeError as exc:
        schema = _schema_row(
            "FAIL", reason="project_profile_document_invalid", detail=type(exc).__name__
        )
        profile = None
        profile_bytes = b""
    else:
        schema = None
        if not isinstance(profile, dict):
            schema = _schema_row("FAIL", reason="project_profile_document_not_object")

    scope = _scope(ctx)
    raw_scope = ctx.get("scope")
    projected_document = scope.get("project_profile_document")
    carrier_failures: list[dict[str, Any]] = []
    if raw_scope is not None and not isinstance(raw_scope, dict):
        carrier_failures.append({"reason": "scope_carrier_invalid"})
    if "project_profile_document" in scope and not isinstance(projected_document, dict):
        carrier_failures.append({"reason": "project_profile_document_carrier_invalid"})
    elif isinstance(projected_document, dict) and isinstance(profile, dict) and projected_document != profile:
        carrier_failures.append({"reason": "project_profile_document_mismatch"})
    foundation_profile = scope.get("foundation_profile")
    if "foundation_profile" in scope and not isinstance(foundation_profile, dict):
        carrier_failures.append({"reason": "foundation_profile_carrier_invalid"})

    adoption = profile.get("adoption") if isinstance(profile, dict) else None
    profile_descriptor = (
        adoption.get("foundation_profile") if isinstance(adoption, dict) else None
    )
    stability = (
        profile_descriptor.get("stability") if isinstance(profile_descriptor, dict) else None
    )
    if carrier_failures:
        schema = _schema_row(
            "FAIL", reason="candidate_profile_carrier_invalid", violations=carrier_failures
        )
    elif schema is None and stability == "stable":
        return _finish_validated(
            [
                _schema_row("NOT_APPLICABLE", reason="stable_profile_not_candidate_only"),
                _digest_row("NOT_APPLICABLE", reason="stable_profile_not_candidate_only"),
            ],
            ["schema_validation", "digest_verification"],
            stability=stability,
            mechanical_half=True,
        )
    elif schema is None and stability != "candidate-only":
        schema = _schema_row(
            "FAIL", reason="foundation_profile_stability_invalid", stability=stability
        )
    elif schema is None:
        if not isinstance(foundation_profile, dict) or not foundation_profile:
            schema = _schema_row(
                "EVIDENCE_MISSING", reason="foundation_profile_spi_result_missing"
            )
        else:
            code = foundation_profile.get("code")
            if code == "SPE0000" and foundation_profile.get("foundation_profile_complete") is True:
                schema = _schema_row(
                    "PASS", reason="candidate_profile_spi_verified", spi_code=code
                )
            elif code == "SPE0000":
                schema = _schema_row(
                    "FAIL", reason="foundation_profile_spi_success_incomplete", spi_code=code
                )
            elif code in _FOUNDATION_VERIFICATION_INFRA_CODES:
                schema = _schema_row(
                    "EVIDENCE_MISSING", reason="foundation_profile_spi_unavailable", spi_code=code
                )
            elif isinstance(code, str) and code:
                schema = _schema_row(
                    "FAIL", reason="foundation_profile_spi_rejected", spi_code=code
                )
            else:
                schema = _schema_row(
                    "EVIDENCE_MISSING", reason="foundation_profile_spi_response_unjudgable"
                )

    expected_digest = scope.get("project_profile_digest")
    if "project_profile_digest" not in scope or expected_digest is None:
        digest = _digest_row("EVIDENCE_MISSING", reason="project_profile_digest_missing")
    elif not is_hex64(expected_digest):
        digest = _digest_row("FAIL", reason="project_profile_digest_invalid")
    else:
        try:
            host = conformance_check.foundation_host_for(__file__)
            observed = host._foundation({
                "operation": "read-file-strict",
                "root": str(target_root),
                "path": "profile.json",
                "expectedSha256": expected_digest,
            })
        except Exception as exc:
            code, kind = _foundation_error_details(exc)
            if code == "SFC2004" and kind in {
                "content-guard-rejected", "path-traversal", "realpath-escape", "symlink-escape"
            }:
                digest = _digest_row(
                    "FAIL", reason="project_profile_digest_or_path_mismatch", kind=kind
                )
            elif code == "SFC2004" and kind in {
                "missing-resource", "read-failed", "unsafe-state-entry"
            }:
                digest = _digest_row(
                    "EVIDENCE_MISSING", reason="project_profile_bytes_unavailable", kind=kind
                )
            else:
                digest = _digest_row(
                    "EVIDENCE_MISSING",
                    reason="foundation_strict_read_unavailable",
                    detail=type(exc).__name__,
                )
        else:
            content = observed.get("content") if isinstance(observed, dict) else None
            data = content.get("data") if isinstance(content, dict) else None
            if (
                not isinstance(observed, dict)
                or observed.get("sha256") != expected_digest
                or not isinstance(content, dict)
                or content.get("type") != "Buffer"
                or not isinstance(data, list)
                or any(type(item) is not int or item < 0 or item > 255 for item in data)
                or bytes(data) != profile_bytes
            ):
                digest = _digest_row(
                    "EVIDENCE_MISSING", reason="foundation_strict_read_response_unjudgable"
                )
            else:
                digest = _digest_row(
                    "PASS", reason="project_profile_digest_verified", profile_sha256=expected_digest
                )
    return _finish_validated(
        [schema, digest],
        ["schema_validation", "digest_verification"],
        stability=stability,
        mechanical_half=True,
    )


def check_foundation_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """foundation 消费精确钉扎与浮动收敛（static_scan + digest_verification）。

    - 触发：消费 foundation（采用声明或具名 import）且存在发布态事实
      （.release-skill 树/release-state 声明/scope release_state 投影）；
    - FAIL：发布态钉扎为浮动范围（^ / ~ / latest / .x 等）；
    - EVIDENCE_MISSING：消费存在但钉扎声明不可判定（既无精确钉扎也无浮动声明）；
    - NOT_APPLICABLE：未消费 foundation，或仅开发期浮动且未进入发布门禁。
    不重复 Profile pin 校验（属 FOUNDATION-008/010）；只扫描采用声明浮动标记
    并复核钉扎内容摘要。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="target_not_observable"),
                _digest_row("NOT_APPLICABLE", reason="target_not_observable"),
            ],
            ["static_scan", "digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    adoption = _doc(ctx, "foundation-pin")
    imports = _foundation_import_specifiers(target_root)
    consumption = (
        adoption is not None or bool(imports) or _scope_flag(ctx, "foundation_consumption")
    )
    release_state = (
        (target_root / ".release-skill").is_dir()
        or _doc(ctx, "release-state") is not None
        or _scope_flag(ctx, "release_state")
    )
    if not consumption:
        return _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="no_foundation_consumption"),
                _digest_row("NOT_APPLICABLE", reason="no_foundation_consumption"),
            ],
            ["static_scan", "digest_verification"],
            mechanical_half=True,
        )
    if not release_state:
        return _finish_validated(
            [
                _static_row("NOT_APPLICABLE", reason="no_release_state_fact"),
                _digest_row("NOT_APPLICABLE", reason="no_release_state_fact"),
            ],
            ["static_scan", "digest_verification"],
            mechanical_half=True,
        )
    if adoption is None:
        return _finish_validated(
            [
                _static_row("EVIDENCE_MISSING", reason="pin_declaration_undeterminable"),
                _digest_row("EVIDENCE_MISSING", reason="pin_declaration_undeterminable"),
            ],
            ["static_scan", "digest_verification"],
            mechanical_half=True,
        )
    floating = []
    adoption_version = adoption.get("version")
    if _is_floating_version(adoption_version):
        floating.append({"field": "version", "value": adoption_version})
    pins = adoption.get("pins")
    pin_shape_violations = []
    if isinstance(pins, list):
        for index, pin in enumerate(pins):
            if isinstance(pin, dict) and _is_floating_version(pin.get("version")):
                floating.append(
                    {"field": "pins", "package": pin.get("package"), "value": pin.get("version")}
                )
            if not isinstance(pin, dict):
                pin_shape_violations.append({"index": index, "reason": "pin_not_object"})
            else:
                pin_version = pin.get("version")
                if not isinstance(pin_version, str) or not pin_version:
                    pin_shape_violations.append({"index": index, "reason": "pin_version_missing"})
                elif not _is_floating_version(pin_version) and not re.fullmatch(
                    r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", pin_version
                ):
                    pin_shape_violations.append(
                        {"index": index, "reason": "pin_version_not_exact", "version": pin_version}
                    )
    shape_violations = []
    if not isinstance(adoption_version, str) or not adoption_version:
        shape_violations.append({"field": "version", "reason": "version_missing"})
    elif not floating and not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", adoption_version):
        shape_violations.append({"field": "version", "reason": "version_not_exact"})
    if not isinstance(pins, list) or not pins:
        shape_violations.append({"field": "pins", "reason": "pins_missing_or_empty"})
    shape_violations.extend(pin_shape_violations)
    static = (
        _static_row("FAIL", reason="floating_pin_in_release_state", floating=floating)
        if floating
        else _static_row("FAIL", reason="release_pin_declaration_shape_invalid", violations=shape_violations)
        if shape_violations
        else _static_row("PASS", reason="exact_pins_in_release_state")
    )
    findings = _verify_pin_bytes(target_root, pins) if isinstance(pins, list) else []
    digest = _digest_row_from_findings(findings)
    return _finish_validated(
        [static, digest],
        ["static_scan", "digest_verification"],
        release_state=True,
        mechanical_half=True,
    )


def check_foundation_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """三坐标兼容判定（digest_verification）。

    - 触发：audit 消费面坐标声明（contracts-consumption 或
      audit-surface-declaration）出现且发生坐标变化/兼容判定事件（scope
      coordinate_change 或 compatibility-conclusion 出现）；
    - EVIDENCE_MISSING：消费声明存在但三坐标（contractsVersion/
      auditSurfaceVersion/surfaceDigest）缺一；
    - FAIL：surfaceDigest 复核不一致（surfaceDigest 必须等于
      audit-surface-declaration.surfaceFile 指向内容字节的 sha256）、坐标齐备
      但结论无法追溯兼容规则（compatibility-conclusion 缺 rule_ref 或结论词
      不在词表）；
    - NOT_APPLICABLE：不消费 foundation 契约/表面（无三坐标声明）。
    与 FOUNDATION-015（E1 baseline pin 三坐标）不重复：本契约管消费面兼容判定。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    try:
        consumption = _doc(ctx, "contracts-consumption")
        surface = _doc(ctx, "audit-surface-declaration")
        conclusion_doc = _doc(ctx, "compatibility-conclusion")
    except ExecutorEvidenceError as exc:
        return _finish_validated(
            [
                _digest_row(
                    "FAIL",
                    reason="governance_document_shape_invalid",
                    error_code=exc.code,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    conclusion_scope = _scope(ctx).get("compatibility_conclusion")
    changed = _scope_flag(ctx, "coordinate_change")
    if consumption is None and surface is None:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_consumption_coordinates")],
            ["digest_verification"],
            mechanical_half=True,
        )
    if not changed and conclusion_doc is None and conclusion_scope is None:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_coordinate_change_or_adjudication")],
            ["digest_verification"],
            mechanical_half=True,
        )
    contracts_version = consumption.get("contractsVersion") if consumption is not None else None
    audit_surface_version = (
        consumption.get("auditSurfaceVersion") if consumption is not None else None
    )
    surface_digest = consumption.get("surfaceDigest") if consumption is not None else None
    coordinates = {
        "contractsVersion": contracts_version,
        "auditSurfaceVersion": audit_surface_version,
        "surfaceDigest": surface_digest,
    }
    missing = [name for name in coordinates if consumption is None or name not in consumption]
    if missing:
        return _finish_validated(
            [_digest_row("EVIDENCE_MISSING", reason="three_coordinates_incomplete", missing=missing)],
            ["digest_verification"],
            mechanical_half=True,
        )
    invalid = [
        name for name, value in coordinates.items()
        if not isinstance(value, str) or not value
    ]
    if invalid:
        return _finish_validated(
            [_digest_row("FAIL", reason="three_coordinates_shape_invalid", fields=invalid)],
            ["digest_verification"],
            mechanical_half=True,
        )
    # surfaceDigest 复核 = 对审计表面内容字节（surfaceFile 指向的真实文件）重算
    # sha256；声明文件自身字节含 surfaceDigest 字段，不能作为复核对象
    # （自引用固定点不可构造，PASS 不可达）。
    surface_file = surface.get("surfaceFile") if surface is not None else None
    declared_surface_digest = surface.get("surfaceDigest") if surface is not None else None
    computed = None
    path_invalid = not isinstance(surface_file, str) or not surface_file
    content_path = target_root
    if not path_invalid:
        relative = Path(surface_file)
        try:
            content_path = target_root / relative
            if relative.is_absolute():
                raise ValueError("absolute path")
            content_path.resolve().relative_to(target_root.resolve())
        except (OSError, ValueError):
            path_invalid = True
        if not path_invalid:
            cursor = target_root
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    path_invalid = True
                    break
    if not path_invalid and content_path.is_file() and not content_path.is_symlink():
        computed = _sha256_bytes(content_path.read_bytes())
    if (
        path_invalid
        or not isinstance(declared_surface_digest, str)
        or computed is None
        or surface_digest != declared_surface_digest
        or surface_digest != computed
    ):
        return _finish_validated(
            [
                _digest_row(
                    "FAIL",
                    reason="surface_digest_mismatch",
                    declared=surface_digest,
                    carrier_declared=declared_surface_digest,
                    surface_file=surface_file,
                    computed=computed,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    conclusion = conclusion_scope if conclusion_scope is not None else conclusion_doc
    if changed and conclusion is None:
        return _finish_validated(
            [_digest_row("FAIL", reason="compatibility_conclusion_missing")],
            ["digest_verification"],
            mechanical_half=True,
        )
    if conclusion is not None:
        if not isinstance(conclusion, dict):
            return _finish_validated(
                [_digest_row("FAIL", reason="compatibility_conclusion_shape_invalid")],
                ["digest_verification"],
                mechanical_half=True,
            )
        rule_ref = conclusion.get("rule_ref")
        verdict = conclusion.get("conclusion")
        if not isinstance(rule_ref, str) or not rule_ref:
            return _finish_validated(
                [_digest_row("FAIL", reason="compatibility_conclusion_untraceable")],
                ["digest_verification"],
                mechanical_half=True,
            )
        if verdict not in ("compatible", "incompatible"):
            return _finish_validated(
                [
                    _digest_row(
                        "FAIL",
                        reason="compatibility_conclusion_vocabulary_invalid",
                        verdict=verdict,
                    )
                ],
                ["digest_verification"],
                mechanical_half=True,
            )
    return _finish_validated(
        [
            _digest_row(
                "PASS",
                reason="three_coordinates_verified",
                coordinates=coordinates,
                rule_ref=conclusion.get("rule_ref") if isinstance(conclusion, dict) else None,
            )
        ],
        ["digest_verification"],
        mechanical_half=True,
    )


def check_foundation_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """捆绑升级纪律（digest_verification）。

    - 触发：foundation 升级或 audit 消费面变更事件（upgrade-batch 记录或
      scope upgrade_event 投影）；
    - EVIDENCE_MISSING：升级事件存在但无 upgrade-batch 同步更新记录；
    - FAIL：单边升级（reference 文件缺失/摘要链断裂）、升级批次记录形状非法
      （from_version/to_version/references 缺失）、废弃 adoption-lock 引用
      残留未清理；
    - NOT_APPLICABLE：无升级且无消费面变更事件。
    本契约管'同步升级'，不重复坐标判定（021）与追加式判定（024）。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    try:
        batch = _doc(ctx, "upgrade-batch")
    except ExecutorEvidenceError as exc:
        return _finish_validated(
            [
                _digest_row(
                    "FAIL",
                    reason="governance_document_shape_invalid",
                    error_code=exc.code,
                )
            ],
            ["digest_verification"],
            mechanical_half=True,
        )
    changed = _scope_flag(ctx, "upgrade_event")
    if batch is None and not changed:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_upgrade_event")],
            ["digest_verification"],
            mechanical_half=True,
        )
    if batch is None:
        return _finish_validated(
            [_digest_row("EVIDENCE_MISSING", reason="upgrade_batch_record_missing")],
            ["digest_verification"],
            mechanical_half=True,
        )
    violations = []
    from_version = batch.get("from_version")
    to_version = batch.get("to_version")
    if not isinstance(from_version, str) or not from_version:
        violations.append({"reason": "from_version_missing"})
    if not isinstance(to_version, str) or not to_version:
        violations.append({"reason": "to_version_missing"})
    references = batch.get("references")
    if not isinstance(references, list) or not references:
        violations.append({"reason": "upgrade_references_missing"})
    else:
        side_counts: dict[str, int] = {}
        for index, ref in enumerate(references):
            if not isinstance(ref, dict):
                violations.append({"index": index, "reason": "reference_not_object"})
                continue
            side = ref.get("side")
            file = ref.get("file")
            sha256 = ref.get("sha256")
            if not isinstance(side, str) or side not in _UPGRADE_SIDES:
                violations.append({"index": index, "reason": "side_unknown", "side": side})
            else:
                side_counts[side] = side_counts.get(side, 0) + 1
            if not isinstance(file, str) or not file:
                violations.append({"index": index, "reason": "reference_file_missing"})
                continue
            relative = Path(file)
            try:
                path = target_root / relative
                if relative.is_absolute():
                    raise ValueError("absolute path")
                path.resolve().relative_to(target_root.resolve())
            except (OSError, ValueError):
                violations.append(
                    {"index": index, "reason": "reference_path_outside_target", "side": side, "file": file}
                )
                continue
            cursor = target_root
            path_has_symlink = False
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    path_has_symlink = True
                    break
            if path_has_symlink:
                violations.append(
                    {"index": index, "reason": "reference_path_has_symlink", "side": side, "file": file}
                )
                continue
            if not path.is_file() or path.is_symlink():
                violations.append(
                    {"index": index, "reason": "reference_dangling", "side": side, "file": file}
                )
                continue
            computed = _sha256_bytes(path.read_bytes())
            if not is_hex64(sha256) or computed != sha256:
                violations.append(
                    {
                        "index": index,
                        "reason": "reference_digest_broken",
                        "side": side,
                        "file": file,
                        "declared": sha256,
                        "computed": computed,
                    }
                )
        missing_sides = [side for side in _UPGRADE_SIDES if side_counts.get(side, 0) == 0]
        duplicate_sides = [side for side in _UPGRADE_SIDES if side_counts.get(side, 0) > 1]
        if missing_sides:
            violations.append(
                {"reason": "required_upgrade_sides_incomplete", "missing": missing_sides}
            )
        if duplicate_sides:
            violations.append(
                {"reason": "required_upgrade_side_duplicate", "sides": duplicate_sides}
            )
    residual = _deprecated_adoption_lock_residual(target_root)
    if residual:
        violations.append({"reason": "deprecated_adoption_lock_reference_residual", "files": residual})
    if violations:
        return _finish_validated(
            [_digest_row("FAIL", reason="bundled_upgrade_discipline_violated", violations=violations)],
            ["digest_verification"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _digest_row(
                "PASS",
                reason="bundled_upgrade_synchronized",
                from_version=from_version,
                to_version=to_version,
                references=len(references),
            )
        ],
        ["digest_verification"],
        mechanical_half=True,
    )


def check_foundation_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """基线 pin 追加式管理（digest_verification）。

    - 触发：基线 pin 清单（baseline-pin-inventory 治理文档）存在且含 pin 条目；
    - EVIDENCE_MISSING：pin 文件字节不可判（文件缺失）或承接/升级引用不可判定；
    - FAIL：pin 文件摘要不一致、承接引用悬空或成环、无根 pin、升级裁决引用
      '最新版本'类非精确表述；
    - NOT_APPLICABLE：不维护基线 pin（无清单）。
    追加式判定以当前树 pin 集合与承接声明为准，不读取 git log 历史。
    """
    target = ctx.get("target")
    if not target or not Path(target).is_dir():
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="target_not_observable")],
            ["digest_verification"],
            mechanical_half=True,
        )
    target_root = Path(target)
    inventory = _doc(ctx, "baseline-pin-inventory")
    if inventory is None:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_baseline_pin_inventory")],
            ["digest_verification"],
            mechanical_half=True,
        )
    pins = inventory.get("pins")
    if not isinstance(pins, list) or not pins:
        return _finish_validated(
            [_digest_row("NOT_APPLICABLE", reason="no_baseline_pins")],
            ["digest_verification"],
            mechanical_half=True,
        )
    violations = []
    undecidable = []
    pin_ids: set[str] = set()
    pin_by_id: dict[str, dict[str, Any]] = {}
    file_owners: dict[str, str] = {}
    file_identity_owners: dict[tuple[int, int], str] = {}
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict):
            violations.append({"index": index, "reason": "pin_not_object"})
            continue
        pin_id = pin.get("id")
        file = pin.get("file")
        sha256 = pin.get("sha256")
        if not isinstance(pin_id, str) or not pin_id:
            violations.append({"index": index, "reason": "pin_id_missing"})
            continue
        if pin_id in pin_by_id:
            violations.append({"index": index, "id": pin_id, "reason": "pin_id_reused"})
        pin_ids.add(pin_id)
        if not isinstance(file, str) or not file:
            violations.append({"index": index, "reason": "pin_file_missing"})
            continue
        normalized_file = str((target_root / file).resolve(strict=False))
        previous_owner = file_owners.setdefault(normalized_file, pin_id)
        if previous_owner != pin_id:
            violations.append(
                {"index": index, "id": pin_id, "file": file, "reason": "pin_file_reused"}
            )
        pin_by_id[pin_id] = pin
        path = target_root / file
        if not path.is_file() or path.is_symlink():
            undecidable.append(
                {"index": index, "id": pin_id, "reason": "pin_bytes_unavailable", "file": file}
            )
            continue
        try:
            stat = path.stat()
            identity = (stat.st_dev, stat.st_ino)
        except OSError:
            undecidable.append(
                {"index": index, "id": pin_id, "reason": "pin_file_identity_unavailable", "file": file}
            )
            continue
        previous_identity_owner = file_identity_owners.setdefault(identity, pin_id)
        if previous_identity_owner != pin_id:
            violations.append(
                {
                    "index": index,
                    "id": pin_id,
                    "file": file,
                    "reason": "pin_actual_file_reused",
                    "previous_owner": previous_identity_owner,
                }
            )
        computed = _sha256_bytes(path.read_bytes())
        if not is_hex64(sha256) or computed != sha256:
            violations.append(
                {
                    "index": index,
                    "id": pin_id,
                    "reason": "pin_digest_mismatch",
                    "declared": sha256,
                    "computed": computed,
                }
            )
    roots = []
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict) or not isinstance(pin.get("id"), str):
            continue
        supersedes = pin.get("supersedes")
        if supersedes is None:
            roots.append(pin.get("id"))
            continue
        refs = supersedes if isinstance(supersedes, list) else [supersedes]
        for ref in refs:
            if not isinstance(ref, str) or ref not in pin_ids:
                violations.append(
                    {
                        "index": index,
                        "id": pin.get("id"),
                        "reason": "succession_reference_unresolvable",
                        "reference": ref,
                    }
                )
    if not roots:
        violations.append({"reason": "no_root_baseline_pin"})
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict):
            continue
        adjudication = pin.get("adjudication")
        if not isinstance(adjudication, dict) or not adjudication:
            undecidable.append(
                {"index": index, "id": pin.get("id"), "reason": "upgrade_reference_undecidable"}
            )
            continue
        reference = adjudication.get("reference")
        if not isinstance(reference, str) or not reference:
            violations.append({"index": index, "id": pin.get("id"), "reason": "upgrade_reference_missing"})
            continue
        if _is_floating_version(reference) or any(
            marker in reference for marker in ("最新", "latest", "current")
        ):
            violations.append(
                {"index": index, "id": pin.get("id"), "reason": "upgrade_reference_not_specific", "reference": reference}
            )
        elif "@" in reference:
            reference_id, reference_digest = reference.split("@", 1)
            referenced_pin = pin_by_id.get(reference_id)
            if referenced_pin is None:
                violations.append(
                    {"index": index, "id": pin.get("id"), "reason": "upgrade_reference_unresolvable", "reference": reference}
                )
            elif not is_hex64(reference_digest) or reference_digest != referenced_pin.get("sha256"):
                violations.append(
                    {"index": index, "id": pin.get("id"), "reason": "upgrade_reference_digest_mismatch", "reference": reference}
                )
        elif reference not in pin_ids:
            violations.append(
                {"index": index, "id": pin.get("id"), "reason": "upgrade_reference_unresolvable", "reference": reference}
            )
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict) or not isinstance(pin.get("id"), str):
            continue
        seen: list[str] = []
        current: dict[str, Any] | None = pin
        while current is not None:
            current_id = current.get("id")
            if current_id in seen:
                violations.append({"reason": "succession_cycle", "cycle": seen + [current_id]})
                break
            seen.append(current_id)
            supersedes = current.get("supersedes")
            refs = (
                supersedes
                if isinstance(supersedes, list)
                else [supersedes]
                if supersedes is not None
                else []
            )
            if not refs:
                break
            target_id = refs[0]
            current = next(
                (candidate for candidate in pins if isinstance(candidate, dict) and candidate.get("id") == target_id),
                None,
            )
    if violations:
        return _finish_validated(
            [_digest_row("FAIL", reason="baseline_pin_management_violated", violations=violations)],
            ["digest_verification"],
            mechanical_half=True,
        )
    if undecidable:
        return _finish_validated(
            [_digest_row("EVIDENCE_MISSING", reason="baseline_pin_facts_undecidable", undecidable=undecidable)],
            ["digest_verification"],
            mechanical_half=True,
        )
    return _finish_validated(
        [
            _digest_row(
                "PASS",
                reason="baseline_pin_current_facts_verified",
                pins=len(pins),
                root=roots[0],
            )
        ],
        ["digest_verification"],
        mechanical_half=True,
    )


# ---------------------------------------------------------------------------
# 登记
# ---------------------------------------------------------------------------

CHECKS = {
    "SFA-AUTHORITY-001": check_authority_001,
    "SFA-AUTHORITY-002": check_authority_002,
    "SFA-CHECKIMPL-001": check_checkimpl_001,
    "SFA-CHECKIMPL-002": check_checkimpl_002,
    "SFA-FINDING-001": check_finding_001,
    "SFA-FOUNDATION-008": check_foundation_008,
    "SFA-FOUNDATION-011": check_foundation_011,
    "SFA-FOUNDATION-012": check_foundation_012,
    "SFA-FOUNDATION-014": check_foundation_014,
    "SFA-FOUNDATION-015": check_foundation_015,
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
    # ---------------------------------------------------------------------------
    # P4-D1: 第二批机械规则（GOVERNANCE-001..003 / DEPEND-012..013 /
    # FOUNDATION-001..007 / 020 / 021 / 023 / 024）
    # ---------------------------------------------------------------------------
    "SFA-DEPEND-012": check_depend_012,
    "SFA-DEPEND-013": check_depend_013,
    "SFA-FOUNDATION-001": check_foundation_001,
    "SFA-FOUNDATION-002": check_foundation_002,
    "SFA-FOUNDATION-003": check_foundation_003,
    "SFA-FOUNDATION-004": check_foundation_004,
    "SFA-FOUNDATION-005": check_foundation_005,
    "SFA-FOUNDATION-006": check_foundation_006,
    "SFA-FOUNDATION-007": check_foundation_007,
    "SFA-FOUNDATION-020": check_foundation_020,
    "SFA-FOUNDATION-021": check_foundation_021,
    "SFA-FOUNDATION-023": check_foundation_023,
    "SFA-FOUNDATION-024": check_foundation_024,
    "SFA-GOVERNANCE-001": check_governance_001,
    "SFA-GOVERNANCE-002": check_governance_002,
    "SFA-GOVERNANCE-003": check_governance_003,
    # ---------------------------------------------------------------------------
    # FOUNDATION: FCR-010/011 缩小实现（2026-09-05 裁决注册；规则仍 RETAINED，
    # 生产路由保持 executor_gap，本注册只闭合实现缺失半区）
    # ---------------------------------------------------------------------------
    "SFA-FOUNDATION-017": check_foundation_017,
    "SFA-FOUNDATION-018": check_foundation_018,
}
