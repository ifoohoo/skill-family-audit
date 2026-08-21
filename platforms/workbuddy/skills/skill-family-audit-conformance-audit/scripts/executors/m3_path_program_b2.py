"""M3 执行族：路径/程序/运行状态/任务结果/错误契约（W2-B2 子批 M3，75 条）。

本模块覆盖 B2 批 execution_family=M3、violation_impact=error 的 75 条规则，
全部被终态裁决为机械方法 static_scan 且 behavior_verification_also_required=true；
执行器只覆盖机械半区（evidence 携 mechanical_half=true），行为义务继续挂账。

证据面（与 B1 M3 / B2 M1 一致，失败关闭）：
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``：
  error-contracts / output-lifecycle / extension-declarations /
  program-contracts / runtime-packages / runtime-state-contracts /
  task-result-contracts / write-closure / path-resolution；
- PATH-001 另对目标真实文件系统做只读静态扫描（已声明者）。

治理声明缺省语义沿用 B1：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 文档存在但形状非法 → ExecutorEvidenceError（失败关闭，绝不静默放行）；
- 文档存在且出现结构性违反 → FAIL。

执行器只消费目标事实，绝不修改目标；不消费模型语义结论。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import (
    ExecutorEvidenceError,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

# ---------------------------------------------------------------------------
# 词表
# ---------------------------------------------------------------------------

#: SFA-ERROR-001：稳定错误分类至少区分的十类。
REQUIRED_ERROR_CATEGORIES = {
    "input_invalid",
    "input_missing",
    "authorization_insufficient",
    "contract_incompatible",
    "dependency_unavailable",
    "budget_limited",
    "execution_exception",
    "output_invalid",
    "side_effect_uncertain",
    "internal_protocol_error",
}

#: SFA-ERROR-004：副作用状态四值枚举。
SIDE_EFFECT_STATUSES = {"none", "rolled_back", "committed", "unknown"}

#: SFA-ERROR-009：非成功输出生命周期词表。
OUTPUT_LIFECYCLE = {"transient", "partial", "unverified", "verified", "committed"}

#: SFA-ERROR-009：触发生命周期标记义务的非成功执行状态。
NON_SUCCESS_EXECUTION_STATUSES = {"waiting", "blocked", "failed", "cancelled"}

#: SFA-ERROR-008：不得降级为通过的关键失败类别。
CRITICAL_FAILURE_CATEGORIES = {
    "required_output",
    "security_check",
    "authorization",
    "path",
    "content_contract",
    "release_digest",
}

#: SFA-EXTENSION-001：三类扩展载体。
EXTENSION_CARRIERS = {"method_parameter", "domain_artifact", "runtime_extension"}

#: SFA-STATE-002：互斥运行状态词表。
RUN_STATES = {
    "completed",
    "waiting_user",
    "blocked",
    "failed",
    "cancelled",
    "not_applicable",
}

#: SFA-STATE-012：严格方法幂等特征词表。
IDEMPOTENCE_CHARACTERISTICS = {
    "readonly_repeatable",
    "once_per_key",
    "checkpoint_resumable",
    "not_auto_repeatable",
}

#: SFA-STATE-015：恢复可依据的权威证据来源。
RECOVERY_EVIDENCE_BASIS = {
    "original_task",
    "last_valid_checkpoint",
    "completed_result",
    "new_input",
    "unblock_evidence",
}

#: SFA-STATE-019：取消必须依序执行的六步。
CANCEL_SEQUENCE = (
    "stop_dispatching",
    "propagate_cancellation",
    "grace_stop",
    "terminate_process_tree",
    "cleanup_temporary_resources",
    "write_checkpoint_and_result",
)

#: SFA-STATE-022：触发二次授权的高风险原因。
HIGH_RISK_REASONS = {
    "plan_digest_changed",
    "authorization_expired",
    "overwrite",
    "delete",
    "external_write",
    "publish",
}

#: SFA-PROGRAM-011：触发运行时包提升的条件。
PROMOTION_CONDITIONS = {
    "cross_repo_reuse",
    "independent_dependency",
    "independent_upgrade_rollback",
    "public_cli_capability",
}

#: SFA-PATH-001：路径解析依据。
PATH_RESOLUTION_BASES = {"existing", "nearest_ancestor"}

#: SFA-TASK-019/020：结构化输出校验合同锁定字段。
STRUCTURED_OUTPUT_REVISION_FIELDS = (
    "schema_contract_revision",
    "example_contract_revision",
    "validator_contract_revision",
)

#: SFA-PROGRAM-010：版本化程序引用最小契约字段。
PROGRAM_REFERENCE_FIELDS = (
    "owning_skills",
    "program_id",
    "interface_version",
    "content_digest",
    "machine_entry",
    "inputs",
    "outputs",
    "dependencies",
    "compatibility_range",
    "platform_resolution",
)

#: SFA-TASK-014：规范化任务必需内容。
TASK_REQUIRED_FIELDS = (
    "run_identity",
    "method_and_process_identity",
    "technical_attempt_count",
    "workspace",
    "small_parameters",
    "input_resources",
    "upstream_results",
    "expected_outputs",
    "exclusive_output_dir",
    "write_set",
    "authorization",
    "acceptance",
    "budget",
    "required_extensions",
)

#: SFA-TASK-015：规范化结果必需内容。
RESULT_REQUIRED_FIELDS = (
    "execution_status",
    "summary",
    "actual_outputs",
    "domain_results",
    "evidence",
    "missing_inputs",
    "warnings",
    "blocked_reasons",
    "degradations",
    "executor",
    "resource_usage",
)


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _missing_fields(row: dict[str, Any], fields: tuple[str, ...]) -> list[str]:
    return [field for field in fields if field not in row]


def _target_root(ctx: dict[str, Any]) -> Path:
    """目标扫描根：D3 起采用声明是项目 Profile，扫描根即受检目标本身。"""
    return Path(str(ctx["target"]))


def _program_reference_violations(reference: Any, label: str) -> list[str]:
    """SFA-PROGRAM-010 最小契约逐项核对，返回缺失/非法字段列表。"""
    if not isinstance(reference, dict):
        return [f"{label}_not_object"]
    problems = []
    for field in PROGRAM_REFERENCE_FIELDS:
        value = reference.get(field)
        if field in ("owning_skills", "inputs", "outputs", "dependencies"):
            if not isinstance(value, list) or (field == "owning_skills" and not value):
                problems.append(field)
        elif field == "content_digest":
            if not is_hex64(value):
                problems.append(field)
        elif not _nonempty_str(value):
            problems.append(field)
    return problems


# ---------------------------------------------------------------------------
# ERROR：结构化错误契约（error-contracts / output-lifecycle）
# ---------------------------------------------------------------------------


def check_error_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """错误采用稳定分类。

    机械断言：已声明的错误分类 ``error-contracts.taxonomy_categories`` 必须
    使用稳定命名空间，且至少覆盖十类必需分类；未声明者无违反事实。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_taxonomy=0, mechanical_half=True)
    categories = document.get("taxonomy_categories")
    if categories is None:
        return result("FAIL", reason="error_taxonomy_missing", mechanical_half=True)
    if not isinstance(categories, list) or not all(
        isinstance(item, str) for item in categories
    ):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "error-contracts.taxonomy_categories 必须是字符串数组",
        )
    missing = sorted(REQUIRED_ERROR_CATEGORIES - set(categories))
    if missing:
        return result("FAIL", missing_stable_categories=missing, mechanical_half=True)
    return result("PASS", declared_taxonomy=len(categories), mechanical_half=True)


def check_error_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台异常只作为脱敏证据。

    机械断言：已声明的平台异常使用记录必须 sanitized=true 且
    used_as_stable_code!=true。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_usages=0, mechanical_half=True)
    usages = rows_of(document, "platform_exception_usages", "error-contracts")
    violations = [
        {"index": index, "exception_ref": row.get("exception_ref")}
        for index, row in enumerate(usages)
        if row.get("sanitized") is not True or row.get("used_as_stable_code") is True
    ]
    if violations:
        return result("FAIL", unsanitized_platform_exceptions=violations, mechanical_half=True)
    return result("PASS", declared_usages=len(usages), mechanical_half=True)


def check_error_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """错误记录最小契约。

    机械断言：每条已声明结构化错误必须记录错误码、类别、发生阶段、说明、
    受影响资源、证据、副作用状态、重试可能性和整改方式九项。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_error_records=0, mechanical_half=True)
    records = rows_of(document, "error_records", "error-contracts")
    required = (
        "code", "category", "stage", "description", "affected_resources",
        "evidence", "side_effect_status", "retryability", "remediation",
    )
    violations = []
    for index, row in enumerate(records):
        missing = _missing_fields(row, required)
        blanks = [
            field
            for field in ("code", "category", "stage", "description", "remediation")
            if not _nonempty_str(row.get(field))
        ]
        if not isinstance(row.get("affected_resources"), list):
            missing.append("affected_resources:list")
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            missing.append("evidence:nonempty_list")
        if missing or blanks:
            violations.append({"index": index, "code": row.get("code"),
                               "missing": missing, "blank": blanks})
    if violations:
        return result("FAIL", error_records_below_minimum_contract=violations, mechanical_half=True)
    return result("PASS", declared_error_records=len(records), mechanical_half=True)


def check_error_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """副作用状态使用四值枚举。

    机械断言：每条已声明错误的 side_effect_status 必须恰为
    none/rolled_back/committed/unknown 之一，不得留空或使用模糊文本。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_error_records=0, mechanical_half=True)
    records = rows_of(document, "error_records", "error-contracts")
    violations = [
        {"index": index, "code": row.get("code"),
         "side_effect_status": row.get("side_effect_status")}
        for index, row in enumerate(records)
        if row.get("side_effect_status") not in SIDE_EFFECT_STATUSES
    ]
    if violations:
        return result("FAIL", side_effect_status_not_enumerated=violations, mechanical_half=True)
    return result("PASS", declared_error_records=len(records), mechanical_half=True)


def check_error_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """结果包含结构化错误集合。

    机械断言：已声明者必须携带 ``result_contract.structured_errors_collection=true``。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", result_contract_declared=False, mechanical_half=True)
    contract = document.get("result_contract")
    if not isinstance(contract, dict):
        return result("FAIL", reason="result_contract_missing", mechanical_half=True)
    if contract.get("structured_errors_collection") is not True:
        return result("FAIL", reason="structured_errors_collection_missing", mechanical_half=True)
    return result("PASS", result_contract_declared=True, mechanical_half=True)


def check_error_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """主要受阻原因引用结构化错误。

    机械断言：已声明受阻原因必须携带非空 error_ref；存在已声明错误记录时，
    error_ref 必须命中其中一个错误码，不得是另写的不可追溯文本。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_blocked_reasons=0, mechanical_half=True)
    reasons = rows_of(document, "blocked_reasons", "error-contracts")
    declared_codes = {
        row.get("code")
        for row in rows_of(document, "error_records", "error-contracts")
        if _nonempty_str(row.get("code"))
    }
    violations = []
    for index, row in enumerate(reasons):
        error_ref = row.get("error_ref")
        if not _nonempty_str(error_ref):
            violations.append({"index": index, "reason": "error_ref_missing"})
        elif declared_codes and error_ref not in declared_codes:
            violations.append({"index": index, "error_ref": error_ref,
                               "reason": "error_ref_not_structured"})
    if violations:
        return result("FAIL", blocked_reasons_not_bound=violations, mechanical_half=True)
    return result("PASS", declared_blocked_reasons=len(reasons), mechanical_half=True)


def check_error_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """只有预先声明的可选能力可以降级。

    机械断言：每条已声明降级必须 predeclared_optional=true 并记录采用的
    替代方式（substitute）与语义影响（semantic_impact）。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_degradations=0, mechanical_half=True)
    degradations = rows_of(document, "degradations", "error-contracts")
    violations = [
        {"index": index, "capability": row.get("capability")}
        for index, row in enumerate(degradations)
        if row.get("predeclared_optional") is not True
        or not _nonempty_str(row.get("substitute"))
        or not _nonempty_str(row.get("semantic_impact"))
    ]
    if violations:
        return result("FAIL", undeclared_degradations=violations, mechanical_half=True)
    return result("PASS", declared_degradations=len(degradations), mechanical_half=True)


def check_error_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """关键失败不得降级为通过。

    机械断言：已声明降级的 target_category 不得落在必需输出、安全校验、
    授权、路径、内容契约或发布摘要六类关键失败类别内。
    """
    document = _doc(ctx, "error-contracts")
    if document is None:
        return result("PASS", declared_degradations=0, mechanical_half=True)
    degradations = rows_of(document, "degradations", "error-contracts")
    violations = [
        {"index": index, "capability": row.get("capability"),
         "target_category": row.get("target_category")}
        for index, row in enumerate(degradations)
        if row.get("target_category") in CRITICAL_FAILURE_CATEGORIES
    ]
    if violations:
        return result("FAIL", critical_failures_degraded=violations, mechanical_half=True)
    return result("PASS", declared_degradations=len(degradations), mechanical_half=True)


def check_error_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """非成功输出标记生命周期。

    机械断言：已声明输出中执行状态为等待/受阻/失败/取消者，lifecycle 必须
    属于 临时/部分完成/未验证/已验证/已提交 五值词表。
    """
    document = _doc(ctx, "output-lifecycle")
    if document is None:
        return result("PASS", declared_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "outputs", "output-lifecycle")
    violations = [
        {"index": index, "output": row.get("output"), "lifecycle": row.get("lifecycle")}
        for index, row in enumerate(outputs)
        if row.get("execution_status") in NON_SUCCESS_EXECUTION_STATUSES
        and row.get("lifecycle") not in OUTPUT_LIFECYCLE
    ]
    if violations:
        return result("FAIL", non_success_outputs_unlabeled=violations, mechanical_half=True)
    return result("PASS", declared_outputs=len(outputs), mechanical_half=True)


def check_error_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """未提交部分输出不得供正式下游消费。

    机械断言：lifecycle 属于 临时/部分完成/未验证 的已声明输出不得标记为
    正式制品（as_formal_artifact）或正式下游输入（formal_downstream_input）。
    """
    document = _doc(ctx, "output-lifecycle")
    if document is None:
        return result("PASS", declared_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "outputs", "output-lifecycle")
    uncommitted = {"transient", "partial", "unverified"}
    violations = [
        {"index": index, "output": row.get("output"), "lifecycle": row.get("lifecycle")}
        for index, row in enumerate(outputs)
        if row.get("lifecycle") in uncommitted
        and (row.get("as_formal_artifact") is True
             or row.get("formal_downstream_input") is True)
    ]
    if violations:
        return result("FAIL", uncommitted_outputs_consumed_formally=violations, mechanical_half=True)
    return result("PASS", declared_outputs=len(outputs), mechanical_half=True)


def check_error_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式输出先独占生成验证再提交。

    机械断言：每条已声明正式输出必须携带独占输出位置、提交前验证、冲突与
    授权检查，以及提交后的最终内容摘要（64 位十六进制）。
    """
    document = _doc(ctx, "output-lifecycle")
    if document is None:
        return result("PASS", declared_formal_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "formal_outputs", "output-lifecycle")
    violations = []
    for index, row in enumerate(outputs):
        if not isinstance(row, dict):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "output-lifecycle.formal_outputs 行必须是对象"
            )
        ok = (
            _nonempty_str(row.get("exclusive_staging_location"))
            and row.get("validation_before_commit") is True
            and row.get("conflict_checked") is True
            and row.get("authorization_checked") is True
            and is_hex64(row.get("committed_content_digest"))
        )
        if not ok:
            violations.append({"index": index, "output": row.get("output")})
    if violations:
        return result("FAIL", formal_outputs_without_controlled_commit=violations, mechanical_half=True)
    return result("PASS", declared_formal_outputs=len(outputs), mechanical_half=True)


# ---------------------------------------------------------------------------
# EXTENSION：扩展载体（extension-declarations，B1 文档扩展消费）
# ---------------------------------------------------------------------------


def check_extension_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """领域个性化使用三类扩展载体。

    机械断言：每条已声明扩展必须落在 方法参数/领域制品/版本化运行扩展 三类
    载体之一，满足对应载体最小形状，且不得用任意扩展字段替代受治理内容。
    """
    document = _doc(ctx, "extension-declarations")
    if document is None:
        return result("PASS", extensions_declared=0, mechanical_half=True)
    rows = rows_of(document, "extensions", "extension-declarations")
    violations = []
    for index, row in enumerate(rows):
        carrier = row.get("carrier")
        problem = None
        if carrier not in EXTENSION_CARRIERS:
            problem = "carrier_unknown"
        elif carrier == "method_parameter" and row.get("alters_object_structure") is True:
            problem = "method_parameter_alters_structure"
        elif carrier == "domain_artifact" and row.get("has_independent_identity") is not True:
            problem = "domain_artifact_lacks_identity"
        elif carrier == "runtime_extension" and not _nonempty_str(row.get("version")):
            problem = "runtime_extension_unversioned"
        if problem is None and row.get("substitutes_governed_content") is True:
            problem = "substitutes_governed_content"
        if problem:
            violations.append({"index": index, "extension": row.get("id"), "reason": problem})
    if violations:
        return result("FAIL", extension_carriers_invalid=violations, mechanical_half=True)
    return result("PASS", extensions_declared=len(rows), mechanical_half=True)


def check_extension_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """未知可选扩展受控保留和透传。

    机械断言：声明为可选且未识别的扩展必须保留原身份、原始值或内容引用，
    明示使用/透传状态，且未被静默删除或用于改变业务结果。
    """
    document = _doc(ctx, "extension-declarations")
    if document is None:
        return result("PASS", extensions_declared=0, mechanical_half=True)
    rows = rows_of(document, "extensions", "extension-declarations")
    violations = []
    for index, row in enumerate(rows):
        if row.get("required") is True or row.get("recognized") is True:
            continue
        ok = (
            _nonempty_str(row.get("original_id"))
            and _nonempty_str(row.get("original_value_or_ref"))
            and row.get("usage_status") in {"unused", "passed_through", "used"}
            and row.get("silently_dropped") is not True
            and row.get("alters_business_result") is not True
        )
        if not ok:
            violations.append({"index": index, "extension": row.get("id")})
    if violations:
        return result("FAIL", unknown_optional_extensions_not_preserved=violations, mechanical_half=True)
    return result("PASS", extensions_declared=len(rows), mechanical_half=True)


def check_extension_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """扩展不得覆盖核心共同契约。

    机械断言：每条已声明扩展不得关闭/覆盖/放宽核心契约
    （overrides_core_contract!=true），个性化只能是增加独立内容或单调收紧。
    """
    document = _doc(ctx, "extension-declarations")
    if document is None:
        return result("PASS", extensions_declared=0, mechanical_half=True)
    rows = rows_of(document, "extensions", "extension-declarations")
    legal_personalization = {"add_independent_content", "monotonic_tightening"}
    violations = [
        {"index": index, "extension": row.get("id")}
        for index, row in enumerate(rows)
        if row.get("overrides_core_contract") is True
        or row.get("personalization") not in legal_personalization
    ]
    if violations:
        return result("FAIL", extensions_overriding_core_contract=violations, mechanical_half=True)
    return result("PASS", extensions_declared=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# PATH：规范真实路径解析（path-resolution + 真实文件系统）
# ---------------------------------------------------------------------------


def check_path_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """所有资源路径先解析为规范真实路径。

    机械断言（真实扫描）：已声明资源路径必须是根内的 POSIX 相对路径且
    无遍历；resolution_basis=existing 者目标必须真实存在；
    resolution_basis=nearest_ancestor 者最近已有祖先必须真实存在。
    """
    document = _doc(ctx, "path-resolution")
    if document is None:
        return result("PASS", declared_paths=0, mechanical_half=True)
    rows = rows_of(document, "paths", "path-resolution")
    root = _target_root(ctx)
    violations = []
    for index, row in enumerate(rows):
        path = row.get("path")
        if (
            not _nonempty_str(path)
            or path.startswith(("/", "\\"))
            or ".." in Path(path).parts
        ):
            violations.append({"index": index, "path": path,
                               "reason": "path_not_normalized_within_root"})
            continue
        if not _nonempty_str(row.get("canonical_real_path")):
            violations.append({"index": index, "path": path,
                               "reason": "canonical_real_path_missing"})
            continue
        basis = row.get("resolution_basis")
        if basis == "existing":
            if not (root / path).exists():
                violations.append({"index": index, "path": path,
                                   "reason": "declared_existing_path_missing"})
        elif basis == "nearest_ancestor":
            ancestor = row.get("nearest_existing_ancestor")
            if not _nonempty_str(ancestor) or not (root / ancestor).exists():
                violations.append({"index": index, "path": path,
                                   "reason": "nearest_existing_ancestor_missing"})
        else:
            violations.append({"index": index, "path": path,
                               "reason": "resolution_basis_unknown"})
    if violations:
        return result("FAIL", paths_not_canonically_resolved=violations, mechanical_half=True)
    return result("PASS", declared_paths=len(rows), scanned_root=root.name, mechanical_half=True)


# ---------------------------------------------------------------------------
# PROGRAM：确定性程序契约（program-contracts，B1 文档扩展消费）
# ---------------------------------------------------------------------------


def _programs(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "program-contracts")
    if document is None:
        return None
    return rows_of(document, "programs", "program-contracts")


def check_program_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """确定性程序默认从属于技能。

    机械断言：每个已声明程序必须落在 ①技能从属/②独立包/③例外登记 三级之一；
    第③级必须记录"前两级不可行"的理由。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        tier = row.get("tier")
        if tier not in (1, 2, 3) or isinstance(tier, bool):
            violations.append({"index": index, "program": row.get("id"),
                               "reason": "tier_unknown"})
        elif tier == 3 and (
            not _nonempty_str(row.get("tier1_infeasible_reason"))
            or not _nonempty_str(row.get("tier2_infeasible_reason"))
        ):
            violations.append({"index": index, "program": row.get("id"),
                               "reason": "tier3_lacks_infeasibility_reasons"})
    if violations:
        return result("FAIL", program_tiers_invalid=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """可执行程序位于所属技能脚本目录。

    机械断言：第①级程序必须声明位于 scripts/ 的路径，且所属技能的
    SKILL.md 直接说明调用时机和入口。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("tier") != 1:
            continue
        scripts_path = row.get("scripts_path")
        in_scripts = (
            _nonempty_str(scripts_path)
            and "scripts" in Path(str(scripts_path)).parts
        )
        if not in_scripts or row.get("skill_md_documents_invocation") is not True:
            violations.append({"index": index, "program": row.get("id")})
    if violations:
        return result("FAIL", tier1_programs_outside_skill_scripts=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个程序只有一个逻辑所有技能。

    机械断言：每个已声明程序必须声明唯一非空 owner，且未声明共享所有权。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = [
        {"index": index, "program": row.get("id")}
        for index, row in enumerate(rows)
        if not _nonempty_str(row.get("owner")) or row.get("shared_ownership") is True
    ]
    if violations:
        return result("FAIL", programs_without_single_owner=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """禁止跨技能相对路径调用程序。

    机械断言：已声明程序不得标记存在跨技能相对路径直接引用或执行。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = [
        {"index": index, "program": row.get("id")}
        for index, row in enumerate(rows)
        if row.get("cross_skill_relative_invocation") is True
    ]
    if violations:
        return result("FAIL", cross_skill_relative_invocations=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """程序复用使用版本化稳定入口。

    机械断言：声明被复用的程序必须通过版本化引用和稳定机器入口调用，
    且未复制程序实现。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("reused") is not True:
            continue
        ok = (
            _nonempty_str(row.get("versioned_reference"))
            and _nonempty_str(row.get("stable_machine_entry"))
            and row.get("implementation_copied") is not True
        )
        if not ok:
            violations.append({"index": index, "program": row.get("id")})
    if violations:
        return result("FAIL", reuse_without_versioned_entry=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """确定性程序复用不得调用模型。

    机械断言：已声明复用路径不得为定位、传参或解析结果重新调用模型。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = [
        {"index": index, "program": row.get("id")}
        for index, row in enumerate(rows)
        if row.get("model_invocation_in_reuse") is True
    ]
    if violations:
        return result("FAIL", reuse_paths_calling_model=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """复用方不得读取所有者内部路径。

    机械断言：已声明程序不得标记复用方读取所有技能内部相对路径、
    私有参考资料或实现文件。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = [
        {"index": index, "program": row.get("id")}
        for index, row in enumerate(rows)
        if row.get("reads_owner_internal_paths") is True
    ]
    if violations:
        return result("FAIL", reuse_reading_owner_internals=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """版本化程序引用最小契约。

    机械断言：每条已声明程序引用必须锁定所有技能、程序身份、接口版本、
    内容摘要、机器入口、输入输出、依赖、兼容范围和平台解析方式。
    """
    document = load_governance_document(ctx, "program-contracts")
    if document is None:
        return result("PASS", program_references_declared=0, mechanical_half=True)
    references = rows_of(document, "program_references", "program-contracts")
    violations = []
    for index, row in enumerate(references):
        problems = _program_reference_violations(row, "reference")
        if problems:
            violations.append({"index": index, "program": row.get("program_id"),
                               "problems": problems})
    if violations:
        return result("FAIL", program_references_below_minimum_contract=violations, mechanical_half=True)
    return result("PASS", program_references_declared=len(references), mechanical_half=True)


def check_program_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """公共程序能力提升为运行时包。

    机械断言：满足跨仓复用/独立依赖/独立升级回滚/公共 CLI 任一条件的程序
    必须提升为运行时包；未达条件者必须继续由所属技能管理。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        conditions = row.get("promotion_conditions")
        if conditions is None:
            conditions = {}
        if not isinstance(conditions, dict):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "program-contracts.promotion_conditions 必须是对象",
            )
        triggered = any(conditions.get(key) is True for key in PROMOTION_CONDITIONS)
        if triggered:
            if (
                row.get("promoted_to_runtime_package") is not True
                or not _nonempty_str(row.get("runtime_package_id"))
            ):
                violations.append({"index": index, "program": row.get("id"),
                                   "reason": "promotion_condition_not_lifted"})
        elif row.get("managed_by_owning_skill") is not True:
            violations.append({"index": index, "program": row.get("id"),
                               "reason": "unlifted_program_not_managed_by_skill"})
    if violations:
        return result("FAIL", program_promotion_contract_violated=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """确定性程序不依赖模型运行。

    机械断言：已声明程序不得依赖模型、聊天记忆或智能体解释中间结果。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = [
        {"index": index, "program": row.get("id")}
        for index, row in enumerate(rows)
        if row.get("model_dependence") is True
        or row.get("chat_memory_dependence") is True
        or row.get("requires_agent_interpretation") is True
    ]
    if violations:
        return result("FAIL", programs_depending_on_model=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """程序退出与诊断结果可机械判定。

    机械断言：每个已声明程序必须携带退出契约：成功=0、失败非零且诊断写入
    标准错误。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        contract = row.get("exit_contract")
        if not isinstance(contract, dict):
            violations.append({"index": index, "program": row.get("id"),
                               "reason": "exit_contract_missing"})
            continue
        success = contract.get("success_exit_code")
        ok = (
            isinstance(success, int) and not isinstance(success, bool) and success == 0
            and contract.get("failure_exit_nonzero") is True
            and contract.get("diagnostic_on_stderr") is True
        )
        if not ok:
            violations.append({"index": index, "program": row.get("id"),
                               "reason": "exit_contract_not_mechanical"})
    if violations:
        return result("FAIL", exit_semantics_not_mechanical=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """程序重复执行语义明确。

    机械断言：每个已声明程序必须声明幂等；无法幂等时必须在调用前声明
    非幂等原因、副作用和重复执行限制。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("idempotent") is True:
            continue
        declaration = row.get("non_idempotent_declaration")
        ok = (
            isinstance(declaration, dict)
            and _nonempty_str(declaration.get("reason"))
            and _nonempty_str(declaration.get("side_effects"))
            and _nonempty_str(declaration.get("repeat_limits"))
        )
        if not ok:
            violations.append({"index": index, "program": row.get("id")})
    if violations:
        return result("FAIL", repeat_semantics_undeclared=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """程序具有合格和失败回归证据。

    机械断言：每个已声明程序必须至少有一个合格样例、一个失败样例和覆盖
    稳定接口与失败语义的回归测试。
    """
    rows = _programs(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        tests = row.get("regression_tests")
        ok = (
            _nonempty_str(row.get("qualified_sample"))
            and _nonempty_str(row.get("failure_sample"))
            and isinstance(tests, list) and bool(tests)
            and row.get("covers_stable_interface") is True
            and row.get("covers_failure_semantics") is True
        )
        if not ok:
            violations.append({"index": index, "program": row.get("id")})
    if violations:
        return result("FAIL", regression_evidence_incomplete=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# RUNTIMEPKG：独立运行时包（runtime-packages）
# ---------------------------------------------------------------------------


def check_runtimepkg_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """提升后只有一个物理实现。

    机械断言：每个已声明运行时包必须 sole_physical_implementation=true 且
    implementation_copies 为空。
    """
    document = _doc(ctx, "runtime-packages")
    if document is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    packages = rows_of(document, "packages", "runtime-packages")
    violations = []
    for index, row in enumerate(packages):
        copies = row.get("implementation_copies")
        if copies is None:
            copies = []
        if not isinstance(copies, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "runtime-packages.implementation_copies 必须是数组",
            )
        if row.get("sole_physical_implementation") is not True or copies:
            violations.append({"index": index, "package": row.get("id"),
                               "copies": copies})
    if violations:
        return result("FAIL", duplicated_physical_implementations=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(packages), mechanical_half=True)


def check_runtimepkg_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行时包拥有独立版本与兼容范围。

    机械断言：每个已声明运行时包必须携带可独立识别的版本，以及与技能族、
    平台和调用接口的兼容范围。
    """
    document = _doc(ctx, "runtime-packages")
    if document is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    packages = rows_of(document, "packages", "runtime-packages")
    violations = []
    for index, row in enumerate(packages):
        compatibility = row.get("compatibility")
        ok = (
            _nonempty_str(row.get("version"))
            and isinstance(compatibility, dict)
            and _nonempty_str(compatibility.get("family"))
            and isinstance(compatibility.get("platforms"), list)
            and bool(compatibility.get("platforms"))
            and _nonempty_str(compatibility.get("interface"))
        )
        if not ok:
            violations.append({"index": index, "package": row.get("id")})
    if violations:
        return result("FAIL", packages_without_independent_version=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(packages), mechanical_half=True)


def check_runtimepkg_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行时包拥有依赖锁和可重建构建。

    机械断言：每个已声明运行时包必须携带依赖锁摘要（64 位十六进制）、
    可重建构建声明，且未依赖开发者机器中未声明的依赖。
    """
    document = _doc(ctx, "runtime-packages")
    if document is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    packages = rows_of(document, "packages", "runtime-packages")
    violations = [
        {"index": index, "package": row.get("id")}
        for index, row in enumerate(packages)
        if not is_hex64(row.get("dependency_lock_digest"))
        or row.get("reproducible_build") is not True
        or row.get("undeclared_machine_dependencies") is True
    ]
    if violations:
        return result("FAIL", packages_without_locked_reproducible_build=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(packages), mechanical_half=True)


def check_runtimepkg_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行时包发布记录绑定实际内容摘要。

    机械断言：每条已声明运行时包发布必须记录发行物内容摘要（64 位十六进制）
    并可追溯到源码、依赖锁和构建输入。
    """
    document = _doc(ctx, "runtime-packages")
    if document is None:
        return result("PASS", releases_declared=0, mechanical_half=True)
    releases = rows_of(document, "releases", "runtime-packages")
    violations = [
        {"index": index, "release": row.get("release_id")}
        for index, row in enumerate(releases)
        if not is_hex64(row.get("artifact_content_digest"))
        or not _nonempty_str(row.get("source_ref"))
        or not _nonempty_str(row.get("dependency_lock_ref"))
        or not _nonempty_str(row.get("build_inputs_ref"))
    ]
    if violations:
        return result("FAIL", releases_without_content_digest_trace=violations, mechanical_half=True)
    return result("PASS", releases_declared=len(releases), mechanical_half=True)


def check_runtimepkg_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行时包提供安装生命周期诊断。

    机械断言：每个已声明运行时包必须能诊断安装、升级、兼容选择、回滚和
    卸载状态，并把结果提供给技能族的 setup 和业务入口。
    """
    document = _doc(ctx, "runtime-packages")
    if document is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    packages = rows_of(document, "packages", "runtime-packages")
    diagnostics_fields = ("install", "upgrade", "compat_selection", "rollback", "uninstall")
    violations = []
    for index, row in enumerate(packages):
        diagnostics = row.get("lifecycle_diagnostics")
        ok = (
            isinstance(diagnostics, dict)
            and all(diagnostics.get(field) is True for field in diagnostics_fields)
            and row.get("exposed_to_setup_and_business_entries") is True
        )
        if not ok:
            violations.append({"index": index, "package": row.get("id")})
    if violations:
        return result("FAIL", packages_without_lifecycle_diagnostics=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(packages), mechanical_half=True)


def check_runtimepkg_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """原技能保留锁定程序引用。

    机械断言：每个已声明运行时包必须携带原逻辑所有技能的锁定程序引用，
    且该引用满足 SFA-PROGRAM-010 最小契约。
    """
    document = _doc(ctx, "runtime-packages")
    if document is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    packages = rows_of(document, "packages", "runtime-packages")
    violations = []
    for index, row in enumerate(packages):
        reference = row.get("original_skill_locked_reference")
        problems = _program_reference_violations(reference, "locked_reference")
        if problems:
            violations.append({"index": index, "package": row.get("id"),
                               "problems": problems})
    if violations:
        return result("FAIL", locked_references_below_minimum_contract=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(packages), mechanical_half=True)


# ---------------------------------------------------------------------------
# STATE：运行状态与控制通道（runtime-state-contracts）
# ---------------------------------------------------------------------------


def check_state_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行状态只描述执行事实。

    机械断言：已声明运行状态不得承载降级程度、领域审阅结论或业务验收结论
    字段。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_states=0, mechanical_half=True)
    states = rows_of(document, "states", "runtime-state-contracts")
    forbidden = ("degradation_degree", "domain_conclusion", "business_acceptance")
    violations = [
        {"index": index, "state": row.get("state"),
         "forbidden_fields": [field for field in forbidden if field in row]}
        for index, row in enumerate(states)
        if any(field in row for field in forbidden)
    ]
    if violations:
        return result("FAIL", states_carrying_non_execution_facts=violations, mechanical_half=True)
    return result("PASS", declared_states=len(states), mechanical_half=True)


def check_state_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """运行状态含义互斥。

    机械断言：每条已声明结果的 primary_state 必须属于互斥词表，且不得
    携带额外主要运行状态。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_results=0, mechanical_half=True)
    results = rows_of(document, "results", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(results):
        extra = row.get("additional_primary_states")
        if extra is None:
            extra = []
        if not isinstance(extra, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "runtime-state-contracts.additional_primary_states 必须是数组",
            )
        if row.get("primary_state") not in RUN_STATES or extra:
            violations.append({"index": index, "run_id": row.get("run_id"),
                               "primary_state": row.get("primary_state")})
    if violations:
        return result("FAIL", run_states_not_exclusive=violations, mechanical_half=True)
    return result("PASS", declared_results=len(results), mechanical_half=True)


def check_state_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """降级情况独立记录。

    机械断言：降级必须记录在独立降级结构中并携带语义影响；运行状态不得
    混入降级（不得声明 carries_degradation）。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_degradations=0, mechanical_half=True)
    degradations = rows_of(document, "degradations", "runtime-state-contracts")
    states = rows_of(document, "states", "runtime-state-contracts")
    violations = [
        {"kind": "degradation_incomplete", "index": index,
         "capability": row.get("capability")}
        for index, row in enumerate(degradations)
        if not _nonempty_str(row.get("capability"))
        or not _nonempty_str(row.get("semantic_impact"))
    ]
    violations += [
        {"kind": "degradation_mixed_into_state", "index": index,
         "state": row.get("state")}
        for index, row in enumerate(states)
        if row.get("carries_degradation") is True
    ]
    if violations:
        return result("FAIL", degradations_not_independent=violations, mechanical_half=True)
    return result("PASS", declared_degradations=len(degradations), mechanical_half=True)


def check_state_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """领域结论记录在领域结果。

    机械断言：已声明结果若携带领域结论，必须同时携带领域结果；不得用
    运行状态表示领域通过或不通过。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_results=0, mechanical_half=True)
    results = rows_of(document, "results", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(results):
        conclusions = row.get("domain_conclusions")
        has_conclusions = isinstance(conclusions, (list, dict)) and bool(conclusions)
        domain_results = row.get("domain_results")
        has_domain_results = isinstance(domain_results, (list, dict)) and bool(domain_results)
        if row.get("domain_conclusion_carried_by_state") is True or (
            has_conclusions and not has_domain_results
        ):
            violations.append({"index": index, "run_id": row.get("run_id")})
    if violations:
        return result("FAIL", domain_conclusions_in_run_state=violations, mechanical_half=True)
    return result("PASS", declared_results=len(results), mechanical_half=True)


def check_state_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """受阻的适用条件。

    机械断言：声明为受阻的结果必须记录等待的外部条件，并声明当前输入
    不能解除受阻。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_results=0, mechanical_half=True)
    results = rows_of(document, "results", "runtime-state-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(results)
        if row.get("primary_state") == "blocked"
        and (
            not _nonempty_str(row.get("external_condition"))
            or row.get("current_input_cannot_unblock") is not True
        )
    ]
    if violations:
        return result("FAIL", blocked_state_misapplied=violations, mechanical_half=True)
    return result("PASS", declared_results=len(results), mechanical_half=True)


def check_state_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """等待或受阻前写检查点结果。

    机械断言：进入等待用户或受阻状态的已声明结果必须携带检查点，记录
    已完成工作、最近有效检查点、缺失内容、续接条件、已有输出和资源使用量。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_results=0, mechanical_half=True)
    results = rows_of(document, "results", "runtime-state-contracts")
    required = (
        "completed_work", "last_valid_checkpoint", "missing",
        "resume_conditions", "outputs", "resource_usage",
    )
    violations = []
    for index, row in enumerate(results):
        if row.get("primary_state") not in {"waiting_user", "blocked"}:
            continue
        checkpoint = row.get("checkpoint")
        if not isinstance(checkpoint, dict) or _missing_fields(checkpoint, required):
            violations.append({"index": index, "run_id": row.get("run_id")})
    if violations:
        return result("FAIL", checkpoint_not_written_before_pause=violations, mechanical_half=True)
    return result("PASS", declared_results=len(results), mechanical_half=True)


def check_state_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """技术重试保持运行身份。

    机械断言：每条已声明技术重试必须保持运行身份、只增加技术尝试次数
    （attempt>=2 的整数）并保留前次证据。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_retries=0, mechanical_half=True)
    retries = rows_of(document, "technical_retries", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(retries):
        attempt = row.get("attempt")
        ok = (
            _nonempty_str(row.get("run_id"))
            and isinstance(attempt, int) and not isinstance(attempt, bool) and attempt >= 2
            and row.get("identity_preserved") is True
            and row.get("previous_evidence_preserved") is True
        )
        if not ok:
            violations.append({"index": index, "run_id": row.get("run_id")})
    if violations:
        return result("FAIL", technical_retries_losing_identity=violations, mechanical_half=True)
    return result("PASS", declared_retries=len(retries), mechanical_half=True)


def check_state_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """业务变化创建谱系新任务。

    机械断言：业务变化的已声明谱系记录必须创建带前任关系的新任务，
    不得伪装成原任务技术重试。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_lineage=0, mechanical_half=True)
    lineage = rows_of(document, "business_task_lineage", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(lineage):
        if row.get("business_change") is not True:
            continue
        ok = (
            _nonempty_str(row.get("new_task_id"))
            and _nonempty_str(row.get("predecessor_ref"))
            and row.get("disguised_as_technical_retry") is not True
        )
        if not ok:
            violations.append({"index": index, "new_task_id": row.get("new_task_id")})
    if violations:
        return result("FAIL", business_changes_disguised_as_retries=violations, mechanical_half=True)
    return result("PASS", declared_lineage=len(lineage), mechanical_half=True)


def check_state_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动重试必须满足全部前提。

    机械断言：每条已声明自动重试必须同时断言错误可重试、副作用未发生或
    已回滚、输入摘要未变化、授权仍有效且重试次数未超限；任一缺失即违反。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_auto_retries=0, mechanical_half=True)
    retries = rows_of(document, "automatic_retries", "runtime-state-contracts")
    preconditions = (
        "error_retryable",
        "side_effect_none_or_rolled_back",
        "input_digest_unchanged",
        "authorization_valid",
        "attempt_within_limit",
    )
    violations = [
        {"index": index, "run_id": row.get("run_id"),
         "missing": [field for field in preconditions if row.get(field) is not True]}
        for index, row in enumerate(retries)
        if any(row.get(field) is not True for field in preconditions)
    ]
    if violations:
        return result("FAIL", automatic_retries_without_full_preconditions=violations, mechanical_half=True)
    return result("PASS", declared_auto_retries=len(retries), mechanical_half=True)


def check_state_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """严格方法声明幂等特征。

    机械断言：每个已声明严格方法必须声明至少一个合法幂等特征
    （只读可重复/同键只提交一次/可从检查点恢复/不可自动重复）。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_methods=0, mechanical_half=True)
    methods = rows_of(document, "methods", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(methods):
        characteristics = row.get("idempotence_characteristics")
        ok = (
            isinstance(characteristics, list)
            and bool(characteristics)
            and all(item in IDEMPOTENCE_CHARACTERISTICS for item in characteristics)
        )
        if not ok:
            violations.append({"index": index, "method_id": row.get("method_id")})
    if violations:
        return result("FAIL", methods_without_idempotence_declaration=violations, mechanical_half=True)
    return result("PASS", declared_methods=len(methods), mechanical_half=True)


def check_state_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """取消操作的最低结果。

    机械断言：每条已声明取消必须记录停止派发、尽力停止运行进程、清理
    临时资源、保留执行证据并标记部分输出。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_cancellations=0, mechanical_half=True)
    cancellations = rows_of(document, "cancellations", "runtime-state-contracts")
    required = (
        "stop_dispatching",
        "attempt_stop_running",
        "cleanup_temporary_resources",
        "evidence_preserved",
        "partial_outputs_marked",
    )
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(cancellations)
        if any(row.get(field) is not True for field in required)
    ]
    if violations:
        return result("FAIL", cancellations_below_minimum=violations, mechanical_half=True)
    return result("PASS", declared_cancellations=len(cancellations), mechanical_half=True)


def check_state_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """取消不得删除已提交制品。

    机械断言：已声明取消不得标记删除已提交的正式制品。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_cancellations=0, mechanical_half=True)
    cancellations = rows_of(document, "cancellations", "runtime-state-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(cancellations)
        if row.get("deletes_committed_artifacts") is True
    ]
    if violations:
        return result("FAIL", cancellations_deleting_committed_artifacts=violations, mechanical_half=True)
    return result("PASS", declared_cancellations=len(cancellations), mechanical_half=True)


def check_state_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """恢复只依据权威证据。

    机械断言：每条已声明恢复的 evidence_basis 必须全部落在原任务、最近
    有效检查点、已完成结果、新增输入或解除受阻证据五类权威来源内。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_recoveries=0, mechanical_half=True)
    recoveries = rows_of(document, "recoveries", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(recoveries):
        basis = row.get("evidence_basis")
        ok = (
            isinstance(basis, list)
            and bool(basis)
            and all(item in RECOVERY_EVIDENCE_BASIS for item in basis)
        )
        if not ok:
            violations.append({"index": index, "run_id": row.get("run_id")})
    if violations:
        return result("FAIL", recoveries_not_based_on_authoritative_evidence=violations, mechanical_half=True)
    return result("PASS", declared_recoveries=len(recoveries), mechanical_half=True)


def check_state_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """恢复不得依赖聊天记忆。

    机械断言：已声明恢复不得依赖聊天会话未落盘记忆；权威文件证据不完整时
    必须报告缺口。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_recoveries=0, mechanical_half=True)
    recoveries = rows_of(document, "recoveries", "runtime-state-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(recoveries)
        if row.get("relies_on_chat_memory") is True
        or (row.get("evidence_incomplete") is True and row.get("gap_reported") is not True)
    ]
    if violations:
        return result("FAIL", recoveries_depending_on_chat_memory=violations, mechanical_half=True)
    return result("PASS", declared_recoveries=len(recoveries), mechanical_half=True)


def check_state_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """任务引用版本化控制通道。

    机械断言：每个已声明规范化业务任务必须引用携带身份与版本的
    控制通道。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_tasks=0, mechanical_half=True)
    tasks = rows_of(document, "tasks", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(tasks):
        channel = row.get("control_channel")
        ok = (
            isinstance(channel, dict)
            and _nonempty_str(channel.get("channel_id"))
            and _nonempty_str(channel.get("version"))
        )
        if not ok:
            violations.append({"index": index, "task_id": row.get("task_id")})
    if violations:
        return result("FAIL", tasks_without_versioned_control_channel=violations, mechanical_half=True)
    return result("PASS", declared_tasks=len(tasks), mechanical_half=True)


def check_state_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """控制通道最小契约。

    机械断言：每个已声明控制通道必须记录运行与进程身份、取消序列、
    取消确认和提交前授权复验（租约或截止时间可选）。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_channels=0, mechanical_half=True)
    channels = rows_of(document, "control_channels", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(channels):
        sequence = row.get("cancel_sequence")
        ok = (
            _nonempty_str(row.get("run_and_process_identity"))
            and isinstance(sequence, list) and bool(sequence)
            and row.get("cancel_confirmation") is True
            and row.get("precommit_authorization_revalidation") is True
        )
        if not ok:
            violations.append({"index": index, "channel_id": row.get("channel_id")})
    if violations:
        return result("FAIL", control_channels_below_minimum_contract=violations, mechanical_half=True)
    return result("PASS", declared_channels=len(channels), mechanical_half=True)


def check_state_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """取消执行顺序。

    机械断言：每条已声明取消的 ordered_steps 必须恰为六步既定顺序，
    且实现不得跳过证据落盘。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_cancellations=0, mechanical_half=True)
    cancellations = rows_of(document, "cancellations", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(cancellations):
        steps = row.get("ordered_steps")
        ok = (
            isinstance(steps, list)
            and tuple(steps) == CANCEL_SEQUENCE
            and row.get("evidence_persisted") is True
        )
        if not ok:
            violations.append({"index": index, "run_id": row.get("run_id")})
    if violations:
        return result("FAIL", cancellation_sequence_skipped=violations, mechanical_half=True)
    return result("PASS", declared_cancellations=len(cancellations), mechanical_half=True)


def check_state_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """控制不可用时不得提交。

    机械断言：每条已声明提交必须断言租约未过期且控制面可达。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_commits=0, mechanical_half=True)
    commits = rows_of(document, "commits", "runtime-state-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(commits)
        if row.get("lease_expired") is True or row.get("control_reachable") is not True
    ]
    if violations:
        return result("FAIL", commits_without_available_control=violations, mechanical_half=True)
    return result("PASS", declared_commits=len(commits), mechanical_half=True)


def check_state_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """取消后的迟到结果未验证。

    机械断言：取消确认后到达的已声明结果只能记录为未验证部分输出，
    不得作为正式结果或下游输入。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_late_results=0, mechanical_half=True)
    late = rows_of(document, "late_results", "runtime-state-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(late)
        if row.get("classification") != "unverified_partial_output"
        or row.get("used_as_formal") is True
        or row.get("used_as_downstream_input") is True
    ]
    if violations:
        return result("FAIL", late_results_treated_as_formal=violations, mechanical_half=True)
    return result("PASS", declared_late_results=len(late), mechanical_half=True)


def check_state_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """高风险提交触发二次授权。

    机械断言：每条已声明高风险提交必须声明触发原因属于既定词表，
    且已重新取得相应授权。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_high_risk_commits=0, mechanical_half=True)
    commits = rows_of(document, "high_risk_commits", "runtime-state-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(commits)
        if row.get("high_risk_reason") not in HIGH_RISK_REASONS
        or row.get("reauthorized") is not True
    ]
    if violations:
        return result("FAIL", high_risk_commits_without_reauthorization=violations, mechanical_half=True)
    return result("PASS", declared_high_risk_commits=len(commits), mechanical_half=True)


def check_state_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """普通授权写入不得反复确认。

    机械断言：计划摘要、影响范围和授权均未变化时，已声明普通写入不得
    要求重复确认。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_normal_writes=0, mechanical_half=True)
    writes = rows_of(document, "normal_writes", "runtime-state-contracts")
    violations = [
        {"index": index, "write_id": row.get("write_id")}
        for index, row in enumerate(writes)
        if row.get("plan_changed") is not True
        and row.get("impact_changed") is not True
        and row.get("authorization_changed") is not True
        and row.get("repeated_confirmation_required") is True
    ]
    if violations:
        return result("FAIL", unchanged_writes_requiring_repeated_confirmation=violations, mechanical_half=True)
    return result("PASS", declared_normal_writes=len(writes), mechanical_half=True)


# ---------------------------------------------------------------------------
# TASK：规范化任务与结果文件（task-result-contracts）
# ---------------------------------------------------------------------------


def check_task_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """业务执行生成任务和结果文件。

    机械断言：每条已声明运行必须携带规范化任务文件与结果文件路径。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_runs=0, mechanical_half=True)
    runs = rows_of(document, "runs", "task-result-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(runs)
        if not _nonempty_str(row.get("run_id"))
        or not _nonempty_str(row.get("task_file"))
        or not _nonempty_str(row.get("result_file"))
    ]
    if violations:
        return result("FAIL", runs_without_task_and_result_files=violations, mechanical_half=True)
    return result("PASS", declared_runs=len(runs), mechanical_half=True)


def check_task_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """聊天不得成为唯一权威记录。

    机械断言：已声明运行不得标记聊天消息为任务、授权、输入输出或运行
    结果的唯一记录。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_runs=0, mechanical_half=True)
    runs = rows_of(document, "runs", "task-result-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(runs)
        if row.get("chat_sole_authoritative_record") is True
    ]
    if violations:
        return result("FAIL", chat_as_sole_authoritative_record=violations, mechanical_half=True)
    return result("PASS", declared_runs=len(runs), mechanical_half=True)


def check_task_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """开始业务执行必须进入文件契约。

    机械断言：声明会调用严格方法或开始实际业务执行的人类入口，必须
    声明进入统一任务与结果文件契约。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_entries=0, mechanical_half=True)
    entries = rows_of(document, "human_entries", "task-result-contracts")
    violations = [
        {"index": index, "entry": row.get("entry")}
        for index, row in enumerate(entries)
        if row.get("invokes_strict_or_business_execution") is True
        and row.get("enters_task_result_contract") is not True
    ]
    if violations:
        return result("FAIL", entries_bypassing_file_contract=violations, mechanical_half=True)
    return result("PASS", declared_entries=len(entries), mechanical_half=True)


def check_task_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """大段业务内容通过资源引用交接。

    机械断言：每条已声明资源引用必须包含路径、内容契约和内容摘要
    （64 位十六进制）。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_references=0, mechanical_half=True)
    references = rows_of(document, "resource_references", "task-result-contracts")
    violations = [
        {"index": index, "resource": row.get("resource_id")}
        for index, row in enumerate(references)
        if not _nonempty_str(row.get("path"))
        or not _nonempty_str(row.get("content_contract"))
        or not is_hex64(row.get("content_digest"))
    ]
    if violations:
        return result("FAIL", resource_references_below_minimum=violations, mechanical_half=True)
    return result("PASS", declared_references=len(references), mechanical_half=True)


def check_task_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """通用外层不得复制大段内容。

    机械断言：已声明运行不得标记通用外层结构复制资源引用所指向的
    大段正文、制品或证据。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_runs=0, mechanical_half=True)
    runs = rows_of(document, "runs", "task-result-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id")}
        for index, row in enumerate(runs)
        if row.get("envelope_copies_referenced_content") is True
    ]
    if violations:
        return result("FAIL", envelopes_copying_referenced_content=violations, mechanical_half=True)
    return result("PASS", declared_runs=len(runs), mechanical_half=True)


def check_task_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目资源按规范化工作区解析。

    机械断言：每个已声明任务必须记录非空工作区绝对根目录，并声明资源
    由该规范化工作区根解析。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_tasks=0, mechanical_half=True)
    tasks = rows_of(document, "tasks", "task-result-contracts")
    violations = [
        {"index": index, "task_id": row.get("task_id")}
        for index, row in enumerate(tasks)
        if not _nonempty_str(row.get("workspace_root"))
        or row.get("workspace_root_absolute") is not True
    ]
    if violations:
        return result("FAIL", tasks_without_normalized_workspace_root=violations, mechanical_half=True)
    return result("PASS", declared_tasks=len(tasks), mechanical_half=True)


def check_task_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """工作区外输入显式声明且默认只读。

    机械断言：每条已声明外部输入必须标记 external、记录解析后路径并
    默认只读。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_external_inputs=0, mechanical_half=True)
    inputs = rows_of(document, "external_inputs", "task-result-contracts")
    violations = [
        {"index": index, "resource": row.get("resource_id")}
        for index, row in enumerate(inputs)
        if row.get("external") is not True
        or not _nonempty_str(row.get("resolved_path"))
        or row.get("readonly") is not True
    ]
    if violations:
        return result("FAIL", external_inputs_not_declared_readonly=violations, mechanical_half=True)
    return result("PASS", declared_external_inputs=len(inputs), mechanical_half=True)


def check_task_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """输出位于授权写入集合。

    机械断言：每条已声明输出的解析后路径必须声明位于授权写入集合内；
    文档同时声明写入集合时，路径必须逐条命中。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "outputs", "task-result-contracts")
    write_set = document.get("write_set")
    if write_set is None:
        write_set = []
    if not isinstance(write_set, list) or not all(
        isinstance(item, str) for item in write_set
    ):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "task-result-contracts.write_set 必须是字符串数组",
        )
    violations = []
    for index, row in enumerate(outputs):
        resolved = row.get("resolved_path")
        if (
            not _nonempty_str(resolved)
            or row.get("within_authorized_write_set") is not True
            or (write_set and resolved not in set(write_set))
        ):
            violations.append({"index": index, "output": row.get("resource_id"),
                               "resolved_path": resolved})
    if violations:
        return result("FAIL", outputs_outside_write_set=violations, mechanical_half=True)
    return result("PASS", declared_outputs=len(outputs), mechanical_half=True)


def check_task_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """输入引用不授予写权限。

    机械断言：每条已声明输入必须记录访问方式，且不得因引用自动获得
    写权限。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_inputs=0, mechanical_half=True)
    inputs = rows_of(document, "inputs", "task-result-contracts")
    violations = [
        {"index": index, "resource": row.get("resource_id")}
        for index, row in enumerate(inputs)
        if not _nonempty_str(row.get("access_mode")) or row.get("write_granted") is True
    ]
    if violations:
        return result("FAIL", input_references_granting_write=violations, mechanical_half=True)
    return result("PASS", declared_inputs=len(inputs), mechanical_half=True)


def check_task_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """符号链接不得越过授权边界。

    机械断言：每条已声明路径边界核对必须断言真实路径与符号链接解析后
    仍在声明的读取根与授权写入集合内。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_boundary_checks=0, mechanical_half=True)
    checks = rows_of(document, "boundary_checks", "task-result-contracts")
    violations = [
        {"index": index, "path": row.get("path")}
        for index, row in enumerate(checks)
        if row.get("resolved_within_read_root") is not True
        or row.get("resolved_within_write_set") is not True
    ]
    if violations:
        return result("FAIL", symlinks_crossing_boundaries=violations, mechanical_half=True)
    return result("PASS", declared_boundary_checks=len(checks), mechanical_half=True)


def check_task_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范化任务必需内容。

    机械断言：每个已声明规范化任务必须记录运行标识、方法与工序身份、
    技术尝试次数、工作区、短小参数、输入资源、上游结果、预期输出、
    独占输出目录、写入集合、授权、验收、预算和必要扩展。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_tasks=0, mechanical_half=True)
    tasks = rows_of(document, "tasks", "task-result-contracts")
    violations = [
        {"index": index, "task_id": row.get("task_id"),
         "missing": _missing_fields(row, TASK_REQUIRED_FIELDS)}
        for index, row in enumerate(tasks)
        if _missing_fields(row, TASK_REQUIRED_FIELDS)
    ]
    if violations:
        return result("FAIL", tasks_below_required_content=violations, mechanical_half=True)
    return result("PASS", declared_tasks=len(tasks), mechanical_half=True)


def check_task_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """规范化结果必需内容。

    机械断言：每个已声明规范化结果必须记录执行状态、摘要、实际输出、
    领域结果、证据、缺失输入、告警、受阻原因、降级、执行者和资源使用量。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_results=0, mechanical_half=True)
    results = rows_of(document, "results", "task-result-contracts")
    violations = [
        {"index": index, "run_id": row.get("run_id"),
         "missing": _missing_fields(row, RESULT_REQUIRED_FIELDS)}
        for index, row in enumerate(results)
        if _missing_fields(row, RESULT_REQUIRED_FIELDS)
    ]
    if violations:
        return result("FAIL", results_below_required_content=violations, mechanical_half=True)
    return result("PASS", declared_results=len(results), mechanical_half=True)


def check_task_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """输入资源最小契约。

    机械断言：每条已声明输入资源必须记录资源身份、种类、路径、内容契约、
    内容摘要、访问方式和必需性。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_inputs=0, mechanical_half=True)
    inputs = rows_of(document, "inputs", "task-result-contracts")
    violations = []
    for index, row in enumerate(inputs):
        ok = (
            _nonempty_str(row.get("resource_id"))
            and _nonempty_str(row.get("kind"))
            and _nonempty_str(row.get("path"))
            and _nonempty_str(row.get("content_contract"))
            and is_hex64(row.get("content_digest"))
            and _nonempty_str(row.get("access_mode"))
            and isinstance(row.get("required"), bool)
        )
        if not ok:
            violations.append({"index": index, "resource": row.get("resource_id")})
    if violations:
        return result("FAIL", inputs_below_minimum_contract=violations, mechanical_half=True)
    return result("PASS", declared_inputs=len(inputs), mechanical_half=True)


def check_task_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """预期输出最小契约。

    机械断言：每条已声明预期输出必须记录资源身份、预期路径、内容契约、
    必需性、覆盖策略和验收要求。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_expected_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "expected_outputs", "task-result-contracts")
    violations = []
    for index, row in enumerate(outputs):
        ok = (
            _nonempty_str(row.get("resource_id"))
            and _nonempty_str(row.get("expected_path"))
            and _nonempty_str(row.get("content_contract"))
            and isinstance(row.get("required"), bool)
            and _nonempty_str(row.get("overwrite_policy"))
            and _nonempty_str(row.get("acceptance"))
        )
        if not ok:
            violations.append({"index": index, "resource": row.get("resource_id")})
    if violations:
        return result("FAIL", expected_outputs_below_minimum_contract=violations, mechanical_half=True)
    return result("PASS", declared_expected_outputs=len(outputs), mechanical_half=True)


def check_task_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """实际输出可验证契约。

    机械断言：每条已声明实际输出必须记录实际路径、内容契约和内容摘要
    （64 位十六进制），不得只记录"已生成"。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_actual_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "actual_outputs", "task-result-contracts")
    violations = [
        {"index": index, "resource": row.get("resource_id")}
        for index, row in enumerate(outputs)
        if not _nonempty_str(row.get("actual_path"))
        or not _nonempty_str(row.get("content_contract"))
        or not is_hex64(row.get("content_digest"))
    ]
    if violations:
        return result("FAIL", actual_outputs_not_verifiable=violations, mechanical_half=True)
    return result("PASS", declared_actual_outputs=len(outputs), mechanical_half=True)


def check_task_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """可复用机器结构化输出具有校验包。

    机械断言：每条已声明结构化输出必须同时提供权威结构定义、至少一个
    合格示例和一个不依赖模型的确定性校验入口，且三者锁定同一内容契约修订。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_structured_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "structured_outputs", "task-result-contracts")
    violations = []
    for index, row in enumerate(outputs):
        examples = row.get("qualified_examples")
        revisions = [row.get(field) for field in STRUCTURED_OUTPUT_REVISION_FIELDS]
        ok = (
            _nonempty_str(row.get("authoritative_schema"))
            and isinstance(examples, list) and bool(examples)
            and _nonempty_str(row.get("deterministic_validator"))
            and all(_nonempty_str(revision) for revision in revisions)
            and len(set(revisions)) == 1
        )
        if not ok:
            violations.append({"index": index, "output": row.get("output_id")})
    if violations:
        return result("FAIL", structured_outputs_without_validation_package=violations, mechanical_half=True)
    return result("PASS", declared_structured_outputs=len(outputs), mechanical_half=True)


def check_task_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """合格示例通过正式校验入口。

    机械断言：每条已声明结构化输出的合格示例必须通过同一公开确定性校验
    入口，不得使用旁路校验器或人工判断。
    """
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return result("PASS", declared_structured_outputs=0, mechanical_half=True)
    outputs = rows_of(document, "structured_outputs", "task-result-contracts")
    violations = [
        {"index": index, "output": row.get("output_id")}
        for index, row in enumerate(outputs)
        if row.get("examples_pass_official_validator") is not True
        or row.get("bypass_validator_used") is True
        or row.get("human_judgment_used") is True
    ]
    if violations:
        return result("FAIL", examples_not_passing_official_validator=violations, mechanical_half=True)
    return result("PASS", declared_structured_outputs=len(outputs), mechanical_half=True)


# ---------------------------------------------------------------------------
# WRITE：变更前写入集合记录（write-closure，B1 文档扩展消费）
# ---------------------------------------------------------------------------


def check_write_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """变更前记录精确写入集合。

    机械断言：每条已声明拟执行写操作必须记录解析后目标路径和操作类型；
    目录级概括必须可确定性展开且仍受同一授权约束。
    """
    document = _doc(ctx, "write-closure")
    if document is None:
        return result("PASS", writes_declared=0, mechanical_half=True)
    writes = rows_of(document, "writes", "write-closure")
    violations = []
    for index, row in enumerate(writes):
        if not _nonempty_str(row.get("path")) or not _nonempty_str(row.get("operation_type")):
            violations.append({"index": index, "path": row.get("path"),
                               "reason": "write_not_precise"})
        elif row.get("is_directory_generalization") is True and (
            row.get("deterministic_expansion") is not True
            or row.get("same_authorization") is not True
        ):
            violations.append({"index": index, "path": row.get("path"),
                               "reason": "generalization_not_deterministic"})
    if violations:
        return result("FAIL", write_set_not_recorded_precisely=violations, mechanical_half=True)
    return result("PASS", writes_declared=len(writes), mechanical_half=True)


def check_write_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """变更前记录相关已有对象状态。

    机械断言：声明为已有对象的写入必须记录存在性、类型、内容摘要和足以
    支持冲突与恢复判断的状态。
    """
    document = _doc(ctx, "write-closure")
    if document is None:
        return result("PASS", writes_declared=0, mechanical_half=True)
    writes = rows_of(document, "writes", "write-closure")
    violations = []
    for index, row in enumerate(writes):
        if row.get("pre_existing") is not True:
            continue
        state = row.get("pre_state")
        ok = (
            isinstance(state, dict)
            and "existence" in state
            and _nonempty_str(state.get("type"))
            and is_hex64(state.get("content_digest"))
            and _nonempty_str(state.get("conflict_recovery_state"))
        )
        if not ok:
            violations.append({"index": index, "path": row.get("path")})
    if violations:
        return result("FAIL", pre_existing_state_not_recorded=violations, mechanical_half=True)
    return result("PASS", writes_declared=len(writes), mechanical_half=True)


def check_write_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """变更前绑定计划摘要。

    机械断言：已声明授权必须绑定由写入集合、已有对象状态、操作顺序和
    外部影响计算的计划摘要（与文档 plan_digest 一致的 64 位十六进制），
    且计划变化后原授权失效。
    """
    document = _doc(ctx, "write-closure")
    if document is None:
        return result("PASS", writes_declared=0, mechanical_half=True)
    plan_digest = document.get("plan_digest")
    if not is_hex64(plan_digest):
        return result("FAIL", reason="plan_digest_missing_or_invalid", mechanical_half=True)
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        return result("FAIL", reason="authorization_binding_missing", mechanical_half=True)
    bound_to = authorization.get("bound_to")
    bound_ok = isinstance(bound_to, dict) and all(
        bound_to.get(field) is True
        for field in ("write_set", "pre_object_states", "operation_order", "external_impacts")
    )
    if (
        authorization.get("plan_digest") != plan_digest
        or not bound_ok
        or authorization.get("plan_change_invalidates_authorization") is not True
    ):
        return result("FAIL", reason="authorization_not_bound_to_plan_digest", mechanical_half=True)
    return result("PASS", plan_digest=plan_digest, mechanical_half=True)


# ---------------------------------------------------------------------------
# 登记
# ---------------------------------------------------------------------------

CHECKS = {
    "SFA-ERROR-001": check_error_001,
    "SFA-ERROR-002": check_error_002,
    "SFA-ERROR-003": check_error_003,
    "SFA-ERROR-004": check_error_004,
    "SFA-ERROR-005": check_error_005,
    "SFA-ERROR-006": check_error_006,
    "SFA-ERROR-007": check_error_007,
    "SFA-ERROR-008": check_error_008,
    "SFA-ERROR-009": check_error_009,
    "SFA-ERROR-010": check_error_010,
    "SFA-ERROR-011": check_error_011,
    "SFA-EXTENSION-001": check_extension_001,
    "SFA-EXTENSION-002": check_extension_002,
    "SFA-EXTENSION-004": check_extension_004,
    "SFA-PATH-001": check_path_001,
    "SFA-PROGRAM-001": check_program_001,
    "SFA-PROGRAM-002": check_program_002,
    "SFA-PROGRAM-005": check_program_005,
    "SFA-PROGRAM-006": check_program_006,
    "SFA-PROGRAM-007": check_program_007,
    "SFA-PROGRAM-008": check_program_008,
    "SFA-PROGRAM-009": check_program_009,
    "SFA-PROGRAM-010": check_program_010,
    "SFA-PROGRAM-011": check_program_011,
    "SFA-PROGRAM-012": check_program_012,
    "SFA-PROGRAM-014": check_program_014,
    "SFA-PROGRAM-016": check_program_016,
    "SFA-PROGRAM-017": check_program_017,
    "SFA-RUNTIMEPKG-001": check_runtimepkg_001,
    "SFA-RUNTIMEPKG-002": check_runtimepkg_002,
    "SFA-RUNTIMEPKG-003": check_runtimepkg_003,
    "SFA-RUNTIMEPKG-004": check_runtimepkg_004,
    "SFA-RUNTIMEPKG-005": check_runtimepkg_005,
    "SFA-RUNTIMEPKG-006": check_runtimepkg_006,
    "SFA-STATE-001": check_state_001,
    "SFA-STATE-002": check_state_002,
    "SFA-STATE-003": check_state_003,
    "SFA-STATE-004": check_state_004,
    "SFA-STATE-006": check_state_006,
    "SFA-STATE-007": check_state_007,
    "SFA-STATE-009": check_state_009,
    "SFA-STATE-010": check_state_010,
    "SFA-STATE-011": check_state_011,
    "SFA-STATE-012": check_state_012,
    "SFA-STATE-013": check_state_013,
    "SFA-STATE-014": check_state_014,
    "SFA-STATE-015": check_state_015,
    "SFA-STATE-016": check_state_016,
    "SFA-STATE-017": check_state_017,
    "SFA-STATE-018": check_state_018,
    "SFA-STATE-019": check_state_019,
    "SFA-STATE-020": check_state_020,
    "SFA-STATE-021": check_state_021,
    "SFA-STATE-022": check_state_022,
    "SFA-STATE-023": check_state_023,
    "SFA-TASK-001": check_task_001,
    "SFA-TASK-002": check_task_002,
    "SFA-TASK-006": check_task_006,
    "SFA-TASK-007": check_task_007,
    "SFA-TASK-008": check_task_008,
    "SFA-TASK-009": check_task_009,
    "SFA-TASK-010": check_task_010,
    "SFA-TASK-011": check_task_011,
    "SFA-TASK-012": check_task_012,
    "SFA-TASK-013": check_task_013,
    "SFA-TASK-014": check_task_014,
    "SFA-TASK-015": check_task_015,
    "SFA-TASK-016": check_task_016,
    "SFA-TASK-017": check_task_017,
    "SFA-TASK-018": check_task_018,
    "SFA-TASK-019": check_task_019,
    "SFA-TASK-020": check_task_020,
    "SFA-WRITE-001": check_write_001,
    "SFA-WRITE-002": check_write_002,
    "SFA-WRITE-003": check_write_003,
}
