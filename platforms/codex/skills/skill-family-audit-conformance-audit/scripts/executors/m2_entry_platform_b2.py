"""M2 执行族：人类入口/命名/平台投影/发行包/源码投影/摘要链（W2-B2 子批 M2，70 条）。

本模块覆盖 B2 批 execution_family=M2、violation_impact=error 的 70 条规则，
全部被终态裁决为机械方法 digest_verification 且
behavior_verification_also_required=true；执行器只覆盖机械半区
（evidence 携 mechanical_half=true），行为义务继续挂账。

证据面（与 B1 M2 / B2 M1 / B2 M3 一致，失败关闭）：
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``：
  entry-boundaries / platform-projections / platform-restrictions（B1 文档扩展消费）
  + naming-registry / release-packages / source-projections / content-chain（本批新增）。

治理声明缺省语义沿用 B1：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 文档存在但形状非法 → ExecutorEvidenceError（失败关闭，绝不静默放行）；
- 文档存在且出现结构性违反 → FAIL。

执行器只消费目标事实，绝不修改目标；不消费模型语义结论。
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import conformance_check

from .contracts import (
    FIXED_HUMAN_ENTRIES,
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

#: SFA-NAM-015：第一版公共意图词表。
PUBLIC_INTENTS = (
    "plan", "create", "iterate", "review", "audit", "repair", "migrate", "publish",
)

#: SFA-NAM-017：第一版内部动作词表。
INTERNAL_ACTIONS = (
    "inspect", "analyze", "design", "compose", "review",
    "repair", "validate", "verify", "finalize",
)

#: SFA-NAM-013：不得附加的实现角色后缀。
FORBIDDEN_NAME_SUFFIXES = {"method", "workflow", "flow"}

#: SFA-NAM-014：公共端到端业务名称形状。
PUBLIC_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")

#: SFA-NAM-016：内部技能名称形状（family[-subject]-operation）。
INTERNAL_NAME_SEGMENT = re.compile(r"^[a-z][a-z0-9]*$")

#: SFA-ENTRY-004：固定入口逻辑名形状（<family>:help|setup|quickstart）。
ENTRY_LOGICAL_NAME_PATTERN = re.compile(r"^([a-z][a-z0-9-]*):(help|setup|quickstart)$")

#: SFA-ENTRY-012：quickstart 不得是的非正式形态。
QUICKSTART_FORBIDDEN_MODES = {
    "trial", "demo", "sample", "temporary_result", "degraded_mode",
}

#: SFA-ENTRY-020：固定入口仅允许的四类职能。
ENTRY_ALLOWED_FUNCTIONS = {"discover", "explain", "complete", "invoke"}

#: SFA-ENTRY-027：未识别信息允许的处置。
UNRECOGNIZED_INFORMATION_ACTIONS = {
    "map_to_supported_parameter",
    "passthrough_reserved",
    "reserved_unused",
    "ask_user_when_outcome_may_change",
}

#: SFA-ENTRY-008：help 至少覆盖的六类内容。
HELP_REQUIRED_SECTIONS = (
    "capability_and_unsupported_scope",
    "applicable_scenarios",
    "dependencies_and_current_status",
    "minimal_formal_example",
    "next_steps",
    "diagnostic_entry",
)

#: SFA-ENTRY-023：无法形成合法规范化任务时必须返回的六项。
NO_TASK_FAILURE_REPORT_FIELDS = (
    "identified_candidates",
    "existing_inputs",
    "missing_or_invalid_information",
    "unacquired_authorization",
    "affected_capabilities",
    "user_next_steps",
)

#: SFA-PLAT-024：平台档案与投影合同必须记录的内容。
PLATFORM_PROFILE_REQUIRED_FIELDS = (
    "official_source",
    "acquired_at",
    "content_digest",
    "applicable_client_versions",
    "expiry_conditions",
    "plugin_manifest",
    "package_directory",
    "logical_physical_mapping",
    "visibility",
    "execution_units",
    "tools",
    "permissions",
    "hooks",
    "connectors",
    "install_to_removal_probes",
)

#: SFA-PLAT-009：四平台必须共享的定义面。
SHARED_DEFINITION_FIELDS = (
    "business_capabilities",
    "method_contracts",
    "input_output_meaning",
    "permission_boundaries",
    "acceptance_conditions",
    "error_semantics",
)

#: SFA-PLAT-001：四平台完整发行必须逐项满足的可验证属性。
FULL_RELEASE_PLATFORM_ATTRIBUTES = (
    "installable", "discoverable", "invokable", "diagnosable",
)

#: SFA-PLAT-028：支持矩阵四维。
SUPPORT_MATRIX_FIELDS = (
    "host_platform", "operating_system", "processor_architecture", "runtime_version",
)

#: SFA-PACKAGE-002：发布构建必须固定或归一化的维度。
BUILD_NORMALIZATION_FIELDS = (
    "file_order",
    "timestamps",
    "permissions",
    "archive_owner",
    "path_representation",
    "compression_parameters",
)

#: SFA-BYTECHAIN-001：摘要链必经阶段（顺序即义务顺序）。
CONTENT_CHAIN_STAGES = (
    "source",
    "generator_or_controlled_overlay",
    "platform_projection",
    "release_package",
    "channel_download",
    "install_result",
)

#: SFA-SOURCE-004：必须位于同一业务源码根的技能类别。
SOURCE_ROOT_SKILL_KINDS = {"fixed_human_entry", "named_entry", "internal_skill"}

#: SFA-SOURCE-014：安装后投影不得反向引用的位置类别。
FORBIDDEN_REVERSE_REFERENCE_KINDS = {
    "source_repo", "adjacent_project", "builder_home",
}

#: SFA-SOURCE-011：平台覆盖不得修改的共同语义面。
OVERLAY_PROTECTED_FIELDS = (
    "public_input_output",
    "authorization",
    "side_effects",
    "errors",
    "quality_gates",
    "acceptance_conditions",
)

#: SFA-SOURCE-009：覆盖补丁必须记录的字段。
OVERLAY_PATCH_REQUIRED_FIELDS = (
    "owner", "reason", "applicable_platform_version_range", "review_deadline",
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


def _bool_rows(
    rows: list[dict[str, Any]], fields: tuple[str, ...], *, row_label: str
) -> list[dict[str, Any]]:
    """返回 fields 未全部声明为 true 的行（附行标识）。"""
    violations = []
    for index, row in enumerate(rows):
        missing = [field for field in fields if row.get(field) is not True]
        if missing:
            violations.append(
                {"index": index, row_label: row.get(row_label), "missing": missing}
            )
    return violations


def _entry_rows(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "entry-boundaries")
    if document is None:
        return None
    return rows_of(document, "entries", "entry-boundaries")


def _entry_row(
    rows: list[dict[str, Any]], name: str
) -> dict[str, Any] | None:
    matches = [row for row in rows if row.get("entry") == name]
    if len(matches) > 1:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"entry-boundaries 重复声明入口: {name}"
        )
    return matches[0] if matches else None


def _fixed_entry_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("entry") in FIXED_HUMAN_ENTRIES]


def _projection_rows(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "platform-projections")
    if document is None:
        return None
    rows = rows_of(document, "projections", "platform-projections")
    for index, row in enumerate(rows):
        if row.get("platform") not in REQUIRED_PLATFORMS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections 第 {index} 行平台非法: {row.get('platform')!r}",
            )
    return rows


def _projection_document(ctx: dict[str, Any]) -> dict[str, Any] | None:
    document = _doc(ctx, "platform-projections")
    if document is None:
        return None
    rows_of(document, "projections", "platform-projections")
    return document


def _sub_rows(
    row: dict[str, Any], key: str, platform: Any, *, required: bool = False
) -> list[dict[str, Any]] | None:
    """投影行下的子行数组；形状非法失败关闭。"""
    value = row.get(key)
    if value is None:
        if required:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INCOMPLETE",
                f"platform-projections {platform} 缺少 {key} 声明",
            )
        return None
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            f"platform-projections {platform} 的 {key} 必须是对象数组",
        )
    return value


def json_stable(value: Any) -> str:
    """对象规范化序列化（键排序），用于跨平台一致性比对。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


# ---------------------------------------------------------------------------
# ENTRY：固定人类入口（entry-boundaries）
# ---------------------------------------------------------------------------


def check_entry_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """固定入口的规范对外名称。

    机械断言：已声明固定入口的逻辑名必须形如 ``<family>:<entry>``；物理名非空；
    采用前缀命名回退必须声明动因为裸名冲突且平台清单映射已登记。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    fixed = _fixed_entry_rows(rows)
    if not fixed:
        return result("PASS", entries_declared=len(rows), mechanical_half=True)
    violations = []
    for row in fixed:
        entry = row.get("entry")
        logical = row.get("logical_name")
        problems = []
        match = ENTRY_LOGICAL_NAME_PATTERN.match(logical) if isinstance(logical, str) else None
        if not match or match.group(2) != entry:
            problems.append("logical_name_not_family_colon_entry")
        if not _nonempty_str(row.get("physical_name")):
            problems.append("physical_name_empty")
        if row.get("naming_fallback") is True:
            if row.get("fallback_reason") != "bare_name_conflict":
                problems.append("fallback_reason_not_bare_name_conflict")
            if row.get("manifest_mapping_declared") is not True:
                problems.append("fallback_mapping_not_declared_in_manifest")
        if problems:
            violations.append({"entry": entry, "problems": problems})
    if violations:
        return result("FAIL", entry_name_violations=violations, mechanical_half=True)
    return result("PASS", fixed_entries_declared=len(fixed), mechanical_half=True)


def check_entry_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """三个固定入口必须从同一份事实生成说明。

    机械断言：已声明固定入口的能力目录来源必须为同一非空来源；出现独立维护的
    能力目录即违反。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    fixed = _fixed_entry_rows(rows)
    if not fixed:
        return result("PASS", entries_declared=len(rows), mechanical_half=True)
    violations = []
    sources = set()
    for row in fixed:
        if row.get("independent_capability_catalog") is True:
            violations.append(
                {"entry": row.get("entry"), "problem": "independent_capability_catalog"}
            )
        source = row.get("capability_catalog_source")
        if _nonempty_str(source):
            sources.add(source)
        elif row.get("capability_catalog_source") is not None:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "entry-boundaries.entries.capability_catalog_source 必须是非空字符串",
            )
    if len(sources) > 1:
        violations.append(
            {"problem": "divergent_capability_catalog_sources", "sources": sorted(sources)}
        )
    if violations:
        return result("FAIL", capability_catalog_violations=violations, mechanical_half=True)
    return result("PASS", fixed_entries_declared=len(fixed), mechanical_half=True)


def check_entry_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """help 内容最小集。

    机械断言：已声明 help 必须覆盖六类必需内容段落。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "help")
    if row is None:
        return result("PASS", help_declared=False, mechanical_half=True)
    sections = row.get("help_sections")
    if not isinstance(sections, list) or not all(isinstance(item, str) for item in sections):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "entry-boundaries.help.help_sections 必须是字符串数组"
        )
    missing = [item for item in HELP_REQUIRED_SECTIONS if item not in sections]
    if missing:
        return result("FAIL", help_sections_missing=missing, mechanical_half=True)
    return result("PASS", help_sections=len(sections), mechanical_half=True)


def check_entry_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 是正式人类执行入口。

    机械断言：已声明 quickstart 必须 formal_execution_entry=true，且形态不得为
    试用/演示/样例/临时结果/降级模式。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    problems = []
    if row.get("formal_execution_entry") is not True:
        problems.append("not_declared_formal_execution_entry")
    mode = row.get("entry_mode")
    if mode in QUICKSTART_FORBIDDEN_MODES:
        problems.append(f"forbidden_entry_mode:{mode}")
    if problems:
        return result("FAIL", quickstart_formality_problems=problems, mechanical_half=True)
    return result("PASS", formal_execution_entry=True, mechanical_half=True)


def check_entry_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 复用严格方法的执行承诺。

    机械断言：已声明 quickstart 必须复用严格方法的承诺；声明只检查不执行必须
    以用户明确要求为前提；不得产出非正式结果。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    problems = []
    if row.get("reuses_strict_method_commitments") is not True:
        problems.append("strict_method_commitments_not_reused")
    if row.get("check_only_mode") is True and row.get("user_explicitly_requested") is not True:
        problems.append("check_only_without_explicit_user_request")
    if row.get("emits_informal_results") is True:
        problems.append("emits_informal_results")
    if problems:
        return result("FAIL", quickstart_commitment_problems=problems, mechanical_half=True)
    return result("PASS", reuses_strict_method_commitments=True, mechanical_half=True)


def check_entry_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 不拥有独立业务实现。

    机械断言：已声明 quickstart 不得拥有独立业务实现，也不得长期承载严格方法
    的完整执行协议。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    problems = []
    if row.get("owns_business_implementation") is True:
        problems.append("owns_business_implementation")
    if row.get("carries_full_execution_protocol") is True:
        problems.append("carries_full_execution_protocol")
    if problems:
        return result("FAIL", quickstart_ownership_problems=problems, mechanical_half=True)
    return result("PASS", routes_to_strict_methods_only=True, mechanical_half=True)


def check_entry_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 必须先确定性枚举候选。

    机械断言：已声明候选枚举方式必须为 deterministic；不得以语义猜测替代既有
    确定性目录与项目事实。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    problems = []
    if row.get("candidate_enumeration") != "deterministic":
        problems.append("candidate_enumeration_not_deterministic")
    if row.get("semantic_guessing_substitutes_catalog") is True:
        problems.append("semantic_guessing_substitutes_catalog")
    if problems:
        return result("FAIL", quickstart_enumeration_problems=problems, mechanical_half=True)
    return result("PASS", candidate_enumeration="deterministic", mechanical_half=True)


def check_entry_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 只做语义导诊并路由到正式业务入口。

    机械断言：声明相关职责边界时，quickstart（及可选独立 router）必须路由到
    正式业务入口，且不得取得业务授权、执行业务阶段或候选 workflow，或拥有业务
    执行生命周期。独立 router 只有在声明真实权限或生命周期边界时才成立。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    router = row.get("semantic_router")
    declared_fields = (
        "routes_to_formal_business_entry",
        "acquires_business_authorization",
        "executes_business_stages",
        "executes_candidate_workflows",
        "owns_business_execution_lifecycle",
    )
    if router is None and not any(field in row for field in declared_fields):
        return result("PASS", semantic_router_declared=False, mechanical_half=True)
    if router is not None and not isinstance(router, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.semantic_router 必须是对象",
        )
    router = router or {}
    problems = []
    # 这些字段构成 r3 的职责边界。只要声明了 router 或任一边界字段，就要求
    # quickstart 明确指向正式业务入口；缺省文档继续沿用触发式 PASS。
    if row.get("routes_to_formal_business_entry") is not True:
        problems.append("does_not_route_to_formal_business_entry")
    boundary_fields = (
        "acquires_business_authorization",
        "executes_business_stages",
        "executes_candidate_workflows",
        "owns_business_execution_lifecycle",
    )
    for field in boundary_fields:
        if row.get(field) is True or router.get(field) is True:
            problems.append(field)
    # 保留旧声明字段的失败关闭行为，兼容已有治理文档并覆盖同一安全边界。
    if router.get("business_write_permission") is True:
        problems.append("router_has_business_write_permission")
    if router.get("acquires_business_authorization") is True:
        problems.append("router_acquires_business_authorization")
    if router.get("executes_candidate_methods") is True:
        problems.append("router_executes_candidate_methods")
    if row.get("semantic_router") is not None and router.get(
        "independent_permission_or_lifecycle_boundary"
    ) is not True:
        problems.append("independent_router_boundary_missing")
    if problems:
        return result("FAIL", semantic_router_problems=problems, mechanical_half=True)
    return result("PASS", semantic_router_isolated=True, routes_to_formal_business_entry=True,
                  mechanical_half=True)


def check_entry_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 保留转换追溯。

    机械断言：已声明追溯必须覆盖原始请求、参数补全、候选与选择依据、最终
    规范化任务四项。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    traceability = row.get("traceability")
    if not isinstance(traceability, dict):
        return result("FAIL", reason="quickstart_traceability_missing", mechanical_half=True)
    required = (
        "original_request",
        "parameter_completion",
        "candidates_and_selection_basis",
        "final_canonical_task",
    )
    missing = [field for field in required if traceability.get(field) is not True]
    if missing:
        return result("FAIL", traceability_missing=missing, mechanical_half=True)
    return result("PASS", traceability_fields=len(required), mechanical_half=True)


def check_entry_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """固定入口不得复制执行协议。

    机械断言：已声明固定入口不得复制严格业务方法的执行协议；声明的职能必须
    限于发现、说明、补全和调用。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    fixed = _fixed_entry_rows(rows)
    if not fixed:
        return result("PASS", entries_declared=len(rows), mechanical_half=True)
    violations = []
    for row in fixed:
        problems = []
        if row.get("duplicates_execution_protocol") is True:
            problems.append("duplicates_execution_protocol")
        functions = row.get("entry_functions")
        if functions is not None:
            if not isinstance(functions, list) or not all(
                isinstance(item, str) for item in functions
            ):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "entry-boundaries.entries.entry_functions 必须是字符串数组",
                )
            unknown = sorted(set(functions) - ENTRY_ALLOWED_FUNCTIONS)
            if unknown:
                problems.append(f"functions_beyond_discovery:{unknown}")
        if problems:
            violations.append({"entry": row.get("entry"), "problems": problems})
    if violations:
        return result("FAIL", entry_protocol_violations=violations, mechanical_half=True)
    return result("PASS", fixed_entries_declared=len(fixed), mechanical_half=True)


def check_entry_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """固定入口不得暴露内部实现面。

    机械断言：已声明固定入口不得把内部技能、专属执行单元、脚本目录或私有
    参考资料作为普通用户操作面暴露。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    fixed = _fixed_entry_rows(rows)
    if not fixed:
        return result("PASS", entries_declared=len(rows), mechanical_half=True)
    violations = []
    for row in fixed:
        exposed = row.get("exposed_internal_kinds")
        if exposed is None:
            exposed = []
        if not isinstance(exposed, list) or not all(
            isinstance(item, str) for item in exposed
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "entry-boundaries.entries.exposed_internal_kinds 必须是字符串数组",
            )
        if exposed:
            violations.append({"entry": row.get("entry"), "exposed": sorted(set(exposed))})
    if violations:
        return result("FAIL", internal_surfaces_exposed=violations, mechanical_half=True)
    return result("PASS", fixed_entries_declared=len(fixed), mechanical_half=True)


def check_entry_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """无合法规范化任务时的结构化失败报告。

    机械断言：已声明失败报告合同必须覆盖候选方法、已有输入、缺失或无效信息、
    未取得的授权、受影响能力和用户下一步六项；不得声明只返回模糊失败文本。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    if row.get("vague_failure_text_only") is True:
        return result("FAIL", reason="vague_failure_text_only", mechanical_half=True)
    contract = row.get("failure_report_contract")
    if contract is None:
        return result("PASS", failure_report_contract_declared=False, mechanical_half=True)
    if not isinstance(contract, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.failure_report_contract 必须是对象",
        )
    missing = [field for field in NO_TASK_FAILURE_REPORT_FIELDS if field not in contract]
    if missing:
        return result("FAIL", failure_report_fields_missing=missing, mechanical_half=True)
    return result("PASS", failure_report_fields=len(NO_TASK_FAILURE_REPORT_FIELDS), mechanical_half=True)


def check_entry_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """无匹配时声明能力边界并返回未匹配依据。

    机械断言：已声明无匹配政策必须声明能力边界与未匹配依据，且不得伪造
    相近方法匹配或借用内部技能/其他技能族。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    policy = row.get("no_match_policy")
    if policy is None:
        return result("PASS", no_match_policy_declared=False, mechanical_half=True)
    if not isinstance(policy, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.no_match_policy 必须是对象",
        )
    problems = []
    if policy.get("declares_capability_boundary") is not True:
        problems.append("capability_boundary_not_declared")
    if policy.get("returns_unmatched_basis") is not True:
        problems.append("unmatched_basis_not_returned")
    if policy.get("fabricates_nearby_match") is True:
        problems.append("fabricates_nearby_match")
    if policy.get("borrows_internal_skills_or_other_families") is True:
        problems.append("borrows_internal_skills_or_other_families")
    if problems:
        return result("FAIL", no_match_policy_problems=problems, mechanical_half=True)
    return result("PASS", no_match_policy_declared=True, mechanical_half=True)


def check_entry_026(ctx: dict[str, Any]) -> dict[str, Any]:
    """单候选才可直接选择。

    机械断言：已声明候选选择政策必须要求直接选择仅在单一候选时发生，且
    多候选必须按实质差异向用户说明并选择。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    policy = row.get("candidate_selection_policy")
    if policy is None:
        return result("PASS", selection_policy_declared=False, mechanical_half=True)
    if not isinstance(policy, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.candidate_selection_policy 必须是对象",
        )
    problems = []
    if policy.get("direct_selection_requires_single_candidate") is not True:
        problems.append("direct_selection_not_limited_to_single_candidate")
    if policy.get("multi_candidate_requires_differentiated_explanation") is not True:
        problems.append("multi_candidate_explanation_not_required")
    if problems:
        return result("FAIL", selection_policy_problems=problems, mechanical_half=True)
    return result("PASS", selection_policy_declared=True, mechanical_half=True)


def check_entry_027(ctx: dict[str, Any]) -> dict[str, Any]:
    """未识别信息的受控处置。

    机械断言：已声明允许处置必须落在四类受控动作内；不得声明静默丢弃、猜测
    含义或写入未声明字段。
    """
    rows = _entry_rows(ctx)
    if rows is None:
        return result("PASS", entries_declared=0, mechanical_half=True)
    row = _entry_row(rows, "quickstart")
    if row is None:
        return result("PASS", quickstart_declared=False, mechanical_half=True)
    policy = row.get("unrecognized_information_policy")
    if policy is None:
        return result("PASS", unrecognized_policy_declared=False, mechanical_half=True)
    if not isinstance(policy, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.unrecognized_information_policy 必须是对象",
        )
    problems = []
    actions = policy.get("allowed_actions")
    if actions is not None:
        if not isinstance(actions, list) or not all(
            isinstance(item, str) for item in actions
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "unrecognized_information_policy.allowed_actions 必须是字符串数组",
            )
        unknown = sorted(set(actions) - UNRECOGNIZED_INFORMATION_ACTIONS)
        if unknown:
            problems.append(f"uncontrolled_actions:{unknown}")
    if policy.get("silently_drops") is True:
        problems.append("silently_drops")
    if policy.get("guesses_meaning") is True:
        problems.append("guesses_meaning")
    if policy.get("writes_undeclared_fields") is True:
        problems.append("writes_undeclared_fields")
    if problems:
        return result("FAIL", unrecognized_information_problems=problems, mechanical_half=True)
    return result("PASS", unrecognized_policy_declared=True, mechanical_half=True)


# ---------------------------------------------------------------------------
# NAM：命名登记（naming-registry）
# ---------------------------------------------------------------------------


def _naming_document(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "naming-registry")


def check_nam_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """同一能力两个调用表面共用同一逻辑名称。

    机械断言：已声明逻辑名必须使面向人表面与严格方法表面同名，且不得附加
    method/workflow/flow 或实现角色后缀。
    """
    document = _naming_document(ctx)
    if document is None:
        return result("PASS", logical_names_declared=0, mechanical_half=True)
    rows = rows_of(document, "logical_names", "naming-registry")
    violations = []
    for index, row in enumerate(rows):
        human = row.get("human_surface_name")
        method = row.get("method_surface_name")
        problems = []
        if not _nonempty_str(human) or not _nonempty_str(method):
            problems.append("surface_name_empty")
        elif human != method:
            problems.append("surface_names_diverge")
        for name in (human, method):
            if isinstance(name, str) and name:
                tail = name.rsplit("-", 1)[-1]
                if tail in FORBIDDEN_NAME_SUFFIXES:
                    problems.append(f"implementation_role_suffix:{name}")
        if problems:
            violations.append(
                {"index": index, "capability": row.get("capability"), "problems": problems}
            )
    if violations:
        return result("FAIL", logical_name_violations=violations, mechanical_half=True)
    return result("PASS", logical_names_declared=len(rows), mechanical_half=True)


def check_nam_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """公共端到端业务名称形状。

    机械断言：已声明公共名称必须形如 ``<family>:<target>-<intent>`` 或
    ``<family>:<source>-to-<target>-<intent>``，意图取第一版词表。
    """
    document = _naming_document(ctx)
    if document is None:
        return result("PASS", public_names_declared=0, mechanical_half=True)
    rows = rows_of(document, "public_names", "naming-registry")
    violations = []
    for index, row in enumerate(rows):
        name = row.get("name")
        problems = []
        if not isinstance(name, str) or not PUBLIC_NAME_PATTERN.match(name):
            problems.append("name_shape_invalid")
        else:
            _, local = name.split(":", 1)
            segments = local.split("-")
            if len(segments) < 2 or segments[-1] not in PUBLIC_INTENTS:
                problems.append("intent_not_in_first_version_vocabulary")
            if "to" in segments[1:-1] and len(segments) < 4:
                problems.append("source_to_target_form_incomplete")
        if problems:
            violations.append({"index": index, "name": name, "problems": problems})
    if violations:
        return result("FAIL", public_name_violations=violations, mechanical_half=True)
    return result("PASS", public_names_declared=len(rows), mechanical_half=True)


def check_nam_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一版公共意图词表。

    机械断言：已声明公共意图必须落在
    plan/create/iterate/review/audit/repair/migrate/publish 内。
    """
    document = _naming_document(ctx)
    if document is None:
        return result("PASS", public_names_declared=0, mechanical_half=True)
    rows = rows_of(document, "public_names", "naming-registry")
    violations = [
        {"index": index, "name": row.get("name"), "intent": row.get("intent")}
        for index, row in enumerate(rows)
        if row.get("intent") not in PUBLIC_INTENTS
    ]
    if violations:
        return result("FAIL", intents_outside_vocabulary=violations, mechanical_half=True)
    return result("PASS", public_names_declared=len(rows), mechanical_half=True)


def check_nam_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """内部工序技能命名形状。

    机械断言：已声明内部技能名必须形如 ``<family>-<subject>-<operation>``
    （单对象族可省略 subject），不得使用冒号限定名。
    """
    document = _naming_document(ctx)
    if document is None:
        return result("PASS", internal_skills_declared=0, mechanical_half=True)
    rows = rows_of(document, "internal_skills", "naming-registry")
    violations = []
    for index, row in enumerate(rows):
        name = row.get("name")
        family = row.get("family")
        problems = []
        if not _nonempty_str(family):
            problems.append("family_empty")
        if not isinstance(name, str) or ":" in name:
            problems.append("colon_qualified_name_forbidden")
        elif _nonempty_str(family):
            segments = name.split("-")
            if (
                len(segments) not in (2, 3)
                or segments[0] != family
                or not all(INTERNAL_NAME_SEGMENT.match(seg) for seg in segments)
            ):
                problems.append("internal_name_shape_invalid")
        if problems:
            violations.append({"index": index, "name": name, "problems": problems})
    if violations:
        return result("FAIL", internal_name_violations=violations, mechanical_half=True)
    return result("PASS", internal_skills_declared=len(rows), mechanical_half=True)


def check_nam_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一版内部动作词表。

    机械断言：已声明内部技能动作必须落在
    inspect/analyze/design/compose/review/repair/validate/verify/finalize 内。
    """
    document = _naming_document(ctx)
    if document is None:
        return result("PASS", internal_skills_declared=0, mechanical_half=True)
    rows = rows_of(document, "internal_skills", "naming-registry")
    violations = [
        {"index": index, "name": row.get("name"), "operation": row.get("operation")}
        for index, row in enumerate(rows)
        if row.get("operation") not in INTERNAL_ACTIONS
    ]
    if violations:
        return result("FAIL", operations_outside_vocabulary=violations, mechanical_half=True)
    return result("PASS", internal_skills_declared=len(rows), mechanical_half=True)


def check_nam_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """专属执行单元名称对应实际语义职责。

    机械断言：实际执行单元必须有稳定名称和语义职责；只有显式声明单一内部
    Skill 一对一绑定时，才检查 ``<skill>-worker`` 派生名。特殊画像必须同时给出
    执行纪律差异和后缀理由，且不再因多个 workflow 复用同一职责而失败。
    """
    document = _naming_document(ctx)
    if document is None:
        return result("PASS", execution_units_declared=0, mechanical_half=True)
    rows = rows_of(document, "execution_units", "naming-registry")
    violations = []
    for index, row in enumerate(rows):
        name = row.get("name")
        responsibility = row.get("semantic_responsibility")
        skill = row.get("bound_internal_skill")
        problems = []
        if not _nonempty_str(name):
            problems.append("name_empty")
        if not _nonempty_str(responsibility):
            problems.append("semantic_responsibility_empty")
        one_to_one = row.get("one_to_one_binding") is True
        derives = row.get("derives_name_from_internal_skill") is True
        if derives and not one_to_one:
            problems.append("name_derivation_without_one_to_one_binding")
        if derives and (not _nonempty_str(skill) or name != f"{skill}-worker"):
            problems.append("name_not_derived_with_worker_suffix")
        if one_to_one and (not _nonempty_str(skill) or name != f"{skill}-worker"):
            problems.append("one_to_one_name_mismatch")
        if row.get("special_profile") is True:
            if not _nonempty_str(row.get("execution_discipline_difference")):
                problems.append("special_profile_without_execution_discipline_difference")
            if not _nonempty_str(row.get("controlled_suffix_reason")):
                problems.append("special_profile_without_reason")
        if problems:
            violations.append({"index": index, "name": name, "problems": problems})
    if violations:
        return result("FAIL", execution_unit_naming_violations=violations, mechanical_half=True)
    return result("PASS", execution_units_declared=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# PACKAGE：平台发行包（release-packages）
# ---------------------------------------------------------------------------


def _package_rows(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "release-packages")
    if document is None:
        return None
    rows = rows_of(document, "packages", "release-packages")
    for index, row in enumerate(rows):
        if row.get("platform") not in REQUIRED_PLATFORMS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"release-packages 第 {index} 行平台非法: {row.get('platform')!r}",
            )
    return rows


def check_package_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台发行包内容边界。

    机械断言：已声明发行包不得混入其他平台专属清单、开发测试设施、源码仓说明
    或未授权内部资料；共同运行资源必须位于真实安装布局并进入载荷清单。
    """
    rows = _package_rows(ctx)
    if rows is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        problems = []
        for key in (
            "foreign_platform_manifest_files",
            "dev_test_facilities",
            "source_repo_docs",
            "unauthorized_internal_materials",
        ):
            value = row.get(key)
            if value is None:
                value = []
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    f"release-packages.{key} 必须是字符串数组",
                )
            if value:
                problems.append(f"{key}:{sorted(set(value))}")
        for res_index, resource in enumerate(row.get("shared_resources") or []):
            if not isinstance(resource, dict):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "release-packages.shared_resources 行必须是对象",
                )
            if (
                resource.get("in_real_install_layout") is not True
                or resource.get("in_payload_manifest") is not True
            ):
                problems.append(f"shared_resource_unplaced:{res_index}")
        if problems:
            violations.append({"index": index, "platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", package_content_violations=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(rows), mechanical_half=True)


def check_package_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """发布构建归一化与构建器记录。

    机械断言：已声明发行包必须固定或归一化六个构建维度，并记录构建器及其版本。
    """
    rows = _package_rows(ctx)
    if rows is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        problems = []
        normalization = row.get("build_normalization")
        if not isinstance(normalization, dict):
            problems.append("build_normalization_missing")
        else:
            missing = [
                field for field in BUILD_NORMALIZATION_FIELDS
                if normalization.get(field) is not True
            ]
            if missing:
                problems.append(f"normalization_missing:{missing}")
        if not _nonempty_str(row.get("builder")):
            problems.append("builder_empty")
        if not _nonempty_str(row.get("builder_version")):
            problems.append("builder_version_empty")
        if problems:
            violations.append({"index": index, "platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", build_normalization_violations=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(rows), mechanical_half=True)


def check_package_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """相同输入重复构建摘要一致。

    机械断言：已声明发行包必须至少记录两次干净构建且载荷摘要全部一致；
    不一致时不得声明可重复构建或稳定发布。
    """
    rows = _package_rows(ctx)
    if rows is None:
        return result("PASS", packages_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        builds = row.get("clean_builds")
        if builds is None:
            builds = []
        if not isinstance(builds, list) or not all(
            isinstance(item, dict) for item in builds
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "release-packages.clean_builds 必须是对象数组"
            )
        problems = []
        digests = [build.get("payload_digest") for build in builds]
        if len(builds) < 2:
            problems.append("fewer_than_two_clean_builds")
        elif any(not is_hex64(digest) for digest in digests):
            problems.append("payload_digest_invalid")
        elif len(set(digests)) != 1:
            problems.append("payload_digest_mismatch")
            if row.get("reproducible_build_claimed") is True:
                problems.append("reproducible_build_claimed_despite_mismatch")
            if row.get("stable_release") is True:
                problems.append("stable_release_despite_mismatch")
        if problems:
            violations.append({"index": index, "platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", reproducibility_violations=violations, mechanical_half=True)
    return result("PASS", packages_declared=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# PLAT：平台投影与发行（platform-projections / platform-restrictions）
# ---------------------------------------------------------------------------


def check_plat_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """四平台完整发行是可选目标。

    机械断言：仅当声明四平台完整发行时，四个必需平台必须齐备且各自可安装、
    可发现、可调用、可诊断，锁定同一技能族版本、来源修订摘要与真实安装调用证据。
    """
    document = _projection_document(ctx)
    if document is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    if document.get("four_platform_full_release_declared") is not True:
        return result("PASS", full_release_declared=False, mechanical_half=True)
    rows = rows_of(document, "projections", "platform-projections")
    platforms = {row.get("platform"): row for row in rows}
    violations = []
    missing_platforms = sorted(set(REQUIRED_PLATFORMS) - set(platforms))
    if missing_platforms:
        violations.append({"problem": "missing_platforms", "platforms": missing_platforms})
    versions = set()
    revisions = set()
    for platform in REQUIRED_PLATFORMS:
        row = platforms.get(platform)
        if row is None:
            continue
        missing_attrs = [
            attribute for attribute in FULL_RELEASE_PLATFORM_ATTRIBUTES
            if row.get(attribute) is not True
        ]
        if missing_attrs:
            violations.append({"platform": platform, "missing": missing_attrs})
        artifact = row.get("artifact")
        if not isinstance(artifact, dict):
            violations.append({"platform": platform, "problem": "artifact_missing"})
            continue
        versions.add(artifact.get("family_version"))
        digest = artifact.get("source_revision_digest")
        if is_hex64(digest):
            revisions.add(digest)
        else:
            violations.append({"platform": platform, "problem": "source_revision_digest_invalid"})
        if not _nonempty_list(artifact.get("real_install_invocation_evidence")):
            violations.append({"platform": platform, "problem": "real_install_invocation_evidence_missing"})
    if not violations and (len(versions) != 1 or None in versions):
        violations.append({"problem": "family_version_not_locked", "versions": sorted(str(v) for v in versions)})
    if not violations and len(revisions) != 1:
        violations.append({"problem": "source_revision_not_locked"})
    if violations:
        return result("FAIL", full_release_violations=violations, mechanical_half=True)
    return result(
        "PASS",
        full_release_platforms=sorted(platforms),
        source_revision_digest=revisions.pop(),
        mechanical_half=True,
    )


def check_plat_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """新增必需平台沿用同一套标准。

    机械断言：已声明的新增必需平台必须复用共同业务能力契约、成熟度模型与
    评估规则，不得另建平台专属标准。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if row.get("newly_required_platform") is not True:
            continue
        standards = row.get("reused_common_standards")
        if not isinstance(standards, dict):
            violations.append(
                {"platform": row.get("platform"), "problem": "reused_common_standards_missing"}
            )
            continue
        problems = [
            field
            for field in ("business_capability_contract", "maturity_model", "evaluation_rules")
            if standards.get(field) != "common"
        ]
        if problems:
            violations.append({"platform": row.get("platform"), "not_common": problems})
    if violations:
        return result("FAIL", platform_specific_standards=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """四平台逻辑名称一致。

    机械断言：已声明各平台的技能族逻辑名、固定入口名与命名端到端入口逻辑名
    必须跨平台一致。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    declared = [row for row in rows if isinstance(row.get("logical_names"), dict)]
    if len(declared) < 2:
        return result("PASS", platforms_with_logical_names=len(declared), mechanical_half=True)
    families = set()
    fixed_maps = set()
    named_sets = set()
    for row in declared:
        names = row["logical_names"]
        families.add(names.get("family"))
        fixed = names.get("fixed_entries")
        if not isinstance(fixed, dict):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections {row.get('platform')} logical_names.fixed_entries 必须是对象",
            )
        fixed_maps.add(json_stable(fixed))
        named = names.get("named_entries")
        if not isinstance(named, list) or not all(isinstance(item, str) for item in named):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections {row.get('platform')} logical_names.named_entries 必须是字符串数组",
            )
        named_sets.add(frozenset(named))
    violations = []
    if len(families) != 1 or None in families:
        violations.append({"problem": "family_name_diverges", "families": sorted(str(f) for f in families)})
    if len(fixed_maps) != 1:
        violations.append({"problem": "fixed_entry_names_diverge"})
    if len(named_sets) != 1:
        violations.append({"problem": "named_entry_sets_diverge"})
    if violations:
        return result("FAIL", logical_name_divergence=violations, mechanical_half=True)
    return result("PASS", platforms_compared=len(declared), mechanical_half=True)


def check_plat_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """无命名空间平台的适配器一一映射。

    机械断言：已声明不支持原生限定名称的平台必须提供一一映射、help 展示逻辑名
    与物理调用方式并保持业务意图不变。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if row.get("native_qualified_name_support") is not False:
            continue
        mapping = row.get("adapter_mapping")
        if not isinstance(mapping, dict):
            violations.append(
                {"platform": row.get("platform"), "problem": "adapter_mapping_missing"}
            )
            continue
        problems = [
            field
            for field in ("one_to_one", "help_displays_logical_and_physical",
                          "business_intent_preserved")
            if mapping.get(field) is not True
        ]
        if problems:
            violations.append({"platform": row.get("platform"), "missing": problems})
    if violations:
        return result("FAIL", adapter_mapping_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """开发阶段顺序投影的如实状态报告。

    机械断言：存在未完成平台时，文档必须声明状态报告；不得把非 complete
    状态的行报告为已完成。
    """
    document = _projection_document(ctx)
    if document is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    rows = rows_of(document, "projections", "platform-projections")
    violations = []
    incomplete = []
    for index, row in enumerate(rows):
        status = row.get("projection_status")
        if status not in {"complete", "in_progress", "not_started"}:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections 第 {index} 行 projection_status 非法: {status!r}",
            )
        if status != "complete":
            incomplete.append(row.get("platform"))
        if status != "complete" and row.get("reported_as_complete") is True:
            violations.append({"platform": row.get("platform"), "problem": "reported_as_complete"})
    if incomplete and document.get("status_report_declares_incomplete") is not True:
        violations.append(
            {"problem": "incomplete_platforms_not_declared_in_status_report",
             "platforms": sorted(incomplete)}
        )
    if violations:
        return result("FAIL", status_report_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """四平台覆盖固定入口、命名入口、严格方法与核心结果。

    机械断言：已声明各平台必须覆盖三项固定人类入口、全部稳定命名端到端入口、
    全部稳定严格方法与共同核心业务结果。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    fields = (
        "fixed_entries_covered",
        "stable_named_entries_covered",
        "stable_strict_methods_covered",
        "core_business_results_covered",
    )
    violations = _bool_rows(rows, fields, row_label="platform")
    if violations:
        return result("FAIL", coverage_below_requirement=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """四平台共享共同业务定义。

    机械断言：已声明各平台必须共享业务能力、方法契约、输入输出含义、权限边界、
    验收条件与错误语义。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = _bool_rows(rows, SHARED_DEFINITION_FIELDS, row_label="platform")
    if violations:
        return result("FAIL", shared_definitions_missing=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """专属执行契约由平台无关权威定义。

    机械断言：已声明执行单元必须由平台无关执行契约定义业务目标、输入输出、
    工具需求、权限与验收。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        units = _sub_rows(row, "execution_units", row.get("platform"))
        if units is None:
            continue
        for unit_index, unit in enumerate(units):
            problems = [
                field
                for field in ("business_goal", "inputs_outputs", "tool_requirements",
                              "permissions", "acceptance")
                if not _nonempty_str(unit.get(field))
            ]
            if unit.get("defined_by_platform_independent_contract") is not True:
                problems.append("not_defined_by_platform_independent_contract")
            if problems:
                violations.append(
                    {"platform": row.get("platform"), "unit_index": unit_index,
                     "problems": problems}
                )
    if violations:
        return result("FAIL", execution_contract_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台执行载体只是契约投影。

    机械断言：已声明文件型执行单元、运行期智能体或会话委派必须是平台无关
    执行契约的投影，不得形成独立业务真源。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        carriers = _sub_rows(row, "execution_carriers", row.get("platform"))
        if carriers is None:
            continue
        for carrier_index, carrier in enumerate(carriers):
            if (
                carrier.get("is_projection_of_platform_independent_contract") is not True
                or carrier.get("independent_business_source") is True
            ):
                violations.append(
                    {"platform": row.get("platform"), "carrier_index": carrier_index,
                     "kind": carrier.get("kind")}
                )
    if violations:
        return result("FAIL", independent_execution_sources=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台独有增强必须是受控声明。

    机械断言：已声明平台独有连接器、浏览器、钩子或扩展必须在能力矩阵中登记
    为受控增强。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        extensions = _sub_rows(row, "platform_specific_extensions", row.get("platform"))
        if extensions is None:
            continue
        for ext_index, extension in enumerate(extensions):
            if (
                extension.get("declared_in_capability_matrix") is not True
                or extension.get("controlled") is not True
            ):
                violations.append(
                    {"platform": row.get("platform"), "extension_index": ext_index,
                     "name": extension.get("name")}
                )
    if violations:
        return result("FAIL", uncontrolled_platform_extensions=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台差异必须在能力矩阵记录四要素。

    机械断言：已声明能力差异必须记录受影响能力、语义差异、替代路径与验证证据。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        differences = _sub_rows(row, "capability_differences", row.get("platform"))
        if differences is None:
            continue
        for diff_index, difference in enumerate(differences):
            problems = []
            if not _nonempty_list(difference.get("affected_capabilities")):
                problems.append("affected_capabilities_missing")
            if not _nonempty_str(difference.get("semantic_difference")):
                problems.append("semantic_difference_missing")
            if not _nonempty_str(difference.get("alternative_path")):
                problems.append("alternative_path_missing")
            if not _nonempty_list(difference.get("verification_evidence")):
                problems.append("verification_evidence_missing")
            if problems:
                violations.append(
                    {"platform": row.get("platform"), "difference_index": diff_index,
                     "problems": problems}
                )
    if violations:
        return result("FAIL", capability_difference_records_incomplete=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """文件生成不得替代真实验证。

    机械断言：已声明投影不得把文件/目录生成当作真实安装、发现、调用和结果
    验证的证据。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if (
            row.get("files_generated_counts_as_verification") is True
            or row.get("generation_only_claimed_as_verification") is True
        ):
            violations.append(row.get("platform"))
        verification = row.get("real_verification")
        if row.get("files_generated") is True and isinstance(verification, dict):
            missing = [
                field
                for field in ("install_verified", "discovery_verified",
                              "invocation_verified", "result_verified")
                if verification.get(field) is not True
            ]
            if missing:
                violations.append({"platform": row.get("platform"), "missing": missing})
    if violations:
        return result("FAIL", generation_treated_as_verification=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台差异必须显式登记。

    机械断言：已声明偏离共同业务定义的差异必须登记于能力档案、投影合同或
    能力矩阵，不得只存在于适配代码。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        deviations = _sub_rows(row, "deviations", row.get("platform"))
        if deviations is None:
            continue
        for dev_index, deviation in enumerate(deviations):
            if (
                deviation.get("registered_in_matrix_or_contract") is not True
                or deviation.get("exists_only_in_adapter_code") is True
            ):
                violations.append(
                    {"platform": row.get("platform"), "deviation_index": dev_index,
                     "name": deviation.get("name")}
                )
    if violations:
        return result("FAIL", unregistered_deviations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """每项登记差异必须有对应测试。

    机械断言：已声明平台差异必须具有验证其映射、替代路径或受限状态的测试。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        deviations = _sub_rows(row, "deviations", row.get("platform"))
        if deviations is None:
            continue
        for dev_index, deviation in enumerate(deviations):
            if not _nonempty_list(deviation.get("verification_tests")):
                violations.append(
                    {"platform": row.get("platform"), "deviation_index": dev_index,
                     "name": deviation.get("name")}
                )
    if violations:
        return result("FAIL", deviations_without_tests=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台特有内容不得写回共享业务规则。

    机械断言：已声明投影不得把平台特有目录、命令、工具名和委派方式写回共享
    业务规则正文。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = [
        row.get("platform")
        for row in rows
        if row.get("platform_specifics_written_back_to_shared_rules") is True
    ]
    if violations:
        return result("FAIL", platform_specifics_written_back=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """Claude Code agents/*.md 只是执行契约投影。

    机械断言：已声明持久执行单元文件必须位于 agents/ 目录且声明为投影，不得
    作为独立业务真源。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        files = _sub_rows(row, "persistent_agent_files", row.get("platform"))
        if files is None:
            continue
        for file_index, item in enumerate(files):
            problems = []
            path = item.get("path")
            if not isinstance(path, str) or not path.startswith("agents/"):
                problems.append("path_not_under_agents_directory")
            if item.get("treated_as_projection_only") is not True:
                problems.append("not_declared_as_projection")
            if item.get("independent_business_source") is True:
                problems.append("independent_business_source")
            if problems:
                violations.append(
                    {"platform": row.get("platform"), "file_index": file_index,
                     "problems": problems}
                )
    if violations:
        return result("FAIL", persistent_agent_file_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """各平台分别维护版本化档案与合同。

    机械断言：已声明平台必须分别维护具有版本和内容摘要的能力档案与投影合同。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        for key in ("capability_profile", "projection_contract"):
            item = row.get(key)
            if not isinstance(item, dict):
                violations.append({"platform": row.get("platform"), "problem": f"{key}_missing"})
                continue
            if not _nonempty_str(item.get("version")):
                violations.append({"platform": row.get("platform"), "problem": f"{key}_version_empty"})
            if not is_hex64(item.get("content_digest")):
                violations.append({"platform": row.get("platform"), "problem": f"{key}_digest_invalid"})
    if violations:
        return result("FAIL", versioned_artifacts_missing=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """档案与合同记录内容最小集。

    机械断言：已声明平台档案与投影合同必须记录官方来源、获取时间、内容摘要、
    适用客户端版本、失效条件、插件清单、包目录、逻辑物理映射、可见性、执行
    单元、工具、权限、钩子、连接器和安装至移除探针。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        for key in ("capability_profile", "projection_contract"):
            item = row.get(key)
            if not isinstance(item, dict):
                violations.append({"platform": row.get("platform"), "problem": f"{key}_missing"})
                continue
            missing = [
                field
                for field in PLATFORM_PROFILE_REQUIRED_FIELDS
                if not _nonempty_str(item.get(field))
                and not _nonempty_list(item.get(field))
                and not (isinstance(item.get(field), dict) and item.get(field))
                and item.get(field) is not True
            ]
            if missing:
                violations.append(
                    {"platform": row.get("platform"), "carrier": key, "missing": missing}
                )
    if violations:
        return result("FAIL", profile_records_incomplete=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_026(ctx: dict[str, Any]) -> dict[str, Any]:
    """适配器不得在冲突证据中挑选有利事实。

    机械断言：存在证据冲突时，已声明处置必须是报告未评估或受阻，不得声明
    适配器自选有利事实形成支持结论。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        conflict = row.get("conflict_resolution")
        if not isinstance(conflict, dict):
            continue
        if conflict.get("evidence_conflict_present") is not True:
            continue
        problems = []
        if conflict.get("resolution") not in {"report_not_evaluated", "report_blocked"}:
            problems.append("resolution_not_limited_to_not_evaluated_or_blocked")
        if conflict.get("adapter_selected_favorable_facts") is True:
            problems.append("adapter_selected_favorable_facts")
        if problems:
            violations.append({"platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", conflict_resolution_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_027(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台变化触发依赖失效与重新验证。

    机械断言：已声明能力、客户端版本或投影合同变化后，依赖的生成投影、测试
    证据和发布结论必须失效并重新验证。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if row.get("capability_or_contract_changed") is not True:
            continue
        policy = row.get("change_invalidation_policy")
        if not isinstance(policy, dict):
            violations.append(
                {"platform": row.get("platform"), "problem": "change_invalidation_policy_missing"}
            )
            continue
        problems = [
            field
            for field in ("dependent_projections_invalidated", "test_evidence_invalidated",
                          "release_conclusions_invalidated", "reverification_required")
            if policy.get(field) is not True
        ]
        if problems:
            violations.append({"platform": row.get("platform"), "missing": problems})
    if violations:
        return result("FAIL", invalidation_policy_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_028(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次发布声明支持矩阵。

    机械断言：已声明发布必须记录由宿主平台、操作系统、处理器架构和运行时
    版本构成的支持矩阵。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        releases = _sub_rows(row, "releases", row.get("platform"))
        if releases is None:
            continue
        for release_index, release in enumerate(releases):
            matrix = release.get("support_matrix")
            if not isinstance(matrix, dict):
                violations.append(
                    {"platform": row.get("platform"), "release_index": release_index,
                     "problem": "support_matrix_missing"}
                )
                continue
            missing = [
                field for field in SUPPORT_MATRIX_FIELDS if not _nonempty_str(matrix.get(field))
            ]
            if missing:
                violations.append(
                    {"platform": row.get("platform"), "release_index": release_index,
                     "missing": missing}
                )
    if violations:
        return result("FAIL", support_matrix_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_029(ctx: dict[str, Any]) -> dict[str, Any]:
    """每平台至少一个真实验证的非空环境组合。

    机械断言：已声明平台必须至少一个公开、可重建、经过真实验证的非空环境组合。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        combinations = _sub_rows(row, "environment_combinations", row.get("platform"))
        if combinations is None:
            combinations = []
        if not combinations:
            violations.append({"platform": row.get("platform"), "problem": "no_environment_combination"})
            continue
        for comb_index, combination in enumerate(combinations):
            problems = [
                field
                for field in ("public", "rebuildable", "real_verified", "non_empty")
                if combination.get(field) is not True
            ]
            if problems:
                violations.append(
                    {"platform": row.get("platform"), "combination_index": comb_index,
                     "missing": problems}
                )
    if violations:
        return result("FAIL", environment_combination_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_031(ctx: dict[str, Any]) -> dict[str, Any]:
    """收紧声明不得掩盖必需平台缺失。

    机械断言：已声明缺失平台的理由为政策收紧时，必须同时声明部分支持表面，
    且不得声明掩盖完全缺失。
    """
    document = _doc(ctx, "platform-restrictions")
    if document is None:
        return result("PASS", restrictions_declared=False, mechanical_half=True)
    declarations = rows_of(document, "missing_platform_declarations", "platform-restrictions")
    violations = []
    for index, declaration in enumerate(declarations):
        problems = []
        if declaration.get("platform") not in REQUIRED_PLATFORMS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-restrictions.missing_platform_declarations 第 {index} 行平台非法",
            )
        if declaration.get("conceals_complete_absence") is True:
            problems.append("conceals_complete_absence")
        if declaration.get("reason") == "policy_tightening" and (
            declaration.get("partial_surface_supported") is not True
        ):
            problems.append("policy_tightening_without_partial_surface")
        if problems:
            violations.append(
                {"index": index, "platform": declaration.get("platform"), "problems": problems}
            )
    if violations:
        return result("FAIL", restriction_concealment_violations=violations, mechanical_half=True)
    return result("PASS", missing_platform_declarations=len(declarations), mechanical_half=True)


def check_plat_032(ctx: dict[str, Any]) -> dict[str, Any]:
    """支持矩阵外环境必须显式标记。

    机械断言：已声明矩阵外环境必须标记为未评估或不支持，不得默认为支持。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        environments = _sub_rows(row, "out_of_matrix_environments", row.get("platform"))
        if environments is None:
            continue
        for env_index, environment in enumerate(environments):
            problems = []
            if environment.get("status") not in {"not_evaluated", "unsupported"}:
                problems.append("status_not_marked")
            if environment.get("defaulted_to_supported") is True:
                problems.append("defaulted_to_supported")
            if problems:
                violations.append(
                    {"platform": row.get("platform"), "environment_index": env_index,
                     "problems": problems}
                )
    if violations:
        return result("FAIL", out_of_matrix_environments_unmarked=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_033(ctx: dict[str, Any]) -> dict[str, Any]:
    """支持矩阵与边界必须公开展示。

    机械断言：已声明发布必须在 help、发布记录和发布渠道说明展示支持矩阵及
    未评估或不支持边界。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    fields = (
        "help_displays_matrix",
        "release_notes_display_matrix",
        "channel_description_displays_matrix",
        "displays_unsupported_boundaries",
    )
    violations = []
    for row in rows:
        publication = row.get("support_matrix_publication")
        if publication is None:
            continue
        if not isinstance(publication, dict):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections {row.get('platform')} support_matrix_publication 必须是对象",
            )
        missing = [field for field in fields if publication.get(field) is not True]
        if missing:
            violations.append({"platform": row.get("platform"), "missing": missing})
    if violations:
        return result("FAIL", support_matrix_publication_missing=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_036(ctx: dict[str, Any]) -> dict[str, Any]:
    """等价替代路径记录实现差异。

    机械断言：已声明首选执行形态缺失的替代必须满足同一业务契约、隔离等级与
    验收，记录实现差异，且不得报告公共业务能力缺失。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        substitutions = _sub_rows(row, "execution_form_substitutions", row.get("platform"))
        if substitutions is None:
            continue
        for sub_index, substitution in enumerate(substitutions):
            problems = []
            if not _nonempty_str(substitution.get("equivalent_alternative")):
                problems.append("equivalent_alternative_missing")
            if substitution.get("satisfies_same_contract_isolation_acceptance") is not True:
                problems.append("same_contract_not_satisfied")
            if substitution.get("implementation_difference_recorded") is not True:
                problems.append("implementation_difference_not_recorded")
            if substitution.get("reports_capability_missing") is True:
                problems.append("reports_capability_missing")
            if problems:
                violations.append(
                    {"platform": row.get("platform"), "substitution_index": sub_index,
                     "problems": problems}
                )
    if violations:
        return result("FAIL", substitution_record_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_037(ctx: dict[str, Any]) -> dict[str, Any]:
    """适配变化必须提升共同技能族修订。

    机械断言：已声明适配层、清单、调用映射或安装行为变化的平台必须提升共同
    技能族修订版本并记录受影响平台。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if row.get("adaptation_changed") is not True:
            continue
        problems = []
        if row.get("family_revision_bumped") is not True:
            problems.append("family_revision_not_bumped")
        if not _nonempty_list(row.get("affected_platforms_recorded")):
            problems.append("affected_platforms_not_recorded")
        if problems:
            violations.append({"platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", adaptation_change_not_propagated=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_038(ctx: dict[str, Any]) -> dict[str, Any]:
    """适配变化后四平台包从同一修订重新生成并复验。

    机械断言：已声明适配变化的平台必须从同一共同技能族修订重新生成四个平台
    发行包，并重新执行漂移、摘要和联合发布验证；不得只发布单平台同版本变体。
    """
    rows = _projection_rows(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if row.get("adaptation_changed") is not True:
            continue
        problems = []
        if row.get("regenerated_from_same_revision") is not True:
            problems.append("not_regenerated_from_same_revision")
        if row.get("drift_digest_joint_release_reverified") is not True:
            problems.append("joint_release_not_reverified")
        if row.get("single_platform_variant_only") is True:
            problems.append("single_platform_variant_only")
        if problems:
            violations.append({"platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", joint_regeneration_violations=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# SOURCE：源码与投影治理（source-projections）
# ---------------------------------------------------------------------------


def _source_document(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return _doc(ctx, "source-projections")


def check_source_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """单一平台无关业务源码与确定性投影。

    机械断言：已声明者必须维护单一平台无关业务源码并确定性生成各平台投影。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    root = document.get("business_source_root")
    if not isinstance(root, dict):
        return result("FAIL", reason="business_source_root_missing", mechanical_half=True)
    problems = []
    if not _nonempty_str(root.get("path")):
        problems.append("source_root_path_empty")
    if root.get("single_platform_independent_source") is not True:
        problems.append("not_single_platform_independent_source")
    if root.get("deterministic_projection_generation") is not True:
        problems.append("projection_generation_not_deterministic")
    if problems:
        return result("FAIL", source_root_problems=problems, mechanical_half=True)
    return result("PASS", source_root=root.get("path"), mechanical_half=True)


def check_source_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台加载目录不是业务源码。

    机械断言：已声明者不得把平台加载目录当作业务源码，也不得手工维护多份
    内容近似的 SKILL.md。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    root = document.get("business_source_root")
    if not isinstance(root, dict):
        return result("FAIL", reason="business_source_root_missing", mechanical_half=True)
    problems = []
    if root.get("platform_load_directory_is_source") is True:
        problems.append("platform_load_directory_is_source")
    copies = root.get("hand_maintained_skill_md_copies")
    if copies is not None and not isinstance(copies, int):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "source-projections.business_source_root.hand_maintained_skill_md_copies 必须是整数",
        )
    if isinstance(copies, int) and copies > 1:
        problems.append(f"hand_maintained_skill_md_copies:{copies}")
    if problems:
        return result("FAIL", second_source_problems=problems, mechanical_half=True)
    return result("PASS", single_source_maintained=True, mechanical_half=True)


def check_source_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """迁移期源码根职责。

    机械断言：已声明源码根必须承担统一技能源码根职责，且不得与平台目录
    双向编辑。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    root = document.get("business_source_root")
    if not isinstance(root, dict):
        return result("FAIL", reason="business_source_root_missing", mechanical_half=True)
    problems = []
    if root.get("carries_unified_source_root_role") is not True:
        problems.append("unified_source_root_role_not_carried")
    if root.get("bidirectional_editing_with_platform_dirs") is True:
        problems.append("bidirectional_editing_with_platform_dirs")
    if problems:
        return result("FAIL", source_root_role_problems=problems, mechanical_half=True)
    return result("PASS", unified_source_root=True, mechanical_half=True)


def check_source_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """固定入口、命名入口与内部技能位于同一源码根。

    机械断言：已声明技能位置必须全部指向同一业务源码根。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    locations = rows_of(document, "skill_locations", "source-projections")
    if not locations:
        return result("PASS", skill_locations_declared=0, mechanical_half=True)
    roots = set()
    violations = []
    for index, row in enumerate(locations):
        if row.get("kind") not in SOURCE_ROOT_SKILL_KINDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"source-projections.skill_locations 第 {index} 行 kind 非法: {row.get('kind')!r}",
            )
        root = row.get("root")
        if not _nonempty_str(root):
            violations.append({"index": index, "skill": row.get("skill"), "problem": "root_empty"})
            continue
        roots.add(root)
    if len(roots) > 1:
        violations.append({"problem": "multiple_source_roots", "roots": sorted(roots)})
    if violations:
        return result("FAIL", source_root_split_violations=violations, mechanical_half=True)
    return result("PASS", skill_locations_declared=len(locations), mechanical_half=True)


def check_source_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """可见性由元数据与清单区分。

    机械断言：已声明可见性必须由权威元数据和平台发布清单区分，不得通过复制
    或移动到不同业务源码根实现。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "visibility_declarations", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("visibility") not in {"public", "internal"}:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"source-projections.visibility_declarations 第 {index} 行 visibility 非法",
            )
        if row.get("distinguished_by_metadata") is not True:
            problems.append("not_distinguished_by_metadata")
        if row.get("distinguished_by_copy_or_move") is True:
            problems.append("distinguished_by_copy_or_move")
        if problems:
            violations.append({"index": index, "skill": row.get("skill"), "problems": problems})
    if violations:
        return result("FAIL", visibility_distinction_violations=violations, mechanical_half=True)
    return result("PASS", visibility_declarations=len(rows), mechanical_half=True)


def check_source_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """隐藏内部技能保持包内相对路径。

    机械断言：已声明被平台隐藏的内部技能必须保持对自身 references/scripts/assets
    的稳定包内相对路径。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "hidden_internal_skills", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        if row.get("intra_package_relative_paths_preserved") is not True:
            violations.append({"index": index, "skill": row.get("skill")})
    if violations:
        return result("FAIL", hidden_skill_paths_unstable=violations, mechanical_half=True)
    return result("PASS", hidden_internal_skills=len(rows), mechanical_half=True)


def check_source_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台覆盖层只表达平台差异。

    机械断言：已声明覆盖层不得拥有或重定义共同业务语义。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "overlays", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("expresses_platform_differences_only") is not True:
            problems.append("not_limited_to_platform_differences")
        if row.get("owns_common_business_semantics") is True:
            problems.append("owns_common_business_semantics")
        if row.get("redefines_common_business_semantics") is True:
            problems.append("redefines_common_business_semantics")
        if problems:
            violations.append({"index": index, "overlay": row.get("overlay"), "problems": problems})
    if violations:
        return result("FAIL", overlay_semantics_violations=violations, mechanical_half=True)
    return result("PASS", overlays_declared=len(rows), mechanical_half=True)


def check_source_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """覆盖层只含白名单补丁。

    机械断言：已声明覆盖补丁必须位于投影合同版本化白名单内。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "overlay_patches", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("in_versioned_whitelist") is not True:
            problems.append("not_in_versioned_whitelist")
        if not _nonempty_str(row.get("whitelist_ref")):
            problems.append("whitelist_ref_empty")
        if problems:
            violations.append({"index": index, "patch": row.get("patch"), "problems": problems})
    if violations:
        return result("FAIL", patches_outside_whitelist=violations, mechanical_half=True)
    return result("PASS", overlay_patches=len(rows), mechanical_half=True)


def check_source_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """覆盖补丁记录最小契约。

    机械断言：已声明覆盖补丁必须记录基础内容摘要、补丁摘要、所有者、理由、
    适用平台版本范围和复核期限。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "overlay_patches", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if not is_hex64(row.get("base_content_digest")):
            problems.append("base_content_digest_invalid")
        if not is_hex64(row.get("patch_digest")):
            problems.append("patch_digest_invalid")
        for field in OVERLAY_PATCH_REQUIRED_FIELDS:
            if not _nonempty_str(row.get(field)):
                problems.append(f"{field}_empty")
        if problems:
            violations.append({"index": index, "patch": row.get("patch"), "problems": problems})
    if violations:
        return result("FAIL", patch_records_incomplete=violations, mechanical_half=True)
    return result("PASS", overlay_patches=len(rows), mechanical_half=True)


def check_source_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """基础变化后补丁失效并重新复核。

    机械断言：已声明基础内容、平台能力或客户端版本变化的补丁必须失效并
    重新复核。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "overlay_patches", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        if row.get("base_changed") is not True:
            continue
        problems = []
        if row.get("invalidated") is not True:
            problems.append("not_invalidated")
        if row.get("re_reviewed") is not True:
            problems.append("not_re_reviewed")
        if problems:
            violations.append({"index": index, "patch": row.get("patch"), "problems": problems})
    if violations:
        return result("FAIL", stale_patches_uninvalidated=violations, mechanical_half=True)
    return result("PASS", overlay_patches=len(rows), mechanical_half=True)


def check_source_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台覆盖不得修改共同语义面。

    机械断言：已声明覆盖补丁不得修改公共输入输出、授权、副作用、错误、
    质量门或验收条件。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "overlay_patches", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        modifies = [field for field in OVERLAY_PROTECTED_FIELDS if row.get(field) is True]
        if modifies:
            violations.append({"index": index, "patch": row.get("patch"), "modifies": modifies})
    if violations:
        return result("FAIL", overlay_modifies_protected_semantics=violations, mechanical_half=True)
    return result("PASS", overlay_patches=len(rows), mechanical_half=True)


def check_source_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台投影自包含。

    机械断言：已声明平台投影必须自包含所需技能、参考资料、程序、清单与已声明
    运行依赖，不得依赖其他平台包。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "platform_projections", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if row.get("self_contained") is not True:
            problems.append("not_self_contained")
        if row.get("depends_on_other_platform_packages") is True:
            problems.append("depends_on_other_platform_packages")
        if problems:
            violations.append({"index": index, "platform": row.get("platform"), "problems": problems})
    if violations:
        return result("FAIL", projection_self_containment_violations=violations, mechanical_half=True)
    return result("PASS", platform_projections=len(rows), mechanical_half=True)


def check_source_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """安装后投影不得反向引用。

    机械断言：已声明安装后投影不得反向引用源码仓库、相邻工程或构建者用户
    主目录中的文件。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "platform_projections", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        references = row.get("reverse_references")
        if references is None:
            references = []
        if not isinstance(references, list) or not all(
            isinstance(item, dict) for item in references
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "source-projections.platform_projections.reverse_references 必须是对象数组",
            )
        forbidden = [
            {"target_kind": item.get("target_kind"), "path": item.get("path")}
            for item in references
            if item.get("target_kind") in FORBIDDEN_REVERSE_REFERENCE_KINDS
        ]
        if forbidden:
            violations.append({"index": index, "platform": row.get("platform"), "references": forbidden})
    if violations:
        return result("FAIL", reverse_references_present=violations, mechanical_half=True)
    return result("PASS", platform_projections=len(rows), mechanical_half=True)


def check_source_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """投影生成器职责。

    机械断言：已声明投影生成器必须负责平台物理命名、清单、平台头部、专属
    执行单元投影和必要兼容包装。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    responsibilities = document.get("generator_responsibilities")
    if responsibilities is None:
        return result("PASS", generator_responsibilities_declared=False, mechanical_half=True)
    if not isinstance(responsibilities, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "source-projections.generator_responsibilities 必须是对象",
        )
    fields = (
        "physical_naming",
        "manifests",
        "platform_headers",
        "execution_unit_projection",
        "compatibility_wrapping",
    )
    missing = [field for field in fields if responsibilities.get(field) is not True]
    if missing:
        return result("FAIL", generator_responsibilities_missing=missing, mechanical_half=True)
    return result("PASS", generator_responsibilities=len(fields), mechanical_half=True)


def check_source_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台生成目录不得手工修改。

    机械断言：已声明平台投影不得存在手工修改的生成文件。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    rows = rows_of(document, "platform_projections", "source-projections")
    violations = []
    for index, row in enumerate(rows):
        hand_modified = row.get("hand_modified_generated_files")
        if hand_modified is None:
            hand_modified = []
        if not isinstance(hand_modified, list) or not all(
            isinstance(item, str) for item in hand_modified
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "source-projections.platform_projections.hand_modified_generated_files 必须是字符串数组",
            )
        if hand_modified or row.get("hand_modified") is True:
            violations.append(
                {"index": index, "platform": row.get("platform"),
                 "files": sorted(set(hand_modified))}
            )
    if violations:
        return result("FAIL", generated_files_hand_modified=violations, mechanical_half=True)
    return result("PASS", platform_projections=len(rows), mechanical_half=True)


def check_source_017(ctx: dict[str, Any]) -> dict[str, Any]:
    """生成器双模式。

    机械断言：已声明投影生成器必须同时提供普通构建模式和只检查漂移、不写
    文件的验证模式。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    modes = document.get("generator_modes")
    if modes is None:
        return result("PASS", generator_modes_declared=False, mechanical_half=True)
    if not isinstance(modes, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "source-projections.generator_modes 必须是对象"
        )
    problems = []
    if modes.get("build") is not True:
        problems.append("build_mode_missing")
    if modes.get("verify_only_drift_check") is not True:
        problems.append("verify_only_mode_missing")
    if problems:
        return result("FAIL", generator_modes_problems=problems, mechanical_half=True)
    return result("PASS", generator_modes_declared=True, mechanical_half=True)


def check_source_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """生成器确定性清理。

    机械断言：旧投影、已删除技能和失效清单必须由生成器依据权威输入确定性
    清理，不得依赖人工挑选。
    """
    document = _source_document(ctx)
    if document is None:
        return result("PASS", source_declared=False, mechanical_half=True)
    cleanup = document.get("cleanup_policy")
    if cleanup is None:
        return result("PASS", cleanup_policy_declared=False, mechanical_half=True)
    if not isinstance(cleanup, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "source-projections.cleanup_policy 必须是对象"
        )
    problems = []
    if cleanup.get("generator_deterministic") is not True:
        problems.append("cleanup_not_generator_deterministic")
    if cleanup.get("manual_picking") is True:
        problems.append("manual_picking")
    if problems:
        return result("FAIL", cleanup_policy_problems=problems, mechanical_half=True)
    return result("PASS", cleanup_policy_declared=True, mechanical_half=True)


# ---------------------------------------------------------------------------
# BYTECHAIN：源码到安装结果的摘要链（content-chain）
# ---------------------------------------------------------------------------


def check_bytechain_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """源码到安装结果形成可重建摘要链。

    机械断言：已声明摘要链必须覆盖源码、生成器或受控覆盖、平台投影、发布包、
    渠道下载和安装结果六个阶段，逐段携带内容摘要与来源关系，且干净再生成
    证明投影可重建。
    """
    document = _doc(ctx, "content-chain")
    if document is None:
        return result("PASS", chain_declared=False, mechanical_half=True)
    links = rows_of(document, "chain_links", "content-chain")
    stages = [link.get("stage") for link in links]
    if stages != list(CONTENT_CHAIN_STAGES):
        return result(
            "FAIL",
            reason="chain_stages_incomplete_or_out_of_order",
            declared_stages=stages,
            mechanical_half=True,
        )
    violations = []
    for index, link in enumerate(links):
        problems = []
        if not is_hex64(link.get("content_digest")):
            problems.append("content_digest_invalid")
        if not _nonempty_str(link.get("provenance_ref")):
            problems.append("provenance_ref_empty")
        if index > 0 and link.get("derived_from_previous_stage") is not True:
            problems.append("not_derived_from_previous_stage")
        if problems:
            violations.append({"stage": link.get("stage"), "problems": problems})
    regeneration = document.get("clean_regeneration")
    if not isinstance(regeneration, dict):
        violations.append({"problem": "clean_regeneration_missing"})
    else:
        problems = [
            field
            for field in ("regenerated_from_source", "projection_rebuildable", "digest_match")
            if regeneration.get(field) is not True
        ]
        if problems:
            violations.append({"problem": "clean_regeneration_incomplete", "missing": problems})
    if violations:
        return result("FAIL", content_chain_violations=violations, mechanical_half=True)
    return result("PASS", chain_links=len(links), mechanical_half=True)


# ---------------------------------------------------------------------------
# P4-D1：NAM-022..024 / SOURCE-019..020 / PUBLISH-011..016（机械执行器）
#
# 与 W2-B2 主体不同：这些规则的证据合同以"目标真实文件系统 + 治理声明"为
# 双证据面（truth_source 契约），执行器只读目标树（绝不执行、绝不写入），
# 逐机械方法返回独立 subresult（validate_method_subresults 消费）。
# ---------------------------------------------------------------------------


def _target_file(ctx: dict[str, Any], relative: str) -> Path | None:
    """目标真实文件（只读）；不存在或不可读返回 None。"""
    path = Path(ctx["target"], *relative.split("/"))
    if not path.is_file() or path.is_symlink():
        return None
    return path


def _read_target_text(ctx: dict[str, Any], relative: str) -> str | None:
    path = _target_file(ctx, relative)
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExecutorEvidenceError(
            "TARGET_FILE_UNREADABLE", f"目标文件无法读取: {relative}: {exc}"
        ) from exc


def _read_json_file(ctx: dict[str, Any], relative: str) -> dict[str, Any] | None:
    text = _read_target_text(ctx, relative)
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExecutorEvidenceError(
            "TARGET_FILE_INVALID", f"目标文件无法解析: {relative}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError("TARGET_FILE_INVALID", f"目标文件顶层必须是对象: {relative}")
    return value


_PLUGIN_MANIFEST_DIRECTORIES = {
    ".claude-plugin",
    ".codebuddy-plugin",
    ".codex-plugin",
    ".kimi-plugin",
}
# 与生产观察器 conformance_workflow.PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
# 沿用同一当前项目边界；执行器不能反向导入工作流（工作流本身导入 executors）。
PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "artifacts",
    "control",
    "dist",
    "evidence",
    "fixtures",
    "generated",
    "node_modules",
    "tests",
}
_METADATA_FIELDS = ("name", "version", "author", "license", "description")
_AUTHOR_FIELDS = ("name", "email", "url")


def _plugin_manifest_paths(ctx: dict[str, Any]) -> list[str]:
    """发现目标树中的真实宿主插件清单，不依赖目标自填治理文档。"""
    target = Path(ctx["target"])
    paths: list[str] = []
    for path in target.rglob("plugin.json"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(target)
        if any(part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS for part in relative.parts):
            continue
        if not any(part in _PLUGIN_MANIFEST_DIRECTORIES for part in relative.parts):
            continue
        paths.append(relative.as_posix())
    return sorted(set(paths))


def _metadata_value(field: str, value: Any) -> Any:
    """按 npm/plugin 元数据的值结构归一化，而不是用文本包含判断。"""
    if field != "author":
        return value
    if isinstance(value, str):
        return {"name": value.strip()}
    if isinstance(value, dict):
        return {
            key: item.strip() if isinstance(item, str) else item
            for key, item in value.items()
            if key in _AUTHOR_FIELDS
        }
    return value


def _metadata_fields(value: dict[str, Any]) -> list[str]:
    return [field for field in _METADATA_FIELDS if field in value]


def _verified_derived_from(
    ctx: dict[str, Any], row: dict[str, Any], package: dict[str, Any]
) -> bool:
    """仅接受可读取、可解析且内容确实等于 package 真源的派生声明。

    该证明只用于识别真实关系；它不会把与 package 真源不同的目标字段
    变成通过结果，因此漂移仍然失败关闭。
    """
    derived_from = row.get("derived_from")
    if not _nonempty_str(derived_from):
        return False
    source = _read_json_file(ctx, derived_from)
    if source is None:
        return False
    for field in row.get("fields", []):
        if field in _METADATA_FIELDS and _metadata_value(field, source.get(field)) != _metadata_value(field, package.get(field)):
            return False
    return True


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


def _static_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "static_scan", status, "executor_static_scan_observation", **evidence
    )


def _schema_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "schema_validation", status, "executor_schema_validation_observation", **evidence
    )


def _digest_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "digest_verification", status, "executor_digest_verification_observation", **evidence
    )


def _sfa_product_gate(
    ctx: dict[str, Any], *, row_factory=_static_row
) -> dict[str, Any] | None:
    """SFA 自身协议规则的产品身份适用性门禁。"""
    scope = ctx.get("scope")
    plugin_project = scope.get("plugin_project") if isinstance(scope, dict) else None
    plugin = plugin_project.get("plugin") if isinstance(plugin_project, dict) else None
    plugin_id = plugin.get("id") if isinstance(plugin, dict) else None
    if not _nonempty_str(plugin_id):
        return _finish(
            [row_factory("EVIDENCE_MISSING", reason="target_plugin_identity_unconfirmed")],
            target_plugin_id=None,
        )
    if plugin_id != "skill-family-audit":
        return _finish(
            [row_factory("NOT_APPLICABLE", reason="target_plugin_is_not_skill_family_audit",
                         target_plugin_id=plugin_id)],
            target_plugin_id=plugin_id,
        )
    return None


#: 冒号式身份：段内小写字母开头，段间单个冒号。
_COLON_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")
#: 点式身份：至少两段、每段小写字母开头。
_DOT_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")
#: 严格 semver（无预发布/构建元数据）。
_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

# NAM-023 只用这个最小 v1 catalog 触发已核验发布 tarball 的真实公共
# validateCatalog 路径；它不替代受检目标的 adapter 与 tarball 业务材料。
_V1_REGISTRY_CATALOG_PROBE = {
    "schemaVersion": 1,
    "catalog": {"id": "skill-family-audit", "version": "1.1.2"},
    "entries": [{
        "ref": "skill-family-audit:conformance-audit",
        "kind": "workflow",
        "provider": {
            "plugin": "skill-family-audit",
            "skill": "skills/skill-family-audit",
            "scope": "plugin",
        },
        "match": {
            "domains": ["skill-governance"],
            "intents": ["audit"],
            "artifactTypes": ["skill_family"],
        },
        "accepts": ["evidence_set", "target_project_path"],
        "produces": ["conformance_result", "rule_findings"],
        "sideEffects": ["read-only"],
        "summary": "NAM-023 exact-version v1 surface probe",
    }],
}


def _sfa_registration_boundary() -> tuple[str, dict[str, Any]] | None:
    """读取随当前 Audit 实现交付的注册边界，而不是受检目标提供的同名文件。"""
    for root in Path(__file__).resolve().parents:
        for relative in (
            "spec/methods/registration-boundary.json",
            "shared/methods/registration-boundary.json",
        ):
            path = root / relative
            if not path.is_file() or path.is_symlink():
                continue
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ExecutorEvidenceError(
                    "AUDIT_AUTHORITY_INVALID",
                    f"当前 Audit 注册边界无法读取或解析: {path}: {exc}",
                ) from exc
            if not isinstance(value, dict):
                raise ExecutorEvidenceError(
                    "AUDIT_AUTHORITY_INVALID", f"当前 Audit 注册边界顶层必须是对象: {path}"
                )
            return relative, value
    return None


def _sfa_v2_service_mappings() -> tuple[str, list[dict[str, str]]] | None:
    boundary = _sfa_registration_boundary()
    if boundary is None:
        return None
    authority_path, value = boundary
    strict_methods = value.get("strictMethods")
    rows = strict_methods.get("v2ServiceMappings") if isinstance(strict_methods, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ExecutorEvidenceError(
            "AUDIT_AUTHORITY_INVALID",
            "当前 Audit 注册边界缺少 strictMethods.v2ServiceMappings",
        )
    mappings: list[dict[str, str]] = []
    logical_seen: set[str] = set()
    service_seen: set[str] = set()
    for index, row in enumerate(rows):
        logical = row.get("logicalMethodId") if isinstance(row, dict) else None
        service = row.get("serviceId") if isinstance(row, dict) else None
        if (
            not _nonempty_str(logical)
            or not _COLON_IDENTITY_RE.match(logical)
            or not _nonempty_str(service)
            or not _DOT_IDENTITY_RE.match(service)
            or logical in logical_seen
            or service in service_seen
        ):
            raise ExecutorEvidenceError(
                "AUDIT_AUTHORITY_INVALID",
                f"当前 Audit v2 服务映射非法或非双射: index={index}",
            )
        logical_seen.add(logical)
        service_seen.add(service)
        mappings.append({
            "colon_identity": logical,
            "dot_identity": service,
            "bidirectional": True,
        })
    return authority_path, mappings


def _catalog_entries(ctx: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]] | None:
    """读取目标真实 agent-methods/catalog.yaml 的最小注册表形状。

    这里刻意只解析 ``ref``、``kind`` 和所在行：catalog 的完整 YAML 合同仍由
    目标项目自己的校验器负责，本执行器只需要确定机器身份是否使用点式 ref。
    """
    text = _read_target_text(ctx, "agent-methods/catalog.yaml")
    if text is None:
        return None
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    current: dict[str, Any] | None = None
    item_indent: int | None = None
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        ref_match = re.match(r"^(\s*)-\s+ref:\s*(.*?)\s*$", line)
        if ref_match:
            if current is not None:
                entries.append(current)
            scalar = ref_match.group(2).strip()
            if len(scalar) >= 2 and scalar[0] == scalar[-1] and scalar[0] in "\"'":
                scalar = scalar[1:-1]
            if not scalar or any(char in scalar for char in "{}[]|>&*! "):
                errors.append(f"catalog_ref_invalid:{line_no}")
                current = None
                item_indent = None
                continue
            current = {"ref": scalar, "line": line_no}
            item_indent = len(ref_match.group(1))
            continue
        if current is not None:
            next_item = re.match(r"^(\s*)-\s+", line)
            if next_item and len(next_item.group(1)) <= (item_indent or 0):
                entries.append(current)
                current = None
                item_indent = None
                continue
            kind_match = re.match(r"^\s+kind:\s*(.*?)\s*$", line)
            if kind_match:
                scalar = kind_match.group(1).strip()
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


def _walk_string_values(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for item in value:
            _walk_string_values(item, out)
    elif isinstance(value, dict):
        for key, item in value.items():
            _walk_string_values(key, out)
            _walk_string_values(item, out)


def _fenced_blocks(text: str) -> list[tuple[str, str | None, str, str | None]]:
    """AGENTS.md/README.md 中的 fenced JSON/YAML 块：(lang, name, content)。"""
    blocks = []
    lines = text.splitlines()
    index = 0
    heading: str | None = None
    while index < len(lines):
        heading_match = re.match(r"^#{1,6}\s+(.+?)\s*$", lines[index].strip())
        if heading_match:
            heading = heading_match.group(1)
        match = re.match(r"^```(json|yaml|yml)(?:\s+([A-Za-z0-9._-]+))?\s*$", lines[index].strip())
        if not match:
            index += 1
            continue
        lang, name = match.group(1), match.group(2)
        content = []
        index += 1
        while index < len(lines) and not lines[index].strip().startswith("```"):
            content.append(lines[index])
            index += 1
        index += 1
        blocks.append((lang, name, "\n".join(content), heading))
    return blocks


#: 真源声明载体命名（SOURCE-019/020）。
_AUTHORITY_FILE_STEM = "skill-family.source-authority"


def _scan_carriers(ctx: dict[str, Any]) -> dict[str, Any]:
    """扫描真源声明载体：根 JSON/YAML 文件 + AGENTS.md/README.md fenced 块。"""
    json_carriers: list[dict[str, Any]] = []
    yaml_carriers: list[str] = []
    fenced_blocks: list[dict[str, Any]] = []
    if _target_file(ctx, f"{_AUTHORITY_FILE_STEM}.json") is not None:
        json_carriers.append({"path": f"{_AUTHORITY_FILE_STEM}.json", "source": "root_file"})
    for suffix in ("yaml", "yml"):
        if _target_file(ctx, f"{_AUTHORITY_FILE_STEM}.{suffix}") is not None:
            yaml_carriers.append(f"{_AUTHORITY_FILE_STEM}.{suffix}")
    for doc_name in ("AGENTS.md", "README.md"):
        text = _read_target_text(ctx, doc_name)
        if text is None:
            continue
        for lang, name, content, heading in _fenced_blocks(text):
            if lang == "json":
                fenced_blocks.append({"path": doc_name, "name": name, "content": content, "heading": heading})
            else:
                yaml_carriers.append(f"{doc_name}#{name or 'unnamed'}")
    return {"json": json_carriers, "yaml": yaml_carriers, "fenced": fenced_blocks}


def _parse_carrier_dict(text: str | None) -> dict[str, Any] | None:
    """解析载体文本；存在但不可解析（散文/非对象）返回 None。"""
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _carrier_documents(ctx: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None]]:
    """解析全部 JSON 载体：(label, parsed|None)；None 表示载体不可解析。"""
    documents: list[tuple[str, dict[str, Any] | None]] = []
    carriers = _scan_carriers(ctx)
    if carriers["json"]:
        label = carriers["json"][0]["path"]
        documents.append((label, _parse_carrier_dict(_read_target_text(ctx, label))))
    for block in carriers["fenced"]:
        label = f"{block['path']}#{block['name']}"
        documents.append((label, _parse_carrier_dict(block["content"])))
    return documents


def _semver_parts(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    match = _SEMVER_RE.match(value.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _minor_line_exceeded(plan: tuple[int, int, int], trunk: tuple[int, int, int]) -> bool:
    """主干版本是否越过门禁证据版本一个 minor 线。"""
    plan_major, plan_minor, _ = plan
    trunk_major, trunk_minor, _ = trunk
    if trunk_major > plan_major:
        return True
    return trunk_major == plan_major and trunk_minor > plan_minor + 1


def _source_truth_schema_ok(
    ctx: dict[str, Any], value: dict[str, Any]
) -> tuple[str, str]:
    """通过同树受管 Foundation Bundle 按完整 schema ID 校验。"""
    schema_id = "https://contracts.skill-family.example/skill-family-audit/candidate/v2/source-truth-declaration.json"
    try:
        host = conformance_check.foundation_host_for(__file__)
        response = host._foundation({
            "operation": "validate-by-schema-id",
            "schemaId": schema_id,
            "document": value,
        })
    except Exception as exc:  # mechanism unavailable/unknown response is evidence missing
        return "EVIDENCE_MISSING", f"foundation_schema_mechanism_unavailable:{type(exc).__name__}"
    if not isinstance(response, dict) or not isinstance(response.get("valid"), bool):
        return "EVIDENCE_MISSING", "foundation_schema_response_unjudgable"
    if response["valid"] is True:
        return "PASS", "foundation_schema_validated"
    return "FAIL", f"foundation_schema_rejected:{response.get('errors', ['schema validation failed'])}"


_SOURCE_AUTHORITY_TITLE = "Skill Family Source Authority"
_SOURCE_AUTHORITY_INFO = "skill-family-source-authority"


def _source_020_authority_scan(ctx: dict[str, Any]) -> dict[str, Any]:
    """识别 SOURCE-020 的有限声明意图，不把普通 Markdown 示例当载体。"""
    root_json = _target_file(ctx, f"{_AUTHORITY_FILE_STEM}.json")
    root_yaml = [
        f"{_AUTHORITY_FILE_STEM}.{suffix}"
        for suffix in ("yaml", "yml")
        if _target_file(ctx, f"{_AUTHORITY_FILE_STEM}.{suffix}") is not None
    ]
    candidates: list[tuple[str, dict[str, Any] | None]] = []
    violations: list[dict[str, Any]] = []
    declaration_signal = bool(root_json or root_yaml)
    if root_json is not None:
        root_value = _parse_carrier_dict(_read_target_text(ctx, f"{_AUTHORITY_FILE_STEM}.json"))
        if root_value is not None:
            candidates.append((f"{_AUTHORITY_FILE_STEM}.json", root_value))
        else:
            violations.append({"carrier": f"{_AUTHORITY_FILE_STEM}.json", "problems": ["prose_or_unparseable_declaration"]})
    if root_yaml:
        violations.append({"carrier": root_yaml[0], "problems": ["yaml_carrier_not_acceptable"]})

    for doc_name in ("AGENTS.md", "README.md"):
        text = _read_target_text(ctx, doc_name)
        if text is None:
            continue
        lines = text.splitlines()
        heading_level: int | None = None
        heading_title: str | None = None
        title_count = 0
        title_has_fence = False
        outer_fence_length: int | None = None
        index = 0
        while index < len(lines):
            if outer_fence_length is not None:
                closing_match = re.match(r"^\s*(`+)\s*$", lines[index])
                if closing_match and len(closing_match.group(1)) >= outer_fence_length:
                    outer_fence_length = None
                index += 1
                continue
            outer_match = re.match(r"^\s*(`{4,})", lines[index])
            if outer_match:
                outer_fence_length = len(outer_match.group(1))
                index += 1
                continue
            heading_match = re.match(r"^(#{1,6})\s+(.+?)\s*$", lines[index])
            if heading_match:
                heading_level = len(heading_match.group(1))
                heading_title = heading_match.group(2)
                if heading_title == _SOURCE_AUTHORITY_TITLE:
                    declaration_signal = True
                    title_count += 1
                    if heading_level != 2:
                        violations.append({"carrier": doc_name, "problems": ["fenced_heading_invalid"]})
                index += 1
                continue
            opener = re.match(r"^\s*```([^\s`]*)?(?:\s+([^`\s]+))?\s*$", lines[index])
            if not opener or opener.group(1) not in {"json", "yaml", "yml"}:
                index += 1
                continue
            language = opener.group(1)
            info_name = opener.group(2)
            body: list[str] = []
            close_index = index + 1
            while close_index < len(lines) and lines[close_index].strip() != "```":
                body.append(lines[close_index])
                close_index += 1
            closed = close_index < len(lines)
            title_intent = heading_title == _SOURCE_AUTHORITY_TITLE
            named_intent = language == "json" and info_name == _SOURCE_AUTHORITY_INFO
            wrong_level_intent = heading_title == _SOURCE_AUTHORITY_TITLE and heading_level != 2
            if title_intent or named_intent or wrong_level_intent:
                declaration_signal = True
                if title_intent or wrong_level_intent:
                    title_has_fence = True
                label = f"{doc_name}#{info_name or 'unnamed'}"
                if not closed:
                    violations.append({"carrier": label, "problems": ["authority_fence_unclosed"]})
                elif heading_level != 2 or heading_title != _SOURCE_AUTHORITY_TITLE:
                    violations.append({"carrier": label, "problems": ["fenced_heading_invalid"]})
                elif language != "json" or info_name != _SOURCE_AUTHORITY_INFO:
                    violations.append({"carrier": label, "problems": ["fenced_info_string_invalid"]})
                else:
                    value = _parse_carrier_dict("\n".join(body))
                    if value is not None:
                        candidates.append((label, value))
                    else:
                        violations.append({"carrier": label, "problems": ["prose_or_unparseable_declaration"]})
                index = close_index + 1 if closed else len(lines)
                continue
            index = close_index + 1 if closed else len(lines)
        if title_count > 1:
            violations.append({"carrier": doc_name, "problems": ["duplicate_authority_heading"]})
        if title_count and not title_has_fence:
            violations.append({"carrier": doc_name, "problems": ["authority_declaration_without_machine_object"]})

    if len(candidates) > 1:
        violations.append({"problem": "multiple_authoritative_declarations", "count": len(candidates)})
    return {
        "candidates": candidates,
        "violations": violations,
        "declaration_signal": declaration_signal,
    }


def check_nam_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """冒号式与点式机器身份映射声明义务。

    机械断言：注册投影文档含机器身份条目时，必须提供冒号式→点式确定性
    双向映射声明；同一能力不得在多个位置各自宣称机器身份；投影文档内
    不得混用冒号式与点式分隔符（映射声明之外的冒号式身份即混用）。
    """
    applicability = _sfa_product_gate(ctx)
    if applicability is not None:
        return applicability
    authority = _sfa_v2_service_mappings()
    if authority is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="audit_registration_boundary_missing")],
            machine_identity_mappings=0,
        )
    authority_path, mappings = authority
    documents: list[tuple[str, dict[str, Any]]] = []
    for name in ("naming-registry", "method-registry-projection"):
        document = _doc(ctx, name)
        if document is not None:
            documents.append((name, document))
    declared_colon: set[str] = set()
    target_mappings: list[dict[str, Any]] = []
    for name, document in documents:
        for row in rows_of(document, "machine_identity_mappings", name):
            target_mappings.append(row)
            if isinstance(row.get("colon_identity"), str):
                declared_colon.add(row["colon_identity"])
    entry_count = 0
    for name, document in documents:
        if name == "method-registry-projection":
            entry_count += len(rows_of(document, "entries", name))
        else:
            entry_count += len(rows_of(document, "machine_identities", name))
    catalog = _catalog_entries(ctx)
    catalog_dot_refs: list[dict[str, Any]] = []
    if catalog is not None:
        catalog_rows, catalog_errors = catalog
        if catalog_errors:
            return _finish(
                [_static_row("EVIDENCE_MISSING", reason="catalog_identity_surface_unparseable", errors=catalog_errors)],
                catalog_path="agent-methods/catalog.yaml",
            )
        catalog_dot_refs = [
            row for row in catalog_rows
            if isinstance(row.get("ref"), str) and _DOT_IDENTITY_RE.match(row["ref"])
        ]
        entry_count += len(catalog_dot_refs)
    violations = []
    authority_pairs = {
        (row["colon_identity"], row["dot_identity"])
        for row in mappings
    }
    for index, row in enumerate(target_mappings):
        pair = (row.get("colon_identity"), row.get("dot_identity"))
        if pair not in authority_pairs:
            violations.append({
                "index": index,
                "problem": "target_mapping_conflicts_with_audit_authority",
                "colon_identity": pair[0],
                "dot_identity": pair[1],
            })
    seen: dict[str, str] = {}
    for index, row in enumerate(mappings):
        colon = row.get("colon_identity")
        dot = row.get("dot_identity")
        problems = []
        if not _nonempty_str(colon) or not _COLON_IDENTITY_RE.match(colon):
            problems.append("colon_identity_invalid")
        if not _nonempty_str(dot) or not _DOT_IDENTITY_RE.match(dot):
            problems.append("dot_identity_invalid")
        if _nonempty_str(colon):
            if colon in seen and seen[colon] != dot:
                problems.append("same_capability_claimed_at_two_positions")
            seen[colon] = dot
        if row.get("bidirectional") is not True:
            problems.append("mapping_not_bidirectional")
        if problems:
            violations.append({"index": index, "colon_identity": colon, "problems": problems})
    for name, document in documents:
        strings: list[str] = []
        _walk_string_values(document, strings)
        for value in strings:
            if _COLON_IDENTITY_RE.match(value) and value not in declared_colon:
                violations.append(
                    {"document": name, "problem": "mixed_colon_dot_usage", "value": value}
                )
    if catalog_dot_refs:
        mapped_dots = {row.get("dot_identity") for row in mappings}
        unmapped = sorted({row["ref"] for row in catalog_dot_refs} - mapped_dots)
        if unmapped:
            violations.append({"catalog": "agent-methods/catalog.yaml",
                               "problem": "catalog_identity_not_in_mapping",
                               "refs": unmapped})
    if violations:
        return _finish(
            [_static_row("FAIL", reason="machine_identity_mapping_violations", violations=violations)],
            machine_identity_mappings=len(mappings),
        )
    return _finish(
        [_static_row("PASS", reason="machine_identity_mapping_declared",
                     authority_path=authority_path, mappings_checked=len(mappings))],
        machine_identity_mappings=len(mappings),
    )


def check_nam_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """冒号式 v1 ref 过渡安排。

    机械断言：使用冒号式 v1 ref 或发生 adapters 登记事件时，逐一从当前
    Audit 权威 adapter 绑定的真实发布 tarball 核实 validateCatalog 与
    catalog schema，并实际执行一个含冒号 ref 的最小 v1 catalog。结论只
    是该精确版本的 Audit 消费事实，不接收目标自填布尔值代替核验。
    """
    applicability = _sfa_product_gate(ctx, row_factory=_digest_row)
    if applicability is not None:
        return applicability
    registry_dir = Path(ctx["target"]) / "spec" / "external-adapters"
    registry_files = []
    if registry_dir.is_dir():
        registry_files = sorted(
            f"spec/external-adapters/{path.name}"
            for path in registry_dir.glob("agent-method-registry-*.json")
            if path.is_file()
        )
    v1_refs = 0
    document = _doc(ctx, "naming-registry")
    if document is not None:
        v1_refs = len(rows_of(document, "v1_colon_refs", "naming-registry"))
    if not registry_files and v1_refs == 0:
        return _finish(
            [_digest_row("NOT_APPLICABLE", reason="no_v1_ref_and_no_adapter_registration")],
            v1_ref_usage=False,
        )
    from . import m7_registry_b2

    version_pattern = re.compile(
        r"^spec/external-adapters/agent-method-registry-(\d+\.\d+\.\d+)\.json$"
    )
    versions: list[tuple[str, str]] = []
    unversioned = []
    for relative in registry_files:
        match = version_pattern.match(relative)
        if match is None:
            unversioned.append(relative)
        else:
            versions.append((match.group(1), relative))
    if unversioned or (not versions and v1_refs > 0):
        return _finish(
            [_digest_row(
                "EVIDENCE_MISSING",
                reason="pinned_registry_versions_unjudgable",
                unversioned_adapter_files=unversioned,
            )],
            v1_refs=v1_refs,
        )

    observations = []
    violations = []
    missing = []
    for version, relative in versions:
        probe = m7_registry_b2._validate_with_released_registry(
            ctx,
            _V1_REGISTRY_CATALOG_PROBE,
            version=version,
            require_audit_authority=False,
        )
        observation = {
            "version": version,
            "adapter": relative,
            "status": probe.get("status"),
            "reason": probe.get("reason"),
            "tarball_sha256": probe.get("tarball_sha256"),
            "catalog_schema_member": probe.get("catalog_schema_member"),
            "registry_version": probe.get("registry_version"),
            "document_sha256": probe.get("document_sha256"),
            "diagnostics": probe.get("diagnostics", []),
        }
        observations.append(observation)
        if probe.get("status") == "FAIL":
            violations.append(observation)
        elif probe.get("status") != "PASS":
            missing.append(observation)
    if violations:
        return _finish(
            [_digest_row(
                "FAIL",
                reason="pinned_version_v1_surface_contracted_or_invalid",
                violations=violations,
                missing=missing,
            )],
            versions_checked=len(versions),
            consumer_fact_scope="audit_exact_version_only",
            ecosystem_support_commitment=False,
        )
    if missing:
        return _finish(
            [_digest_row(
                "EVIDENCE_MISSING",
                reason="pinned_version_v1_surface_evidence_missing",
                missing=missing,
            )],
            versions_checked=len(versions),
            consumer_fact_scope="audit_exact_version_only",
            ecosystem_support_commitment=False,
        )
    return _finish(
        [_digest_row(
            "PASS",
            reason="pinned_version_v1_surfaces_verified",
            versions=observations,
            digest_source="foundation.strict-read+adapter_tarball_digest",
        )],
        versions_checked=len(versions),
        consumer_fact_scope="audit_exact_version_only",
        ecosystem_support_commitment=False,
    )


def check_nam_024(ctx: dict[str, Any]) -> dict[str, Any]:
    """migration 机制位采用裁决。

    机械断言：存在 v1→v2 映射需求或 forbiddenDiscriminators 声明时，必须
    消费协议侧 migration-plan 机制或留痕 forbiddenDiscriminators 解除；
    禁止自造映射协议文档；宣称解除必须伴随 adapters 登记更新消费姿态。
    """
    applicability = _sfa_product_gate(ctx)
    if applicability is not None:
        return applicability
    pending = 0
    document = _doc(ctx, "naming-registry")
    if document is not None:
        pending = len(rows_of(document, "pending_v2_upgrades", "naming-registry"))
    registry_dir = Path(ctx["target"]) / "spec" / "external-adapters"
    forbidden_declared = False
    synthetic_identities: list[dict[str, Any]] = []
    synthetic_sources: list[str] = []
    plans = load_governance_document(ctx, "migration-plan")
    adapters = load_governance_document(ctx, "adapter-registrations")
    if registry_dir.is_dir():
        for path in sorted(registry_dir.glob("agent-method-registry-*.json")):
            if not path.is_file():
                continue
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ExecutorEvidenceError(
                    "TARGET_FILE_INVALID", f"登记文件无法解析: {path.name}: {exc}"
                ) from exc
            if isinstance(value, dict) and "forbiddenDiscriminators" in value.get("v2Surface", {}):
                forbidden_declared = True
            if isinstance(value, dict):
                surface = value.get("v2Surface")
                if isinstance(surface, dict) and "syntheticIdentities" in surface:
                    identities = surface.get("syntheticIdentities")
                    synthetic_sources.append(path.name)
                    if not isinstance(identities, list) or not all(isinstance(item, dict) for item in identities):
                        return _finish(
                            [_static_row("EVIDENCE_MISSING", reason="synthetic_identity_surface_unparseable",
                                         source=path.name)],
                            v2_mapping_requirement=True,
                        )
                    if not identities:
                        return _finish(
                            [_static_row("EVIDENCE_MISSING", reason="synthetic_identity_surface_empty",
                                         source=path.name)],
                            v2_mapping_requirement=True,
                        )
                    synthetic_identities.extend(identities)
    if isinstance(plans, dict):
        for index, plan_row in enumerate(rows_of(plans, "plans", "migration-plan")):
            identities = plan_row.get("syntheticIdentities")
            if identities is None:
                identities = plan_row.get("synthetic_identities")
            if identities is None:
                continue
            synthetic_sources.append(f"migration-plan[{index}]")
            if not isinstance(identities, list) or not all(isinstance(item, dict) for item in identities):
                return _finish(
                    [_static_row("EVIDENCE_MISSING", reason="synthetic_identity_surface_unparseable",
                                 source=f"migration-plan[{index}]")],
                    v2_mapping_requirement=True,
                )
            if not identities:
                return _finish(
                    [_static_row("EVIDENCE_MISSING", reason="synthetic_identity_surface_empty",
                                 source=f"migration-plan[{index}]")],
                    v2_mapping_requirement=True,
                )
            synthetic_identities.extend(identities)
    # ``forbiddenDiscriminators: [migration-plan]`` is the pinned adapter's
    # declaration that this consumer has *not* adopted migration-plan yet.  It
    # must not by itself turn the rule on.  Applicability begins only when the
    # target declares pending work, supplies synthetic identities, or actually
    # creates a migration-plan document.
    if pending == 0 and not synthetic_sources and plans is None:
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="no_v2_mapping_requirement")],
            v2_mapping_requirement=False,
            migration_plan_forbidden=forbidden_declared,
        )
    if plans is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="migration_mechanism_consumption_missing")],
            pending_v2_upgrades=pending,
        )
    plan_rows = rows_of(plans, "plans", "migration-plan")
    if not plan_rows:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="migration_plan_entries_missing")],
            pending_v2_upgrades=pending,
        )
    violations = []
    missing_material = []
    for index, row in enumerate(plan_rows):
        missing = []
        problems = []
        if not _nonempty_str(row.get("plan_id")):
            missing.append("plan_id_missing")
        if "consumes_protocol_migration_mechanism" not in row:
            missing.append("protocol_mechanism_consumption_missing")
        elif row.get("consumes_protocol_migration_mechanism") is not True:
            problems.append("protocol_mechanism_not_consumed")
        if row.get("self_invented_mapping_protocol") is True:
            problems.append("self_invented_mapping_protocol")
        if missing:
            missing_material.append({"index": index, "plan_id": row.get("plan_id"), "missing": missing})
        if problems:
            violations.append({"index": index, "plan_id": row.get("plan_id"), "problems": problems})
    if adapters is not None:
        adapter_rows = rows_of(adapters, "registrations", "adapter-registrations")
        if not adapter_rows:
            missing_material.append({"missing": ["adapter_registration_entries_missing"]})
        posture_closed = False
        for index, row in enumerate(adapter_rows):
            problems = []
            missing = []
            if not _nonempty_str(row.get("registry_version")):
                missing.append("registry_version_missing")
            if "forbidden_discriminators_cleared" not in row:
                missing.append("forbidden_discriminators_clearance_missing")
            elif row.get("forbidden_discriminators_cleared") is not True:
                problems.append("forbidden_discriminators_not_cleared")
            if "consumption_posture_declared" not in row:
                missing.append("consumption_posture_missing")
            elif row.get("consumption_posture_declared") is not True:
                problems.append("consumption_posture_not_declared")
            if (
                row.get("forbidden_discriminators_cleared") is True
                and row.get("consumption_posture_declared") is True
            ):
                posture_closed = True
            if missing:
                missing_material.append(
                    {"index": index, "registry_version": row.get("registry_version"), "missing": missing}
                )
            if problems:
                violations.append(
                    {"index": index, "registry_version": row.get("registry_version"), "problems": problems}
                )
        if adapter_rows and not posture_closed and not any(
            item.get("index") is not None for item in missing_material
        ):
            violations.append({"problem": "migration_consumption_posture_not_closed"})
    else:
        missing_material.append({"missing": ["adapter_registrations_missing"]})
    if not synthetic_identities:
        missing_material.append({"missing": ["synthetic_identities_missing"]})
    for index, row in enumerate(synthetic_identities):
        missing = []
        problems = []
        v1_ref = row.get("v1Ref")
        v2_identity = row.get("v2Identity")
        source_digest = row.get("sourceDigest")
        conflict_report = row.get("conflictReport")
        algorithm_version = row.get("algorithmVersion")
        if not _nonempty_str(v1_ref):
            missing.append("v1_ref_missing")
        elif not _COLON_IDENTITY_RE.match(v1_ref):
            problems.append("v1_ref_invalid")
        if not _nonempty_str(v2_identity):
            missing.append("explicit_v2_mapping_missing")
        elif not _DOT_IDENTITY_RE.match(v2_identity):
            problems.append("v2_identity_invalid")
        if source_digest is None:
            missing.append("source_digest_missing")
        elif not is_hex64(source_digest):
            problems.append("source_digest_invalid")
        if conflict_report is None:
            missing.append("conflict_report_missing")
        elif not isinstance(conflict_report, (dict, list)):
            problems.append("conflict_report_invalid")
        if algorithm_version is None:
            missing.append("algorithm_version_missing")
        elif algorithm_version != "2.0.0":
            problems.append("algorithm_version_not_2_0_0")
        if missing:
            missing_material.append({"index": index, "v1Ref": v1_ref, "missing": missing})
        if problems:
            violations.append({"index": index, "v1Ref": v1_ref, "problems": problems})
    if violations:
        return _finish(
            [_static_row("FAIL", reason="migration_mechanism_violations", violations=violations)],
            pending_v2_upgrades=pending,
        )
    if missing_material:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="migration_plan_key_material_missing",
                         missing=missing_material)],
            pending_v2_upgrades=pending,
        )
    return _finish(
        [
            _static_row(
                "PASS",
                reason="migration_mechanism_consumed",
                plans_declared=plans is not None,
                adapters_declared=adapters is not None,
            )
        ],
        pending_v2_upgrades=pending,
    )


def check_source_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """单一真源声明。

    机械断言：存在公开能力生成物时，必须存在机器可读真源声明，且其
    源→生成物边集合可机械派生；同一能力不得有两个位置各自宣称真源；
    YAML 载体不是可审计载体（检出不通过）。
    """
    projections = 0
    document = _doc(ctx, "source-projections")
    if document is not None:
        projections = len(rows_of(document, "projections", "source-projections"))
    scan = _source_020_authority_scan(ctx)
    surface_roots: list[dict[str, Any]] = []
    target = Path(ctx["target"])
    if (target / "skills-src").is_dir() and ((target / "skills").is_dir() or (target / "adapters").is_dir()):
        surface_roots.append({"source": "skills-src", "generated": [name for name in ("skills", "adapters") if (target / name).is_dir()]})
    if (target / "src").is_dir() and ((target / "dist").is_dir() or (target / "build").is_dir()):
        surface_roots.append({"source": "src", "generated": [name for name in ("dist", "build") if (target / name).is_dir()]})
    if (target / "plugin-src").is_dir() and (target / "generated" / "platforms").is_dir():
        surface_roots.append({"source": "plugin-src", "generated": ["generated/platforms"]})
    trigger = ctx.get("target_type") == "family_source" or projections > 0 or bool(surface_roots)
    if not trigger and not scan["declaration_signal"]:
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="no_generated_artifacts_and_no_declaration")],
            generated_artifacts=0,
        )
    if not scan["candidates"]:
        return _finish(
            [_static_row("FAIL" if scan["violations"] else "EVIDENCE_MISSING",
                         reason="truth_source_carrier_violations" if scan["violations"] else "truth_source_declaration_missing",
                         violations=scan["violations"] or None)],
            generated_artifacts=projections,
            source_generated_roots=surface_roots,
        )
    violations = list(scan["violations"])
    authoritative = scan["candidates"]
    if len(authoritative) > 1:
        violations.append({"problem": "dual_truth_source_declaration",
                           "carriers": [label for label, _ in authoritative]})
    else:
        label, value = authoritative[0]
        # 现行 source-truth 合同唯一真源是 schemaVersion/kind/mappings；
        # 不再读取历史 source_files/lineage/generator_identity 字段。
        schema_status, schema_reason = _source_truth_schema_ok(ctx, value)
        if schema_status != "PASS":
            return _finish(
                [_static_row("EVIDENCE_MISSING" if schema_status == "EVIDENCE_MISSING" else "FAIL",
                             reason="source_truth_schema_unverifiable" if schema_status == "EVIDENCE_MISSING" else "source_truth_schema_invalid",
                             detail=schema_reason)],
                generated_artifacts=projections,
                source_generated_roots=surface_roots,
            )
        mappings = value.get("mappings", [])
        declared_sources = {root for mapping in mappings for root in mapping.get("sourceRoots", [])}
        declared_generated = {root for mapping in mappings for root in mapping.get("generatedRoots", [])}
        declared_generators = {mapping.get("generator", {}).get("path") for mapping in mappings}
        for surface in surface_roots:
            if surface["source"] not in declared_sources:
                violations.append({"problem": "actual_source_root_not_declared", "root": surface["source"]})
            missing = sorted(set(surface["generated"]) - declared_generated)
            if missing:
                violations.append({"problem": "actual_generated_root_not_declared", "roots": missing})
        for kind, paths in (
            ("declared_source_root_missing", declared_sources),
            ("declared_generated_root_missing", declared_generated),
        ):
            missing = sorted(
                path for path in paths
                if isinstance(path, str)
                and (not (target / path).exists() or (target / path).is_symlink())
            )
            if missing:
                violations.append({"problem": kind, "paths": missing})
        missing_generators = sorted(
            path for path in declared_generators
            if isinstance(path, str) and _target_file(ctx, path) is None
        )
        if missing_generators:
            violations.append({"problem": "declared_generator_entry_missing", "generators": missing_generators})
    if violations:
        return _finish(
            [_static_row("FAIL", reason="truth_source_carrier_violations", violations=violations)],
            generated_artifacts=projections,
        )
    return _finish(
        [_static_row("PASS", reason="truth_source_declaration_derivable", carriers=len(authoritative))],
        generated_artifacts=projections,
    )


def check_source_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """真源声明机器可读最低形态。

    机械断言：真源声明必须落在两种可审计载体（根目录
    skill-family.source-authority.json 或 AGENTS.md/README.md 带名称 fenced
    JSON）；YAML 载体检出即非通过；声明必须通过仓库既有
    source-truth-declaration schema（缺省按 STRS-002 最低形态）校验。
    """
    scan = _source_020_authority_scan(ctx)
    projections = 0
    document = _doc(ctx, "source-projections")
    if document is not None:
        projections = len(rows_of(document, "projections", "source-projections"))
    candidates = scan["candidates"]
    static_violations = list(scan["violations"])
    has_signal = bool(scan["declaration_signal"])

    def not_applicable() -> dict[str, Any]:
        return _finish(
            [
                _static_row("NOT_APPLICABLE", reason="no_truth_source_declaration_and_no_artifacts"),
                _schema_row("NOT_APPLICABLE", reason="no_truth_source_declaration_and_no_artifacts"),
            ],
            truth_source_declared=False,
        )

    if not has_signal and projections == 0:
        return not_applicable()
    if not candidates:
        return _finish(
            [
                _static_row(
                    "FAIL" if static_violations else "EVIDENCE_MISSING",
                    reason="truth_source_carrier_violations" if static_violations else "truth_source_declaration_missing",
                    violations=static_violations or None,
                ),
                _schema_row("EVIDENCE_MISSING", reason="no_parsable_carrier_to_validate"),
            ],
            truth_source_declared=has_signal,
        )
    target_label, target_value = candidates[0]
    schema_status, reason = _source_truth_schema_ok(ctx, target_value)
    if schema_status != "PASS":
        return _finish(
            [
                _static_row(
                    "FAIL" if static_violations else "PASS",
                    reason="truth_source_carrier_violations" if static_violations else "carrier_scan_ok",
                    violations=static_violations or None,
                ),
                _schema_row(schema_status, reason=reason),
            ],
            truth_source_declared=True,
        )
    return _finish(
        [
            _static_row(
                "FAIL" if static_violations else "PASS",
                reason="truth_source_carrier_violations" if static_violations else "carrier_scan_ok",
                violations=static_violations or None,
            ),
            _schema_row("PASS", reason=reason, carrier=target_label),
        ],
        truth_source_declared=True,
    )


def check_publish_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """版本真源载体钉扎。

    机械断言：package.json version 是唯一版本真源；历史载体（VERSION 等）
    已删除或降级为生成物并注明派生关系，无任何位置自称版本真源。
    """
    package = _read_json_file(ctx, "package.json")
    if package is None or not _nonempty_str(package.get("version")):
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="no_release_unit")],
            release_unit=False,
        )
    legacy_carriers = ("VERSION", "version.txt")
    legacy_found = [name for name in legacy_carriers if _target_file(ctx, name) is not None]
    authority = load_governance_document(ctx, "version-authority")
    if authority is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="version_authority_declaration_missing",
                         observed_package_version=package.get("version"),
                         historical_carriers=legacy_found)],
            release_unit=True,
        )
    violations = []
    source = authority.get("unique_truth_source")
    if source != "package.json":
        violations.append({"problem": "version_truth_source_not_package_json", "declared": source})
    declared_paths = set()
    for index, row in enumerate(rows_of(authority, "historical_carriers", "version-authority")):
        problems = []
        path = row.get("path")
        status = row.get("status")
        if _nonempty_str(path):
            declared_paths.add(path)
        if not _nonempty_str(path):
            problems.append("carrier_path_missing")
        if status not in ("removed", "derived_generated"):
            problems.append("carrier_status_unknown")
        if row.get("claims_authority") is True:
            problems.append("historical_carrier_claims_authority")
        if status == "derived_generated" and not _nonempty_str(row.get("derivation_note")):
            problems.append("derivation_note_missing")
        if problems:
            violations.append({"index": index, "path": path, "problems": problems})
            continue
        if status == "removed" and _target_file(ctx, path) is not None:
            violations.append({"index": index, "path": path, "problems": ["historical_carrier_not_converged"]})
        if status == "derived_generated" and _target_file(ctx, path) is None:
            violations.append({"index": index, "path": path, "problems": ["derived_carrier_missing"]})
    unknown_legacy = sorted(set(legacy_found) - declared_paths)
    if unknown_legacy:
        return _finish(
            [
                _static_row(
                    "EVIDENCE_MISSING",
                    reason="undeclared_historical_carrier_status_unknown",
                    carriers=unknown_legacy,
                )
            ],
            release_unit=True,
        )
    if violations:
        return _finish(
            [_static_row("FAIL", reason="version_authority_violations", violations=violations)],
            release_unit=True,
        )
    return _finish(
        [
            _static_row(
                "PASS",
                reason="version_truth_source_pinned",
                historical_carriers=len(rows_of(authority, "historical_carriers", "version-authority")),
            )
        ],
        release_unit=True,
    )


def check_publish_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """版本字段单点声明与机械同步。

    机械断言：除 package.json 外存在版本值载体时，必须有确定性同步机制
    声明（version_fields/mechanism 形状）与冻结运行收据；声明载体与
    package.json 版本值必须一致。
    """
    package = _read_json_file(ctx, "package.json")
    if package is None or not _nonempty_str(package.get("version")):
        return _finish(
            [
                _static_row("NOT_APPLICABLE", reason="no_release_unit"),
                _schema_row("NOT_APPLICABLE", reason="no_release_unit"),
            ],
            release_unit=False,
        )
    version = package["version"]
    sync = load_governance_document(ctx, "version-sync")
    legacy_found = [name for name in ("VERSION", "version.txt") if _target_file(ctx, name) is not None]
    if sync is None and not legacy_found:
        return _finish(
            [
                _static_row("NOT_APPLICABLE", reason="version_value_single_carrier"),
                _schema_row("NOT_APPLICABLE", reason="version_value_single_carrier"),
            ],
            release_unit=True,
        )
    if sync is None:
        return _finish(
            [
                _static_row("EVIDENCE_MISSING", reason="no_sync_mechanism_declared"),
                _schema_row("EVIDENCE_MISSING", reason="no_declaration_to_validate"),
            ],
            release_unit=True,
            extra_carriers=legacy_found,
        )
    fields = sync.get("version_fields")
    if not isinstance(fields, list) or not fields or not all(
        isinstance(item, dict) and _nonempty_str(item.get("path")) for item in fields
    ):
        return _finish(
            [
                _static_row("EVIDENCE_MISSING", reason="version_fields_undeterminable"),
                _schema_row("FAIL", reason="sync_mechanism_shape_invalid"),
            ],
            release_unit=True,
        )
    if not _nonempty_str(sync.get("mechanism")):
        return _finish(
            [
                _static_row("EVIDENCE_MISSING", reason="sync_mechanism_declaration_missing"),
                _schema_row("EVIDENCE_MISSING", reason="sync_mechanism_declaration_missing"),
            ],
            release_unit=True,
        )
    if sync.get("deterministic") is not True:
        return _finish(
            [
                _static_row("FAIL", reason="sync_mechanism_not_deterministic"),
                _schema_row("FAIL", reason="sync_mechanism_shape_invalid"),
            ],
            release_unit=True,
        )
    mechanism = sync["mechanism"].strip()
    mechanism_is_path = (
        "/" in mechanism
        or mechanism.startswith(".")
        or mechanism.endswith((".py", ".js", ".mjs", ".sh"))
    )
    if mechanism_is_path and _target_file(ctx, mechanism) is None:
        return _finish(
            [
                _static_row(
                    "EVIDENCE_MISSING",
                    reason="sync_mechanism_path_missing",
                    mechanism=mechanism,
                ),
                _schema_row("PASS", reason="sync_mechanism_shape_valid"),
            ],
            release_unit=True,
        )
    violations = []
    missing_carriers = []
    undeterminable_carriers = []
    for index, item in enumerate(fields):
        problems = []
        path = item["path"]
        file_text = _read_target_text(ctx, path)
        if file_text is None:
            missing_carriers.append({"index": index, "path": path})
        elif path not in {"VERSION", "version.txt"}:
            undeterminable_carriers.append({"index": index, "path": path})
        else:
            carrier_value = file_text.strip()
            if carrier_value.startswith("v"):
                carrier_value = carrier_value[1:]
            if carrier_value != version:
                problems.append("version_value_drift")
        if problems:
            violations.append({"index": index, "path": path, "problems": problems})
    if violations:
        return _finish(
            [
                _static_row("FAIL", reason="version_sync_violations", violations=violations),
                _schema_row("PASS", reason="sync_mechanism_shape_valid"),
            ],
            release_unit=True,
        )
    if missing_carriers or undeterminable_carriers:
        return _finish(
            [
                _static_row(
                    "EVIDENCE_MISSING",
                    reason=(
                        "declared_version_carrier_missing"
                        if missing_carriers
                        else "version_carrier_value_undeterminable"
                    ),
                    carriers=missing_carriers,
                    undeterminable_carriers=undeterminable_carriers,
                ),
                _schema_row("PASS", reason="sync_mechanism_shape_valid"),
            ],
            release_unit=True,
        )
    receipt = load_governance_document(ctx, "version-sync-receipt")
    if receipt is None:
        return _finish(
            [
                _static_row("EVIDENCE_MISSING", reason="sync_verification_receipt_missing"),
                _schema_row("PASS", reason="sync_mechanism_shape_valid"),
            ],
            release_unit=True,
        )
    if receipt.get("consistent") is not True or receipt.get("frozen") is not True:
        return _finish(
            [
                _static_row(
                    "FAIL",
                    reason="sync_receipt_not_consistent_or_not_frozen",
                    consistent=receipt.get("consistent"),
                    frozen=receipt.get("frozen"),
                ),
                _schema_row("PASS", reason="sync_mechanism_shape_valid"),
            ],
            release_unit=True,
        )
    return _finish(
        [
            _static_row("PASS", reason="version_values_sync_verified", carriers_checked=len(fields)),
            _schema_row("PASS", reason="sync_mechanism_shape_valid"),
        ],
        release_unit=True,
    )


def check_publish_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """插件元数据字段所有权唯一。

    机械断言：五类字段（name/version/author/license/description）只由
    package.json 真源承载；其余元数据载体与真源一致或声明派生来源。
    """
    package = _read_json_file(ctx, "package.json")
    if package is None or not _nonempty_str(package.get("version")):
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="no_release_unit")],
            release_unit=False,
        )
    surfaces = load_governance_document(ctx, "metadata-surfaces")
    declared_rows = [] if surfaces is None else rows_of(surfaces, "surfaces", "metadata-surfaces")
    discovered_paths = _plugin_manifest_paths(ctx)
    rows: list[dict[str, Any]] = []
    declared_path_indexes: dict[str, list[int]] = {}
    for index, row in enumerate(declared_rows):
        path = row.get("path")
        if _nonempty_str(path):
            declared_path_indexes.setdefault(path, []).append(index)
        rows.append(dict(row))
    for path in discovered_paths:
        manifest = _read_json_file(ctx, path)
        if manifest is None:
            continue
        fields = _metadata_fields(manifest)
        if not fields:
            continue
        merged = False
        for index in declared_path_indexes.get(path, []):
            declared_fields = rows[index].get("fields")
            if not isinstance(declared_fields, list):
                continue
            rows[index]["fields"] = [
                *declared_fields,
                *(field for field in fields if field not in declared_fields),
            ]
            rows[index]["discovered"] = True
            merged = True
        if not merged:
            rows.append({"path": path, "fields": fields, "discovered": True})
    if not rows:
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="no_other_metadata_surface")],
            release_unit=True,
        )
    violations = []
    undetermined_rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        problems = []
        path = row.get("path")
        fields = row.get("fields")
        if not _nonempty_str(path):
            problems.append("surface_path_missing")
        if not isinstance(fields, list) or not fields:
            undetermined_rows.append({"index": index, "path": path, "problems": problems})
            continue
        unknown = [field for field in fields if field not in _METADATA_FIELDS]
        if unknown:
            problems.append(f"unknown_metadata_field:{','.join(unknown)}")
        surface = _read_json_file(ctx, path)
        if surface is None:
            problems.append("metadata_surface_missing")
        for field in fields:
            if field not in _METADATA_FIELDS:
                continue
            value = package.get(field)
            if field == "author":
                valid_source = _nonempty_str(value) or (
                    isinstance(value, dict) and _nonempty_str(value.get("name"))
                )
            else:
                valid_source = _nonempty_str(value)
            if not valid_source:
                problems.append(f"truth_source_field_missing:{field}")
            elif surface is not None and field not in surface:
                # 载体没有声明该可选字段，不构成漂移；只有实际承载的字段比较。
                continue
            elif surface is not None and _metadata_value(field, surface.get(field)) != _metadata_value(field, value):
                problems.append(f"metadata_drift:{field}")
                if _nonempty_str(row.get("derived_from")) and not _verified_derived_from(ctx, row, package):
                    problems.append("derived_from_unverified")
        if problems:
            violations.append({"index": index, "path": path, "problems": problems})
    if violations:
        return _finish(
            [_schema_row("FAIL", reason="metadata_ownership_violations", violations=violations)],
            release_unit=True,
        )
    if undetermined_rows:
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING",
                    reason="metadata_surfaces_undeterminable",
                    surfaces=undetermined_rows,
                )
            ],
            release_unit=True,
        )
    return _finish(
        [_schema_row(
            "PASS",
            reason="metadata_owned_by_package_json",
            surfaces_checked=len(rows),
            discovered_surfaces=len([row for row in rows if row.get("discovered") is True]),
        )],
        release_unit=True,
    )


def check_publish_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """公开边界声明。

    机械断言：存在公开发布面时必须有机器可读公开边界声明
    （publicRoots/forbiddenPaths/requiredPaths 语义），且发布载荷扫描与
    声明一致。
    """
    package = _read_json_file(ctx, "package.json")
    release = _doc(ctx, "release-packages")
    release_rows = [] if release is None else rows_of(release, "packages", "release-packages")
    has_release_surface = (
        bool(release_rows)
        or (
            package is not None
            and _nonempty_str(package.get("version"))
            and package.get("private") is not True
        )
    )
    if not has_release_surface:
        return _finish(
            [
                _schema_row("NOT_APPLICABLE", reason="no_public_release_surface"),
                _static_row("NOT_APPLICABLE", reason="no_public_release_surface"),
            ],
            public_release_surface=False,
        )
    boundary = load_governance_document(ctx, "public-boundary")
    if boundary is None:
        return _finish(
            [
                _schema_row("FAIL", reason="public_boundary_declaration_missing"),
                _static_row("FAIL", reason="public_boundary_declaration_missing"),
            ],
            public_release_surface=True,
        )
    roots = boundary.get("publicRoots")
    forbidden = boundary.get("forbiddenPaths")
    required = boundary.get("requiredPaths")
    lists_ok = (
        isinstance(roots, list)
        and all(_nonempty_str(item) for item in roots)
        and isinstance(forbidden, list)
        and all(_nonempty_str(item) for item in forbidden)
        and isinstance(required, list)
        and all(_nonempty_str(item) for item in required)
    )
    if not lists_ok or not (roots or forbidden or required):
        return _finish(
            [
                _schema_row("FAIL", reason="boundary_semantics_invalid"),
                _static_row("EVIDENCE_MISSING", reason="payload_comparison_undeterminable"),
            ],
            public_release_surface=True,
        )
    payload_files: list[str] = []
    invalid_payload_rows = []
    for index, row in enumerate(release_rows):
        files = row.get("payload_files")
        if isinstance(files, list) and files and all(_nonempty_str(item) for item in files):
            payload_files.extend(files)
        else:
            invalid_payload_rows.append(index)
    if not release_rows:
        return _finish(
            [
                _schema_row("PASS", reason="boundary_semantics_valid"),
                _static_row("EVIDENCE_MISSING", reason="release_payload_undeterminable"),
            ],
            public_release_surface=True,
        )
    violations = []
    for path in payload_files:
        if any(path == item or path.startswith(item.rstrip("/") + "/") for item in forbidden):
            violations.append({"problem": "payload_contains_forbidden_path", "path": path})
        if roots and not any(path == item or path.startswith(item.rstrip("/") + "/") for item in roots):
            violations.append({"problem": "payload_outside_public_roots", "path": path})
    for item in required:
        if item not in payload_files:
            violations.append({"problem": "required_path_missing_from_payload", "path": item})
    if violations:
        return _finish(
            [
                _schema_row("PASS", reason="boundary_semantics_valid"),
                _static_row("FAIL", reason="payload_boundary_mismatch", violations=violations),
            ],
            public_release_surface=True,
        )
    if invalid_payload_rows or not payload_files:
        return _finish(
            [
                _schema_row("PASS", reason="boundary_semantics_valid"),
                _static_row(
                    "EVIDENCE_MISSING",
                    reason="release_payload_undeterminable",
                    invalid_rows=invalid_payload_rows,
                ),
            ],
            public_release_surface=True,
        )
    missing_payload_files = sorted({
        path
        for path in payload_files
        if _target_file(ctx, path) is None
    })
    if missing_payload_files:
        return _finish(
            [
                _schema_row("PASS", reason="boundary_semantics_valid"),
                _static_row(
                    "EVIDENCE_MISSING",
                    reason="payload_evidence_undeterminable",
                    missing_payload_files=missing_payload_files,
                ),
            ],
            public_release_surface=True,
        )
    return _finish(
        [
            _schema_row("PASS", reason="boundary_semantics_valid"),
            _static_row("PASS", reason="payload_within_public_boundary", payload_files=len(payload_files)),
        ],
        public_release_surface=True,
    )


def check_publish_016(ctx: dict[str, Any]) -> dict[str, Any]:
    """发布门禁证据新鲜度。

    机械断言：门禁证据所载版本与源码主干版本差超过一个 minor 线时，
    必须有重新裁决记录或滞留理由登记；多版本线场景必须显式声明各版本线
    与版本真源关系。
    """
    # 只消费 release-skill 的正式稳定别名，不发明 Audit 私有 plan/approval 形状。
    plan_path = (
        ".release-skill/release-plan.json"
        if _target_file(ctx, ".release-skill/release-plan.json") is not None
        else None
    )
    approval_path = (
        ".release-skill/approval-record.json"
        if _target_file(ctx, ".release-skill/approval-record.json") is not None
        else None
    )
    plan_material = _read_json_file(ctx, plan_path) if plan_path else None
    approval_material = _read_json_file(ctx, approval_path) if approval_path else None
    if plan_path is None and approval_path is None:
        return _finish(
            [_static_row("NOT_APPLICABLE", reason="no_release_plan_or_approval_material")],
            release_gate_evidence=False,
        )
    if plan_path is None or approval_path is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_plan_approval_pair_incomplete")],
            release_gate_evidence=True,
            release_plan_path=plan_path,
            approval_path=approval_path,
        )
    if plan_material is None or approval_material is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_plan_or_approval_unparseable")],
            release_gate_evidence=True,
        )
    plan_version_number = plan_material.get("planVersion")
    if not isinstance(plan_version_number, int) or plan_version_number < 1:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_plan_contract_version_missing")],
            release_gate_evidence=True,
        )
    binding = dict(plan_material)
    if plan_version_number in {2, 3}:
        for key in ("digest", "status", "createdAt", "baseline"):
            binding.pop(key, None)
        actions = binding.get("externalActions", [])
        if not isinstance(actions, list) or not all(isinstance(item, dict) for item in actions):
            return _finish(
                [_static_row("EVIDENCE_MISSING", reason="release_plan_actions_unparseable")],
                release_gate_evidence=True,
            )
        binding["externalActions"] = [
            {key: value for key, value in item.items() if key != "status"}
            for item in actions
        ]
    else:
        binding.pop("digest", None)
    actual_plan_digest = hashlib.sha256(
        json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    approval_plan_digest = approval_material.get("planDigest")
    if approval_plan_digest is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="approval_plan_digest_missing")],
            release_gate_evidence=True,
        )
    if approval_plan_digest != actual_plan_digest:
        return _finish(
            [_static_row("FAIL", reason="approval_plan_digest_mismatch",
                         approved_digest=approval_plan_digest,
                         actual_digest=actual_plan_digest)],
            release_gate_evidence=True,
        )
    explicit_approved = approval_material.get("approved")
    formal_approval = (
        _nonempty_str(approval_material.get("actor"))
        and _nonempty_str(approval_material.get("approvedAt"))
        and isinstance(approval_material.get("approvedActions"), list)
        and bool(approval_material["approvedActions"])
        and all(_nonempty_str(item) for item in approval_material["approvedActions"])
    )
    if explicit_approved is False:
        return _finish(
            [_static_row("FAIL", reason="release_approval_explicitly_rejected")],
            release_gate_evidence=True,
        )
    if explicit_approved is not True and not formal_approval:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_approval_fact_missing")],
            release_gate_evidence=True,
        )
    approved_actions = approval_material.get("approvedActions")
    if isinstance(approved_actions, list):
        planned_action_ids = {
            item.get("id")
            for item in plan_material.get("externalActions", [])
            if isinstance(item, dict) and _nonempty_str(item.get("id"))
        }
        unapproved_actions = sorted(planned_action_ids - set(approved_actions))
        if unapproved_actions:
            return _finish(
                [_static_row("FAIL", reason="release_actions_not_approved",
                             action_ids=unapproved_actions)],
                release_gate_evidence=True,
            )
    scope = ctx.get("scope")
    plugin_project = scope.get("plugin_project") if isinstance(scope, dict) else None
    plugin = plugin_project.get("plugin") if isinstance(plugin_project, dict) else None
    plugin_id = plugin.get("id") if isinstance(plugin, dict) else None
    units = plan_material.get("units")
    if not isinstance(units, list) or not units or not all(isinstance(item, dict) for item in units):
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_plan_units_missing")],
            release_gate_evidence=True,
        )
    matching_units = [item for item in units if item.get("id") == plugin_id]
    if not matching_units and len(units) == 1:
        matching_units = list(units)
    if len(matching_units) != 1:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_plan_target_unit_unresolved",
                         target_plugin_id=plugin_id)],
            release_gate_evidence=True,
        )
    unit = matching_units[0]
    source = unit.get("source")
    package_path = "package.json"
    if source is not None:
        if (
            not _nonempty_str(source)
            or source.startswith(("/", "\\"))
            or ".." in Path(source.replace("\\", "/")).parts
        ):
            return _finish(
                [_static_row("FAIL", reason="release_unit_source_path_invalid", source=source)],
                release_gate_evidence=True,
            )
        package_path = source.rstrip("/\\") + "/package.json"
    package = _read_json_file(ctx, package_path)
    trunk_version = package.get("version") if package else None
    trunk_parts = _semver_parts(trunk_version)
    if trunk_parts is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="trunk_version_fact_unavailable",
                         package_path=package_path)],
            release_gate_evidence=True,
        )
    plan_version = unit.get("targetVersion")
    plan_parts = _semver_parts(plan_version)
    if plan_version is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_plan_version_missing")],
            release_gate_evidence=True,
        )
    if plan_parts is None:
        return _finish(
            [_static_row("FAIL", reason="release_plan_version_invalid", plan_version=plan_version)],
            release_gate_evidence=True,
        )
    unit_versions = approval_material.get("unitVersions")
    approved_version = (
        unit_versions.get(unit.get("id"))
        if isinstance(unit_versions, dict)
        else approval_material.get("targetVersion")
    )
    if approved_version is None:
        return _finish(
            [_static_row("EVIDENCE_MISSING", reason="release_approval_version_missing")],
            release_gate_evidence=True,
        )
    if approved_version != plan_version:
        return _finish(
            [_static_row("FAIL", reason="release_approval_version_mismatch",
                         plan_version=plan_version, approved_version=approved_version)],
            release_gate_evidence=True,
        )
    approval_target_version = approval_material.get("targetVersion")
    if approval_target_version is not None and approval_target_version != plan_version:
        return _finish(
            [_static_row("FAIL", reason="release_approval_target_version_mismatch",
                         plan_version=plan_version,
                         approval_target_version=approval_target_version)],
            release_gate_evidence=True,
        )
    if trunk_version != plan_version:
        if _minor_line_exceeded(plan_parts, trunk_parts):
            if not _nonempty_str(plan_material.get("stallReason")) and not _nonempty_str(
                plan_material.get("reAdjudicationRef")
            ):
                return _finish(
                    [_static_row("FAIL", reason="release_plan_stale_without_re_adjudication",
                                 plan_version=plan_version, source_version=trunk_version)],
                    release_gate_evidence=True,
                )
        else:
            return _finish(
                [_static_row("FAIL", reason="release_plan_source_version_mismatch",
                             plan_version=plan_version, source_version=trunk_version)],
                release_gate_evidence=True,
            )
    return _finish(
        [_static_row("PASS", reason="release_plan_and_approval_current",
                     plan_version=plan_version, plan_digest=actual_plan_digest)],
        release_gate_evidence=True,
    )


# ---------------------------------------------------------------------------
# 登记
# ---------------------------------------------------------------------------

CHECKS = {
    "SFA-BYTECHAIN-001": check_bytechain_001,
    "SFA-ENTRY-004": check_entry_004,
    "SFA-ENTRY-006": check_entry_006,
    "SFA-ENTRY-008": check_entry_008,
    "SFA-ENTRY-012": check_entry_012,
    "SFA-ENTRY-013": check_entry_013,
    "SFA-ENTRY-014": check_entry_014,
    "SFA-ENTRY-015": check_entry_015,
    "SFA-ENTRY-016": check_entry_016,
    "SFA-ENTRY-017": check_entry_017,
    "SFA-ENTRY-020": check_entry_020,
    "SFA-ENTRY-021": check_entry_021,
    "SFA-ENTRY-023": check_entry_023,
    "SFA-ENTRY-024": check_entry_024,
    "SFA-ENTRY-026": check_entry_026,
    "SFA-ENTRY-027": check_entry_027,
    "SFA-NAM-013": check_nam_013,
    "SFA-NAM-014": check_nam_014,
    "SFA-NAM-015": check_nam_015,
    "SFA-NAM-016": check_nam_016,
    "SFA-NAM-017": check_nam_017,
    "SFA-NAM-018": check_nam_018,
    "SFA-NAM-022": check_nam_022,
    "SFA-NAM-023": check_nam_023,
    "SFA-NAM-024": check_nam_024,
    "SFA-PACKAGE-001": check_package_001,
    "SFA-PACKAGE-002": check_package_002,
    "SFA-PACKAGE-003": check_package_003,
    "SFA-PUBLISH-011": check_publish_011,
    "SFA-PUBLISH-012": check_publish_012,
    "SFA-PUBLISH-013": check_publish_013,
    "SFA-PUBLISH-015": check_publish_015,
    "SFA-PUBLISH-016": check_publish_016,
    "SFA-PLAT-001": check_plat_001,
    "SFA-PLAT-003": check_plat_003,
    "SFA-PLAT-004": check_plat_004,
    "SFA-PLAT-006": check_plat_006,
    "SFA-PLAT-007": check_plat_007,
    "SFA-PLAT-008": check_plat_008,
    "SFA-PLAT-009": check_plat_009,
    "SFA-PLAT-011": check_plat_011,
    "SFA-PLAT-012": check_plat_012,
    "SFA-PLAT-013": check_plat_013,
    "SFA-PLAT-015": check_plat_015,
    "SFA-PLAT-016": check_plat_016,
    "SFA-PLAT-017": check_plat_017,
    "SFA-PLAT-018": check_plat_018,
    "SFA-PLAT-019": check_plat_019,
    "SFA-PLAT-020": check_plat_020,
    "SFA-PLAT-023": check_plat_023,
    "SFA-PLAT-024": check_plat_024,
    "SFA-PLAT-026": check_plat_026,
    "SFA-PLAT-027": check_plat_027,
    "SFA-PLAT-028": check_plat_028,
    "SFA-PLAT-029": check_plat_029,
    "SFA-PLAT-031": check_plat_031,
    "SFA-PLAT-032": check_plat_032,
    "SFA-PLAT-033": check_plat_033,
    "SFA-PLAT-036": check_plat_036,
    "SFA-PLAT-037": check_plat_037,
    "SFA-PLAT-038": check_plat_038,
    "SFA-SOURCE-001": check_source_001,
    "SFA-SOURCE-002": check_source_002,
    "SFA-SOURCE-003": check_source_003,
    "SFA-SOURCE-004": check_source_004,
    "SFA-SOURCE-005": check_source_005,
    "SFA-SOURCE-006": check_source_006,
    "SFA-SOURCE-007": check_source_007,
    "SFA-SOURCE-008": check_source_008,
    "SFA-SOURCE-009": check_source_009,
    "SFA-SOURCE-010": check_source_010,
    "SFA-SOURCE-011": check_source_011,
    "SFA-SOURCE-013": check_source_013,
    "SFA-SOURCE-014": check_source_014,
    "SFA-SOURCE-015": check_source_015,
    "SFA-SOURCE-016": check_source_016,
    "SFA-SOURCE-017": check_source_017,
    "SFA-SOURCE-018": check_source_018,
    "SFA-SOURCE-019": check_source_019,
    "SFA-SOURCE-020": check_source_020,
}
