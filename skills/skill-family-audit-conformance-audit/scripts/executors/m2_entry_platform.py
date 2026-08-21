"""M2 执行族：人类入口与平台投影（W2-B1 共 19 条）。

证据面：
- 观察投影（ctx["scope"]["plugin_project"]）：逻辑技能身份与路径；
- 项目治理声明：entry-boundaries.json / method-registry-candidates.json /
  platform-restrictions.json / platform-projections.json。

文档缺省语义（逐规则注明）：
- 入口结构类（ENTRY-003/009）直接消费观察投影，无文档依赖；
- 边界声明类规则约束"已声明者"：文档缺失 = 无可判违反事实 → PASS；
- PLAT-002 例外：project_adoption 目标已声明发布，限制声明缺失本身即违反。

所有 behavior_also_required 规则只覆盖机械半区，行为义务继续挂账
（证据以 mechanical_half=true 标注）。
"""
from __future__ import annotations

from typing import Any

from .contracts import (
    FIXED_HUMAN_ENTRIES,
    REQUIRED_PLATFORMS,
    ExecutorEvidenceError,
    is_hex64,
    load_governance_document,
    observation,
    result,
    rows_of,
)

#: 入口边界声明中只读入口允许的权限词表（SFA-ENTRY-007）。
READONLY_CAPABILITIES = {"read", "list", "explain"}
#: quickstart 参数合法来源（SFA-ENTRY-019）。
PARAMETER_SOURCES = {
    "user_input",
    "project_config",
    "method_contract_default",
    "deterministic_project_fact",
}
#: setup 事务边界阶段词表（SFA-ENTRY-010），顺序即义务顺序。
SETUP_PHASES = (
    "check",
    "plan",
    "present_impact",
    "authorize",
    "execute",
    "diagnose",
    "reverify",
)


def _entry_local_id(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.rsplit(":", 1)[-1]


def _observed_entry_ids(ctx: dict[str, Any]) -> set[str]:
    obs = observation(ctx)
    skills = obs.get("skills")
    if not isinstance(skills, list):
        raise ExecutorEvidenceError(
            "PLUGIN_PROJECT_OBSERVATION_INVALID", "观察投影缺少 skills 数组"
        )
    local_ids: set[str] = set()
    for skill in skills:
        if not isinstance(skill, dict):
            raise ExecutorEvidenceError(
                "PLUGIN_PROJECT_OBSERVATION_INVALID", "观察投影 skills 行必须是对象"
            )
        local = _entry_local_id(skill.get("id"))
        if local:
            local_ids.add(local)
    return local_ids


def check_entry_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """每个完整技能族必须提供 help/setup/quickstart 三个固定人类入口。

    机械断言：观察投影的逻辑技能身份必须覆盖三个固定入口本地名。
    """
    local_ids = _observed_entry_ids(ctx)
    missing = [name for name in FIXED_HUMAN_ENTRIES if name not in local_ids]
    if missing:
        return result(
            "FAIL",
            missing_entries=missing,
            observed=sorted(local_ids),
            mechanical_half=True,
        )
    return result(
        "PASS", observed_entries=sorted(local_ids), mechanical_half=True
    )


def check_entry_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """help/setup/quickstart 不得登记到方法注册表或作为自动规划候选。

    机械断言：已声明注册候选不得引用固定人类入口身份。
    """
    document = load_governance_document(ctx, "method-registry-candidates")
    if document is None:
        return result("PASS", declared_candidates=0, mechanical_half=True)
    rows = rows_of(document, "candidates", "method-registry-candidates")
    violations = []
    for index, row in enumerate(rows):
        identity = _entry_local_id(row.get("method_id")) or row.get("method_id")
        if identity in FIXED_HUMAN_ENTRIES or row.get("planning_candidate") is True and (
            _entry_local_id(row.get("method_id")) in FIXED_HUMAN_ENTRIES
        ):
            violations.append({"index": index, "method_id": row.get("method_id")})
    if violations:
        return result(
            "FAIL", registered_human_entries=violations, mechanical_half=True
        )
    return result("PASS", declared_candidates=len(rows), mechanical_half=True)


def _entry_boundaries(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "entry-boundaries")
    if document is None:
        return None
    return rows_of(document, "entries", "entry-boundaries")


def _entry_row(rows: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    matches = [row for row in rows if row.get("entry") == name]
    if len(matches) > 1:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", f"entry-boundaries 重复声明入口: {name}"
        )
    return matches[0] if matches else None


def check_entry_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """help 必须始终只读，不得写入、安装、改配置或联网。

    机械断言：已声明 help 能力必须落在只读词表内；声明写入/安装/联网即违反。
    """
    rows = _entry_boundaries(ctx)
    if rows is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    row = _entry_row(rows, "help")
    if row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    capabilities = row.get("capabilities")
    if not isinstance(capabilities, list) or not all(
        isinstance(item, str) for item in capabilities
    ):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "entry-boundaries.help.capabilities 必须是字符串数组"
        )
    forbidden = sorted(set(capabilities) - READONLY_CAPABILITIES)
    if forbidden:
        return result("FAIL", help_non_readonly_capabilities=forbidden, mechanical_half=True)
    return result("PASS", help_capabilities=sorted(capabilities), mechanical_half=True)


def check_entry_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """setup 必须作为固定入口存在。

    机械断言：观察投影必须含 setup 入口；已声明者还必须在边界声明中登记。
    """
    local_ids = _observed_entry_ids(ctx)
    if "setup" not in local_ids:
        return result("FAIL", missing_entry="setup", observed=sorted(local_ids), mechanical_half=True)
    rows = _entry_boundaries(ctx)
    if rows is not None and _entry_row(rows, "setup") is None:
        return result(
            "FAIL",
            reason="setup_present_but_boundary_undeclared",
            mechanical_half=True,
        )
    return result("PASS", setup_present=True, boundary_declared=rows is not None, mechanical_half=True)


def check_entry_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """setup 必须按检查→计划→展示→授权→执行→诊断→复验顺序工作。

    机械断言：已声明阶段必须是词表子集且保持义务顺序；声明 execute 而无
    authorize 前置即违反；把 check/present 当作执行授权即违反。
    """
    rows = _entry_boundaries(ctx)
    if rows is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    row = _entry_row(rows, "setup")
    if row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    phases = row.get("phases")
    if not isinstance(phases, list) or not all(isinstance(item, str) for item in phases):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "entry-boundaries.setup.phases 必须是字符串数组"
        )
    unknown = sorted(set(phases) - set(SETUP_PHASES))
    if unknown:
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            f"entry-boundaries.setup.phases 含未知阶段: {unknown}",
        )
    order = [phase for phase in SETUP_PHASES if phase in phases]
    if phases != order:
        return result("FAIL", reason="setup_phase_order_violated", declared=phases, mechanical_half=True)
    if "execute" in phases and "authorize" not in phases:
        return result("FAIL", reason="setup_execute_without_authorization", mechanical_half=True)
    if row.get("check_or_plan_is_execution_authorization") is True:
        return result("FAIL", reason="setup_plan_treated_as_authorization", mechanical_half=True)
    return result("PASS", setup_phases=phases, mechanical_half=True)


def check_entry_011(ctx: dict[str, Any]) -> dict[str, Any]:
    """setup 必须幂等并保护已有文件、配置和用户修改。

    机械断言：已声明 setup 边界必须 idempotent=true 且 protect_existing=true。
    """
    rows = _entry_boundaries(ctx)
    if rows is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    row = _entry_row(rows, "setup")
    if row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    missing = [
        field
        for field in ("idempotent", "protect_existing")
        if row.get(field) is not True
    ]
    if missing:
        return result("FAIL", setup_guarantees_missing=missing, mechanical_half=True)
    return result("PASS", idempotent=True, protect_existing=True, mechanical_half=True)


def _quickstart_row(ctx: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    rows = _entry_boundaries(ctx)
    if rows is None:
        return None, None
    return rows, _entry_row(rows, "quickstart")


def check_entry_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """重大选择必须由用户决定，路由工序不得代替用户。

    机械断言：已声明 quickstart 的高影响参数必须 user_decision_required=true。
    """
    rows, row = _quickstart_row(ctx)
    if rows is None or row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    high_impact = row.get("high_impact_parameters")
    if high_impact is None:
        high_impact = []
    if not isinstance(high_impact, list) or not all(isinstance(item, dict) for item in high_impact):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.high_impact_parameters 必须是对象数组",
        )
    violations = [
        {"parameter": item.get("name")}
        for item in high_impact
        if item.get("user_decision_required") is not True
    ]
    if violations:
        return result("FAIL", parameters_without_user_decision=violations, mechanical_half=True)
    return result("PASS", high_impact_parameter_count=len(high_impact), mechanical_half=True)


def check_entry_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """quickstart 不得编造路径、业务决定等参数。

    机械断言：已声明参数来源必须全部落在合法来源词表内。
    """
    rows, row = _quickstart_row(ctx)
    if rows is None or row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    parameters = row.get("parameters")
    if parameters is None:
        parameters = []
    if not isinstance(parameters, list) or not all(isinstance(item, dict) for item in parameters):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.parameters 必须是对象数组",
        )
    violations = []
    for index, item in enumerate(parameters):
        source = item.get("source")
        if source not in PARAMETER_SOURCES:
            violations.append({"index": index, "parameter": item.get("name"), "source": source})
    if violations:
        return result("FAIL", fabricated_parameter_sources=violations, mechanical_half=True)
    return result("PASS", parameter_count=len(parameters), mechanical_half=True)


def check_entry_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """非法规范化任务不得启动内部执行，也不得伪造已执行结果。

    机械断言：已声明 quickstart 边界必须 block_invalid_task=true，且不得
    声明 invalid_task_launch 或 fabricated_result 行为。
    """
    rows, row = _quickstart_row(ctx)
    if rows is None or row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    violations = []
    if row.get("block_invalid_task") is not True:
        violations.append("block_invalid_task_not_declared")
    if row.get("launch_internal_on_invalid_task") is True:
        violations.append("launch_internal_on_invalid_task")
    if row.get("emit_fabricated_result") is True:
        violations.append("emit_fabricated_result")
    if violations:
        return result("FAIL", invalid_task_handling=violations, mechanical_half=True)
    return result("PASS", block_invalid_task=True, mechanical_half=True)


def check_entry_025(ctx: dict[str, Any]) -> dict[str, Any]:
    """高影响参数不得由快速入口静默采用默认值。

    机械断言：已声明高影响参数不得 silent_default=true；即使契约提供默认值，
    也必须声明展示影响并取得用户选择或精确授权。
    """
    rows, row = _quickstart_row(ctx)
    if rows is None or row is None:
        return result("PASS", boundary_declared=False, mechanical_half=True)
    high_impact = row.get("high_impact_parameters") or []
    if not isinstance(high_impact, list) or not all(isinstance(item, dict) for item in high_impact):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "entry-boundaries.quickstart.high_impact_parameters 必须是对象数组",
        )
    violations = [
        {"parameter": item.get("name")}
        for item in high_impact
        if item.get("silent_default") is True
        or item.get("impact_presented") is not True
        or item.get("user_decision_required") is not True
    ]
    if violations:
        return result("FAIL", silent_high_impact_defaults=violations, mechanical_half=True)
    return result("PASS", high_impact_parameter_count=len(high_impact), mechanical_half=True)


def _platform_restrictions(ctx: dict[str, Any], *, required: bool):
    document = load_governance_document(
        ctx,
        "platform-restrictions",
        required_fields=(
            "project",
            "released_platform_subset",
            "missing_platforms",
            "declared_version",
        ),
    )
    if document is None and required:
        raise ExecutorEvidenceError(
            "PLATFORM_RESTRICTIONS_MISSING",
            "已声明发布的采用目标缺少平台限制声明",
        )
    return document


def check_plat_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台子集自由但必须用标准限制声明如实声明（四字段，机器可检查）。

    机械断言：project_adoption 目标必须声明四字段；subset/missing 必须是
    必需平台集合的互补划分；声明版本非空。未声明者（非发布目标）无违反事实。
    """
    adoption_declared = isinstance(ctx.get("scope", {}).get("project_profile_document"), dict)
    document = _platform_restrictions(ctx, required=adoption_declared)
    if document is None:
        return result("PASS", release_declared=False, mechanical_half=True)
    subset = document.get("released_platform_subset")
    missing = document.get("missing_platforms")
    if (
        not isinstance(subset, list)
        or not isinstance(missing, list)
        or not all(isinstance(item, str) for item in subset)
        or not all(isinstance(item, str) for item in missing)
    ):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "platform-restrictions 平台集合必须是字符串数组",
        )
    violations = []
    if not set(subset) <= set(REQUIRED_PLATFORMS):
        violations.append("unknown_platform_in_subset")
    if not set(missing) <= set(REQUIRED_PLATFORMS):
        violations.append("unknown_platform_in_missing")
    if set(subset) & set(missing):
        violations.append("subset_and_missing_overlap")
    if set(subset) | set(missing) != set(REQUIRED_PLATFORMS):
        violations.append("subset_missing_not_a_partition")
    if not isinstance(document.get("declared_version"), str) or not document.get("declared_version"):
        violations.append("declared_version_empty")
    if violations:
        return result("FAIL", restriction_violations=violations, mechanical_half=True)
    return result(
        "PASS",
        released_platform_subset=sorted(subset),
        missing_platforms=sorted(missing),
        mechanical_half=True,
    )


def _platform_projections(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "platform-projections")
    if document is None:
        return None
    return rows_of(document, "projections", "platform-projections")


def check_plat_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台物理映射必须由共同逻辑定义确定性生成，不得人工维护第二份。

    机械断言：已声明平台投影必须 generator=deterministic_projection 且
    source_of_truth=single_logical_definition；manual_second_source=true 即违反。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("platform") not in REQUIRED_PLATFORMS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections 第 {index} 行平台非法: {row.get('platform')!r}",
            )
        if (
            row.get("generator") != "deterministic_projection"
            or row.get("source_of_truth") != "single_logical_definition"
            or row.get("manual_second_source") is True
        ):
            violations.append({"index": index, "platform": row.get("platform")})
    if violations:
        return result("FAIL", manual_platform_sources=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_014(ctx: dict[str, Any]) -> dict[str, Any]:
    """核心能力不得依赖平台独有特性。

    机械断言：已声明核心依赖的 available_on 必须覆盖全部必需平台，或声明
    等价替代；存在独有依赖且无等价替代即违反。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        for dependency in row.get("core_dependencies") or []:
            if not isinstance(dependency, dict):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "platform-projections.core_dependencies 行必须是对象",
                )
            available = dependency.get("available_on")
            if not isinstance(available, list):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "core_dependencies.available_on 必须是数组",
                )
            if set(available) < set(REQUIRED_PLATFORMS) and dependency.get(
                "equivalent_alternative"
            ) in (None, "", False):
                violations.append(
                    {"platform": row.get("platform"), "dependency": dependency.get("name")}
                )
    if violations:
        return result("FAIL", platform_exclusive_dependencies=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """Codex 投影必须使用平台真实运行期委派，不得伪造文件型执行单元。

    机械断言：已声明 codex 投影 runtime_delegation=platform_provided，且
    declare_file_based_units!=true。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    codex = [row for row in rows if row.get("platform") == "codex"]
    if not codex:
        return result("PASS", codex_declared=False, mechanical_half=True)
    violations = [
        row.get("platform")
        for row in codex
        if row.get("runtime_delegation") != "platform_provided"
        or row.get("declare_file_based_units") is True
    ]
    if violations:
        return result("FAIL", codex_fake_execution_units=len(violations), mechanical_half=True)
    return result("PASS", codex_runtime_delegation="platform_provided", mechanical_half=True)


def check_plat_022(ctx: dict[str, Any]) -> dict[str, Any]:
    """Kimi Code 不得伪造 Claude Code 式目录。

    机械断言：已声明 kimi 投影必须 claude_style_directory!=true 且
    runtime_delegation=platform_provided。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    kimi = [row for row in rows if row.get("platform") == "kimi-code"]
    if not kimi:
        return result("PASS", kimi_declared=False, mechanical_half=True)
    violations = [
        row.get("platform")
        for row in kimi
        if row.get("claude_style_directory") is True
        or row.get("runtime_delegation") != "platform_provided"
    ]
    if violations:
        return result("FAIL", kimi_forged_directories=len(violations), mechanical_half=True)
    return result("PASS", kimi_runtime_delegation="platform_provided", mechanical_half=True)


def check_plat_025(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台证据冲突、超档案范围或过期时只能报告未评估或受阻。

    机械断言：已声明能力证据状态为 conflict/expired/out_of_scope 时，能力
    状态必须 ∈ {not_evaluated, blocked}。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    conflict_states = {"conflict", "expired", "out_of_scope"}
    violations = []
    for index, row in enumerate(rows):
        for capability in row.get("capabilities") or []:
            if not isinstance(capability, dict):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "platform-projections.capabilities 行必须是对象",
                )
            if capability.get("evidence_status") in conflict_states and capability.get(
                "capability_status"
            ) not in {"not_evaluated", "blocked"}:
                violations.append(
                    {"platform": row.get("platform"), "capability": capability.get("name")}
                )
    if violations:
        return result("FAIL", conflicted_capabilities_overstated=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_035(ctx: dict[str, Any]) -> dict[str, Any]:
    """稳定公共表面不得以排除状态绕过联合发行。

    机械断言：已声明联合发行中稳定入口状态不得为 excluded；缺少实现必须
    按 missing_declared/experimental/blocked 声明。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    allowed_states = {"present", "experimental", "blocked", "missing_declared"}
    violations = []
    for index, row in enumerate(rows):
        for entry in row.get("stable_entries") or []:
            if not isinstance(entry, dict):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "platform-projections.stable_entries 行必须是对象",
                )
            status = entry.get("status")
            if status not in allowed_states:
                violations.append(
                    {"platform": row.get("platform"), "entry": entry.get("name"), "status": status}
                )
    if violations:
        return result("FAIL", excluded_stable_entries=violations, mechanical_half=True)
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


def check_plat_039(ctx: dict[str, Any]) -> dict[str, Any]:
    """四平台发行物必须锁定同一技能族修订。

    机械断言：已声明联合发行中所有平台 artifact 的 family_version 与
    source_revision_digest 必须一致（载荷摘要允许差异）。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    joint = [row for row in rows if row.get("joint_release") is True]
    if not joint:
        return result("PASS", joint_release_declared=False, mechanical_half=True)
    versions = set()
    revisions = set()
    for row in joint:
        artifact = row.get("artifact")
        if not isinstance(artifact, dict):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections {row.get('platform')} 缺少 artifact 声明",
            )
        versions.add(artifact.get("family_version"))
        digest = artifact.get("source_revision_digest")
        if not is_hex64(digest):
            return result(
                "FAIL",
                reason="source_revision_digest_invalid",
                platform=row.get("platform"),
                mechanical_half=True,
            )
        revisions.add(digest)
    if len(versions) != 1 or len(revisions) != 1 or None in versions:
        return result(
            "FAIL",
            joint_release_versions=sorted(str(item) for item in versions),
            distinct_source_revisions=len(revisions),
            mechanical_half=True,
        )
    return result(
        "PASS",
        joint_platforms=sorted(row.get("platform") for row in joint),
        source_revision_digest=revisions.pop(),
        mechanical_half=True,
    )


def check_source_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台改变公共业务语义时必须阻断稳定联合发布或标记实验。

    机械断言：已声明 business_semantics_changed=true 的平台必须使联合发布
    blocked=true，或该平台状态为 experimental。
    """
    rows = _platform_projections(ctx)
    if rows is None:
        return result("PASS", projections_declared=0, mechanical_half=True)
    violations = []
    for row in rows:
        if row.get("business_semantics_changed") is not True:
            continue
        joint_blocked = row.get("joint_release_blocked") is True
        experimental = row.get("capability_status") == "experimental" or row.get(
            "experimental"
        ) is True
        if not joint_blocked and not experimental:
            violations.append(row.get("platform"))
    if violations:
        return result(
            "FAIL", semantic_divergence_uncontained=violations, mechanical_half=True
        )
    return result("PASS", projections_declared=len(rows), mechanical_half=True)


CHECKS = {
    "SFA-ENTRY-003": check_entry_003,
    "SFA-ENTRY-005": check_entry_005,
    "SFA-ENTRY-007": check_entry_007,
    "SFA-ENTRY-009": check_entry_009,
    "SFA-ENTRY-010": check_entry_010,
    "SFA-ENTRY-011": check_entry_011,
    "SFA-ENTRY-018": check_entry_018,
    "SFA-ENTRY-019": check_entry_019,
    "SFA-ENTRY-022": check_entry_022,
    "SFA-ENTRY-025": check_entry_025,
    "SFA-PLAT-002": check_plat_002,
    "SFA-PLAT-005": check_plat_005,
    "SFA-PLAT-014": check_plat_014,
    "SFA-PLAT-021": check_plat_021,
    "SFA-PLAT-022": check_plat_022,
    "SFA-PLAT-025": check_plat_025,
    "SFA-PLAT-035": check_plat_035,
    "SFA-PLAT-039": check_plat_039,
    "SFA-SOURCE-012": check_source_012,
}
