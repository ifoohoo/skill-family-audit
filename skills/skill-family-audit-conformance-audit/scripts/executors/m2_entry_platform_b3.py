"""M2 执行族：命名/平台投影（W2-B3 批，6 条）。

本模块覆盖 B3 批 execution_family=M2、violation_impact=warning/observe 的
6 条规则，全部被终态裁决为机械方法 digest_verification 且
behavior_verification_also_required=true；执行器只覆盖机械半区
（evidence 携 mechanical_half=true），行为义务继续挂账。

证据面（与 B1/B2 M2 一致，失败关闭）：
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``：
  naming-registry（verification_semantics / vocabulary_extensions /
  family_name_segments 新轴，SFA-NAM-019/020/021）、
  platform-projections（process_model_uniformity / support_matrix_claims
  扩展，SFA-PLAT-010/030/034）。

治理声明缺省语义沿用 B1：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 文档存在但形状非法 → ExecutorEvidenceError（失败关闭，绝不静默放行）；
- 文档存在且出现结构性违反 → FAIL。

执行器只消费目标事实，绝不修改目标；不消费模型语义结论。
"""
from __future__ import annotations

import re
from typing import Any

from .contracts import (
    ExecutorEvidenceError,
    load_governance_document,
    result,
    rows_of,
)
from .m2_entry_platform_b2 import INTERNAL_ACTIONS, PUBLIC_INTENTS

# ---------------------------------------------------------------------------
# 词表
# ---------------------------------------------------------------------------

#: SFA-NAM-019：本条只裁决 validate 与 audit 两个代码词的语义边界。
VERIFICATION_CODE_WORDS = {"validate", "audit"}

#: SFA-NAM-021：技能族名称段形状（英文小写连字符）。
FAMILY_NAME_PATTERN = re.compile(r"^[a-z]+(-[a-z]+)*$")

#: SFA-NAM-021：名称段不得携带的平台名称。
FAMILY_NAME_FORBIDDEN_PLATFORM_SEGMENTS = {
    "claude", "claudecode", "codex", "kimi", "kimicode", "workbuddy",
}

#: SFA-NAM-021：名称段不得携带的组织信息。
FAMILY_NAME_FORBIDDEN_ORG_SEGMENTS = {
    "inc", "corp", "ltd", "llc", "org", "company", "team", "group",
}

#: SFA-PLAT-034：完整发行的支持边界必须锚定的声明面。
FULL_RELEASE_CLAIM_FIELDS = (
    "support_scope_limited_to_declared_matrix",
)


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


# ---------------------------------------------------------------------------
# NAM：语义边界 / 词表扩展 / 名称段语法（naming-registry）
# ---------------------------------------------------------------------------


def check_nam_019(ctx: dict[str, Any]) -> dict[str, Any]:
    """validate 与 audit 的语义边界。

    机械断言：已声明校验语义登记中，依据版本化正式规则和证据执行的完整
    规范检查必须使用 audit；validate 只允许内部确定性校验。
    """
    document = _doc(ctx, "naming-registry")
    if document is None:
        return result("PASS", verification_semantics_declared=0, mechanical_half=True)
    rows = rows_of(document, "verification_semantics", "naming-registry")
    violations = []
    for index, row in enumerate(rows):
        code_word = row.get("code_word")
        if code_word not in VERIFICATION_CODE_WORDS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"naming-registry.verification_semantics 第 {index} 行代码词非法: {code_word!r}",
            )
        full_spec = row.get("full_spec_check_on_versioned_rules_and_evidence")
        if not isinstance(full_spec, bool):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                "naming-registry.verification_semantics 必须声明完整规范检查布尔语义",
            )
        problems = []
        if full_spec and code_word != "audit":
            problems.append("full_spec_check_not_named_audit")
        if code_word == "validate" and full_spec:
            problems.append("validate_exceeds_internal_deterministic_scope")
        if problems:
            violations.append(
                {"index": index, "activity": row.get("activity_id"), "problems": problems}
            )
    if violations:
        return result("FAIL", validate_audit_boundary_crossed=violations, mechanical_half=True)
    return result("PASS", verification_semantics=len(rows), mechanical_half=True)


def check_nam_020(ctx: dict[str, Any]) -> dict[str, Any]:
    """领域词表扩展治理。

    机械断言：已声明词表扩展必须给出唯一代码词、中文定义和与既有词的
    边界；代码词不得复用第一版词表既有词（不得私造同义词或改变既有词义），
    且批内不得重复。
    """
    document = _doc(ctx, "naming-registry")
    if document is None:
        return result("PASS", vocabulary_extensions_declared=0, mechanical_half=True)
    rows = rows_of(document, "vocabulary_extensions", "naming-registry")
    existing = set(PUBLIC_INTENTS) | set(INTERNAL_ACTIONS)
    seen: set[str] = set()
    violations = []
    for index, row in enumerate(rows):
        code_word = row.get("code_word")
        problems = []
        if not _nonempty_str(code_word):
            problems.append("code_word_missing")
        else:
            if code_word in existing:
                problems.append("reuses_existing_vocabulary_word")
            if code_word in seen:
                problems.append("duplicate_code_word_within_extensions")
            seen.add(code_word)
        if not _nonempty_str(row.get("chinese_definition")):
            problems.append("chinese_definition_missing")
        if not _nonempty_str(row.get("boundary_with_existing")):
            problems.append("boundary_with_existing_missing")
        if problems:
            violations.append(
                {"index": index, "code_word": code_word, "problems": problems}
            )
    if violations:
        return result("FAIL", vocabulary_extension_governance_violations=violations, mechanical_half=True)
    return result("PASS", vocabulary_extensions=len(rows), mechanical_half=True)


def check_nam_021(ctx: dict[str, Any]) -> dict[str, Any]:
    """技能族名称段语法。

    机械断言：已声明技能族名称必须为英文小写连字符形式，不得出现大写、
    数字、平台名称、组织信息等不稳定限定语（名词化与业务可读的行为核验
    挂账）。
    """
    document = _doc(ctx, "naming-registry")
    if document is None:
        return result("PASS", family_names_declared=0, mechanical_half=True)
    rows = rows_of(document, "family_name_segments", "naming-registry")
    violations = []
    for index, row in enumerate(rows):
        name = row.get("name")
        problems = []
        if not isinstance(name, str) or not FAMILY_NAME_PATTERN.match(name):
            problems.append("name_shape_invalid")
        else:
            segments = name.split("-")
            hit_platforms = sorted(set(segments) & FAMILY_NAME_FORBIDDEN_PLATFORM_SEGMENTS)
            hit_orgs = sorted(set(segments) & FAMILY_NAME_FORBIDDEN_ORG_SEGMENTS)
            if hit_platforms:
                problems.append(f"platform_name_segments:{hit_platforms}")
            if hit_orgs:
                problems.append(f"organization_segments:{hit_orgs}")
        if problems:
            violations.append({"index": index, "name": name, "problems": problems})
    if violations:
        return result("FAIL", family_name_segment_violations=violations, mechanical_half=True)
    return result("PASS", family_names=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# PLAT：进程模型 / 架构交集 / 支持边界（platform-projections）
# ---------------------------------------------------------------------------


def check_plat_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """平台内部进程模型可以不同。

    机械断言：已声明平台投影不得要求四个平台采用相同的执行单元文件、
    子进程、会话或委派模型（进程模型统一化声明即违反）。
    """
    document = _doc(ctx, "platform-projections")
    if document is None:
        return result("PASS", projections_declared=False, mechanical_half=True)
    uniformity = document.get("process_model_uniformity")
    if uniformity is not None and not isinstance(uniformity, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "platform-projections.process_model_uniformity 必须是对象",
        )
    problems = []
    if isinstance(uniformity, dict) and uniformity.get("required") is True:
        problems.append("process_model_uniformity_required")
    rows = rows_of(document, "projections", "platform-projections")
    for index, row in enumerate(rows):
        if row.get("requires_uniform_process_model") is True:
            problems.append(
                f"platform_requires_uniform_process_model:{row.get('platform')}"
            )
    if problems:
        return result("FAIL", process_model_uniformity_forced=problems, mechanical_half=True)
    return result("PASS", platforms=len(rows), mechanical_half=True)


def check_plat_030(ctx: dict[str, Any]) -> dict[str, Any]:
    """四平台不要求共同系统架构交集。

    机械断言：已声明支持矩阵不得把共同操作系统或共同处理器架构交集声明
    为必需条件。
    """
    document = _doc(ctx, "platform-projections")
    if document is None:
        return result("PASS", projections_declared=False, mechanical_half=True)
    claims = document.get("support_matrix_claims")
    if claims is not None and not isinstance(claims, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "platform-projections.support_matrix_claims 必须是对象",
        )
    problems = []
    if isinstance(claims, dict):
        if claims.get("common_os_required") is True:
            problems.append("common_os_intersection_required")
        if claims.get("common_arch_required") is True:
            problems.append("common_arch_intersection_required")
    rows = rows_of(document, "projections", "platform-projections")
    for row in rows:
        if row.get("requires_common_system_intersection") is True:
            problems.append(
                f"platform_requires_common_intersection:{row.get('platform')}"
            )
    if problems:
        return result("FAIL", support_matrix_intersection_forced=problems, mechanical_half=True)
    return result("PASS", platforms=len(rows), mechanical_half=True)


def check_plat_034(ctx: dict[str, Any]) -> dict[str, Any]:
    """完整发行不等于支持所有宿主环境。

    机械断言：已声明完整发行必须把支持范围锚定在各自声明矩阵内，不得
    声明支持宿主能够运行的所有操作系统、架构和运行时。
    """
    document = _doc(ctx, "platform-projections")
    if document is None:
        return result("PASS", projections_declared=False, mechanical_half=True)
    rows = rows_of(document, "projections", "platform-projections")
    violations = []
    for index, row in enumerate(rows):
        releases = row.get("releases")
        if releases is None:
            continue
        if not isinstance(releases, list) or not all(
            isinstance(item, dict) for item in releases
        ):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"platform-projections {row.get('platform')} releases 必须是对象数组",
            )
        for release_index, release in enumerate(releases):
            if release.get("full_distribution") is not True:
                continue
            problems = []
            if release.get("claims_all_host_environments") is True:
                problems.append("claims_all_host_environments")
            for field in FULL_RELEASE_CLAIM_FIELDS:
                if release.get(field) is not True:
                    problems.append(f"{field}_missing")
            if not _nonempty_str(release.get("support_matrix_ref")):
                problems.append("support_matrix_ref_missing")
            if problems:
                violations.append({
                    "platform": row.get("platform"),
                    "release_index": release_index,
                    "problems": problems,
                })
    if violations:
        return result(
            "FAIL", full_distribution_overclaiming_host_support=violations,
            mechanical_half=True,
        )
    return result("PASS", platforms=len(rows), mechanical_half=True)


CHECKS = {
    "SFA-NAM-019": check_nam_019,
    "SFA-NAM-020": check_nam_020,
    "SFA-NAM-021": check_nam_021,
    "SFA-PLAT-010": check_plat_010,
    "SFA-PLAT-030": check_plat_030,
    "SFA-PLAT-034": check_plat_034,
}
