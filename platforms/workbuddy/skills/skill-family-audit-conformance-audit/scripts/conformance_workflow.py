#!/usr/bin/env python3
"""四类受检对象的生产 Conformance 工作流。

确定性规则先执行；只有规则明确声明 ``checkType=semantic`` 时才消费隔离
语义 Worker 的 Schema 化结果。目标只读，唯一写集是显式 output_dir。
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

import conformance_check as checker
import executors
import foundation_adoption_verifier as adoption_verifier
from executors.contracts import ExecutorEvidenceError


TARGET_TYPES = {
    "single_skill",
    "family_source",
    "release_artifact",
    "project_adoption",
}
SEMANTIC_SCHEMA_ID = "skill-family-audit:semantic-review-result"
REFS = Path(__file__).resolve().parent.parent / "refs"
TRUST_POLICY = REFS / "conformance-trust-policy.json"
CANONICAL_PROJECTION = REFS / "canonical-rule-projection.json"
CROSS_SKILL_RULE_PREFIX = "cross-skill:"
SHARED_SKILL_NAME_TEMPLATE = "{{SHARED_SKILL_NAME}}"
TEMPLATE_TOKEN_RE = re.compile(r"\{\{[^{}]+\}\}")
MANAGED_PLATFORM_TEMPLATE_IDS = {
    "claude-code",
    "codex",
    "kimi-code",
    "workbuddy",
}

# Audit 领域既有的 harness 分工裁决（原 migration/harness-owner-adjudications.json
# owner_boundary 的语义冻结）。D3 起采用锁废弃，指导视图直接绑定该领域裁决，
# 不再经由项目 Profile 文档转手。
OWNER_BOUNDARY = {
    "audit": "skill-family-audit",
    "domain_semantics": "skill-family-audit",
    "foundation_harness": "skill-family-foundation",
    "loop": "loop-agent",
    "release": "release-skill",
}

# D1 第一档执行路由：冻结闭包规则逐条显式路由（总数以信任策略 total_rules 钉扎），禁止静默跳过。
# 口径与 scripts/governance/build_first_tier_execution_routing.py 一致：
# 机械方法 = static_scan / schema_validation / digest_verification。
MECHANICAL_CHECK_METHODS = frozenset(
    {"static_scan", "schema_validation", "digest_verification"}
)
ROUTE_FIRST_TIER_STATIC = "first_tier_static_executor"
ROUTE_FIRST_TIER_SEMANTIC = "first_tier_semantic_review"
ROUTE_MECHANICAL_CANDIDATE = "mechanical_candidate_executor_gap"
ROUTE_SEMANTIC_REVIEW = "semantic_review_route"
ROUTE_UNROUTED_CANDIDATE = "candidate_undetermined_not_routed"
EXECUTION_ROUTE_VOCABULARY = (
    ROUTE_FIRST_TIER_STATIC,
    ROUTE_FIRST_TIER_SEMANTIC,
    ROUTE_MECHANICAL_CANDIDATE,
    ROUTE_SEMANTIC_REVIEW,
    ROUTE_UNROUTED_CANDIDATE,
)


def canonical_rule_execution_route(
    rule: dict[str, Any]
) -> tuple[str, str]:
    """返回 (execution_route, execution_route_detail)；逐条显式，不静默跳过。

    - ACTIVE_MECHANICAL / ACTIVE_SEMANTIC：第一档实执行（确定性执行器或
      隔离语义审阅），绑定校验由 _validated_baseline_lineage 失败关闭承担；
    - RETAINED_UNIMPLEMENTED 且含机械方法：机械候选档，执行器缺口明示；
    - 其余 RETAINED：语义审阅路由；
    - 候选未决：失败关闭，不得路由。
    """
    lifecycle = rule.get("lifecycle_status")
    methods = sorted(set(rule.get("check_methods") or []))
    if lifecycle == "ACTIVE_MECHANICAL":
        return ROUTE_FIRST_TIER_STATIC, "terminal_governance_baseline_static"
    if lifecycle == "ACTIVE_SEMANTIC":
        return ROUTE_FIRST_TIER_SEMANTIC, "isolated_semantic_review"
    if lifecycle == "RETAINED_UNIMPLEMENTED":
        mechanical = sorted(set(methods) & MECHANICAL_CHECK_METHODS)
        if mechanical:
            return (
                ROUTE_MECHANICAL_CANDIDATE,
                "executor_missing:" + "+".join(mechanical),
            )
        if "semantic_review" in methods:
            return ROUTE_SEMANTIC_REVIEW, "semantic_review_required"
        if methods == ["behavior_verification"]:
            return ROUTE_SEMANTIC_REVIEW, "behavior_verification_only"
        return ROUTE_SEMANTIC_REVIEW, "no_mechanical_method"
    return ROUTE_UNROUTED_CANDIDATE, "candidate_undetermined"


class WorkflowError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _foundation(request: dict[str, Any]) -> dict[str, Any]:
    try:
        return checker._foundation(request)
    except RuntimeError as exc:
        raise WorkflowError("FOUNDATION_MECHANISM_FAILED", str(exc)) from exc


def foundation_canonical_bytes(value: Any) -> bytes:
    return str(_foundation({"operation": "canonical-json", "document": value})["text"]).encode("utf-8")


def foundation_document_digest(value: Any) -> str:
    return str(_foundation({"operation": "digest-document", "document": value})["digest"])


def foundation_resource_closure(root: Path, relative_paths: list[str]) -> dict[str, Any]:
    return _foundation({
        "operation": "resource-closure",
        "root": str(root),
        "resources": [
            {"path": relative, "role": "input"}
            for relative in sorted(relative_paths)
        ],
    })


def foundation_file_digest(path: Path) -> str:
    closure = foundation_resource_closure(path.parent, [path.name])
    return str(closure["resources"][0]["sha256"])


def foundation_tree_digest(root: Path) -> str:
    paths = [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    return str(foundation_resource_closure(root, paths)["digest"])


def foundation_candidate_payload_digest(root: Path) -> str:
    paths = [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(root).as_posix() != "candidate-summary.json"
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    return str(foundation_resource_closure(root, paths)["digest"])


def foundation_target_content_digest(target: Path, target_type: str) -> str:
    if target_type == "single_skill":
        skill = target if target.name == "SKILL.md" else target / "SKILL.md"
        return foundation_file_digest(skill)
    return foundation_tree_digest(target)


def foundation_project_adoption_task_digest(target: Path) -> str:
    """Bind semantic work to declared business inputs, never runtime outputs.

    The project-root ``profile.json`` is the D3 adoption identity.  Declared
    inputs are the profile itself, the Foundation pin artifacts it declares,
    and the ``plugin-src``/``spec`` source/contract authorities.  Generated
    projections, release candidates, test caches, and audit output stay
    outside this task identity.
    """
    profile_relative = "profile.json"
    profile_path = target / profile_relative
    if not profile_path.is_file() or profile_path.is_symlink():
        raise WorkflowError("PROJECT_PROFILE_MISSING", "项目缺少 profile.json")
    profile = load_json(profile_path)
    declared = {profile_relative}
    adoption = profile.get("adoption")
    packages = adoption.get("foundation_pin", {}).get("packages") if isinstance(adoption, dict) else None
    if not isinstance(packages, dict) or not packages:
        raise WorkflowError(
            "PROJECT_PROFILE_INVALID",
            "profile.json adoption.foundation_pin.packages 必须声明 Foundation pin",
        )
    for name, pin in packages.items():
        relative = pin.get("path") if isinstance(pin, dict) else None
        _validate_posix_relative_path(relative, f"adoption.foundation_pin.packages.{name}.path")
        declared.add(relative)
    for authority_root in ("plugin-src", "spec"):
        root = target / authority_root
        if not root.is_dir() or root.is_symlink():
            continue
        declared.update(
            path.relative_to(target).as_posix()
            for path in root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    missing = sorted(relative for relative in declared if not (target / relative).is_file())
    if missing:
        raise WorkflowError(
            "PROJECT_PROFILE_INPUT_MISSING",
            f"声明的 Task 输入不存在: {missing}",
        )
    return str(foundation_resource_closure(target, sorted(declared))["digest"])


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError("INPUT_INVALID", f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkflowError("INPUT_INVALID", f"{path}: 顶层必须是对象")
    return value


def _foundation_schema_errors(value: Any, schema_id: str) -> list[str]:
    """Validate an Audit consumer document through the managed Bundle."""
    result = _foundation({
        "operation": "validate-by-schema-id",
        "schemaId": schema_id,
        "document": value,
    })
    if result.get("valid") is True:
        return []
    return [str(item) for item in result.get("errors", ["schema validation failed"])]


def _semantic_schema_errors(value: Any) -> list[str]:
    """Validate the Audit-owned Worker result through the managed Bundle."""
    return _foundation_schema_errors(value, SEMANTIC_SCHEMA_ID)


def load_rules(
    package: Path, allow_test_fixture: bool
) -> tuple[dict[str, Any], dict[str, Any], bool, dict[str, Any]]:
    index = load_json(package / "authority-index.json")
    manifest_path = package / "applicable-rules.json"
    manifest = load_json(manifest_path)
    is_fixture = index.get("test_fixture") is True
    if is_fixture and not allow_test_fixture:
        raise WorkflowError("TEST_FIXTURE_NOT_ALLOWED", "生产路径拒绝测试规范包")
    trust_policy = load_json(TRUST_POLICY)
    return index, manifest, is_fixture, trust_policy


def canonical_rule_summary(trust_policy: dict[str, Any]) -> dict[str, Any]:
    projection = load_json(CANONICAL_PROJECTION)
    expected = trust_policy.get("canonical_rule_projection", {})
    expected_total_rules = expected.get("total_rules")
    if (
        foundation_file_digest(CANONICAL_PROJECTION) != expected.get("digest")
        or projection.get("source_digest") != expected.get("source_digest")
        or projection.get("business_digest") != expected.get("business_digest")
        or projection.get("total_rules") != expected_total_rules
        or len(projection.get("rules", [])) != expected_total_rules
    ):
        raise WorkflowError(
            "CANONICAL_RULE_PROJECTION_INVALID",
            "权威规则投影与冻结信任策略不一致（含信任策略钉扎的规则总数）",
        )
    dispositions = {
        "candidate_undetermined": 0,
        "retained_unimplemented": 0,
        "effective": 0,
    }
    for rule in projection["rules"]:
        if rule.get("lifecycle_status") == "RETAINED_UNIMPLEMENTED":
            dispositions["retained_unimplemented"] += 1
        elif (
            rule.get("effect") == "candidate_undetermined"
            or rule.get("adoption_mode") == "candidate_undetermined"
        ):
            dispositions["candidate_undetermined"] += 1
        elif rule.get("lifecycle_status") in {
            "ACTIVE_MECHANICAL",
            "ACTIVE_SEMANTIC",
        }:
            dispositions["effective"] += 1
    return {
        "projection_digest": foundation_file_digest(CANONICAL_PROJECTION),
        "source_digest": projection["source_digest"],
        "business_digest": projection["business_digest"],
        "total_rules": expected_total_rules,
        **dispositions,
    }


def canonical_rule_applicability(
    trust_policy: dict[str, Any],
    target_type: str,
    platform: str = "all",
) -> dict[str, Any]:
    """逐条分类信任策略钉扎的全量规则；终态记录是候选投影的唯一运行覆盖。"""
    summary = canonical_rule_summary(trust_policy)
    projection = load_json(CANONICAL_PROJECTION)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in projection["rules"]:
        canonical_id = rule.get("canonical_id")
        revision = rule.get("revision")
        revision_digest = rule.get("revision_digest")
        effect = rule.get("effect")
        adoption_mode = rule.get("adoption_mode")
        lifecycle_status = rule.get("lifecycle_status")
        platform_scope = rule.get("platform_scope")
        if (
            not isinstance(canonical_id, str)
            or not canonical_id
            or canonical_id in seen
            or not isinstance(revision, int)
            or revision < 1
            or not isinstance(revision_digest, str)
            or len(revision_digest) != 64
            or not isinstance(platform_scope, list)
            or not all(isinstance(item, str) for item in platform_scope)
        ):
            raise WorkflowError(
                "CANONICAL_RULE_APPLICABILITY_INVALID",
                f"权威规则身份或适用性字段非法: {canonical_id}",
            )
        seen.add(canonical_id)
        candidate_undetermined = (
            lifecycle_status == "candidate"
            or effect == "candidate_undetermined"
            or adoption_mode == "candidate_undetermined"
            or "candidate_undetermined" in platform_scope
        )
        retained_unimplemented = lifecycle_status == "RETAINED_UNIMPLEMENTED"
        active = lifecycle_status in {"ACTIVE_MECHANICAL", "ACTIVE_SEMANTIC"}
        executable = active and not candidate_undetermined and not retained_unimplemented and (
            target_type == "project_adoption"
            or (
                target_type == "family_source"
                and rule.get("applicability") in {"all_families", "family_scoped"}
            )
        )
        execution_route, execution_route_detail = canonical_rule_execution_route(rule)
        if candidate_undetermined and execution_route != ROUTE_UNROUTED_CANDIDATE:
            raise WorkflowError(
                "CANONICAL_RULE_APPLICABILITY_INVALID",
                f"候选未决规则不得持有执行路由: {canonical_id}",
            )
        rows.append({
            "canonical_id": canonical_id,
            "revision": revision,
            "revision_digest": revision_digest,
            "effect": effect,
            "adoption_mode": adoption_mode,
            "lifecycle_status": lifecycle_status,
            "platform_scope": platform_scope,
            "requested_target_type": target_type,
            "requested_platform": platform,
            "disposition": (
                "executable" if executable else
                "retained_unimplemented" if retained_unimplemented else
                "candidate_undetermined" if candidate_undetermined else
                "not_applicable"
            ),
            "executable": executable,
            "execution_route": execution_route,
            "execution_route_detail": execution_route_detail,
            "reason": (
                "终态五轴已冻结并适用于当前目标" if executable else
                "规则已保留但尚未绑定可执行实现，禁止执行" if retained_unimplemented else
                "候选权威尚未冻结五轴，禁止执行" if candidate_undetermined else
                "终态规则不适用于当前目标"
            ),
        })
    expected_total_rules = summary["total_rules"]
    if len(rows) != expected_total_rules or len(seen) != expected_total_rules:
        raise WorkflowError(
            "CANONICAL_RULE_APPLICABILITY_INVALID",
            "冻结信任策略钉扎的权威规则没有被逐条且唯一地分类",
        )
    execution_routing_counts = {
        route: sum(1 for row in rows if row["execution_route"] == route)
        for route in EXECUTION_ROUTE_VOCABULARY
    }
    if sum(execution_routing_counts.values()) != expected_total_rules:
        raise WorkflowError(
            "CANONICAL_RULE_APPLICABILITY_INVALID",
            "执行路由未逐条覆盖冻结信任策略钉扎的全量权威规则，存在静默跳过",
        )
    payload = {
        "schema_version": "1.0.0",
        "projection_digest": summary["projection_digest"],
        "target_type": target_type,
        "platform": platform,
        "counts": {
            "total": len(rows),
            "executable": sum(1 for row in rows if row["executable"]),
            "candidate_undetermined": sum(
                1 for row in rows
                if row["disposition"] == "candidate_undetermined"
            ),
            "retained_unimplemented": sum(
                1 for row in rows
                if row["disposition"] == "retained_unimplemented"
            ),
        },
        "execution_routing_counts": execution_routing_counts,
        "rules": rows,
    }
    payload["applicability_digest"] = foundation_document_digest(payload)
    return payload


def bound_rule_set_digest(
    baseline_rules: list[dict[str, Any]],
    canonical_applicability: dict[str, Any],
    canonical_lineage: dict[str, dict[str, str]] | None = None,
) -> str:
    return foundation_document_digest({
        "baseline_rule_set_kind": "implementation-baseline",
        "baseline_rules": baseline_rules,
        "canonical_rule_lineage": sorted(
            (canonical_lineage or {}).values(),
            key=lambda item: (
                item["canonical_id"], item["baseline_rule_id"]
            ),
        ),
        "canonical_projection_digest": canonical_applicability[
            "projection_digest"
        ],
        "canonical_applicability_digest": canonical_applicability[
            "applicability_digest"
        ],
    })


def _validated_baseline_lineage(
    manifest: dict[str, Any],
    rules: list[dict[str, Any]],
    canonical_applicability: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Bind declarations to authoritative rows; declarations alone cover nothing."""
    if manifest.get("ruleSetKind") not in {None, "implementation-baseline"}:
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "现有检查器规则必须明确标记为非权威实现基线",
        )
    declared = manifest.get("canonicalRuleIds", [])
    lineage_rows = manifest.get("canonicalRuleLineage", [])
    if (
        not isinstance(declared, list)
        or not all(isinstance(item, str) and item for item in declared)
        or len(declared) != len(set(declared))
        or not isinstance(lineage_rows, list)
    ):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "canonical lineage 声明必须是唯一且非空的规则身份数组",
        )
    rule_index = {
        rule.get("ruleId"): rule
        for rule in rules
        if isinstance(rule.get("ruleId"), str) and rule.get("ruleId")
    }
    if len(rule_index) != len(rules):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "基线执行规则身份缺失或重复",
        )
    authoritative = {
        row.get("canonical_id"): row
        for row in canonical_applicability.get("rules", [])
        if isinstance(row, dict)
        and isinstance(row.get("canonical_id"), str)
        and row.get("canonical_id")
    }
    # P1（G3 F1）：canonical lineage 按目标类型双重裁剪。非 adoption 目标类型不
    # 装载终态基线规则（terminalRuleImplementations），gmin 基线规则不存在于
    # rule_index。只有"canonical 在当前目标类型可执行 且 其基线规则已装载"的
    # lineage 行才要求绑定校验；其余行只做形状与身份约束校验，不参与绑定比对。
    executable_ids = {
        canonical_id
        for canonical_id, row in authoritative.items()
        if row.get("executable") is True
    }
    bindings: dict[str, dict[str, str]] = {}
    bound_canonical_ids: set[str] = set()
    lineage_by_canonical: dict[str, dict[str, str]] = {}
    required_fields = {
        "baselineRuleId",
        "baselineRevisionDigest",
        "canonicalId",
        "canonicalRevisionDigest",
    }
    for lineage in lineage_rows:
        if not isinstance(lineage, dict) or set(lineage) != required_fields:
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                "canonical lineage 记录字段不完整或包含未知字段",
            )
        baseline_id = lineage["baselineRuleId"]
        baseline_digest = lineage["baselineRevisionDigest"]
        canonical_id = lineage["canonicalId"]
        canonical_digest = lineage["canonicalRevisionDigest"]
        if not all(
            isinstance(item, str) and item
            for item in (
                baseline_id, baseline_digest, canonical_id, canonical_digest
            )
        ):
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                "canonical lineage 身份与摘要必须是非空字符串",
            )
        if canonical_id in lineage_by_canonical:
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"canonical lineage 重复声明: {canonical_id}",
            )
        lineage_by_canonical[canonical_id] = lineage
        if canonical_id not in executable_ids:
            # 本目标类型下不可执行的 canonical 规则不要求基线绑定
            continue
        baseline_rule = rule_index.get(baseline_id)
        if baseline_rule is None:
            # 基线规则未在当前目标类型装载（非 adoption 类型不装载终态规则），
            # 该 canonical 的 lineage 绑定不参与本目标类型的绑定比对
            continue
        canonical_rule = authoritative.get(canonical_id)
        if (
            baseline_id in bindings
            or canonical_id in bound_canonical_ids
            or baseline_rule.get("revisionDigest") != baseline_digest
            or canonical_rule is None
            or canonical_rule.get("executable") is not True
            or canonical_rule.get("revision_digest") != canonical_digest
        ):
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"canonical lineage 未绑定同一权威规则与实际基线修订: {canonical_id}",
            )
        bindings[baseline_id] = {
            "baseline_rule_id": baseline_id,
            "baseline_revision_digest": baseline_digest,
            "canonical_id": canonical_id,
            "canonical_revision_digest": canonical_digest,
        }
        bound_canonical_ids.add(canonical_id)
    # 守卫一：声明了本目标类型可执行 canonical 却缺少 lineage 行 → 失败关闭
    unbound_executable = (set(declared) & executable_ids) - set(
        lineage_by_canonical
    )
    if unbound_executable:
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "canonicalRuleIds 声明了本目标类型可执行的 canonical 规则但缺少 "
            "逐规则 lineage 绑定",
        )
    # 守卫二：可绑定声明与已校验绑定必须逐项一致（按同一可执行且基线已装载口径裁剪）
    declared_pruned = {
        canonical_id
        for canonical_id in declared
        if canonical_id in executable_ids
        and canonical_id in lineage_by_canonical
        and lineage_by_canonical[canonical_id]["baselineRuleId"] in rule_index
    }
    if declared_pruned != bound_canonical_ids:
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "canonicalRuleIds 与逐规则 lineage 绑定不一致",
        )
    return bindings


def _canonical_coverage_from_results(
    canonical_applicability: dict[str, Any],
    bindings: dict[str, dict[str, str]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Count only real execution results carrying the verified lineage tuple."""
    required = {
        (row["canonical_id"], row["revision_digest"])
        for row in canonical_applicability["rules"]
        if row.get("executable") is True
    }
    result_index = {item.get("rule_id"): item for item in results}
    covered: set[tuple[str, str]] = set()
    for baseline_id, binding in bindings.items():
        result = result_index.get(baseline_id)
        expected_lineage = {
            "canonical_id": binding["canonical_id"],
            "revision_digest": binding["canonical_revision_digest"],
        }
        if (
            result is None
            or result.get("rule_revision_digest")
            != binding["baseline_revision_digest"]
            or result.get("canonical_lineage") != expected_lineage
        ):
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"执行结果未绑定已验证 canonical lineage: {baseline_id}",
            )
        covered.add((binding["canonical_id"], binding["canonical_revision_digest"]))
    if not covered <= required:
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "执行结果包含非权威或不可执行 canonical lineage",
        )
    complete = bool(required) and covered == required
    return {
        "required_executable_rule_count": len(required),
        "covered_executable_rule_count": len(covered),
        "complete": complete,
        "reason_code": (
            "CANONICAL_EXECUTABLE_COVERAGE_COMPLETE"
            if complete
            else "CANONICAL_EXECUTABLE_COVERAGE_ZERO"
            if not required
            else "CANONICAL_EXECUTABLE_COVERAGE_INCOMPLETE"
        ),
    }


def _release_reference_values(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(child, str)
                and child.split("#", 1)[0].endswith(".json")
                and (key == "$ref" or key.endswith("Ref") or key.endswith("_ref"))
            ):
                refs.append(child)
            refs.extend(_release_reference_values(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_release_reference_values(child))
    return refs


def _validate_release_closure(root: Path) -> list[str]:
    files: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise WorkflowError(
                "RELEASE_ARTIFACT_CLOSURE_INVALID", "发行物包含符号链接"
            )
        if path.is_file():
            files.append(path.relative_to(root).as_posix())
    for relative in files:
        path = root / relative
        if path.suffix != ".json":
            continue
        value = load_json(path)
        for reference in _release_reference_values(value):
            resource = reference.split("#", 1)[0]
            if not resource:
                continue
            candidate = (
                root / resource
                if resource.startswith(("spec/", "platforms/"))
                else path.parent / resource
            )
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root.resolve())
            except (OSError, ValueError) as exc:
                raise WorkflowError(
                    "RELEASE_ARTIFACT_CLOSURE_INVALID",
                    f"未闭合或越界引用: {relative} -> {reference}",
                ) from exc
            if candidate.is_symlink() or not resolved.is_file():
                raise WorkflowError(
                    "RELEASE_ARTIFACT_CLOSURE_INVALID",
                    f"引用不是普通文件: {relative} -> {reference}",
                )
    return files


def _foundation_platform_payload_digest(root: Path) -> str:
    paths = [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(root).as_posix() != "platform-manifest.json"
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    return str(foundation_resource_closure(root, paths)["digest"])


PLUGIN_PROJECT_SCHEMA_NAME = "plugin-project-observation.schema.json"
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


def _validate_posix_relative_path(value: str, field_name: str) -> None:
    """收容校验：必须是 POSIX 相对路径，拒绝绝对路径、遍历、反斜杠。"""
    if not isinstance(value, str) or not value:
        raise WorkflowError(
            "PROJECT_ADOPTION_INVALID",
            f"{field_name} 不是非空字符串",
        )
    if value.startswith("/") or value.startswith("\\"):
        raise WorkflowError(
            "PROJECT_ADOPTION_INVALID",
            f"{field_name} 是绝对路径: {value}",
        )
    if "\\" in value:
        raise WorkflowError(
            "PROJECT_ADOPTION_INVALID",
            f"{field_name} 包含反斜杠: {value}",
        )
    # 使用原始字符串分割检查，避免 Path() 自动规范化
    parts = value.split("/")
    if ".." in parts:
        raise WorkflowError(
            "PROJECT_ADOPTION_INVALID",
            f"{field_name} 包含遍历 '..': {value}",
        )
    if not parts or any(part in ("", ".") for part in parts):
        raise WorkflowError(
            "PROJECT_ADOPTION_INVALID",
            f"{field_name} 不是规范相对路径: {value}",
        )


def _validate_harness_scan_root(target: Path, value: str) -> Path:
    """校验 Foundation receipt 的产品源扫描根。

    ``.`` 保持兼容；其他值必须是位于项目根内、不经过符号链接的
    规范 POSIX 相对目录。Foundation 仍以项目根为 ``root``，并使用
    receipt 自身的 ``scanRoot`` 进行真实重扫。
    """
    if value == ".":
        return target.resolve()
    _validate_posix_relative_path(value, "harness_inventory.scanRoot")
    project_root = target.resolve()
    current = project_root
    for part in value.split("/"):
        current = current / part
        if current.is_symlink():
            raise WorkflowError(
                "HARNESS_INVENTORY_SCAN_ROOT_INVALID",
                f"receipt scanRoot 路径链中存在符号链接: {value}",
            )
    try:
        scan_root = current.resolve(strict=True)
        scan_root.relative_to(project_root)
    except (FileNotFoundError, ValueError) as exc:
        raise WorkflowError(
            "HARNESS_INVENTORY_SCAN_ROOT_INVALID",
            f"receipt scanRoot 不在项目根内或不存在: {value}",
        ) from exc
    if not scan_root.is_dir():
        raise WorkflowError(
            "HARNESS_INVENTORY_SCAN_ROOT_INVALID",
            f"receipt scanRoot 不是目录: {value}",
        )
    return scan_root


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _manifest_identity(
    path: Path,
    root: Path,
    *,
    package_name_is_plugin_id: bool = True,
) -> dict[str, Any]:
    value = load_json(path)
    plugin_id_fields = [("pluginId", "familyId")]
    if package_name_is_plugin_id:
        plugin_id_fields.append(("pluginId", "name"))
    plugin_id_fields.append(("pluginId", "id"))
    supported_claims = (
        *plugin_id_fields,
        ("version", "version"),
    )
    claims = sorted(
        (
            {
                "dimension": dimension,
                "field": field,
                "value": value[field],
            }
            for dimension, field in supported_claims
            if isinstance(value.get(field), str) and value[field]
        ),
        key=lambda claim: (
            claim["dimension"], claim["field"], claim["value"]
        ),
    )
    plugin_id = next(
        (
            value[field]
            for _, field in plugin_id_fields
            if isinstance(value.get(field), str) and value[field]
        ),
        None,
    )
    version = value.get("version")
    return {
        "path": _relative_path(path, root),
        "pluginId": plugin_id if isinstance(plugin_id, str) and plugin_id else None,
        "version": version if isinstance(version, str) and version else None,
        "claims": claims,
        "contentDigest": foundation_file_digest(path),
    }


def _frontmatter_identity(skill: Path) -> str:
    content = skill.read_text(encoding="utf-8")
    frontmatter, error = checker._parse_frontmatter(content)
    if isinstance(frontmatter, dict):
        name = frontmatter.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    fallback = skill.parent.name if skill.parent.name else "skill"
    return fallback


def _managed_platform_source_template(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    raw_mappings: list[Any],
) -> Path | None:
    """Return the one pre-instantiation template owned by a closed projection."""
    platform_id = manifest.get("platformId")
    if (
        platform_id not in MANAGED_PLATFORM_TEMPLATE_IDS
        or manifest_path.parent.name != platform_id
        or manifest.get("projectionStatus") != "projection_complete"
        or len(raw_mappings) != 1
    ):
        return None
    mapping = raw_mappings[0]
    if not isinstance(mapping, dict):
        return None
    logical_name = mapping.get("logicalName")
    physical_name = mapping.get("physicalName")
    mapping_path = mapping.get("path")
    if (
        not isinstance(logical_name, str)
        or not logical_name
        or TEMPLATE_TOKEN_RE.search(logical_name)
        or physical_name != logical_name
        or not isinstance(mapping_path, str)
        or not mapping_path
    ):
        return None
    relative_mapping = Path(mapping_path)
    if (
        relative_mapping.is_absolute()
        or ".." in relative_mapping.parts
        or relative_mapping.name != "SKILL.md"
    ):
        return None
    projected_path = (manifest_path.parent / relative_mapping).resolve()
    if projected_path != root and root not in projected_path.parents:
        return None
    template = manifest_path.parent / "SKILL.md"
    if (
        projected_path == template.resolve()
        or not template.is_file()
        or template.is_symlink()
        or _frontmatter_identity(template) != SHARED_SKILL_NAME_TEMPLATE
    ):
        return None
    return template.resolve()


def _validate_plugin_identity(
    plugin_id: str | None,
    version: str | None,
    manifest_rows: list[dict[str, Any]],
    candidate: dict[str, Any] | None,
) -> None:
    """Reject conflicting identity claims without storing a claims ledger."""
    if not plugin_id:
        return
    claims: list[dict[str, str]] = []
    for row in manifest_rows:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path", "<unknown>"))
        row_claims = row.get("claims")
        if not isinstance(row_claims, list):
            continue
        for claim in row_claims:
            if (
                isinstance(claim, dict)
                and isinstance(claim.get("dimension"), str)
                and isinstance(claim.get("field"), str)
                and isinstance(claim.get("value"), str)
                and claim["value"]
            ):
                claims.append({
                    "path": path,
                    "dimension": claim["dimension"],
                    "field": claim["field"],
                    "value": claim["value"],
                })

    if isinstance(candidate, dict):
        candidate_version = candidate.get("version")
        if isinstance(candidate_version, str) and candidate_version:
            claims.append({
                "path": "candidate-summary.json",
                "dimension": "version",
                "field": "version",
                "value": candidate_version,
            })
        summary_candidate = candidate.get("id")
        if isinstance(summary_candidate, str) and summary_candidate:
            claims.append({
                "path": "candidate-summary.json",
                "dimension": "candidateId",
                "field": "candidateId",
                "value": summary_candidate,
            })

    expected = {
        "pluginId": plugin_id,
        "version": version,
        "candidateId": (
            f"{plugin_id}:{version}"
            if isinstance(version, str) and version
            else None
        ),
    }
    error_codes = {
        "pluginId": "PLUGIN_PROJECT_PLUGIN_IDENTITY_MISMATCH",
        "version": "PLUGIN_PROJECT_VERSION_IDENTITY_MISMATCH",
        "candidateId": "PLUGIN_PROJECT_CANDIDATE_IDENTITY_MISMATCH",
    }
    labels = {
        "pluginId": "插件身份声明",
        "version": "版本声明",
        "candidateId": "候选身份声明",
    }
    for dimension in ("pluginId", "version", "candidateId"):
        canonical_value = expected[dimension]
        if not isinstance(canonical_value, str) or not canonical_value:
            continue
        conflicts = sorted(
            (
                {
                    "path": claim["path"],
                    "field": claim["field"],
                    "dimension": dimension,
                }
                for claim in claims
                if claim["dimension"] == dimension
                and claim["value"] != canonical_value
            ),
            key=lambda evidence: (
                evidence["path"], evidence["field"], evidence["dimension"]
            ),
        )
        if conflicts:
            raise WorkflowError(
                error_codes[dimension],
                f"{labels[dimension]}与 canonical {dimension} "
                f"{canonical_value!r} 冲突: {conflicts}",
            )


def validate_plugin_project_observation(observation: dict[str, Any]) -> None:
    """Validate only scope requirements and declared projection mappings."""
    scope = observation.get("scope")
    projections = observation.get("projections")
    skills = observation.get("skills")
    observed_ids = {
        item.get("id")
        for item in skills or []
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    mapped_ids = {
        mapping.get("skillId")
        for projection in projections or []
        if isinstance(projection, dict)
        for mapping in projection.get("mappings", [])
        if isinstance(mapping, dict)
        and isinstance(mapping.get("skillId"), str)
    }
    unmapped = sorted(mapped_ids - observed_ids)
    if unmapped:
        raise WorkflowError(
            "PROJECTION_LOGICAL_SKILL_UNMAPPED",
            f"平台投影引用不存在的逻辑技能: {unmapped}",
        )
    if scope == "skill" and len(observed_ids) != 1:
        raise WorkflowError(
            "PLUGIN_PROJECT_OBSERVATION_INVALID",
            "skill scope 必须恰好包含一个 Skill",
        )
    if scope in {"plugin", "release"} and not isinstance(
        observation.get("plugin"), dict
    ):
        raise WorkflowError(
            "PLUGIN_PROJECT_IDENTITY_MISSING",
            f"{scope} scope 必须具有插件身份",
        )

    errors = _foundation_schema_errors(
        observation,
        "https://contracts.skill-family.example/skill-family-audit/"
        "candidate/v2/plugin-project-observation.json",
    )
    if errors:
        raise WorkflowError(
            "PLUGIN_PROJECT_OBSERVATION_INVALID",
            f"PluginProject 观察对象不符合 Audit 合同: {errors}",
        )


def observe_plugin_project(
    target: Path,
    target_type: str,
    *,
    identity_hint: dict[str, Any] | None = None,
    install_digests: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Normalize N=1 and N>1 targets through the same PluginProject path."""
    del install_digests
    root = target.parent if target.is_file() else target
    package_path = root / "package.json"
    candidate_summary_path = root / "candidate-summary.json"

    host_manifest_relatives = (
        ".codex-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codebuddy-plugin/plugin.json",
        "kimi.plugin.json",
    )
    manifest_paths: set[Path] = set()
    identity_relatives = (
        ("platform-manifest.json", *host_manifest_relatives)
        if target_type == "project_adoption"
        else (
            "package.json",
            "plugin-src/manifest.json",
            *host_manifest_relatives,
        )
    )
    for relative in identity_relatives:
        path = root / relative
        if path.is_file() and not path.is_symlink():
            manifest_paths.add(path)
    if target_type != "project_adoption":
        manifest_paths.update(
            path
            for path in root.rglob("platform-manifest.json")
            if path.is_file()
            and not path.is_symlink()
            and not any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in path.relative_to(root).parts
            )
        )
    manifest_identities = [
        _manifest_identity(
            path,
            root,
            # In project-adoption the project Profile and platform manifest own
            # the plugin identity.  The installed package.json names the adapter
            # distribution and may legitimately differ from the family id.
            package_name_is_plugin_id=not (path == package_path and identity_hint),
        )
        for path in sorted(manifest_paths)
    ]

    package = load_json(package_path) if package_path.is_file() else {}
    summary = (
        load_json(candidate_summary_path)
        if candidate_summary_path.is_file() and not candidate_summary_path.is_symlink()
        else None
    )
    hint = identity_hint or {}
    scope = {
        "single_skill": "skill",
        "release_artifact": "release",
        "family_source": "plugin",
        "project_adoption": "plugin",
    }[target_type]
    plugin_id = hint.get("pluginId") or package.get("name")
    version = hint.get("version") or package.get("version")
    if not isinstance(plugin_id, str) or not plugin_id:
        plugin_id = next(
            (
                row["pluginId"]
                for row in manifest_identities
                if isinstance(row.get("pluginId"), str) and row["pluginId"]
            ),
            None,
        )
    if not isinstance(version, str) or not version:
        version = next(
            (
                row["version"]
                for row in manifest_identities
                if isinstance(row.get("version"), str) and row["version"]
            ),
            None,
        )

    projections = []
    projected_skill_paths: set[Path] = set()
    managed_template_paths: set[Path] = set()
    for manifest_path in sorted(root.rglob("platform-manifest.json")):
        if (
            not manifest_path.is_file()
            or manifest_path.is_symlink()
            or any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in manifest_path.relative_to(root).parts
            )
        ):
            continue
        manifest = load_json(manifest_path)
        raw_mappings = manifest.get("logicalMappings", [])
        if not isinstance(raw_mappings, list):
            raise WorkflowError(
                "PLUGIN_PROJECT_OBSERVATION_INVALID",
                f"平台投影 logicalMappings 不是数组: {_relative_path(manifest_path, root)}",
            )
        managed_template = _managed_platform_source_template(
            root, manifest_path, manifest, raw_mappings
        )
        if managed_template is not None:
            managed_template_paths.add(managed_template)
        mappings = []
        for raw in raw_mappings:
            if not isinstance(raw, dict):
                raise WorkflowError(
                    "PLUGIN_PROJECT_OBSERVATION_INVALID",
                    f"平台投影映射不是对象: {_relative_path(manifest_path, root)}",
                )
            logical_id = raw.get("logicalName")
            if not isinstance(logical_id, str) or not logical_id:
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    f"平台投影缺少逻辑技能 ID: {_relative_path(manifest_path, root)}",
                )
            mapping_path = raw.get("path")
            if not isinstance(mapping_path, str) or not mapping_path:
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    f"平台投影映射缺少 Skill 路径: {_relative_path(manifest_path, root)}",
                )
            if ".." not in Path(mapping_path).parts:
                projected_skill_paths.add(
                    (manifest_path.parent / mapping_path).resolve()
                )
            mappings.append({
                "skillId": logical_id,
                "path": mapping_path if isinstance(mapping_path, str) else None,
            })
        platform_id = manifest.get("platformId")
        projections.append({
            "platform": platform_id if isinstance(platform_id, str) and platform_id else manifest_path.parent.name,
            "manifest": _relative_path(manifest_path, root),
            "mappings": sorted(
                mappings,
                key=lambda item: (
                    item["skillId"], item["path"]
                ),
            ),
        })

    if target.is_file():
        skill_paths = [target]
    else:
        skill_paths = [
            path
            for path in sorted(root.rglob("SKILL.md"))
            if path.is_file()
            and not path.is_symlink()
            and path.resolve() not in projected_skill_paths
            and not any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in path.relative_to(root).parts
            )
        ]
    skills = []
    seen_ids: dict[str, str] = {}
    for skill in skill_paths:
        logical_id = _frontmatter_identity(skill)
        relative = _relative_path(skill, root)
        if TEMPLATE_TOKEN_RE.search(logical_id):
            if (
                logical_id == SHARED_SKILL_NAME_TEMPLATE
                and skill.resolve() in managed_template_paths
            ):
                continue
            raise WorkflowError(
                "UNMANAGED_LOGICAL_SKILL_TEMPLATE",
                f"未由闭合平台投影认领的逻辑技能模板: {relative}",
            )
        if logical_id in seen_ids:
            raise WorkflowError(
                "DUPLICATE_LOGICAL_SKILL_ID",
                f"逻辑技能 ID {logical_id!r} 同时由 {seen_ids[logical_id]} 与 {relative} 声明",
            )
        seen_ids[logical_id] = relative
        skills.append({"id": logical_id, "path": relative})

    if not skills:
        for projection in projections:
            manifest_parent = root / Path(projection["manifest"]).parent
            for mapping in projection["mappings"]:
                path = (manifest_parent / mapping["path"]).resolve()
                if (
                    path.is_file()
                    and not path.is_symlink()
                    and (path == root or root in path.parents)
                    and mapping["skillId"] not in seen_ids
                ):
                    relative = _relative_path(path, root)
                    seen_ids[mapping["skillId"]] = relative
                    skills.append({"id": mapping["skillId"], "path": relative})
    if not skills:
        raise WorkflowError("FAMILY_SOURCE_EMPTY", "受检插件没有可观察逻辑技能")

    observation: dict[str, Any] = {
        "schemaVersion": "1.0.0-candidate",
        "scope": scope,
        "skills": sorted(skills, key=lambda item: (item["id"], item["path"])),
        "projections": sorted(
            projections, key=lambda item: (item["platform"], item["manifest"])
        ),
    }
    if isinstance(plugin_id, str) and plugin_id:
        manifest_path = (
            "package.json"
            if package_path.is_file()
            else manifest_identities[0]["path"] if manifest_identities else None
        )
        observation["plugin"] = {
            "id": plugin_id,
            "version": version if isinstance(version, str) else None,
            "manifest": manifest_path,
        }
    candidate = None
    if isinstance(summary, dict):
        candidate_id = summary.get("candidateId") or hint.get("candidateId")
        candidate_version = summary.get("version") or version
        payload_digest = summary.get("candidatePayloadDigest")
        if (
            isinstance(candidate_id, str)
            and isinstance(candidate_version, str)
            and isinstance(payload_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", payload_digest)
        ):
            candidate = {
                "id": candidate_id,
                "version": candidate_version,
                "payloadDigest": payload_digest,
            }
            observation["candidate"] = candidate
    _validate_plugin_identity(plugin_id, version, manifest_identities, candidate)
    validate_plugin_project_observation(observation)
    return observation


def _assert_project_profile_baseline(
    profile_document: dict[str, Any], profile_result: dict[str, Any]
) -> None:
    """Audit 领域判定：项目必须采用 Audit 捆绑的 Foundation 基线。

    SPI 只证明 profile 自身合同闭合与摘要真实；采用版本是否与 Audit
    实际携带的 Foundation 0.8.0 一致属于 Audit 的领域判断。基线事实取自
    SPI 运行闭包 provenance（由权威生成器从隔离安装机械投影），不在
    Audit 侧重复 Foundation 的 Schema 或摘要算法。
    """
    closure_root = Path(profile_result.get("closure_root", ""))
    provenance_path = (
        closure_root / adoption_verifier.SPI_PROVENANCE_RELATIVE
    )
    try:
        provenance = load_json(provenance_path)
    except WorkflowError as exc:
        raise WorkflowError(
            "PROJECT_PROFILE_BASELINE_MISSING",
            f"SPI 闭包 provenance 不可读: {exc}",
        ) from exc
    expected_profile = provenance.get("profile")
    if not isinstance(expected_profile, dict):
        raise WorkflowError(
            "PROJECT_PROFILE_BASELINE_MISSING", "SPI 闭包 provenance 缺少 profile 绑定"
        )
    adoption = profile_document.get("adoption", {})
    declared_profile = adoption.get("foundation_profile", {})
    for key in ("id", "version"):
        if declared_profile.get(key) != expected_profile.get(key):
            raise WorkflowError(
                "PROJECT_PROFILE_BASELINE_MISMATCH",
                f"项目采用的 Foundation profile {key} 与 Audit 基线不一致: "
                f"declared={declared_profile.get(key)} expected={expected_profile.get(key)}",
            )
    expected_packages = {
        item["name"]: item["version"]
        for item in provenance.get("packages", [])
        if isinstance(item, dict) and "name" in item and "version" in item
    }
    declared_packages = adoption.get("foundation_pin", {}).get("packages", {})
    for name, expected_version in sorted(expected_packages.items()):
        pin = declared_packages.get(name)
        declared_version = pin.get("version") if isinstance(pin, dict) else None
        if declared_version != expected_version:
            raise WorkflowError(
                "PROJECT_PROFILE_BASELINE_MISMATCH",
                f"项目采用的 Foundation 包版本与 Audit 基线不一致: {name} "
                f"declared={declared_version} expected={expected_version}",
            )


def target_scope(target: Path, target_type: str) -> dict[str, Any]:
    if target_type == "single_skill":
        skill = target if target.name == "SKILL.md" else target / "SKILL.md"
        if not skill.is_file():
            raise WorkflowError("SINGLE_SKILL_MISSING", "单技能目标缺少 SKILL.md")
        observation = observe_plugin_project(skill, target_type)
        return {
            "skill_files": [skill.relative_to(target.parent).as_posix()],
            "plugin_project": observation,
            "logical_skill_count": len(observation["skills"]),
        }
    if not target.is_dir():
        raise WorkflowError("TARGET_TYPE_MISMATCH", "该目标类型要求目录")
    if target_type == "family_source":
        skills = sorted(
            path.relative_to(target).as_posix()
            for path in target.rglob("SKILL.md")
            if path.is_file() and not path.is_symlink()
        )
        if not skills:
            raise WorkflowError("FAMILY_SOURCE_EMPTY", "技能族源码没有 SKILL.md")
        observation = observe_plugin_project(target, target_type)
        source_excluded_parts = {"__pycache__", ".pytest_cache", ".git", "node_modules"}
        source_excluded_suffixes = {".pyc", ".pyo"}
        source_files = sorted(
            path.relative_to(target).as_posix()
            for path in target.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and path.name != "SKILL.md"
            and not any(part in source_excluded_parts for part in path.relative_to(target).parts)
            and path.suffix not in source_excluded_suffixes
        )
        return {
            "skill_files": skills,
            "source_files": source_files,
            "source_tree_digest": foundation_tree_digest(target),
            "plugin_project": observation,
            "logical_skill_count": len(observation["skills"]),
        }
    if target_type == "release_artifact":
        required = ["package.json", "candidate-summary.json"]
        missing = [name for name in required if not (target / name).is_file()]
        if missing:
            raise WorkflowError(
                "RELEASE_ARTIFACT_INCOMPLETE", f"缺失: {missing}"
            )
        package_json = load_json(target / "package.json")
        summary = load_json(target / "candidate-summary.json")
        release_files = _validate_release_closure(target)
        plugin_name = package_json.get("name")
        version = package_json.get("version")
        actual_payload = foundation_candidate_payload_digest(target)
        if (
            not isinstance(plugin_name, str)
            or not plugin_name
            or not isinstance(version, str)
            or summary.get("version") != version
            or summary.get("candidateId") != f"{plugin_name}:{version}"
            or summary.get("candidatePayloadDigest") != actual_payload
        ):
            raise WorkflowError(
                "RELEASE_ARTIFACT_IDENTITY_INVALID",
                "发行包身份、版本或 payload 摘要不闭合",
            )
        observation = observe_plugin_project(target, target_type)
        return {
            "plugin_name": plugin_name,
            "release_files": release_files,
            "release_tree_digest": foundation_tree_digest(target),
            "candidate_payload_digest": actual_payload,
            "plugin_project": observation,
            "logical_skill_count": len(observation["skills"]),
        }
    # D3: 项目根 profile.json 是唯一采用身份来源。Foundation 0.8.0 拥有该合同，
    # 公共入口 verifyProjectProfile 完成外壳校验、真实文件摘要比对与自加严规则检查；
    # verifyProfile 仍只用于 Profile 提供者描述符。缺少 profile 时失败关闭，
    # 不存在任何废弃 adoption lock 回退。
    project_profile_path = target / "profile.json"
    if not project_profile_path.is_file() or project_profile_path.is_symlink():
        raise WorkflowError("PROJECT_PROFILE_MISSING", "项目缺少 profile.json")
    profile_result = adoption_verifier.verify_project_profile(target)
    if not profile_result.get("foundation_profile_complete"):
        raise WorkflowError(
            "PROJECT_PROFILE_INVALID",
            "项目 profile.json 未通过 Foundation Profile SPI: "
            + "; ".join(profile_result.get("blockers", [])),
        )
    profile_document = load_json(project_profile_path)
    _assert_project_profile_baseline(profile_document, profile_result)
    observation = observe_plugin_project(
        target,
        target_type,
        identity_hint={
            "pluginId": profile_document.get("project", {}).get("id"),
            "profileKind": profile_document.get("kind"),
        },
        install_digests=[
            {
                "kind": "project_profile",
                "path": "profile.json",
                "contentDigest": foundation_file_digest(project_profile_path),
            }
        ],
    )
    return {
        "project_profile_document": profile_document,
        "project_profile": "profile.json",
        "project_profile_digest": foundation_file_digest(project_profile_path),
        "foundation_profile": profile_result,
        "plugin_project": observation,
        "logical_skill_count": len(observation["skills"]),
    }

def semantic_reviews(
    path: Path | None,
    rules: list[dict[str, Any]],
    task_digest: str,
    target: Path,
    target_type: str,
    output_dir: Path,
) -> dict[str, dict[str, Any]]:
    semantic = [rule for rule in rules if rule.get("checkType") == "semantic"]
    if not semantic:
        return {}
    if path is None:
        return {
            rule["ruleId"]: {
                "rule_id": rule["ruleId"],
                "rule_revision_digest": rule["revisionDigest"],
                "status": "EVIDENCE_MISSING",
                "evidence": [],
            }
            for rule in semantic
        }
    if path.is_symlink():
        raise WorkflowError(
            "SEMANTIC_RESULT_NOT_REGULAR_FILE",
            "语义结果不得是符号链接",
        )
    try:
        semantic_path = path.resolve(strict=True)
    except OSError as exc:
        raise WorkflowError(
            "SEMANTIC_RESULT_NOT_REGULAR_FILE",
            "语义结果必须是既有普通文件",
        ) from exc
    if not semantic_path.is_file():
        raise WorkflowError(
            "SEMANTIC_RESULT_NOT_REGULAR_FILE",
            "语义结果必须是既有普通文件",
        )
    boundary = target.parent if target.is_file() else target
    if semantic_path == boundary or boundary in semantic_path.parents:
        raise WorkflowError(
            "SEMANTIC_RESULT_INSIDE_TARGET",
            "语义结果必须位于只读目标之外",
        )
    if semantic_path == output_dir or output_dir in semantic_path.parents:
        raise WorkflowError(
            "SEMANTIC_RESULT_INSIDE_OUTPUT",
            "语义结果不得位于本次运行输出目录",
        )
    value = load_json(semantic_path)
    validation_errors = _semantic_schema_errors(value)
    if validation_errors:
        raise WorkflowError(
            "SEMANTIC_RESULT_SCHEMA_INVALID",
            "; ".join(validation_errors),
        )
    if value["task_digest"] != task_digest:
        raise WorkflowError(
            "SEMANTIC_RESULT_TASK_MISMATCH",
            "语义结果没有绑定当前规范化 Task",
        )
    reviews = {item.get("rule_id"): item for item in value["reviews"] if isinstance(item, dict)}
    for rule in semantic:
        review = reviews.get(rule.get("ruleId"))
        if (
            not review
            or review.get("rule_revision_digest") != rule.get("revisionDigest")
            or review.get("status") not in {"PASS", "FAIL", "EVIDENCE_MISSING"}
            or not isinstance(review.get("evidence"), list)
        ):
            raise WorkflowError("SEMANTIC_RESULT_SCHEMA_INVALID", rule.get("ruleId", ""))
        for evidence in review["evidence"]:
            relative = evidence.split(":", 1)[0]
            candidate = (
                target
                if target_type == "single_skill" and target.name == "SKILL.md"
                else target / relative
            )
            cursor = boundary
            try:
                candidate_parts = candidate.relative_to(boundary).parts
            except ValueError:
                candidate_parts = ()
            for part in candidate_parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise WorkflowError("SEMANTIC_EVIDENCE_SYMLINK", evidence)
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise WorkflowError(
                    "SEMANTIC_EVIDENCE_MISSING", evidence
                ) from exc
            if resolved != boundary and boundary not in resolved.parents:
                raise WorkflowError("SEMANTIC_EVIDENCE_ESCAPE", evidence)
            if not resolved.is_file():
                raise WorkflowError("SEMANTIC_EVIDENCE_NOT_REGULAR_FILE", evidence)
            if resolved == semantic_path:
                raise WorkflowError("SEMANTIC_EVIDENCE_SELF_REFERENCE", evidence)
            if resolved == output_dir or output_dir in resolved.parents:
                raise WorkflowError("SEMANTIC_EVIDENCE_RUNTIME_OUTPUT", evidence)
    return reviews


def _validate_method_parameters(
    parameters: dict[str, Any],
) -> None:
    """Draft 2020-12 校验 Audit 领域参数。"""
    errors = _foundation_schema_errors(
        parameters,
        "https://contracts.skill-family.example/skill-family-audit/"
        "candidate/v2/methods/conformance/parameters.json",
    )
    if errors:
        raise WorkflowError(
            "METHOD_PARAMETER_SCHEMA_INVALID",
            f"Conformance 领域参数不符合 parameterSchema: {errors}",
        )


def _gmin_static_outcome(
    rule_id: str,
    scope: dict[str, Any],
) -> dict[str, Any]:
    """Execute the mechanical half of the twelve terminal governance rules.

    D3 rebasing: adoption proof is the project-root profile verified through
    Foundation Profile SPI v3.  Facts now come from the profile document and
    the SPI result.  Rules whose evidence fields only existed in the retired
    lock contract return a stable NOT_APPLICABLE with a deprecation reason
    code instead of inventing substitute evidence.
    """
    profile_result = scope.get("foundation_profile", {})
    profile_document = scope.get("project_profile_document", {})
    complete = profile_result.get("foundation_profile_complete") is True
    steps = profile_result.get("steps", [])
    if rule_id == "gmin:compat-status-evidence":
        required_steps = {
            "project-profile-schema",
            "adoption-pin-digests",
            "overrides-policy",
        }
        checks = {
            "spi_code": profile_result.get("code"),
            "steps": steps,
        }
        status_ok = complete and required_steps <= set(steps)
        return {
            "status": "PASS" if status_ok else "FAIL",
            "evidence": {"foundation_complete": complete, "checks": checks},
        }
    if rule_id == "gmin:harness-authority-dependencies":
        packages = (
            profile_document.get("adoption", {}).get("foundation_pin", {}).get("packages", {})
        )
        owners = []
        if isinstance(packages, dict):
            for name in sorted(packages):
                pin = packages.get(name)
                if (
                    isinstance(pin, dict)
                    and isinstance(pin.get("version"), str)
                    and isinstance(pin.get("path"), str)
                    and isinstance(pin.get("sha256"), str)
                ):
                    owners.append({
                        "authority_source": f"foundation_pin:{name}",
                        "dependency_edges": [
                            other for other in sorted(packages) if other != name
                        ],
                    })
        status_ok = complete and len(owners) == len(packages) and len(owners) >= 3
        return {
            "status": "PASS" if status_ok else "FAIL",
            "evidence": {
                "inventory_verified": complete,
                "authority_dependency_closure": status_ok,
                "owner_count": len(owners),
                "owner_adjudications": owners,
            },
        }
    if rule_id == "gmin:legacy-risk-plan":
        return {
            "status": "NOT_APPLICABLE",
            "evidence": {
                "reason_code": "CONTRACT_DEPRECATED_D8",
                "legacy_risk_count": 0,
                "plan": "plan_not_required",
            },
        }
    if rule_id == "gmin:new-family-native-outer":
        return {
            "status": "NOT_APPLICABLE",
            "evidence": {
                "reason_code": "PROFILE_ADOPTION_NO_ROUTE",
                "required": ["foundation_pin", "bundle_provenance", "migration_manifest"],
                "present": [],
            },
        }
    if rule_id == "gmin:affected-scope-migration":
        return {
            "status": "NOT_APPLICABLE",
            "evidence": {
                "reason_code": "CONTRACT_DEPRECATED_D8",
                "impact_closure": [],
                "migration_scope": [],
            },
        }
    if rule_id == "gmin:family-migration-checklist":
        return {
            "status": "NOT_APPLICABLE",
            "evidence": {"reason_code": "CONTRACT_DEPRECATED_D8", "missing": []},
        }
    if rule_id == "gmin:profile-composition-conflicts":
        required_sections = {
            "schemaVersion", "kind", "project", "adoption", "overrides",
        }
        overrides = profile_document.get("overrides", [])
        seen: set[tuple[Any, Any]] = set()
        conflicts: list[dict[str, Any]] = []
        if isinstance(overrides, list):
            for index, override in enumerate(overrides):
                key = (
                    override.get("ruleId") if isinstance(override, dict) else None,
                    override.get("parameter") if isinstance(override, dict) else None,
                )
                if key in seen:
                    conflicts.append({"index": index, "ruleId": key[0], "parameter": key[1]})
                seen.add(key)
        else:
            conflicts.append({"index": None, "reason": "overrides_not_array"})
        missing = sorted(required_sections - set(profile_document))
        if missing:
            conflicts.append({"missing_sections": missing})
        return {
            "status": "PASS" if complete and not conflicts else "FAIL",
            "evidence": {"conflicts": conflicts},
        }
    if rule_id == "gmin:generated-state-traceability":
        project = profile_document.get("project", {})
        adoption = profile_document.get("adoption", {})
        facts = {
            "project_id": project.get("id") if isinstance(project, dict) else None,
            "adopted_at": adoption.get("adopted_at") if isinstance(adoption, dict) else None,
            "spi_project_id": profile_result.get("projectId"),
            "closure_root": profile_result.get("closure_root"),
        }
        missing = sorted(key for key, value in facts.items() if value in (None, ""))
        return {
            "status": "PASS" if complete and not missing else "FAIL",
            "evidence": {"missing": missing, **facts},
        }
    raise WorkflowError("GMIN_RULE_UNIMPLEMENTED", rule_id)


def _w2b1_executor_outcome(
    rule_id: str,
    scope: dict[str, Any],
    target: Path,
    output_dir: Path,
    args: argparse.Namespace,
    spec_index: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Execute one W2-B1 first-tier mechanical rule through the executor package.

    The context carries only observable target facts and this run's invariants;
    executors never mutate the target. Declared-evidence shape failures are
    fail-closed as EVIDENCE_MISSING findings, never silent passes.
    """
    ctx: dict[str, Any] = {
        "target": target,
        "target_type": args.target_type,
        "scope": scope,
        "manifest": manifest,
        "spec_index": spec_index,
        "output_dir": output_dir,
        "run_args": {
            "target_is_absolute": Path(args.target).is_absolute(),
            "output_dir_declared": bool(args.output_dir),
            "run_id_declared": bool(args.run_id),
        },
        "remediation_patch_status": "unapplied",
    }
    installed = scope.get("installed_root")
    if isinstance(installed, str) and installed:
        installed_root = target / installed
        ctx["recompute_installed_digest"] = (
            lambda: foundation_candidate_payload_digest(installed_root)
        )
    try:
        return executors.execute(rule_id, ctx)
    except ExecutorEvidenceError as exc:
        return {
            "status": "EVIDENCE_MISSING",
            "evidence": {
                "reason": "executor_evidence_invalid",
                "code": getattr(exc, "code", type(exc).__name__),
                "detail": str(exc),
            },
        }


def _canonical_guidance_from_results(
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    scope: dict[str, Any],
    remediation_items: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Compile executable guidance from real, lineage-bound rule results.

    The view does not restate canonical rule prose and does not invent another
    rule layer.  It binds each existing guidance group to the route and owner
    facts in the project Profile, summarizes the evidence shape actually returned
    by its terminal implementations, and links non-passing rules to the current
    remediation items.
    """
    guidance = manifest.get("canonicalGuidance")
    if not isinstance(guidance, dict):
        raise WorkflowError(
            "CANONICAL_GUIDANCE_INVALID",
            "canonicalGuidance 必须声明四类指导视图",
        )
    expected_groups = {
        "new_scaffold",
        "existing_adoption",
        "harness_division",
        "normalization",
    }
    if set(guidance) != expected_groups:
        raise WorkflowError(
            "CANONICAL_GUIDANCE_INVALID",
            "canonicalGuidance 四类指导视图不完整",
        )
    result_index: dict[str, dict[str, Any]] = {}
    for result in results:
        lineage = result.get("canonical_lineage")
        canonical_id = lineage.get("canonical_id") if isinstance(lineage, dict) else None
        if not isinstance(canonical_id, str) or not canonical_id or canonical_id in result_index:
            continue
        result_index[canonical_id] = result

    profile_document = scope.get("project_profile_document")
    profile_result = scope.get("foundation_profile")
    if not isinstance(profile_document, dict) or not isinstance(profile_result, dict):
        raise WorkflowError(
            "CANONICAL_GUIDANCE_CONTEXT_MISSING",
            "四类指导必须绑定当前项目 Profile 与 SPI 校验结果",
        )
    if profile_result.get("foundation_profile_complete") is not True:
        raise WorkflowError(
            "CANONICAL_GUIDANCE_CONTEXT_MISSING",
            "四类指导要求项目 Profile 已通过 Foundation Profile SPI",
        )
    # D3: profile 采用合同不声明 scaffold/adopt-plan 路由；项目 Profile
    # 是存量工作区的采用声明，指导上下文按存量采用路由组织。
    adoption_route = {"route_type": "adopt-plan", "is_new_skill_family": False}
    owner_boundary = OWNER_BOUNDARY
    is_new_family = adoption_route.get("is_new_skill_family")
    if not isinstance(is_new_family, bool):
        raise WorkflowError(
            "CANONICAL_GUIDANCE_CONTEXT_MISSING",
            "四类指导无法判定新建族或存量族路由",
        )
    remediation_by_rule = {
        item.get("rule_id"): item
        for item in remediation_items
        if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
    }
    group_context = {
        "new_scaffold": {
            "route": "scaffold",
            "applicable": is_new_family,
            "owner": {
                "mechanism": owner_boundary.get("foundation_harness"),
                "domain_decision": owner_boundary.get("domain_semantics"),
            },
            "pass_action": "continue_foundation_scaffold",
            "inactive_action": "use_existing_adoption_guidance",
            "blocked_action": "resolve_scaffold_findings",
        },
        "existing_adoption": {
            "route": "adopt-plan",
            "applicable": not is_new_family,
            "owner": {
                "migration_decision": owner_boundary.get("domain_semantics"),
                "conformance": owner_boundary.get("audit"),
            },
            "pass_action": "continue_existing_adoption",
            "inactive_action": "use_new_scaffold_guidance",
            "blocked_action": "resolve_adoption_findings",
        },
        "harness_division": {
            "route": "harness-inventory",
            "applicable": True,
            "owner": {
                "reusable_mechanism": owner_boundary.get("foundation_harness"),
                "surface_classification": owner_boundary.get("domain_semantics"),
            },
            "pass_action": "preserve_harness_owner_boundary",
            "inactive_action": "preserve_harness_owner_boundary",
            "blocked_action": "restore_harness_authority_evidence",
        },
        "normalization": {
            "route": "canonical-normalization",
            "applicable": True,
            "owner": {
                "domain_state": owner_boundary.get("domain_semantics"),
                "conformance": owner_boundary.get("audit"),
            },
            "pass_action": "continue_canonical_normalization",
            "inactive_action": "continue_canonical_normalization",
            "blocked_action": "restore_normalization_evidence",
        },
    }
    aggregates: dict[str, dict[str, Any]] = {}
    for group in sorted(expected_groups):
        canonical_ids = guidance[group]
        if (
            not isinstance(canonical_ids, list)
            or not canonical_ids
            or not all(isinstance(item, str) and item for item in canonical_ids)
            or len(canonical_ids) != len(set(canonical_ids))
        ):
            raise WorkflowError(
                "CANONICAL_GUIDANCE_INVALID",
                f"canonicalGuidance.{group} 必须是唯一且非空的规则身份数组",
            )
        missing = [item for item in canonical_ids if item not in result_index]
        if missing:
            raise WorkflowError(
                "CANONICAL_GUIDANCE_RESULT_MISSING",
                f"{group} 缺少真实执行结果: {missing}",
            )
        group_results = [result_index[item] for item in canonical_ids]
        counts = {
            status: sum(1 for item in group_results if item.get("status") == status)
            for status in ("PASS", "FAIL", "EVIDENCE_MISSING", "NOT_APPLICABLE")
        }
        non_passing = [
            item for item in group_results
            if item.get("status") not in {"PASS", "NOT_APPLICABLE"}
        ]
        context = group_context[group]
        evidence_requirements = []
        for item in group_results:
            evidence = item.get("evidence")
            if isinstance(evidence, dict):
                evidence_shape = {
                    "kind": "fields",
                    "values": sorted(str(key) for key in evidence),
                }
            elif isinstance(evidence, list):
                evidence_shape = {
                    "kind": "references",
                    "values": sorted(str(value) for value in evidence),
                }
            else:
                evidence_shape = {"kind": "missing", "values": []}
            evidence_requirements.append({
                "canonical_id": item["canonical_lineage"]["canonical_id"],
                "baseline_rule_id": item["rule_id"],
                "status": item.get("status"),
                "evidence": evidence_shape,
            })
        if non_passing:
            action_code = context["blocked_action"]
        elif context["applicable"]:
            action_code = context["pass_action"]
        else:
            action_code = context["inactive_action"]
        linked_remediation = [
            remediation_by_rule[item["rule_id"]]
            for item in non_passing
            if item["rule_id"] in remediation_by_rule
        ]
        aggregates[group] = {
            "status": "PASS" if not non_passing else "FAIL",
            "route": context["route"],
            "applicability": {
                "applicable": context["applicable"],
                "reason_code": (
                    "NEW_SKILL_FAMILY" if group == "new_scaffold" and is_new_family
                    else "EXISTING_SKILL_FAMILY" if group == "existing_adoption" and not is_new_family
                    else "ROUTE_NOT_SELECTED" if not context["applicable"]
                    else "ALL_PROJECT_ADOPTIONS"
                ),
            },
            "required_evidence": evidence_requirements,
            "owner": context["owner"],
            "next_actions": [{
                "action": action_code,
                "blocked_by": [item["rule_id"] for item in non_passing],
                "remediation": linked_remediation,
            }],
            "counts": counts,
            "rule_results": [
                {
                    "canonical_id": item["canonical_lineage"]["canonical_id"],
                    "revision_digest": item["canonical_lineage"]["revision_digest"],
                    "baseline_rule_id": item["rule_id"],
                    "status": item["status"],
                }
                for item in group_results
            ],
            "finding_rule_ids": [item["rule_id"] for item in non_passing],
        }
    return aggregates


def run_workflow(args: argparse.Namespace) -> dict[str, Any]:
    if not args.output_dir or not args.run_id:
        raise WorkflowError(
            "WORKFLOW_ARGS_MISSING",
            "完整工作流需要 --output-dir 与 --run-id；规范包可省略（默认自审规范包）或显式 --spec-package",
        )
    spec_package = args.spec_package
    if not spec_package:
        # D2 自审默认发现路径：无显式规范包时只接受本仓裁决权威派生的
        # 自审规范包（selfAudit: true，摘要新鲜性逐条校验）；外部规范必须
        # 显式 --spec-package 提供。自审包缺失时维持失败关闭结论。
        default_spec = checker.self_audit_spec_package_default()
        if default_spec is None:
            raise WorkflowError(
                "NO_ACTIVE_APPROVED_SPEC",
                "未找到批准规范包：自审需要仓内 spec/self-audit/，外部规范需要显式 --spec-package",
            )
        freshness_error = checker.verify_self_audit_freshness(default_spec)
        if freshness_error:
            raise WorkflowError(
                freshness_error,
                "自审规范包陈旧或非法；运行 scripts/spec/build_self_audit_spec_package.py 重建",
            )
        spec_package = str(default_spec)
    target = Path(args.target).resolve(strict=True)
    output_dir = Path(args.output_dir).resolve()
    if output_dir == target or target in output_dir.parents:
        raise WorkflowError("OUTPUT_INSIDE_TARGET", "输出目录不得位于只读目标内")
    index, manifest, is_fixture, trust_policy = load_rules(
        Path(spec_package).resolve(strict=True), args.allow_test_fixture
    )
    scope = target_scope(target, args.target_type)
    declared_observation = os.environ.get("SFA_PLUGIN_PROJECT_OBSERVATION_REF")
    if declared_observation:
        observation_path = Path(declared_observation).resolve(strict=True)
        observation = load_json(observation_path)
        validate_plugin_project_observation(observation)
        if observation != scope["plugin_project"]:
            raise WorkflowError(
                "PLUGIN_PROJECT_OBSERVATION_MISMATCH",
                "Foundation Resource 中的观察对象与当前目标扫描结果不一致",
            )
    applicability = {
        "single_skill": {"all", "skill", "single_skill"},
        "family_source": {"all", "family", "family_source", "skill"},
        "release_artifact": {"all", "release", "release_artifact"},
        "project_adoption": {"all", "adoption", "project_adoption"},
    }[args.target_type]
    rules = [
        rule
        for rule in (
            [
                item
                for category in manifest.get("ruleCategories", [])
                for item in category.get("rules", [])
            ]
            + (
                manifest.get("terminalRuleImplementations", [])
                if args.target_type == "project_adoption" else []
            )
        )
        if rule.get("applicability") in applicability
    ]
    canonical_summary = canonical_rule_summary(trust_policy)
    canonical_applicability = canonical_rule_applicability(
        trust_policy, args.target_type, args.platform
    )
    canonical_lineage = _validated_baseline_lineage(
        manifest, rules, canonical_applicability
    )
    rule_set_digest = bound_rule_set_digest(
        rules, canonical_applicability, canonical_lineage
    )
    parameters = {
        "target_project_path": args.target,
        "scope_selector": {
            "single_skill": "skill",
            "family_source": "plugin",
            "project_adoption": "plugin",
            "release_artifact": "release",
        }[args.target_type],
    }
    _validate_method_parameters(parameters)
    semantic_target_digest = (
        foundation_project_adoption_task_digest(target)
        if args.target_type == "project_adoption"
        else foundation_target_content_digest(target, args.target_type)
    )
    semantic_request_digest = foundation_document_digest({
        "target_digest": semantic_target_digest,
        "target_type": args.target_type,
        "rule_set_digest": rule_set_digest,
    })
    reviews = semantic_reviews(
        Path(args.semantic_result) if args.semantic_result else None,
        rules,
        semantic_request_digest,
        target,
        args.target_type,
        output_dir,
    )
    scan = checker._scan(target if target.is_dir() else target.parent)
    results = []
    for rule in rules:
        if (
            scope.get("logical_skill_count") == 1
            and rule.get("ruleId", "").startswith(CROSS_SKILL_RULE_PREFIX)
        ):
            outcome = {
                "status": "NOT_APPLICABLE",
                "evidence": {
                    "reason_code": "SINGLE_LOGICAL_SKILL",
                    "logical_skill_count": 1,
                    "scope": scope["plugin_project"]["scope"],
                },
                "worker": "deterministic-applicability",
            }
        elif rule.get("checkType") == "semantic":
            review = reviews[rule["ruleId"]]
            outcome = {
                "status": review["status"],
                "evidence": review["evidence"],
                "worker": "isolated-semantic-review",
            }
        elif rule.get("checkType") == "static":
            if rule["ruleId"].startswith("gmin:"):
                outcome = _gmin_static_outcome(rule["ruleId"], scope)
                outcome["worker"] = "deterministic-terminal-governance"
                result = {
                    "rule_id": rule["ruleId"],
                    "rule_revision_digest": rule["revisionDigest"],
                    **outcome,
                }
                lineage = canonical_lineage.get(rule["ruleId"])
                if lineage is not None:
                    result["canonical_lineage"] = {
                        "canonical_id": lineage["canonical_id"],
                        "revision_digest": lineage["canonical_revision_digest"],
                    }
                results.append(result)
                continue
            if executors.supports(rule["ruleId"]):
                outcome = _w2b1_executor_outcome(
                    rule["ruleId"],
                    scope,
                    target,
                    output_dir,
                    args,
                    index,
                    manifest,
                )
                outcome["worker"] = "deterministic-first-tier-executor"
                result = {
                    "rule_id": rule["ruleId"],
                    "rule_revision_digest": rule["revisionDigest"],
                    **outcome,
                }
                lineage = canonical_lineage.get(rule["ruleId"])
                if lineage is not None:
                    result["canonical_lineage"] = {
                        "canonical_id": lineage["canonical_id"],
                        "revision_digest": lineage["canonical_revision_digest"],
                    }
                results.append(result)
                continue
            scope_rule = {
                "scope:single-skill-complete": ("skill_files",),
                "scope:family-source-complete": ("skill_files", "source_files"),
                "scope:release-artifact-complete": ("release_files",),
                "scope:project-adoption-present": ("project_profile",),
            }.get(rule["ruleId"])
            if scope_rule:
                all_present = all(scope.get(key) for key in scope_rule)
                evidence = {key: scope.get(key, []) for key in scope_rule}
                # project_adoption 规则还要求项目 Profile 已通过 Foundation
                # Profile SPI v3（D3：采用证明 = 项目根 profile.json）
                if rule["ruleId"] == "scope:project-adoption-present":
                    foundation_profile = scope.get("foundation_profile", {})
                    foundation_complete = (
                        foundation_profile.get("foundation_profile_complete") is True
                    )
                    all_present = all_present and foundation_complete
                    evidence["foundation_profile"] = {
                        "foundation_profile_complete": foundation_complete,
                        "code": foundation_profile.get("code"),
                        "projectId": foundation_profile.get("projectId"),
                        "steps": foundation_profile.get("steps", []),
                    }
                outcome = {
                    "status": "PASS" if all_present else "FAIL",
                    "evidence": evidence,
                }
            else:
                outcome = checker._check(rule["ruleId"], scan, target if target.is_dir() else target.parent)
            outcome["worker"] = "deterministic-checker"
        else:
            outcome = {"status": "NOT_RUN", "evidence": {"reason": "unsupported_check_type"}}
        result = {
            "rule_id": rule["ruleId"],
            "rule_revision_digest": rule["revisionDigest"],
            **outcome,
        }
        lineage = canonical_lineage.get(rule["ruleId"])
        if lineage is not None:
            result["canonical_lineage"] = {
                "canonical_id": lineage["canonical_id"],
                "revision_digest": lineage["canonical_revision_digest"],
            }
        results.append(result)
    failed = [
        item
        for item in results
        if item["status"] not in {"PASS", "NOT_APPLICABLE"}
    ]
    findings = [
        {
            "finding_id": f"finding-{index + 1}",
            "rule_id": item["rule_id"],
            "rule_revision_digest": item["rule_revision_digest"],
            "status": item["status"],
        }
        for index, item in enumerate(failed)
    ]
    remediation = {
        "schema_version": "1.0.0",
        "status": "unapplied",
        "target_digest": foundation_tree_digest(target if target.is_dir() else target.parent),
        "target_type": args.target_type,
        "items": [
            {
                **finding,
                "applicability_scope": args.target_type,
                "suggested_action": "按规则整改后重新运行；本制品不修改目标",
                "patch_status": "unapplied",
            }
            for finding in findings
        ],
    }
    canonical_coverage = _canonical_coverage_from_results(
        canonical_applicability, canonical_lineage, results
    )
    canonical_guidance = (
        _canonical_guidance_from_results(
            manifest,
            results,
            scope,
            remediation["items"],
        )
        if args.target_type == "project_adoption"
        and manifest.get("canonicalGuidance") is not None
        else {}
    )
    canonical_coverage_complete = canonical_coverage["complete"]
    adoption_completion_blocked = (
        args.target_type == "project_adoption"
        and not canonical_coverage_complete
    )
    status = (
        "SUCCEEDED"
        if rules and not failed and not adoption_completion_blocked
        else "FAILED"
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    plugin_project_path = output_dir / "plugin-project-observation.json"
    plugin_project_path.write_bytes(foundation_canonical_bytes(scope["plugin_project"]) + b"\n")
    applicability_path = output_dir / "canonical-rule-applicability.json"
    applicability_path.write_bytes(foundation_canonical_bytes(canonical_applicability) + b"\n")
    findings_path = output_dir / "rule-findings.json"
    findings_path.write_bytes(foundation_canonical_bytes(results) + b"\n")
    (output_dir / "remediation-plan.json").write_bytes(
        foundation_canonical_bytes(remediation) + b"\n"
    )
    domain = {
        "schema_version": "1.0.0",
        "target_type": args.target_type,
        "target_digest": foundation_target_content_digest(target, args.target_type),
        "status": status,
        "rule_results": results,
        "canonical_rule_summary": canonical_summary,
        "canonical_rule_applicability": {
            "path": str(applicability_path),
            "content_digest": foundation_file_digest(applicability_path),
            "applicability_digest": canonical_applicability[
                "applicability_digest"
            ],
            "counts": canonical_applicability["counts"],
        },
        "baseline_rule_set": {
            "kind": "implementation-baseline",
            "canonical_rule_ids": sorted(manifest.get("canonicalRuleIds", [])),
            "executed_rule_count": len(rules),
            "status": (
                "NON_PASSING"
                if adoption_completion_blocked
                else "OBSERVED"
            ),
        },
        "canonical_executable_coverage": canonical_coverage,
        "canonical_guidance": canonical_guidance,
    }
    domain_path = output_dir / "conformance-result.json"
    domain_path.write_bytes(foundation_canonical_bytes(domain) + b"\n")
    evidence = [{
        "kind": "target-observation",
        "path": str(target),
        "source": "conformance-workflow",
        "target_digest": foundation_target_content_digest(target, args.target_type),
        "credibility": (
            "self_reported" if is_fixture or index.get("selfAudit") is True else "verified"
        ),
    }]
    result = {
        "conformance_result": domain,
        "rule_findings": results,
        "evidence_list": evidence,
        "remediation_plan": remediation["items"],
    }
    (output_dir / "evidence-list.json").write_bytes(foundation_canonical_bytes(evidence) + b"\n")
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--target", required=True)
    value.add_argument("--target-type", required=True, choices=sorted(TARGET_TYPES))
    value.add_argument(
        "--spec-package",
        help=(
            "显式规范包目录；省略时默认使用仓内自审规范包 spec/self-audit/"
            "（selfAudit: true，仅用于自审，永不具备发布资格）"
        ),
    )
    value.add_argument("--output-dir")
    value.add_argument("--run-id")
    value.add_argument("--semantic-result")
    value.add_argument(
        "--platform",
        default="all",
        choices=["all", "claude-code", "codex", "kimi-code", "workbuddy"],
    )
    value.add_argument("--allow-test-fixture", action="store_true")
    value.add_argument(
        "--observe-only",
        action="store_true",
        help="只输出受检目标的权威 PluginProject 观察投影，不执行规则",
    )
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.observe_only:
            target = Path(args.target).resolve(strict=True)
            scope = target_scope(target, args.target_type)
            print(
                foundation_canonical_bytes(scope["plugin_project"]).decode("utf-8")
            )
            return 0
        result = run_workflow(args)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["conformance_result"]["status"] == "SUCCEEDED" else 1
    except (WorkflowError, OSError, ValueError) as exc:
        result = {
            "conformance_result": {
                "status": "BLOCKED",
                "reason_code": getattr(exc, "code", type(exc).__name__),
                "summary": str(exc),
            },
            "rule_findings": [],
            "evidence_list": [],
            "remediation_plan": [],
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
