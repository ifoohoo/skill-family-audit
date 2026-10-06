#!/usr/bin/env python3
"""四类受检对象的生产 Conformance 工作流。

只读消费调用方提供的证据集合（源码树、源码文件、JSONL 对话、日志、manifest、
receipt、policy、exception、platform support）；不执行受检目标。确定性规则先
执行；语义规则由确定性 CLI 保持 REVIEW_REQUIRED，外部语义审阅结果只作为
待审证据。只有非源码证据时审阅仍然完成，未获证规则保持 EVIDENCE_MISSING/
REVIEW_REQUIRED。目标与证据始终只读，结果只作为内存对象返回并由 CLI 输出 JSON。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import conformance_check as checker
import resolve_spec_release as spec_release_resolver
import conformance_human_route
import conformance_profiles
import executors
import foundation_adoption_verifier as adoption_verifier
import rule_method_assurance
import semantic_context_plan
import semantic_review
from executors.contracts import ExecutorEvidenceError


TARGET_TYPES = {
    "single_skill",
    "family_source",
    "release_artifact",
    "project_adoption",
}
SEMANTIC_SCHEMA_ID = "skill-family-audit:semantic-review-result"
SEMANTIC_INPUT_BUDGET = 16_000
REFS = Path(__file__).resolve().parent.parent / "refs"
TRUST_POLICY = REFS / "conformance-trust-policy.json"
CANONICAL_PROJECTION = REFS / "canonical-rule-projection.json"
SEMANTIC_GROUP_REGISTRY = REFS / "semantic-rule-groups.json"
METHOD_ASSURANCE_TRUST_PROJECTION = (
    REFS / "method-assurance-trust-projection.json"
)
def _method_assurance_layout() -> tuple[Path, str, str, str]:
    """Derive the method assurance root and authority paths from the runtime layout.

    仓库布局：脚本位于 ``plugin-src/skills/<name>/scripts/``，包根在 parents[4]；
    安装 bundle 布局：脚本位于 ``<platform>/skills/<name>/scripts/``，
    平台根在 parents[3] 且带有 ``foundation/`` 目录。bundle 的 authority 资源、
    routing 真源与规范投影都由构建器按 bundle 相对路径生成，运行时按布局选取。
    """
    script_parent = Path(__file__).resolve().parent
    bundle_root = script_parent.parents[2]
    if (bundle_root / "foundation").is_dir():
        skill_rel = script_parent.parents[0].relative_to(bundle_root).as_posix()
        return (
            bundle_root,
            f"{skill_rel}/refs/method-assurance-authority-resources.json",
            f"{skill_rel}/refs/first-tier-execution-routing.json",
            f"{skill_rel}/refs/canonical-rule-projection.json",
        )
    repo_root = script_parent.parents[3]
    return (
        repo_root,
        "plugin-src/skills/skill-family-audit-conformance/refs/"
        "method-assurance-authority-resources.json",
        "governance/rules/first-tier-execution-routing.json",
        "plugin-src/skills/skill-family-audit-conformance/refs/"
        "canonical-rule-projection.json",
    )


(
    AUDIT_PACKAGE_ROOT,
    METHOD_ASSURANCE_AUTHORITY_RESOURCES_RELATIVE,
    METHOD_ASSURANCE_ROUTING_SOURCE_RELATIVE,
    CANONICAL_PROJECTION_RELATIVE,
) = _method_assurance_layout()
CROSS_SKILL_RULE_PREFIX = "cross-skill:"
SHARED_SKILL_NAME_TEMPLATE = "{{SHARED_SKILL_NAME}}"
TEMPLATE_TOKEN_RE = re.compile(r"\{\{[^{}]+\}\}")
MANAGED_PLATFORM_TEMPLATE_IDS = {
    "claude-code",
    "codex",
    "kimi-code",
    "workbuddy",
}

# Audit 的领域职责边界。D3 起采用锁废弃，指导视图直接绑定这些与审计有关的
# owner，不再经由项目 Profile 文档转手；外部执行器不属于 Audit 运行时边界。
OWNER_BOUNDARY = {
    "audit": "skill-family-audit",
    "domain_semantics": "skill-family-audit",
    "foundation_harness": "skill-family-foundation",
    "release": "release-skill",
}

_RUN_TREE_DIGEST_CACHE: dict[Path, str] = {}
_GOVERNED_ROUTE_CACHE: dict[str, dict[str, Any]] = {}


def _reset_run_fact_cache() -> None:
    """Start one workflow-call frozen-fact scope without persistent state."""
    _RUN_TREE_DIGEST_CACHE.clear()
    _GOVERNED_ROUTE_CACHE.clear()

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


def _governed_route_rows() -> dict[str, dict[str, Any]]:
    """只读消费第一档执行路由权威，返回 canonical_id 索引的路线真源。

    路线口径（含 ACTIVE_MECHANICAL 中语义义务是唯一义务的 54 条承接规则）
    已由 ``governance/rules/first-tier-execution-routing.json`` 逐条冻结，
    本模块不再按生命周期自行二次判定：路线必须与治理路由表逐条一致
    （见 tests/spec/test_first_tier_execution_routing.py）。承载者身份只从
    该权威读取，不在代码中复制映射或计数。
    """
    if _GOVERNED_ROUTE_CACHE:
        return _GOVERNED_ROUTE_CACHE
    root, _authority, routing_relative, _projection = _method_assurance_layout()
    path = root / routing_relative
    try:
        routing_authority = load_json(path)
    except (OSError, WorkflowError) as exc:
        raise WorkflowError(
            "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
            "第一档执行路由权威不可读取: {path}: {exc}".format(
                path=routing_relative, exc=exc
            ),
        ) from exc
    if (
        routing_authority.get("kind")
        != "skill-family-audit.first-tier-execution-routing"
        or not isinstance(routing_authority.get("counts"), dict)
    ):
        raise WorkflowError(
            "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
            "第一档执行路由权威的 kind 或结构非法",
        )
    total_rules = routing_authority["counts"].get("total_rules")
    governed: dict[str, dict[str, Any]] = {}
    for key in ("first_tier", "executor_gap_list", "semantic_review_routes"):
        rows = routing_authority.get(key)
        if not isinstance(rows, list):
            raise WorkflowError(
                "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
                "第一档执行路由权威缺少 {key} 数组".format(key=key),
            )
        for row in rows:
            canonical_id = row.get("canonical_id") if isinstance(row, dict) else None
            revision_digest = (
                row.get("revision_digest") if isinstance(row, dict) else None
            )
            execution_route = (
                row.get("execution_route") if isinstance(row, dict) else None
            )
            methods = row.get("check_methods") if isinstance(row, dict) else None
            if (
                not isinstance(canonical_id, str)
                or not canonical_id
                or canonical_id in governed
                or not isinstance(revision_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", revision_digest)
                or execution_route not in EXECUTION_ROUTE_VOCABULARY
                or not isinstance(methods, list)
                or not all(isinstance(method, str) for method in methods)
            ):
                raise WorkflowError(
                    "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
                    "第一档执行路由权威行非法或身份重复: {id}".format(
                        id=canonical_id
                    ),
                )
            governed[canonical_id] = {
                "revision_digest": revision_digest,
                "execution_route": execution_route,
                "check_methods": methods,
            }
    if isinstance(total_rules, int) and len(governed) != total_rules:
        raise WorkflowError(
            "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
            "第一档执行路由权威没有逐条覆盖冻结信任策略钉扎的全量规则",
        )
    _GOVERNED_ROUTE_CACHE.update(governed)
    return _GOVERNED_ROUTE_CACHE


def _governed_route_detail(entry: dict[str, Any]) -> str:
    """路由明细只描述已冻结的路线口径，不新增语义。"""
    methods = entry["check_methods"]
    if entry["execution_route"] == ROUTE_FIRST_TIER_STATIC:
        if "semantic_review" in methods:
            return "terminal_governance_baseline_static_semantic_half_pending"
        return "terminal_governance_baseline_static"
    if "semantic_review" in methods:
        return "isolated_semantic_review"
    return "governance_routing_authority"


def canonical_rule_execution_route(
    rule: dict[str, Any]
) -> tuple[str, str]:
    """返回 (execution_route, execution_route_detail)；逐条显式，不静默跳过。

    - ACTIVE_MECHANICAL / ACTIVE_SEMANTIC：路线只从第一档执行路由权威读取。
      该权威已按当前终态 lifecycle + check_methods + 语义证据角色绑定逐条
      冻结，包含 ACTIVE_MECHANICAL 中「语义义务是唯一义务」的承接规则；
      本函数不得再按生命周期单独判定，绑定校验由 _validated_baseline_lineage
      失败关闭承担；
    - RETAINED_UNIMPLEMENTED 且含机械方法：机械候选档，执行器缺口明示；
    - 其余 RETAINED：语义审阅路由；
    - 生命周期未冻结：失败关闭，不得路由（候选品质标签本身不改变路由）。
    """
    lifecycle = rule.get("lifecycle_status")
    methods = sorted(set(rule.get("check_methods") or []))
    if lifecycle in {"ACTIVE_MECHANICAL", "ACTIVE_SEMANTIC"}:
        canonical_id = rule.get("canonical_id")
        governed = _governed_route_rows().get(canonical_id)
        if governed is None:
            raise WorkflowError(
                "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
                "激活规则缺少第一档执行路由: {id}".format(id=canonical_id),
            )
        if governed["revision_digest"] != rule.get("revision_digest"):
            raise WorkflowError(
                "FIRST_TIER_ROUTING_AUTHORITY_INVALID",
                "激活规则的修订摘要与第一档执行路由不一致: {id}".format(
                    id=canonical_id
                ),
            )
        return governed["execution_route"], _governed_route_detail(governed)
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
    def __init__(
        self,
        code: str,
        detail: str,
        *,
        failure_stage: str | None = None,
    ):
        super().__init__(detail)
        self.code = code
        self.failure_stage = failure_stage
        self.evidence_set: list[dict[str, Any]] | None = None
        self.result: dict[str, Any] | None = None


def _foundation(request: dict[str, Any]) -> dict[str, Any]:
    try:
        return checker._foundation(request)
    except RuntimeError as exc:
        raise WorkflowError("FOUNDATION_MECHANISM_FAILED", str(exc)) from exc


def foundation_canonical_bytes(value: Any) -> bytes:
    return str(_foundation({"operation": "canonical-json", "document": value})["text"]).encode("utf-8")


def foundation_document_digest(value: Any) -> str:
    return str(_foundation({"operation": "digest-document", "document": value})["digest"])


def foundation_document_digests(values: list[Any]) -> list[str]:
    """Digest independent result facts through Foundation with bounded parallelism."""
    if len(values) < 2:
        return [foundation_document_digest(value) for value in values]
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, len(values))
    ) as executor:
        return list(executor.map(foundation_document_digest, values))


def foundation_resource_closure(root: Path, relative_paths: list[str]) -> dict[str, Any]:
    return _foundation({
        "operation": "resource-closure",
        "root": str(root),
        "resources": [
            {"path": relative, "role": "input"}
            for relative in sorted(relative_paths)
        ],
    })


def foundation_estimate_tokens(
    text: str,
    *,
    profile_spi_root: Path | None = None,
) -> dict[str, Any]:
    """Estimate one frozen context through Foundation 0.14's public API.

    The normal production root is derived from the already verified managed
    Bundle.  Tests may inject a complete ``foundation/profile-spi`` closure;
    neither path permits an arbitrary module or estimator implementation.
    """
    if not isinstance(text, str):
        raise WorkflowError(
            "SEMANTIC_CONTEXT_INVALID", "待估算语义上下文必须是字符串"
        )
    if profile_spi_root is None:
        runner = checker.foundation_runner()
        profile_spi_root = runner.parent.parent / "profile-spi"
    result = adoption_verifier.estimate_tokens(
        text,
        profile_spi_root=profile_spi_root,
    )
    if (
        result.get("authority_ok") is not True
        or result.get("kind") != "skill-family.token-estimate-record"
        or result.get("schemaVersion") != 1
        or result.get("unit") != "tokens"
        or not isinstance(result.get("tokens"), int)
        or result["tokens"] < 0
        or not isinstance(result.get("estimator"), dict)
        or not isinstance(result["estimator"].get("id"), str)
        or not isinstance(result["estimator"].get("version"), str)
    ):
        raise WorkflowError(
            "FOUNDATION_TOKEN_ESTIMATION_FAILED",
            "; ".join(str(item) for item in result.get("blockers", []))
            or "Foundation estimateTokens 返回无效或未获权威确认的记录",
        )
    return {
        key: value
        for key, value in result.items()
        if key not in {"authority_ok", "closure_root", "node_version"}
    }


def foundation_read_file_strict(
    root: Path,
    relative: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "operation": "read-file-strict",
        "root": str(root),
        "path": relative,
        "encoding": "utf8",
    }
    if expected_sha256 is not None:
        request["expectedSha256"] = expected_sha256
    result = _foundation(request)
    if (
        not isinstance(result.get("content"), str)
        or not isinstance(result.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", result["sha256"])
    ):
        raise WorkflowError(
            "FOUNDATION_MECHANISM_FAILED",
            "Foundation read-file-strict returned invalid response",
        )
    if expected_sha256 is not None and result["sha256"] != expected_sha256:
        raise WorkflowError(
            "FOUNDATION_MECHANISM_FAILED",
            "Foundation read-file-strict returned an unexpected digest",
        )
    return {
        "content": result["content"],
        "sha256": result["sha256"],
    }


def strict_read_json(
    receipt: dict[str, Any],
    code: str,
    label: str,
) -> dict[str, Any]:
    try:
        value = json.loads(receipt["content"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise WorkflowError(code, f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise WorkflowError(code, f"{label} must be a JSON object")
    return value


def foundation_file_digest(path: Path) -> str:
    closure = foundation_resource_closure(path.parent, [path.name])
    return str(closure["resources"][0]["sha256"])


def method_assurance_routes() -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    str,
    dict[str, Any],
    str,
]:
    """Load and verify the Foundation-digested managed trust projection."""
    projection = load_json(METHOD_ASSURANCE_TRUST_PROJECTION)
    if (
        set(projection) != {
            "kind", "schema_version", "routing", "source_closure",
            "projection_digest",
        }
        or
        projection.get("kind")
        != "skill-family-audit.method-assurance-trust-projection"
        or projection.get("schema_version") != "1.0.0"
    ):
        raise WorkflowError(
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "method assurance trust projection kind/schema invalid",
        )
    digest = projection.get("projection_digest")
    routing = projection.get("routing")
    rows = routing.get("first_tier_static") if isinstance(routing, dict) else None
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(rows, list)
    ):
        raise WorkflowError(
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "method assurance trust projection shape invalid",
        )
    body = {
        key: value for key, value in projection.items()
        if key != "projection_digest"
    }
    if foundation_document_digest(body) != digest:
        raise WorkflowError(
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "method assurance trust projection digest is stale",
        )
    source_closure = projection.get("source_closure")
    try:
        authority_receipt = foundation_read_file_strict(
            AUDIT_PACKAGE_ROOT,
            METHOD_ASSURANCE_AUTHORITY_RESOURCES_RELATIVE,
        )
        authority = strict_read_json(
            authority_receipt,
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "method assurance authority resources",
        )
        authority_paths = authority.get("resources") if isinstance(authority, dict) else None
        closed_roots = authority.get("closed_roots") if isinstance(authority, dict) else None
        if (
            not isinstance(authority, dict)
            or set(authority)
            != {"closed_roots", "kind", "resources", "schema_version"}
            or authority.get("kind")
            != "skill-family-audit.method-assurance-authority-resources"
            or authority.get("schema_version") != "1.0.0"
            or not isinstance(authority_paths, list)
            or not authority_paths
            or authority_paths != sorted(set(authority_paths))
            or not all(isinstance(path, str) and path for path in authority_paths)
            or not isinstance(closed_roots, list)
            or not closed_roots
            or closed_roots != sorted(set(closed_roots))
            or not all(isinstance(path, str) and path for path in closed_roots)
            or METHOD_ASSURANCE_AUTHORITY_RESOURCES_RELATIVE not in authority_paths
            or METHOD_ASSURANCE_ROUTING_SOURCE_RELATIVE not in authority_paths
            or CANONICAL_PROJECTION_RELATIVE not in authority_paths
        ):
            raise ValueError("authority resource set is invalid")
        if (
            not isinstance(source_closure, dict)
            or set(source_closure) != {
                "kind", "schemaVersion", "digestAlgorithm", "resources",
                "digest",
            }
            or source_closure.get("kind") != "skill-family.resource-closure"
            or source_closure.get("schemaVersion") != 1
            or source_closure.get("digestAlgorithm") != "sha256"
            or not isinstance(source_closure.get("digest"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", source_closure["digest"])
            or not isinstance(source_closure.get("resources"), list)
            or not source_closure["resources"]
        ):
            raise ValueError("source closure shape is invalid")
        resource_paths = []
        for resource in source_closure["resources"]:
            if (
                not isinstance(resource, dict)
                or set(resource) != {"path", "role", "exists", "sha256"}
                or not isinstance(resource.get("path"), str)
                or not resource["path"]
                or resource.get("role") != "input"
                or resource.get("exists") is not True
                or not isinstance(resource.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", resource["sha256"])
                or resource["path"] in resource_paths
            ):
                raise ValueError("source closure resource is invalid")
            resource_paths.append(resource["path"])
        if resource_paths != authority_paths:
            raise ValueError("source closure resource set is not authoritative")
        for relative_root in closed_roots:
            root = AUDIT_PACKAGE_ROOT / relative_root
            if not root.is_dir():
                raise ValueError("authority closed root is invalid")
            observed_paths = sorted(
                path.relative_to(AUDIT_PACKAGE_ROOT).as_posix()
                for path in root.glob("*.py")
            )
            expected_paths = sorted(
                path for path in authority_paths
                if Path(path).parent.as_posix() == relative_root
            )
            if observed_paths != expected_paths:
                raise ValueError("authority closed resource set drifted")
        expected_digests = {
            resource["path"]: resource["sha256"]
            for resource in source_closure["resources"]
        }
        if (
            authority_receipt["sha256"]
            != expected_digests[METHOD_ASSURANCE_AUTHORITY_RESOURCES_RELATIVE]
        ):
            raise ValueError("authority bootstrap digest does not match its closure")
        strict_cache = {
            METHOD_ASSURANCE_AUTHORITY_RESOURCES_RELATIVE: authority_receipt,
        }
        for relative in resource_paths:
            if relative in strict_cache:
                continue
            strict_cache[relative] = foundation_read_file_strict(
                AUDIT_PACKAGE_ROOT,
                relative,
                expected_digests[relative],
            )
        routing_authority = strict_read_json(
            strict_cache[METHOD_ASSURANCE_ROUTING_SOURCE_RELATIVE],
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "first-tier execution routing",
        )
        rebuilt_rows = []
        carried_rows = []
        seen_routing_identities: set[tuple[str, str]] = set()
        for raw in routing_authority.get("first_tier", []):
            if not isinstance(raw, dict):
                raise ValueError("routing authority row is invalid")
            execution_route = raw.get("execution_route")
            if execution_route not in {
                ROUTE_FIRST_TIER_STATIC, ROUTE_FIRST_TIER_SEMANTIC,
            }:
                continue
            if (
                execution_route == ROUTE_FIRST_TIER_SEMANTIC
                and raw.get("lifecycle_status") != "ACTIVE_MECHANICAL"
            ):
                # 语义路线上的非激活机械义务不持有方法路线身份。
                continue
            canonical_id = raw.get("canonical_id")
            revision_digest = raw.get("revision_digest")
            methods = raw.get("check_methods")
            baseline_rule_id = raw.get("executor_baseline_rule_id")
            route_identity = (canonical_id, revision_digest)
            if (
                not isinstance(canonical_id, str)
                or not canonical_id
                or not isinstance(revision_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", revision_digest)
                or route_identity in seen_routing_identities
                or not isinstance(methods, list)
                or not methods
                or not all(isinstance(method, str) for method in methods)
                or len(methods) != len(set(methods))
                or not isinstance(baseline_rule_id, str)
                or not baseline_rule_id
            ):
                raise ValueError("routing authority method row is invalid")
            seen_routing_identities.add(route_identity)
            method_row = {
                "canonical_id": canonical_id,
                "revision_digest": revision_digest,
                "baseline_rule_id": baseline_rule_id,
                "check_methods": sorted(methods),
                "required_mechanical_methods": sorted(
                    set(methods) & MECHANICAL_CHECK_METHODS
                ),
            }
            if execution_route == ROUTE_FIRST_TIER_SEMANTIC:
                # 已批准承接：改由第一档语义审阅路线覆盖的激活机械义务仍持有
                # 执行器绑定行——静态执行器按该行绑定执行，其终态由语义审阅
                # 通道合并。该行身份与内容只从第一档执行路由权威读取，不在此
                # 另立口径，也不免除任何激活义务的路线覆盖。
                carried_rows.append(method_row)
            else:
                rebuilt_rows.append(method_row)
        rebuilt_rows.sort(key=lambda row: row["canonical_id"])
        carried_rows.sort(key=lambda row: row["canonical_id"])
        routing_rows = rebuilt_rows + carried_rows
        if (
            not rebuilt_rows
            or routing != {
                "source": METHOD_ASSURANCE_ROUTING_SOURCE_RELATIVE,
                "first_tier_static": rebuilt_rows,
            }
        ):
            raise ValueError(
                "trust projection routing differs from strict routing authority"
            )
        canonical_projection = strict_read_json(
            strict_cache[CANONICAL_PROJECTION_RELATIVE],
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "canonical rule projection",
        )
    except (KeyError, OSError, TypeError, ValueError, WorkflowError) as exc:
        raise WorkflowError(
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            f"method assurance source closure is invalid: {exc}",
        ) from exc
    canonical_rules = canonical_projection.get("rules")
    if not isinstance(canonical_rules, list):
        raise WorkflowError(
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "canonical rule projection has no rule array",
        )
    canonical_methods: dict[tuple[str, str], list[str]] = {}
    for rule in canonical_rules:
        if (
            not isinstance(rule, dict)
            or rule.get("lifecycle_status") != "ACTIVE_MECHANICAL"
        ):
            continue
        key = (rule.get("canonical_id"), rule.get("revision_digest"))
        methods = rule.get("check_methods")
        if (
            not all(isinstance(value, str) and value for value in key)
            or key in canonical_methods
            or not isinstance(methods, list)
            or not methods
            or len(methods) != len(set(methods))
            or any(
                method not in rule_method_assurance.CANONICAL_CHECK_METHODS
                for method in methods
            )
        ):
            raise WorkflowError(
                "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
                "canonical active method obligation is invalid or duplicate",
            )
        canonical_methods[key] = sorted(methods)
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in routing_rows:
        if not isinstance(row, dict) or set(row) != {
            "canonical_id", "revision_digest", "baseline_rule_id",
            "check_methods", "required_mechanical_methods",
        }:
            raise WorkflowError(
                "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
                "method assurance routing row must be an object",
            )
        key = (row.get("canonical_id"), row.get("revision_digest"))
        if (
            not all(isinstance(value, str) and value for value in key)
            or key in index
            or not isinstance(row.get("baseline_rule_id"), str)
            or not row["baseline_rule_id"]
            or not isinstance(row.get("check_methods"), list)
            or not isinstance(row.get("required_mechanical_methods"), list)
            or len(row["check_methods"]) != len(set(row["check_methods"]))
            or len(row["required_mechanical_methods"])
            != len(set(row["required_mechanical_methods"]))
            or row["check_methods"] != canonical_methods.get(key)
            or sorted(
                set(row["check_methods"]) & MECHANICAL_CHECK_METHODS
            ) != sorted(row["required_mechanical_methods"])
        ):
            raise WorkflowError(
                "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
                "method assurance routing identity is missing or duplicate",
            )
        index[key] = row
    if set(index) != set(canonical_methods):
        raise WorkflowError(
            "METHOD_ASSURANCE_TRUST_PROJECTION_INVALID",
            "method assurance routes do not cover canonical active obligations",
        )
    return (
        index,
        digest,
        canonical_projection,
        strict_cache[CANONICAL_PROJECTION_RELATIVE]["sha256"],
    )


def foundation_tree_digest(root: Path) -> str:
    cached = _RUN_TREE_DIGEST_CACHE.get(root)
    if cached is not None:
        return cached
    paths = [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    digest = str(foundation_resource_closure(root, paths)["digest"])
    _RUN_TREE_DIGEST_CACHE[root] = digest
    return digest


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


def load_semantic_group_registry() -> tuple[dict[str, Any], str]:
    """Strictly load the generated runtime grouping projection and its byte digest."""
    receipt = foundation_read_file_strict(
        REFS,
        SEMANTIC_GROUP_REGISTRY.name,
    )
    registry = strict_read_json(
        receipt,
        "SEMANTIC_GROUP_REGISTRY_INVALID",
        "semantic rule group registry",
    )
    if (
        registry.get("kind") != "skill-family-audit.semantic-rule-groups"
        or registry.get("status") != "implementation-design-authority-for-sfa-814-goal"
        or not isinstance(registry.get("groups"), list)
        or not isinstance(registry.get("review_families"), list)
    ):
        raise WorkflowError(
            "SEMANTIC_GROUP_REGISTRY_INVALID",
            "语义组运行时投影的身份、状态或顶层结构非法",
        )
    return registry, receipt["sha256"]


def _semantic_group_members(
    registry: dict[str, Any],
) -> dict[str, list[str]]:
    """Validate the thin registry identity surface and return group membership."""
    members: dict[str, list[str]] = {}
    seen_rules: set[str] = set()
    for group in registry.get("groups", []):
        if not isinstance(group, dict):
            raise WorkflowError(
                "SEMANTIC_GROUP_REGISTRY_INVALID",
                "语义组行必须是对象",
            )
        group_id = group.get("group_id")
        name = group.get("name")
        review_family = group.get("review_family")
        rules = group.get("rules")
        if (
            not isinstance(group_id, str)
            or not group_id
            or group_id in members
            or not isinstance(name, str)
            or not name
            or not isinstance(review_family, str)
            or not review_family
            or not isinstance(rules, list)
            or not rules
        ):
            raise WorkflowError(
                "SEMANTIC_GROUP_REGISTRY_INVALID",
                f"语义组身份或成员结构非法: {group_id}",
            )
        rule_ids: list[str] = []
        for rule in rules:
            canonical_id = rule.get("canonical_id") if isinstance(rule, dict) else None
            if (
                not isinstance(canonical_id, str)
                or not canonical_id
                or canonical_id in seen_rules
            ):
                raise WorkflowError(
                    "SEMANTIC_GROUP_REGISTRY_INVALID",
                    f"语义组规则身份非法或重复: {canonical_id}",
                )
            seen_rules.add(canonical_id)
            rule_ids.append(canonical_id)
        members[group_id] = sorted(rule_ids)
    return members


def _profile_execution_plan(
    args: argparse.Namespace,
    rules: list[dict[str, Any]],
    canonical_lineage: dict[str, dict[str, str]],
    canonical_applicability: dict[str, Any],
    registry: dict[str, Any],
    registry_digest: str,
) -> dict[str, Any]:
    """Derive one deterministic profile selection from current runtime authorities."""
    rule_by_canonical: dict[str, dict[str, Any]] = {}
    auxiliary_rule_ids: list[str] = []
    for rule in rules:
        lineage = canonical_lineage.get(rule.get("ruleId"))
        canonical_id = lineage.get("canonical_id") if isinstance(lineage, dict) else None
        if not isinstance(canonical_id, str) or not canonical_id:
            auxiliary_rule_ids.append(rule["ruleId"])
            continue
        if canonical_id in rule_by_canonical:
            raise WorkflowError(
                "CONFORMANCE_PROFILE_SCOPE_INVALID",
                f"in-scope baseline 不能唯一映射 canonical rule: {canonical_id}",
            )
        rule_by_canonical[canonical_id] = rule

    group_members = _semantic_group_members(registry)
    registered_group_ids = sorted(group_members)
    try:
        inventory_rule_ids = sorted({
            row.get("canonical_id")
            for row in canonical_applicability.get("rules", [])
            if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
        })
        profile, requested_group_ids, requested_rule_ids = (
            conformance_profiles.normalize_targeted_selection(
            getattr(args, "execution_profile", None),
            getattr(args, "semantic_group_ids", None),
            getattr(args, "canonical_rule_ids", None),
            registered_group_ids,
            inventory_rule_ids,
            sorted(rule_by_canonical),
        ))
    except ValueError as exc:
        raise WorkflowError("CONFORMANCE_PROFILE_INVALID", str(exc)) from exc

    applicability_by_id = {
        row.get("canonical_id"): row
        for row in canonical_applicability.get("rules", [])
        if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
    }
    baseline_in_scope_rule_ids = sorted(rule_by_canonical)
    # ``full`` is the one canonical-complete profile.  Its result identity is
    # the complete authority inventory, not only the implementation-baseline
    # carriers currently available to this target.  Other profiles retain the
    # established baseline-derived scope.
    in_scope_rule_ids = (
        inventory_rule_ids
        if profile == "full"
        else baseline_in_scope_rule_ids
    )
    deterministic_rule_ids = sorted(
        canonical_id
        for canonical_id in in_scope_rule_ids
        if applicability_by_id.get(canonical_id, {}).get("execution_route")
        == ROUTE_FIRST_TIER_STATIC
    )
    first_tier_semantic_rule_ids = sorted(
        canonical_id
        for canonical_id in in_scope_rule_ids
        if applicability_by_id.get(canonical_id, {}).get("execution_route")
        == ROUTE_FIRST_TIER_SEMANTIC
    )
    try:
        selected_rule_ids = conformance_profiles.select_rule_ids(
            profile,
            in_scope_rule_ids,
            deterministic_rule_ids,
            first_tier_semantic_rule_ids,
            group_members,
            requested_group_ids,
            requested_rule_ids,
        )
    except ValueError as exc:
        raise WorkflowError("CONFORMANCE_PROFILE_INVALID", str(exc)) from exc

    selected_set = set(selected_rule_ids)
    if profile == "targeted":
        selected_group_ids = sorted(
            group_id
            for group_id in requested_group_ids
            if selected_set.intersection(group_members[group_id])
        )
    elif profile == "full":
        selected_group_ids = sorted(
            group_id
            for group_id, members in group_members.items()
            if selected_set.intersection(members)
        )
    else:
        selected_group_ids = []

    revision_by_canonical: dict[str, str] = {}
    for canonical_id in inventory_rule_ids:
        revision_digest = applicability_by_id.get(canonical_id, {}).get(
            "revision_digest"
        )
        if not isinstance(revision_digest, str):
            baseline = rule_by_canonical.get(canonical_id)
            lineage = (
                canonical_lineage.get(baseline["ruleId"])
                if baseline is not None
                else None
            )
            revision_digest = (
                lineage.get("canonical_revision_digest")
                if isinstance(lineage, dict)
                else None
            )
        if isinstance(revision_digest, str):
            revision_by_canonical[canonical_id] = revision_digest
    if set(revision_by_canonical) != set(inventory_rule_ids):
        raise WorkflowError(
            "CONFORMANCE_PROFILE_SCOPE_INVALID",
            "canonical inventory 缺少精确 revision digest",
        )

    def identity_rows(canonical_ids: list[str]) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for canonical_id in sorted(canonical_ids):
            rows.append({
                "canonical_id": canonical_id,
                "revision_digest": revision_by_canonical[canonical_id],
            })
        return rows

    return {
        "execution_profile": profile,
        "requested_semantic_group_ids": requested_group_ids,
        "requested_canonical_rule_ids": requested_rule_ids,
        "selected_semantic_group_ids": selected_group_ids,
        "in_scope_rule_ids": in_scope_rule_ids,
        "baseline_in_scope_rule_ids": baseline_in_scope_rule_ids,
        "selected_rule_ids": selected_rule_ids,
        "deterministic_rule_ids": deterministic_rule_ids,
        "first_tier_semantic_rule_ids": first_tier_semantic_rule_ids,
        "selected_deterministic_rule_count": len(
            selected_set.intersection(deterministic_rule_ids)
        ),
        "in_scope_rule_set_digest": foundation_document_digest(
            identity_rows(in_scope_rule_ids)
        ),
        "selected_rule_set_digest": foundation_document_digest(
            identity_rows(selected_rule_ids)
        ),
        "semantic_group_registry_digest": registry_digest,
        "group_members": group_members,
        "rule_by_canonical": rule_by_canonical,
        "revision_by_canonical": revision_by_canonical,
        "auxiliary_rule_ids": sorted(auxiliary_rule_ids),
    }


def _retained_targeted_trial_ids(
    plan: dict[str, Any],
    canonical_projection: dict[str, Any],
) -> list[str]:
    """Derive canonical-only retained trial members for targeted or full runs.

    The implementation baseline intentionally excludes retained rules.  A
    targeted trial may still reach a retained rule when the Registry selects
    it.  ``full`` reaches every retained rule with an existing semantic or
    behavior-verification binding.  This helper only returns canonical
    identities; it never changes executable applicability or creates a
    baseline carrier.
    """
    if plan["execution_profile"] not in {"targeted", "full"}:
        return []
    if plan["execution_profile"] == "full":
        requested_members = set(plan["selected_rule_ids"])
    else:
        requested = set(plan["requested_semantic_group_ids"])
        group_members = plan["group_members"]
        requested_members = {
            canonical_id
            for group_id in requested
            for canonical_id in group_members[group_id]
        }
    projection_rules = [
        row for row in canonical_projection.get("rules", [])
        if isinstance(row, dict)
        and row.get("canonical_id") in requested_members
        and row.get("lifecycle_status") == "RETAINED_UNIMPLEMENTED"
        and set(row.get("check_methods") or []).intersection(
            semantic_review.NON_MECHANICAL_CHECK_METHODS
        )
    ]
    descriptors = semantic_review.retained_trial_descriptors(
        canonical_projection.get("rules", []),
        {row["canonical_id"] for row in projection_rules},
    )
    return sorted({row["canonical_id"] for row in descriptors})


def _profile_not_run_results(
    plan: dict[str, Any],
    canonical_lineage: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    selected = set(plan["selected_rule_ids"])
    selected.update(plan.get("retained_trial_rule_ids", []))
    rows: list[dict[str, Any]] = []
    for canonical_id in plan["in_scope_rule_ids"]:
        if canonical_id in selected:
            continue
        rule = plan["rule_by_canonical"][canonical_id]
        lineage = canonical_lineage[rule["ruleId"]]
        rows.append({
            "rule_id": rule["ruleId"],
            "rule_revision_digest": rule["revisionDigest"],
            "status": "NOT_RUN",
            "evidence": {
                "reason_code": "NOT_SELECTED_BY_EXECUTION_PROFILE",
                "execution_profile": plan["execution_profile"],
            },
            "worker": "conformance-profile-selection",
            "canonical_lineage": {
                "canonical_id": canonical_id,
                "revision_digest": lineage["canonical_revision_digest"],
            },
        })
    return rows


def _full_canonical_only_scope_results(
    plan: dict[str, Any],
    canonical_applicability: dict[str, Any],
) -> list[dict[str, Any]]:
    """Project selected full identities that legitimately have no baseline carrier.

    Active applicable rules remain on the verified baseline lineage path.
    Retained rules are produced by the retained-trial path.  This projection
    therefore covers only authority-backed non-applicability and any remaining
    canonical identity that cannot yet be executed.  It never invents a
    baseline identity.
    """
    if plan["execution_profile"] != "full":
        return []
    baseline_ids = set(plan["baseline_in_scope_rule_ids"])
    retained_ids = set(plan.get("retained_trial_rule_ids", []))
    selected = set(plan["selected_rule_ids"])
    rows: list[dict[str, Any]] = []
    for applicability in canonical_applicability.get("rules", []):
        canonical_id = applicability.get("canonical_id")
        if (
            canonical_id not in selected
            or canonical_id in baseline_ids
            or canonical_id in retained_ids
        ):
            continue
        disposition = applicability.get("disposition")
        if disposition == "not_applicable":
            status = "NOT_APPLICABLE"
            reason_code = "CANONICAL_SCOPE_NOT_APPLICABLE"
        else:
            status = "EVIDENCE_MISSING"
            reason_code = "CANONICAL_EXECUTION_CARRIER_MISSING"
        rows.append({
            "rule_id": canonical_id,
            "rule_revision_digest": applicability["revision_digest"],
            "canonical_id": canonical_id,
            "canonical_only": True,
            "status": status,
            "evidence": {
                "reason_code": reason_code,
                "disposition": disposition,
                "reason": applicability.get("reason"),
                "requested_target_type": applicability.get(
                    "requested_target_type"
                ),
                "requested_platform": applicability.get(
                    "requested_platform"
                ),
            },
            "worker": "canonical-applicability",
        })
    return sorted(rows, key=lambda row: row["canonical_id"])


def _semantic_profile_preflight(
    plan: dict[str, Any],
    registry: dict[str, Any],
    canonical_applicability: dict[str, Any],
    canonical_rules: list[dict[str, Any]],
    evidence_set: list[dict[str, Any]],
    *,
    foundation_task_digest: str,
    evidence_set_digest: str,
) -> dict[str, Any]:
    """Build the local evidence-role preflight without producing semantic verdicts."""
    base = {
        "performed": plan["execution_profile"] != "mechanical",
        "foundation_task_digest": foundation_task_digest,
        "evidence_set_digest": evidence_set_digest,
        "in_scope_rule_set_digest": plan["in_scope_rule_set_digest"],
        "semantic_group_registry_digest": plan[
            "semantic_group_registry_digest"
        ],
        "records": [],
    }
    if not base["performed"]:
        return base

    group_by_rule: dict[str, str] = {}
    for group in registry["groups"]:
        for rule in group["rules"]:
            group_by_rule[rule["canonical_id"]] = group["group_id"]
    in_scope_group_rules = set(plan["in_scope_rule_ids"]).intersection(group_by_rule)
    retained_trial_ids = set(plan.get("retained_trial_rule_ids", []))
    in_scope_group_rules.update(retained_trial_ids.intersection(group_by_rule))
    if plan["execution_profile"] == "targeted":
        in_scope_group_rules.intersection_update(
            set(plan["selected_rule_ids"]) | retained_trial_ids
        )
    in_scope_group_rules = sorted(in_scope_group_rules)
    if not in_scope_group_rules:
        return base

    canonical_by_id = {
        row.get("canonical_id"): row
        for row in canonical_rules
        if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
    }
    applicability_by_id = {
        row.get("canonical_id"): row
        for row in canonical_applicability.get("rules", [])
        if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
    }
    try:
        binding_index = semantic_review.load_bindings(canonical_rules)
    except semantic_review.SemanticReviewError as exc:
        raise WorkflowError(exc.code, str(exc)) from exc

    rule_rows: list[dict[str, Any]] = []
    binding_rows: list[dict[str, Any]] = []
    evidence_role_rows: list[dict[str, Any]] = []
    for canonical_id in in_scope_group_rules:
        canonical = canonical_by_id.get(canonical_id)
        applicability = applicability_by_id.get(canonical_id)
        if not isinstance(canonical, dict) or not isinstance(applicability, dict):
            raise WorkflowError(
                "SEMANTIC_PREFLIGHT_IDENTITY_MISSING",
                f"语义预筛缺少 canonical 或 applicability 身份: {canonical_id}",
            )
        identity = (canonical_id, canonical.get("revision_digest"))
        binding = binding_index.get(identity)
        if binding is None:
            raise WorkflowError(
                "SEMANTIC_PREFLIGHT_BINDING_MISSING",
                f"语义预筛规则缺少精确 evidence-role binding: {canonical_id}",
            )
        if canonical.get("lifecycle_status") == "RETAINED_UNIMPLEMENTED" and applicability.get("scope_disposition") in {"APPLICABLE", "NOT_APPLICABLE", "UNDETERMINED"}:
            scope_disposition = applicability["scope_disposition"]
            citable_scope_facts = applicability.get("citable_scope_facts", [])
        elif applicability.get("disposition") == "not_applicable":
            scope_disposition = "NOT_APPLICABLE"
            citable_scope_facts = [
                f"canonical_applicability.rules[{canonical_id}].disposition=not_applicable"
            ]
        elif applicability.get("executable") is True:
            scope_disposition = "APPLICABLE"
            citable_scope_facts = []
        else:
            scope_disposition = "UNDETERMINED"
            citable_scope_facts = []
        methods = canonical.get("check_methods") or []
        rule_rows.append({
            "canonical_id": canonical_id,
            "group_id": group_by_rule[canonical_id],
            "revision_digest": canonical["revision_digest"],
            "semantic_review_required": bool(
                set(methods) & set(semantic_review.NON_MECHANICAL_CHECK_METHODS)
            ),
            "scope_disposition": scope_disposition,
            "citable_scope_facts": citable_scope_facts,
        })
        required_roles = binding["required_evidence_roles"]
        binding_rows.append({
            "canonical_id": canonical_id,
            "binding_id": binding["binding_id"],
            "revision_digest": binding["revision_digest"],
            "required_evidence_roles": sorted(required_roles),
        })
        for role, allowed_kinds in required_roles.items():
            for evidence in evidence_set:
                if evidence["kind"] not in allowed_kinds:
                    continue
                evidence_role_rows.append({
                    "canonical_id": canonical_id,
                    "role": role,
                    "evidence_kind": evidence["kind"],
                    "evidence_id": evidence["evidence_id"],
                    "sha256": evidence["sha256"],
                    "locator": evidence["path"],
                })
    try:
        base["records"] = semantic_context_plan.build_semantic_preflight(
            rule_rows,
            binding_rows,
            evidence_role_rows,
        )
    except ValueError as exc:
        raise WorkflowError("SEMANTIC_PREFLIGHT_INVALID", str(exc)) from exc
    return base


def _semantic_profile_preflight_result(
    preflight: dict[str, Any],
) -> dict[str, Any]:
    """Project internal per-rule rows into a compact group-level result."""
    summaries: dict[str, dict[str, Any]] = {}
    for row in preflight["records"]:
        group_id = row["group_id"]
        summary = summaries.setdefault(
            group_id,
            {
                "group_id": group_id,
                "rule_count": 0,
                "applicable_rule_count": 0,
                "not_applicable_rule_count": 0,
                "undetermined_rule_count": 0,
                "ready_rule_count": 0,
                "missing_rule_count": 0,
                "review_required_rule_count": 0,
                "missing_evidence_roles": set(),
            },
        )
        summary["rule_count"] += 1
        applicability = row["applicability_preflight"]
        if applicability == "APPLICABLE":
            summary["applicable_rule_count"] += 1
        elif applicability == "NOT_APPLICABLE":
            summary["not_applicable_rule_count"] += 1
        else:
            summary["undetermined_rule_count"] += 1
        evidence_status = row["evidence_role_status"]
        if (
            row["semantic_review_required"] is True
            and applicability != "NOT_APPLICABLE"
            and evidence_status != "NOT_REQUIRED"
        ):
            summary["review_required_rule_count"] += 1
        if evidence_status == "READY":
            summary["ready_rule_count"] += 1
        elif evidence_status == "MISSING":
            summary["missing_rule_count"] += 1
            summary["missing_evidence_roles"].update(
                row["missing_evidence_roles"]
            )
    return {
        "performed": preflight["performed"],
        "groups": [
            {
                **summary,
                "missing_evidence_roles": sorted(
                    summary["missing_evidence_roles"]
                ),
            }
            for _, summary in sorted(summaries.items())
        ],
    }


def _descriptor_evidence_refs(
    descriptor: dict[str, Any],
    evidence_set: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Freeze the evidence rows made available to one semantic rule."""
    rows: list[dict[str, str]] = []
    for role, allowed_kinds in sorted(
        descriptor["required_evidence_roles"].items()
    ):
        for evidence in evidence_set:
            if evidence["kind"] not in allowed_kinds:
                continue
            rows.append({
                "evidence_id": evidence["evidence_id"],
                "sha256": evidence["sha256"],
                "locator": evidence["path"],
                "role": role,
            })
    return sorted(
        rows,
        key=lambda row: (
            row["role"], row["evidence_id"], row["sha256"], row["locator"]
        ),
    )


def _semantic_review_candidate_descriptors(
    plan: dict[str, Any],
    preflight: dict[str, Any],
    descriptors: list[dict[str, Any]],
    evidence_set: list[dict[str, Any]],
    canonical_applicability: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Select only rules that may enter a semantic model context.

    ``mechanical`` and ``economy`` never schedule semantic work.  Registry
    rules must be selected and READY in the local preflight.  The registry
    covers both retained and active semantic execution routes.  Deterministic
    routes that also declare a semantic method stay outside this grouping;
    ``full`` completes that additional method, while exact ``targeted`` does
    so only when that canonical rule was explicitly requested.
    """
    if plan["execution_profile"] not in {"targeted", "full"}:
        return []
    selected = set(plan["selected_rule_ids"])
    selected.update(plan.get("retained_trial_rule_ids", []))
    not_applicable = {
        row["canonical_id"] for row in (canonical_applicability or {}).get("rules", [])
        if row.get("disposition") == "not_applicable"
    }
    ready_group_rules = {
        row["canonical_id"]
        for row in preflight["records"]
        if row["canonical_id"] in selected
        and row["semantic_review_required"] is True
        and row["evidence_role_status"] == "READY"
        and row["applicability_preflight"] != "NOT_APPLICABLE"
    }
    if plan["execution_profile"] == "full":
        grouped_ids = {
            row["canonical_id"] for row in preflight["records"]
        }
        ungrouped_selected = selected.intersection(
            set(plan["deterministic_rule_ids"])
            | (set(plan.get("retained_trial_rule_ids", [])) - grouped_ids)
        )
    else:
        ungrouped_selected = set(plan.get("requested_canonical_rule_ids", []))
    candidates: list[dict[str, Any]] = []
    for descriptor in descriptors:
        canonical_id = descriptor["canonical_id"]
        if canonical_id in not_applicable:
            continue
        evidence_refs = _descriptor_evidence_refs(descriptor, evidence_set)
        covered_roles = {row["role"] for row in evidence_refs}
        required_roles = set(descriptor["required_evidence_roles"])
        if (
            canonical_id in ready_group_rules
            or canonical_id in ungrouped_selected
        ) and required_roles <= covered_roles:
            candidates.append({**descriptor, "evidence_refs": evidence_refs})
    return sorted(
        candidates,
        key=lambda row: (row["canonical_id"], row["check_method"]),
    )


def _selected_nonmechanical_obligations(
    plan: dict[str, Any],
    canonical_rules: list[dict[str, Any]],
) -> dict[tuple[str, str], list[str]]:
    """Derive selected non-mechanical methods from the verified projection."""
    selected = set(plan.get("selected_rule_ids", []))
    selected.update(plan.get("retained_trial_rule_ids", []))
    obligations: dict[tuple[str, str], list[str]] = {}
    seen_ids: set[str] = set()
    for row in canonical_rules:
        if not isinstance(row, dict):
            continue
        canonical_id = row.get("canonical_id")
        if canonical_id not in selected:
            continue
        revision_digest = row.get("revision_digest")
        methods = row.get("check_methods")
        if (
            not isinstance(canonical_id, str)
            or canonical_id in seen_ids
            or not isinstance(revision_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", revision_digest)
            or not isinstance(methods, list)
        ):
            raise WorkflowError(
                "SEMANTIC_REVIEW_REQUEST_INVALID",
                "selected canonical method identity is invalid",
            )
        seen_ids.add(canonical_id)
        nonmechanical = sorted(
            set(methods)
            & set(semantic_review.NON_MECHANICAL_CHECK_METHODS)
        )
        if nonmechanical:
            obligations[(canonical_id, revision_digest)] = nonmechanical
    return dict(sorted(obligations.items()))


def _nonmechanical_obligation_statuses(
    canonical_id: str,
    revision_digest: str,
    check_methods: list[str],
    finalized_reviews: dict[tuple[str, str, str], dict[str, Any]],
    scheduled_review_identities: set[tuple[str, str, str]],
    missing_evidence_roles: list[str],
) -> dict[str, str]:
    """Project every non-mechanical method without allowing substitution."""
    statuses: dict[str, str] = {}
    for check_method in sorted(check_methods):
        identity = (canonical_id, revision_digest, check_method)
        review = finalized_reviews.get(identity)
        if review is not None:
            statuses[check_method] = review["status"]
        elif missing_evidence_roles:
            statuses[check_method] = "EVIDENCE_MISSING"
        elif identity in scheduled_review_identities:
            statuses[check_method] = "REVIEW_REQUIRED"
        else:
            statuses[check_method] = "NOT_RUN"
    return statuses


def _retained_mechanical_gap_statuses(
    canonical_rule: dict[str, Any],
) -> dict[str, str]:
    """Keep every unimplemented retained mechanical method fail-closed."""
    if canonical_rule.get("lifecycle_status") != "RETAINED_UNIMPLEMENTED":
        return {}
    return {
        method: "EVIDENCE_MISSING"
        for method in sorted(
            set(canonical_rule.get("check_methods") or [])
            & MECHANICAL_CHECK_METHODS
        )
    }


def _selected_semantic_missing_evidence_roles(
    plan: dict[str, Any],
    preflight: dict[str, Any],
    descriptors: list[dict[str, Any]],
    evidence_set: list[dict[str, Any]],
    canonical_applicability: dict[str, Any] | None = None,
) -> dict[str, list[str]]:
    """Derive missing evidence for every selected executable semantic rule."""
    selected = set(plan["selected_rule_ids"])
    selected.update(plan.get("retained_trial_rule_ids", []))
    not_applicable = {
        row["canonical_id"] for row in (canonical_applicability or {}).get("rules", [])
        if row.get("disposition") == "not_applicable"
    }
    grouped_selected = {
        row["canonical_id"]
        for row in preflight["records"]
        if row["canonical_id"] in selected
        and row["semantic_review_required"] is True
        and row["applicability_preflight"] != "NOT_APPLICABLE"
    }
    selected_semantic = grouped_selected
    if plan["execution_profile"] == "full":
        selected_semantic.update(plan["deterministic_rule_ids"])
        selected_semantic.update(plan.get("retained_trial_rule_ids", []))
    elif plan.get("requested_canonical_rule_ids"):
        selected_semantic.update(plan["requested_canonical_rule_ids"])
    missing_by_id: dict[str, list[str]] = {}
    for descriptor in descriptors:
        canonical_id = descriptor["canonical_id"]
        if canonical_id not in selected_semantic or canonical_id in not_applicable:
            continue
        covered_roles = {
            row["role"]
            for row in _descriptor_evidence_refs(descriptor, evidence_set)
        }
        missing_roles = sorted(
            set(descriptor["required_evidence_roles"]) - covered_roles
        )
        if missing_roles:
            missing_by_id[canonical_id] = missing_roles
    return dict(sorted(missing_by_id.items()))


def _semantic_registry_indexes(
    registry: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    group_by_rule: dict[str, str] = {}
    family_by_rule: dict[str, str] = {}
    for group in registry["groups"]:
        for rule in group["rules"]:
            group_by_rule[rule["canonical_id"]] = group["group_id"]
            family_by_rule[rule["canonical_id"]] = group["review_family"]
    return group_by_rule, family_by_rule


def _bounded_security_observation(
    target: Path | None,
    canonical_projection: dict[str, Any],
) -> dict[str, Any]:
    """Project the existing checker's bounded scan without exposing matches."""
    revision = next(
        (
            row.get("revision_digest")
            for row in canonical_projection.get("rules", [])
            if row.get("canonical_id") == "SFA-SECRET-003"
        ),
        None,
    )
    expected_version = f"SFA-SECRET-003@{revision}" if revision else None
    if target is not None:
        scan = checker._scan(target)
        observation = scan.get("material_security") if isinstance(scan, dict) else None
        if isinstance(observation, dict):
            if observation.get("redaction_rule_version") == expected_version:
                return observation
    return {
        "scanner": {
            "method_id": checker.CHECKER_METHOD_ID,
            "version": checker.CHECKER_VERSION,
        },
        "scope": "enumerated-audit-text-materials-only",
        "status": "EVIDENCE_MISSING",
        "paths": [],
        "path_count": 0,
        "unavailable": [{
            "path": ".",
            "reason": (
                "bounded_material_root_unavailable"
                if target is None
                else "material_scan_unavailable"
            ),
        }],
        "findings": [],
        "finding_count": 0,
        "finding_limit": checker._MATERIAL_FINDING_LIMIT,
        "truncated": False,
        "credential_shaped_or_sensitive_match_present": False,
        "absence_claim_scope": "scanned_paths_only",
        "redaction_rule_version": expected_version,
        "redaction_applied": False,
    }


def _context_document(
    canonical_ids: list[str],
    *,
    request: dict[str, Any],
    plan: dict[str, Any],
    registry: dict[str, Any],
    target_type: str,
    platform: str,
    target_digest: str,
) -> dict[str, Any]:
    descriptor_by_id: dict[str, list[dict[str, Any]]] = {}
    for row in request["rules"]:
        descriptor_by_id.setdefault(row["canonical_id"], []).append(row)
    group_by_rule, family_by_rule = _semantic_registry_indexes(registry)
    families = sorted({
        family_by_rule.get(canonical_id, "first-tier-semantic")
        for canonical_id in canonical_ids
    })
    if len(families) != 1:
        raise WorkflowError(
            "SEMANTIC_CONTEXT_INVALID",
            "一个语义上下文不能混入多个 review family",
        )
    rules = [
        descriptor
        for canonical_id in canonical_ids
        for descriptor in sorted(
            descriptor_by_id[canonical_id], key=lambda row: row["check_method"]
        )
    ]
    identity_rows = [
        {
            "canonical_id": row["canonical_id"],
            "revision_digest": row["canonical_revision_digest"],
            "check_method": row["check_method"],
            "binding_id": row["binding_id"],
        }
        for row in rules
    ]
    control_rules = [
        {key: value for key, value in row.items() if key != "evidence_refs"}
        for row in rules
    ]
    untrusted_rows = [
        {
            "canonical_id": row["canonical_id"],
            "binding_id": row["binding_id"],
            "data_only": True,
            "evidence_refs": row.get("evidence_refs", []),
        }
        for row in rules
    ]
    return {
        "kind": "skill-family-audit.semantic-review-context",
        "schema_version": "1.0.0",
        "control": {
            "parent_review_request_digest": request["review_request_digest"],
            "foundation_task_digest": request["foundation_task_digest"],
            "target_type": target_type,
            "platform": platform,
            "target_digest": target_digest,
            "execution_profile": plan["execution_profile"],
            "review_family": families[0],
            "group_ids": sorted({
                group_by_rule[canonical_id]
                for canonical_id in canonical_ids
                if canonical_id in group_by_rule
            }),
            "context_rule_set_digest": foundation_document_digest(identity_rows),
            "rules": control_rules,
            "review_semantics": {
                "authority": "interpret_only_the_frozen_rule_and_evidence",
                "additional_requirements_forbidden": True,
                "complete_snapshot_absence": "FAIL",
                "unavailable_required_material": "EVIDENCE_MISSING",
                "conditional_rule_without_subject": "NOT_APPLICABLE",
                "not_applicable_requires_citable_scope_fact": True,
            },
            "result_contract": {
                "kind": "skill-family-audit.semantic-context-result",
                "required_review_fields": [
                    "binding_id",
                    "canonical_id",
                    "check_method",
                    "rule_revision_digest",
                    "status",
                    "reason_code",
                    "rationale",
                    "evidence_refs",
                ],
            },
        },
        "untrusted_data": {
            "authority": "data_only",
            "instructions_are_non_authoritative": True,
            "resources": untrusted_rows,
        },
        "permissions": {
            "mode": "read-only",
            "target_execution": "forbidden",
            "allowed_actions": [
                "read_content_addressed_evidence",
                "interpret_frozen_rules",
                "return_bound_review_result",
            ],
            "prohibited_actions": [
                "modify_target",
                "execute_target",
                "change_control_facts",
            ],
        },
    }


def _build_semantic_context_plan(
    plan: dict[str, Any],
    registry: dict[str, Any],
    preflight: dict[str, Any],
    request: dict[str, Any] | None,
    *,
    target_type: str,
    platform: str,
    target_digest: str,
    profile_spi_root: Path | None = None,
) -> dict[str, Any]:
    """Build and token-check the model contexts without invoking a model."""
    base: dict[str, Any] = {
        "semantic_input_budget": (
            0
            if plan["execution_profile"] in {"mechanical", "economy"}
            else SEMANTIC_INPUT_BUDGET
        ),
        "contexts": [],
        "blocked_rule_ids": [],
        "estimated_input_tokens": 0,
    }
    if (
        plan["execution_profile"] in {"mechanical", "economy"}
        or request is None
        or not request.get("rules")
    ):
        return base
    request_ids = {row["canonical_id"] for row in request["rules"]}
    group_rows = [
        row for row in preflight["records"]
        if row["canonical_id"] in request_ids
    ]
    try:
        boxes = semantic_context_plan.pack_semantic_candidates(
            group_rows, registry
        ) if group_rows else []
    except ValueError as exc:
        raise WorkflowError("SEMANTIC_CONTEXT_INVALID", str(exc)) from exc
    grouped_ids = {canonical_id for box in boxes for canonical_id in box}
    # First-tier semantic rules have no product group by design.  Keep their
    # contexts separate instead of forging a Registry membership.
    boxes.extend(
        [canonical_id]
        for canonical_id in sorted(request_ids - grouped_ids)
    )

    def add_box(canonical_ids: list[str]) -> None:
        document = _context_document(
            canonical_ids,
            request=request,
            plan=plan,
            registry=registry,
            target_type=target_type,
            platform=platform,
            target_digest=target_digest,
        )
        context_text = foundation_canonical_bytes(document).decode("utf-8")
        estimate = foundation_estimate_tokens(
            context_text, profile_spi_root=profile_spi_root
        )
        if estimate["tokens"] > SEMANTIC_INPUT_BUDGET:
            if len(canonical_ids) == 1:
                base["blocked_rule_ids"].append(canonical_ids[0])
                return
            midpoint = len(canonical_ids) // 2
            add_box(canonical_ids[:midpoint])
            add_box(canonical_ids[midpoint:])
            return
        context_digest = foundation_document_digest(document)
        base["contexts"].append({
            "context_digest": context_digest,
            "canonical_ids": list(canonical_ids),
            "estimated_input_tokens": estimate["tokens"],
            "estimator": estimate["estimator"],
            "request": document,
        })
        base["estimated_input_tokens"] += estimate["tokens"]

    for box in boxes:
        add_box(box)
    base["blocked_rule_ids"].sort()
    return base


def _review_ref_identities(refs: Any) -> list[str]:
    if not isinstance(refs, list):
        raise WorkflowError(
            "SEMANTIC_CONTEXT_RESULT_INVALID", "evidence_refs 必须是数组"
        )
    fields = ("evidence_id", "sha256", "locator", "role")
    identities: list[str] = []
    for ref in refs:
        if (
            not isinstance(ref, dict)
            or set(ref) != set(fields)
            or any(not isinstance(ref[field], str) for field in fields)
        ):
            raise WorkflowError(
                "SEMANTIC_CONTEXT_RESULT_INVALID",
                "evidence_refs 必须只含 evidence_id、sha256、locator、role 四个字符串字段",
            )
        # 仅用于本次父子引用比较；不是 Foundation canonical JSON 或制品摘要。
        identities.append(json.dumps([ref[field] for field in fields], ensure_ascii=True))
    return identities


def _semantic_context_rules(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Read rules from the partitioned context while accepting old frozen fixtures."""
    control = document.get("control")
    if not isinstance(control, dict):
        rules = document.get("rules")
        return rules if isinstance(rules, list) else []
    rules = control.get("rules")
    untrusted = document.get("untrusted_data")
    resources = untrusted.get("resources") if isinstance(untrusted, dict) else None
    if not isinstance(rules, list) or not isinstance(resources, list):
        return []
    refs_by_binding = {
        row.get("binding_id"): row.get("evidence_refs")
        for row in resources
        if isinstance(row, dict) and row.get("data_only") is True
    }
    return [
        {**row, "evidence_refs": refs_by_binding.get(row.get("binding_id"), [])}
        for row in rules
        if isinstance(row, dict)
    ]


def _merge_semantic_context_results(
    request: dict[str, Any],
    context_plan: dict[str, Any],
    context_results: Any,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Validate exact child subsets and construct one internalReviewV2 payload."""
    if not isinstance(context_results, list):
        raise WorkflowError(
            "SEMANTIC_CONTEXT_RESULT_INVALID", "context results 必须是数组"
        )
    expected_contexts = {
        row["context_digest"]: row for row in context_plan["contexts"]
    }
    observed_contexts: set[str] = set()
    child_reviews: list[dict[str, Any]] = []
    parent_rows: list[dict[str, Any]] = []
    child_rows: list[dict[str, Any]] = []
    for expected in context_plan["contexts"]:
        for rule in _semantic_context_rules(expected["request"]):
            parent_rows.append({
                "canonical_id": rule["canonical_id"],
                "revision_digest": rule["canonical_revision_digest"],
                "check_method": rule["check_method"],
                "binding_id": rule["binding_id"],
                "evidence_refs": _review_ref_identities(rule["evidence_refs"]),
            })
    for item in context_results:
        if not isinstance(item, dict) or set(item) != {
            "context_digest", "reviews"
        }:
            raise WorkflowError(
                "SEMANTIC_CONTEXT_RESULT_INVALID",
                "每个 context result 只能包含 context_digest 与 reviews",
            )
        context_digest = item["context_digest"]
        expected = expected_contexts.get(context_digest)
        if expected is None or context_digest in observed_contexts:
            raise WorkflowError(
                "SEMANTIC_CONTEXT_RESULT_INVALID",
                "context result 包含未知或重复的 context_digest",
            )
        reviews = item["reviews"]
        if not isinstance(reviews, list):
            raise WorkflowError(
                "SEMANTIC_CONTEXT_RESULT_INVALID", "context reviews 必须是数组"
            )
        expected_review_ids = {
            (
                row["canonical_id"],
                row["canonical_revision_digest"],
                row["check_method"],
            )
            for row in _semantic_context_rules(expected["request"])
        }
        observed_review_ids = {
            (
                row.get("canonical_id"),
                row.get("rule_revision_digest"),
                row.get("check_method"),
            )
            for row in reviews if isinstance(row, dict)
        }
        if (
            observed_review_ids != expected_review_ids
            or len(reviews) != len(expected_review_ids)
        ):
            raise WorkflowError(
                "SEMANTIC_CONTEXT_RESULT_INVALID",
                "context reviews 未精确覆盖冻结的规则子集",
            )
        observed_contexts.add(context_digest)
        for review in reviews:
            if not isinstance(review, dict):
                raise WorkflowError(
                    "SEMANTIC_CONTEXT_RESULT_INVALID", "review 必须是对象"
                )
            child_reviews.append(review)
            child_rows.append({
                "canonical_id": review.get("canonical_id"),
                "revision_digest": review.get("rule_revision_digest"),
                "check_method": review.get("check_method"),
                "binding_id": review.get("binding_id"),
                "evidence_refs": _review_ref_identities(
                    review.get("evidence_refs")
                ),
            })
    if observed_contexts != set(expected_contexts):
        raise WorkflowError(
            "SEMANTIC_CONTEXT_RESULT_INVALID",
            "context results 遗漏冻结的语义上下文",
        )
    try:
        validated = semantic_context_plan.validate_child_result_rows(
            parent_rows, child_rows
        )
    except ValueError as exc:
        raise WorkflowError("SEMANTIC_CONTEXT_RESULT_INVALID", str(exc)) from exc
    ordered_ids = [
        (row["canonical_id"], row["revision_digest"], row["check_method"])
        for row in validated
    ]
    review_by_id = {
        (
            row["canonical_id"],
            row["rule_revision_digest"],
            row["check_method"],
        ): row
        for row in child_reviews
    }
    payload = {
        "schema_version": "2.0.0",
        "kind": "skill-family-audit.semantic-review-result",
        "producer_method_id": request["producer_method_id"],
        "cognitive_independence": request["cognitive_independence"],
        "foundation_task_digest": request["foundation_task_digest"],
        "review_request_digest": request["review_request_digest"],
        "evidence_set_digest": request["evidence_set_digest"],
        "reviewed_rule_set_digest": request["reviewed_rule_set_digest"],
        "reviews": [review_by_id[identity] for identity in ordered_ids],
    }
    return payload, {
        # Bound context results prove what this run consumed, not whether the
        # host produced them through a current model call, a retry, or a
        # previously frozen review.  Keep unbound host observations unknown.
        "semantic_model_call_count": None,
        "semantic_context_count": len(context_results),
        "estimated_input_tokens": context_plan["estimated_input_tokens"],
        "semantic_rules_sent_to_model_count": None,
    }


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


def _load_formal_release_object(path: Path) -> dict[str, Any] | None:
    if path.is_symlink():
        raise WorkflowError("INPUT_INVALID", f"{path}: 拒绝符号链接")
    if not path.exists():
        return None
    return load_json(path)


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
    # 自审与显式测试夹具保留原分支，不借此取得正式可发布性。
    if is_fixture or index.get("selfAudit") is True:
        return index, manifest, is_fixture, trust_policy
    # --spec-package 仍是消费方 spec 目录；release_root 只由其外层显式推导。
    release_root = package.resolve().parent
    release_index = _load_formal_release_object(
        release_root / spec_release_resolver.EXTERNAL_RELEASE_INDEX_PATH
    )
    receipt = _load_formal_release_object(
        release_root / spec_release_resolver.GOVERNANCE_APPROVAL_RECEIPT_PATH
    )
    resolved = spec_release_resolver.resolve_spec_release(
        release_index or {}, receipt, release_root
    )
    binding_error = checker.external_consumer_binding_error(package, resolved)
    if binding_error:
        if (
            resolved.get("status") != "active"
            or not isinstance(resolved.get("active_release"), dict)
        ):
            detail = "正式外部规范未通过批准链，规则运行前拒绝"
        else:
            detail = "正式外部规范的消费目录或 scope 不符合外部消费者前提，规则运行前拒绝"
        raise WorkflowError(binding_error, detail)
    return index, manifest, is_fixture, trust_policy


def canonical_rule_summary(
    trust_policy: dict[str, Any],
    projection: dict[str, Any] | None = None,
    projection_sha256: str | None = None,
) -> dict[str, Any]:
    expected = trust_policy.get("canonical_rule_projection", {})
    expected_total_rules = expected.get("total_rules")
    if projection is None:
        receipt = foundation_read_file_strict(
            AUDIT_PACKAGE_ROOT,
            CANONICAL_PROJECTION_RELATIVE,
            expected.get("digest"),
        )
        projection = strict_read_json(
            receipt,
            "CANONICAL_RULE_PROJECTION_INVALID",
            "canonical rule projection",
        )
        projection_sha256 = receipt["sha256"]
    if (
        projection_sha256 != expected.get("digest")
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
        "projection_digest": projection_sha256,
        "source_digest": projection["source_digest"],
        "business_digest": projection["business_digest"],
        "total_rules": expected_total_rules,
        **dispositions,
    }


def canonical_rule_applicability(
    trust_policy: dict[str, Any],
    target_type: str,
    platform: str = "all",
    projection: dict[str, Any] | None = None,
    projection_sha256: str | None = None,
    retained_scope_observations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """逐条分类信任策略钉扎的全量规则；终态记录是候选投影的唯一运行覆盖。"""
    if projection is None:
        expected = trust_policy.get("canonical_rule_projection", {})
        receipt = foundation_read_file_strict(
            AUDIT_PACKAGE_ROOT,
            CANONICAL_PROJECTION_RELATIVE,
            expected.get("digest"),
        )
        projection = strict_read_json(
            receipt,
            "CANONICAL_RULE_PROJECTION_INVALID",
            "canonical rule projection",
        )
        projection_sha256 = receipt["sha256"]
    summary = canonical_rule_summary(
        trust_policy,
        projection,
        projection_sha256,
    )
    rows: list[dict[str, Any]] = []
    retained_scope_observations = retained_scope_observations or {}
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
        platform_matches = (
            platform == "all"
            or "all" in platform_scope
            or platform in platform_scope
        )
        # 候选品质标签只是如实披露的质量描述，不构成执行封禁：可执行性由
        # 生命周期是否冻结、目标类型与宿主范围是否匹配决定。
        candidate_label = (
            effect == "candidate_undetermined"
            or adoption_mode == "candidate_undetermined"
            or "candidate_undetermined" in platform_scope
        )
        # 只有生命周期未冻结才失败关闭：未冻结规则不得持有执行路由。
        lifecycle_unfrozen = lifecycle_status not in {
            "ACTIVE_MECHANICAL",
            "ACTIVE_SEMANTIC",
            "RETAINED_UNIMPLEMENTED",
        }
        candidate_undetermined = candidate_label or lifecycle_unfrozen
        retained_unimplemented = lifecycle_status == "RETAINED_UNIMPLEMENTED"
        retained_scope = retained_scope_observations.get(canonical_id, {})
        scope_disposition = retained_scope.get("scope_disposition", "UNDETERMINED")
        if scope_disposition not in {"APPLICABLE", "UNDETERMINED"}:
            raise WorkflowError("CANONICAL_RULE_APPLICABILITY_INVALID",
                                f"保留规则范围观察非法: {canonical_id}")
        active = lifecycle_status in {"ACTIVE_MECHANICAL", "ACTIVE_SEMANTIC"}
        executable = active and (
            target_type == "project_adoption"
            or (
                target_type == "family_source"
                and rule.get("execution_scope") in {"all_families", "family_scoped"}
            )
        ) and platform_matches
        execution_route, execution_route_detail = canonical_rule_execution_route(rule)
        if lifecycle_unfrozen != (execution_route == ROUTE_UNROUTED_CANDIDATE):
            raise WorkflowError(
                "CANONICAL_RULE_APPLICABILITY_INVALID",
                f"生命周期冻结状态与执行路由不一致，禁止静默: {canonical_id}",
            )
        row = {
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
                "not_applicable" if not platform_matches else
                "executable" if executable else
                "retained_unimplemented" if retained_unimplemented else
                "candidate_undetermined" if candidate_undetermined else
                "not_applicable"
            ),
            "executable": executable,
            "execution_route": execution_route,
            "execution_route_detail": execution_route_detail,
            "reason": (
                f"规则 platform_scope 不包含请求宿主 {platform}" if not platform_matches else
                "终态五轴已冻结并适用于当前目标" if executable else
                "规则已保留但尚未绑定可执行实现，禁止执行" if retained_unimplemented else
                "候选品质标签如实披露，不作为执行封禁依据；本规则未进入本次可执行集合"
                if candidate_undetermined else
                "终态规则不适用于当前目标"
            ),
        }
        if retained_unimplemented:
            row.update({
                "scope_disposition": scope_disposition,
                "citable_scope_facts": retained_scope.get("citable_scope_facts", []),
            })
        rows.append(row)
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


def _family_source_terminal_execution_plan(
    manifest: dict[str, Any],
    canonical_applicability: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Select only terminal carriers that this workflow can really execute.

    Canonical applicability decides which rules apply to a family.  The
    terminal implementation row only supplies the existing execution carrier;
    its legacy ``project_adoption`` label must not override canonical scope.
    Unsupported static GMIN carriers remain explicit blockers and produce no
    result, so declarations and lineage can never inflate execution coverage.
    """
    terminal_rows = manifest.get("terminalRuleImplementations", [])
    if terminal_rows in (None, []):
        return [], []
    if not isinstance(terminal_rows, list) or not all(
        isinstance(row, dict) for row in terminal_rows
    ):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "terminalRuleImplementations 必须是对象数组",
        )
    terminal_index: dict[str, dict[str, Any]] = {}
    for row in terminal_rows:
        rule_id = row.get("ruleId")
        if not isinstance(rule_id, str) or not rule_id or rule_id in terminal_index:
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                "terminalRuleImplementations 规则身份缺失或重复",
            )
        terminal_index[rule_id] = row

    lineage_rows = manifest.get("canonicalRuleLineage", [])
    if not isinstance(lineage_rows, list):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID", "canonicalRuleLineage 必须是数组"
        )
    lineage_index: dict[str, dict[str, Any]] = {}
    baseline_ids: set[str] = set()
    for row in lineage_rows:
        if not isinstance(row, dict):
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID", "canonical lineage 行必须是对象"
            )
        canonical_id = row.get("canonicalId")
        baseline_id = row.get("baselineRuleId")
        if (
            not isinstance(canonical_id, str)
            or not canonical_id
            or canonical_id in lineage_index
            or not isinstance(baseline_id, str)
            or not baseline_id
            or baseline_id in baseline_ids
        ):
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                "canonical lineage 身份缺失、重复或非一对一",
            )
        lineage_index[canonical_id] = row
        baseline_ids.add(baseline_id)

    authoritative = {
        row.get("canonical_id"): row
        for row in canonical_applicability.get("rules", [])
        if isinstance(row, dict)
        and isinstance(row.get("canonical_id"), str)
        and row.get("canonical_id")
        and row.get("executable") is True
    }
    declared_rows = manifest.get("canonicalRuleIds", [])
    if not isinstance(declared_rows, list) or not all(
        isinstance(item, str) and item for item in declared_rows
    ):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "canonicalRuleIds 必须是非空字符串数组",
        )
    declared = set(declared_rows)
    if len(declared) != len(declared_rows):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID", "canonicalRuleIds 不得重复"
        )
    runnable: list[dict[str, Any]] = []
    blockers: list[dict[str, str]] = []
    for canonical_id in sorted(declared & set(authoritative)):
        lineage = lineage_index.get(canonical_id)
        if lineage is None:
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"family_source 可执行 canonical 缺少 lineage: {canonical_id}",
            )
        baseline_id = lineage["baselineRuleId"]
        terminal = terminal_index.get(baseline_id)
        canonical = authoritative[canonical_id]
        if terminal is None:
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"family_source 可执行 canonical 缺少 terminal carrier: {canonical_id}",
            )
        if (
            terminal.get("revisionDigest") != lineage.get("baselineRevisionDigest")
            or canonical.get("revision_digest")
            != lineage.get("canonicalRevisionDigest")
        ):
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"family_source terminal carrier 与 lineage 修订不一致: {canonical_id}",
            )
        check_type = terminal.get("checkType")
        if executors.supports(baseline_id):
            if check_type != "static":
                raise WorkflowError(
                    "BASELINE_RULE_LINEAGE_INVALID",
                    f"W2 terminal carrier 必须使用 static 执行器: {canonical_id}",
                )
            runnable.append(terminal)
        elif baseline_id.startswith("gmin:") and check_type in ("semantic", "static"):
            # 静态 gmin 承载由 _gmin_static_outcome 的确定性分支执行，
            # 与语义承载一样属于既有执行路由，不得继续投影为无执行器 blocker。
            runnable.append(terminal)
        elif baseline_id.startswith("semantic:") and check_type == "semantic":
            # 激活语义规则的正式语义 binding 载体：由单一语义审阅通道承接，
            # 无内部审阅时回落 external-semantic-review-pending 的真实结果。
            runnable.append(terminal)
        else:
            raise WorkflowError(
                "BASELINE_RULE_LINEAGE_INVALID",
                f"family_source terminal carrier 没有既有执行路由: {canonical_id}",
            )
    return runnable, blockers


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
    method_assurance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Count only real execution results carrying the verified lineage tuple."""
    required = {
        (row["canonical_id"], row["revision_digest"])
        for row in canonical_applicability["rules"]
        if row.get("executable") is True
    }
    result_index = {item.get("rule_id"): item for item in results}
    method_records = {
        rule_method_assurance.obligation_identity(record): record
        for record in (method_assurance or {}).get("records", [])
    }
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
        # A lineage-bound result is only executed coverage when its method
        # actually reached a terminal determination.  Missing evidence is a
        # real non-passing result, but never proof that the rule was executed.
        method_subresults = result.get("check_method_subresults")
        method_terminal = (
            True
            if method_subresults is None
            else (
                isinstance(method_subresults, list)
                and bool(method_subresults)
                and all(
                    isinstance(item, dict)
                    and item.get("status")
                    not in {"EVIDENCE_MISSING", "NOT_RUN"}
                    for item in method_subresults
                )
            )
        )
        review_method = (
            rule_method_assurance.select_review_method([
                item.get("check_method")
                for item in method_subresults
                if isinstance(item, dict) and item.get("status") == "NOT_RUN"
            ])
            if isinstance(method_subresults, list)
            else None
        )
        if review_method is not None:
            # Mixed rules consume the same validated ledger; executor rows
            # retain their original non-mechanical NOT_RUN observation.
            method_terminal = bool(method_subresults) and all(
                isinstance(item, dict)
                and method_records.get((
                    binding["canonical_id"], binding["canonical_revision_digest"],
                    item.get("check_method"),
                ), {}).get("trusted_observation", {}).get("status")
                in {"PASS", "FAIL", "NOT_APPLICABLE"}
                for item in method_subresults
            )
        if result.get("status") in {
            "PASS", "FAIL", "NOT_APPLICABLE",
        } and method_terminal:
            covered.add(
                (binding["canonical_id"], binding["canonical_revision_digest"])
            )
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


def _release_file_references(value: Any) -> list[str]:
    if isinstance(value, dict):
        refs = [value["methodContractRef"]] if "methodContractRef" in value else []
        for child in value.values():
            refs.extend(_release_file_references(child))
        return refs
    if isinstance(value, list):
        refs = []
        for child in value:
            refs.extend(_release_file_references(child))
        return refs
    return []


def _validate_release_closure(root: Path) -> list[str]:
    files: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise WorkflowError(
                "RELEASE_ARTIFACT_CLOSURE_INVALID", "发行物包含符号链接"
            )
        if path.is_file():
            files.append(path.relative_to(root).as_posix())
    schema_entries: list[dict[str, Any]] = []
    file_references: list[tuple[str, str]] = []
    for relative in files:
        path = root / relative
        if path.suffix != ".json":
            continue
        value = load_json(path)
        if path.name.endswith(".schema.json"):
            if not isinstance(value, dict) or not isinstance(value.get("$id"), str) or not value["$id"]:
                raise WorkflowError(
                    "RELEASE_ARTIFACT_CLOSURE_INVALID",
                    f"Schema 缺少有效 $id: {relative}",
                )
            schema_entries.append({"$id": value["$id"], "document": value})
        else:
            for reference in _release_file_references(value):
                if not isinstance(reference, str) or not reference:
                    raise WorkflowError(
                        "RELEASE_ARTIFACT_CLOSURE_INVALID",
                        f"文件引用不是非空字符串: {relative}",
                    )
                file_references.append((relative, reference))
    if schema_entries:
        try:
            runner = checker.foundation_runner()
            result = adoption_verifier._invoke_closure_entry(
                "import { collectUnresolvedRefs } from 'skill-family-contracts'; "
                "process.stdin.setEncoding('utf8'); "
                "let raw = ''; for await (const chunk of process.stdin) raw += chunk; "
                "process.stdout.write(JSON.stringify({unresolved: "
                "collectUnresolvedRefs(JSON.parse(raw))}));",
                [],
                payload=json.dumps(schema_entries, ensure_ascii=False),
                profile_spi_root=runner.parent.parent / "profile-spi",
            )
        except (RuntimeError, adoption_verifier.VerificationError) as exc:
            raise WorkflowError(
                "RELEASE_ARTIFACT_CLOSURE_INVALID",
                f"受管 Foundation Schema 引用检查不可用: {exc}",
            ) from exc
        unresolved = result.get("unresolved")
        if not isinstance(unresolved, list) or any(not isinstance(item, dict) for item in unresolved):
            raise WorkflowError(
                "RELEASE_ARTIFACT_CLOSURE_INVALID",
                "受管 Foundation Schema 引用检查返回无效结果",
            )
        if unresolved:
            first = unresolved[0]
            raise WorkflowError(
                "RELEASE_ARTIFACT_CLOSURE_INVALID",
                f"未闭合 Schema 引用: {first.get('$id')} -> {first.get('ref')}: {first.get('reason')}",
            )
    for relative, reference in file_references:
        resource = reference.split("#", 1)[0]
        if not resource:
            continue
        if ":" in resource or resource.startswith("//"):
            raise WorkflowError(
                "RELEASE_ARTIFACT_CLOSURE_INVALID",
                f"未闭合或越界引用: {relative} -> {reference}",
            )
        path = root / relative
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


PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".codex",
    ".release-skill",
    "artifacts",
    "control",
    "dist",
    "evidence",
    "fixtures",
    "generated",
    "node_modules",
    "tests",
}


def _validate_posix_relative_path(
    value: str,
    field_name: str,
    *,
    code: str = "PROJECT_ADOPTION_INVALID",
) -> None:
    """收容校验：必须是 POSIX 相对路径，拒绝绝对路径、遍历、反斜杠。"""
    if not isinstance(value, str) or not value:
        raise WorkflowError(
            code,
            f"{field_name} 不是非空字符串",
        )
    if value.startswith("/") or value.startswith("\\"):
        raise WorkflowError(
            code,
            f"{field_name} 是绝对路径: {value}",
        )
    if "\\" in value:
        raise WorkflowError(
            code,
            f"{field_name} 包含反斜杠: {value}",
        )
    # 使用原始字符串分割检查，避免 Path() 自动规范化
    parts = value.split("/")
    if ".." in parts:
        raise WorkflowError(
            code,
            f"{field_name} 包含遍历 '..': {value}",
        )
    if not parts or any(part in ("", ".") for part in parts):
        raise WorkflowError(
            code,
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
    mapped_physical_names = set()
    for projection in projections or []:
        if not isinstance(projection, dict):
            continue
        for mapping in projection.get("mappings", []):
            if not isinstance(mapping, dict) or any(
                not isinstance(mapping.get(field), str) or not mapping[field]
                for field in ("skillId", "physicalName", "path")
            ):
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    "平台投影映射缺少逻辑技能、物理技能名或路径",
                )
            mapped_physical_names.add(mapping["physicalName"])
    unmapped = sorted(mapped_physical_names - observed_ids)
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

# 平台分布目录：宿主 manifest 位于插件根时，根 skills/ 逻辑技能在各平台
# adapters/<平台>/skills/** 下的同名拷贝视为平台分布拷贝（分诊裁决
# triage-duplicate-logical-skill-id.md §3；豁免仅当同一逻辑 ID 同时由根
# skills/ 声明，根声明为准；根无对应声明或宿主 manifest 缺失时维持 fail-closed）。
_PLATFORM_DISTRIBUTION_ADAPTER_DIRS = frozenset(
    {"claude", "codex", "workbuddy", "kimi-code"}
)


def _is_platform_distribution_skill_copy(path: Path, root: Path) -> bool:
    """判定 path 是否位于 adapters/<已知平台>/skills/** 平台分布拷贝区。

    调用方保证 path 是既有普通文件且非符号链接；本函数只做相对布局判定，
    不做文件系统访问。
    """
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return (
        len(parts) >= 4
        and parts[0] == "adapters"
        and parts[1] in _PLATFORM_DISTRIBUTION_ADAPTER_DIRS
        and parts[2] == "skills"
    )


SOURCE_AUTHORITY_FILENAME = "skill-family.source-authority.json"
SOURCE_AUTHORITY_KIND = "skill-family.source-authority-declaration"
RELEASE_PROJECT_RELATIVE = ".release-skill/project.yaml"
BEFORE_RULE_SELECTION = "before_rule_selection"


class DeclaredProduct:
    """Workspace vs current product declaration resolved from the audited tree."""

    __slots__ = (
        "observation_root",
        "workspace_root",
        "product_root",
        "generated_roots",
        "release_units",
    )

    def __init__(
        self,
        observation_root: Path,
        workspace_root: Path | None,
        product_root: Path,
        generated_roots: tuple[Path, ...],
        release_units: tuple[dict[str, str], ...] = (),
    ) -> None:
        self.observation_root = observation_root
        self.workspace_root = workspace_root
        self.product_root = product_root
        self.generated_roots = generated_roots
        self.release_units = release_units


class _WorkflowStage:
    """Actual control-flow marker; never derived from caller-supplied stage flags."""

    __slots__ = ("rule_scope_resolved", "evidence_set", "after_scope")

    def __init__(self) -> None:
        self.rule_scope_resolved = False
        self.evidence_set: list[dict[str, Any]] | None = None
        self.after_scope: dict[str, Any] | None = None


def _record_after_scope(stage: _WorkflowStage, **fields: Any) -> None:
    if stage.after_scope is None:
        stage.after_scope = {}
    stage.after_scope.update(fields)


def _strip_yaml_scalar(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text.split(" #", 1)[0].strip()


def _parse_release_unit_sources(text: str) -> list[dict[str, str]]:
    """Read releaseUnits[].id and unit-level source from release-skill YAML.

    Nested keys such as version.source are ignored by indent.  This parser
    only consumes the current product locator; it does not interpret the
    rest of the publish configuration.
    """
    units: list[dict[str, str]] = []
    in_units = False
    units_indent: int | None = None
    item_indent: int | None = None
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        stripped = raw.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        body = stripped.strip()
        if not in_units:
            if body.rstrip(":") == "releaseUnits":
                in_units = True
                units_indent = indent
            continue
        if units_indent is not None and indent <= units_indent and not body.startswith("-"):
            break
        if body.startswith("-"):
            if item_indent is not None and indent > item_indent:
                continue
            if current is not None:
                units.append(current)
            current = {}
            item_indent = indent
            rest = body[1:].strip()
            if rest:
                key, _, value = rest.partition(":")
                key = key.strip()
                if key in {"id", "source"} and key not in current:
                    current[key] = _strip_yaml_scalar(value)
            continue
        if current is None or item_indent is None:
            continue
        if indent > item_indent + 2:
            continue
        key, _, value = body.partition(":")
        key = key.strip()
        if key in {"id", "source"} and key not in current:
            current[key] = _strip_yaml_scalar(value)
    if current is not None:
        units.append(current)
    return units


def _contained_existing_dir(root: Path, relative: str, *, code: str) -> Path:
    """Resolve a POSIX relative directory inside root without following symlinks."""
    _validate_posix_relative_path(relative, "declared product path", code=code)
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise WorkflowError(
                code,
                f"声明路径链中存在符号链接: {relative}",
            )
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (FileNotFoundError, ValueError) as exc:
        raise WorkflowError(
            code,
            f"声明路径不在目标内或不存在: {relative}",
        ) from exc
    if not resolved.is_dir():
        raise WorkflowError(
            code,
            f"声明路径不是目录: {relative}",
        )
    return resolved


def _read_source_authority(product_root: Path) -> dict[str, Any] | None:
    path = product_root / SOURCE_AUTHORITY_FILENAME
    if not path.is_file():
        return None
    if path.is_symlink():
        raise WorkflowError(
            "SOURCE_AUTHORITY_SYMLINK",
            f"{SOURCE_AUTHORITY_FILENAME} 不得是符号链接",
        )
    value = load_json(path)
    if value.get("kind") != SOURCE_AUTHORITY_KIND:
        raise WorkflowError(
            "SOURCE_AUTHORITY_INVALID",
            f"{SOURCE_AUTHORITY_FILENAME} kind 不是 {SOURCE_AUTHORITY_KIND}",
        )
    mappings = value.get("mappings")
    if mappings is None:
        return value
    if not isinstance(mappings, list):
        raise WorkflowError(
            "SOURCE_AUTHORITY_INVALID",
            f"{SOURCE_AUTHORITY_FILENAME} mappings 必须是数组",
        )
    return value


def _generated_roots_from_authority(
    product_root: Path, authority: dict[str, Any] | None
) -> tuple[Path, ...]:
    if not isinstance(authority, dict):
        return ()
    mappings = authority.get("mappings")
    if not isinstance(mappings, list):
        return ()
    roots: list[Path] = []
    seen: set[Path] = set()
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        declared = mapping.get("generatedRoots")
        if not isinstance(declared, list):
            continue
        for relative in declared:
            if not isinstance(relative, str) or not relative:
                raise WorkflowError(
                    "SOURCE_AUTHORITY_INVALID",
                    "generatedRoots 必须是非空相对路径字符串",
                )
            generated = product_root / relative
            if generated.is_symlink():
                raise WorkflowError(
                    "SOURCE_AUTHORITY_INVALID",
                    f"当前生成投影根不得是符号链接: {relative}",
                )
            if not generated.is_dir():
                continue
            resolved = _contained_existing_dir(
                product_root,
                relative,
                code="SOURCE_AUTHORITY_INVALID",
            )
            if resolved not in seen:
                seen.add(resolved)
                roots.append(resolved)
    return tuple(roots)


def _platform_manifests_under(generated_root: Path) -> list[Path]:
    found: list[Path] = []
    direct = generated_root / "platform-manifest.json"
    if direct.is_file() and not direct.is_symlink():
        found.append(direct)
    if not generated_root.is_dir() or generated_root.is_symlink():
        return found
    for child in sorted(generated_root.iterdir()):
        if not child.is_dir() or child.is_symlink():
            continue
        candidate = child / "platform-manifest.json"
        if candidate.is_file() and not candidate.is_symlink():
            found.append(candidate)
    return found


def _release_project_path(root: Path) -> Path | None:
    path = root / RELEASE_PROJECT_RELATIVE
    if not path.is_file():
        return None
    if path.is_symlink() or any(
        (root / part).is_symlink()
        for part in Path(RELEASE_PROJECT_RELATIVE).parts[:-1]
    ):
        raise WorkflowError(
            "RELEASE_PROJECT_SYMLINK",
            f"{RELEASE_PROJECT_RELATIVE} 不得是符号链接",
        )
    return path


def _workspace_root_declaring(product_root: Path) -> Path | None:
    """If the audited product is declared by a containing workspace, return that root.

    Only reads a `.release-skill/project.yaml` whose unit source resolves to this
    product.  Does not walk the checker install layout.
    """
    parent = product_root.parent
    if parent == product_root:
        return None
    workspace = parent.parent
    if workspace == parent:
        return None
    yaml_path = _release_project_path(workspace)
    if yaml_path is None:
        return None
    units = _parse_release_unit_sources(yaml_path.read_text(encoding="utf-8"))
    for unit in units:
        source = unit.get("source")
        if not isinstance(source, str) or not source:
            continue
        try:
            resolved = _contained_existing_dir(
                workspace, source, code="RELEASE_UNIT_SOURCE_INVALID"
            )
        except WorkflowError:
            continue
        if resolved == product_root.resolve():
            return workspace
    return None


def declared_product_observation(root: Path) -> DeclaredProduct:
    """Locate the current product from the audited tree without guessing install layout.

    Direct product directories keep existing identification.  A workspace with
    `.release-skill/project.yaml` uses the unique release unit `source`.  Multiple
    units are an entry question, not a default-first choice.
    """
    observation_root = root.resolve()
    project_yaml = _release_project_path(observation_root)
    if project_yaml is not None:
        units = _parse_release_unit_sources(
            project_yaml.read_text(encoding="utf-8")
        )
        valid = [
            {"id": unit["id"], "source": unit["source"]}
            for unit in units
            if unit.get("id") and unit.get("source")
        ]
        incomplete = [
            unit for unit in units
            if unit.get("id") and not unit.get("source")
        ]
        if incomplete:
            raise WorkflowError(
                "RELEASE_PROJECT_INVALID",
                "releaseUnits 条目必须同时具有 id 与 source",
            )
        if valid:
            if len(valid) > 1:
                options = ", ".join(
                    f"{item['id']} ({item['source']})" for item in valid
                )
                raise WorkflowError(
                    "RELEASE_UNIT_AMBIGUOUS",
                    "工作区声明了多个发布单元，不能默认取第一个；请选择要检查的产品: "
                    + options,
                )
            product_root = _contained_existing_dir(
                observation_root,
                valid[0]["source"],
                code="RELEASE_UNIT_SOURCE_INVALID",
            )
            product_authority = _read_source_authority(product_root)
            return DeclaredProduct(
                observation_root=observation_root,
                workspace_root=observation_root,
                product_root=product_root,
                generated_roots=_generated_roots_from_authority(
                    product_root, product_authority
                ),
                release_units=tuple(valid),
            )
    authority = _read_source_authority(observation_root)
    if authority is not None:
        return DeclaredProduct(
            observation_root=observation_root,
            workspace_root=_workspace_root_declaring(observation_root),
            product_root=observation_root,
            generated_roots=_generated_roots_from_authority(
                observation_root, authority
            ),
        )
    return DeclaredProduct(
        observation_root=observation_root,
        workspace_root=None,
        product_root=observation_root,
        generated_roots=(),
    )


def _identity_scan_root(root: Path, target_type: str) -> tuple[Path, DeclaredProduct]:
    declared = declared_product_observation(root)
    if target_type == "project_adoption" and declared.workspace_root is None:
        return root, declared
    return declared.product_root, declared


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
    identity_root, declared = _identity_scan_root(root, target_type)
    package_path = identity_root / "package.json"
    candidate_summary_path = identity_root / "candidate-summary.json"

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
        path = identity_root / relative
        if path.is_file() and not path.is_symlink():
            manifest_paths.add(path)
    if target_type != "project_adoption":
        source_scan = identity_root / "plugin-src"
        if source_scan.is_dir() and not source_scan.is_symlink():
            manifest_paths.update(
                path
                for path in source_scan.rglob("platform-manifest.json")
                if path.is_file() and not path.is_symlink()
            )
        elif not declared.generated_roots:
            manifest_paths.update(
                path
                for path in identity_root.rglob("platform-manifest.json")
                if path.is_file()
                and not path.is_symlink()
                and not any(
                    part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                    for part in path.relative_to(identity_root).parts
                )
            )
        for generated_root in declared.generated_roots:
            manifest_paths.update(_platform_manifests_under(generated_root))
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
    for manifest_path in sorted(identity_root.rglob("platform-manifest.json")):
        if (
            not manifest_path.is_file()
            or manifest_path.is_symlink()
            or any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in manifest_path.relative_to(identity_root).parts
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
        source_manifest = (
            target_type == "family_source"
            and manifest_path.is_relative_to(identity_root / "plugin-src" / "platforms")
        )
        managed_template = (
            _managed_platform_source_template(
                identity_root, manifest_path, manifest, raw_mappings
            )
            if source_manifest else None
        )
        if managed_template is not None:
            managed_template_paths.add(managed_template)
        elif source_manifest:
            source_template = manifest_path.parent / "SKILL.md"
            if (
                source_template.is_file()
                and not source_template.is_symlink()
                and _frontmatter_identity(source_template) == SHARED_SKILL_NAME_TEMPLATE
            ):
                raise WorkflowError(
                    "UNMANAGED_LOGICAL_SKILL_TEMPLATE",
                    f"未由闭合平台投影认领的逻辑技能模板: {_relative_path(source_template, root)}",
                )
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
            physical_name = raw.get("physicalName")
            if not isinstance(physical_name, str) or not physical_name:
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    f"平台投影映射缺少物理技能名: {_relative_path(manifest_path, root)}",
                )
            _validate_posix_relative_path(
                mapping_path, "平台投影 Skill 路径",
                code="PROJECTION_LOGICAL_SKILL_UNMAPPED",
            )
            mapped_path = manifest_path.parent / mapping_path
            declared_source_mapping = (
                source_manifest
                and manifest.get("platformId") in MANAGED_PLATFORM_TEMPLATE_IDS
                and manifest.get("projectionStatus") == "projection_complete"
                and len(raw_mappings) == 1
                and mapping_path == "skill/SKILL.md"
                and logical_id == physical_name
            )
            if (
                (managed_template is not None or declared_source_mapping)
                and not mapped_path.exists()
                and not mapped_path.is_symlink()
            ):
                # The source declaration precedes its generated platform Skill.
                mappings.append({
                    "skillId": logical_id,
                    "physicalName": physical_name,
                    "path": mapping_path,
                })
                continue
            try:
                resolved_mapping = mapped_path.resolve(strict=True)
                resolved_mapping.relative_to(identity_root.resolve())
            except (OSError, ValueError) as exc:
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    f"平台投影 Skill 路径缺失或越界: {_relative_path(manifest_path, root)} -> {mapping_path}",
                ) from exc
            if resolved_mapping != mapped_path or not resolved_mapping.is_file():
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    f"平台投影 Skill 路径不是候选内普通文件: {_relative_path(manifest_path, root)} -> {mapping_path}",
                )
            frontmatter, _ = checker._parse_frontmatter(
                mapped_path.read_text(encoding="utf-8")
            )
            if not isinstance(frontmatter, dict) or frontmatter.get("name") != physical_name:
                raise WorkflowError(
                    "PROJECTION_LOGICAL_SKILL_UNMAPPED",
                    f"平台投影 Skill 物理身份不符: {_relative_path(manifest_path, root)} -> {mapping_path}",
                )
            projected_skill_paths.add(resolved_mapping)
            mappings.append({
                "skillId": logical_id,
                "physicalName": physical_name,
                "path": mapping_path,
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

    skill_root = (
        identity_root
        if declared.workspace_root is not None and declared.product_root != root
        else root
    )
    if target.is_file():
        skill_paths = [target]
    elif (
        target_type == "family_source"
        and (skill_root / "skills-src").is_dir()
        and not (skill_root / "skills-src").is_symlink()
    ):
        source_root = skill_root / "skills-src"
        skill_paths = [
            path
            for path in sorted({
                *source_root.rglob("SKILL.md"),
                *source_root.rglob("SKILL.md.tpl"),
            })
            if path.is_file()
            and not path.is_symlink()
            and not any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in path.relative_to(source_root).parts
            )
        ]
    else:
        skill_paths = [
            path
            for path in sorted(skill_root.rglob("SKILL.md"))
            if path.is_file()
            and not path.is_symlink()
            and path.resolve() not in projected_skill_paths
            and not any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in path.relative_to(skill_root).parts
            )
        ]
        # 宿主 manifest 认领的平台分布拷贝豁免（仅 observe 区最小改动）。
        # 条件：根存在宿主 manifest、且同一逻辑 ID 同时由根 skills/ 声明；
        # 豁免的拷贝不进入 skills 列表（根声明为准）。根无对应声明或宿主
        # manifest 缺失时维持 fail-closed（拷贝按普通声明参与重复判定）。
        distribution_copies = [
            path
            for path in skill_paths
            if _is_platform_distribution_skill_copy(path, skill_root)
        ]
        if (
            distribution_copies
            and not target.is_file()
            and any(
                (skill_root / relative).is_file()
                and not (skill_root / relative).is_symlink()
                for relative in host_manifest_relatives
            )
        ):
            root_skills_dir = skill_root / "skills"
            root_declared_ids: set[str] = set()
            if root_skills_dir.is_dir() and not root_skills_dir.is_symlink():
                for declared in sorted(root_skills_dir.rglob("SKILL.md")):
                    if (
                        declared.is_file()
                        and not declared.is_symlink()
                        and not any(
                            part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                            for part in declared.relative_to(root_skills_dir).parts
                        )
                    ):
                        root_declared_ids.add(_frontmatter_identity(declared))
            if root_declared_ids:
                exempt: set[Path] = {
                    path
                    for path in distribution_copies
                    if _frontmatter_identity(path) in root_declared_ids
                }
                if exempt:
                    skill_paths = [path for path in skill_paths if path not in exempt]
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
                    and mapping["physicalName"] not in seen_ids
                ):
                    relative = _relative_path(path, root)
                    seen_ids[mapping["physicalName"]] = relative
                    skills.append({"id": mapping["physicalName"], "path": relative})
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
    elif target_type == "project_adoption":
        # 缺少插件身份是应由审计结果暴露的目标事实，不是拒绝审计该目标的理由。
        observation["plugin"] = {
            "id": None,
            "version": version if isinstance(version, str) else None,
            "manifest": (
                manifest_identities[0]["path"] if manifest_identities else None
            ),
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


def _declared_product_payload(declared: DeclaredProduct) -> dict[str, Any]:
    return {
        "observation_root": str(declared.observation_root),
        "workspace_root": (
            str(declared.workspace_root) if declared.workspace_root is not None else None
        ),
        "product_root": str(declared.product_root),
        "generated_roots": [str(path) for path in declared.generated_roots],
    }


def _observe_foundation_profile(root: Path) -> dict[str, Any]:
    """Observe profile.json at the product root without blocking the audit.

    Missing, invalid or unverified profiles stay observational.  Callers must
    not treat an absent verification as a verified empty configuration.
    """
    project_profile_path = root / "profile.json"
    profile_document: dict[str, Any] | None = None
    profile_result: dict[str, Any] = {
        "foundation_profile_complete": False,
        "code": "PROJECT_PROFILE_MISSING",
        "blockers": ["项目未提供 profile.json"],
    }
    profile_digest: str | None = None
    if project_profile_path.is_symlink():
        profile_result = {
            "foundation_profile_complete": False,
            "code": "PROJECT_PROFILE_SYMLINK",
            "blockers": ["profile.json 不得是符号链接"],
        }
    elif project_profile_path.is_file():
        try:
            profile_document = load_json(project_profile_path)
            profile_digest = foundation_file_digest(project_profile_path)
            profile_result = adoption_verifier.verify_project_profile(root)
            profile_result["foundation_profile_complete"] = (
                profile_result.get("code") == "SPE0000"
                and profile_result.get("foundation_profile_complete") is True
            )
        except WorkflowError as exc:
            profile_result = {
                "foundation_profile_complete": False,
                "code": "PROJECT_PROFILE_INVALID",
                "blockers": [str(exc)],
            }
    observed: dict[str, Any] = {"foundation_profile": profile_result}
    if profile_document is not None:
        observed.update({
            "project_profile_document": profile_document,
            "project_profile": "profile.json",
            "project_profile_digest": profile_digest,
        })
    return observed


def target_scope(target: Path, target_type: str) -> dict[str, Any]:
    if target_type == "single_skill":
        skill = target if target.name == "SKILL.md" else target / "SKILL.md"
        if not skill.is_file():
            raise WorkflowError("SINGLE_SKILL_MISSING", "单技能目标缺少 SKILL.md")
        observation = observe_plugin_project(skill, target_type)
        declared = declared_product_observation(skill.parent)
        return {
            "skill_files": [skill.relative_to(target.parent).as_posix()],
            "plugin_project": observation,
            "logical_skill_count": len(observation["skills"]),
            "declared_product": _declared_product_payload(declared),
        }
    if not target.is_dir():
        raise WorkflowError("TARGET_TYPE_MISMATCH", "该目标类型要求目录")
    if target_type == "family_source":
        skills = sorted(
            path.relative_to(target).as_posix()
            for path in target.rglob("SKILL.md")
            if path.is_file()
            and not path.is_symlink()
            and not any(
                part in PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
                for part in path.relative_to(target).parts
            )
        )
        if not skills:
            raise WorkflowError("FAMILY_SOURCE_EMPTY", "技能族源码没有 SKILL.md")
        observation = observe_plugin_project(target, target_type)
        declared = declared_product_observation(target)
        source_excluded_parts = {
            "__pycache__",
            ".pytest_cache",
            ".git",
            "node_modules",
            *PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS,
        }
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
        scope = {
            "skill_files": skills,
            "source_files": source_files,
            "source_tree_digest": foundation_tree_digest(target),
            "plugin_project": observation,
            "logical_skill_count": len(observation["skills"]),
            "declared_product": _declared_product_payload(declared),
        }
        scope.update(_observe_foundation_profile(declared.product_root))
        return scope
    if target_type == "release_artifact":
        payload_roots = ("platforms", "spec", ".claude-plugin", "skills")
        if not (target / "candidate-summary.json").is_file():
            raise WorkflowError(
                "RELEASE_ARTIFACT_INCOMPLETE", "缺失: ['candidate-summary.json']"
            )
        summary = load_json(target / "candidate-summary.json")
        release_files = _validate_release_closure(target)
        payload_files = [
            relative for relative in release_files
            if relative.startswith(tuple(f"{name}/" for name in payload_roots))
        ]
        actual_payload = str(
            foundation_resource_closure(target, payload_files)["digest"]
        )
        plugin_name = summary.get("familyId")
        version = summary.get("version")
        package_path = target / "package.json"
        package_json = load_json(package_path) if package_path.is_file() else None
        if (
            not isinstance(plugin_name, str)
            or not plugin_name
            or not isinstance(version, str)
            or not version
            or summary.get("candidateId") != f"{plugin_name}:{version}"
            or summary.get("candidatePayloadDigest") != actual_payload
            or (
                package_json is not None
                and (
                    package_json.get("name") != plugin_name
                    or package_json.get("version") != version
                )
            )
        ):
            raise WorkflowError(
                "RELEASE_ARTIFACT_IDENTITY_INVALID",
                "发行包身份、版本或 payload 摘要不闭合",
            )
        observation = observe_plugin_project(target, target_type)
        declared = declared_product_observation(target)
        return {
            "plugin_name": plugin_name,
            "release_files": release_files,
            "release_tree_digest": foundation_tree_digest(target),
            "candidate_payload_digest": actual_payload,
            "plugin_project": observation,
            "logical_skill_count": len(observation["skills"]),
            "declared_product": _declared_product_payload(declared),
        }
    # project_adoption 是审计范围，不是“目标已经合规”的前置断言。存在
    # profile.json 时通过 Foundation 0.12.0 公共 SPI 观察其有效性；缺失、非法
    # 或符号链接只形成非通过证据，不能在规则执行前阻断整个审计。零/部分消费
    # Foundation 的项目可以用 Audit 自有 exemption 载体进入同一范围，其完整
    # 合同仍由对应 canonical 规则判定，scope 层不重复实现第二套验证器。
    project_profile_path = target / "profile.json"
    exemption_relatives = (
        "foundation-adoption-exemption.json",
        ".skill-family-audit/governance/foundation-adoption-exemption.json",
    )
    exemption_paths = [
        target / relative
        for relative in exemption_relatives
        if (target / relative).is_file() and not (target / relative).is_symlink()
    ]
    if len(exemption_paths) > 1:
        raise WorkflowError(
            "PROJECT_ADOPTION_PROOF_AMBIGUOUS",
            "项目同时声明多份 Foundation adoption exemption",
        )

    profile_observation = _observe_foundation_profile(target)
    profile_result = profile_observation["foundation_profile"]
    profile_document = profile_observation.get("project_profile_document")

    exemption_document: dict[str, Any] | None = None
    exemption_relative: str | None = None
    exemption_digest: str | None = None
    if exemption_paths:
        exemption_path = exemption_paths[0]
        exemption_relative = exemption_path.relative_to(target).as_posix()
        try:
            exemption_document = load_json(exemption_path)
            exemption_digest = foundation_file_digest(exemption_path)
        except WorkflowError:
            # 文件存在本身足以让 scope 规则观察到 proof carrier；详细合同错误由
            # SFA-FOUNDATION-003/006 返回，不在范围识别阶段吞掉整次审计。
            exemption_document = None

    profile_project = (
        profile_document.get("project")
        if isinstance(profile_document, dict)
        else None
    )
    exemption_project = (
        exemption_document.get("project")
        if isinstance(exemption_document, dict)
        else None
    )
    plugin_id = (
        profile_project.get("id")
        if isinstance(profile_project, dict)
        else exemption_project.get("projectId")
        if isinstance(exemption_project, dict)
        else None
    )
    profile_kind = (
        profile_document.get("kind")
        if isinstance(profile_document, dict)
        else None
    )
    observation = observe_plugin_project(
        target,
        target_type,
        identity_hint={
            "pluginId": plugin_id,
            "profileKind": profile_kind,
        },
    )
    declared = declared_product_observation(target)
    scope = {
        **profile_observation,
        "project_adoption_evidence": {
            "reviewable": True,
            "profile_carrier": (
                "profile.json"
                if project_profile_path.is_file() or project_profile_path.is_symlink()
                else None
            ),
            "profile_code": profile_result.get("code"),
            "exemption_carrier": exemption_relative,
        },
        "plugin_project": observation,
        "logical_skill_count": len(observation["skills"]),
        "declared_product": _declared_product_payload(declared),
    }
    if exemption_relative is not None:
        scope.update({
            "foundation_exemption": exemption_relative,
            "foundation_exemption_document": exemption_document,
            "foundation_exemption_digest": exemption_digest,
        })
    return scope

def semantic_reviews(
    path: Path | None,
    rules: list[dict[str, Any]],
    task_digest: str,
    target: Path | None,
    target_type: str,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """返回 (逐规则待审证据, 调用方原始审阅条目)。

    调用方提交的外部语义审阅结果只能作为待审证据：其状态（含 PASS）不改变
    逐规则结论（确定性 CLI 保持 REVIEW_REQUIRED），也不改变顶层结论。
    文档本身失败关闭（Schema、任务绑定、符号链接与目标边界等）。
    """
    semantic = [rule for rule in rules if rule.get("checkType") == "semantic"]
    if not semantic:
        return {}, []
    if path is None:
        return {
            rule["ruleId"]: {
                "rule_id": rule["ruleId"],
                "rule_revision_digest": rule["revisionDigest"],
                "status": "EVIDENCE_MISSING",
                "evidence": [],
            }
            for rule in semantic
        }, []
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
    if target is not None:
        boundary = target.parent if target.is_file() else target
        if semantic_path == boundary or boundary in semantic_path.parents:
            raise WorkflowError(
                "SEMANTIC_RESULT_INSIDE_TARGET",
                "语义结果必须位于只读目标之外",
            )
    value = load_json(semantic_path)
    validation_errors = _semantic_schema_errors(value)
    if validation_errors:
        raise WorkflowError(
            "SEMANTIC_RESULT_SCHEMA_INVALID",
            "; ".join(validation_errors),
        )
    if value.get("schema_version") != "1.0.0":
        raise WorkflowError(
            "SEMANTIC_RESULT_EXTERNAL_ONLY",
            "外部 semantic-result 只能使用 v1 待审证据合同；v2 仅限当前 conformance Skill 内存通道",
        )
    if value["task_digest"] != task_digest:
        raise WorkflowError(
            "SEMANTIC_RESULT_TASK_MISMATCH",
            "语义结果没有绑定当前规范化 Task",
        )
    reviews: dict[str, dict[str, Any]] = {}
    for item in value["reviews"]:
        if not isinstance(item, dict):
            # The schema normally rejects this first; keep the consumer
            # fail-closed if a schema implementation is replaced or mocked.
            raise WorkflowError("SEMANTIC_RESULT_SCHEMA_INVALID", "reviews")
        rule_id = item.get("rule_id")
        if rule_id in reviews:
            raise WorkflowError(
                "SEMANTIC_RESULT_DUPLICATE_RULE_ID",
                f"语义结果重复 rule_id: {rule_id}",
            )
        reviews[rule_id] = item
    for rule in semantic:
        review = reviews.get(rule.get("ruleId"))
        if (
            not review
            or review.get("rule_revision_digest") != rule.get("revisionDigest")
            or review.get("status") not in {"PASS", "FAIL", "EVIDENCE_MISSING"}
            or not isinstance(review.get("evidence"), list)
        ):
            raise WorkflowError("SEMANTIC_RESULT_SCHEMA_INVALID", rule.get("ruleId", ""))
        if target is None:
            # 无源码边界（证据受限审阅）：evidence 引用无法按目标树解析，
            # 保持原样记录为待审证据，不声明其可解析。
            continue
        boundary = target.parent if target.is_file() else target
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
    return reviews, list(value["reviews"])


EVIDENCE_KINDS = {
    "source_tree",
    "source_file",
    "jsonl_conversation",
    "log",
    "manifest",
    "receipt",
    "policy",
    "exception",
    "platform_support",
}
SOURCE_EVIDENCE_KINDS = {"source_tree", "source_file"}


def _evidence_entry_error(entry: Any, label: str) -> str | None:
    """逐项失败关闭校验：闭合字段集合、已知种类、绝对规范路径、SHA-256 与实际字节一致。

    额外字段、未知类型、摘要不符与符号链接一律拒绝（不静默忽略）。
    """
    if not isinstance(entry, dict):
        return f"{label} 必须是对象"
    if set(entry) != {"evidence_id", "kind", "path", "sha256"}:
        return f"{label} 字段集合必须精确闭合（额外字段失败关闭）"
    evidence_id = entry.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id:
        return f"{label}.evidence_id 必须是非空字符串"
    kind = entry.get("kind")
    if kind not in EVIDENCE_KINDS:
        return f"{label}.kind 是未知类型"
    path_value = entry.get("path")
    if (
        not isinstance(path_value, str)
        or not os.path.isabs(path_value)
        or os.path.normpath(path_value) != path_value
    ):
        return f"{label}.path 必须是绝对规范路径"
    sha256 = entry.get("sha256")
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return f"{label}.sha256 必须是 64 位十六进制摘要"
    path = Path(path_value)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return f"{label}.path 不存在"
    if resolved != path:
        return f"{label}.path 不得包含符号链接"
    if kind == "source_tree":
        if not resolved.is_dir():
            return f"{label}.path 必须是目录（source_tree）"
    elif not resolved.is_file():
        return f"{label}.path 必须是普通文件（{kind}）"
    actual = (
        foundation_tree_digest(resolved)
        if kind == "source_tree"
        else foundation_file_digest(resolved)
    )
    if actual != sha256:
        return f"{label}.sha256 与实际字节不符"
    return None


def _load_evidence_set(path: Path) -> list[dict[str, Any]]:
    """加载并校验调用方提供的证据集合文件（仅含 evidence_set 键）。"""
    if path.is_symlink():
        raise WorkflowError(
            "EVIDENCE_SET_NOT_REGULAR_FILE",
            "证据集合文件不得是符号链接",
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise WorkflowError(
            "EVIDENCE_SET_NOT_REGULAR_FILE",
            "证据集合文件必须是既有普通文件",
        ) from exc
    if not resolved.is_file():
        raise WorkflowError(
            "EVIDENCE_SET_NOT_REGULAR_FILE",
            "证据集合文件必须是既有普通文件",
        )
    value = load_json(resolved)
    if set(value) != {"evidence_set"}:
        raise WorkflowError(
            "EVIDENCE_SET_DOCUMENT_INVALID",
            "证据集合文档必须只含 evidence_set 键",
        )
    entries = value.get("evidence_set")
    if not isinstance(entries, list) or not entries:
        raise WorkflowError(
            "EVIDENCE_SET_DOCUMENT_INVALID",
            "evidence_set 必须是非空数组",
        )
    seen_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        error = _evidence_entry_error(entry, f"evidence_set[{index}]")
        if error:
            raise WorkflowError("EVIDENCE_SET_ENTRY_INVALID", error)
        if entry["evidence_id"] in seen_ids:
            raise WorkflowError(
                "EVIDENCE_SET_DUPLICATE_ID",
                f"evidence_id 重复: {entry['evidence_id']}",
            )
        seen_ids.add(entry["evidence_id"])
        normalized.append({
            "evidence_id": entry["evidence_id"],
            "kind": entry["kind"],
            "path": str(Path(entry["path"]).resolve()),
            "sha256": entry["sha256"],
        })
    return normalized


def _workspace_evidence_selection_entries(
    workspace_root: Path,
    product_root: Path,
) -> list[dict[str, Any]]:
    """从已选产品根的正式制品清单读取 workspace_evidence_selection。

    清单位于被审产品根；所选文件相对被审工作区根读取。不从安装缓存父目录
    猜测工作区。SHA-256 必须由 Foundation 在运行时严格读取派生。
    """
    inventory_path = (
        product_root / "spec/current-artifacts/formal-artifact-inventory.json"
    )
    if not inventory_path.is_file() or inventory_path.is_symlink():
        return []
    try:
        inventory = load_json(inventory_path)
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(
            "FORMAL_ARTIFACT_INVENTORY_INVALID",
            f"无法读取正式制品清单: {exc}",
        ) from exc
    selection = inventory.get("workspace_evidence_selection")
    if selection is None:
        return []
    if not isinstance(selection, list):
        raise WorkflowError(
            "FORMAL_ARTIFACT_INVENTORY_INVALID",
            "workspace_evidence_selection 必须是数组",
        )
    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(selection):
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "kind", "proves"}
        ):
            raise WorkflowError(
                "FORMAL_ARTIFACT_INVENTORY_INVALID",
                f"workspace_evidence_selection[{index}] 字段集合不合法",
            )
        relative_path = item.get("path")
        kind = item.get("kind")
        proves = item.get("proves")
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or relative_path.startswith("/")
        ):
            raise WorkflowError(
                "FORMAL_ARTIFACT_INVENTORY_INVALID",
                f"workspace_evidence_selection[{index}].path 必须是相对路径",
            )
        if kind not in EVIDENCE_KINDS:
            raise WorkflowError(
                "FORMAL_ARTIFACT_INVENTORY_INVALID",
                f"workspace_evidence_selection[{index}].kind 不是已知证据类型",
            )
        if not isinstance(proves, str) or not proves:
            raise WorkflowError(
                "FORMAL_ARTIFACT_INVENTORY_INVALID",
                f"workspace_evidence_selection[{index}].proves 必须是非空字符串",
            )
        evidence_id = f"workspace-evidence:{relative_path}"
        if evidence_id in seen_ids:
            raise WorkflowError(
                "FORMAL_ARTIFACT_INVENTORY_INVALID",
                f"workspace_evidence_selection evidence_id 重复: {evidence_id}",
            )
        seen_ids.add(evidence_id)
        receipt = foundation_read_file_strict(workspace_root, relative_path)
        entries.append({
            "evidence_id": evidence_id,
            "kind": kind,
            "path": str(workspace_root / relative_path),
            "sha256": receipt["sha256"],
        })
    return entries


def _declared_product_for_target(target: Path) -> DeclaredProduct | None:
    root = target if target.is_dir() else target.parent
    try:
        return declared_product_observation(root)
    except WorkflowError:
        return None


def _is_audit_self_audit_target(target_arg: str | None) -> DeclaredProduct | None:
    """受检目标是否声明为当前 Audit 产品或其工作区。

    只读取被审目录上的发布单元与源码权威，不从安装缓存父目录猜测工作区。
    外部目标不携带本仓图事实。
    """
    if not target_arg:
        return None
    try:
        resolved = Path(target_arg).resolve()
    except OSError:
        return None
    declared = _declared_product_for_target(resolved)
    if declared is None:
        return None
    product_name = None
    package_path = declared.product_root / "package.json"
    if package_path.is_file() and not package_path.is_symlink():
        try:
            name = load_json(package_path).get("name")
        except WorkflowError:
            name = None
        if isinstance(name, str) and name:
            product_name = name
    if product_name != "skill-family-audit":
        return None
    if resolved == declared.product_root or resolved == declared.workspace_root:
        return declared
    if declared.workspace_root is not None and (
        resolved == declared.workspace_root
        or declared.workspace_root in resolved.parents
    ):
        return declared
    return None


def _augment_evidence_set_with_workspace_selection(
    evidence_set: list[dict[str, Any]],
    target_arg: str | None,
) -> list[dict[str, Any]]:
    """自审时把清单声明的工作区证据选择补充进 evidence set，避免重复。"""
    declared = _is_audit_self_audit_target(target_arg)
    if declared is None or declared.workspace_root is None:
        return evidence_set
    existing_ids = {entry.get("evidence_id") for entry in evidence_set}
    for entry in _workspace_evidence_selection_entries(
        declared.workspace_root, declared.product_root
    ):
        if entry["evidence_id"] not in existing_ids:
            evidence_set.append(entry)
    return evidence_set


_PRODUCT_METADATA_MATERIALS = (
    ("package.json", "manifest"),
    ("plugin-src/manifest.json", "manifest"),
    ("spec/platforms/support-matrix.json", "platform_support"),
    (".skill-family-audit/governance/runtime-layout.json", "policy"),
)
_PLUGIN_SRC_MANIFEST = "plugin-src/manifest.json"


def _declared_skill_source_files(product_root: Path) -> list[str]:
    """Follow the selected product's existing entry and method declarations.

    sourceDir values are POSIX paths relative to plugin-src.  Absolute,
    traversing, missing, unreadable, or non-object declarations yield no
    skill files rather than a rewritten relative twin or a new discovery
    scan.
    """
    manifest_path = product_root / _PLUGIN_SRC_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return []
    try:
        receipt = foundation_read_file_strict(product_root, _PLUGIN_SRC_MANIFEST)
        declared = json.loads(receipt["content"])
    except (WorkflowError, json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(declared, dict):
        return []
    relatives: list[str] = []
    seen: set[str] = set()
    for collection in ("entrySkills", "internalSkills"):
        rows = declared.get(collection)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            source_dir = row.get("sourceDir")
            if not isinstance(source_dir, str) or not source_dir.strip():
                continue
            declared_dir = source_dir.strip()
            try:
                _validate_posix_relative_path(declared_dir, "manifest.sourceDir")
            except WorkflowError:
                continue
            relative = f"plugin-src/{declared_dir}/SKILL.md"
            if relative in seen:
                continue
            seen.add(relative)
            relatives.append(relative)
    return relatives


def _product_direct_evidence_entries(product_root: Path) -> list[dict[str, Any]]:
    """Bind selected-product metadata, entry/method text, and support matrix.

    Only existing regular files under the already selected product root are
    bound.  Kinds stay the declared evidence kinds; missing files are omitted
    rather than relabeled.
    """
    materials: list[tuple[str, str]] = list(_PRODUCT_METADATA_MATERIALS)
    for relative in _declared_skill_source_files(product_root):
        materials.append((relative, "source_file"))
    entries: list[dict[str, Any]] = []
    bound: set[str] = set()
    for relative, kind in materials:
        if relative in bound:
            continue
        path = product_root / relative
        if path.is_symlink() or not path.is_file():
            continue
        try:
            receipt = foundation_read_file_strict(product_root, relative)
        except WorkflowError:
            continue
        bound.add(relative)
        entries.append({
            "evidence_id": f"product-direct:{relative}",
            "kind": kind,
            "path": str(path),
            "sha256": receipt["sha256"],
        })
    return entries


def _derived_evidence_set(target: Path) -> list[dict[str, Any]]:
    """--evidence-set 缺省时从只读目标派生源码证据及 Task 前直接材料。

    派生只是诚实描述既有输入（目标字节即证据），不合成任何通过结论。
    """
    kind = "source_tree" if target.is_dir() else "source_file"
    digest_value = (
        foundation_tree_digest(target)
        if target.is_dir()
        else foundation_file_digest(target)
    )
    entries: list[dict[str, Any]] = [{
        "evidence_id": f"derived-{kind}:{digest_value}",
        "kind": kind,
        "path": str(target),
        "sha256": digest_value,
    }]
    declared = _declared_product_for_target(target)
    if declared is not None:
        entries.extend(_product_direct_evidence_entries(declared.product_root))
        if declared.workspace_root is not None:
            entries.extend(
                _workspace_evidence_selection_entries(
                    declared.workspace_root, declared.product_root
                )
            )
    seen_ids: set[str] = set()
    unique: list[dict[str, Any]] = []
    for entry in entries:
        evidence_id = entry["evidence_id"]
        if evidence_id in seen_ids:
            continue
        seen_ids.add(evidence_id)
        unique.append(entry)
    return unique


def _evidence_set_digest(entries: list[dict[str, Any]]) -> str:
    return foundation_document_digest({
        "evidence_set": sorted(entries, key=lambda item: item["evidence_id"])
    })


def _receipt_closure_observation(
    closure_root: Path,
    evidence_id: str,
    closure: dict[str, Any],
) -> dict[str, Any]:
    """重算收据声明路径的当前树资源闭包。

    声明路径必须通过收容校验；缺失或符号链接只记录为不可核验观察，
    由对应规则失败关闭判定，不在投影阶段吞掉整次审计。
    """
    paths = closure.get("paths")
    if (
        not isinstance(paths, list)
        or not paths
        or not all(isinstance(item, str) and item for item in paths)
        or len(paths) != len(set(paths))
    ):
        raise WorkflowError(
            "FROZEN_RECEIPT_PROJECTION_INVALID",
            f"receipt {evidence_id} resourceClosure.paths 必须是非空唯一路径字符串数组",
        )
    missing: list[str] = []
    symlinked: list[str] = []
    present: list[str] = []
    for relative in paths:
        _validate_posix_relative_path(
            relative,
            f"receipt {evidence_id} resourceClosure.paths",
            code="FROZEN_RECEIPT_PROJECTION_INVALID",
        )
        cursor = closure_root
        for part in Path(relative).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                break
        if cursor.is_symlink():
            symlinked.append(relative)
        elif not cursor.is_file():
            missing.append(relative)
        else:
            present.append(relative)
    observation: dict[str, Any] = {
        "paths": sorted(set(paths)),
        "declared_sha256": closure.get("sha256"),
    }
    if missing or symlinked:
        observation.update({
            "current_sha256": None,
            "missing_paths": sorted(set(missing)),
            "symlink_paths": sorted(set(symlinked)),
        })
    else:
        observation["current_sha256"] = str(
            foundation_resource_closure(closure_root, sorted(present))["digest"]
        )
    return observation


def frozen_receipt_projections(
    evidence_set: list[dict[str, Any]],
    target: Path | None,
) -> list[dict[str, Any]]:
    """冻结收据投影函数已停用。"""
    if target is None:
        return []
    return []


def _evidence_only_results(
    rules: list[dict[str, Any]],
    canonical_lineage: dict[str, dict[str, str]],
    provided_kinds: set[str],
) -> list[dict[str, Any]]:
    """只有非源码证据时逐规则返回未获证结果：审阅完成，但不合成 PASS。"""
    results: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("checkType") == "semantic":
            status = "REVIEW_REQUIRED"
            reason_code = "SEMANTIC_REVIEW_PENDING"
        else:
            status = "EVIDENCE_MISSING"
            reason_code = "NO_SOURCE_EVIDENCE"
        outcome = {
            "status": status,
            "evidence": {
                "reason_code": reason_code,
                "provided_evidence_kinds": sorted(provided_kinds),
            },
            "worker": "evidence-set-review",
        }
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
    return results


def _validate_method_parameters(
    parameters: dict[str, Any],
) -> None:
    """Draft 2020-12 校验 Audit 领域参数，含 professional_consumption。"""
    try:
        errors = _foundation_schema_errors(
            parameters,
            "https://contracts.skill-family.example/skill-family-audit/"
            "candidate/v2/methods/conformance/parameters.json",
        )
    except TypeError as exc:
        raise WorkflowError(
            "METHOD_PARAMETER_SCHEMA_INVALID",
            f"Conformance 领域参数不符合 parameterSchema: {exc}",
        ) from exc
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
        schema_steps = {"project-profile-schema", "overrides-policy"}
        digest_steps = {"adoption-pin-digests"}
        checks = {
            "spi_code": profile_result.get("code"),
            "steps": steps,
        }
        observed_steps = set(steps)
        schema_ok = complete and schema_steps <= observed_steps
        digest_ok = complete and digest_steps <= observed_steps
        status_ok = schema_ok and digest_ok
        return {
            "status": "PASS" if status_ok else "FAIL",
            "evidence": {"foundation_complete": complete, "checks": checks},
            "check_method_subresults": [
                {
                    "check_method": "schema_validation",
                    "status": "PASS" if schema_ok else "FAIL",
                    "observation_source": "foundation_profile_schema_and_policy_steps",
                    "evidence": {
                        "foundation_complete": complete,
                        "required_steps": sorted(schema_steps),
                        "observed_steps": steps,
                    },
                },
                {
                    "check_method": "digest_verification",
                    "status": "PASS" if digest_ok else "FAIL",
                    "observation_source": "foundation_profile_adoption_pin_digest_step",
                    "evidence": {
                        "foundation_complete": complete,
                        "required_steps": sorted(digest_steps),
                        "observed_steps": steps,
                    },
                },
            ],
        }
    if rule_id == "gmin:harness-authority-dependencies":
        profile_code = profile_result.get("code")
        profile_observed = profile_code not in (None, "PROJECT_PROFILE_MISSING")
        if not profile_observed:
            return {
                "status": "EVIDENCE_MISSING",
                "evidence": {
                    "reason": "foundation_profile_not_verified",
                    "inventory_verified": False,
                    "owner_count": 0,
                },
            }
        packages = (
            profile_document.get("adoption", {}).get("foundation_pin", {}).get("packages", {})
            if isinstance(profile_document, dict)
            else {}
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
            "check_method_subresults": [
                {
                    "check_method": "schema_validation",
                    "status": "NOT_APPLICABLE",
                    "observation_source": "deprecated_family_migration_contract",
                    "evidence": {"reason_code": "CONTRACT_DEPRECATED_D8"},
                },
                {
                    "check_method": "digest_verification",
                    "status": "NOT_APPLICABLE",
                    "observation_source": "deprecated_family_migration_contract",
                    "evidence": {"reason_code": "CONTRACT_DEPRECATED_D8"},
                },
            ],
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


GMIN_METHOD_ASSURANCE_FAMILY = "GMIN"


def _method_assurance_executor_family_of(rule_id: str) -> str:
    if rule_id.startswith("gmin:"):
        return GMIN_METHOD_ASSURANCE_FAMILY
    return executors.executor_family_of(rule_id)


def _gmin_method_assured_outcome(
    rule_id: str,
    scope: dict[str, Any],
    method_route: dict[str, Any],
) -> dict[str, Any]:
    """Bind the existing GMIN check result to its managed method route."""
    outcome = _gmin_static_outcome(rule_id, scope)
    outcome["executor_family"] = GMIN_METHOD_ASSURANCE_FAMILY
    outcome["check_method_subresults"] = executors._check_method_subresults(
        outcome, method_route
    )
    return outcome


def _method_assurance_gated_status(
    provisional_status: str,
    report: dict[str, Any],
) -> str:
    if (
        provisional_status == "SUCCEEDED"
        and not rule_method_assurance.trusted_observation_accepts_top_level(
            report
        )
    ):
        return "FAILED"
    return provisional_status


def _verified_static_evidence_refs(
    internal_semantic_reviews: dict[Any, Any] | None,
    internal_semantic_binding: dict[str, Any] | None,
    internal_review_request: dict[str, Any] | None,
    foundation_task_digest: str | None,
    canonical_id: str,
    revision_digest: str,
) -> list[dict[str, str]]:
    """取同一次 Task、同一条已终审规则的证据引用，只留四个定位字段。

    finalize_review 已经核对过请求、证据集和审阅规则集合。这里再要求
    binding 与当前请求的四份摘要一致，并且键精确为
    (canonical_id, revision_digest, semantic_review)。状态、理由和说明
    不进入机械执行器。任一引用形状不合法时整表失败关闭。
    """
    if (
        not isinstance(internal_semantic_reviews, dict)
        or not isinstance(internal_semantic_binding, dict)
        or not isinstance(internal_review_request, dict)
        or not isinstance(foundation_task_digest, str)
        or not isinstance(canonical_id, str)
        or not canonical_id
        or not isinstance(revision_digest, str)
        or not revision_digest
        or internal_semantic_binding.get("foundation_task_digest")
        != foundation_task_digest
        or internal_semantic_binding.get("review_request_digest")
        != internal_review_request.get("review_request_digest")
        or internal_semantic_binding.get("evidence_set_digest")
        != internal_review_request.get("evidence_set_digest")
        or internal_semantic_binding.get("reviewed_rule_set_digest")
        != internal_review_request.get("reviewed_rule_set_digest")
    ):
        return []
    review = internal_semantic_reviews.get(
        (canonical_id, revision_digest, "semantic_review")
    )
    refs = review.get("evidence_refs") if isinstance(review, dict) else None
    if not isinstance(refs, list):
        return []
    copied: list[dict[str, str]] = []
    for ref in refs:
        if not isinstance(ref, dict):
            return []
        row: dict[str, str] = {}
        for key in ("evidence_id", "sha256", "locator", "role"):
            value = ref.get(key)
            if not isinstance(value, str) or not value:
                return []
            row[key] = value
        if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            return []
        copied.append(row)
    return copied


def _static_evidence_ref_rows(refs: Any) -> list[dict[str, str]]:
    """执行上下文只保留四字段引用；多余键和坏引用都不能变成静态结论。"""
    if not isinstance(refs, (list, tuple)):
        return []
    rows: list[dict[str, str]] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        row: dict[str, str] = {}
        valid = True
        for key in ("evidence_id", "sha256", "locator", "role"):
            value = ref.get(key)
            if not isinstance(value, str) or not value:
                valid = False
                break
            row[key] = value
        if valid and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            rows.append(row)
    return rows


def _w2b1_executor_outcome(
    rule_id: str,
    scope: dict[str, Any],
    target: Path,
    args: argparse.Namespace,
    spec_index: dict[str, Any],
    manifest: dict[str, Any],
    method_route: dict[str, Any],
    frozen_receipts: list[dict[str, Any]] = (),
    evidence_set: list[dict[str, Any]] = (),
    expected_binding: dict[str, Any] | None = None,
    verified_evidence_refs: Any = (),
) -> dict[str, Any]:
    """Execute one W2-B1 first-tier mechanical rule through the executor package.

    The context carries only observable target facts and this run's invariants;
    executors never mutate the target. Declared-evidence shape failures are
    fail-closed as EVIDENCE_MISSING findings, never silent passes.
    """
    declared = scope.get("declared_product")
    product_root = (
        declared.get("product_root")
        if isinstance(declared, dict) and isinstance(declared.get("product_root"), str)
        else None
    )
    ctx: dict[str, Any] = {
        "target": target,
        "product_root": product_root or str(target),
        "target_type": args.target_type,
        "scope": scope,
        "manifest": manifest,
        "spec_index": spec_index,
        "remediation_patch_status": "unapplied",
        "method_route": method_route,
        # 只投影已验证 evidence-set 中与本规则有关的冻结 receipt 及其当前树
        # 闭包重算结果；不执行 scaffold、adopt-plan 或受检目标。
        "evidence_receipts": frozen_receipts,
        # Governance behavior verification consumes only the caller-validated
        # evidence-set entries.  It never reads scope-injected observations.
        "evidence_set": evidence_set,
        "gate_binding": expected_binding,
        "foundation_task_digest": getattr(args, "foundation_task_digest", None),
        "professional_consumption": getattr(args, "professional_consumption_document", None),
        # 来源只限已终审的同身份引用。scope 和 args 上的审阅原文不在这里读取。
        "verified_evidence_refs": _static_evidence_ref_rows(verified_evidence_refs),
    }
    installed = scope.get("installed_root")
    if isinstance(installed, str) and installed:
        installed_root = target / installed
        ctx["recompute_installed_digest"] = (
            lambda: foundation_candidate_payload_digest(installed_root)
        )
    try:
        outcome = executors.execute(rule_id, ctx)
        # 非机械半区由受管路由与 finalized review 通道承接，机械执行器自产的
        # 观测不得提升为结论（BIND-0558）。behavior_verification 已从当前权威的
        # check_methods 剥除，运行认证退出后其观测更不构成规则结论；保留该剔除
        # 边界，使任何执行器自产的非机械观测都不会污染聚合机械状态
        # （见 test_negative_commands_never_ran_fails 的反污染合同）。
        outcome.pop("behavior_verification_result", None)
        return outcome
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


def _combine_route_status(statuses: set[str]) -> str:
    """行级规则终态聚合阶梯（route method ledger + executor 行状态的并集判定）。

    FAIL 优先；任何 EVIDENCE_MISSING/NOT_RUN 混合 fail-closed 为
    EVIDENCE_MISSING；仅 {PASS}、仅 {NOT_APPLICABLE} 各自直通；聚合阶梯缺口
    闭合（sfa-814 Batch A 实证）：behavior_verification 是非机械半区
    （BIND-0558），受信 NOT_APPLICABLE 经 finalized review 通道合成并已投影到
    assurance 台账（TRUSTED_OBSERVED_NOT_PROVEN），故 {PASS, NOT_APPLICABLE}
    组合 = 机械 static PASS + 行为半区受信 NA，无 FAIL/EVIDENCE_MISSING/NOT_RUN；
    SPEC §5.1 关闭标准允许以可核对适用性事实判 NOT_APPLICABLE，该混合按
    NOT_APPLICABLE 收口。其余组合一律 REVIEW_REQUIRED，不做放宽。
    """
    if "FAIL" in statuses:
        return "FAIL"
    if statuses & {"EVIDENCE_MISSING", "NOT_RUN"}:
        return "EVIDENCE_MISSING"
    if statuses == {"PASS"}:
        return "PASS"
    if statuses == {"NOT_APPLICABLE"}:
        return "NOT_APPLICABLE"
    if statuses == {"PASS", "NOT_APPLICABLE"}:
        return "NOT_APPLICABLE"
    return "REVIEW_REQUIRED"


def run_workflow(args: argparse.Namespace) -> dict[str, Any]:
    """Execute the domain workflow.  Signature and raise/return contract are unchanged.

    Input, authority, and target-binding failures are tagged
    ``failure_stage=before_rule_selection`` on the raised WorkflowError.
    Callers such as ``main`` may project that into the mutually exclusive
    early-exit result; after rule scope is resolved the exception is not tagged
    and cannot select the early-exit branch.  Post-scope failures still raise,
    with a complete result envelope attached on ``exc.result`` when the selected
    scope is available.
    """
    stage = _WorkflowStage()
    try:
        return _execute_conformance_workflow(args, stage)
    except WorkflowError as exc:
        if not stage.rule_scope_resolved:
            exc.failure_stage = BEFORE_RULE_SELECTION
            if stage.evidence_set is not None:
                exc.evidence_set = stage.evidence_set
        else:
            _attach_after_scope_failure_result(exc, stage)
        raise
    except (OSError, ValueError) as exc:
        if stage.rule_scope_resolved:
            _attach_after_scope_failure_result(exc, stage)
            raise
        wrapped = WorkflowError(type(exc).__name__, str(exc))
        wrapped.failure_stage = BEFORE_RULE_SELECTION
        if stage.evidence_set is not None:
            wrapped.evidence_set = stage.evidence_set
        raise wrapped from exc


def _selected_product_root(target: Path | None) -> Path | None:
    if target is None:
        return None
    root = target if target.is_dir() else target.parent
    return declared_product_observation(root).product_root


def _discover_self_audit_spec_package(product_root: Path | None) -> str:
    if product_root is None:
        raise WorkflowError(
            "NO_ACTIVE_APPROVED_SPEC",
            "未找到自审规范包：没有已选产品根可供发现 spec/self-audit/；"
            "外部规范需要显式 --spec-package。"
            "不会从安装目录或当前目录猜测工作区，审计路径也不会运行目标生成器补齐。",
        )
    default_spec = checker.self_audit_spec_package_default(product_root)
    if default_spec is None:
        location = (
            str(product_root / "spec" / "self-audit")
            if product_root is not None
            else "已选产品根"
        )
        raise WorkflowError(
            "NO_ACTIVE_APPROVED_SPEC",
            "未找到自审规范包：自审只从已明确选中的产品根读取 "
            f"{location}；外部规范需要显式 --spec-package。"
            "不会从安装目录或当前目录猜测工作区，审计路径也不会运行目标生成器补齐。",
        )
    freshness_error = checker.verify_self_audit_freshness(default_spec)
    if freshness_error:
        raise WorkflowError(
            freshness_error,
            "自审规范包陈旧或非法，不能用于本次审计。"
            "原因由新鲜度检查给出；审计路径不会运行目标生成器补齐规范包。",
        )
    return str(default_spec)


def _execute_conformance_workflow(
    args: argparse.Namespace, stage: _WorkflowStage
) -> dict[str, Any]:
    if not args.run_id:
        raise WorkflowError(
            "WORKFLOW_ARGS_MISSING",
            "完整工作流需要 --run-id；规范包可省略（默认自审规范包）或显式 --spec-package",
        )
    _reset_run_fact_cache()
    target_hint: Path | None = None
    if args.target:
        try:
            target_hint = Path(args.target).resolve(strict=True)
        except OSError as exc:
            raise WorkflowError(
                "TARGET_NOT_FOUND",
                f"受检目标不存在: {args.target}",
            ) from exc
    spec_package = args.spec_package
    if not spec_package and target_hint is not None:
        spec_package = _discover_self_audit_spec_package(
            _selected_product_root(target_hint)
        )
    evidence_set: list[dict[str, Any]]
    if args.evidence_set:
        evidence_set = _load_evidence_set(Path(args.evidence_set))
    elif not args.target:
        raise WorkflowError(
            "WORKFLOW_ARGS_MISSING",
            "完整工作流需要 --evidence-set 或 --target 之一",
        )
    else:
        evidence_set = []
    target: Path | None
    evidence_only = False
    if not evidence_set:
        target = target_hint if target_hint is not None else Path(args.target).resolve(strict=True)
        evidence_set = _derived_evidence_set(target)
    else:
        source_trees = [
            item for item in evidence_set if item["kind"] == "source_tree"
        ]
        source_files = [
            item for item in evidence_set if item["kind"] == "source_file"
        ]
        if len(source_trees) > 1:
            raise WorkflowError(
                "EVIDENCE_SET_SOURCE_ROOT_AMBIGUOUS",
                "source_tree 证据必须唯一",
            )
        if source_trees:
            candidate: Path | None = Path(source_trees[0]["path"]).resolve(strict=True)
        elif len(source_files) == 1 and args.target_type == "single_skill":
            candidate = Path(source_files[0]["path"]).resolve(strict=True)
        else:
            candidate = None
        if candidate is not None:
            if args.target and Path(args.target).resolve() != candidate:
                raise WorkflowError(
                    "EVIDENCE_SET_TARGET_MISMATCH",
                    "target_project_path 与 source 证据路径不一致",
                )
            target = candidate
        else:
            target = None
            evidence_only = True
    evidence_set = _augment_evidence_set_with_workspace_selection(
        evidence_set, args.target
    )
    stage.evidence_set = evidence_set
    if not spec_package:
        spec_package = _discover_self_audit_spec_package(
            _selected_product_root(target)
        )
    evidence_set_digest = _evidence_set_digest(evidence_set)
    index, manifest, is_fixture, trust_policy = load_rules(
        Path(spec_package).resolve(strict=True), args.allow_test_fixture
    )
    (
        assurance_routes,
        assurance_trust_digest,
        assurance_canonical_projection,
        assurance_canonical_sha256,
    ) = method_assurance_routes()
    assurance_routing_receipt = foundation_read_file_strict(
        REFS,
        METHOD_ASSURANCE_TRUST_PROJECTION.name,
    )
    scope = target_scope(target, args.target_type) if not evidence_only else {}
    frozen_receipts = (
        frozen_receipt_projections(evidence_set, target)
        if target is not None
        else []
    )
    applicability = {
        "single_skill": {"all", "skill", "single_skill"},
        "family_source": {"all", "family", "family_source", "skill"},
        "release_artifact": {"all", "release", "release_artifact"},
        "project_adoption": {"all", "adoption", "project_adoption"},
    }[args.target_type]
    canonical_summary = canonical_rule_summary(
        trust_policy,
        assurance_canonical_projection,
        assurance_canonical_sha256,
    )
    canonical_applicability = canonical_rule_applicability(
        trust_policy,
        args.target_type,
        args.platform,
        assurance_canonical_projection,
        assurance_canonical_sha256,
    )
    category_rules = [
        item
        for category in manifest.get("ruleCategories", [])
        for item in category.get("rules", [])
        if item.get("applicability") in applicability
    ]
    family_source_blockers: list[dict[str, str]] = []
    if args.target_type == "family_source":
        terminal_rules, family_source_blockers = (
            _family_source_terminal_execution_plan(
                manifest, canonical_applicability
            )
        )
    elif args.target_type == "project_adoption":
        terminal_rules = [
            rule
            for rule in manifest.get("terminalRuleImplementations", [])
            if rule.get("applicability") in applicability
        ]
    else:
        terminal_rules = []
    rules = category_rules + terminal_rules
    canonical_lineage = _validated_baseline_lineage(
        manifest, rules, canonical_applicability
    )
    if args.target_type == "project_adoption":
        # Validate before selecting carriers: missing or mismatched lineage
        # for an executable rule must still fail, not disappear by filtering.
        terminal_rules = [
            rule for rule in terminal_rules
            if rule["ruleId"] in canonical_lineage
        ]
        rules = category_rules + terminal_rules
    all_rules = list(rules)
    semantic_group_registry, semantic_group_registry_digest = (
        load_semantic_group_registry()
    )
    profile_plan = _profile_execution_plan(
        args,
        all_rules,
        canonical_lineage,
        canonical_applicability,
        semantic_group_registry,
        semantic_group_registry_digest,
    )
    stage.rule_scope_resolved = True
    _record_after_scope(stage, args=args, profile_plan=profile_plan)
    retained_trial_ids = _retained_targeted_trial_ids(
        profile_plan, assurance_canonical_projection
    )
    profile_plan["retained_trial_rule_ids"] = retained_trial_ids
    if retained_trial_ids:
        selected_groups = set(profile_plan["selected_semantic_group_ids"])
        selected_groups.update(
            group_id
            for group_id in profile_plan["requested_semantic_group_ids"]
            if set(profile_plan["group_members"][group_id]).intersection(
                retained_trial_ids
            )
        )
        profile_plan["selected_semantic_group_ids"] = sorted(selected_groups)
    selected_canonical_ids = set(profile_plan["selected_rule_ids"])
    auxiliary_rule_ids = set(profile_plan["auxiliary_rule_ids"])
    rules = [
        rule
        for rule in all_rules
        if rule["ruleId"] in auxiliary_rule_ids
        or canonical_lineage[rule["ruleId"]]["canonical_id"]
        in selected_canonical_ids
    ]
    rule_set_digest = bound_rule_set_digest(
        all_rules, canonical_applicability, canonical_lineage
    )
    parameters = {
        "evidence_set": evidence_set,
        "scope_selector": {
            "single_skill": "skill",
            "family_source": "plugin",
            "project_adoption": "plugin",
            "release_artifact": "release",
        }[args.target_type],
    }
    if args.target is not None:
        parameters["target_project_path"] = args.target
    if getattr(args, "execution_profile", None) is not None:
        parameters["execution_profile"] = args.execution_profile
    if getattr(args, "semantic_group_ids", None) is not None:
        parameters["semantic_group_ids"] = args.semantic_group_ids
    if getattr(args, "canonical_rule_ids", None) is not None:
        parameters["canonical_rule_ids"] = args.canonical_rule_ids
    professional_consumption = _load_professional_consumption(args)
    if professional_consumption is not None:
        parameters["professional_consumption"] = professional_consumption
    _validate_method_parameters(parameters)
    if professional_consumption is not None:
        professional_consumption = _consume_professional_inputs(professional_consumption)
        args.professional_consumption_document = professional_consumption
    semantic_target_digest = (
        evidence_set_digest
        if evidence_only or args.target_type == "project_adoption"
        else foundation_target_content_digest(target, args.target_type)
    )
    semantic_request_digest = foundation_document_digest({
        "target_digest": semantic_target_digest,
        "target_type": args.target_type,
        "rule_set_digest": rule_set_digest,
    })
    _record_after_scope(
        stage,
        profile_plan=profile_plan,
        rule_set_digest=rule_set_digest,
        semantic_target_digest=semantic_target_digest,
        semantic_request_digest=semantic_request_digest,
    )
    all_semantic_descriptors = semantic_review.bound_rule_descriptors(
        rules,
        canonical_lineage,
        assurance_canonical_projection.get("rules", []),
    )
    retained_descriptors = semantic_review.retained_trial_descriptors(
        assurance_canonical_projection.get("rules", []),
        profile_plan.get("retained_trial_rule_ids", []),
    )
    all_semantic_descriptors.extend(retained_descriptors)
    all_semantic_descriptors.sort(
        key=lambda row: (row["canonical_id"], row["check_method"])
    )
    selected_nonmechanical_obligations = (
        _selected_nonmechanical_obligations(
            profile_plan,
            assurance_canonical_projection.get("rules", []),
        )
    )
    internal_review_request: dict[str, Any] | None = None
    foundation_task_digest = getattr(args, "foundation_task_digest", None)
    if getattr(args, "semantic_review_preflight", False) and (
        not isinstance(foundation_task_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", foundation_task_digest)
    ):
        return {
            "semantic_review_request": {
                "kind": "skill-family-audit.semantic-review-request",
                "schema_version": "1.0.0",
                "producer_method_id": semantic_review.METHOD_ID,
                "cognitive_independence": semantic_review.COGNITIVE_INDEPENDENCE,
                "rules": [],
                "reason_code": (
                    "SEMANTIC_FOUNDATION_TASK_MISSING"
                    if all_semantic_descriptors
                    else "NO_ACTIVE_BOUND_SEMANTIC_RULES"
                ),
            },
            "semantic_context_plan": {
                "semantic_input_budget": SEMANTIC_INPUT_BUDGET,
                "contexts": [],
                "blocked_rule_ids": [],
                "estimated_input_tokens": 0,
            },
        }
    if (
        not isinstance(foundation_task_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", foundation_task_digest)
    ):
        raise WorkflowError(
            "FOUNDATION_TASK_DIGEST_MISSING",
            "完整 conformance 执行必须绑定由 Quickstart 创建并计算的 Foundation Task digest",
        )
    semantic_profile_preflight = _semantic_profile_preflight(
        profile_plan,
        semantic_group_registry,
        canonical_applicability,
        assurance_canonical_projection.get("rules", []),
        evidence_set,
        foundation_task_digest=foundation_task_digest,
        evidence_set_digest=evidence_set_digest,
    )
    semantic_descriptors = _semantic_review_candidate_descriptors(
        profile_plan,
        semantic_profile_preflight,
        all_semantic_descriptors,
        evidence_set,
        canonical_applicability,
    )
    semantic_missing_evidence_roles = (
        _selected_semantic_missing_evidence_roles(
            profile_plan,
            semantic_profile_preflight,
            all_semantic_descriptors,
            evidence_set,
            canonical_applicability,
        )
    )
    _record_after_scope(
        stage,
        semantic_preflight=semantic_profile_preflight,
        semantic_rules_skipped_missing_evidence_count=len(
            semantic_missing_evidence_roles
        ),
    )
    if semantic_descriptors:
        try:
            internal_review_request = semantic_review.build_review_request(
                foundation_task_digest=foundation_task_digest,
                evidence_set_digest=evidence_set_digest,
                rule_set_digest=rule_set_digest,
                descriptors=semantic_descriptors,
                evidence_set=evidence_set,
                digest_document=foundation_document_digest,
            )
        except semantic_review.SemanticReviewError as exc:
            raise WorkflowError(exc.code, str(exc)) from exc
    scheduled_review_identities = {
        semantic_review.review_identity(row)
        for row in (internal_review_request or {}).get("rules", [])
    }
    injected_spi_root = getattr(args, "foundation_profile_spi_root", None)
    if injected_spi_root is not None:
        injected_spi_root = Path(injected_spi_root)
    semantic_model_plan = _build_semantic_context_plan(
        profile_plan,
        semantic_group_registry,
        semantic_profile_preflight,
        internal_review_request,
        target_type=args.target_type,
        platform=args.platform,
        target_digest=semantic_target_digest,
        profile_spi_root=injected_spi_root,
    )
    execution_plan_event = conformance_human_route._build_execution_plan_event(
        profile_plan,
        semantic_profile_preflight,
        semantic_model_plan,
        semantic_rules_skipped_missing_evidence_count=len(
            semantic_missing_evidence_roles
        ),
        target_digest=semantic_target_digest,
        selection_reason=getattr(
            args, "profile_selection_reason", None
        ) or "domain_default_full",
        routing_file_digest=assurance_routing_receipt["sha256"],
        trust_projection_digest=assurance_trust_digest,
    )
    print(
        "SFA_EXECUTION_PLAN "
        + json.dumps(execution_plan_event, ensure_ascii=False, sort_keys=True),
        file=sys.stderr,
        flush=True,
    )
    if getattr(args, "semantic_review_preflight", False):
        return {
            "semantic_review_request": internal_review_request
            or {
                "kind": "skill-family-audit.semantic-review-request",
                "schema_version": "1.0.0",
                "producer_method_id": semantic_review.METHOD_ID,
                "cognitive_independence": semantic_review.COGNITIVE_INDEPENDENCE,
                "rules": [],
                "reason_code": "NO_REVIEW_READY_RULES",
            },
            "semantic_context_plan": semantic_model_plan,
        }
    reviews, external_semantic_reviews = semantic_reviews(
        Path(args.semantic_result) if args.semantic_result else None,
        rules,
        semantic_request_digest,
        target,
        args.target_type,
    )
    internal_semantic_reviews: dict[tuple[str, str, str], dict[str, Any]] = {}
    internal_semantic_binding: dict[str, Any] | None = None
    internal_payload = getattr(args, "internal_semantic_review", None)
    internal_context_results = getattr(
        args, "internal_semantic_context_results", None
    )
    semantic_context_metrics = {
        "semantic_model_call_count": 0,
        "semantic_context_count": 0,
        "estimated_input_tokens": 0,
        "semantic_rules_sent_to_model_count": 0,
    }
    _record_after_scope(stage, semantic_context_metrics=semantic_context_metrics)
    if internal_payload is not None and internal_context_results is not None:
        raise WorkflowError(
            "SEMANTIC_REVIEW_INPUT_AMBIGUOUS",
            "单体 internal review 与 context results 不能同时提供",
        )
    if internal_context_results is not None:
        if internal_review_request is None:
            raise WorkflowError(
                "SEMANTIC_REVIEW_UNEXPECTED",
                "当前适用规则没有可接受 context result 的精确 binding",
            )
        if semantic_model_plan["blocked_rule_ids"]:
            raise WorkflowError(
                "SEMANTIC_CONTEXT_BUDGET_EXCEEDED",
                "单条规则上下文仍超过预算: "
                + ", ".join(semantic_model_plan["blocked_rule_ids"]),
            )
        internal_payload, semantic_context_metrics = (
            _merge_semantic_context_results(
                internal_review_request,
                semantic_model_plan,
                internal_context_results,
            )
        )
        _record_after_scope(
            stage, semantic_context_metrics=semantic_context_metrics
        )
    if internal_payload is not None:
        if internal_review_request is None:
            raise WorkflowError(
                "SEMANTIC_REVIEW_UNEXPECTED",
                "当前适用规则没有可接受内部审阅的精确 binding",
            )
        if internal_context_results is None:
            # Bound v2 payload proves reviews were consumed, not how many
            # host model calls produced them.  Do not infer call counts
            # from review or result cardinality.
            semantic_context_metrics = {
                "semantic_model_call_count": None,
                "semantic_context_count": semantic_context_metrics[
                    "semantic_context_count"
                ],
                "estimated_input_tokens": semantic_context_metrics[
                    "estimated_input_tokens"
                ],
                "semantic_rules_sent_to_model_count": None,
            }
            _record_after_scope(
                stage, semantic_context_metrics=semantic_context_metrics
            )
        validation_errors = _semantic_schema_errors(internal_payload)
        if validation_errors:
            raise WorkflowError(
                "SEMANTIC_REVIEW_RESULT_INVALID",
                "; ".join(validation_errors),
            )
        try:
            internal_semantic_reviews, internal_semantic_binding = (
                semantic_review.finalize_review(
                    internal_review_request,
                    internal_payload,
                    digest_document=foundation_document_digest,
                )
            )
        except semantic_review.SemanticReviewError as exc:
            raise WorkflowError(exc.code, str(exc)) from exc
    retained_trial_results: list[dict[str, Any]] = []
    canonical_by_id = {
        row["canonical_id"]: row
        for row in assurance_canonical_projection.get("rules", [])
        if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
    }
    preflight_by_id = {
        row["canonical_id"]: row
        for row in semantic_profile_preflight.get("records", [])
    }
    applicability_by_id = {
        row["canonical_id"]: row
        for row in canonical_applicability.get("rules", [])
    }
    retained_by_id: dict[str, list[dict[str, Any]]] = {}
    for descriptor in retained_descriptors:
        retained_by_id.setdefault(descriptor["canonical_id"], []).append(
            descriptor
        )
    for canonical_id, descriptors in sorted(retained_by_id.items()):
        revision_digest = descriptors[0]["canonical_revision_digest"]
        methods = selected_nonmechanical_obligations.get(
            (canonical_id, revision_digest), []
        )
        preflight_row = preflight_by_id.get(canonical_id)
        if preflight_row is None:
            scope_row = applicability_by_id.get(canonical_id, {})
            preflight_row = {
                "applicability_preflight": scope_row.get("scope_disposition", "UNDETERMINED"),
                "citable_scope_facts": scope_row.get("citable_scope_facts", []),
            }
        missing_roles = semantic_missing_evidence_roles.get(canonical_id, [])
        method_statuses = _nonmechanical_obligation_statuses(
            canonical_id,
            revision_digest,
            methods,
            internal_semantic_reviews,
            scheduled_review_identities,
            missing_roles,
        )
        mechanical_gap_statuses = _retained_mechanical_gap_statuses(
            canonical_by_id[canonical_id]
        )
        # A retained mixed rule has no trusted mechanical executor.  Keep each
        # missing mechanical method in the same rule aggregation so a semantic
        # PASS or NOT_APPLICABLE cannot hide the unimplemented half.
        method_statuses.update(mechanical_gap_statuses)
        status = _combine_route_status(set(method_statuses.values()))
        semantic_internal = internal_semantic_reviews.get((
            canonical_id,
            revision_digest,
            "semantic_review",
        ))
        evidence = (
            semantic_internal["evidence_refs"]
            if semantic_internal is not None
            else _descriptor_evidence_refs(descriptors[0], evidence_set)
        )
        worker = (
            "conformance-skill-semantic-review"
            if any(
                identity[0] == canonical_id and identity[1] == revision_digest
                for identity in internal_semantic_reviews
            )
            else "conformance-skill-semantic-trial"
        )
        reason_code = (
            "CANONICAL_SCOPE_NOT_APPLICABLE"
            if status == "NOT_APPLICABLE"
            else "REQUIRED_EVIDENCE_ROLE_MISSING"
            if missing_roles
            else "RETAINED_MECHANICAL_METHOD_UNIMPLEMENTED"
            if mechanical_gap_statuses
            else "SEMANTIC_REVIEW_PENDING"
        )
        row = {
            "reason_code": reason_code,
            "missing_evidence_roles": missing_roles,
            "preflight": preflight_row,
        }
        if semantic_internal is not None:
            row["semantic_review"] = semantic_internal
        retained_trial_results.append({
            "rule_id": canonical_id,
            "rule_revision_digest": revision_digest,
            "canonical_id": canonical_id,
            "canonical_only": True,
            "retained_trial": True,
            "status": status,
            "evidence": evidence,
            "worker": worker,
            **row,
        })
    if evidence_only:
        results = _evidence_only_results(
            rules,
            canonical_lineage,
            {item["kind"] for item in evidence_set},
        )
        for result in results:
            lineage = result.get("canonical_lineage", {})
            internal = internal_semantic_reviews.get((
                lineage.get("canonical_id"),
                lineage.get("revision_digest"),
                "semantic_review",
            ))
            if internal is None or next(
                rule.get("checkType") for rule in rules
                if rule["ruleId"] == result["rule_id"]
            ) != "semantic":
                continue
            result.update({
                "status": internal["status"],
                "evidence": internal["evidence_refs"],
                "worker": "conformance-skill-semantic-review",
                "semantic_review": internal,
            })
    else:
        scan = checker._scan(target if target.is_dir() else target.parent)
        results = []
    results.extend(retained_trial_results)
    results.extend(_full_canonical_only_scope_results(
        profile_plan, canonical_applicability
    ))
    # 证据受限审阅不进入源码扫描循环（results 已由 _evidence_only_results 填充）。
    for rule in rules if not evidence_only else []:
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
            lineage = canonical_lineage.get(rule["ruleId"], {})
            internal = internal_semantic_reviews.get((
                lineage.get("canonical_id"),
                lineage.get("canonical_revision_digest"),
                "semantic_review",
            ))
            if internal is not None:
                outcome = {
                    "status": internal["status"],
                    "evidence": internal["evidence_refs"],
                    "worker": "conformance-skill-semantic-review",
                    "semantic_review": internal,
                }
            else:
                # 外部结果始终只是待审证据；调用方 PASS 不能形成规则 PASS。
                review = reviews[rule["ruleId"]]
                outcome = {
                    "status": (
                        "EVIDENCE_MISSING"
                        if review["status"] == "EVIDENCE_MISSING"
                        else "REVIEW_REQUIRED"
                    ),
                    "evidence": review["evidence"],
                    "worker": "external-semantic-review-pending",
                }
                if "reason" in review:
                    outcome["pending_review"] = {
                        "submitted_status": review["status"],
                        "reason": review["reason"],
                    }
        elif rule.get("checkType") == "static":
            # GMIN 终态家族显式承接的静态规则：路由表以 executor_baseline_rule_id
            # 声明其执行器载体，未实现的分支一律 GMIN_RULE_UNIMPLEMENTED 失败
            # 关闭，不存在静默回退。三条 ACTIVE_MECHANICAL 规则
            # （SFA-HARNESS-002 → gmin:harness-authority-dependencies、
            # SFA-MIGRATE-001 → gmin:legacy-risk-plan、
            # SFA-MIGRATE-021 → gmin:family-migration-checklist）即由此承接，
            # 不登记在 w2b1/w2b2/w2b3 注册表中。
            if rule["ruleId"].startswith("gmin:"):
                lineage = canonical_lineage.get(rule["ruleId"])
                if lineage is None:
                    raise WorkflowError(
                        "METHOD_ASSURANCE_ROUTE_IDENTITY_MISSING",
                        f"{rule['ruleId']} lacks canonical lineage",
                    )
                route_key = (
                    lineage["canonical_id"],
                    lineage["canonical_revision_digest"],
                )
                method_route = assurance_routes.get(route_key)
                if method_route is None:
                    raise WorkflowError(
                        "METHOD_ASSURANCE_ROUTE_IDENTITY_MISSING",
                        f"{rule['ruleId']} lacks a managed method route",
                    )
                outcome = _gmin_method_assured_outcome(
                    rule["ruleId"], scope, method_route
                )
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
                lineage = canonical_lineage.get(rule["ruleId"])
                if lineage is None:
                    raise WorkflowError(
                        "METHOD_ASSURANCE_ROUTE_IDENTITY_MISSING",
                        f"{rule['ruleId']} lacks canonical lineage",
                    )
                route_key = (
                    lineage["canonical_id"],
                    lineage["canonical_revision_digest"],
                )
                method_route = assurance_routes.get(route_key)
                if method_route is None:
                    raise WorkflowError(
                        "METHOD_ASSURANCE_ROUTE_IDENTITY_MISSING",
                        f"{rule['ruleId']} lacks a managed method route",
                    )
                outcome = _w2b1_executor_outcome(
                    rule["ruleId"],
                    scope,
                    target,
                    args,
                    index,
                    manifest,
                    method_route,
                    frozen_receipts,
                    evidence_set,
                    {
                        "target_digest": foundation_target_content_digest(
                            target, args.target_type
                        ),
                        "platform": args.platform,
                        "target_version": (
                            scope.get("plugin_project", {})
                            .get("plugin", {})
                            .get("version")
                            if isinstance(scope.get("plugin_project"), dict)
                            and isinstance(scope["plugin_project"].get("plugin"), dict)
                            else None
                        ),
                    },
                    verified_evidence_refs=_verified_static_evidence_refs(
                        internal_semantic_reviews,
                        internal_semantic_binding,
                        internal_review_request,
                        foundation_task_digest,
                        lineage["canonical_id"],
                        lineage["canonical_revision_digest"],
                    ),
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
                "scope:project-adoption-present": ("project_adoption_evidence",),
            }.get(rule["ruleId"])
            if scope_rule:
                all_present = all(scope.get(key) for key in scope_rule)
                evidence = {key: scope.get(key, []) for key in scope_rule}
                # scope 只回答“目标或冻结证据是否足以审阅”，不回答“目标是
                # 否已经采用 Foundation”。profile 缺失/无效/符号链接与豁免
                # 合同的真实性由对应 canonical 规则逐项判定，不得在规则执行
                # 前把审计整体拦成 BLOCKED。
                if rule["ruleId"] == "scope:project-adoption-present":
                    all_present = (
                        scope.get("project_adoption_evidence", {})
                        .get("reviewable") is True
                    )
                    foundation_profile = scope.get("foundation_profile", {})
                    foundation_complete = (
                        foundation_profile.get("foundation_profile_complete") is True
                    )
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
    for result in results:
        lineage = result.get("canonical_lineage") or {}
        missing_roles = semantic_missing_evidence_roles.get(
            lineage.get("canonical_id")
        )
        if missing_roles and result.get("status") in {
            "EVIDENCE_MISSING", "REVIEW_REQUIRED"
        }:
            result["missing_evidence_roles"] = missing_roles
    method_assurance_identity = {
        "run_id": args.run_id,
        "target_digest": semantic_target_digest,
        "target_type": args.target_type,
        "platform": args.platform,
        "rule_set_digest": rule_set_digest,
        "semantic_request_digest": semantic_request_digest,
        "trust_projection_digest": assurance_trust_digest,
    }
    trusted_results = [
        item
        for item in results
        if item.get("worker") in {
            "deterministic-first-tier-executor",
            "deterministic-terminal-governance",
        }
        and isinstance(item.get("canonical_lineage"), dict)
        and isinstance(item.get("check_method_subresults"), list)
    ]
    trusted_result_digests = foundation_document_digests(trusted_results)
    trusted_result_digest_cache = {
        id(item): (item, result_digest)
        for item, result_digest in zip(trusted_results, trusted_result_digests)
    }

    def trusted_result_digest(value: Any) -> str:
        cached = trusted_result_digest_cache.get(id(value))
        if cached is not None and cached[0] is value:
            return cached[1]
        return foundation_document_digest(value)

    trusted_observation = {
        "kind": "skill-family-audit.conformance-method-observation",
        "schema_version": "1.0.0",
        **method_assurance_identity,
        "rule_results": [
            {
                "canonical_id": item["canonical_lineage"]["canonical_id"],
                "revision_digest": item["canonical_lineage"]["revision_digest"],
                "baseline_rule_id": item["rule_id"],
                "executor_family": item["executor_family"],
                "result_digest": result_digest,
                "result_payload": item,
                "check_method_subresults": item["check_method_subresults"],
            }
            for item, result_digest in zip(
                trusted_results, trusted_result_digests
            )
        ],
    }
    method_ledger = rule_method_assurance.assurance_report(
        assurance_canonical_projection,
        None,
        foundation_document_digest,
        lifecycle_statuses={"ACTIVE_MECHANICAL", "ACTIVE_SEMANTIC"},
    )
    # The method ledger covers managed static executor routes only.  Pure
    # semantic terminal rules are consumed directly by the rule-level result
    # path above and must not be presented to the static-route ledger as an
    # unknown identity.
    method_assurance_semantic_reviews = {
            identity: review
            for identity, review in internal_semantic_reviews.items()
            if (
                identity[0], identity[1],
            ) in assurance_routes
    }
    method_assurance = (
        rule_method_assurance._project_trusted_conformance_observation(
            method_ledger,
            trusted_observation,
            method_assurance_identity,
            assurance_routes,
            _method_assurance_executor_family_of,
            trusted_result_digest,
            finalized_semantic_reviews=method_assurance_semantic_reviews,
        )
    )
    _record_after_scope(stage, method_assurance=method_assurance)
    method_records = {
        rule_method_assurance.obligation_identity(record): record
        for record in method_assurance["records"]
    }
    # Keep the raw executor payloads held by trusted_observation intact.
    # Only the rule-level view is derived from the combined method ledger.
    combined_results = []
    for item in results:
        lineage = item.get("canonical_lineage", {})
        canonical_identity = (
            lineage.get("canonical_id"), lineage.get("revision_digest")
        )
        route = assurance_routes.get(canonical_identity)
        review_methods = sorted(
            set(route.get("check_methods", []))
            & set(rule_method_assurance.NON_MECHANICAL_CHECK_METHODS)
        ) if route is not None else []
        selected_methods = selected_nonmechanical_obligations.get(
            canonical_identity, []
        )
        if route is not None and review_methods:
            statuses = {item["status"]}
            statuses.update(
                method_records.get((
                    lineage["canonical_id"], lineage["revision_digest"], method,
                ), {}).get("trusted_observation", {}).get("status", "NOT_RUN")
                for method in route["check_methods"]
            )
        elif selected_methods:
            statuses = set(_nonmechanical_obligation_statuses(
                lineage["canonical_id"],
                lineage["revision_digest"],
                selected_methods,
                internal_semantic_reviews,
                scheduled_review_identities,
                semantic_missing_evidence_roles.get(
                    lineage["canonical_id"], []
                ),
            ).values())
        else:
            combined_results.append(_present_professional_finding(item))
            continue
        combined_status = _combine_route_status(statuses)
        combined = {**item, "status": combined_status}
        internal = internal_semantic_reviews.get((
            lineage["canonical_id"],
            lineage["revision_digest"],
            "semantic_review",
        ))
        if internal is not None:
            combined["semantic_review"] = internal
        combined_results.append(_present_professional_finding(combined))
    results = combined_results + _profile_not_run_results(
        profile_plan,
        canonical_lineage,
    )
    results.sort(
        key=lambda item: item.get("canonical_lineage", {}).get(
            "canonical_id", item["rule_id"]
        )
    )
    try:
        canonical_results = conformance_profiles.project_in_scope_rule_results(
            profile_plan["in_scope_rule_ids"], results
        )
    except ValueError as exc:
        raise WorkflowError("CONFORMANCE_PROFILE_RESULT_INVALID", str(exc)) from exc
    _record_after_scope(stage, canonical_results=canonical_results)
    failed = [
        item
        for item in canonical_results
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
        "target_digest": (
            evidence_set_digest
            if evidence_only
            else foundation_tree_digest(target if target.is_dir() else target.parent)
        ),
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
        canonical_applicability, canonical_lineage, results, method_assurance
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
        and not evidence_only
        and scope.get("foundation_profile", {}).get(
            "foundation_profile_complete"
        ) is True
        else {}
    )
    canonical_coverage_complete = canonical_coverage["complete"]
    canonical_coverage_blocked = (
        canonical_coverage["required_executable_rule_count"] > 0
        and not canonical_coverage_complete
    )
    status_by_canonical = {
        (
            item["canonical_lineage"]["canonical_id"]
            if isinstance(item.get("canonical_lineage"), dict)
            else item["canonical_id"]
        ): item["status"]
        for item in canonical_results
    }
    try:
        coverage_core = conformance_profiles.derive_coverage(
            profile_plan["in_scope_rule_ids"],
            profile_plan["selected_rule_ids"],
            status_by_canonical,
        )
        status = conformance_profiles.derive_conformance_status(
            profile_plan["execution_profile"],
            profile_plan["selected_rule_ids"],
            profile_plan["in_scope_rule_ids"],
            status_by_canonical,
        )
    except ValueError as exc:
        raise WorkflowError("CONFORMANCE_PROFILE_RESULT_INVALID", str(exc)) from exc
    if profile_plan["execution_profile"] == "targeted" and retained_trial_results:
        # Targeted retained trials remain outside the executable coverage
        # counts, but their honest outcome still gates the run conclusion.
        trial_statuses = {row["status"] for row in retained_trial_results}
        if "FAIL" in trial_statuses:
            status = "FAILED"
        elif (
            status != "FAILED"
            and trial_statuses & {"EVIDENCE_MISSING", "REVIEW_REQUIRED"}
        ):
            status = "BLOCKED"
    # The profile coverage table describes only the canonical rules carried by
    # the current spec package.  A full run still compares those results with
    # every executable canonical rule in the authority projection.  A coverage
    # gap cannot be promoted to a proven violation: keep an existing FAIL, but
    # otherwise report BLOCKED until the missing assurance is closed.  Partial
    # profiles deliberately omit canonical rules and retain their own
    # PARTIAL/BLOCKED status contract.
    if (
        profile_plan["execution_profile"] == "full"
        and canonical_coverage_blocked
        and status != "FAILED"
    ):
        status = "BLOCKED"

    def result_identity_rows(canonical_ids: list[str]) -> list[dict[str, str]]:
        return [
            {
                "canonical_id": canonical_id,
                "revision_digest": profile_plan["revision_by_canonical"][
                    canonical_id
                ],
            }
            for canonical_id in sorted(canonical_ids)
        ]

    coverage = {
        "in_scope_rule_set_digest": profile_plan["in_scope_rule_set_digest"],
        "in_scope_count": coverage_core["in_scope_count"],
        "selected_rule_set_digest": profile_plan["selected_rule_set_digest"],
        "selected_count": coverage_core["selected_count"],
        "attempted_rule_set_digest": foundation_document_digest(
            result_identity_rows(coverage_core["attempted"])
        ),
        "attempted_count": coverage_core["attempted_count"],
        "not_run_count": coverage_core["not_run_count"],
        "coverage_complete": coverage_core["coverage_complete"],
        "conclusion_complete": coverage_core["conclusion_complete"],
        "requested_semantic_group_ids": profile_plan[
            "requested_semantic_group_ids"
        ],
        "requested_canonical_rule_ids": profile_plan[
            "requested_canonical_rule_ids"
        ],
        "selected_semantic_group_ids": profile_plan[
            "selected_semantic_group_ids"
        ],
        "selected_deterministic_rule_count": profile_plan[
            "selected_deterministic_rule_count"
        ],
        "semantic_group_registry_digest": profile_plan[
            "semantic_group_registry_digest"
        ],
    }
    execution_metrics = {
        **semantic_context_metrics,
        "semantic_rules_skipped_missing_evidence_count": len(
            semantic_missing_evidence_roles
        ),
    }
    domain = {
        "schema_version": "1.0.0",
        "run_id": args.run_id,
        "target_type": args.target_type,
        "target_digest": semantic_target_digest,
        "platform": args.platform,
        "rule_set_digest": rule_set_digest,
        "semantic_request_digest": semantic_request_digest,
        "status": status,
        "execution_profile": profile_plan["execution_profile"],
        "coverage": coverage,
        "semantic_preflight": _semantic_profile_preflight_result(
            semantic_profile_preflight
        ),
        "execution_metrics": execution_metrics,
        "rule_results": canonical_results,
        "external_semantic_reviews": external_semantic_reviews,
        "semantic_review_binding": internal_semantic_binding,
        "canonical_rule_summary": canonical_summary,
        "canonical_rule_applicability": {
            "document": canonical_applicability,
            "content_digest": foundation_document_digest(
                canonical_applicability
            ),
            "applicability_digest": canonical_applicability[
                "applicability_digest"
            ],
            "counts": canonical_applicability["counts"],
        },
        "baseline_rule_set": {
            "kind": "implementation-baseline",
            "canonical_rule_ids": sorted(manifest.get("canonicalRuleIds", [])),
            "executed_rule_count": sum(
                1
                for canonical_id in profile_plan["baseline_in_scope_rule_ids"]
                if status_by_canonical.get(canonical_id) != "NOT_RUN"
            ),
            **(
                {"execution_blockers": family_source_blockers}
                if args.target_type == "family_source"
                else {}
            ),
            "status": (
                "NON_PASSING"
                if canonical_coverage_blocked
                else "OBSERVED"
            ),
        },
        "canonical_executable_coverage": canonical_coverage,
        "canonical_guidance": canonical_guidance,
    }
    if professional_consumption is not None:
        domain["professional_consumption"] = professional_consumption
    domain["method_assurance"] = method_assurance
    domain["status"] = _method_assurance_gated_status(
        domain["status"], domain["method_assurance"]
    )
    if domain["status"] != status:
        domain["baseline_rule_set"]["status"] = "NON_PASSING"
    credibility = (
        "self_reported" if is_fixture or index.get("selfAudit") is True else "verified"
    )
    security_observation = _bounded_security_observation(
        target, assurance_canonical_projection
    )
    results.extend({
        "kind": "skill-family-audit.safe-sensitive-finding",
        **finding,
    } for finding in security_observation["findings"])
    evidence = [{
        "kind": "caller-evidence",
        "evidence_id": item["evidence_id"],
        "path": item["path"],
        "sha256": item["sha256"],
        "source": "caller-evidence-set",
        "evidence_set_digest": evidence_set_digest,
        "credibility": credibility,
    } for item in evidence_set]
    evidence.append({
        "kind": "skill-family-audit.bounded-material-security-observation",
        "evidence_id": "audit-bounded-material-security-observation",
        "path": str(target),
        "sha256": semantic_target_digest,
        "source": "conformance-check-existing-target-enumeration",
        "canonical_rule_ids": [
            "SFA-DATASEC-002",
            "SFA-EVIDENCESEC-001",
            "SFA-SECRET-003",
        ],
        "observation": security_observation,
        "credibility": credibility,
    })
    result = {
        "conformance_result": domain,
        "rule_findings": results,
        "evidence_list": evidence,
        "remediation_plan": remediation["items"],
    }
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument(
        "--target",
        help="受检对象路径；可选源码根提示（证据集合为主输入）",
    )
    value.add_argument(
        "--evidence-set",
        help="调用方证据集合文件（JSON 对象，仅含 evidence_set 数组）；"
             "缺省时从 --target 派生单条源码证据",
    )
    value.add_argument("--target-type", required=True, choices=sorted(TARGET_TYPES))
    value.add_argument(
        "--spec-package",
        help=(
            "显式规范包目录；省略时默认使用仓内自审规范包 spec/self-audit/"
            "（selfAudit: true，仅用于自审，永不具备发布资格）"
        ),
    )
    value.add_argument("--run-id")
    value.add_argument(
        "--execution-profile",
        choices=conformance_profiles.VALID_PROFILES,
        help="执行档位；底层方法缺省为 full",
    )
    value.add_argument(
        "--semantic-group-id",
        dest="semantic_group_ids",
        action="append",
        help="targeted 档位请求的精确语义组 ID；可重复",
    )
    value.add_argument(
        "--canonical-rule-id",
        dest="canonical_rule_ids",
        action="append",
        help="targeted 档位请求的精确 canonical rule ID；与语义组互斥",
    )
    value.add_argument("--semantic-result")
    value.add_argument("--foundation-task-digest")
    value.add_argument("--profile-selection-reason")
    semantic_mode = value.add_mutually_exclusive_group()
    semantic_mode.add_argument("--semantic-review-preflight", action="store_true")
    semantic_mode.add_argument("--semantic-review-stdin", action="store_true")
    value.add_argument(
        "--platform",
        default="all",
        choices=["all", "claude-code", "codex", "kimi-code", "workbuddy"],
    )
    value.add_argument("--allow-test-fixture", action="store_true")
    value.add_argument(
        "--professional-consumption",
        help="专业消费 JSON；进入同一次 Task 与符合性结果，不得携带待执行命令",
    )
    return value


def _load_professional_consumption(args: argparse.Namespace) -> dict[str, Any] | None:
    raw = getattr(args, "professional_consumption", None)
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if path.is_symlink() or not path.is_file():
        raise WorkflowError(
            "PROFESSIONAL_CONSUMPTION_INVALID",
            "professional_consumption 必须是真实普通文件",
        )
    document = load_json(path)
    if not isinstance(document, dict) or "command" in document:
        raise WorkflowError(
            "PROFESSIONAL_CONSUMPTION_INVALID",
            "professional_consumption 不得携带命令或非对象根",
        )
    return document


def _present_professional_finding(item: dict[str, Any]) -> dict[str, Any]:
    """Show a complete Foundation finding as REVIEW_REQUIRED on the domain row.

    The executor aggregate stays in the legal mechanical vocabulary. This copy
    is the rule view; the trusted observation keeps the original payload.
    """
    rows = item.get("check_method_subresults")
    if not isinstance(rows, list):
        return item
    promoted: list[Any] = []
    changed = False
    for row in rows:
        evidence = row.get("evidence") if isinstance(row, dict) else None
        if (
            isinstance(row, dict)
            and row.get("check_method") in {"static_scan", "schema_validation"}
            and row.get("status") == "EVIDENCE_MISSING"
            and isinstance(evidence, dict)
            and evidence.get("professional_issue") == "professional_findings"
        ):
            promoted.append({**row, "status": "REVIEW_REQUIRED"})
            changed = True
        else:
            promoted.append(row)
    if not changed:
        return item
    return {**item, "status": "REVIEW_REQUIRED", "check_method_subresults": promoted}


def _consume_professional_inputs(document: dict[str, Any]) -> dict[str, Any]:
    """Call the existing proof consumer from validated host inputs."""
    items = document.get("items")
    if not isinstance(items, list):
        raise WorkflowError(
            "PROFESSIONAL_CONSUMPTION_INVALID",
            "professional_consumption.items 必须是数组",
        )
    consumed: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise WorkflowError(
                "PROFESSIONAL_CONSUMPTION_INVALID",
                "professional_consumption.items 项必须是对象",
            )
        try:
            result = checker.consume_professional_proof(item)
        except (RuntimeError, TypeError) as exc:
            raise WorkflowError("PROFESSIONAL_PROOF_FAILED", str(exc)) from exc
        if not isinstance(result, dict) or "command" in result:
            raise WorkflowError(
                "PROFESSIONAL_PROOF_FAILED",
                "专业消费结果非法",
            )
        consumed.append(result)
    return {"items": consumed}


def _caller_evidence_list(
    evidence_set: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    return [
        {
            "kind": "caller-evidence",
            "evidence_id": item["evidence_id"],
            "path": item["path"],
            "sha256": item["sha256"],
            "source": "caller-evidence-set",
        }
        for item in evidence_set or []
        if isinstance(item, dict)
        and isinstance(item.get("evidence_id"), str)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha256"), str)
    ]


def _canonical_id_from_result_row(row: dict[str, Any]) -> str | None:
    lineage = row.get("canonical_lineage")
    if isinstance(lineage, dict) and isinstance(lineage.get("canonical_id"), str):
        return lineage["canonical_id"]
    if row.get("canonical_only") is True and isinstance(row.get("canonical_id"), str):
        return row["canonical_id"]
    return None


def _unexecuted_in_scope_rule_results(
    plan: dict[str, Any],
    existing: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    covered: set[str] = set()
    rows: list[dict[str, Any]] = []
    in_scope = set(plan["in_scope_rule_ids"])
    for row in existing or []:
        if not isinstance(row, dict):
            continue
        canonical_id = _canonical_id_from_result_row(row)
        if (
            canonical_id is None
            or canonical_id not in in_scope
            or canonical_id in covered
        ):
            continue
        covered.add(canonical_id)
        rows.append(row)
    revision_by_canonical = plan["revision_by_canonical"]
    for canonical_id in plan["in_scope_rule_ids"]:
        if canonical_id in covered:
            continue
        rows.append({
            "rule_id": canonical_id,
            "rule_revision_digest": revision_by_canonical[canonical_id],
            "canonical_id": canonical_id,
            "canonical_only": True,
            "status": "NOT_RUN",
        })
    return rows


def after_scope_failure_result(
    exc: BaseException,
    stage: _WorkflowStage,
) -> dict[str, Any]:
    """Project a post-scope failure into the original complete result contract.

    Reuses the selected profile plan and any already assembled rule results.
    Unexecuted in-scope rules stay NOT_RUN.  Does not select the early-exit
    branch.
    """
    after_scope = stage.after_scope or {}
    plan = after_scope.get("profile_plan")
    if not isinstance(plan, dict):
        raise ValueError("after-scope failure requires a selected profile plan")
    args = after_scope.get("args")
    rule_results = _unexecuted_in_scope_rule_results(
        plan, after_scope.get("canonical_results")
    )
    status_by_canonical: dict[str, str] = {}
    for row in rule_results:
        canonical_id = _canonical_id_from_result_row(row)
        if canonical_id is not None:
            status_by_canonical[canonical_id] = row["status"]
    coverage_core = conformance_profiles.derive_coverage(
        plan["in_scope_rule_ids"],
        plan["selected_rule_ids"],
        status_by_canonical,
    )

    def identity_rows(canonical_ids: list[str]) -> list[dict[str, str]]:
        return [
            {
                "canonical_id": canonical_id,
                "revision_digest": plan["revision_by_canonical"][canonical_id],
            }
            for canonical_id in sorted(canonical_ids)
        ]

    coverage = {
        "in_scope_rule_set_digest": plan["in_scope_rule_set_digest"],
        "in_scope_count": coverage_core["in_scope_count"],
        "selected_rule_set_digest": plan["selected_rule_set_digest"],
        "selected_count": coverage_core["selected_count"],
        "attempted_rule_set_digest": foundation_document_digest(
            identity_rows(coverage_core["attempted"])
        ),
        "attempted_count": coverage_core["attempted_count"],
        "not_run_count": coverage_core["not_run_count"],
        "coverage_complete": coverage_core["coverage_complete"],
        "conclusion_complete": coverage_core["conclusion_complete"],
        "requested_semantic_group_ids": plan["requested_semantic_group_ids"],
        "requested_canonical_rule_ids": plan["requested_canonical_rule_ids"],
        "selected_semantic_group_ids": plan["selected_semantic_group_ids"],
        "selected_deterministic_rule_count": plan[
            "selected_deterministic_rule_count"
        ],
        "semantic_group_registry_digest": plan["semantic_group_registry_digest"],
    }
    preflight = after_scope.get("semantic_preflight")
    if isinstance(preflight, dict) and "performed" in preflight:
        semantic_preflight = _semantic_profile_preflight_result(preflight)
    else:
        semantic_preflight = {
            "performed": plan["execution_profile"] != "mechanical",
            "groups": [],
        }
    observed_metrics = after_scope.get("semantic_context_metrics")
    skipped = after_scope.get("semantic_rules_skipped_missing_evidence_count", 0)
    if (
        isinstance(observed_metrics, dict)
        and "semantic_model_call_count" in observed_metrics
        and "semantic_context_count" in observed_metrics
        and "estimated_input_tokens" in observed_metrics
        and "semantic_rules_sent_to_model_count" in observed_metrics
    ):
        execution_metrics = {
            "semantic_model_call_count": observed_metrics[
                "semantic_model_call_count"
            ],
            "semantic_context_count": observed_metrics["semantic_context_count"],
            "estimated_input_tokens": observed_metrics["estimated_input_tokens"],
            "semantic_rules_sent_to_model_count": observed_metrics[
                "semantic_rules_sent_to_model_count"
            ],
            "semantic_rules_skipped_missing_evidence_count": skipped,
        }
    else:
        execution_metrics = {
            "semantic_model_call_count": 0,
            "semantic_context_count": 0,
            "estimated_input_tokens": 0,
            "semantic_rules_sent_to_model_count": 0,
            "semantic_rules_skipped_missing_evidence_count": skipped,
        }
    statuses = {row["status"] for row in rule_results}
    status = "FAILED" if "FAIL" in statuses else "BLOCKED"
    domain: dict[str, Any] = {
        "schema_version": "1.0.0",
        "status": status,
        "reason_code": getattr(exc, "code", type(exc).__name__),
        "summary": str(exc),
        "execution_profile": plan["execution_profile"],
        "coverage": coverage,
        "semantic_preflight": semantic_preflight,
        "execution_metrics": execution_metrics,
        "rule_results": rule_results,
    }
    method_assurance = after_scope.get("method_assurance")
    if status == "FAILED" and isinstance(method_assurance, dict):
        domain["method_assurance"] = method_assurance
    if args is not None:
        run_id = getattr(args, "run_id", None)
        if isinstance(run_id, str) and run_id:
            domain["run_id"] = run_id
        target_type = getattr(args, "target_type", None)
        if target_type in TARGET_TYPES:
            domain["target_type"] = target_type
        platform = getattr(args, "platform", None)
        if platform in {"all", "claude-code", "codex", "kimi-code", "workbuddy"}:
            domain["platform"] = platform
    for field in (
        "semantic_target_digest",
        "rule_set_digest",
        "semantic_request_digest",
    ):
        digest = after_scope.get(field)
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
            domain_key = (
                "target_digest" if field == "semantic_target_digest" else field
            )
            domain[domain_key] = digest
    return {
        "conformance_result": domain,
        "rule_findings": [],
        "evidence_list": _caller_evidence_list(stage.evidence_set),
        "remediation_plan": [],
    }


def _attach_after_scope_failure_result(
    exc: BaseException, stage: _WorkflowStage
) -> None:
    if getattr(exc, "result", None) is not None:
        return
    try:
        exc.result = after_scope_failure_result(exc, stage)
    except Exception:
        return


def before_rule_selection_result(
    exc: BaseException,
    *,
    evidence_set: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project a pre-scope failure into the mutually exclusive early-exit result.

    The stage is taken from actual control flow (the exception), not from a
    caller-supplied failure declaration.  Coverage, rule results, registry
    summaries and completion ratios are omitted rather than fabricated.
    """
    return {
        "conformance_result": {
            "status": "BLOCKED",
            "failure_stage": BEFORE_RULE_SELECTION,
            "reason_code": getattr(exc, "code", type(exc).__name__),
            "summary": str(exc),
        },
        "rule_findings": [],
        "evidence_list": _caller_evidence_list(evidence_set),
        "remediation_plan": [],
    }


def main() -> int:
    args = parser().parse_args()
    if args.semantic_review_stdin:
        result = before_rule_selection_result(
            WorkflowError(
                "SEMANTIC_REVIEW_PRODUCER_UNTRUSTED",
                "生产 CLI 不接受调用方通过 --semantic-review-stdin 提升语义审阅结论",
            )
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 2
    else:
        args.internal_semantic_review = None
    try:
        result = run_workflow(args)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if args.semantic_review_preflight:
            return 0
        return 0 if result["conformance_result"]["status"] == "SUCCEEDED" else 1
    except (WorkflowError, OSError, ValueError) as exc:
        if getattr(exc, "failure_stage", None) == BEFORE_RULE_SELECTION:
            result = before_rule_selection_result(
                exc,
                evidence_set=getattr(exc, "evidence_set", None),
            )
        elif getattr(exc, "result", None) is not None:
            result = exc.result
        else:
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
