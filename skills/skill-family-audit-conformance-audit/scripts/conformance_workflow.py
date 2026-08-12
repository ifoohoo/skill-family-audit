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
from jsonschema import Draft202012Validator


TARGET_TYPES = {
    "single_skill",
    "family_source",
    "release_artifact",
    "project_adoption",
}
SEMANTIC_SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "refs/semantic-review-result.schema.json"
)
REFS = Path(__file__).resolve().parent.parent / "refs"
TRUST_POLICY = REFS / "conformance-trust-policy.json"
CANONICAL_PROJECTION = REFS / "canonical-rule-projection.json"
CROSS_SKILL_RULE_PREFIX = "cross-skill:"


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
    return str(_foundation({"operation": "canonical-json", "document": value})["text"]).encode()


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


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError("INPUT_INVALID", f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkflowError("INPUT_INVALID", f"{path}: 顶层必须是对象")
    return value


def _draft202012_errors(value: Any, schema: dict[str, Any]) -> list[str]:
    """Use the standard validator for Audit-owned domain schemas."""
    return [
        f"{error.json_path}: {error.message}"
        for error in sorted(
            Draft202012Validator(schema).iter_errors(value),
            key=lambda item: (list(item.absolute_path), item.message),
        )
    ]


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
    if (
        foundation_file_digest(CANONICAL_PROJECTION) != expected.get("digest")
        or projection.get("source_digest") != expected.get("source_digest")
        or projection.get("business_digest") != expected.get("business_digest")
        or projection.get("total_rules") != 761
        or len(projection.get("rules", [])) != 761
    ):
        raise WorkflowError(
            "CANONICAL_RULE_PROJECTION_INVALID",
            "761 条权威规则投影与冻结信任策略不一致",
        )
    dispositions = {
        "candidate_undetermined": 0,
        "effective": 0,
    }
    for rule in projection["rules"]:
        if (
            rule.get("effect") == "candidate_undetermined"
            or rule.get("adoption_mode") == "candidate_undetermined"
        ):
            dispositions["candidate_undetermined"] += 1
        else:
            dispositions["effective"] += 1
    return {
        "projection_digest": foundation_file_digest(CANONICAL_PROJECTION),
        "source_digest": projection["source_digest"],
        "business_digest": projection["business_digest"],
        "total_rules": 761,
        **dispositions,
    }


def canonical_rule_applicability(
    trust_policy: dict[str, Any],
    target_type: str,
    platform: str = "all",
) -> dict[str, Any]:
    """逐条分类冻结的 761 条规则；候选未决规则绝不进入执行集合。"""
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
        if not candidate_undetermined:
            # 当前权威投影尚未定义可执行 effect/adoption/scope 词表。
            # 在治理升级同时提供结构化 target/platform 语义前，禁止猜测执行。
            raise WorkflowError(
                "CANONICAL_RULE_APPLICABILITY_UNSUPPORTED",
                f"权威规则尚无可执行适用性合同: {canonical_id}",
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
            "disposition": "candidate_undetermined",
            "executable": False,
            "reason": (
                "候选权威尚未冻结 effect、adoption_mode、"
                "target/platform scope，禁止执行"
            ),
        })
    if len(rows) != 761 or len(seen) != 761:
        raise WorkflowError(
            "CANONICAL_RULE_APPLICABILITY_INVALID",
            "761 条权威规则没有被逐条且唯一地分类",
        )
    payload = {
        "schema_version": "1.0.0",
        "projection_digest": summary["projection_digest"],
        "target_type": target_type,
        "platform": platform,
        "counts": {
            "total": len(rows),
            "executable": 0,
            "candidate_undetermined": len(rows),
        },
        "rules": rows,
    }
    payload["applicability_digest"] = foundation_document_digest(payload)
    return payload


def bound_rule_set_digest(
    baseline_rules: list[dict[str, Any]],
    canonical_applicability: dict[str, Any],
) -> str:
    return foundation_document_digest({
        "baseline_rule_set_kind": "implementation-baseline",
        "baseline_rules": baseline_rules,
        "canonical_rule_ids": [],
        "canonical_projection_digest": canonical_applicability[
            "projection_digest"
        ],
        "canonical_applicability_digest": canonical_applicability[
            "applicability_digest"
        ],
    })


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
def _plugin_project_schema() -> dict[str, Any]:
    """Locate the Audit-owned observation contract in source or projection."""
    current = Path(__file__).resolve()
    for ancestor in current.parents:
        for relative in (
            f"spec/contracts/{PLUGIN_PROJECT_SCHEMA_NAME}",
            f"shared/contracts/{PLUGIN_PROJECT_SCHEMA_NAME}",
        ):
            candidate = ancestor / relative
            if candidate.is_file() and not candidate.is_symlink():
                return load_json(candidate)
    raise WorkflowError(
        "PLUGIN_PROJECT_OBSERVATION_SCHEMA_MISSING",
        "无法定位 Audit PluginProject 观察合同",
    )


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _manifest_identity(path: Path, root: Path) -> dict[str, Any]:
    value = load_json(path)
    supported_claims = (
        ("pluginId", "familyId"),
        ("pluginId", "name"),
        ("pluginId", "id"),
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
            for field in ("familyId", "name", "id")
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

    errors = _draft202012_errors(observation, _plugin_project_schema())
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

    manifest_paths: set[Path] = set()
    for relative in (
        "package.json",
        "plugin-src/manifest.json",
        ".codex-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codebuddy-plugin/plugin.json",
        "kimi.plugin.json",
    ):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            manifest_paths.add(path)
    for pattern in ("platform-manifest.json", "plugin.json", "kimi.plugin.json"):
        manifest_paths.update(
            path
            for path in root.rglob(pattern)
            if path.is_file()
            and not path.is_symlink()
            and not any(
                part in {".git", "node_modules", "__pycache__"}
                for part in path.relative_to(root).parts
            )
        )
    manifest_identities = [
        _manifest_identity(path, root) for path in sorted(manifest_paths)
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
    for manifest_path in sorted(root.rglob("platform-manifest.json")):
        if (
            not manifest_path.is_file()
            or manifest_path.is_symlink()
            or any(
                part in {".git", "node_modules", "__pycache__"}
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
    adoption_lock_path = target / ".skill-family-audit/adoption-lock.json"
    if not adoption_lock_path.is_file() or adoption_lock_path.is_symlink():
        raise WorkflowError("PROJECT_ADOPTION_MISSING", "项目缺少采用锁")
    adoption_lock = load_json(adoption_lock_path)
    installed_root_value = adoption_lock.get("installed_root")
    family_id = adoption_lock.get("family_id")
    adoption_version = adoption_lock.get("version")
    if (
        not isinstance(family_id, str)
        or not family_id
        or not isinstance(adoption_version, str)
        or adoption_lock.get("candidate_id")
        != f"{family_id}:{adoption_version}"
        or not isinstance(adoption_lock.get("candidate_digest"), str)
        or not isinstance(adoption_lock.get("platform"), str)
        or not isinstance(installed_root_value, str)
    ):
        raise WorkflowError("PROJECT_ADOPTION_INVALID", "采用锁字段不完整")
    installed_root = (target / installed_root_value).resolve()
    if target not in installed_root.parents or not installed_root.is_dir():
        raise WorkflowError("PROJECT_ADOPTION_INVALID", "采用锁安装根无效")
    skill_files = [
        path for path in installed_root.rglob("SKILL.md")
        if path.is_file() and not path.is_symlink()
    ]
    if not skill_files:
        raise WorkflowError("PROJECT_ADOPTION_SKILL_MISSING", "安装根缺少 SKILL.md")
    manifest_path = installed_root / "platform-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise WorkflowError(
            "PROJECT_ADOPTION_MANIFEST_MISSING", "安装根缺少平台清单"
        )
    manifest = load_json(manifest_path)
    if (
        manifest.get("familyId") != family_id
        or manifest.get("platformId") != adoption_lock["platform"]
        or manifest.get("version") != adoption_lock["version"]
        or manifest.get("projectionDigest") != adoption_lock["candidate_digest"]
    ):
        raise WorkflowError(
            "PROJECT_ADOPTION_IDENTITY_INVALID",
            "采用锁未绑定安装清单的 family/platform/version/candidate",
        )
    if _foundation_platform_payload_digest(installed_root) != adoption_lock["candidate_digest"]:
        raise WorkflowError("PROJECT_ADOPTION_STALE", "采用锁摘要与安装内容不一致")
    observation = observe_plugin_project(
        installed_root,
        target_type,
        identity_hint={
            "pluginId": family_id,
            "version": adoption_version,
            "candidateId": adoption_lock["candidate_id"],
        },
        install_digests=[
            {
                "kind": "adoption_lock",
                "path": adoption_lock_path.relative_to(target).as_posix(),
                "contentDigest": foundation_file_digest(adoption_lock_path),
            },
            {
                "kind": "installed_tree",
                "path": installed_root.relative_to(target).as_posix(),
                "contentDigest": adoption_lock["candidate_digest"],
            },
        ],
    )
    return {
        "adoption_lock": adoption_lock_path.relative_to(target).as_posix(),
        "adoption_lock_digest": foundation_file_digest(adoption_lock_path),
        "installed_root": installed_root.relative_to(target).as_posix(),
        "installed_digest": adoption_lock["candidate_digest"],
        "plugin_project": observation,
        "logical_skill_count": len(observation["skills"]),
    }


def semantic_reviews(
    path: Path | None,
    rules: list[dict[str, Any]],
    task_digest: str,
    target: Path,
    target_type: str,
) -> dict[str, dict[str, Any]]:
    semantic = [rule for rule in rules if rule.get("checkType") == "semantic"]
    if not semantic:
        return {}
    if path is None:
        raise WorkflowError("SEMANTIC_REVIEW_MISSING", "适用语义规则缺少 Worker 结果")
    value = load_json(path)
    schema = load_json(SEMANTIC_SCHEMA)
    validation_errors = _draft202012_errors(value, schema)
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
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise WorkflowError(
                    "SEMANTIC_EVIDENCE_MISSING", evidence
                ) from exc
            boundary = target.parent if target.is_file() else target
            if resolved != boundary and boundary not in resolved.parents:
                raise WorkflowError("SEMANTIC_EVIDENCE_ESCAPE", evidence)
    return reviews


def _consumer_schema_index() -> dict[str, dict[str, Any]]:
    """按 $id 索引 Audit 消费者 Schema；合并来源树与平台投影的全部合同根。"""
    index: dict[str, dict[str, Any]] = {}
    current = Path(__file__).resolve()
    for ancestor in current.parents:
        for contracts_root in (
            ancestor / "spec" / "contracts",
            ancestor / "shared" / "contracts",
            ancestor / "foundation" / "quickstart-profile" / "schemas" / "consumer",
        ):
            if not contracts_root.is_dir():
                continue
            for schema_path in sorted(contracts_root.rglob("*.schema.json")):
                if schema_path.is_symlink() or not schema_path.is_file():
                    continue
                document = load_json(schema_path)
                schema_id = document.get("$id")
                if isinstance(schema_id, str) and schema_id and schema_id not in index:
                    index[schema_id] = document
    if not index:
        raise WorkflowError(
            "METHOD_PARAMETER_SCHEMA_MISSING",
            "无法定位 Audit 消费者 Schema 集合",
        )
    return index


def _conformance_parameter_schema() -> dict[str, Any]:
    """从当前源码包或平台投影读取权威方法参数合同。"""
    current = Path(__file__).resolve()
    for ancestor in current.parents:
        for relative in (
            "spec/methods/conformance-audit.json",
            "shared/methods/conformance-audit.json",
        ):
            candidate = ancestor / relative
            if not candidate.is_file() or candidate.is_symlink():
                continue
            value = load_json(candidate)
            schema = value.get("strictIOBinding", {}).get("parameterSchema")
            if not isinstance(schema, dict):
                continue
            ref = schema.get("$ref")
            if isinstance(ref, str) and ref:
                resolved = _consumer_schema_index().get(ref)
                if resolved is None:
                    raise WorkflowError(
                        "METHOD_PARAMETER_SCHEMA_MISSING",
                        f"Conformance parameterSchema $ref 无法解析: {ref}",
                    )
                return resolved
            return schema
    raise WorkflowError(
        "METHOD_PARAMETER_SCHEMA_MISSING",
        "无法定位 Conformance 权威 parameterSchema",
    )


def _validate_method_parameters(
    parameters: dict[str, Any],
) -> None:
    """Draft 2020-12 校验 Audit 领域参数。"""
    errors = _draft202012_errors(parameters, _conformance_parameter_schema())
    if errors:
        raise WorkflowError(
            "METHOD_PARAMETER_SCHEMA_INVALID",
            f"Conformance 领域参数不符合 parameterSchema: {errors}",
        )


def run_workflow(args: argparse.Namespace) -> dict[str, Any]:
    if not args.spec_package or not args.output_dir or not args.run_id:
        raise WorkflowError(
            "WORKFLOW_ARGS_MISSING",
            "完整工作流需要 --spec-package、--output-dir 与 --run-id",
        )
    target = Path(args.target).resolve(strict=True)
    output_dir = Path(args.output_dir).resolve()
    if output_dir == target or target in output_dir.parents:
        raise WorkflowError("OUTPUT_INSIDE_TARGET", "输出目录不得位于只读目标内")
    index, manifest, is_fixture, trust_policy = load_rules(
        Path(args.spec_package).resolve(strict=True), args.allow_test_fixture
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
        for category in manifest.get("ruleCategories", [])
        for rule in category.get("rules", [])
        if rule.get("applicability") in applicability
    ]
    if (
        manifest.get("ruleSetKind") not in {None, "implementation-baseline"}
        or manifest.get("canonicalRuleIds", []) != []
    ):
        raise WorkflowError(
            "BASELINE_RULE_LINEAGE_INVALID",
            "现有检查器规则必须明确标记为非权威实现基线",
        )
    canonical_summary = canonical_rule_summary(trust_policy)
    canonical_applicability = canonical_rule_applicability(
        trust_policy, args.target_type, args.platform
    )
    rule_set_digest = bound_rule_set_digest(rules, canonical_applicability)
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
    semantic_request_digest = foundation_document_digest({
        "target_digest": foundation_target_content_digest(target, args.target_type),
        "target_type": args.target_type,
        "rule_set_digest": rule_set_digest,
    })
    reviews = semantic_reviews(
        Path(args.semantic_result).resolve() if args.semantic_result else None,
        rules,
        semantic_request_digest,
        target,
        args.target_type,
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
            scope_rule = {
                "scope:single-skill-complete": ("skill_files",),
                "scope:family-source-complete": ("skill_files", "source_files"),
                "scope:release-artifact-complete": ("release_files",),
                "scope:project-adoption-present": ("adoption_lock",),
            }.get(rule["ruleId"])
            if scope_rule:
                all_present = all(scope.get(key) for key in scope_rule)
                outcome = {
                    "status": "PASS" if all_present else "FAIL",
                    "evidence": {key: scope.get(key, []) for key in scope_rule},
                }
            else:
                outcome = checker._check(rule["ruleId"], scan, target if target.is_dir() else target.parent)
            outcome["worker"] = "deterministic-checker"
        else:
            outcome = {"status": "NOT_RUN", "evidence": {"reason": "unsupported_check_type"}}
        results.append(
            {
                "rule_id": rule["ruleId"],
                "rule_revision_digest": rule["revisionDigest"],
                **outcome,
            }
        )
    failed = [
        item
        for item in results
        if item["status"] not in {"PASS", "NOT_APPLICABLE"}
    ]
    status = "SUCCEEDED" if rules and not failed else "FAILED"
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
            "canonical_rule_ids": [],
            "executed_rule_count": len(rules),
        },
    }
    domain_path = output_dir / "conformance-result.json"
    domain_path.write_bytes(foundation_canonical_bytes(domain) + b"\n")
    evidence = [{
        "kind": "target-observation",
        "path": str(target),
        "source": "conformance-workflow",
        "target_digest": foundation_target_content_digest(target, args.target_type),
        "credibility": "verified" if not is_fixture else "self_reported",
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
    value.add_argument("--spec-package")
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
