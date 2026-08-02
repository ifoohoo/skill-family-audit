#!/usr/bin/env python3
"""四类受检对象的生产 Conformance 工作流。

确定性规则先执行；只有规则明确声明 ``checkType=semantic`` 时才消费隔离
语义 Worker 的 Schema 化结果。目标只读，唯一写集是显式 output_dir。
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import conformance_check as checker


TARGET_TYPES = {
    "single_skill",
    "family_source",
    "release_artifact",
    "project_adoption",
}
WORKSPACE_TREE_EXCLUDED_PARTS = {
    ".git",
    ".codex",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
}
SEMANTIC_SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "refs/semantic-review-result.schema.json"
)
REFS = Path(__file__).resolve().parent.parent / "refs"
TRUST_POLICY = REFS / "conformance-trust-policy.json"
CANONICAL_PROJECTION = REFS / "canonical-rule-projection.json"


class WorkflowError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def consume_quickstart_task(argv: list[str]) -> dict[str, Any] | None:
    if not os.environ.get("SFA_NORMALIZED_TASK_REF"):
        return None
    raw = os.environ.get("SFA_RUNTIME_CONTRACTS_REF", "")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink():
        raise WorkflowError("NORMALIZED_TASK_BINDING_INVALID", "Task 合同引用无效")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise WorkflowError("NORMALIZED_TASK_BINDING_INVALID", str(exc)) from exc
    spec = importlib.util.spec_from_file_location(
        "conformance_quickstart_contracts", resolved
    )
    if spec is None or spec.loader is None:
        raise WorkflowError("NORMALIZED_TASK_BINDING_INVALID", "Task 合同不可加载")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.consume_normalized_task(
            method_id="skill-family-audit:conformance-audit",
            script_path=__file__,
            argv=argv,
        )
    except module.NormalizedTaskBindingError as exc:
        raise WorkflowError("NORMALIZED_TASK_BINDING_INVALID", str(exc)) from exc


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def tree_digest(root: Path) -> str:
    rows = {
        path.relative_to(root).as_posix(): file_digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    return digest_bytes(canonical(rows))


def workspace_input_tree_digest(root: Path) -> str:
    """Digest workspace input bytes while excluding VCS/runtime-only state."""
    rows = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in WORKSPACE_TREE_EXCLUDED_PARTS for part in relative.parts):
            continue
        if (
            path.is_file()
            and not path.is_symlink()
            and path.suffix not in {".pyc", ".pyo"}
        ):
            rows[relative.as_posix()] = file_digest(path)
    return digest_bytes(canonical(rows))


def candidate_payload_digest(root: Path) -> str:
    rows = {
        path.relative_to(root).as_posix(): file_digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(root).as_posix() != "candidate-summary.json"
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    return digest_bytes(canonical(rows))


def target_content_digest(target: Path, target_type: str) -> str:
    if target_type == "single_skill":
        skill = target if target.name == "SKILL.md" else target / "SKILL.md"
        return file_digest(skill)
    return tree_digest(target)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError("INPUT_INVALID", f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkflowError("INPUT_INVALID", f"{path}: 顶层必须是对象")
    return value


def schema_errors(
    value: Any,
    schema: dict[str, Any],
    pointer: str = "$",
) -> list[str]:
    """Validate the small, dependency-free JSON Schema subset used here."""
    errors: list[str] = []
    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
    }
    if expected_type in type_matches and not type_matches[expected_type]:
        return [f"{pointer}: expected {expected_type}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{pointer}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{pointer}: enum mismatch")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{pointer}: shorter than minLength")
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(pattern, value) is None:
            errors.append(f"{pointer}: pattern mismatch")
    if isinstance(value, dict):
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                errors.append(f"{pointer}: missing {name}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in sorted(set(value) - set(properties)):
                errors.append(f"{pointer}: unknown property {name}")
        for name, child in value.items():
            if name in properties:
                errors.extend(
                    schema_errors(child, properties[name], f"{pointer}/{name}")
                )
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, child in enumerate(value):
            errors.extend(
                schema_errors(child, schema["items"], f"{pointer}/{index}")
            )
    return errors


def load_approved_rules(
    package: Path, allow_test_fixture: bool
) -> tuple[dict[str, Any], dict[str, Any], bool, dict[str, Any]]:
    index = load_json(package / "authority-index.json")
    manifest_path = package / "applicable-rules.json"
    manifest = load_json(manifest_path)
    is_fixture = index.get("test_fixture") is True
    if is_fixture and not allow_test_fixture:
        raise WorkflowError("TEST_FIXTURE_NOT_ALLOWED", "生产路径拒绝测试规范包")
    trust_policy = load_json(TRUST_POLICY)
    if not is_fixture:
        trusted = [
            entry
            for entry in trust_policy.get("trusted_production_authorities", [])
            if isinstance(entry, dict)
            and entry.get("authority_index_digest")
            == file_digest(package / "authority-index.json")
        ]
        if len(trusted) != 1:
            raise WorkflowError(
                "SPEC_AUTHORITY_UNTRUSTED",
                "规范包未被当前不可变候选的信任策略批准",
            )
        if index.get("approvalStatus") not in {
            "active",
            "active_candidate_governance_approval",
        }:
            raise WorkflowError("NO_ACTIVE_APPROVED_SPEC", "规范包没有活动批准")
    else:
        trusted = []
    active = index.get("activeSpecRelease")
    receipt = index.get("approvalReceipt")
    if not isinstance(active, dict) or not isinstance(receipt, dict):
        raise WorkflowError("APPROVAL_CLOSURE_MISSING", "缺少活动发布或批准收据")
    releases = index.get("releases")
    if (
        not isinstance(releases, list)
        or len([item for item in releases if item.get("status") == "active"]) != 1
    ):
        raise WorkflowError("ACTIVE_RELEASE_NOT_UNIQUE", "活动规范发布不唯一")
    actual = file_digest(manifest_path)
    if active.get("ruleManifestDigest") != actual:
        raise WorkflowError("RULE_MANIFEST_DIGEST_MISMATCH", "规则清单摘要不匹配")
    if (
        receipt.get("approvedObject") != active.get("releaseId")
        or receipt.get("approvedReleaseDigest") != active.get("contentDigest")
        or receipt.get("approvedRuleManifestDigest") != actual
    ):
        raise WorkflowError("APPROVAL_CLOSURE_MISMATCH", "批准收据未闭合活动发布")
    allowed_signers = (
        index.get("approvedAuthorities", [])
        if is_fixture
        else trusted[0].get("approved_signers", [])
    )
    if receipt.get("signedBy") not in allowed_signers:
        raise WorkflowError("APPROVAL_SIGNER_UNTRUSTED", "批准者不在冻结信任集合")
    if not is_fixture and (
        trusted[0].get("rule_manifest_digest") != actual
        or trusted[0].get("release_id") != active.get("releaseId")
    ):
        raise WorkflowError("SPEC_AUTHORITY_UNTRUSTED", "活动发布不匹配冻结信任策略")
    return index, manifest, is_fixture, trust_policy


def canonical_rule_summary(trust_policy: dict[str, Any]) -> dict[str, Any]:
    projection = load_json(CANONICAL_PROJECTION)
    expected = trust_policy.get("canonical_rule_projection", {})
    if (
        file_digest(CANONICAL_PROJECTION) != expected.get("digest")
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
        "projection_digest": file_digest(CANONICAL_PROJECTION),
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
    payload["applicability_digest"] = digest_bytes(canonical(payload))
    return payload


def bound_rule_set_digest(
    baseline_rules: list[dict[str, Any]],
    canonical_applicability: dict[str, Any],
) -> str:
    return digest_bytes(canonical({
        "baseline_rule_set_kind": "implementation-baseline",
        "baseline_rules": baseline_rules,
        "canonical_rule_ids": [],
        "canonical_projection_digest": canonical_applicability[
            "projection_digest"
        ],
        "canonical_applicability_digest": canonical_applicability[
            "applicability_digest"
        ],
    }))


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
                if resource.startswith(("spec/", "registry-v2/", "platforms/"))
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


def _platform_payload_digest(root: Path) -> str:
    rows = {
        path.relative_to(root).as_posix(): file_digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(root).as_posix() != "platform-manifest.json"
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    return digest_bytes(canonical(rows))


def target_scope(target: Path, target_type: str) -> dict[str, Any]:
    if target_type == "single_skill":
        skill = target if target.name == "SKILL.md" else target / "SKILL.md"
        if not skill.is_file():
            raise WorkflowError("SINGLE_SKILL_MISSING", "单技能目标缺少 SKILL.md")
        return {"skill_files": [skill.relative_to(target.parent).as_posix()]}
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
            "source_tree_digest": tree_digest(target),
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
        version = package_json.get("version")
        actual_payload = candidate_payload_digest(target)
        if (
            package_json.get("name") != "skill-family-audit"
            or not isinstance(version, str)
            or summary.get("version") != version
            or summary.get("candidateId") != f"skill-family-audit:{version}"
            or summary.get("candidatePayloadDigest") != actual_payload
        ):
            raise WorkflowError(
                "RELEASE_ARTIFACT_IDENTITY_INVALID",
                "发行包身份、版本或 payload 摘要不闭合",
            )
        return {
            "release_files": release_files,
            "release_tree_digest": tree_digest(target),
            "candidate_payload_digest": actual_payload,
        }
    adoption_lock_path = target / ".skill-family-audit/adoption-lock.json"
    if not adoption_lock_path.is_file() or adoption_lock_path.is_symlink():
        raise WorkflowError("PROJECT_ADOPTION_MISSING", "项目缺少采用锁")
    adoption_lock = load_json(adoption_lock_path)
    installed_root_value = adoption_lock.get("installed_root")
    if (
        adoption_lock.get("family_id") != "skill-family-audit"
        or not isinstance(adoption_lock.get("version"), str)
        or adoption_lock.get("candidate_id")
        != f"skill-family-audit:{adoption_lock.get('version')}"
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
        manifest.get("familyId") != "skill-family-audit"
        or manifest.get("platformId") != adoption_lock["platform"]
        or manifest.get("version") != adoption_lock["version"]
        or manifest.get("projectionDigest") != adoption_lock["candidate_digest"]
    ):
        raise WorkflowError(
            "PROJECT_ADOPTION_IDENTITY_INVALID",
            "采用锁未绑定安装清单的 family/platform/version/candidate",
        )
    if _platform_payload_digest(installed_root) != adoption_lock["candidate_digest"]:
        raise WorkflowError("PROJECT_ADOPTION_STALE", "采用锁摘要与安装内容不一致")
    return {
        "adoption_lock": adoption_lock_path.relative_to(target).as_posix(),
        "adoption_lock_digest": file_digest(adoption_lock_path),
        "installed_root": installed_root.relative_to(target).as_posix(),
        "installed_digest": adoption_lock["candidate_digest"],
    }


def _workspace_verifier_invocation(
    invocation: dict[str, Any],
) -> dict[str, str | None]:
    argv = invocation.get("argv")
    cwd_value = invocation.get("cwd")
    if (
        set(invocation) != {"argv", "cwd", "exitCode"}
        or not isinstance(argv, list)
        or not all(isinstance(item, str) for item in argv)
        or not isinstance(cwd_value, str)
        or not Path(cwd_value).is_absolute()
        or invocation.get("exitCode") != 0
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID",
            "verifier 调用证据结构无效",
        )
    allowed = {"root", "schema", "release-project", "manifest"}
    parsed: dict[str, str] = {}
    index = 0
    while index < len(argv):
        argument = argv[index]
        if not argument.startswith("--"):
            raise WorkflowError(
                "WORKSPACE_VERIFIER_RECEIPT_INVALID",
                "verifier argv 包含位置参数",
            )
        name_value = argument[2:].split("=", 1)
        name = name_value[0]
        if name not in allowed or name in parsed:
            raise WorkflowError(
                "WORKSPACE_VERIFIER_RECEIPT_INVALID",
                "verifier argv 包含未知或重复参数",
            )
        if len(name_value) == 2:
            value = name_value[1]
        else:
            index += 1
            if index >= len(argv) or argv[index].startswith("--"):
                raise WorkflowError(
                    "WORKSPACE_VERIFIER_RECEIPT_INVALID",
                    "verifier argv 参数缺少值",
                )
            value = argv[index]
        if not value:
            raise WorkflowError(
                "WORKSPACE_VERIFIER_RECEIPT_INVALID",
                "verifier argv 参数为空",
            )
        parsed[name] = value
        index += 1
    cwd = Path(cwd_value)
    root = (cwd / parsed.get("root", ".")).resolve()
    schema = (cwd / parsed.get(
        "schema",
        str(
            root
            / "packages/skill-family-audit/spec/contracts/skill-family-workspace.schema.json"
        ),
    )).resolve()
    project = (cwd / parsed.get(
        "release-project", str(root / ".release-skill/project.yaml")
    )).resolve()
    manifest = (
        (cwd / parsed["manifest"]).resolve()
        if "manifest" in parsed
        else None
    )
    return {
        "root": str(root),
        "schema": str(schema),
        "release-project": str(project),
        "manifest": str(manifest) if manifest else None,
    }


def _receipt_entry_path(
    target: Path,
    package_root: str,
    source_kind: str,
    source: str,
) -> Path:
    if (
        not source
        or "\\" in source
        or source.startswith("/")
        or "//" in source
        or any(part in {"", ".", ".."} for part in source.split("/"))
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID", "公开清单源路径无效"
        )
    anchor = target if source_kind == "release-project" else target / package_root
    try:
        anchor = anchor.resolve(strict=True)
        resolved = (anchor / source).resolve(strict=True)
    except OSError as exc:
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_STALE", str(exc)
        ) from exc
    if resolved != anchor and anchor not in resolved.parents:
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID", "公开清单源路径越界"
        )
    if resolved.is_symlink() or not resolved.is_file():
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_STALE", "公开清单源不是普通文件"
        )
    return resolved


def workspace_receipt(
    target: Path,
    receipt_path: Path | None,
    verifier_path: Path | None,
    trust_policy: dict[str, Any],
) -> dict[str, Any] | None:
    project = target / ".release-skill/project.yaml"
    if not project.is_file():
        return None
    schema = (
        target
        / "packages/skill-family-audit/spec/contracts/skill-family-workspace.schema.json"
    )
    if (
        receipt_path is None
        or not receipt_path.is_file()
        or verifier_path is None
        or not verifier_path.is_file()
        or verifier_path.is_symlink()
        or not schema.is_file()
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_MISSING",
            "私有 workspace 必须提供进程外权威 verifier 与其真实收据",
        )
    receipt = load_json(receipt_path)
    trusted_verifier = trust_policy.get("workspace_verifier", {}).get("digest")
    verifier_path = verifier_path.resolve(strict=True)
    actual_verifier_digest = file_digest(verifier_path)
    if actual_verifier_digest != trusted_verifier:
        raise WorkflowError(
            "WORKSPACE_VERIFIER_UNTRUSTED",
            "显式 verifier 字节不匹配候选内冻结信任根",
        )
    expected_keys = {
        "schemaVersion", "receiptType", "verdict", "structuredErrorCode",
        "verifierPath", "verifierDigest", "invocation", "workspaceRoot",
        "workspaceSchemaPath", "workspaceSchemaDigest", "releaseProjectPath",
        "releaseProjectDigest", "manifestSourceKind", "manifestSourcePath",
        "manifestSourceDigest", "inputTreeDigest", "manifestDigest",
        "assessmentDigest", "releaseUnitId", "packageRoot", "entryCount",
        "entries",
    }
    if (
        set(receipt) != expected_keys
        or receipt.get("schemaVersion") != "1.1.0"
        or receipt.get("receiptType")
        != "skill-family-workspace-verification"
        or receipt.get("verdict") != "PASS"
        or receipt.get("structuredErrorCode") is not None
        or receipt.get("verifierPath") != str(verifier_path)
        or receipt.get("verifierDigest") != actual_verifier_digest
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID",
            "收据不是冻结 verifier 的完整真实输出格式",
        )
    invocation = receipt.get("invocation")
    if not isinstance(invocation, dict):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID", "缺少 verifier 调用证据"
        )
    resolved_invocation = _workspace_verifier_invocation(invocation)
    expected_schema = schema.resolve(strict=True)
    expected_project = project.resolve(strict=True)
    if (
        resolved_invocation["root"] != str(target)
        or resolved_invocation["schema"] != str(expected_schema)
        or resolved_invocation["release-project"] != str(expected_project)
        or receipt.get("workspaceRoot") != str(target)
        or receipt.get("workspaceSchemaPath") != str(expected_schema)
        or receipt.get("releaseProjectPath") != str(expected_project)
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID",
            "verifier argv、解析输入与当前目标不一致",
        )
    source_kind = receipt.get("manifestSourceKind")
    manifest_source = receipt.get("manifestSourcePath")
    if source_kind not in {"release-project", "explicit"} or not isinstance(
        manifest_source, str
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID", "公开清单来源无效"
        )
    expected_manifest = (
        expected_project
        if source_kind == "release-project"
        else Path(resolved_invocation["manifest"] or "").resolve()
    )
    if (
        resolved_invocation["manifest"]
        != (str(expected_manifest) if source_kind == "explicit" else None)
        or Path(manifest_source).resolve() != expected_manifest
        or not expected_manifest.is_file()
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID", "公开清单调用来源不一致"
        )
    entries = receipt.get("entries")
    package_root = receipt.get("packageRoot")
    if (
        not isinstance(entries, list)
        or not isinstance(package_root, str)
        or not isinstance(receipt.get("releaseUnitId"), str)
        or receipt.get("entryCount") != len(entries)
    ):
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_INVALID", "公开清单 assessment 无效"
        )
    recomputed_entries = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"from", "to", "sha256", "size"}
            or not isinstance(entry.get("from"), str)
            or not isinstance(entry.get("to"), str)
            or not isinstance(entry.get("sha256"), str)
            or not isinstance(entry.get("size"), int)
        ):
            raise WorkflowError(
                "WORKSPACE_VERIFIER_RECEIPT_INVALID", "公开清单条目结构无效"
            )
        source = _receipt_entry_path(
            target, package_root, source_kind, entry["from"]
        )
        recomputed_entries.append({
            "from": entry["from"],
            "to": entry["to"],
            "sha256": file_digest(source),
            "size": source.stat().st_size,
        })
    assessment = {
        "releaseUnitId": receipt["releaseUnitId"],
        "packageRoot": package_root,
        "entryCount": len(recomputed_entries),
        "entries": recomputed_entries,
    }
    expected_tree = workspace_input_tree_digest(target)
    stale = (
        recomputed_entries != entries
        or receipt.get("workspaceSchemaDigest") != file_digest(expected_schema)
        or receipt.get("releaseProjectDigest") != file_digest(expected_project)
        or receipt.get("manifestSourceDigest") != file_digest(expected_manifest)
        or receipt.get("inputTreeDigest") != expected_tree
        or receipt.get("manifestDigest") != digest_bytes(canonical(entries))
        or receipt.get("assessmentDigest") != digest_bytes(canonical(assessment))
    )
    if stale:
        raise WorkflowError(
            "WORKSPACE_VERIFIER_RECEIPT_STALE",
            "进程外 verifier 收据与当前目标字节不一致",
        )
    return {
        "receipt_path": str(receipt_path),
        "receipt_digest": file_digest(receipt_path),
        "verifier_path": str(verifier_path),
        "verifier_digest": actual_verifier_digest,
        "schema_digest": file_digest(expected_schema),
        "release_project_digest": file_digest(expected_project),
        "manifest_digest": receipt["manifestDigest"],
        "input_tree_digest": expected_tree,
        "argv": invocation["argv"],
        "exit_code": invocation["exitCode"],
        "verdict": "PASS",
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
    validation_errors = schema_errors(value, schema)
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


def normalized_task(
    run_id: str,
    target: Path,
    target_type: str,
    output_dir: Path,
    rule_set_digest: str = "",
    workspace_binding: dict[str, Any] | None = None,
    platform: str = "all",
    target_project_path: str | None = None,
    spec_version_ref: str = "spec-release:active",
) -> dict[str, Any]:
    # 公共 Task parameters 精确且仅包含权威 parameterSchema 四字段。
    # 内容与规则摘要属于输入资源身份，不得成为第二套业务参数。
    parameters = {
        "target_project_path": target_project_path or str(target),
        "spec_version_ref": spec_version_ref,
        "scope_selector": target_type,
        "platform_filter": platform,
    }
    inputs = [
        {
            "resource_id": f"{run_id}:target-project",
            "name": "target_project",
            "kind": "file" if target.is_file() else "directory",
            "path": str(target),
            "required": True,
            "content_digest": target_content_digest(target, target_type),
            "access": "read_only",
            "workspace_scope": "inside_workspace",
        },
        {
            "resource_id": f"{run_id}:rule-set",
            "name": "effective_rule_set",
            "kind": "artifact",
            "path": spec_version_ref,
            "required": True,
            "content_digest": rule_set_digest,
            "access": "read_only",
            "workspace_scope": "outside_workspace",
        },
    ]
    if workspace_binding is not None:
        inputs.extend([
            {
                "resource_id": f"{run_id}:workspace-verifier",
                "name": "workspace_verifier",
                "kind": "file",
                "path": workspace_binding["verifier_path"],
                "required": True,
                "content_digest": workspace_binding["verifier_digest"],
                "access": "read_only",
                "workspace_scope": "outside_workspace",
            },
            {
                "resource_id": f"{run_id}:workspace-verifier-receipt",
                "name": "workspace_verifier_receipt",
                "kind": "artifact",
                "path": workspace_binding["receipt_path"],
                "required": True,
                "content_digest": workspace_binding["receipt_digest"],
                "access": "read_only",
                "workspace_scope": "outside_workspace",
            },
        ])
    return {
        "schema_version": "1.1.0-candidate",
        "run_id": run_id,
        "method_id": "skill-family-audit:conformance-audit",
        "operation_id": "conformance-audit",
        "stage_id": "conformance",
        "attempt": 1,
        "target": {
            "skill": "skill-family-audit:conformance-audit",
            "script_id": "conformance_workflow.py",
        },
        "workspace_root": str(target),
        "parameters": parameters,
        "inputs": inputs,
        "expected_outputs": [],
        "output_dir": str(output_dir),
        "write_set": [str(output_dir)],
        "authorization_ref": "read-only-target/output-dir-only",
        "acceptance_ref": "spec/methods/conformance-audit.json",
        "required_extensions": [],
        "budget": {
            "model_context_limit_tokens": 1000,
            "skill_warning_tokens": 2000,
            "skill_intervention_tokens": 2400,
            "context_observation_threshold": 400,
            "context_static_split_threshold": 480,
            "reserved_output_tokens": 100,
            "measurement_policy": "estimated",
        },
        "control_channel": {
            "run_id": run_id,
            "process_id": "local",
            "cancel_sequence": [
                "STOP_DISPATCH",
                "PROPAGATE_CANCEL",
                "GRACEFUL_STOP",
            ],
            "lease_deadline": "2099-01-01T00:00:00Z",
            "cancel_acknowledged": False,
            "pre_submit_auth_recheck": True,
            "late_result_disposition": "discard",
        },
    }


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
            if isinstance(schema, dict):
                return schema
    raise WorkflowError(
        "METHOD_PARAMETER_SCHEMA_MISSING",
        "无法定位 Conformance 权威 parameterSchema",
    )


def _validate_method_parameters(
    parameters: dict[str, Any],
) -> None:
    """Draft 2020-12 校验公共 Task parameters 与权威合同精确一致。"""
    errors = schema_errors(parameters, _conformance_parameter_schema())
    if errors:
        raise WorkflowError(
            "METHOD_PARAMETER_SCHEMA_INVALID",
            f"Conformance Task parameters 不符合 parameterSchema: {errors}",
        )


def run_workflow(
    args: argparse.Namespace,
    quickstart_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = Path(args.target).resolve(strict=True)
    output_dir = Path(args.output_dir).resolve()
    if output_dir == target or target in output_dir.parents:
        raise WorkflowError("OUTPUT_INSIDE_TARGET", "输出目录不得位于只读目标内")
    index, manifest, is_fixture, trust_policy = load_approved_rules(
        Path(args.spec_package).resolve(strict=True), args.allow_test_fixture
    )
    scope = target_scope(target, args.target_type)
    workspace = (
        workspace_receipt(
            target,
            Path(args.workspace_receipt).resolve()
            if args.workspace_receipt
            else None,
            Path(args.workspace_verifier).resolve()
            if args.workspace_verifier
            else None,
            trust_policy,
        )
        if args.target_type == "family_source"
        else None
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
    run_id = args.run_id
    task = normalized_task(
        run_id,
        target,
        args.target_type,
        output_dir,
        rule_set_digest,
        workspace,
        platform=args.platform,
        target_project_path=args.target,
        spec_version_ref=args.spec_package,
    )
    # 落盘/语义绑定前执行 Draft 2020-12 方法参数校验
    _validate_method_parameters(task["parameters"])
    task_digest = digest_bytes(canonical(task))
    reviews = semantic_reviews(
        Path(args.semantic_result).resolve() if args.semantic_result else None,
        rules,
        task_digest,
        target,
        args.target_type,
    )
    scan = checker._scan(target if target.is_dir() else target.parent)
    results = []
    for rule in rules:
        if rule.get("checkType") == "semantic":
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
    failed = [item for item in results if item["status"] != "PASS"]
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
        "target_digest": tree_digest(target if target.is_dir() else target.parent),
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
    (output_dir / "task.json").write_bytes(canonical(task) + b"\n")
    applicability_path = output_dir / "canonical-rule-applicability.json"
    applicability_path.write_bytes(canonical(canonical_applicability) + b"\n")
    findings_path = output_dir / "rule-findings.json"
    findings_path.write_bytes(canonical(results) + b"\n")
    (output_dir / "remediation-plan.json").write_bytes(
        canonical(remediation) + b"\n"
    )
    domain = {
        "schema_version": "1.0.0",
        "target_type": args.target_type,
        "target_digest": target_content_digest(target, args.target_type),
        "status": status,
        "rule_results": results,
        "canonical_rule_summary": canonical_summary,
        "canonical_rule_applicability": {
            "path": str(applicability_path),
            "content_digest": file_digest(applicability_path),
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
    domain_path.write_bytes(canonical(domain) + b"\n")
    implementation_digest = file_digest(Path(__file__).resolve())
    target_digest_value = target_content_digest(target, args.target_type)
    evidence = [{
        "evidence_id": f"{run_id}:target",
        "kind": "task_input",
        "path": str(target),
        "source": "conformance-workflow",
        "candidate_id": index.get("activeSpecRelease", {}).get(
            "releaseId", "fixture"
        ),
        "task_id": run_id,
        "environment_digest": target_digest_value,
        "rule_ref": canonical_summary["projection_digest"],
        "implementation_digest": implementation_digest,
        "executor_id": "skill-family-audit:conformance-audit",
        "sequence_number": 0,
        "content_digest": target_digest_value,
        "credibility": "verified" if not is_fixture else "self_reported",
    }]
    if workspace is not None:
        evidence.append({
            "evidence_id": f"{run_id}:workspace-verifier-receipt",
            "kind": "execution_record",
            "path": workspace["receipt_path"],
            "source": "trusted-workspace-verifier",
            "candidate_id": index.get("activeSpecRelease", {}).get(
                "releaseId", "fixture"
            ),
            "task_id": run_id,
            "environment_digest": target_digest_value,
            "rule_ref": canonical_summary["projection_digest"],
            "implementation_digest": workspace["verifier_digest"],
            "executor_id": "scripts/workspace/verify-workspace-contract.mjs",
            "sequence_number": 1,
            "content_digest": workspace["receipt_digest"],
            "credibility": "verified",
        })
    result = {
        "schema_version": "1.1.0-candidate",
        "run_id": run_id,
        "stage_id": "conformance",
        "attempt": 1,
        "execution_status": status,
        "summary": "规范检查通过" if status == "SUCCEEDED" else "规范检查失败",
        "outputs": [
            {
                "resource_id": f"{run_id}:canonical-rule-applicability",
                "name": "canonical_rule_applicability",
                "kind": "artifact",
                "path": str(applicability_path),
                "required": True,
                "content_digest": file_digest(applicability_path),
                "access": "read_only",
                "workspace_scope": "outside_workspace",
            },
            {
                "resource_id": f"{run_id}:rule-findings",
                "name": "rule_findings",
                "kind": "artifact",
                "path": str(findings_path),
                "required": True,
                "content_digest": file_digest(findings_path),
                "access": "read_only",
                "workspace_scope": "outside_workspace",
            },
            {
                "resource_id": f"{run_id}:remediation-plan",
                "name": "remediation_plan",
                "kind": "artifact",
                "path": str(output_dir / "remediation-plan.json"),
                "required": True,
                "content_digest": file_digest(
                    output_dir / "remediation-plan.json"
                ),
                "access": "read_only",
                "workspace_scope": "outside_workspace",
            },
        ],
        "domain_results": [{
            "protocol_id": "skill-family-audit:conformance-result",
            "protocol_version": "1.0.0",
            "result_path": str(domain_path),
            "content_digest": file_digest(domain_path),
        }],
        "evidence": evidence,
        "missing_inputs": [],
        "warnings": [],
        "errors": [],
        "side_effects": [],
        "producer": {
            "skill": "skill-family-audit:conformance-audit",
            "script_id": "conformance_workflow.py",
        },
        "usage": {
            "measurement_method": "observed",
            "context_limit_tokens": 1,
        },
        "extensions": [
            {
                "target_type": args.target_type,
                "target_scope": scope,
                "rule_results": results,
                "workspace_verifier_receipt": workspace,
                "test_fixture": is_fixture,
                "publication_eligible": status == "SUCCEEDED" and not is_fixture,
                "task_digest": task_digest,
                "semantic_schema_digest": file_digest(SEMANTIC_SCHEMA),
                "canonical_rule_summary": canonical_summary,
                "canonical_rule_applicability": {
                    "content_digest": file_digest(applicability_path),
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
                "remediation_status": "unapplied",
            }
        ] + ([quickstart_binding] if quickstart_binding is not None else []),
    }
    (output_dir / "result.json").write_bytes(canonical(result) + b"\n")
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--target", required=True)
    value.add_argument("--target-type", required=True, choices=sorted(TARGET_TYPES))
    value.add_argument("--spec-package", required=True)
    value.add_argument("--output-dir", required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--semantic-result")
    value.add_argument("--workspace-receipt")
    value.add_argument("--workspace-verifier")
    value.add_argument(
        "--platform",
        default="all",
        choices=["all", "claude-code", "codex", "kimi-code", "workbuddy"],
    )
    value.add_argument("--allow-test-fixture", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        quickstart_binding = consume_quickstart_task(sys.argv[1:])
        result = run_workflow(args, quickstart_binding)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["execution_status"] == "SUCCEEDED" else 1
    except (WorkflowError, OSError, ValueError) as exc:
        result = {
            "schema_version": "1.1.0-candidate",
            "run_id": args.run_id,
            "stage_id": "conformance",
            "attempt": 1,
            "execution_status": "BLOCKED",
            "summary": "规范检查被阻断",
            "outputs": [],
            "domain_results": [],
            "evidence": [],
            "missing_inputs": [],
            "warnings": [],
            "errors": [{
                "error_code": (
                    f"CONFORMANCE.{getattr(exc, 'code', 'EXECUTION_ERROR')}"
                ),
                "category": "AUTHORIZATION_INSUFFICIENT"
                if "AUTHORITY" in getattr(exc, "code", "")
                or "APPROVAL" in getattr(exc, "code", "")
                else "INPUT_INVALID",
                "stage_id": "conformance",
                "message": str(exc),
                "affected_resources": [args.target, args.spec_package],
                "evidence": [],
                "side_effect_status": "NONE",
                "retry_possible": True,
                "remediation": "提供受信任且摘要闭合的输入后重试",
            }],
            "side_effects": [],
            "blocking_reason": {
                "reason_code": getattr(exc, "code", type(exc).__name__),
                "description": str(exc),
            },
            "producer": {
                "skill": "skill-family-audit:conformance-audit",
                "script_id": "conformance_workflow.py",
            },
            "usage": {
                "measurement_method": "observed",
                "context_limit_tokens": 1,
            },
        }
        if "quickstart_binding" in locals() and quickstart_binding is not None:
            result["extensions"] = [quickstart_binding]
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
