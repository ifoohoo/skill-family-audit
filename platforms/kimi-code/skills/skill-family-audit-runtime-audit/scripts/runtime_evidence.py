"""
runtime_evidence -- runtime-audit Loop Agent 证据语义验证器

只读取调用方显式传入的三个根目录（provider_root, public_contract_root,
evidence_root），验证已安装 loop-agent 0.1.x 的真实运行证据包。

不写文件、不执行命令、不导入外部项目 Python 代码。
不捕获广义异常后返回空错误或通过。
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

LOOP_SCHEMA_FILES: dict[str, str] = {
    "process_evidence": "process-evidence.schema.json",
    "delivery_task": "delivery-task.schema.json",
    "task_result": "delivery-task-result.schema.json",
    "isolation_manifest": "case-isolation-manifest.schema.json",
    "cleanup_proof": "cleanup-proof.schema.json",
    "attempt_seal": "attempt-seal-record.schema.json",
    "finalization": "finalization-request.schema.json",
}

MATURITY_LEVELS: dict[str, dict[str, Any]] = {
    "candidate_ready": {
        "required_artifacts": {
            "process_evidence": {
                "schema_source": "loop-agent",
                "schema_filename": "process-evidence.schema.json",
            },
            "delivery_task": {
                "schema_source": "loop-agent",
                "schema_filename": "delivery-task.schema.json",
            },
            "task_result": {
                "schema_source": "loop-agent",
                "schema_filename": "delivery-task-result.schema.json",
            },
            "isolation_manifest": {
                "schema_source": "loop-agent",
                "schema_filename": "case-isolation-manifest.schema.json",
            },
        },
    },
    "consumer_qualified": {
        "required_artifacts": {
            "cleanup_proof": {
                "schema_source": "loop-agent",
                "schema_filename": "cleanup-proof.schema.json",
            },
            "attempt_seal": {
                "schema_source": "loop-agent",
                "schema_filename": "attempt-seal-record.schema.json",
            },
            "finalization": {
                "schema_source": "loop-agent",
                "schema_filename": "finalization-request.schema.json",
            },
        },
    },
    "stable": {
        "required_artifacts": {},
    },
}

# 语义交叉验证：所需最低成熟度 -> (category, json_path, label)
# 路径以 load 后的 dict 为根
_CROSS_CHECKS: list[tuple[str, str, str, str, str]] = [
    (
        "candidate_ready",
        "task_result",
        "/delivery_task_id",
        "delivery_task",
        "/delivery_task_id",
    ),
    (
        "candidate_ready",
        "task_result",
        "/process_id",
        "process_evidence",
        "/process_id",
    ),
    (
        "candidate_ready",
        "isolation_manifest",
        "/top_level_task_id",
        None,
        None,
    ),
    (
        "consumer_qualified",
        "cleanup_proof",
        "/domain_id",
        "isolation_manifest",
        "/domain_id",
    ),
    (
        "consumer_qualified",
        "finalization",
        "/run_id",
        None,
        None,
    ),
    (
        "consumer_qualified",
        "finalization",
        "/delivery_task_id",
        "delivery_task",
        "/delivery_task_id",
    ),
    (
        "consumer_qualified",
        "finalization",
        "/process_id",
        "task_result",
        "/process_id",
    ),
    (
        "consumer_qualified",
        "finalization",
        "/attempt_id",
        "attempt_seal",
        "/attempt_id",
    ),
]

# 成熟度包含关系
_MATURITY_ORDER = ["candidate_ready", "consumer_qualified", "stable"]

# Schema 摘要的键顺序
_CONTRACT_DIGEST_KEYS = [
    "loop-agent:process-evidence.schema.json",
    "loop-agent:delivery-task.schema.json",
    "loop-agent:delivery-task-result.schema.json",
    "loop-agent:case-isolation-manifest.schema.json",
    "loop-agent:cleanup-proof.schema.json",
    "loop-agent:attempt-seal-record.schema.json",
    "loop-agent:finalization-request.schema.json",
]

# 模块级缓存只保留领域绑定；Schema 编译与摘要机制由 Foundation Bundle 提供。
_schema_ids: dict[str, str] = {}
_provider_manifest_digest: str = ""
_EVIDENCE_PROFILE = (
    Path(__file__).resolve().parent.parent
    / "refs/runtime-evidence-profile.json"
)


def _foundation(request: dict[str, Any]) -> dict[str, Any]:
    """Use the canonical Audit host injected by the owning entrypoint."""
    host = sys.modules.get("conformance_check")
    if host is None:
        raise RuntimeError("FOUNDATION_TRANSPORT_MISSING")
    return host.foundation_host_for(__file__)._foundation(request)

# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class RuntimeEvidenceValidationError(Exception):
    """证据包验证失败，包含全部错误及稳定 JSON 路径。"""

    def __init__(self, errors: list[str]) -> None:
        self.errors = sorted(errors)
        super().__init__(f"runtime evidence validation failed ({len(self.errors)} errors): "
                         + "; ".join(self.errors))


# ---------------------------------------------------------------------------
# Provider 合同加载
# ---------------------------------------------------------------------------


def load_loop_provider_contract(
    provider_root: str,
    public_contract_root: str,
) -> dict[str, str]:
    """加载并验证 provider 与公共 schema，返回 {key: sha256_hex}。

    key 格式: ``"loop-agent:<filename>"`` 或 ``"spec:<filename>"``。
    """

    del public_contract_root  # 保留稳定调用签名；本方法只消费 provider 自身权威清单。
    global _provider_manifest_digest
    errors: list[str] = []
    contracts: dict[str, str] = {}

    # ---- Provider 根 ----
    if not os.path.isdir(provider_root):
        raise RuntimeEvidenceValidationError(
            [f"provider_root does not exist: {provider_root}"]
        )

    pkg_path = os.path.join(provider_root, "package.json")
    pkg: dict[str, Any] = {}
    if not os.path.isfile(pkg_path):
        errors.append("provider_root/package.json does not exist")
    elif os.path.islink(pkg_path):
        errors.append("provider_root/package.json is a symlink")
    else:
        with open(pkg_path, "r", encoding="utf-8") as f:
            pkg = json.load(f)
        if pkg.get("name") != "loop-agent":
            errors.append(
                f"provider_root/package.json name is not 'loop-agent': {pkg.get('name')!r}"
            )
    manifest_relative = "references/schema-provider-manifest.json"
    manifest_path = os.path.join(provider_root, manifest_relative)
    if not os.path.isfile(manifest_path) or os.path.islink(manifest_path):
        errors.append("provider schema manifest is missing, non-regular, or a symlink")
        manifest: dict[str, Any] = {}
    else:
        try:
            with open(manifest_path, "r", encoding="utf-8") as stream:
                manifest = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"provider schema manifest is invalid JSON: {exc}")
            manifest = {}

    provider = manifest.get("provider") if isinstance(manifest, dict) else None
    if manifest.get("schema_version") != "1.0.0" or not isinstance(provider, dict):
        errors.append("provider schema manifest identity is invalid")
    elif provider.get("name") != "loop-agent" or provider.get("version") != pkg.get("version"):
        errors.append("provider schema manifest does not match package identity")

    schema_entries = manifest.get("schemas") if isinstance(manifest, dict) else None
    by_role = {
        item.get("role"): item
        for item in schema_entries or []
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    }
    if not isinstance(schema_entries, list) or set(by_role) != set(LOOP_SCHEMA_FILES):
        errors.append("provider schema manifest must exhaustively bind the seven runtime roles")
        by_role = {}
    elif str(_foundation({
        "operation": "digest-document",
        "document": {
            "schema_version": manifest.get("schema_version"),
            "provider": provider,
            "schemas": schema_entries,
        },
    })["digest"]) != manifest.get("digest"):
        errors.append("provider schema manifest canonical digest is invalid")

    expected_paths: list[str] = ["package.json", manifest_relative]
    for role, fname in LOOP_SCHEMA_FILES.items():
        item = by_role.get(role)
        expected_path = f"references/schemas/{fname}"
        if (
            not isinstance(item, dict)
            or item.get("path") != expected_path
            or item.get("dialect") != "https://json-schema.org/draft/2020-12/schema"
            or not isinstance(item.get("$id"), str)
            or not item.get("$id")
            or not isinstance(item.get("sha256"), str)
        ):
            errors.append(f"provider schema manifest binding is invalid for role {role}")
            continue
        expected_paths.append(expected_path)

    if errors:
        raise RuntimeEvidenceValidationError(errors)

    try:
        closure = _resource_closure(provider_root, expected_paths)
    except RuntimeError as exc:
        raise RuntimeEvidenceValidationError([f"provider resource closure failed: {exc}"]) from exc
    digests = _closure_digests(closure)
    _provider_manifest_digest = digests.get(manifest_relative, "")
    _schema_ids.clear()
    for role, fname in LOOP_SCHEMA_FILES.items():
        item = by_role[role]
        key = f"loop-agent:{fname}"
        path = str(item["path"])
        actual = digests.get(path)
        if actual != item["sha256"]:
            errors.append(
                f"provider schema manifest digest mismatch for {path}: "
                f"manifest={item['sha256']!r}, actual={actual!r}"
            )
        contracts[key] = str(item["sha256"])
        _schema_ids[key] = str(item["$id"])

    if errors:
        raise RuntimeEvidenceValidationError(errors)

    return contracts


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------


def _validate_json_object(
    data: Any,
    schema_key: str,
    json_path_prefix: str,
) -> list[str]:
    """通过受管 Bundle 的固定 Schema ID 校验，保留 Audit 错误路径前缀。"""
    schema_id = _schema_ids.get(schema_key)
    if schema_id is None:
        return [f"{json_path_prefix}: schema is not bound: {schema_key}"]
    outcome = _foundation({
        "operation": "validate-by-schema-id",
        "schemaId": schema_id,
        "document": data,
    })
    if outcome.get("valid") is True:
        return []
    return [f"{json_path_prefix}: {error}" for error in outcome.get("errors", [])]


def _resource_closure(root: str, paths: list[str]) -> dict[str, Any]:
    return _foundation({
        "operation": "resource-closure",
        "root": root,
        "resources": [
            {"path": path, "role": "input"}
            for path in sorted(paths)
        ],
    })


def _closure_digests(closure: dict[str, Any]) -> dict[str, str]:
    return {
        str(item["path"]): str(item["sha256"])
        for item in closure.get("resources", [])
        if item.get("exists") is True
    }


def _resolve_and_validate_path(
    rel_path: str,
    evidence_root: str,
    label: str,
) -> tuple[str | None, list[str]]:
    """验证相对路径安全性，返回 (绝对路径, 错误列表)。

    验证：非空、非绝对、不含 ..、解析后仍在 evidence_root、
    路径本身及所有祖先均非符号链接。
    """
    errors: list[str] = []

    if not isinstance(rel_path, str) or not rel_path:
        errors.append(f"{label} path: must be a non-empty string")
        return None, errors
    if os.path.isabs(rel_path):
        errors.append(f"{label} path: must be relative, got absolute: {rel_path}")
        return None, errors
    parts = PurePosixPath(rel_path).parts
    if ".." in parts:
        errors.append(f"{label} path: must not contain '..': {rel_path}")
        return None, errors

    try:
        _foundation({
            "operation": "resolve-contained",
            "root": evidence_root,
            "path": rel_path,
        })
    except RuntimeError as exc:
        errors.append(f"{label} path rejected by Foundation: {rel_path}: {exc}")
        return None, errors
    return os.path.normpath(os.path.join(evidence_root, rel_path)), errors


def _validate_evidence_entry(
    category: str,
    artifact: Any,
    evidence_root: str,
    provider_contracts: dict[str, str],
    category_spec: dict[str, str],
) -> tuple[dict[str, Any] | None, list[str]]:
    """验证单个证据条目：路径安全、存在、JSON 有效、摘要匹配、Schema 校验。

    返回 (解析后的 JSON 内容或 None, 错误列表)。
    """
    errors: list[str] = []
    prefix = f"/artifacts/{category}"
    result: dict[str, Any] | None = None

    if not isinstance(artifact, dict):
        return None, [f"{prefix}: must be an object"]

    allowed_fields = {"path", "content_digest", "schema_source", "schema_filename", "schema_digest"}

    # 字段存在性
    for field in allowed_fields:
        if field not in artifact:
            errors.append(f"{prefix}: missing required field '{field}'")

    # 拒绝额外字段（纠偏 #4）
    extra = set(artifact.keys()) - allowed_fields
    for k in sorted(extra):
        errors.append(f"{prefix}: unknown field: {k}")

    rel_path = artifact.get("path", "")
    content_digest = artifact.get("content_digest", "")
    schema_source = artifact.get("schema_source", "")
    schema_filename = artifact.get("schema_filename", "")
    schema_digest = artifact.get("schema_digest", "")

    # 路径验证
    abs_path, path_errors = _resolve_and_validate_path(
        rel_path, evidence_root, f"{prefix}/path"
    )
    errors.extend(path_errors)
    if abs_path is None:
        return None, errors

    # 文件存在性
    if not os.path.isfile(abs_path):
        errors.append(f"{prefix}/path: file does not exist: {rel_path}")
        return None, errors

    # 文件内容 JSON 有效性
    with open(abs_path, "rb") as f:
        raw_bytes = f.read()
    try:
        content = json.loads(raw_bytes)
    except json.JSONDecodeError as e:
        errors.append(f"{prefix}/path: invalid JSON: {e}")
        return None, errors

    # content_digest 由 Foundation resource closure 对原始字节复算。
    try:
        actual_cd = _closure_digests(
            _resource_closure(evidence_root, [rel_path])
        )[rel_path]
    except (RuntimeError, KeyError) as exc:
        errors.append(f"{prefix}/content_digest: Foundation closure failed: {exc}")
        return None, errors
    if content_digest != actual_cd:
        errors.append(
            f"{prefix}/content_digest: mismatch: expected {actual_cd}, got {content_digest}"
        )

    # schema_source / schema_filename 基本格式
    if not isinstance(schema_source, str) or schema_source not in ("loop-agent", "spec"):
        errors.append(
            f"{prefix}/schema_source: must be 'loop-agent' or 'spec', got {schema_source!r}"
        )

    if not isinstance(schema_filename, str) or not schema_filename:
        errors.append(f"{prefix}/schema_filename: must be a non-empty string")

    # schema_source / schema_filename 与 MATURITY_LEVELS 精确绑定比较（纠偏 #1）
    expected_source = category_spec.get("schema_source", "")
    expected_filename = category_spec.get("schema_filename", "")
    if schema_source != expected_source:
        errors.append(
            f"{prefix}/schema_source: expected {expected_source!r} "
            f"per MATURITY_LEVELS binding, got {schema_source!r}"
        )
    if schema_filename != expected_filename:
        errors.append(
            f"{prefix}/schema_filename: expected {expected_filename!r} "
            f"per MATURITY_LEVELS binding, got {schema_filename!r}"
        )

    # schema_digest 匹配 provider_contracts
    contract_key = f"{schema_source}:{schema_filename}"
    expected_sd = provider_contracts.get(contract_key)
    if expected_sd is None:
        if schema_source in ("loop-agent", "spec") and schema_filename:
            errors.append(
                f"{prefix}/schema_digest: unknown schema key {contract_key!r} "
                "in provider contracts"
            )
    elif schema_digest != expected_sd:
        errors.append(
            f"{prefix}/schema_digest: mismatch for {contract_key}: "
            f"expected {expected_sd}, got {schema_digest}"
        )

    # JSON Schema 校验
    schema_key = contract_key
    if schema_key in _schema_ids:
        schema_errors = _validate_json_object(content, schema_key, f"{prefix}/content")
        errors.extend(schema_errors)
    elif expected_sd is not None:
        errors.append(
            f"{prefix}: schema loaded in contracts but not in cache: {contract_key}"
        )

    if not errors:
        result = content

    return result, errors


def _check_bundle_metadata(bundle: dict[str, Any]) -> list[str]:
    """验证 bundle 顶层结构字段。"""
    errors: list[str] = []

    if not isinstance(bundle, dict):
        return ["bundle: must be an object"]

    # 拒绝顶层额外字段（纠偏 #4）
    _allowed_top = {
        "schema_version", "provider", "identity",
        "artifacts", "stable_consumers", "control_scenarios",
    }
    for k in sorted(set(bundle.keys()) - _allowed_top):
        errors.append(f"/: unknown field: {k}")

    # schema_version
    sv = bundle.get("schema_version")
    if sv != "1.0.0-candidate":
        errors.append(f"/schema_version: must be '1.0.0-candidate', got {sv!r}")

    # provider
    provider = bundle.get("provider")
    if not isinstance(provider, dict):
        errors.append("/provider: must be an object")
        return errors  # 无法继续

    # 拒绝 provider 额外字段（纠偏 #4）
    _allowed_provider = {"provider_id", "provider_version", "provider_manifest_digest", "contract_digest"}
    for k in sorted(set(provider.keys()) - _allowed_provider):
        errors.append(f"/provider: unknown field: {k}")

    pid = provider.get("provider_id")
    if pid != "loop-agent":
        errors.append(f"/provider/provider_id: must be 'loop-agent', got {pid!r}")

    for field in ("provider_version", "provider_manifest_digest", "contract_digest"):
        if not provider.get(field):
            errors.append(f"/provider/{field}: must be a non-empty string")

    # identity
    identity = bundle.get("identity")
    if not isinstance(identity, dict):
        errors.append("/identity: must be an object")
        return errors

    # 拒绝 identity 额外字段（纠偏 #4）
    _allowed_identity = {
        "run_id",
        "task_id",
        "platform",
        "method_id",
        "candidate_id",
    }
    for k in sorted(set(identity.keys()) - _allowed_identity):
        errors.append(f"/identity: unknown field: {k}")

    for field in ("run_id", "task_id", "platform", "candidate_id"):
        if not identity.get(field):
            errors.append(f"/identity/{field}: must be a non-empty string")

    mid = identity.get("method_id")
    if mid != "skill-family-audit:runtime-audit":
        errors.append(
            f"/identity/method_id: must be 'skill-family-audit:runtime-audit', got {mid!r}"
        )

    # artifacts
    artifacts = bundle.get("artifacts")
    if not isinstance(artifact_dict := artifacts, dict):
        errors.append("/artifacts: must be an object")

    # stable_consumers / control_scenarios 存在性
    if not isinstance(bundle.get("stable_consumers"), list):
        errors.append("/stable_consumers: must be an array")
    if not isinstance(bundle.get("control_scenarios"), list):
        errors.append("/control_scenarios: must be an array")

    return errors


def _validate_bundle_metadata(
    bundle: dict[str, Any],
    provider_contracts: dict[str, str],
) -> list[str]:
    """验证 bundle 元数据与 provider 合同的一致性。"""
    errors = _check_bundle_metadata(bundle)
    if (
        not isinstance(bundle, dict)
        or not isinstance(bundle.get("provider"), dict)
        or not isinstance(bundle.get("identity"), dict)
        or not isinstance(bundle.get("artifacts"), dict)
        or not isinstance(bundle.get("stable_consumers"), list)
        or not isinstance(bundle.get("control_scenarios"), list)
    ):
        return errors

    provider = bundle["provider"]

    # 版本完全一致
    manifest_digest = provider.get("provider_manifest_digest", "")
    contract_digest = provider.get("contract_digest", "")
    bundle_version = provider.get("provider_version", "")

    if bundle_version != _cached_provider_version:
        errors.append(
            f"/provider/provider_version: bundle={bundle_version!r} "
            f"!= actual={_cached_provider_version!r}"
        )

    # provider_manifest_digest 与 package.json 独立复算匹配
    if manifest_digest != _cached_manifest_digest:
        errors.append(
            f"/provider/provider_manifest_digest: mismatch: "
            f"expected {_cached_manifest_digest}, got {manifest_digest}"
        )

    # contract_digest 与独立加载的 schema 摘要映射匹配
    expected_cd = _compute_contract_digest(provider_contracts)
    if contract_digest != expected_cd:
        errors.append(
            f"/provider/contract_digest: mismatch: "
            f"expected {expected_cd}, got {contract_digest}"
        )

    return errors


# Provider 合同加载时缓存的值
_cached_provider_version: str = ""
_cached_manifest_digest: str = ""


def _load_provider_contract_and_cache(
    provider_root: str,
    public_contract_root: str,
) -> dict[str, str]:
    """加载 provider 合同并缓存 package.json 摘要和版本。"""
    global _cached_provider_version, _cached_manifest_digest

    contracts = load_loop_provider_contract(provider_root, public_contract_root)

    # 缓存 package.json resource-closure 摘要和版本。
    pkg_path = os.path.join(provider_root, "package.json")
    _cached_manifest_digest = _closure_digests(
        _resource_closure(provider_root, ["package.json"])
    )["package.json"]
    with open(pkg_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)
    _cached_provider_version = pkg["version"]

    return contracts


def _validate_frozen_evidence_profile(
    provider_root: str,
    provider_contracts: dict[str, str],
) -> list[str]:
    """Bind runtime validation to the immutable consumer profile."""
    try:
        profile = json.loads(_EVIDENCE_PROFILE.read_text(encoding="utf-8"))
        package_path = Path(provider_root) / "package.json"
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"runtime evidence profile unavailable: {exc}"]
    try:
        package_digest = _closure_digests(
            _resource_closure(provider_root, ["package.json"])
        )["package.json"]
    except (RuntimeError, KeyError) as exc:
        return [f"runtime evidence provider closure unavailable: {exc}"]
    provider = next(
        (
            item
            for item in profile.get("allowed_providers", [])
            if item.get("provider_id") == package.get("name")
            and item.get("package_digest") == package_digest
        ),
        None,
    )
    errors: list[str] = []
    if provider is None:
        errors.append(
            "provider identity/package digest is not allowed by "
            "runtime-evidence-profile.json"
        )
    if provider is not None and provider.get("schema_provider_manifest_digest") != _provider_manifest_digest:
        errors.append(
            "provider schema manifest digest is not allowed by "
            "runtime-evidence-profile.json"
        )
    return errors


def _compute_contract_digest(contracts: dict[str, str]) -> str:
    """由 Foundation 对有序合同映射做规范 JSON 摘要。"""
    ordered = {k: contracts[k] for k in _CONTRACT_DIGEST_KEYS if k in contracts}
    return str(_foundation({
        "operation": "digest-document",
        "document": ordered,
    })["digest"])


def _validate_artifacts(
    bundle: dict[str, Any],
    evidence_root: str,
    provider_contracts: dict[str, str],
    required_artifacts: dict[str, dict[str, str]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """验证指定的 artifact 条目，返回 ({category: content}, errors)。"""
    errors: list[str] = []
    artifacts = bundle.get("artifacts", {})
    loaded: dict[str, dict[str, Any]] = {}

    for cat, spec in required_artifacts.items():
        if cat not in artifacts:
            schema_source = spec["schema_source"]
            schema_filename = spec["schema_filename"]
            errors.append(
                f"/artifacts/{cat}: missing required artifact for maturity "
                f"(expected schema: {schema_source}:{schema_filename})"
            )
            continue

        content, cat_errors = _validate_evidence_entry(
            cat, artifacts[cat], evidence_root, provider_contracts, spec
        )
        errors.extend(cat_errors)
        if content is not None:
            loaded[cat] = content

    return loaded, errors


def _validate_identity_cross_checks(
    loaded: dict[str, dict[str, Any]],
    bundle: dict[str, Any],
    checks: list[tuple[str, str, str, str | None, str | None]],
    current_maturity: str,
) -> list[str]:
    """执行跨证据身份一致性检查。"""
    errors: list[str] = []
    current_idx = _MATURITY_ORDER.index(current_maturity)

    for required_maturity, cat_a, path_a, cat_b_opt, path_b_opt in checks:
        req_idx = _MATURITY_ORDER.index(required_maturity)
        if current_idx < req_idx:
            continue
        if cat_a not in loaded:
            continue

        val_a = loaded[cat_a]
        for segment in path_a.strip("/").split("/"):
            if isinstance(val_a, dict):
                val_a = val_a.get(segment)
            else:
                val_a = None
                break

        if cat_b_opt is not None and path_b_opt is not None:
            if cat_b_opt not in loaded:
                continue
            val_b = loaded[cat_b_opt]
            for segment in path_b_opt.strip("/").split("/"):
                if isinstance(val_b, dict):
                    val_b = val_b.get(segment)
                else:
                    val_b = None
                    break

            json_path = f"/artifacts/{cat_a}{path_a}"
            if val_a != val_b:
                errors.append(
                    f"cross-check: {cat_a}{path_a}={val_a!r} "
                    f"!= {cat_b_opt}{path_b_opt}={val_b!r}"
                )
        else:
            # 与 bundle identity 比较
            identity = bundle.get("identity", {})
            field = path_a.strip("/")

            if cat_a == "isolation_manifest" and field == "top_level_task_id":
                expected = identity.get("task_id")
                if val_a != expected:
                    errors.append(
                        f"cross-check: isolation_manifest/top_level_task_id={val_a!r} "
                        f"!= identity/task_id={expected!r}"
                    )
            elif cat_a == "finalization" and field == "run_id":
                expected = identity.get("run_id")
                if val_a != expected:
                    errors.append(
                        f"cross-check: finalization/run_id={val_a!r} "
                        f"!= identity/run_id={expected!r}"
                    )

    return errors


def _validate_stable_requirements(
    bundle: dict[str, Any],
    evidence_root: str,
) -> list[str]:
    """验证 stable 成熟度的额外要求。"""
    errors: list[str] = []
    stable_consumers = bundle.get("stable_consumers", [])
    control_scenarios = bundle.get("control_scenarios", [])

    # --- stable_consumers ---
    if len(stable_consumers) < 2:
        errors.append(
            f"/stable_consumers: must have at least 2 items, got {len(stable_consumers)}"
        )

    domains: set[str] = set()
    for idx, consumer in enumerate(stable_consumers):
        prefix = f"/stable_consumers[{idx}]"
        if not isinstance(consumer, dict):
            errors.append(f"{prefix}: must be an object")
            continue

        _allowed_consumer = {"consumer_id", "consumer_domain", "validation_status",
                             "evidence_path", "content_digest"}
        for field in _allowed_consumer:
            if field not in consumer:
                errors.append(f"{prefix}: missing required field '{field}'")

        # 拒绝额外字段（纠偏 #4）
        for k in sorted(set(consumer.keys()) - _allowed_consumer):
            errors.append(f"{prefix}: unknown field: {k}")

        # consumer_id 必须是非空字符串（纠偏 #6）
        cid = consumer.get("consumer_id")
        if not isinstance(cid, str) or not cid:
            errors.append(f"{prefix}/consumer_id: must be a non-empty string")

        vs = consumer.get("validation_status")
        if vs != "PASS":
            errors.append(
                f"{prefix}/validation_status: must be 'PASS', got {vs!r}"
            )

        domain = consumer.get("consumer_domain")
        if isinstance(domain, str) and domain:
            domains.add(domain)
        else:
            errors.append(f"{prefix}/consumer_domain: must be a non-empty string")

        # 证据文件验证
        ep = consumer.get("evidence_path", "")
        abs_path, path_errors = _resolve_and_validate_path(
            ep, evidence_root, f"{prefix}/evidence_path"
        )
        errors.extend(path_errors)

        if abs_path is not None:
            if not os.path.isfile(abs_path):
                errors.append(f"{prefix}/evidence_path: file does not exist: {ep}")
            else:
                try:
                    actual_cd = _closure_digests(
                        _resource_closure(evidence_root, [ep])
                    )[ep]
                except (RuntimeError, KeyError) as exc:
                    errors.append(f"{prefix}/content_digest: Foundation closure failed: {exc}")
                    continue
                expected_cd = consumer.get("content_digest", "")
                if expected_cd != actual_cd:
                    errors.append(
                        f"{prefix}/content_digest: mismatch: "
                        f"expected {actual_cd}, got {expected_cd}"
                    )

    if len(domains) < 2:
        errors.append(
            f"/stable_consumers: must have at least 2 distinct consumer_domain values, "
            f"got {len(domains)}"
        )

    # --- control_scenarios ---
    required_types = {"environment_failure", "business_rejection", "uncertain_result"}
    seen_types: set[str] = set()

    for idx, scenario in enumerate(control_scenarios):
        prefix = f"/control_scenarios[{idx}]"
        if not isinstance(scenario, dict):
            errors.append(f"{prefix}: must be an object")
            continue

        _allowed_scenario = {"scenario_type", "scenario_outcome", "evidence_path", "content_digest"}
        for field in _allowed_scenario:
            if field not in scenario:
                errors.append(f"{prefix}: missing required field '{field}'")

        # 拒绝额外字段（纠偏 #4）
        for k in sorted(set(scenario.keys()) - _allowed_scenario):
            errors.append(f"{prefix}: unknown field: {k}")

        # scenario_outcome 必须是非空字符串（纠偏 #6）
        so = scenario.get("scenario_outcome")
        if not isinstance(so, str) or not so:
            errors.append(f"{prefix}/scenario_outcome: must be a non-empty string")

        st = scenario.get("scenario_type")
        if not isinstance(st, str) or not st:
            errors.append(f"{prefix}/scenario_type: must be a non-empty string")
        elif st not in required_types:
            errors.append(f"{prefix}/scenario_type: unknown scenario type: {st!r}")
        elif st in seen_types:
            errors.append(f"{prefix}/scenario_type: duplicate scenario type: {st!r}")
        else:
            seen_types.add(st)

        # 证据文件验证
        ep = scenario.get("evidence_path", "")
        abs_path, path_errors = _resolve_and_validate_path(
            ep, evidence_root, f"{prefix}/evidence_path"
        )
        errors.extend(path_errors)

        if abs_path is not None:
            if not os.path.isfile(abs_path):
                errors.append(f"{prefix}/evidence_path: file does not exist: {ep}")
            else:
                try:
                    actual_cd = _closure_digests(
                        _resource_closure(evidence_root, [ep])
                    )[ep]
                except (RuntimeError, KeyError) as exc:
                    errors.append(f"{prefix}/content_digest: Foundation closure failed: {exc}")
                    continue
                expected_cd = scenario.get("content_digest", "")
                if expected_cd != actual_cd:
                    errors.append(
                        f"{prefix}/content_digest: mismatch: "
                        f"expected {actual_cd}, got {expected_cd}"
                    )

    missing_types = required_types - seen_types
    if missing_types:
        errors.append(
            f"/control_scenarios: missing required scenario types: "
            + ", ".join(sorted(missing_types))
        )

    return errors


# ---------------------------------------------------------------------------
# 内部主验证
# ---------------------------------------------------------------------------


def _validate_bundle(
    bundle: dict[str, Any],
    *,
    evidence_root: str,
    provider_contracts: dict[str, str],
    maturity_level: str,
) -> list[str]:
    """主验证逻辑。validator 缓存在每次验证入口清空（纠偏 #9）。"""
    errors: list[str] = []

    # ---- 0. evidence_root 真实存在且非符号链接（纠偏 #5） ----
    if not os.path.isdir(evidence_root):
        errors.append(f"evidence_root does not exist or is not a directory: {evidence_root}")
    elif os.path.islink(evidence_root):
        errors.append(f"evidence_root must not be a symlink: {evidence_root}")

    # ---- 1. Bundle 元数据 ----
    meta_errors = _validate_bundle_metadata(bundle, provider_contracts)
    errors.extend(meta_errors)
    if (
        not isinstance(bundle, dict)
        or not isinstance(bundle.get("provider"), dict)
        or not isinstance(bundle.get("identity"), dict)
        or not isinstance(bundle.get("artifacts"), dict)
        or not isinstance(bundle.get("stable_consumers"), list)
        or not isinstance(bundle.get("control_scenarios"), list)
    ):
        return sorted(errors)

    # ---- 2. 累积 maturity 所需 artifact ----
    all_required: dict[str, dict[str, str]] = {}
    maturity_idx = _MATURITY_ORDER.index(maturity_level)
    for i in range(maturity_idx + 1):
        level = _MATURITY_ORDER[i]
        all_required.update(MATURITY_LEVELS[level]["required_artifacts"])

    # ---- 3. 逐条验证 artifact ----
    loaded, art_errors = _validate_artifacts(
        bundle, evidence_root, provider_contracts, all_required
    )
    errors.extend(art_errors)

    # ---- 4. 跨证据身份检查（仅对已成功加载的 category 执行） ----
    cross_errors = _validate_identity_cross_checks(
        loaded, bundle, _CROSS_CHECKS, maturity_level
    )
    errors.extend(cross_errors)

    # ---- 5. Stable 额外要求（不因 artifact 失败跳过，纠偏 #8） ----
    if maturity_level == "stable":
        stable_errors = _validate_stable_requirements(bundle, evidence_root)
        errors.extend(stable_errors)

    return sorted(errors)


# ---------------------------------------------------------------------------
# 公共 API
# ---------------------------------------------------------------------------


def validate_runtime_evidence_bundle(
    bundle: dict[str, Any],
    *,
    evidence_root: str,
    provider_root: str,
    public_contract_root: str,
    maturity_level: str,
) -> list[str]:
    """验证运行时证据包，返回错误列表（空列表表示通过）。"""

    if maturity_level not in MATURITY_LEVELS:
        return [f"unknown maturity_level: {maturity_level!r}"]

    try:
        provider_contracts = _load_provider_contract_and_cache(
            provider_root, public_contract_root
        )
    except RuntimeEvidenceValidationError as e:
        return e.errors

    profile_errors = _validate_frozen_evidence_profile(
        provider_root, provider_contracts
    )
    return sorted(profile_errors + _validate_bundle(
        bundle,
        evidence_root=evidence_root,
        provider_contracts=provider_contracts,
        maturity_level=maturity_level,
    ))


def assert_valid_runtime_evidence(
    bundle: dict[str, Any],
    *,
    evidence_root: str,
    provider_root: str,
    public_contract_root: str,
    maturity_level: str,
) -> None:
    """验证运行时证据包，任一错误时抛出 RuntimeEvidenceValidationError。"""

    errors = validate_runtime_evidence_bundle(
        bundle,
        evidence_root=evidence_root,
        provider_root=provider_root,
        public_contract_root=public_contract_root,
        maturity_level=maturity_level,
    )
    if errors:
        raise RuntimeEvidenceValidationError(errors)
