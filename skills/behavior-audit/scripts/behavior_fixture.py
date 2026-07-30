"""behavior-audit 夹具与隔离证明验证器。

本模块只读取和验证行为夹具清单、外部沙箱证明、执行授权和可执行文件。
不运行命令、不写文件、不访问网络、不导入外部代码。
执行器将在后续独立任务中实现。
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

_SCHEMA_FILES: dict[str, str] = {
    "behavior-fixture-manifest": "behavior-fixture-manifest.schema.json",
    "isolation-profile": "isolation-profile.schema.json",
}


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------


class BehaviorFixtureValidationError(Exception):
    """夹具验证失败，包含所有聚合错误。"""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        lines = [f"fixture validation failed with {len(self.errors)} error(s):"]
        for i, err in enumerate(self.errors, 1):
            lines.append(f"  [{i}] {err}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------


def _schema_dir() -> Path:
    script_path = Path(__file__).resolve()
    for root in script_path.parents:
        projected = root / "shared" / "contracts"
        if (root / "platform-manifest.json").is_file() and projected.is_dir():
            return projected
    source_root = script_path.parents[4] / "spec" / "contracts"
    if source_root.is_dir():
        return source_root
    raise FileNotFoundError(
        "cannot locate public contract root (shared/contracts or spec/contracts)"
    )


def load_fixture_schemas() -> dict[str, dict[str, Any]]:
    """加载并返回全部夹具相关 JSON Schema，按逻辑名索引。"""

    schemas: dict[str, dict[str, Any]] = {}
    sdir = _schema_dir()
    for logical_name, filename in _SCHEMA_FILES.items():
        path = sdir / filename
        if not path.is_file():
            raise FileNotFoundError(f"schema not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            schemas[logical_name] = json.load(f)
    return schemas


def _build_schema_registry(schemas: dict[str, dict[str, Any]]) -> Registry:
    """为 Draft 2020-12 构建包含所有 schema 的引用注册表。"""

    registry = Registry()
    for schema in schemas.values():
        uri = schema.get("$id", "")
        if uri:
            registry = registry.with_resource(
                uri, Resource.from_contents(schema, DRAFT202012)
            )
    return registry


# ---------------------------------------------------------------------------
# Path safety helpers
# ---------------------------------------------------------------------------


def _resolve_no_symlink(path: Path, label: str, errors: list[str]) -> Path | None:
    """解析路径，检查符号链接。返回 resolved Path 或 None（错误已追加）。"""
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        errors.append(f"{label}: cannot resolve {path} — {exc}")
        return None

    # 逐段检查祖先是否含符号链接
    current = path
    segments: list[Path] = []
    while current != current.parent:
        segments.append(current)
        current = current.parent
    segments.append(current)  # root

    for seg in reversed(segments):
        try:
            if seg.is_symlink():
                errors.append(f"{label}: symlink detected at {seg}")
                return None
        except OSError:
            pass

    return resolved


def _assert_absolute(path: Path, label: str, errors: list[str]) -> None:
    if not path.is_absolute():
        errors.append(f"{label}: must be absolute, got {path}")


def _assert_within(path: Path, root: Path, label: str, errors: list[str]) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        errors.append(f"{label}: {path} is not within sandbox root {root}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path, label: str, errors: list[str]) -> Any | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"{label}: failed to load JSON from {path} — {exc}")
        return None


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def validate_fixture_schema(
    instance: Any,
    schema_name: str,
    schemas: dict[str, dict[str, Any]] | None = None,
    registry: Registry | None = None,
) -> list[str]:
    """用指定 schema 校验实例，返回错误列表（空表示通过）。"""

    if schemas is None:
        schemas = load_fixture_schemas()
    if schema_name not in schemas:
        raise KeyError(f"unknown schema: {schema_name}")

    schema = schemas[schema_name]
    if registry is None:
        registry = _build_schema_registry(schemas)

    validator = Draft202012Validator(schema, registry=registry)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        path_str = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"[{path_str}] {error.message}")
    return errors


# ---------------------------------------------------------------------------
# Semantic gates (per plan §Schema 与语义门禁)
# ---------------------------------------------------------------------------


def _validate_provider_proof(
    *,
    proof: dict[str, Any],
    manifest_ep: dict[str, Any],
    isolation_profile: dict[str, Any],
    sandbox_root: Path,
    target_project_path: Path,
    platform_selector: str,
    model_selector: str,
    scope_selector: str,
    errors: list[str],
) -> None:
    """门禁 5：provider proof 逐字段绑定检查。"""

    for field in (
        "provider_id",
        "provider_version",
        "isolation_id",
        "sandbox_root",
        "target_project_path",
        "platform_selector",
        "model_selector",
        "scope_selector",
    ):
        proof_val = proof.get(field)
        if field in ("provider_id", "provider_version"):
            expected = manifest_ep.get(field)
        elif field == "isolation_id":
            expected = isolation_profile.get("isolation_id")
        elif field == "sandbox_root":
            expected = str(sandbox_root)
        elif field == "target_project_path":
            expected = str(target_project_path)
        else:
            expected = {"platform_selector": platform_selector, "model_selector": model_selector, "scope_selector": scope_selector}[field]

        if str(proof_val) != str(expected):
            errors.append(f"provider proof field '{field}': got '{proof_val}', expected '{expected}'")

    # control_plane_proof 必须等于 isolation profile 中的同名值
    proof_cpp = proof.get("control_plane_proof")
    iso_cpp = isolation_profile.get("control_plane_proof")
    if proof_cpp != iso_cpp:
        errors.append(
            f"provider proof control_plane_proof mismatch: proof='{proof_cpp}', isolation='{iso_cpp}'"
        )


def _validate_authorization_receipt(
    *,
    receipt: dict[str, Any],
    manifest_auth: dict[str, Any],
    candidate: dict[str, Any],
    platform_selector: str,
    model_selector: str,
    scope_selector: str,
    actual_fixture_ids: set[str],
    now_utc: datetime,
    errors: list[str],
) -> None:
    """门禁 6：authorization receipt 逐字段绑定与过期检查。"""

    for field in ("authorization_id",):
        if receipt.get(field) != manifest_auth.get(field):
            errors.append(f"receipt field '{field}': got '{receipt.get(field)}', expected '{manifest_auth.get(field)}'")

    if receipt.get("approver") in (None, ""):
        errors.append("receipt missing 'approver'")

    if receipt.get("approved") is not True:
        errors.append(f"receipt 'approved' must be true, got {receipt.get('approved')}")

    # candidate id/digest
    if receipt.get("candidate_id") != candidate.get("candidate_id"):
        errors.append("receipt candidate_id mismatch")
    if receipt.get("candidate_digest") != candidate.get("candidate_digest"):
        errors.append("receipt candidate_digest mismatch")

    # 三个 selector
    for sel_field, expected in (
        ("platform_selector", platform_selector),
        ("model_selector", model_selector),
        ("scope_selector", scope_selector),
    ):
        if receipt.get(sel_field) != expected:
            errors.append(f"receipt '{sel_field}': got '{receipt.get(sel_field)}', expected '{expected}'")

    # authorized_fixture_ids 与实际 fixture id 集合必须完全相等
    receipt_ids = set(receipt.get("authorized_fixture_ids", []))
    if receipt_ids != actual_fixture_ids:
        missing = actual_fixture_ids - receipt_ids
        extra = receipt_ids - actual_fixture_ids
        if missing:
            errors.append(f"receipt authorized_fixture_ids missing: {sorted(missing)}")
        if extra:
            errors.append(f"receipt authorized_fixture_ids extra: {sorted(extra)}")

    manifest_ids = set(manifest_auth.get("authorized_fixture_ids", []))
    if manifest_ids != actual_fixture_ids:
        errors.append(
            "manifest authorized_fixture_ids must exactly equal fixture ids"
        )
    if manifest_ids != receipt_ids:
        errors.append(
            "manifest and receipt authorized_fixture_ids must be identical"
        )

    # 过期时间：manifest 和 receipt 必须一致，且 now_utc 必须带时区。
    expires_str = receipt.get("expires_at")
    if expires_str != manifest_auth.get("expires_at"):
        errors.append("manifest and receipt expires_at must be identical")
    if now_utc.tzinfo is None or now_utc.utcoffset() is None:
        errors.append("now_utc must be timezone-aware")
        return
    if expires_str:
        try:
            expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if now_utc >= expires_at:
                errors.append(f"authorization expired: now={now_utc.isoformat()}, expires={expires_str}")
        except (ValueError, TypeError):
            errors.append(f"receipt expires_at not parseable: {expires_str}")


def _validate_fixtures(
    *,
    fixtures: list[dict[str, Any]],
    sandbox_root: Path,
    writable_roots: list[Path],
    errors: list[str],
) -> None:
    """门禁 7–9：可执行文件、cwd、write_set、expected output、唯一性。"""

    seen_ids: set[str] = set()

    for idx, fixture in enumerate(fixtures):
        prefix = f"fixtures[{idx}]"
        fid = fixture.get("fixture_id", "")

        # 9: fixture id 唯一
        if fid in seen_ids:
            errors.append(f"{prefix}: duplicate fixture_id '{fid}'")
        seen_ids.add(fid)

        argv = fixture.get("argv", [])
        if not argv:
            errors.append(f"{prefix} ({fid}): argv is empty")
            continue

        # 7: argv[0] 必须是 sandbox 内的绝对普通可执行文件
        exe = Path(argv[0])
        if not exe.is_absolute():
            errors.append(f"{prefix} ({fid}): argv[0] must be absolute, got {exe}")
        else:
            exe_resolved = _resolve_no_symlink(exe, f"{prefix} ({fid}) argv[0]", errors)
            if exe_resolved is not None:
                _assert_within(exe_resolved, sandbox_root, f"{prefix} ({fid}) argv[0]", errors)
                if not exe_resolved.is_file():
                    errors.append(f"{prefix} ({fid}): argv[0] not a file: {exe}")
                elif not os.access(exe_resolved, os.X_OK):
                    errors.append(f"{prefix} ({fid}): argv[0] not executable: {exe}")
                else:
                    actual_digest = _sha256_file(exe_resolved)
                    expected_digest = fixture.get("executable_digest", "")
                    if actual_digest != expected_digest:
                        errors.append(
                            f"{prefix} ({fid}): executable_digest mismatch: "
                            f"actual={actual_digest}, expected={expected_digest}"
                        )

        # 8: cwd 必须是 sandbox 内已存在的普通目录
        cwd_rel = fixture.get("cwd", "")
        cwd_path = Path(os.path.normpath(os.path.join(str(sandbox_root), cwd_rel)))
        cwd_resolved = _resolve_no_symlink(cwd_path, f"{prefix} ({fid}) cwd", errors)
        if cwd_resolved is not None:
            _assert_within(cwd_resolved, sandbox_root, f"{prefix} ({fid}) cwd", errors)
            if not cwd_resolved.is_dir():
                errors.append(f"{prefix} ({fid}): cwd does not exist or is not a directory: {cwd_path}")
            elif not any(
                _is_within(cwd_resolved, writable_root)
                for writable_root in writable_roots
            ):
                errors.append(
                    f"{prefix} ({fid}): cwd is outside isolation writable_roots"
                )

        # 8: write_set 和 expected output 必须在 cwd 内
        write_set = fixture.get("write_set", [])
        write_resolved: list[Path] = []
        for ws_rel in write_set:
            ws_path = Path(os.path.normpath(os.path.join(str(sandbox_root), cwd_rel, ws_rel)))
            ws_resolved = _resolve_no_symlink(ws_path, f"{prefix} ({fid}) write_set '{ws_rel}'", errors)
            if ws_resolved is not None:
                if cwd_resolved is not None:
                    _assert_within(ws_resolved, cwd_resolved, f"{prefix} ({fid}) write_set '{ws_rel}'", errors)
                # 9: write_set 目标在执行前必须不存在
                if ws_resolved.exists():
                    errors.append(f"{prefix} ({fid}): write_set target already exists: {ws_path}")
                write_resolved.append(ws_resolved)

        # expected output_files
        expected = fixture.get("expected", {})
        output_files = expected.get("output_files", [])
        output_paths: set[str] = set()
        for of in output_files:
            of_rel = of.get("path", "")
            output_paths.add(of_rel)
            of_path = Path(os.path.normpath(os.path.join(str(sandbox_root), cwd_rel, of_rel)))
            of_resolved = _resolve_no_symlink(of_path, f"{prefix} ({fid}) output_file '{of_rel}'", errors)
            if of_resolved is not None and cwd_resolved is not None:
                _assert_within(of_resolved, cwd_resolved, f"{prefix} ({fid}) output_file '{of_rel}'", errors)

        # 8: expected output 集合必须是 write_set 子集
        ws_set = set(write_set)
        for of_rel in output_paths:
            if of_rel not in ws_set:
                errors.append(
                    f"{prefix} ({fid}): expected output_file '{of_rel}' not in write_set"
                )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validated_writable_roots(
    isolation_profile: dict[str, Any],
    sandbox_root: Path,
    errors: list[str],
) -> list[Path]:
    roots: list[Path] = []
    for idx, raw_root in enumerate(isolation_profile.get("writable_roots", [])):
        path = Path(raw_root)
        label = f"isolation_profile.writable_roots[{idx}]"
        _assert_absolute(path, label, errors)
        resolved = _resolve_no_symlink(path, label, errors)
        if resolved is None:
            continue
        _assert_within(resolved, sandbox_root, label, errors)
        roots.append(resolved)
    return roots


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def load_and_validate_fixture_plan(
    *,
    fixture_manifest_path: str,
    sandbox_root: str,
    target_project_path: str,
    platform_selector: str,
    model_selector: str,
    scope_selector: str,
    now_utc: datetime,
) -> dict[str, Any]:
    """加载并完整验证行为夹具计划，返回 JSON 可序列化字典。

    任一验证步骤失败均抛出 BehaviorFixtureValidationError，
    不返回部分可执行计划（门禁 10）。
    """

    errors: list[str] = []

    # ------------------------------------------------------------------
    # 门禁 2：路径绝对性与符号链接检查
    # ------------------------------------------------------------------
    manifest_p = Path(fixture_manifest_path)
    sandbox_p = Path(sandbox_root)
    target_p = Path(target_project_path)

    _assert_absolute(manifest_p, "fixture_manifest_path", errors)
    _assert_absolute(sandbox_p, "sandbox_root", errors)
    _assert_absolute(target_p, "target_project_path", errors)

    manifest_resolved = _resolve_no_symlink(manifest_p, "fixture_manifest_path", errors)
    sandbox_resolved = _resolve_no_symlink(sandbox_p, "sandbox_root", errors)
    target_resolved = _resolve_no_symlink(target_p, "target_project_path", errors)

    if errors:
        raise BehaviorFixtureValidationError(errors)

    assert manifest_resolved is not None
    assert sandbox_resolved is not None
    assert target_resolved is not None
    if not manifest_resolved.is_file():
        errors.append(f"fixture_manifest_path must be a regular file: {manifest_resolved}")
    if not sandbox_resolved.is_dir():
        errors.append(f"sandbox_root must be an existing directory: {sandbox_resolved}")
    if not target_resolved.is_dir():
        errors.append(
            f"target_project_path must be an existing directory: {target_resolved}"
        )
    _assert_within(
        manifest_resolved, sandbox_resolved, "fixture_manifest_path", errors
    )

    # sandbox_root 与目标项目不得互相包含
    try:
        sandbox_resolved.relative_to(target_resolved)
        errors.append("sandbox_root is inside target_project_path")
    except ValueError:
        pass
    try:
        target_resolved.relative_to(sandbox_resolved)
        errors.append("target_project_path is inside sandbox_root")
    except ValueError:
        pass

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 加载 schemas
    # ------------------------------------------------------------------
    schemas = load_fixture_schemas()
    registry = _build_schema_registry(schemas)

    # ------------------------------------------------------------------
    # 门禁 1：加载并校验 manifest schema
    # ------------------------------------------------------------------
    manifest_raw = _load_json(manifest_resolved, "manifest", errors)
    if manifest_raw is None:
        raise BehaviorFixtureValidationError(errors)

    schema_errors = validate_fixture_schema(manifest_raw, "behavior-fixture-manifest", schemas, registry)
    errors.extend(schema_errors)

    if errors:
        raise BehaviorFixtureValidationError(errors)

    for field, expected in (
        ("platform_selector", platform_selector),
        ("model_selector", model_selector),
        ("scope_selector", scope_selector),
    ):
        if manifest_raw.get(field) != expected:
            errors.append(
                f"manifest {field}: got {manifest_raw.get(field)!r}, expected {expected!r}"
            )

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 门禁 3：manifest 内所有路径必须在 sandbox_root 内
    # ------------------------------------------------------------------

    # proof_path
    ep = manifest_raw["execution_provider"]
    proof_rel = ep["proof_path"]
    proof_path = Path(os.path.normpath(os.path.join(str(sandbox_resolved), proof_rel)))
    proof_resolved = _resolve_no_symlink(proof_path, "provider proof_path", errors)
    if proof_resolved is not None:
        _assert_within(proof_resolved, sandbox_resolved, "provider proof_path", errors)

    # receipt_path
    auth = manifest_raw["authorization"]
    receipt_rel = auth["receipt_path"]
    receipt_path = Path(os.path.normpath(os.path.join(str(sandbox_resolved), receipt_rel)))
    receipt_resolved = _resolve_no_symlink(receipt_path, "authorization receipt_path", errors)
    if receipt_resolved is not None:
        _assert_within(receipt_resolved, sandbox_resolved, "authorization receipt_path", errors)

    # isolation_profile 内的 writable_roots（仅检查格式，不影响 manifest 路径验证）

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 门禁 4：provider proof 与 authorization receipt 摘要校验
    # ------------------------------------------------------------------
    assert proof_resolved is not None
    assert receipt_resolved is not None

    if not proof_resolved.is_file():
        errors.append(f"provider proof must be a regular file: {proof_resolved}")
    if not receipt_resolved.is_file():
        errors.append(
            f"authorization receipt must be a regular file: {receipt_resolved}"
        )
    if errors:
        raise BehaviorFixtureValidationError(errors)

    actual_proof_digest = _sha256_file(proof_resolved)
    if actual_proof_digest != ep["proof_digest"]:
        errors.append(
            f"provider proof digest mismatch: actual={actual_proof_digest}, expected={ep['proof_digest']}"
        )

    actual_receipt_digest = _sha256_file(receipt_resolved)
    if actual_receipt_digest != auth["receipt_digest"]:
        errors.append(
            f"authorization receipt digest mismatch: actual={actual_receipt_digest}, expected={auth['receipt_digest']}"
        )

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 加载并 schema 校验 provider proof 与 authorization receipt
    # ------------------------------------------------------------------
    proof_data = _load_json(proof_resolved, "provider proof", errors)
    receipt_data = _load_json(receipt_resolved, "authorization receipt", errors)

    if proof_data is None or receipt_data is None:
        raise BehaviorFixtureValidationError(errors)
    if not isinstance(proof_data, dict):
        errors.append("provider proof must be a JSON object")
    if not isinstance(receipt_data, dict):
        errors.append("authorization receipt must be a JSON object")
    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 加载并校验 isolation profile
    # ------------------------------------------------------------------
    iso_profile = manifest_raw["isolation_profile"]
    iso_errors = validate_fixture_schema(iso_profile, "isolation-profile", schemas, registry)
    errors.extend(iso_errors)
    writable_roots = _validated_writable_roots(
        iso_profile, sandbox_resolved, errors
    )

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 门禁 5：provider proof 逐字段绑定
    # ------------------------------------------------------------------
    _validate_provider_proof(
        proof=proof_data,
        manifest_ep=ep,
        isolation_profile=iso_profile,
        sandbox_root=sandbox_resolved,
        target_project_path=target_resolved,
        platform_selector=platform_selector,
        model_selector=model_selector,
        scope_selector=scope_selector,
        errors=errors,
    )

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 门禁 6：authorization receipt 逐字段绑定
    # ------------------------------------------------------------------
    actual_fixture_ids = {f["fixture_id"] for f in manifest_raw["fixtures"]}
    _validate_authorization_receipt(
        receipt=receipt_data,
        manifest_auth=auth,
        candidate=manifest_raw["candidate"],
        platform_selector=platform_selector,
        model_selector=model_selector,
        scope_selector=scope_selector,
        actual_fixture_ids=actual_fixture_ids,
        now_utc=now_utc,
        errors=errors,
    )

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 门禁 7–9：fixture 逐项验证
    # ------------------------------------------------------------------
    _validate_fixtures(
        fixtures=manifest_raw["fixtures"],
        sandbox_root=sandbox_resolved,
        writable_roots=writable_roots,
        errors=errors,
    )

    if errors:
        raise BehaviorFixtureValidationError(errors)

    # ------------------------------------------------------------------
    # 构建返回摘要（全部门禁通过后）
    # ------------------------------------------------------------------

    # manifest 摘要
    manifest_digest = _sha256_file(manifest_resolved)

    fixture_summary = []
    for fx in manifest_raw["fixtures"]:
        cwd_rel = fx["cwd"]
        cwd_abs = str(Path(os.path.normpath(os.path.join(str(sandbox_resolved), cwd_rel))))
        exe_abs = str(Path(fx["argv"][0]).resolve())

        write_set_abs = []
        for ws in fx["write_set"]:
            write_set_abs.append(
                str(Path(os.path.normpath(os.path.join(str(sandbox_resolved), cwd_rel, ws))))
            )

        expected_output_abs = []
        for of in fx.get("expected", {}).get("output_files", []):
            expected_output_abs.append({
                "path": str(
                    Path(
                        os.path.normpath(
                            os.path.join(
                                str(sandbox_resolved), cwd_rel, of["path"]
                            )
                        )
                    )
                ),
                "content_digest": of["content_digest"],
            })

        fixture_summary.append(
            {
                "fixture_id": fx["fixture_id"],
                "category": fx["category"],
                "executable": exe_abs,
                "argv": [exe_abs, *fx["argv"][1:]],
                "cwd": cwd_abs,
                "write_set": write_set_abs,
                "expected_output_files": expected_output_abs,
                "timeout_seconds": fx["timeout_seconds"],
                "environment": dict(fx["environment"]),
                "expected": {
                    "exit_code": fx["expected"]["exit_code"],
                    "stdout_digest": fx["expected"]["stdout_digest"],
                    "stderr_digest": fx["expected"]["stderr_digest"],
                    "output_files": expected_output_abs,
                },
            }
        )

    return {
        "manifest": manifest_raw,
        "manifest_path": str(manifest_resolved),
        "provider_proof_path": str(proof_resolved),
        "authorization_receipt_path": str(receipt_resolved),
        "manifest_summary": {
            "schema_version": manifest_raw["schema_version"],
            "candidate_id": manifest_raw["candidate"]["candidate_id"],
            "candidate_digest": manifest_raw["candidate"]["candidate_digest"],
            "platform_selector": manifest_raw["platform_selector"],
            "model_selector": manifest_raw["model_selector"],
            "scope_selector": manifest_raw["scope_selector"],
            "fixture_count": len(manifest_raw["fixtures"]),
            "manifest_digest": manifest_digest,
        },
        "provider_proof_summary": {
            "provider_id": ep["provider_id"],
            "provider_version": ep["provider_version"],
            "proof_digest": ep["proof_digest"],
            "isolation_id": iso_profile["isolation_id"],
            "control_plane_proof": iso_profile["control_plane_proof"],
        },
        "authorization_receipt_summary": {
            "authorization_id": auth["authorization_id"],
            "approver": receipt_data.get("approver"),
            "approved": receipt_data.get("approved"),
            "authorized_fixture_ids": sorted(auth["authorized_fixture_ids"]),
            "expires_at": auth["expires_at"],
        },
        "executables": [fx["executable"] for fx in fixture_summary],
        "fixtures": fixture_summary,
        "writable_roots": [str(path) for path in writable_roots],
        "cwd": {
            fx["fixture_id"]: fx["cwd"] for fx in fixture_summary
        },
        "write_set": {
            fx["fixture_id"]: fx["write_set"] for fx in fixture_summary
        },
        "expected_output_files": {
            fx["fixture_id"]: fx["expected_output_files"] for fx in fixture_summary
        },
    }
