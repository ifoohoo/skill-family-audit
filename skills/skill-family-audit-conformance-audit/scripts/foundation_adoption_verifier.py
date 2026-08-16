#!/usr/bin/env python3
"""Foundation 采用验证器：进程外调用 Foundation Engineering Kit 只读函数。

职责：
- 读取并校验 adoption-lock.json（Audit 领域合同）
- 通过 SFA_FOUNDATION_NODE 环境变量绑定显式 Node.js 绝对无符号链接入口
- 探测并要求 Node >=22.22.2 <23，用于所有进程外调用
- 调用 Foundation 只读函数：loadMigrationManifestState、assessLegacyExitList、
  assessLegacyReferences、assessAdoptionBinding
- 独立核对 pin/provenance/bundle 闭合、profile/version/payload/package 绑定、
  production mechanisms 覆盖、legacy exit/reference 状态
- 输出 foundation_adoption_complete 布尔值

边界：
- Foundation 迁移语义由进程外 Foundation 权威入口提供
- Audit 拥有 adoption-lock 合同；Foundation 拥有 migration manifest 结构和评估函数
- 不修改 761 条 canonical rules 的治理状态
- Node 运行时不依赖任意 PATH；缺失或不兼容失败关闭
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import conformance_check as foundation_bridge

SCRIPTS_DIR = Path(__file__).resolve().parent
REFS_DIR = SCRIPTS_DIR.parent / "refs"

REQUIRED_FOUNDATION_PACKAGES = [
    "skill-family-contracts",
    "skill-family-harness-node",
    "skill-family-engineering-kit",
]

class VerificationError(RuntimeError):
    """验证失败，携带稳定错误码。"""
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code = code


def _reject_symlink(path: Path, code: str) -> None:
    """Map the canonical host's trust-boundary failure into Audit vocabulary."""
    try:
        foundation_bridge._check_path_chain_no_symlinks(path, code)
    except RuntimeError as exc:
        raise VerificationError(code, str(exc)) from exc


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError("ADOPTION_LOCK_UNREADABLE", str(exc)) from exc


def _resolve_foundation_adoption_cli(runner: Path) -> tuple[Path, dict]:
    """从已验证的受管 Bundle 解析 Foundation 固定 adoption CLI。"""
    try:
        runner = foundation_bridge.target_foundation_runner(runner)
    except RuntimeError as exc:
        raise VerificationError("FOUNDATION_BUNDLE_INVALID", str(exc)) from exc
    cli = runner.parent / "adoption-cli.mjs"
    _reject_symlink(cli, "FOUNDATION_ADOPTION_CLI_PATH_SYMLINK")
    if not cli.is_file():
        raise VerificationError(
            "FOUNDATION_ADOPTION_CLI_MISSING",
            f"受管 Bundle 缺少 adoption-cli.mjs: {cli}",
        )
    try:
        identity = foundation_bridge.call_foundation_cli(
            runner, "adoption-cli.mjs", {"operation": "self-check", "params": {}}
        )
    except RuntimeError as exc:
        raise VerificationError("FOUNDATION_ADOPTION_CLI_IDENTITY_INVALID", str(exc)) from exc
    if not isinstance(identity, dict) or identity.get("valid") is not True:
        raise VerificationError("FOUNDATION_ADOPTION_CLI_IDENTITY_INVALID")
    return cli, {
        "entry_path": identity["cli"]["path"],
        "entry_digest": identity["cli"]["sha256"],
        "self_check": identity,
    }


def _call_foundation_read(
    node_path: Path,
    cli: Path,
    operation: str,
    payload: dict,
) -> Any:
    """通过受管 adoption CLI 调用 Foundation 固定只读能力。"""
    try:
        del node_path
        runner = cli.with_name("runner.mjs")
        result = foundation_bridge.call_foundation_cli(
            runner,
            "adoption-cli.mjs",
            {"operation": operation, "params": payload},
        )
        if operation not in {"assess-legacy-exit-list", "assess-legacy-references"} and not isinstance(result, dict):
            raise RuntimeError("Foundation adoption mechanism returned non-object")
        return result
    except RuntimeError as exc:
        raise VerificationError(
            "FOUNDATION_READ_CALL_FAILED",
            f"Foundation 只读操作 {operation} 调用失败: {exc}",
        ) from exc


def _load_foundation_pin(installed_root: Path, pin_rel: str) -> dict:
    """加载并验证 Foundation pin 文件。"""
    pin_path = installed_root / pin_rel
    _reject_symlink(pin_path, "FOUNDATION_PIN_PATH_SYMLINK")
    if not pin_path.is_file():
        raise VerificationError(
            "FOUNDATION_PIN_MISSING",
            f"Foundation pin 文件不存在: {pin_rel}",
        )
    return _load_json(pin_path)


def _load_bundle_provenance(installed_root: Path, prov_rel: str) -> dict:
    """加载并验证 Bundle provenance 文件。"""
    prov_path = installed_root / prov_rel
    _reject_symlink(prov_path, "BUNDLE_PROVENANCE_PATH_SYMLINK")
    if not prov_path.is_file():
        raise VerificationError(
            "BUNDLE_PROVENANCE_MISSING",
            f"Bundle provenance 文件不存在: {prov_rel}",
        )
    return _load_json(prov_path)


def _verify_profile_binding(
    lock_profile: dict,
    pin: dict,
) -> list[str]:
    """验证 profile 绑定一致性。"""
    errors = []
    pin_profile = pin.get("profile", {})
    if pin_profile.get("id") != lock_profile.get("id"):
        errors.append(
            f"profile id 漂移: lock={lock_profile.get('id')}, pin={pin_profile.get('id')}"
        )
    if pin_profile.get("version") != lock_profile.get("version"):
        errors.append(
            f"profile version 漂移: lock={lock_profile.get('version')}, pin={pin_profile.get('version')}"
        )
    return errors


def _verify_package_bindings(
    lock: dict,
    pin: dict,
) -> tuple[list[str], list[str]]:
    """验证 Foundation 包 exact version+digest 绑定。返回 (errors, covered)。"""
    errors = []
    packages = pin.get("packages", [])
    if not isinstance(packages, list):
        return ["pin.packages 不是数组"], []
    bound = {}
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        sha = pkg.get("sha256")
        if isinstance(name, str) and isinstance(version, str) and isinstance(sha, str):
            bound[name] = {"version": version, "sha256": sha}
    covered = sorted(bound.keys())
    missing = [name for name in REQUIRED_FOUNDATION_PACKAGES if name not in bound]
    if missing:
        errors.append(f"Foundation 包未绑定: {missing}")
    # 验证与 lock 中的 foundation_engineering_kit 版本一致（如有）
    kit_info = lock.get("foundation_engineering_kit", {})
    if kit_info.get("version"):
        kit_pkg = bound.get("skill-family-engineering-kit", {})
        if kit_pkg.get("version") and kit_pkg["version"] != kit_info["version"]:
            errors.append(
                f"engineering-kit 版本漂移: lock={kit_info['version']}, pin={kit_pkg.get('version')}"
            )
    return errors, covered


def _verify_production_mechanisms(
    lock_mechanisms: list[str],
    pin: dict,
) -> list[str]:
    """验证 production mechanisms 集合非空、唯一，并能从 pin 的 consumerSchemas 闭合。"""
    errors = []
    if not lock_mechanisms:
        errors.append("production_mechanisms 为空")
        return errors
    if len(lock_mechanisms) != len(set(lock_mechanisms)):
        errors.append("production_mechanisms 有重复条目")
    # 从 pin 的 consumerSchemas 收集已知 schema id
    consumer_schemas = pin.get("consumerSchemas", [])
    known_ids = set()
    for cs in consumer_schemas:
        if isinstance(cs, dict) and isinstance(cs.get("$id"), str):
            known_ids.add(cs["$id"])
    # 验证每个 mechanism 可以从 consumerSchemas 闭合
    for mechanism in lock_mechanisms:
        if mechanism not in known_ids:
            errors.append(f"production mechanism 无法从 pin consumerSchemas 闭合: {mechanism}")
    return errors


def verify_foundation_adoption(
    target: Path,
    adoption_lock: dict,
) -> dict:
    """执行完整的 Foundation 采用验证。

    返回验证结果对象，包含：
    - foundation_adoption_complete: bool
    - 各维度的验证事实
    - 进程外 verifier 入口摘要与调用事实
    """
    result: dict[str, Any] = {
        "foundation_adoption_complete": False,
        "checks": {},
        "verifier_facts": {},
        "blockers": [],
    }

    # 0. 解析 Node.js 运行时（SFA_FOUNDATION_NODE，>=22.22.2 <23）
    node_path: Path | None = None
    try:
        node_path, node_version = foundation_bridge.foundation_node_runtime()
        result["verifier_facts"]["node_runtime"] = {
            "path": str(node_path),
            "version": node_version,
        }
    except (VerificationError, foundation_bridge.FoundationNodeRuntimeError) as exc:
        result["blockers"].append(f"NODE_RUNTIME: {exc.code}: {exc}")
        result["verifier_facts"]["node_runtime"] = {"error": exc.code}
        return result

    installed_root_rel = adoption_lock.get("installed_root", "")
    installed_root_raw = target / installed_root_rel
    try:
        _reject_symlink(installed_root_raw, "INSTALLED_ROOT_PATH_SYMLINK")
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        return result
    installed_root = installed_root_raw.resolve()
    if not installed_root.is_dir():
        result["blockers"].append(f"INSTALLED_ROOT_MISSING: {installed_root_rel}")
        return result

    # 1. 从 adoption lock 绑定的目标 Bundle 解析固定 Foundation adoption CLI。
    # Audit 自身 runner 继续服务 Audit 合同验证，不能冒充受检消费者身份。
    bundle_rel = adoption_lock.get("bundle_root", "")
    try:
        adoption_cli, kit_facts = _resolve_foundation_adoption_cli(
            installed_root / bundle_rel / "runner.mjs"
        )
        result["verifier_facts"]["foundation_engineering_kit"] = kit_facts
    except VerificationError as exc:
        result["blockers"].append(f"FOUNDATION_KIT_REF: {exc.code}: {exc}")
        result["verifier_facts"]["foundation_engineering_kit"] = {"error": exc.code}
        return result

    # 2. 加载 Foundation pin
    pin_rel = adoption_lock.get("foundation_pin", {}).get("relative_path", "")
    expected_pin_digest = adoption_lock.get("foundation_pin", {}).get("digest", "")
    try:
        pin = _load_foundation_pin(installed_root, pin_rel)
        actual_pin_digest = foundation_bridge._file_digest(installed_root / pin_rel)
        result["checks"]["pin_loaded"] = True
        if actual_pin_digest != expected_pin_digest:
            result["blockers"].append("FOUNDATION_PIN_DIGEST_MISMATCH")
            result["checks"]["pin_digest_match"] = False
        else:
            result["checks"]["pin_digest_match"] = True
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        result["checks"]["pin_loaded"] = False
        return result

    # 3. 加载 Bundle provenance
    prov_rel = adoption_lock.get("bundle_provenance", {}).get("relative_path", "")
    expected_prov_digest = adoption_lock.get("bundle_provenance", {}).get("digest", "")
    expected_payload_digest = adoption_lock.get("bundle_provenance", {}).get("payload_digest", "")
    try:
        provenance = _load_bundle_provenance(installed_root, prov_rel)
        actual_prov_digest = foundation_bridge._file_digest(installed_root / prov_rel)
        result["checks"]["provenance_loaded"] = True
        if actual_prov_digest != expected_prov_digest:
            result["blockers"].append("BUNDLE_PROVENANCE_DIGEST_MISMATCH")
            result["checks"]["provenance_digest_match"] = False
        else:
            result["checks"]["provenance_digest_match"] = True
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        result["checks"]["provenance_loaded"] = False
        return result

    # 4. 验证 Bundle payload 闭合
    payload_digest = provenance.get("payload", {}).get("digest", "")
    if payload_digest != expected_payload_digest:
        result["blockers"].append("BUNDLE_PAYLOAD_DIGEST_MISMATCH")
        result["checks"]["payload_digest_match"] = False
    else:
        result["checks"]["payload_digest_match"] = True

    identity = kit_facts["self_check"]
    result["checks"]["bundle_closure"] = (
        identity.get("valid") is True
        and identity.get("projection", {}).get("payloadDigest") == payload_digest
    )
    if not result["checks"]["bundle_closure"]:
        result["blockers"].append("BUNDLE_SELF_CHECK_IDENTITY_MISMATCH")

    # 5. 验证 profile 绑定
    lock_profile = adoption_lock.get("foundation_profile", {})
    profile_errors = _verify_profile_binding(lock_profile, pin)
    if profile_errors:
        result["blockers"].extend(profile_errors)
        result["checks"]["profile_binding"] = False
    else:
        result["checks"]["profile_binding"] = True

    # 6. 验证 Foundation 包绑定
    package_errors, covered = _verify_package_bindings(adoption_lock, pin)
    if package_errors:
        result["blockers"].extend(package_errors)
        result["checks"]["package_bindings"] = False
    else:
        result["checks"]["package_bindings"] = True
    result["checks"]["covered_packages"] = covered

    # 7. 验证 production mechanisms
    mechanisms = adoption_lock.get("production_mechanisms", [])
    mechanism_errors = _verify_production_mechanisms(mechanisms, pin)
    if mechanism_errors:
        result["blockers"].extend(mechanism_errors)
        result["checks"]["production_mechanisms"] = False
    else:
        result["checks"]["production_mechanisms"] = True

    # 8. 调用 Foundation Engineering Kit 只读函数
    # 8a. 加载 migration manifest 状态
    manifest_state: dict[str, Any] = {"status": "unavailable", "manifest": {}}
    try:
        manifest_state = _call_foundation_read(
            node_path, adoption_cli, "load-migration-manifest-state",
            {"root": str(installed_root)},
        )
        result["verifier_facts"]["migration_manifest_state"] = manifest_state
        if manifest_state.get("status") != "valid":
            result["blockers"].append(
                f"MIGRATION_MANIFEST_STATE: {manifest_state.get('status')}"
            )
            result["checks"]["migration_manifest_valid"] = False
        else:
            result["checks"]["migration_manifest_valid"] = True
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        result["verifier_facts"]["migration_manifest_state"] = {"error": exc.code}
        result["checks"]["migration_manifest_valid"] = False

    # 8b. 评估 adoption binding
    try:
        binding = _call_foundation_read(
            node_path, adoption_cli, "assess-adoption-binding",
            {"manifest": manifest_state.get("manifest", {}), "profileId": lock_profile.get("id", "")},
        )
        result["verifier_facts"]["adoption_binding"] = binding
        if not binding.get("profileMatches"):
            result["blockers"].append("ADOPTION_BINDING_PROFILE_MISMATCH")
            result["checks"]["adoption_binding"] = False
        elif binding.get("missingPackages"):
            result["blockers"].append(
                f"ADOPTION_BINDING_MISSING_PACKAGES: {binding['missingPackages']}"
            )
            result["checks"]["adoption_binding"] = False
        else:
            result["checks"]["adoption_binding"] = True
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        result["verifier_facts"]["adoption_binding"] = {"error": exc.code}
        result["checks"]["adoption_binding"] = False

    # 8c. 评估 legacy exit list
    manifest = manifest_state.get("manifest", {})
    legacy_infra = manifest.get("legacyInfra", [])
    try:
        legacy_exit = _call_foundation_read(
            node_path, adoption_cli, "assess-legacy-exit-list",
            {"root": str(installed_root), "legacyItems": legacy_infra},
        )
        result["verifier_facts"]["legacy_exit_list"] = legacy_exit
        present_legacy = [
            item for item in legacy_exit
            if isinstance(item, dict) and item.get("status") == "present"
        ]
        invalid_legacy = [
            item for item in legacy_exit
            if isinstance(item, dict) and item.get("status") == "invalid"
        ]
        if present_legacy:
            result["blockers"].append(
                f"LEGACY_INFRA_PRESENT: {[item.get('path') for item in present_legacy]}"
            )
            result["checks"]["legacy_exit"] = False
        elif invalid_legacy:
            result["blockers"].append(
                f"LEGACY_INFRA_INVALID: {[item.get('path') for item in invalid_legacy]}"
            )
            result["checks"]["legacy_exit"] = False
        else:
            result["checks"]["legacy_exit"] = True
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        result["verifier_facts"]["legacy_exit_list"] = {"error": exc.code}
        result["checks"]["legacy_exit"] = False

    # 8d. 评估 legacy references
    legacy_refs = manifest.get("legacyReferences", [])
    try:
        legacy_ref_exit = _call_foundation_read(
            node_path, adoption_cli, "assess-legacy-references",
            {"root": str(installed_root), "legacyReferences": legacy_refs},
        )
        result["verifier_facts"]["legacy_reference_exit"] = legacy_ref_exit
        present_refs = [
            item for item in legacy_ref_exit
            if isinstance(item, dict) and item.get("status") == "present"
        ]
        invalid_refs = [
            item for item in legacy_ref_exit
            if isinstance(item, dict) and item.get("status") == "invalid"
        ]
        if present_refs:
            result["blockers"].append(
                f"LEGACY_REFERENCES_PRESENT: {[item.get('path') for item in present_refs]}"
            )
            result["checks"]["legacy_references"] = False
        elif invalid_refs:
            result["blockers"].append(
                f"LEGACY_REFERENCES_INVALID: {[item.get('path') for item in invalid_refs]}"
            )
            result["checks"]["legacy_references"] = False
        else:
            result["checks"]["legacy_references"] = True
    except VerificationError as exc:
        result["blockers"].append(f"{exc.code}: {exc}")
        result["verifier_facts"]["legacy_reference_exit"] = {"error": exc.code}
        result["checks"]["legacy_references"] = False

    # 8e. Foundation source verification status
    pin_source = pin.get("source", {})
    source_status = pin_source.get("status", "UNKNOWN")
    result["checks"]["foundation_source_status"] = source_status
    if source_status != "DECLARED_UNVERIFIED":
        # 如实保留状态，不冒充 verified
        result["checks"]["foundation_source_note"] = (
            f"Foundation source 状态为 {source_status}，非 DECLARED_UNVERIFIED"
        )

    # 9. 总结
    result["foundation_adoption_complete"] = len(result["blockers"]) == 0
    return result


def verify_harness_inventory(
    target: Path,
    adoption_lock: dict,
    detectors: list[dict],
) -> dict:
    """调用 Foundation verifyHarnessSurfaceInventory 验证 harness inventory receipt。

    真实调用 Foundation candidate 的 verifyHarnessSurfaceInventory，不自行 scan/hash/path。
    只在 verify valid 后，对 receipt.surfaces 的 surfaceId 与 owner adjudications 做精确全集相等判断。

    返回验证结果对象。
    """
    result: dict[str, Any] = {
        "harness_inventory_verified": False,
        "checks": {},
        "verifier_facts": {},
        "blockers": [],
    }

    # 0. 解析 Node.js 运行时
    node_path: Path | None = None
    try:
        node_path, node_version = foundation_bridge.foundation_node_runtime()
        result["verifier_facts"]["node_runtime"] = {
            "path": str(node_path),
            "version": node_version,
        }
    except (VerificationError, foundation_bridge.FoundationNodeRuntimeError) as exc:
        result["blockers"].append(f"NODE_RUNTIME: {exc.code}: {exc}")
        result["verifier_facts"]["node_runtime"] = {"error": exc.code}
        return result

    # 1. 从同一受管 Bundle 解析固定 Foundation adoption CLI
    try:
        installed_root_rel = adoption_lock.get("installed_root", "")
        bundle_rel = adoption_lock.get("bundle_root", "")
        target_runner = target / installed_root_rel / bundle_rel / "runner.mjs"
        adoption_cli, harness_facts = _resolve_foundation_adoption_cli(target_runner)
        result["verifier_facts"]["foundation_harness"] = harness_facts
    except VerificationError as exc:
        result["blockers"].append(f"FOUNDATION_HARNESS_REF: {exc.code}: {exc}")
        result["verifier_facts"]["foundation_harness"] = {"error": exc.code}
        return result

    # 2. 读取 harness_inventory 绑定
    harness_inventory = adoption_lock.get("harness_inventory")
    if not isinstance(harness_inventory, dict):
        result["blockers"].append("HARNESS_INVENTORY_MISSING: 采用锁缺少 harness_inventory 绑定")
        return result

    inventory_rel = harness_inventory.get("relative_path", "")
    expected_inventory_digest = harness_inventory.get("inventory_digest", "")
    if not inventory_rel:
        result["blockers"].append("HARNESS_INVENTORY_PATH_MISSING: harness_inventory.relative_path 缺失")
        return result

    # 3. 加载 receipt JSON
    receipt_path = target / inventory_rel
    if not receipt_path.is_file() or receipt_path.is_symlink():
        result["blockers"].append(f"HARNESS_INVENTORY_FILE_MISSING: receipt 文件不存在: {inventory_rel}")
        return result

    try:
        receipt = _load_json(receipt_path)
    except VerificationError as exc:
        result["blockers"].append(f"HARNESS_INVENTORY_UNREADABLE: {exc.code}: {exc}")
        return result

    # 4. 验证 receipt inventoryDigest 与 lock 绑定一致
    actual_inventory_digest = receipt.get("inventoryDigest", "")
    if actual_inventory_digest != expected_inventory_digest:
        result["blockers"].append(
            f"HARNESS_INVENTORY_DIGEST_MISMATCH: "
            f"receipt.inventoryDigest={actual_inventory_digest}, "
            f"lock.inventory_digest={expected_inventory_digest}"
        )
        result["checks"]["inventory_digest_match"] = False
    else:
        result["checks"]["inventory_digest_match"] = True

    # 5. 调用 Foundation verifyHarnessSurfaceInventory（真实重扫、收容、SHA-256、排序、摘要严格比对）
    try:
        verify_result = _call_foundation_read(
            node_path, adoption_cli, "verify-harness-surface-inventory",
            {"root": str(target), "inventory": receipt, "detectors": detectors},
        )
        result["verifier_facts"]["harness_verify"] = verify_result
        result["checks"]["foundation_harness_verify"] = True
    except VerificationError as exc:
        result["blockers"].append(f"FOUNDATION_HARNESS_VERIFY: {exc.code}: {exc}")
        result["verifier_facts"]["harness_verify"] = {"error": exc.code}
        result["checks"]["foundation_harness_verify"] = False
        return result

    # 6. 只在 verify valid 后，对 receipt.surfaces 的 surfaceId 与 owner adjudications 做精确全集相等判断
    receipt_surface_ids = sorted(s.get("surfaceId", "") for s in receipt.get("surfaces", []))
    owner_adj = harness_inventory.get("owner_adjudications")
    if isinstance(owner_adj, dict):
        adj_rel = owner_adj.get("relative_path", "")
        adj_digest = owner_adj.get("digest", "")
        if adj_rel:
            adj_path = target / adj_rel
            if adj_path.is_file() and not adj_path.is_symlink():
                actual_adj_digest = foundation_bridge._file_digest(adj_path)
                if actual_adj_digest == adj_digest:
                    adjudication = _load_json(adj_path)
                    result["verifier_facts"]["owner_adjudications"] = (
                        adjudication.get("owner_adjudications", [])
                    )
                    adj_surface_ids = sorted(
                        a.get("surface_id", "") for a in adjudication.get("owner_adjudications", [])
                    )
                    if receipt_surface_ids != adj_surface_ids:
                        result["blockers"].append(
                            f"SURFACE_ID_MISMATCH: "
                            f"receipt surfaces={receipt_surface_ids}, "
                            f"adjudication surfaces={adj_surface_ids}"
                        )
                        result["checks"]["surface_id_equality"] = False
                    else:
                        result["checks"]["surface_id_equality"] = True
                else:
                    result["blockers"].append("ADJUDICATION_DIGEST_MISMATCH")
                    result["checks"]["surface_id_equality"] = False
            else:
                result["blockers"].append(f"ADJUDICATION_FILE_MISSING: {adj_rel}")
                result["checks"]["surface_id_equality"] = False
        else:
            result["blockers"].append("ADJUDICATION_PATH_MISSING")
            result["checks"]["surface_id_equality"] = False
    else:
        result["blockers"].append("OWNER_ADJUDICATIONS_MISSING")
        result["checks"]["surface_id_equality"] = False

    result["verifier_facts"]["receipt_surface_ids"] = receipt_surface_ids
    result["verifier_facts"]["receipt_surface_count"] = len(receipt_surface_ids)
    result["harness_inventory_verified"] = len(result["blockers"]) == 0
    return result
