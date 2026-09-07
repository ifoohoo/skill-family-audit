"""机械候选规则的只读领域执行器。

本模块只读取受检项目的真实文件。它不执行目标代码，不读取相邻工作树，也不
自行激活规则。它是 W2-C2 候选实现，不登记到生产 executor 注册表，不参与
生产路由闭包；正式激活仍须另行完成 canonical/routing/binding 修订。
候选可用性只通过本模块的直接导入与调用验证。SFA-PUBLISH-015 与
SFA-SOURCE-020 已从候选 CHECKS 撤下，在 canonical 路由中保持
RETAINED_UNIMPLEMENTED/mechanical_candidate_executor_gap 缺口。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import ExecutorEvidenceError


FOUNDATION_PACKAGES = {
    "skill-family-contracts",
    "skill-family-engineering-kit",
    "skill-family-harness-node",
}
METHODS: dict[str, tuple[str, ...]] = {
    "SFA-DEPEND-012": ("digest_verification", "static_scan"),
    "SFA-FOUNDATION-002": ("digest_verification", "schema_validation"),
    "SFA-FOUNDATION-003": ("schema_validation",),
    "SFA-FOUNDATION-006": ("digest_verification", "schema_validation"),
    "SFA-FOUNDATION-020": ("digest_verification", "static_scan"),
    "SFA-FOUNDATION-024": ("digest_verification",),
    "SFA-PUBLISH-012": ("schema_validation", "static_scan"),
    "SFA-REPO-006": ("static_scan",),
}
APPLICABILITY = {
    "SFA-DEPEND-012": "family_source/project_adoption 且存在 agent-method-registry adapter；未消费时不适用",
    "SFA-FOUNDATION-002": "family_source/project_adoption 且实际消费 Foundation；有效零消费豁免时不适用",
    "SFA-FOUNDATION-003": "family_source/project_adoption 且有 Foundation 零消费或部分消费缺口；三包全消费时不适用",
    "SFA-FOUNDATION-006": "family_source/project_adoption 且存在 Foundation 豁免记录；无豁免时不适用",
    "SFA-FOUNDATION-020": "family_source/project_adoption 且实际消费 Foundation；有效零消费豁免时不适用",
    "SFA-FOUNDATION-024": "family_source/project_adoption 且消费 Foundation 并维护基线 pin；未消费时不适用",
    "SFA-PUBLISH-012": "具有 package.json 发布单元的 family_source/project_adoption；无发布单元时不适用",
    "SFA-REPO-006": "family_source/project_adoption 且存在运行或证据目录；无此类目录时不适用",
}
SEMVER = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CONSUMPTION_FORMS = {"npm_exact_pin", "vendored_bundle", "bundle_projection"}


def _root(ctx: dict[str, Any]) -> Path:
    root = Path(ctx["target"])
    if not root.is_dir() or root.is_symlink():
        raise ExecutorEvidenceError("TARGET_ROOT_INVALID")
    return root.resolve()


def _in_scope(ctx: dict[str, Any], *target_types: str) -> bool:
    return ctx.get("target_type", "family_source") in target_types


def _row(method: str, status: str, source: str, **evidence: Any) -> dict[str, Any]:
    return {
        "check_method": method,
        "status": status,
        "observation_source": source,
        "evidence": evidence or {"reason": status.lower()},
    }


def _finish(rows: list[dict[str, Any]], **evidence: Any) -> dict[str, Any]:
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
        raise ExecutorEvidenceError("METHOD_RESULT_COMBINATION_INVALID", repr(statuses))
    return {"status": status, "evidence": evidence, "check_method_subresults": rows}


def _uniform(rule_id: str, status: str, reason: str) -> dict[str, Any]:
    return _finish([
        _row(method, status, f"{rule_id.lower()}:{method}", reason=reason)
        for method in METHODS[rule_id]
    ], reason=reason)


def _contained(root: Path, relative: Any, *, must_exist: bool = True) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ExecutorEvidenceError("CONTAINED_PATH_INVALID", repr(relative))
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != relative:
        raise ExecutorEvidenceError("CONTAINED_PATH_INVALID", relative)
    candidate = root / relative
    cursor = root
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ExecutorEvidenceError("CONTAINED_PATH_SYMLINK", relative)
    if must_exist and not candidate.is_file():
        raise ExecutorEvidenceError("REFERENCED_EVIDENCE_MISSING", relative)
    return candidate


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise ExecutorEvidenceError("EVIDENCE_SYMLINK", label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError("EVIDENCE_JSON_INVALID", f"{label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError("EVIDENCE_JSON_INVALID", f"{label}: object required")
    return value


def _optional_json(root: Path, relatives: tuple[str, ...]) -> tuple[dict[str, Any] | None, str | None]:
    found = [relative for relative in relatives if (root / relative).is_file()]
    if len(found) > 1:
        raise ExecutorEvidenceError("DUPLICATE_AUTHORITY_CARRIER", repr(found))
    if not found:
        return None, None
    return _load_json(root / found[0], found[0]), found[0]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ref_rows(root: Path, refs: Any) -> list[dict[str, str]]:
    if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)):
        raise ExecutorEvidenceError("EVIDENCE_REFS_INVALID")
    rows = []
    for relative in refs:
        path = _contained(root, relative)
        rows.append({"path": relative, "sha256": _sha256(path)})
    return rows


def _profile(root: Path) -> dict[str, Any] | None:
    path = root / "profile.json"
    return _load_json(path, "profile.json") if path.is_file() else None


def _foundation_pins(profile: dict[str, Any] | None) -> dict[str, Any]:
    adoption = profile.get("adoption") if isinstance(profile, dict) else None
    pin = adoption.get("foundation_pin") if isinstance(adoption, dict) else None
    packages = pin.get("packages") if isinstance(pin, dict) else None
    return packages if isinstance(packages, dict) else {}


def _foundation_dependencies(root: Path) -> set[str]:
    package_path = root / "package.json"
    if not package_path.is_file():
        return set()
    package = _load_json(package_path, "package.json")
    names: set[str] = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(field, {})
        if isinstance(values, dict):
            names.update(set(values) & FOUNDATION_PACKAGES)
    return names


def _exemption(root: Path) -> tuple[dict[str, Any] | None, str | None]:
    return _optional_json(root, (
        "foundation-adoption-exemption.json",
        ".skill-family-audit/governance/foundation-adoption-exemption.json",
    ))


def _validate_pin_rows(root: Path, packages: dict[str, Any]) -> tuple[list[str], list[str]]:
    schema_errors: list[str] = []
    digest_errors: list[str] = []
    for name, pin in sorted(packages.items()):
        if name not in FOUNDATION_PACKAGES or not isinstance(pin, dict):
            schema_errors.append(f"{name}:invalid_pin")
            continue
        version, relative, declared = pin.get("version"), pin.get("path"), pin.get("sha256")
        if not isinstance(version, str) or not SEMVER.fullmatch(version):
            schema_errors.append(f"{name}:version_not_exact")
        if not isinstance(declared, str) or not HEX64.fullmatch(declared):
            schema_errors.append(f"{name}:sha256_invalid")
        try:
            path = _contained(root, relative)
        except ExecutorEvidenceError as exc:
            digest_errors.append(f"{name}:{exc.code}")
            continue
        if isinstance(declared, str) and _sha256(path) != declared:
            digest_errors.append(f"{name}:sha256_mismatch")
    return schema_errors, digest_errors


def check_foundation_002(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-FOUNDATION-002"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    profile = _profile(root)
    packages = _foundation_pins(profile)
    if not packages:
        exemption, _ = _exemption(root)
        return _uniform(rule, "NOT_APPLICABLE" if exemption else "EVIDENCE_MISSING", "zero_consumption" if exemption else "adoption_identity_missing")
    classification, carrier = _optional_json(root, (
        "foundation-consumption-classification.json",
        ".skill-family-audit/governance/foundation-consumption-classification.json",
    ))
    schema_errors, digest_errors = _validate_pin_rows(root, packages)
    refs: list[dict[str, str]] = []
    if classification is None:
        schema_status, schema_reason = "EVIDENCE_MISSING", "classification_missing"
    else:
        allowed = {"schemaVersion", "kind", "consumptionForm", "evidenceRefs"}
        if set(classification) != allowed or classification.get("schemaVersion") != 1 or classification.get("kind") != "skill-family.foundation-consumption-classification" or classification.get("consumptionForm") not in CONSUMPTION_FORMS:
            schema_errors.append("classification_schema_invalid")
        try:
            refs = _ref_rows(root, classification.get("evidenceRefs"))
        except ExecutorEvidenceError as exc:
            schema_errors.append(exc.code)
        schema_status, schema_reason = ("FAIL", schema_errors) if schema_errors else ("PASS", "closed_schema_valid")
    rows = [
        _row("digest_verification", "FAIL" if digest_errors else "PASS", "foundation-pin-byte-verification", carrier=carrier, errors=digest_errors, pins=sorted(packages)),
        _row("schema_validation", schema_status, "foundation-consumption-classification-schema", carrier=carrier, result=schema_reason, evidence_refs=refs),
    ]
    return _finish(rows, consumed_packages=sorted(packages), classification=carrier)


def _validate_exemption(root: Path, value: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    required = {"schemaVersion", "exemptionId", "project", "exemptedPackages", "reasonCategory", "reason", "boundaryEvidence", "approval", "expiresAt", "status"}
    errors = sorted(required - set(value))
    allowed = required | {"selfBuildReplacement", "statusEvents", "reviewEvents"}
    if set(value) - allowed:
        errors.append("additionalProperties")
    if value.get("schemaVersion") != "1.0.0-candidate":
        errors.append("schemaVersion")
    if not isinstance(value.get("exemptionId"), str) or not re.fullmatch(r"FAE-[a-z0-9]+(?:-[a-z0-9]+)*", value["exemptionId"]):
        errors.append("exemptionId")
    project = value.get("project")
    if not isinstance(project, dict) or set(project) - {"projectId", "familyId", "repositoryRef"} or not isinstance(project.get("projectId"), str) or not project["projectId"]:
        errors.append("project")
    packages = value.get("exemptedPackages")
    if not isinstance(packages, list) or not packages or len(packages) != len(set(packages)) or not set(packages) <= FOUNDATION_PACKAGES:
        errors.append("exemptedPackages")
    reason_category = value.get("reasonCategory")
    if reason_category not in {"language_stack_boundary", "runtime_environment_boundary", "dependency_supply_boundary", "temporary_migration_window"}:
        errors.append("reasonCategory")
    if reason_category == "temporary_migration_window" and not isinstance(value.get("selfBuildReplacement"), dict):
        errors.append("selfBuildReplacement")
    if value.get("status") not in {"pending_approval", "active", "expired", "revoked"}:
        errors.append("status")
    refs: list[dict[str, str]] = []
    boundaries = value.get("boundaryEvidence")
    if not isinstance(boundaries, list) or not boundaries:
        errors.append("boundaryEvidence")
    else:
        for row in boundaries:
            if not isinstance(row, dict) or set(row) != {"kind", "description", "evidenceRefs"} or row.get("kind") not in {"language_stack", "runtime_environment", "dependency_supply", "migration_plan"} or not isinstance(row.get("description"), str) or not row["description"].strip():
                errors.append("boundaryEvidence.shape")
                continue
            try:
                refs.extend(_ref_rows(root, row.get("evidenceRefs")))
            except ExecutorEvidenceError as exc:
                errors.append(exc.code)
    approval = value.get("approval")
    if not isinstance(approval, dict) or set(approval) - {"approver", "grantedAt", "approvalRef"} or not approval.get("approver") or not approval.get("grantedAt"):
        errors.append("approval")
    if not isinstance(value.get("reason"), str) or not value["reason"].strip():
        errors.append("reason")
    if not isinstance(value.get("expiresAt"), str):
        errors.append("expiresAt")
    for field in ("expiresAt",):
        try:
            parsed = datetime.fromisoformat(str(value[field]).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                errors.append(field)
        except (KeyError, ValueError):
            errors.append(field)
    return errors, refs


def check_foundation_003(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-FOUNDATION-003"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    consumed = set(_foundation_pins(_profile(root))) | _foundation_dependencies(root)
    missing_packages = FOUNDATION_PACKAGES - consumed
    if not missing_packages:
        return _uniform(rule, "NOT_APPLICABLE", "all_foundation_packages_consumed")
    exemption, carrier = _exemption(root)
    if exemption is None:
        return _uniform(rule, "FAIL", "zero_or_partial_consumption_without_exemption")
    errors, refs = _validate_exemption(root, exemption)
    exempted = set(exemption.get("exemptedPackages", []))
    if not missing_packages <= exempted:
        errors.append("missing_packages_not_covered")
    status = "FAIL" if errors else "PASS"
    return _finish([_row("schema_validation", status, "foundation-exemption-contract", carrier=carrier, errors=errors, evidence_refs=refs)], missing_packages=sorted(missing_packages))


def _event_chain_errors(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    events = value.get("statusEvents", [])
    reviews = value.get("reviewEvents", [])
    if not isinstance(events, list) or not all(isinstance(row, dict) for row in events):
        return ["statusEvents"]
    if not isinstance(reviews, list) or not all(isinstance(row, dict) for row in reviews):
        errors.append("reviewEvents")
    for index, row in enumerate(events):
        if set(row) != {"at", "from", "to", "recordedBy"} or not row.get("recordedBy"):
            errors.append(f"statusEvents[{index}].shape")
        if index and events[index - 1].get("to") != row.get("from"):
            errors.append(f"statusEvents[{index}].continuity")
    if events and events[-1].get("to") != value.get("status"):
        errors.append("status_not_latest_event")
    return errors


def _git_snapshots(root: Path, relative: str) -> list[dict[str, Any]]:
    log = subprocess.run(["git", "-C", str(root), "log", "--format=%H", "--", relative], text=True, capture_output=True, check=False)
    if log.returncode != 0 or not log.stdout.strip():
        raise ExecutorEvidenceError("VERSION_HISTORY_MISSING", relative)
    snapshots = []
    for commit in reversed(log.stdout.splitlines()):
        shown = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{relative}"], text=True, capture_output=True, check=False)
        if shown.returncode != 0:
            raise ExecutorEvidenceError("VERSION_HISTORY_INVALID", relative)
        value = json.loads(shown.stdout)
        if not isinstance(value, dict):
            raise ExecutorEvidenceError("VERSION_HISTORY_INVALID", relative)
        snapshots.append(value)
    current = _load_json(root / relative, relative)
    if snapshots[-1] != current:
        snapshots.append(current)
    return snapshots


def _prefix_history_errors(snapshots: list[dict[str, Any]], list_fields: tuple[str, ...], mutable_fields: set[str]) -> list[str]:
    errors: list[str] = []
    for index, (before, after) in enumerate(zip(snapshots, snapshots[1:])):
        for field in list_fields:
            old, new = before.get(field, []), after.get(field, [])
            if not isinstance(old, list) or not isinstance(new, list) or new[:len(old)] != old:
                errors.append(f"revision[{index}].{field}_not_append_only")
        immutable = set(before) | set(after)
        immutable -= set(list_fields) | mutable_fields
        for field in immutable:
            if before.get(field) != after.get(field):
                errors.append(f"revision[{index}].{field}_rewritten")
    return errors


def check_foundation_006(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-FOUNDATION-006"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    exemption, carrier = _exemption(root)
    if exemption is None:
        return _uniform(rule, "NOT_APPLICABLE", "no_exemption_record")
    schema_errors, _ = _validate_exemption(root, exemption)
    schema_errors.extend(_event_chain_errors(exemption))
    try:
        expires = datetime.fromisoformat(exemption["expiresAt"].replace("Z", "+00:00"))
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            schema_errors.append("exemption_expired")
    except (KeyError, TypeError, ValueError):
        schema_errors.append("expiresAt")
    if exemption.get("status") in {"expired", "revoked"}:
        schema_errors.append("adoption_obligation_reexposed")
    try:
        snapshots = _git_snapshots(root, str(carrier))
        history_errors = _prefix_history_errors(snapshots, ("statusEvents", "reviewEvents"), {"status"})
        digest_status = "FAIL" if history_errors else "PASS"
        digest_evidence = {"carrier": carrier, "revisions": len(snapshots), "errors": history_errors}
    except ExecutorEvidenceError as exc:
        digest_status = "EVIDENCE_MISSING"
        digest_evidence = {"carrier": carrier, "reason": exc.code}
    rows = [
        _row("digest_verification", digest_status, "git-object-append-history", **digest_evidence),
        _row("schema_validation", "FAIL" if schema_errors else "PASS", "foundation-exemption-event-chain", carrier=carrier, errors=schema_errors),
    ]
    return _finish(rows, carrier=carrier)


def _no_null(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        return all(_no_null(item) for item in value.values())
    if isinstance(value, list):
        return all(_no_null(item) for item in value)
    return True


def check_foundation_020(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-FOUNDATION-020"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    packages = _foundation_pins(_profile(root))
    if not packages:
        exemption, _ = _exemption(root)
        return _uniform(rule, "NOT_APPLICABLE" if exemption else "EVIDENCE_MISSING", "zero_consumption" if exemption else "foundation_pin_missing")
    schema_errors, digest_errors = _validate_pin_rows(root, packages)
    package_path = root / "package.json"
    if package_path.is_file():
        package = _load_json(package_path, "package.json")
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            values = package.get(field, {})
            if isinstance(values, dict):
                for name in set(values) & FOUNDATION_PACKAGES:
                    if not isinstance(values[name], str) or not SEMVER.fullmatch(values[name]):
                        schema_errors.append(f"{field}.{name}:floating")
    return _finish([
        _row("digest_verification", "FAIL" if digest_errors else "PASS", "foundation-pin-byte-verification", errors=digest_errors, pins=sorted(packages)),
        _row("static_scan", "FAIL" if schema_errors else "PASS", "foundation-exact-version-scan", errors=schema_errors, pins=sorted(packages)),
    ], consumed_packages=sorted(packages))


def check_foundation_024(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-FOUNDATION-024"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    relative = ".skill-family-audit/governance/foundation-baseline-pins.json"
    if not (root / relative).is_file():
        if not _foundation_pins(_profile(root)):
            return _uniform(rule, "NOT_APPLICABLE", "foundation_not_consumed")
        return _uniform(rule, "EVIDENCE_MISSING", "baseline_pin_index_missing")
    index = _load_json(root / relative, relative)
    pins = index.get("pins")
    errors: list[str] = []
    if not isinstance(pins, list) or not pins:
        errors.append("pins")
        pins = []
    seen: set[str] = set()
    for position, pin in enumerate(pins):
        if not isinstance(pin, dict) or set(pin) != {"id", "path", "sha256", "predecessor"}:
            errors.append(f"pins[{position}].shape")
            continue
        if pin["id"] in seen or (position == 0 and pin["predecessor"] is not None) or (position and pin["predecessor"] != pins[position - 1].get("id")):
            errors.append(f"pins[{position}].chain")
        seen.add(pin["id"])
        try:
            path = _contained(root, pin["path"])
            if not HEX64.fullmatch(str(pin["sha256"])) or _sha256(path) != pin["sha256"]:
                errors.append(f"pins[{position}].digest")
        except ExecutorEvidenceError as exc:
            errors.append(f"pins[{position}].{exc.code}")
    try:
        snapshots = _git_snapshots(root, relative)
        errors.extend(_prefix_history_errors(snapshots, ("pins",), set()))
        history = len(snapshots)
        missing = False
    except ExecutorEvidenceError as exc:
        history, missing = 0, True
        history_reason = exc.code
    status = "EVIDENCE_MISSING" if missing else ("FAIL" if errors else "PASS")
    return _finish([_row("digest_verification", status, "foundation-baseline-pin-history", carrier=relative, errors=errors, history_revisions=history, reason=history_reason if missing else "checked")], pins=len(pins))


def check_depend_012(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-DEPEND-012"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    evidence_relative = ".skill-family-audit/governance/dependency-adapter-evidence.json"
    declarations = sorted((root / "spec/external-adapters").glob("agent-method-registry-*.json")) if (root / "spec/external-adapters").is_dir() else []
    if not declarations:
        return _uniform(rule, "NOT_APPLICABLE", "agent_method_registry_not_declared")
    if not (root / evidence_relative).is_file():
        return _uniform(rule, "EVIDENCE_MISSING", "adapter_tarball_evidence_missing")
    evidence = _load_json(root / evidence_relative, evidence_relative)
    bindings = evidence.get("adapters")
    if not isinstance(bindings, list):
        return _uniform(rule, "FAIL", "adapter_evidence_shape_invalid")
    static_errors: list[str] = []
    digest_errors: list[str] = []
    adapters: list[dict[str, Any]] = []
    bound_declarations = {
        row.get("declaration") for row in bindings if isinstance(row, dict)
    }
    observed_declarations = {
        path.relative_to(root).as_posix() for path in declarations
    }
    if bound_declarations != observed_declarations:
        static_errors.append("adapter_declaration_set_not_exact")
    for row in bindings:
        if not isinstance(row, dict) or set(row) != {"declaration", "tarball"}:
            static_errors.append("binding_shape")
            continue
        try:
            declaration = _load_json(_contained(root, row["declaration"]), row["declaration"])
            tarball = _contained(root, row["tarball"])
        except ExecutorEvidenceError as exc:
            digest_errors.append(exc.code)
            continue
        actual_sha = _sha256(tarball)
        actual_integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball.read_bytes()).digest()).decode("ascii")
        if declaration.get("packageTarballSha256") != actual_sha:
            digest_errors.append(f"{declaration.get('version')}:sha256")
        if declaration.get("npmIntegrity") != actual_integrity:
            digest_errors.append(f"{declaration.get('version')}:integrity")
        if declaration.get("package") != "agent-method-registry":
            static_errors.append(f"{declaration.get('version')}:package")
        adapters.append(declaration)
    by_version = {row.get("version"): row for row in adapters}
    if set(by_version) != {"0.2.0", "0.2.2"}:
        static_errors.append("supported_version_set")
    elif adapters:
        left, right = by_version["0.2.0"], by_version["0.2.2"]
        if left.get("stableRuntimeApiWhitelist") != right.get("stableRuntimeApiWhitelist"):
            static_errors.append("runtime_api_whitelist_drift")
        if left.get("cliWhitelist") != right.get("cliWhitelist"):
            static_errors.append("cli_whitelist_drift")
        left_schemas = left.get("v2Surface", {}).get("v2SchemaDigests", {})
        right_schemas = right.get("v2Surface", {}).get("v2SchemaDigests", {})
        changed = sorted(key for key in set(left_schemas) | set(right_schemas) if left_schemas.get(key) != right_schemas.get(key))
        if changed != ["method-query.schema.json"]:
            static_errors.append("incompatible_schema_delta_not_exact")
        if right.get("v2Surface", {}).get("allowedAsDependency") is not True:
            static_errors.append("current_version_not_approved")
    return _finish([
        _row("digest_verification", "FAIL" if digest_errors else "PASS", "adapter-tarball-byte-binding", errors=digest_errors, versions=sorted(by_version)),
        _row("static_scan", "FAIL" if static_errors else "PASS", "adapter-version-comparison", errors=static_errors, versions=sorted(by_version)),
    ], evidence=evidence_relative)


def check_publish_012(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-PUBLISH-012"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_source_release_unit")
    root = _root(ctx)
    package_path = root / "package.json"
    if not package_path.is_file():
        return _uniform(rule, "NOT_APPLICABLE", "no_release_unit_package")
    relative = ".skill-family-audit/governance/version-authority.json"
    if not (root / relative).is_file():
        return _uniform(rule, "EVIDENCE_MISSING", "version_authority_missing")
    authority = _load_json(root / relative, relative)
    allowed = {"schemaVersion", "kind", "source", "derivatives", "mechanicalCheck"}
    schema_errors: list[str] = []
    if set(authority) != allowed or authority.get("schemaVersion") != 1 or authority.get("kind") != "skill-family.version-authority":
        schema_errors.append("closed_schema")
    source = authority.get("source")
    if source != {"path": "package.json", "jsonPointer": "/version"}:
        schema_errors.append("source")
    derivatives = authority.get("derivatives")
    if not isinstance(derivatives, list) or len({json.dumps(row, sort_keys=True) for row in derivatives if isinstance(row, dict)}) != len(derivatives):
        schema_errors.append("derivatives")
        derivatives = []
    static_errors: list[str] = []
    source_version = _load_json(package_path, "package.json").get("version")
    if not isinstance(source_version, str) or not SEMVER.fullmatch(source_version):
        static_errors.append("source_version_invalid")
    for index, row in enumerate(derivatives):
        if not isinstance(row, dict) or set(row) != {"path", "jsonPointer"} or row.get("jsonPointer") != "/version":
            schema_errors.append(f"derivatives[{index}]")
            continue
        try:
            value = _load_json(_contained(root, row["path"]), row["path"])
            if value.get("version") != source_version:
                static_errors.append(f"{row['path']}:version_drift")
        except ExecutorEvidenceError as exc:
            static_errors.append(f"{row.get('path')}:{exc.code}")
    check = authority.get("mechanicalCheck")
    if not isinstance(check, dict) or set(check) != {"path", "argument"} or check.get("argument") != "--check":
        schema_errors.append("mechanicalCheck")
    else:
        try:
            _contained(root, check["path"])
        except ExecutorEvidenceError as exc:
            static_errors.append(f"mechanicalCheck:{exc.code}")
    return _finish([
        _row("schema_validation", "FAIL" if schema_errors else "PASS", "version-authority-schema", errors=schema_errors),
        _row("static_scan", "FAIL" if static_errors else "PASS", "version-derivative-byte-scan", errors=static_errors, version=source_version),
    ], carrier=relative)


def check_repo_006(ctx: dict[str, Any]) -> dict[str, Any]:
    rule = "SFA-REPO-006"
    if not _in_scope(ctx, "family_source", "project_adoption"):
        return _uniform(rule, "NOT_APPLICABLE", "not_a_project_source")
    root = _root(ctx)
    candidates = []
    for child in root.iterdir():
        if child.is_dir() and (child.name in {"runs", "evidence", ".runs", ".evidence", ".qoder", ".workbuddy", ".codex", ".claude"} or child.name.endswith("-runs")):
            candidates.append(child.name)
    if not candidates:
        return _uniform(rule, "NOT_APPLICABLE", "no_runtime_or_evidence_directories")
    ignore = root / ".gitignore"
    if not ignore.is_file() or ignore.is_symlink():
        return _uniform(rule, "FAIL", "gitignore_missing")
    patterns = {line.strip() for line in ignore.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
    retention, _ = _optional_json(root, (".skill-family-audit/governance/evidence-retention.json",))
    retained = set(retention.get("retainedDirectories", [])) if isinstance(retention, dict) and isinstance(retention.get("retainedDirectories"), list) else set()
    errors = []
    for name in candidates:
        ignored = any(pattern in patterns for pattern in {name, f"{name}/", f"/{name}", f"/{name}/"})
        retained_with_authority = name in {"evidence", ".evidence"} and name in retained
        if retained_with_authority:
            if not isinstance(retention.get("policyRef"), str) or not retention["policyRef"] or not isinstance(retention.get("sourceAuthorityRef"), str) or not retention["sourceAuthorityRef"]:
                errors.append(f"{name}:retention_authority_missing")
        elif not ignored:
            errors.append(f"{name}:not_ignored")
    return _finish([_row("static_scan", "FAIL" if errors else "PASS", "runtime-directory-gitignore-scan", directories=sorted(candidates), errors=errors)], directories=sorted(candidates))


CHECKS = {
    "SFA-DEPEND-012": check_depend_012,
    "SFA-FOUNDATION-002": check_foundation_002,
    "SFA-FOUNDATION-003": check_foundation_003,
    "SFA-FOUNDATION-006": check_foundation_006,
    "SFA-FOUNDATION-020": check_foundation_020,
    "SFA-FOUNDATION-024": check_foundation_024,
    "SFA-PUBLISH-012": check_publish_012,
    "SFA-REPO-006": check_repo_006,
}
