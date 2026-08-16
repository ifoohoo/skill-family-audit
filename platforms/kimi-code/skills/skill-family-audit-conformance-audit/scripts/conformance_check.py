#!/usr/bin/env python3
"""第一档静态符合性检查器：8 条规则全覆盖。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CHECKER_METHOD_ID = "skill-family-audit:conformance-audit"
CHECKER_VERSION = "0.4.0-conformance-repair"
RULE_FIELDS = {"ruleId", "revisionDigest", "description", "applicability", "checkType", "failureImpact", "remediation"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FAMILY_NAME_RE = re.compile(r"^[a-z][a-z0-9-]+$")
FRONTMATTER_BOUNDARY = re.compile(r"^---\s*$")
FOUNDATION_PROFILE_EXPECTED = {"id": "quickstart-profile", "version": 2}
FOUNDATION_RECEIPT_KINDS = {
    "skill-family.foundation-local-tarball-receipt",
    "foundation-local-three-package-receipt",
    "skill-family.release-artifacts-manifest",
}
NODE_VERSION_MIN = (22, 22, 2)
NODE_VERSION_EXCLUSIVE_MAX = (23, 0, 0)
NODE_VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)")
FOUNDATION_FIXED_ENTRIES = frozenset({
    "runner.mjs",
    "validators.mjs",
    "mechanisms-cli.mjs",
    "adoption-cli.mjs",
})


class FoundationNodeRuntimeError(RuntimeError):
    """The explicitly bound Foundation Node runtime is not trustworthy."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code = code


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_path_chain_no_symlinks(path: Path, error_code: str = "FOUNDATION_RUNNER_SYMLINK") -> None:
    """检查路径完整链上无符号链接：对原始绝对路径逐段执行 lstat 风格检查。

    不调用 resolve()，避免中间层符号链接被消解后逃逸检查。
    任一已存在路径分量或最终入口为符号链接即失败关闭。
    """
    if not path.is_absolute():
        raise RuntimeError(error_code)
    current = path
    while current != current.parent:
        if current.is_symlink():
            raise RuntimeError(error_code)
        current = current.parent


def verify_foundation_bundle(entry_ref: str) -> Path:
    """Verify one fixed entry's static import closure before Node imports it."""
    raw = Path(entry_ref).expanduser()
    symlink_error = (
        "FOUNDATION_RUNNER_SYMLINK"
        if raw.name == "runner.mjs"
        else "FOUNDATION_BUNDLE_MEMBER_SYMLINK"
    )
    invalid_error = (
        "FOUNDATION_RUNNER_INVALID"
        if raw.name == "runner.mjs"
        else "FOUNDATION_ENTRY_INVALID"
    )
    _check_path_chain_no_symlinks(raw, symlink_error)
    if not raw.is_file() or raw.name not in FOUNDATION_FIXED_ENTRIES:
        raise RuntimeError(invalid_error)
    entry = raw.resolve(strict=True)
    if not entry.is_file():
        raise RuntimeError(invalid_error)

    bundle_root = entry.parent
    provenance_raw = bundle_root / "foundation-projection.json"
    for member in (provenance_raw, entry):
        _check_path_chain_no_symlinks(member, "FOUNDATION_BUNDLE_MEMBER_SYMLINK")
        if not member.is_file():
            raise RuntimeError("FOUNDATION_BUNDLE_MEMBER_MISSING")

    provenance = _load(provenance_raw.resolve(strict=True))
    if provenance.get("kind") != "skill-family.foundation-projection":
        raise RuntimeError("FOUNDATION_BUNDLE_PROVENANCE_INVALID")
    profile = provenance.get("profile")
    if (
        not isinstance(profile, dict)
        or profile.get("id") != FOUNDATION_PROFILE_EXPECTED["id"]
        or profile.get("version") != FOUNDATION_PROFILE_EXPECTED["version"]
    ):
        raise RuntimeError("FOUNDATION_BUNDLE_PROVENANCE_INVALID")
    payload = provenance.get("payload")
    files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(files, list) or not files:
        raise RuntimeError("FOUNDATION_BUNDLE_PAYLOAD_INVALID")
    declared: dict[str, str] = {}
    for record in files:
        relative = record.get("path") if isinstance(record, dict) else None
        digest = record.get("sha256") if isinstance(record, dict) else None
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or relative in declared
        ):
            raise RuntimeError("FOUNDATION_BUNDLE_PAYLOAD_INVALID")
        declared[relative] = digest
    source = provenance.get("source")
    if not isinstance(source, dict):
        raise RuntimeError("FOUNDATION_RECEIPT_INVALID")
    handoff_raw = bundle_root.parent / "foundation-handoff.json"
    pin_raw = bundle_root.parent / "foundation-pin.json"
    if handoff_raw.is_file():
        _check_path_chain_no_symlinks(handoff_raw, "FOUNDATION_RECEIPT_INVALID")
        handoff = _load(handoff_raw)
        receipt = handoff.get("receipt")
        if (
            handoff.get("kind") != "skill-family-audit.foundation-handoff"
            or handoff.get("schemaVersion") != 2
            or handoff.get("source") != {
                "repository": source.get("repository"),
                "baseCommit": source.get("baseCommit"),
            }
            or not isinstance(receipt, dict)
            or receipt.get("kind") not in FOUNDATION_RECEIPT_KINDS
            or not isinstance(receipt.get("receiptId"), str)
            or not HEX64.fullmatch(receipt.get("sha256", ""))
            or handoff.get("payloadDigest") != payload.get("digest")
            or handoff.get("provenanceDigest") != _sha256(provenance_raw)
        ):
            raise RuntimeError("FOUNDATION_RECEIPT_INVALID")
    else:
        _check_path_chain_no_symlinks(pin_raw, "FOUNDATION_RECEIPT_INVALID")
        if not pin_raw.is_file():
            raise RuntimeError("FOUNDATION_RECEIPT_INVALID")
        pin = _load(pin_raw)
        pin_profile = pin.get("profile")
        pin_source = pin.get("source")
        if (
            pin.get("schemaVersion") != "1.0"
            or not isinstance(pin_profile, dict)
            or {key: pin_profile.get(key) for key in ("id", "version")} != {
                "id": profile.get("id"), "version": profile.get("version")
            }
            or not isinstance(pin_source, dict)
            or {
                "repository": pin_source.get("repository"),
                "baseCommit": pin_source.get("baseCommit"),
            } != {
                "repository": source.get("repository"),
                "baseCommit": source.get("baseCommit"),
            }
            or pin.get("bundle", {}).get("payloadSha256") != payload.get("digest")
        ):
            raise RuntimeError("FOUNDATION_RECEIPT_INVALID")

    pending = [entry]
    checked: set[str] = set()
    import_pattern = re.compile(r'(?:from\s*|import\s*)["\'](\.[^"\']+)["\']')
    while pending:
        member = pending.pop()
        _check_path_chain_no_symlinks(member, "FOUNDATION_BUNDLE_MEMBER_SYMLINK")
        if not member.is_file():
            raise RuntimeError("FOUNDATION_BUNDLE_MEMBER_MISSING")
        resolved = member.resolve(strict=True)
        try:
            relative = resolved.relative_to(bundle_root).as_posix()
        except ValueError as exc:
            raise RuntimeError("FOUNDATION_BUNDLE_IMPORT_ESCAPE") from exc
        if relative in checked:
            continue
        if declared.get(relative) != _sha256(resolved):
            raise RuntimeError("FOUNDATION_BUNDLE_MEMBER_DIGEST_MISMATCH")
        checked.add(relative)
        if resolved.suffix == ".mjs":
            source = resolved.read_text(encoding="utf-8")
            pending.extend(resolved.parent / match for match in import_pattern.findall(source))
    return entry


def _reject_ambiguous_runner_role() -> None:
    if "SFA_FOUNDATION_RUNNER_REF" in os.environ:
        raise RuntimeError("FOUNDATION_RUNNER_ROLE_AMBIGUOUS")


def foundation_runner() -> Path:
    """Resolve only Audit's Bundle for schemas, canonical data and closures."""
    _reject_ambiguous_runner_role()
    configured = os.environ.get("SFA_AUDIT_BUNDLE_RUNNER_REF")
    if configured:
        return verify_foundation_bundle(configured)
    raise RuntimeError(
        "FOUNDATION_AUDIT_RUNNER_MISSING: 需要通过 SFA_AUDIT_BUNDLE_RUNNER_REF 显式绑定 Audit 的受管 Foundation Bundle"
    )


def target_foundation_runner(expected: Path) -> Path:
    """Resolve only the target Bundle and require exact lock-derived identity."""
    _reject_ambiguous_runner_role()
    configured = os.environ.get("SFA_TARGET_BUNDLE_RUNNER_REF")
    if configured != str(expected):
        raise RuntimeError("FOUNDATION_TARGET_RUNNER_MISMATCH")
    return verify_foundation_bundle(configured)


def foundation_node_runtime() -> tuple[Path, str]:
    """Resolve the explicit, real Node 22 runtime used by every Bundle CLI."""
    ref = os.environ.get("SFA_FOUNDATION_NODE")
    if not ref:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_MISSING", "SFA_FOUNDATION_NODE 环境变量未设置"
        )
    raw = Path(ref)
    if not raw.is_absolute():
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_NOT_ABSOLUTE", f"SFA_FOUNDATION_NODE 必须是绝对路径: {ref}"
        )
    try:
        _check_path_chain_no_symlinks(raw, "NODE_PATH_SYMLINK")
    except RuntimeError as exc:
        raise FoundationNodeRuntimeError(
            "NODE_PATH_SYMLINK", f"Node.js 路径链包含符号链接: {raw}"
        ) from exc
    if not raw.is_file():
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_MISSING_FILE", f"Node.js 入口文件不存在: {ref}"
        )
    try:
        completed = subprocess.run(
            [str(raw), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_UNAVAILABLE", f"Node.js 版本探测失败: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_UNAVAILABLE",
            f"Node.js --version 失败: {completed.stderr.strip()}",
        )
    version = completed.stdout.strip()
    match = NODE_VERSION_RE.match(version)
    if not match:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_VERSION_UNPARSEABLE", f"Node.js 版本字符串无法解析: {version}"
        )
    parsed = tuple(int(match.group(index)) for index in range(1, 4))
    if parsed < NODE_VERSION_MIN or parsed >= NODE_VERSION_EXCLUSIVE_MAX:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_VERSION_INCOMPATIBLE",
            f"Node.js 版本 {version} 不在 >=22.22.2 <23 范围内",
        )
    return raw, version


def call_foundation_cli(runner: Path, cli_name: str, request: dict) -> object:
    """Call one fixed CLI from the already verified managed Bundle."""
    if cli_name not in {"mechanisms-cli.mjs", "adoption-cli.mjs"}:
        raise RuntimeError("FOUNDATION_CLI_NOT_ALLOWED")
    runner = verify_foundation_bundle(str(runner))
    cli = verify_foundation_bundle(str(runner.parent / cli_name))
    node_path, _node_version = foundation_node_runtime()
    if request.get("operation") != "self-check":
        self_check = _run_foundation_cli(node_path, cli, {"operation": "self-check", "params": {}})
        if not isinstance(self_check, dict) or self_check.get("valid") is not True:
            raise RuntimeError("FOUNDATION_CLI_SELF_CHECK_FAILED")
    return _run_foundation_cli(node_path, cli, request)


def _run_foundation_cli(node_path: Path, cli: Path, request: dict) -> object:
    completed = subprocess.run(
        [str(node_path), str(cli)],
        input=json.dumps(request, ensure_ascii=False).encode("utf-8"),
        capture_output=True, check=False,
    )
    try:
        stdout = completed.stdout.decode("utf-8", errors="strict")
        stderr = completed.stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Foundation CLI returned invalid UTF-8") from exc
    if completed.returncode != 0:
        raise RuntimeError(stderr.strip() or "Foundation CLI failed")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Foundation CLI returned invalid JSON") from exc


def call_foundation_mechanism(runner: Path, request: dict) -> dict:
    """Invoke one of the Bundle's fixed, domain-neutral mechanisms."""
    operation = str(request.get("operation", ""))
    params = (
        {"document": request.get("document")}
        if operation in {"canonical-json", "digest-document"}
        else {key: value for key, value in request.items() if key != "operation"}
    )
    result = call_foundation_cli(
        runner,
        "mechanisms-cli.mjs",
        {"operation": operation, "params": params},
    )
    if operation == "canonical-json":
        if (
            not isinstance(result, dict)
            or set(result) != {"text"}
            or not isinstance(result.get("text"), str)
        ):
            raise RuntimeError("Foundation canonical-json returned invalid response")
        return result
    if not isinstance(result, dict):
        raise RuntimeError("Foundation mechanism returned non-object")
    return result


def _foundation(request: dict) -> dict:
    return call_foundation_mechanism(foundation_runner(), request)


def _digest(value: object) -> str:
    return str(
        _foundation({"operation": "digest-document", "document": value})["digest"]
    )


def _file_digest(path: Path) -> str:
    closure = _foundation({
        "operation": "resource-closure",
        "root": str(path.parent),
        "resources": [{"path": path.name, "role": "input"}],
    })
    return str(closure["resources"][0]["sha256"])


def foundation_host_for(module_file: str, runner: Path | None = None) -> object:
    """Return this single host only to a sibling in the same managed platform tree."""
    caller = Path(module_file).resolve(strict=True)
    host_file = Path(__file__).resolve(strict=True)
    allowed_roots: list[Path] = []
    if runner is None:
        allowed_roots.append(foundation_runner().parents[2])
    for origin in (host_file, caller):
        source_root = next(
            (ancestor / "plugin-src" for ancestor in origin.parents if (ancestor / "plugin-src").is_dir()),
            None,
        )
        if source_root is not None:
            allowed_roots.append(source_root.resolve(strict=True))
    if runner is not None and host_file in runner.parents[2].parents:
        allowed_roots.append(runner.parents[2])
    if not any(caller == root or root in caller.parents for root in allowed_roots):
        raise RuntimeError("FOUNDATION_HOST_CALLER_OUTSIDE_PLATFORM")
    return sys.modules.get(__name__) or sys.modules.get("conformance_check")


def _relative_name(value: str) -> str:
    return Path(value).name if value else ""


def _checker_summary() -> dict:
    return {"method_id": CHECKER_METHOD_ID, "version": CHECKER_VERSION,
            "content_digest": _file_digest(Path(__file__).resolve())}


def _result(status: str, reason: str = "", index: dict | None = None, target: str = "") -> dict:
    index = index or {}
    active = index.get("activeSpecRelease") or {}
    return {"status": status, "summary": "规范检查被阻断" if status == "BLOCKED" else "规范检查失败",
            "error_code": reason, "counts": {"total": 0, "pass": 0, "fail": 0, "not_run": 0, "blocked": int(status == "BLOCKED"), "evidence_missing": 0},
            "rule_results": [], "scan_summary": {"skill_files": [], "agent_files": [], "script_files": [], "manifest_files": []},
            "input_summary": {"target": _relative_name(target), "target_is_relative": True},
            "rule_release_summary": {"release_id": active.get("releaseId", ""), "release_digest": active.get("contentDigest", ""), "rule_manifest_digest": active.get("ruleManifestDigest", "")},
            "checker_summary": _checker_summary(), "warnings": [], "blocked_reason": reason}


def _blocked(code: str, index: dict | None = None, target: str = "") -> dict:
    return _result("BLOCKED", code, index, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_package(package: Path, test_fixture: bool) -> tuple[dict | None, dict | None, str | None]:
    index_path, rules_path = package / "authority-index.json", package / "applicable-rules.json"
    if not index_path.is_file() or not rules_path.is_file():
        return None, None, "SPEC_PACKAGE_INCOMPLETE"
    try:
        index, manifest = _load(index_path), _load(rules_path)
    except (OSError, json.JSONDecodeError):
        return None, None, "SPEC_PACKAGE_INVALID_JSON"
    if index.get("test_fixture") is True and not test_fixture:
        return index, None, "EXTERNAL_SPEC_REQUIRES_TEST_FIXTURE"
    if test_fixture and index.get("test_fixture") is not True:
        return index, None, "SPEC_PACKAGE_NOT_TEST_FIXTURE"
    return index, manifest, None


def _scan(target: Path) -> dict:
    result = {"skill_files": [], "agent_files": [], "script_files": [], "manifest_files": []}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in {"node_modules", "__pycache__"}]
        for filename in files:
            rel = (Path(root) / filename).relative_to(target).as_posix()
            if filename == "SKILL.md": result["skill_files"].append(rel)
            elif filename.endswith((".py", ".sh")): result["script_files"].append(rel)
            elif filename.endswith(".md") and "agent" in filename.lower(): result["agent_files"].append(rel)
            elif filename == "manifest.json" or filename.endswith(".plugin.json"): result["manifest_files"].append(rel)
    return result


def _parse_frontmatter(content: str) -> tuple[dict | None, str | None]:
    """解析 YAML frontmatter，返回 (data, error)。最小实现：只支持简单键值对。"""
    lines = content.split("\n")
    if not lines or not FRONTMATTER_BOUNDARY.match(lines[0]):
        return None, "no_frontmatter_boundary"
    end_idx = None
    for i in range(1, len(lines)):
        if FRONTMATTER_BOUNDARY.match(lines[i]):
            end_idx = i
            break
    if end_idx is None:
        return None, "unclosed_frontmatter"
    fm_lines = lines[1:end_idx]
    data = {}
    for line in fm_lines:
        raw_line = line
        line = line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if raw_line[:1].isspace():
            return None, "unsupported_nested_frontmatter"
        if ":" not in line:
            return None, "malformed_frontmatter_line"
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            return None, "empty_frontmatter_key"
        if key in data:
            return None, f"duplicate_key:{key}"
        if value.startswith('"') != value.endswith('"'):
            return None, f"unclosed_quote:{key}"
        if value.startswith("'") != value.endswith("'"):
            return None, f"unclosed_quote:{key}"
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        elif value.lower() in ("true", "yes"):
            value = True
        elif value.lower() in ("false", "no"):
            value = False
        elif value.isdigit():
            value = int(value)
        data[key] = value
    if not isinstance(data, dict):
        return None, "frontmatter_not_mapping"
    return data, None


def _extract_family_from_path(rel_path: str, target: Path) -> str:
    """从相对路径和目标目录提取 family 名称。

    - 如果 SKILL.md 在子目录中（如 `family/SKILL.md`），family 是第一级目录
    - 如果 SKILL.md 在目标根目录（如 `SKILL.md`），family 是目标目录名
    """
    parts = Path(rel_path).parts
    if len(parts) > 1:
        return parts[0]
    return target.name


def _check(rule_id: str, scan: dict, target: Path) -> dict:
    """执行单条规则检查，返回 {status, evidence}。"""
    if rule_id == "structure:skills-exist":
        has_skills = len(scan["skill_files"]) > 0
        return {"status": "PASS" if has_skills else "FAIL",
                "evidence": {"skill_files": scan["skill_files"], "count": len(scan["skill_files"])}}

    if rule_id == "structure:skill-frontmatter-exists":
        evidence = []
        all_have = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            has_fm = bool(re.search(r"^---\s*$", content, re.MULTILINE) and
                         content.index("---") == 0 and
                         content.count("---") >= 2)
            evidence.append({"file": rel, "has_frontmatter": has_fm})
            if not has_fm:
                all_have = False
        return {"status": "PASS" if all_have else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:skill-frontmatter-valid":
        evidence = []
        all_valid = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            valid = error is None and isinstance(data, dict)
            evidence.append({"file": rel, "valid": valid, "error": error})
            if not valid:
                all_valid = False
        return {"status": "PASS" if all_valid else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:skill-name-present":
        evidence = []
        all_present = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            has_name = error is None and isinstance(data, dict) and "name" in data and data["name"]
            evidence.append({"file": rel, "has_name": has_name, "error": error})
            if not has_name:
                all_present = False
        return {"status": "PASS" if all_present else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:skill-description-present":
        evidence = []
        all_present = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            has_desc = error is None and isinstance(data, dict) and "description" in data and data["description"]
            evidence.append({"file": rel, "has_description": has_desc, "error": error})
            if not has_desc:
                all_present = False
        return {"status": "PASS" if all_present else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:entry-count":
        # 入口技能：frontmatter 有非空 name、不是内部技能且没有显式禁止用户调用。
        entry_count = 0
        evidence = []
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            name = data.get("name") if isinstance(data, dict) else None
            is_internal = isinstance(data, dict) and data.get("internal") is True
            user_invocable = data.get("user-invocable") if isinstance(data, dict) else None
            is_entry = bool(
                error is None
                and isinstance(name, str)
                and name.strip()
                and not is_internal
                and user_invocable is not False
            )
            if is_entry:
                entry_count += 1
            evidence.append({
                "file": rel,
                "is_entry": is_entry,
                "is_internal": is_internal,
                "user_invocable": user_invocable,
                "error": error,
            })
        return {"status": "PASS" if entry_count > 0 else "FAIL",
                "evidence": {"entry_count": entry_count, "files": evidence}}

    if rule_id == "naming:family-name-format":
        families = set()
        evidence = []
        all_valid = True
        for rel in scan["skill_files"]:
            family = _extract_family_from_path(rel, target)
            if family and family not in families:
                families.add(family)
                valid = bool(FAMILY_NAME_RE.match(family))
                evidence.append({"family": family, "valid": valid})
                if not valid:
                    all_valid = False
        if not families:
            return {"status": "FAIL", "evidence": {"reason": "no_families_found"}}
        return {"status": "PASS" if all_valid else "FAIL", "evidence": {"families": evidence}}

    if rule_id == "visibility:internal-not-user-invocable":
        # 检查是否有内部技能同时标记为 user-invocable: true
        violations = []
        evidence = []
        parse_errors = []
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            if error or not isinstance(data, dict):
                evidence.append({"file": rel, "parsed": False, "error": error})
                parse_errors.append({"file": rel, "error": error})
                continue
            # 检查是否为内部技能
            is_internal = data.get("internal") is True or data.get("internal") == "true"
            user_invocable = data.get("user-invocable") is True or data.get("user-invocable") == "true"
            has_violation = is_internal and user_invocable
            evidence.append({"file": rel, "is_internal": is_internal, "user_invocable": user_invocable,
                           "violation": has_violation})
            if has_violation:
                violations.append(rel)
        if parse_errors:
            return {
                "status": "NOT_RUN",
                "evidence": {"reason": "frontmatter_unavailable", "parse_errors": parse_errors, "files": evidence},
            }
        return {"status": "FAIL" if violations else "PASS",
                "evidence": {"violations": violations, "files": evidence}}

    # --- 四条 scope 规则（FM-03 残留标注）---
    # 下列四条分支对 conformance_check.py 兼容入口是死代码，刻意保留不删除：
    # 1. 四条 scope 规则的 applicability 分别为 single_skill / family_source /
    #    release_artifact / project_adoption（见 0.1.27-candidate
    #    refs/applicable-rules.json），本入口的 run_conformance_check 只处理
    #    applicability ∈ {"all", "skill"} 的规则，四类目标由
    #    conformance_workflow.py 按显式 target_type 专属分支承担
    #    （scope:*-complete 的按 target 类型语义在 conformance_workflow.py
    #    L2021-2046 附近，含 project_adoption 的 Foundation 采用完整性校验）。
    # 2. 保留分支以防规则投影回归到本入口时 fail-closed（返回 FAIL 而非误放行）。
    # 3. 本入口只审计 skill 目标，此处出现的目标类型规则不得在此混入错误分母。
    # --- 四条 scope 规则：fail-closed，通过正常 ruleCategories 执行 ---
    if rule_id == "scope:single-skill-complete":
        has_skills = len(scan.get("skill_files", [])) > 0
        return {"status": "PASS" if has_skills else "FAIL",
                "evidence": {"skill_files": scan.get("skill_files", []), "count": len(scan.get("skill_files", []))}}

    if rule_id == "scope:family-source-complete":
        family_files = (
            [f for f in scan.get("script_files", []) if "plugin-src" in f or "spec" in f]
            + scan.get("manifest_files", [])
            + scan.get("skill_files", [])
        )
        return {"status": "PASS" if family_files else "FAIL",
                "evidence": {"family_files": family_files, "count": len(family_files)}}

    if rule_id == "scope:release-artifact-complete":
        artifact_files = scan.get("manifest_files", [])
        return {"status": "PASS" if artifact_files else "FAIL",
                "evidence": {"artifact_files": artifact_files, "count": len(artifact_files)}}

    if rule_id == "scope:project-adoption-present":
        adoption_files = scan.get("skill_files", []) + scan.get("manifest_files", [])
        return {"status": "PASS" if adoption_files else "FAIL",
                "evidence": {"adoption_files": adoption_files, "count": len(adoption_files)}}

    return {"status": "EVIDENCE_MISSING", "evidence": {"reason": "unknown_checker", "rule_id": rule_id}}


def run_conformance_check(target_path: str, project_root: str, spec_version_ref: str | None = None,
                          spec_package: str | None = None, test_fixture: bool = False,
                          output_path: str | None = None) -> dict:
    target, root = Path(target_path).resolve(), Path(project_root).resolve()
    if not target.exists(): return _blocked("TARGET_NOT_FOUND", target=target_path)
    if output_path:
        resolved = Path(output_path).resolve()
        try: resolved.relative_to(root)
        except ValueError: return _blocked("OUTPUT_OUTSIDE_AUTHORIZED_ROOT", target=target_path)
        output = resolved
    else: output = None
    if spec_package:
        index, manifest, error = _validate_package(Path(spec_package).resolve(), test_fixture)
        if error: return _blocked(error, index, target_path)
    else:
        # 当前仓库无批准收据，正式路径必须默认关闭；绝不读取本地 refs。
        return _blocked("NO_ACTIVE_APPROVED_SPEC", target=target_path)
    if manifest.get("checkerMethodId") != CHECKER_METHOD_ID:
        return _blocked("UNKNOWN_CHECKER", index, target_path)
    scan, results = _scan(target), []
    for category in manifest.get("ruleCategories", []):
        for rule in category.get("rules", []):
            # 该兼容入口只审计 skill；四类目标由 conformance_workflow.py
            # 按显式 target_type 过滤和执行，不能在这里混入错误分母。
            if rule.get("applicability") not in {"all", "skill"}:
                continue
            rule_id = rule.get("ruleId", "unknown")
            expected = rule.get("revisionDigest")
            actual = _digest({k: v for k, v in rule.items() if k != "revisionDigest"})
            if set(rule) != RULE_FIELDS or not HEX64.fullmatch(str(expected)):
                outcome = {"status": "NOT_RUN", "evidence": {"reason": "invalid_rule_definition"}}
            elif expected != actual:
                outcome = {"status": "BLOCKED", "evidence": {"reason": "rule_revision_digest_mismatch"}}
            else:
                try:
                    outcome = _check(rule_id, scan, target)
                except Exception as exc:
                    outcome = {"status": "NOT_RUN", "evidence": {"reason": "checker_exception", "exception_type": type(exc).__name__}}
            results.append({"rule_id": rule_id, "rule_revision_digest": expected or "", **outcome})
    counts = {key: sum(r["status"] == label for r in results) for key, label in
              {"pass":"PASS", "fail":"FAIL", "not_run":"NOT_RUN", "blocked":"BLOCKED", "evidence_missing":"EVIDENCE_MISSING"}.items()}
    counts["total"] = len(results)
    if counts["blocked"]:
        status, error_code = "BLOCKED", "RULE_BLOCKED"
    elif not counts["total"]:
        status, error_code = "FAILED", "RULE_MANIFEST_EMPTY"
    elif counts["evidence_missing"]:
        status, error_code = "FAILED", "RULE_EVIDENCE_MISSING"
    elif counts["not_run"]:
        status, error_code = "FAILED", "RULE_NOT_RUN"
    elif counts["fail"]:
        status, error_code = "FAILED", "RULE_FAILED"
    else:
        status, error_code = "SUCCEEDED", ""
    result = {"status": status, "summary": "规范检查通过" if status == "SUCCEEDED" else "规范检查失败",
              "error_code": error_code, "counts": counts,
              "rule_results": results,
              "scan_summary": scan, "input_summary": {"target": target.name, "target_is_relative": True},
              "rule_release_summary": {"release_id": "", "release_digest": "", "rule_manifest_digest": ""},
              "checker_summary": _checker_summary(), "warnings": [], "blocked_reason": "",
              "test_fixture": index.get("test_fixture") is True,
              "publication_eligible": index.get("test_fixture") is not True}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result



def publication_consumption_error(result: dict) -> str | None:
    """发布门禁消费前的固定拒绝规则；测试夹具结果永不具备发布资格。"""
    if result.get("test_fixture") is True or result.get("publication_eligible") is False:
        return "TEST_FIXTURE_RESULT_NOT_PUBLISHABLE"
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target_path"); parser.add_argument("--project-root", default="."); parser.add_argument("--spec-version")
    parser.add_argument("--spec-package"); parser.add_argument("--test-fixture", action="store_true"); parser.add_argument("--output")
    args = parser.parse_args()
    result = run_conformance_check(args.target_path, args.project_root, args.spec_version, args.spec_package, args.test_fixture, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["status"] == "SUCCEEDED" else 2 if result["status"] == "BLOCKED" else 1)


if __name__ == "__main__": main()
