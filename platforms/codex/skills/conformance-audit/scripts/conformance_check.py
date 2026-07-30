#!/usr/bin/env python3
"""第一档静态符合性检查器：8 条规则全覆盖。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

CHECKER_METHOD_ID = "skill-family-audit:conformance-audit"
CHECKER_VERSION = "0.4.0-conformance-repair"
RULE_FIELDS = {"ruleId", "revisionDigest", "description", "applicability", "checkType", "failureImpact", "remediation"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FAMILY_NAME_RE = re.compile(r"^[a-z][a-z0-9-]+$")
FRONTMATTER_BOUNDARY = re.compile(r"^---\s*$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    if not test_fixture:
        return None, None, "EXTERNAL_SPEC_REQUIRES_TEST_FIXTURE"
    index_path, rules_path = package / "authority-index.json", package / "applicable-rules.json"
    if not index_path.is_file() or not rules_path.is_file():
        return None, None, "SPEC_PACKAGE_INCOMPLETE"
    try:
        index, manifest = _load(index_path), _load(rules_path)
    except (OSError, json.JSONDecodeError):
        return None, None, "SPEC_PACKAGE_INVALID_JSON"
    if index.get("test_fixture") is not True:
        return index, None, "SPEC_PACKAGE_NOT_TEST_FIXTURE"
    active, receipt, releases = index.get("activeSpecRelease"), index.get("approvalReceipt"), index.get("releases")
    if not isinstance(active, dict) or not isinstance(receipt, dict) or not isinstance(releases, list):
        return index, None, "APPROVAL_CLOSURE_MISSING"
    active_releases = [r for r in releases if r.get("status") == "active"]
    if len(active_releases) != 1 or active_releases[0] != active:
        return index, None, "ACTIVE_RELEASE_NOT_UNIQUE"
    actual_manifest = _file_digest(rules_path)
    required = ("releaseId", "contentDigest", "ruleManifestDigest")
    if any(not active.get(k) for k in required) or active["ruleManifestDigest"] != actual_manifest:
        return index, None, "RULE_MANIFEST_DIGEST_MISMATCH"
    if any(not receipt.get(field) for field in ("receiptId", "signedAt", "signedBy")):
        return index, None, "APPROVAL_RECEIPT_FIELDS_INVALID"
    if receipt.get("approvedObject") != active["releaseId"] or receipt.get("approvedReleaseDigest") != active["contentDigest"] or receipt.get("approvedRuleManifestDigest") != actual_manifest:
        return index, None, "APPROVAL_CLOSURE_MISMATCH"
    if receipt.get("signedBy") not in index.get("approvedAuthorities", []):
        return index, None, "APPROVAL_SIGNER_UNTRUSTED"
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
              "rule_results": results, "scan_summary": scan, "input_summary": {"target": target.name, "target_is_relative": True},
              "rule_release_summary": {"release_id": index["activeSpecRelease"]["releaseId"], "release_digest": index["activeSpecRelease"]["contentDigest"], "rule_manifest_digest": index["activeSpecRelease"]["ruleManifestDigest"]},
              "checker_summary": _checker_summary(), "warnings": [], "blocked_reason": "", "test_fixture": True,
              "publication_eligible": False}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result



def run_workspace_contract_check(workspace_path: str) -> dict:
    """Self-contained workspace-boundary gate used by the stage-5 candidate."""
    root = Path(workspace_path).resolve()
    project = root / ".release-skill/project.yaml"
    if not project.is_file():
        return _result("FAILED", "PROJECT_PARSE_FAILED", target=workspace_path)
    release_source = None
    public_sources: list[str] = []
    in_public = False
    public_indent = -1
    for raw in project.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if release_source is None and stripped.startswith("source:") and indent <= 4:
            release_source = stripped.split(":", 1)[1].strip()
        if stripped == "publicFiles:":
            in_public = True
            public_indent = indent
            continue
        if (
            in_public
            and indent <= public_indent
            and stripped
            and not stripped.startswith("- ")
        ):
            in_public = False
        if in_public:
            match = re.match(r"(?:-\s*)?(?:from|source):\s*(.+)$", stripped)
            if match:
                public_sources.append(match.group(1).strip())
    def portable(value: str) -> bool:
        return bool(value) and not value.startswith(("/", "\\")) and not re.match(r"^[A-Za-z]:", value) and "\\" not in value and "\0" not in value and "//" not in value and all(x not in {"", ".", ".."} for x in value.split("/"))
    if not release_source or not portable(release_source) or not public_sources:
        return _result("FAILED", "PATH_SYNTAX_INVALID", target=workspace_path)
    package = root / release_source
    try:
        if package.resolve() != (root / "packages/skill-family-audit").resolve():
            return _result("FAILED", "ANCHOR_ESCAPE", target=workspace_path)
    except OSError:
        return _result("FAILED", "REALPATH_ESCAPE", target=workspace_path)
    for source in public_sources:
        if source == "artifacts" or source.startswith("artifacts/") or source == "public-release.json":
            return _result("FAILED", "PUBLIC_BOUNDARY_LEAK", target=workspace_path)
        if not portable(source):
            return _result("FAILED", "PATH_TRAVERSAL" if ".." in source.split("/") else "PATH_SYNTAX_INVALID", target=workspace_path)
        cur = root
        for part in source.split("/"):
            cur = cur / part
            try:
                if cur.is_symlink():
                    return _result("FAILED", "ANCESTOR_SYMLINK_FORBIDDEN", target=workspace_path)
            except OSError:
                return _result("FAILED", "REALPATH_ESCAPE", target=workspace_path)
        try:
            cur.resolve().relative_to(package.resolve())
        except (OSError, ValueError):
            return _result("FAILED", "ANCHOR_ESCAPE", target=workspace_path)
        if not cur.is_file():
            return _result("FAILED", "FILE_TYPE_FORBIDDEN", target=workspace_path)
        public_text = cur.read_text(encoding="utf-8", errors="replace")
        if (
            re.search(r"/" + r"Users/[A-Za-z0-9._-]+/", public_text)
            or re.search(r"/" + r"home/[A-Za-z0-9._-]+/", public_text)
        ):
            return _result("FAILED", "PUBLIC_BOUNDARY_LEAK", target=workspace_path)
    return {"status": "SUCCEEDED", "summary": "workspace contract passed", "error_code": "",
            "checker_summary": _checker_summary(), "workspace_root": root.name,
            "publication_eligible": False}

def publication_consumption_error(result: dict) -> str | None:
    """发布门禁消费前的固定拒绝规则；测试夹具结果永不具备发布资格。"""
    if result.get("test_fixture") is True or result.get("publication_eligible") is False:
        return "TEST_FIXTURE_RESULT_NOT_PUBLISHABLE"
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target_path"); parser.add_argument("--project-root", default="."); parser.add_argument("--spec-version")
    parser.add_argument("--spec-package"); parser.add_argument("--test-fixture", action="store_true"); parser.add_argument("--output"); parser.add_argument("--workspace-contract", action="store_true")
    args = parser.parse_args()
    result = run_workspace_contract_check(args.target_path) if args.workspace_contract else run_conformance_check(args.target_path, args.project_root, args.spec_version, args.spec_package, args.test_fixture, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["status"] == "SUCCEEDED" else 2 if result["status"] == "BLOCKED" else 1)


if __name__ == "__main__": main()
