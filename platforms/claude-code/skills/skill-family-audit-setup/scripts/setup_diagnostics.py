#!/usr/bin/env python3
"""只读采集 skill-family-audit 当前环境、规范与平台客户端事实。"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any


PLATFORM_CLIENTS = {
    "claude-code": {
        "command": "claude",
        "environment_markers": ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"),
    },
    "codex": {
        "command": "codex",
        "environment_markers": ("CODEX_HOME",),
    },
    "kimi-code": {
        "command": "kimi",
        "environment_markers": ("KIMI_CLI",),
    },
    "workbuddy": {
        "command": "workbuddy",
        "environment_markers": ("WORKBUDDY_HOME",),
    },
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON 顶层必须是对象")
    return value


def discover_project_root(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve(strict=True)
    script = Path(__file__).resolve()
    candidates = [Path.cwd().resolve(), *Path.cwd().resolve().parents]
    candidates.extend(script.parents)
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if (candidate / "spec/authority-index.json").is_file():
            return candidate
    return script.parents[5]


def read_document_fact(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    fact: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file() and not path.is_symlink(),
        "parse_status": "not_attempted",
    }
    if not fact["exists"]:
        return None, fact
    try:
        document = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fact["parse_status"] = "invalid"
        fact["error"] = type(exc).__name__
        return None, fact
    fact["parse_status"] = "valid"
    return document, fact


def collect_approval(project_root: Path) -> tuple[dict[str, Any], list[str]]:
    summary_path = project_root / "spec/releases/candidate-spec-release-summary.json"
    receipt_path = (
        project_root
        / "spec/user-decisions/current-spec-governance-approval-receipt.json"
    )
    summary, summary_fact = read_document_fact(summary_path)
    receipt, receipt_fact = read_document_fact(receipt_path)
    warnings: list[str] = []
    current_release_id = None
    reported_status = None
    subject_status = None
    if summary is not None:
        releases = summary.get("candidateSpecReleases")
        if isinstance(releases, list) and len(releases) == 1:
            current_release_id = releases[0].get("release_id")
        reported_status = summary.get("approvalStatus")
        subject_status = summary.get("approvalSubjectStatus")
    receipt_subject = receipt.get("approved_object") if receipt else None
    receipt_matches = bool(
        current_release_id
        and receipt_subject
        and receipt_subject == current_release_id
    )
    if receipt is not None and not receipt_matches:
        warnings.append("approval_receipt_subject_mismatch")
    if summary is None or not isinstance(current_release_id, str):
        status = "approval_state_unavailable"
    elif receipt_matches:
        status = "active_approval_receipt"
    elif reported_status == "no_active_approval_receipt":
        status = "no_active_approval_receipt"
    else:
        status = "approval_state_unverified"
    return {
        "status": status,
        "reported_status": reported_status,
        "subject_status": subject_status,
        "current_release_id": current_release_id,
        "summary": summary_fact,
        "receipt": {
            **receipt_fact,
            "approved_object": receipt_subject,
            "matches_current_release": receipt_matches,
        },
    }, warnings


def collect_platforms(project_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    matrix_path = project_root / "spec/platforms/support-matrix.json"
    matrix, matrix_fact = read_document_fact(matrix_path)
    declared: set[str] = set()
    if matrix is not None and isinstance(matrix.get("platforms"), list):
        declared = {
            row.get("platformId")
            for row in matrix["platforms"]
            if isinstance(row, dict) and isinstance(row.get("platformId"), str)
        }
    platforms: list[dict[str, Any]] = []
    for platform_id, config in PLATFORM_CLIENTS.items():
        resolved = shutil.which(config["command"])
        markers = {
            name: name in os.environ
            for name in config["environment_markers"]
        }
        projection = (
            project_root / "generated/platforms" / platform_id
            / "platform-manifest.json"
        )
        platforms.append({
            "platform_id": platform_id,
            "declared_in_support_matrix": platform_id in declared,
            "client_command": config["command"],
            "client_detected": resolved is not None,
            "client_path": resolved,
            "environment_markers": markers,
            "static_projection": {
                "path": str(projection),
                "exists": projection.is_file() and not projection.is_symlink(),
            },
            "status": "client_detected" if resolved else "client_not_detected",
        })
    return platforms, matrix_fact


def collect_diagnostics(project_root: Path) -> dict[str, Any]:
    authority_path = project_root / "spec/authority-index.json"
    authority, authority_fact = read_document_fact(authority_path)
    approval, approval_warnings = collect_approval(project_root)
    platforms, matrix_fact = collect_platforms(project_root)
    python_supported = sys.version_info >= (3, 11)
    spec_directory = project_root / "spec"
    blockers: list[str] = []
    if not python_supported:
        blockers.append("python_below_3_11")
    if not spec_directory.is_dir():
        blockers.append("spec_directory_missing")
    if authority is None:
        blockers.append("authority_index_unavailable")
    if approval["summary"]["parse_status"] != "valid":
        blockers.append("approval_summary_unavailable")
    if matrix_fact["parse_status"] != "valid":
        blockers.append("platform_support_matrix_unavailable")
    warnings = list(approval_warnings)
    warnings.extend(
        f"{row['platform_id']}_client_not_detected"
        for row in platforms
        if not row["client_detected"]
    )
    identity = authority.get("identity") if authority else None
    return {
        "schema_version": "1.0.0",
        "kind": "skill-family-audit.setup-diagnostics",
        "status": "BLOCKED" if blockers else "READY",
        "project_root": str(project_root),
        "environment": {
            "python": {
                "version": ".".join(str(value) for value in sys.version_info[:3]),
                "executable": sys.executable,
                "required": ">=3.11",
                "status": "supported" if python_supported else "unsupported",
            },
            "specification": {
                "directory": str(spec_directory),
                "directory_exists": spec_directory.is_dir(),
                "authority_index": {
                    **authority_fact,
                    "identity": identity,
                },
            },
            "approval": approval,
            "platform_support_matrix": matrix_fact,
            "platforms": platforms,
        },
        "actions_required": blockers,
        "warnings": sorted(set(warnings)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="只读诊断 skill-family-audit 当前运行环境"
    )
    parser.add_argument("--project-root")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    try:
        project_root = discover_project_root(args.project_root)
        result = collect_diagnostics(project_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {
            "schema_version": "1.0.0",
            "kind": "skill-family-audit.setup-diagnostics",
            "status": "BLOCKED",
            "actions_required": ["project_root_unavailable"],
            "warnings": [type(exc).__name__],
        }
    print(json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
        **({} if args.compact else {"indent": 2}),
    ))
    return 0 if result["status"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
