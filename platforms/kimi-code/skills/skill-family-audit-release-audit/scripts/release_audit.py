#!/usr/bin/env python3
"""只读单向 release-audit CLI；全程零子进程调用（processExecution=none）。

方法合同只绑定一个 ``release-audit-input`` Resource，显式指定候选身份（unit_id、
target_version）、发布评估引用（assessments_ref）及可选静态记录路径（records）。
Audit 仅做纯静态评估汇总与候选身份闭合核对，并支持通过 ``--conclusion-output``
在零外部进程条件下单向产出符合 ``professional-conclusion`` 契约的结论文件供发布方消费。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import release_assessments
import release_public

IMPLEMENTATION_FILES = (
    "release_audit.py",
    "release_assessments.py",
    "release_public.py",
)

RELEASE_AUDIT_INPUT_KIND = "skill-family-audit.release-audit-input"
PROFESSIONAL_CONCLUSION_KIND = "skill-family.professional-conclusion"
PROVIDER_ID = "skill-family-audit"
PROVIDER_ENTRY = "skill-family-audit:release-audit"


class ReleaseCliError(Exception):
    """CLI input or boundary validation failed."""


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseCliError(f"argument error: {message}")


def implementation_digest() -> str:
    scripts_dir = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for filename in IMPLEMENTATION_FILES:
        raw = (scripts_dir / filename).read_bytes()
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def _provider_version() -> str:
    for root in Path(__file__).resolve().parents:
        for rel in ("platform-manifest.json", "plugin-src/manifest.json", "package.json"):
            cand = root / rel
            if cand.is_file() and not cand.is_symlink():
                try:
                    data = json.loads(cand.read_text(encoding="utf-8"))
                    ver = data.get("version")
                    if isinstance(ver, str) and ver:
                        return ver
                except (OSError, json.JSONDecodeError):
                    continue
    return "1.1.68"


def _absolute_normalized(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ReleaseCliError(f"{label} must be an absolute normalized path")
    return value


def _static_record_snapshot(path_str: str, label: str) -> dict[str, Any]:
    path = Path(_absolute_normalized(path_str, label))
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {"label": label, "path": str(path), "exists": False, "sha256": None, "valid_json": False, "parsed": None}
    except OSError as exc:
        raise ReleaseCliError(f"{label} unavailable: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or path.resolve(strict=True) != path:
        raise ReleaseCliError(f"{label} must be a real regular file without symlinks")
    raw = path.read_bytes()
    parsed: Any = None
    valid_json = False
    try:
        loaded = json.loads(raw.decode("utf-8"))
        if isinstance(loaded, dict):
            parsed = loaded
            valid_json = True
    except (UnicodeDecodeError, json.JSONDecodeError):
        valid_json = False
    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "valid_json": valid_json,
        "parsed": parsed,
    }


def _verify_record_identity_closure(
    snapshots_by_label: dict[str, dict[str, Any]],
    *,
    expected_unit_id: str,
    expected_target_version: str,
) -> list[str]:
    """Verify static release records bind to expected candidate identity (unit_id, target_version, planDigest)."""
    findings: list[str] = []
    expected_cid = f"{expected_unit_id}:{expected_target_version}"

    plan_doc = snapshots_by_label["records.plan"]["parsed"]
    plan_digest: str | None = None
    if isinstance(plan_doc, dict):
        raw_pd = plan_doc.get("planDigest") or plan_doc.get("plan_digest")
        if isinstance(raw_pd, str) and len(raw_pd) == 64:
            plan_digest = raw_pd
        # Accept either release-skill plan structure (releaseUnits/targetVersion/version) or explicit candidate tuple
        cand = plan_doc.get("candidate")
        units = plan_doc.get("releaseUnits")
        ver_match = (
            plan_doc.get("targetVersion") == expected_target_version
            or plan_doc.get("version") == expected_target_version
            or (isinstance(cand, dict) and cand.get("unit_id") == expected_unit_id and cand.get("target_version") == expected_target_version)
            or plan_doc.get("candidate_id") == expected_cid
            or (
                isinstance(units, list)
                and any(
                    isinstance(u, dict)
                    and u.get("id") == expected_unit_id
                    and (u.get("version") == expected_target_version or u.get("targetVersion") == expected_target_version)
                    for u in units
                )
            )
        )
        unit_match = (
            plan_doc.get("unitId") in (None, expected_unit_id)
            and (not isinstance(cand, dict) or cand.get("unit_id") == expected_unit_id)
        )
        if not ver_match or not unit_match:
            findings.append("STATIC_RECORD_IDENTITY_MISMATCH:records.plan")

    approval_doc = snapshots_by_label["records.approval"]["parsed"]
    if isinstance(approval_doc, dict):
        app_pd = approval_doc.get("planDigest") or approval_doc.get("plan_digest")
        cand = approval_doc.get("candidate")
        has_valid_binding = (
            (isinstance(app_pd, str) and len(app_pd) == 64 and (plan_digest is None or app_pd == plan_digest))
            or (isinstance(cand, dict) and cand.get("unit_id") == expected_unit_id and cand.get("target_version") == expected_target_version)
            or approval_doc.get("candidate_id") == expected_cid
        )
        if not has_valid_binding:
            findings.append("STATIC_RECORD_IDENTITY_MISMATCH:records.approval")

    run_doc = snapshots_by_label["records.target_run"]["parsed"]
    if isinstance(run_doc, dict):
        run_pd = run_doc.get("planDigest") or run_doc.get("plan_digest")
        cand = run_doc.get("candidate")
        run_id = run_doc.get("runId") or run_doc.get("run_id")
        has_run_binding = (
            (isinstance(run_id, str) and bool(run_id.strip()) and (plan_digest is None or run_pd in (None, plan_digest)))
            or (isinstance(cand, dict) and cand.get("unit_id") == expected_unit_id and cand.get("target_version") == expected_target_version)
            or run_doc.get("candidate_id") == expected_cid
        )
        if not has_run_binding:
            findings.append("STATIC_RECORD_IDENTITY_MISMATCH:records.target_run")

    for label, snap in snapshots_by_label.items():
        if not label.startswith("records.source_runs["):
            continue
        sdoc = snap["parsed"]
        if isinstance(sdoc, dict):
            has_src_id = bool(
                sdoc.get("runId")
                or sdoc.get("run_id")
                or sdoc.get("candidate_id") == expected_cid
                or (isinstance(sdoc.get("candidate"), dict) and sdoc["candidate"].get("target_version") == expected_target_version)
            )
            if not has_src_id:
                findings.append(f"STATIC_RECORD_IDENTITY_MISMATCH:{label}")
    return findings


def _static_audit_records(
    records: dict[str, Any] | None,
    *,
    expected_unit_id: str,
    expected_target_version: str,
) -> dict[str, Any]:
    base = {
        "protocol_id": "skill-family-audit.static-release-record-audit",
        "protocol_version": "3.0.0",
        "process_execution": "none",
        "candidate": {
            "unit_id": expected_unit_id,
            "target_version": expected_target_version,
        },
        "status": "SUCCEEDED",
        "gate_findings": [],
        "blocking_reasons": [],
        "evidence": [],
    }
    if records is None:
        return base

    snapshots: list[dict[str, Any]] = []
    for field in ("plan", "approval", "target_run"):
        snapshots.append(_static_record_snapshot(records[field], f"records.{field}"))
    for idx, src in enumerate(records["source_runs"]):
        snapshots.append(_static_record_snapshot(src, f"records.source_runs[{idx}]"))

    missing = [s["label"] for s in snapshots if not s["exists"]]
    damaged = [s["label"] for s in snapshots if s["exists"] and not s["valid_json"]]
    base["evidence"] = [
        {
            "kind": "static-release-record-digest",
            "label": s["label"],
            "path": s["path"],
            "exists": s["exists"],
            "sha256": s["sha256"],
        }
        for s in snapshots
    ]
    if damaged:
        base["status"] = "FAILED"
        base["gate_findings"] = [f"STATIC_RECORD_DAMAGED:{label}" for label in damaged]
    elif missing:
        base["status"] = "BLOCKED"
        base["blocking_reasons"] = [f"STATIC_RECORD_MISSING:{label}" for label in missing]
    else:
        by_label = {s["label"]: s for s in snapshots}
        identity_mismatches = _verify_record_identity_closure(
            by_label,
            expected_unit_id=expected_unit_id,
            expected_target_version=expected_target_version,
        )
        if identity_mismatches:
            base["status"] = "FAILED"
            base["gate_findings"] = identity_mismatches
    return base


def _load_release_audit_input(value: str) -> dict[str, Any]:
    path = Path(_absolute_normalized(value, "release-audit input"))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseCliError(f"release-audit input is unavailable: {exc}") from exc
    if resolved != path or not resolved.is_file():
        raise ReleaseCliError("release-audit input must be a real file without symlinks")
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseCliError(f"release-audit input is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ReleaseCliError("release-audit input top level must be an object")

    allowed_fields = {"schema_version", "kind", "candidate", "assessments_ref", "records"}
    required_fields = {"schema_version", "kind", "candidate", "assessments_ref"}
    if "release_skill" in document:
        raise ReleaseCliError("release_skill subprocess configuration is retired; release-audit is strictly processExecution=none")
    if not required_fields <= set(document) or not set(document) <= allowed_fields:
        raise ReleaseCliError("release-audit input field set must be closed")
    if (
        document.get("schema_version") != "1.0.0"
        or document.get("kind") != RELEASE_AUDIT_INPUT_KIND
    ):
        raise ReleaseCliError("release-audit input identity is invalid")
    candidate = document.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {"unit_id", "target_version"}:
        raise ReleaseCliError("release-audit input candidate shape is invalid")
    if (
        not isinstance(candidate.get("unit_id"), str)
        or not candidate["unit_id"]
        or not isinstance(candidate.get("target_version"), str)
        or not candidate["target_version"]
    ):
        raise ReleaseCliError("release-audit input candidate identity is invalid")
    assessments_ref = document.get("assessments_ref")
    _absolute_normalized(assessments_ref, "assessments_ref")

    records = document.get("records")
    if records is not None:
        if not isinstance(records, dict) or set(records) != {
            "plan",
            "approval",
            "target_run",
            "source_runs",
        }:
            raise ReleaseCliError("records shape is invalid")
        for field in ("plan", "approval", "target_run"):
            _absolute_normalized(records.get(field), f"records.{field}")
        source_runs = records.get("source_runs")
        if not isinstance(source_runs, list) or not all(isinstance(p, str) for p in source_runs):
            raise ReleaseCliError("records.source_runs must be an array of paths")
        for idx, p in enumerate(source_runs):
            _absolute_normalized(p, f"records.source_runs[{idx}]")
    return document


def project_professional_conclusion(
    response: dict[str, Any],
    *,
    assessments_sha256: str | None = None,
) -> dict[str, Any]:
    """Project one release-audit domain response into a unidirectional professional-conclusion."""
    rel_res = response["release_result"]
    cand_id = rel_res.get("candidate_id", "unknown:0.0.0")
    unit_id, target_version = cand_id.split(":", 1) if ":" in cand_id else (cand_id, "0.0.0")
    status = rel_res["status"]
    checked = ["conformance", "platforms", "exceptions", "release_policy"]
    limitations: list[str] = []
    gate_findings = list(response.get("gate_findings") or [])
    blocking_reasons = list(response.get("blocking_reasons") or [])
    blocking_count = len(gate_findings) + len(blocking_reasons)
    if status == "SUCCEEDED":
        completion = "complete"
        code = "AUDIT_RELEASE_GATE_CLEAR"
        summary = "静态发布门禁评估通过，可供下游发布工具单向消费。"
    elif status == "BLOCKED":
        completion = "partial"
        code = "AUDIT_RELEASE_GATE_BLOCKED"
        limitations = blocking_reasons or ["发布门禁证据不完整或处于受阻态"]
        summary = "静态发布门禁评估处于受阻态，存在未满足前置条件。"
    else:
        completion = "complete"
        code = "AUDIT_RELEASE_GATE_FINDINGS"
        summary = "静态发布门禁评估检出阻断性问题。"
    revision = f"sha256:{assessments_sha256}" if assessments_sha256 else target_version
    return {
        "schemaVersion": 1,
        "kind": PROFESSIONAL_CONCLUSION_KIND,
        "provider": {
            "id": PROVIDER_ID,
            "version": _provider_version(),
            "entry": PROVIDER_ENTRY,
        },
        "subject": {
            "ref": f"pkg:{unit_id}@{target_version}",
            "revision": revision,
        },
        "scope": {
            "checked": checked,
            "limitations": limitations,
        },
        "outcome": {
            "completion": completion,
            "code": code,
            "summary": summary,
        },
        "details": {
            **response,
            "blockingFindingsCount": blocking_count,
        },
    }


def _assert_valid_professional_conclusion_pure(doc: Any) -> None:
    """Validate professional-conclusion 2020-12 contract invariants in pure Python (zero subprocess)."""
    if not isinstance(doc, dict) or set(doc) != {
        "schemaVersion",
        "kind",
        "provider",
        "subject",
        "scope",
        "outcome",
        "details",
    }:
        raise ReleaseCliError("professional-conclusion top-level fields invalid")
    if doc["schemaVersion"] != 1 or doc["kind"] != PROFESSIONAL_CONCLUSION_KIND:
        raise ReleaseCliError("professional-conclusion identity invalid")
    prov = doc["provider"]
    if (
        not isinstance(prov, dict)
        or set(prov) != {"id", "version", "entry"}
        or any(not isinstance(prov[k], str) or not prov[k].strip() for k in ("id", "version", "entry"))
    ):
        raise ReleaseCliError("professional-conclusion provider invalid")
    subj = doc["subject"]
    if (
        not isinstance(subj, dict)
        or set(subj) != {"ref", "revision"}
        or any(not isinstance(subj[k], str) or not subj[k].strip() for k in ("ref", "revision"))
    ):
        raise ReleaseCliError("professional-conclusion subject invalid")
    scope = doc["scope"]
    if (
        not isinstance(scope, dict)
        or set(scope) != {"checked", "limitations"}
        or not isinstance(scope["checked"], list)
        or not scope["checked"]
        or any(not isinstance(x, str) or not x.strip() for x in scope["checked"])
        or not isinstance(scope["limitations"], list)
        or any(not isinstance(x, str) or not x.strip() for x in scope["limitations"])
    ):
        raise ReleaseCliError("professional-conclusion scope invalid")
    outcome = doc["outcome"]
    if (
        not isinstance(outcome, dict)
        or set(outcome) != {"completion", "code", "summary"}
        or outcome["completion"] not in {"complete", "partial"}
        or any(not isinstance(outcome[k], str) or not outcome[k].strip() for k in ("code", "summary"))
    ):
        raise ReleaseCliError("professional-conclusion outcome invalid")
    if outcome["completion"] == "partial" and not scope["limitations"]:
        raise ReleaseCliError("professional-conclusion partial outcome requires non-empty scope.limitations")
    details = doc["details"]
    if (
        not isinstance(details, dict)
        or not isinstance(details.get("blockingFindingsCount"), int)
        or isinstance(details.get("blockingFindingsCount"), bool)
        or details["blockingFindingsCount"] < 0
    ):
        raise ReleaseCliError("professional-conclusion details.blockingFindingsCount invalid")


def _validate_and_write_conclusion(conclusion: dict[str, Any], output_raw: str) -> None:
    out_path = Path(_absolute_normalized(output_raw, "conclusion-output"))
    if out_path.exists() or out_path.is_symlink():
        raise ReleaseCliError(f"conclusion-output must not already exist: {out_path}")
    parent = out_path.parent.resolve(strict=True)
    if parent != out_path.parent:
        raise ReleaseCliError("conclusion-output parent must not contain symlinks")

    _assert_valid_professional_conclusion_pure(conclusion)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(out_path), flags, 0o600)
    try:
        os.write(fd, (json.dumps(conclusion, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    document = _load_release_audit_input(args.release_audit_input)
    candidate = document["candidate"]
    digest_before = implementation_digest()

    static_audit = _static_audit_records(
        document.get("records"),
        expected_unit_id=candidate["unit_id"],
        expected_target_version=candidate["target_version"],
    )
    assessments_path = Path(
        _absolute_normalized(document["assessments_ref"], "release assessments")
    ).resolve(strict=True)
    assessments_sha256 = hashlib.sha256(assessments_path.read_bytes()).hexdigest()
    assessment_result = release_assessments.assess(
        release_assessments.load(assessments_path),
        expected_candidate_id=f"{candidate['unit_id']}:{candidate['target_version']}",
    )
    if implementation_digest() != digest_before:
        raise ReleaseCliError("release-audit implementation changed during execution")
    response = release_public._compose_domain_result(
        expected_unit_id=candidate["unit_id"],
        expected_target_version=candidate["target_version"],
        verifier_audit=static_audit,
        assessment_result=assessment_result,
        assessments_path=document["assessments_ref"],
    )
    if getattr(args, "conclusion_output", None):
        conclusion = project_professional_conclusion(response, assessments_sha256=assessments_sha256)
        _validate_and_write_conclusion(conclusion, args.conclusion_output)
    status = response["release_result"]["status"]
    return (0 if status == "SUCCEEDED" else 1 if status == "BLOCKED" else 2), response


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        description="Statically audit release assessments without external subprocess invocation"
    )
    parser.add_argument("--release-audit-input", required=True)
    parser.add_argument("--conclusion-output", required=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        code, response = run(_parser().parse_args(raw_argv))
    except Exception as exc:
        response = {
            "release_result": {
                "status": "BLOCKED",
                "summary": f"发布审计预执行失败: {exc}",
            },
            "gate_findings": [],
            "evidence_list": [],
            "blocking_reasons": [str(exc)],
        }
        code = 2
    print(json.dumps(response, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
