"""Invoke the pinned Release Skill verifier and map its result for Audit.

The adapter executes exactly one caller-selected, byte-pinned public command:
Release Skill 0.9.17 ``verify-records``. It never discovers release records,
uses ``PATH`` to locate either executable, follows record-carried paths, or
reimplements Release Skill's plan, approval, digest, lineage, or state logic.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


UPSTREAM_PROTOCOL_ID = "release-skill.verify-records"
UPSTREAM_CONTRACT_VERSION = "0.9.17"
PINNED_CLI_SHA256 = (
    "df0779f5f23ac6d4d72f71271ce9ff50a9a98f739e8a4ca9a5707fcb460fc737"
)
PINNED_BUNDLE_SHA256 = (
    "37bbd3a8569616c08115ae02a81d0f31490b5c5143ecf59d7e3418943526fbf4"
)
UPSTREAM_BLOCKED_CODE = "RELEASE_VERIFIER_INPUT_UNAVAILABLE"
UPSTREAM_INVALID_CODE = "RELEASE_VERIFIER_EXECUTION_INVALID"
PROCESS_TIMEOUT_SECONDS = 60

_OUTPUT_FIELDS = {
    "status", "unitId", "targetVersion", "historicalTerminalStatus",
    "inputs", "digests", "findings",
}
_RECORD_FIELDS = {"plan", "approval", "targetRun", "sourceRuns"}
_STATUSES = {"CONSISTENT", "CONTRADICTED", "INSUFFICIENT"}
_EXIT_CODES = {"CONSISTENT": 0, "CONTRADICTED": 1, "INSUFFICIENT": 2}
_TERMINAL_STATUSES = {"PARTIAL", "PUBLISHED", "VERIFIED"}
_FINDING_CODES = {
    "INPUT_MISSING", "INPUT_DAMAGED", "FORMAT_UNSUPPORTED",
    "PLAN_DIGEST_MISMATCH", "APPROVAL_DIGEST_MISMATCH", "RUN_DIGEST_MISMATCH",
    "IDENTITY_MISMATCH", "PLAN_BINDING_MISMATCH", "APPROVAL_ACTION_MISMATCH",
    "RUN_LINEAGE_MISMATCH", "TRANSITION_MISMATCH", "CHECKPOINT_MISMATCH",
    "HISTORICAL_TIME_MISSING", "HISTORICAL_TIME_OUTSIDE_WINDOW",
}


class TrustedVerifierError(RuntimeError):
    """The pinned verifier could not produce an attributable result."""

    def __init__(self, code: str, detail: str, *, blocked: bool = False) -> None:
        self.code = code
        self.detail = detail
        self.blocked = blocked
        super().__init__(f"{code}:{detail}")


def _base(expected_unit_id: str, expected_target_version: str) -> dict[str, Any]:
    return {
        "protocol_id": "skill-family-audit.release-receipt-audit",
        "protocol_version": "2.0.0",
        "upstream_protocol": UPSTREAM_PROTOCOL_ID,
        "upstream_contract_version": UPSTREAM_CONTRACT_VERSION,
        "candidate": {
            "unit_id": expected_unit_id,
            "target_version": expected_target_version,
        },
        "gate_findings": [],
        "blocking_reasons": [],
        "evidence": [],
    }


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _absolute_normalized(value: str, label: str) -> Path:
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, f"{label}_path_not_absolute_normalized"
        )
    return Path(value)


def _real_file(value: str, label: str) -> Path:
    path = _absolute_normalized(value, label)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise TrustedVerifierError(
            UPSTREAM_BLOCKED_CODE,
            f"{label}_unavailable:{exc}",
            blocked=True,
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or resolved != path or not stat.S_ISREG(metadata.st_mode):
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, f"{label}_not_real_regular_file"
        )
    return path


def _record_snapshot(value: str, label: str) -> dict[str, Any]:
    """Snapshot one explicit record path; absence stays an upstream fact."""
    path = _absolute_normalized(value, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"path": path, "exists": False, "bytes_sha256": None}
    except OSError as exc:
        raise TrustedVerifierError(
            UPSTREAM_BLOCKED_CODE, f"{label}_unavailable:{exc}", blocked=True
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, f"{label}_not_real_regular_file"
        )
    try:
        if path.resolve(strict=True) != path:
            raise TrustedVerifierError(
                UPSTREAM_INVALID_CODE, f"{label}_path_resolution_changed"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustedVerifierError(
            UPSTREAM_BLOCKED_CODE, f"{label}_unreadable:{exc}", blocked=True
        ) from exc
    return {"path": path, "exists": True, "bytes_sha256": _sha256(raw)}


def _assert_snapshot_unchanged(snapshot: dict[str, Any], label: str) -> None:
    current = _record_snapshot(str(snapshot["path"]), label)
    if (
        current["exists"] != snapshot["exists"]
        or current["bytes_sha256"] != snapshot["bytes_sha256"]
    ):
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, f"{label}_changed_during_verification"
        )


def _trusted_provider_snapshot(release_skill_cli: str) -> dict[str, Any]:
    cli = _real_file(release_skill_cli, "release_skill_cli")
    if cli.name != "release-skill.mjs" or cli.parent.name != "bin":
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, "release_skill_cli_layout_invalid"
        )
    bundle = _real_file(
        str(cli.with_name("release-skill.bundle.mjs")), "release_skill_bundle"
    )
    package = _real_file(
        str(cli.parent.parent / "package.json"), "release_skill_package"
    )
    try:
        package_document = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, f"release_skill_package_invalid:{exc}"
        ) from exc
    if (
        not isinstance(package_document, dict)
        or package_document.get("name") != "release-skill"
        or package_document.get("version") != UPSTREAM_CONTRACT_VERSION
        or package_document.get("bin", {}).get("release-skill")
        != "./bin/release-skill.mjs"
    ):
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, "release_skill_package_identity_invalid"
        )
    snapshot = {
        "cli": cli,
        "bundle": bundle,
        "cli_sha256": _sha256(cli.read_bytes()),
        "bundle_sha256": _sha256(bundle.read_bytes()),
    }
    if snapshot["cli_sha256"] != PINNED_CLI_SHA256:
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, "release_skill_cli_pin_mismatch"
        )
    if snapshot["bundle_sha256"] != PINNED_BUNDLE_SHA256:
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, "release_skill_bundle_pin_mismatch"
        )
    return snapshot


def _assert_provider_unchanged(snapshot: dict[str, Any]) -> None:
    if (
        _sha256(snapshot["cli"].read_bytes()) != snapshot["cli_sha256"]
        or _sha256(snapshot["bundle"].read_bytes()) != snapshot["bundle_sha256"]
    ):
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE,
            "release_skill_provider_changed_during_verification",
        )


def _digest_shape(value: Any, expected_bytes_sha256: str | None) -> bool:
    if expected_bytes_sha256 is None:
        return value is None
    return (
        isinstance(value, dict)
        and set(value) == {
            "bytesSha256", "carriedDomainDigest", "recomputedDomainDigest"
        }
        and value.get("bytesSha256") == expected_bytes_sha256
        and (
            value.get("carriedDomainDigest") is None
            or _hex64(value.get("carriedDomainDigest"))
        )
        and (
            value.get("recomputedDomainDigest") is None
            or _hex64(value.get("recomputedDomainDigest"))
        )
    )


def _shape_problems(
    value: dict[str, Any],
    *,
    expected_unit_id: str,
    expected_target_version: str,
    records: dict[str, Any],
) -> list[str]:
    problems: list[str] = []
    if set(value) != _OUTPUT_FIELDS:
        problems.append("top_level_fields_not_closed")
    status = value.get("status")
    if status not in _STATUSES:
        problems.append("status_invalid")
    if value.get("unitId") != expected_unit_id:
        problems.append("unit_id_mismatch")
    if value.get("targetVersion") != expected_target_version:
        problems.append("target_version_mismatch")
    terminal = value.get("historicalTerminalStatus")
    if terminal is not None and terminal not in _TERMINAL_STATUSES:
        problems.append("historical_terminal_status_invalid")

    inputs = value.get("inputs")
    digests = value.get("digests")
    if not isinstance(inputs, dict) or set(inputs) != _RECORD_FIELDS:
        problems.append("inputs_shape_invalid")
        inputs = {}
    if not isinstance(digests, dict) or set(digests) != _RECORD_FIELDS:
        problems.append("digests_shape_invalid")
        digests = {}
    source_inputs = inputs.get("sourceRuns")
    source_digests = digests.get("sourceRuns")
    if not isinstance(source_inputs, list):
        problems.append("source_inputs_invalid")
        source_inputs = []
    if not isinstance(source_digests, list):
        problems.append("source_digests_invalid")
        source_digests = []
    if len(source_inputs) != len(records["sourceRuns"]):
        problems.append("source_input_cardinality_mismatch")
    if len(source_digests) != len(records["sourceRuns"]):
        problems.append("source_digest_cardinality_mismatch")

    for role, snapshot in (
        ("plan", records["plan"]),
        ("approval", records["approval"]),
        ("targetRun", records["targetRun"]),
    ):
        summary = inputs.get(role)
        if (
            not isinstance(summary, dict)
            or set(summary) != {"role", "source"}
            or summary.get("role") != role
            or summary.get("source") != snapshot["path"].name
        ):
            problems.append(f"input_summary_invalid:{role}")
        if not _digest_shape(digests.get(role), snapshot["bytes_sha256"]):
            problems.append(f"digest_binding_invalid:{role}")

    for index, snapshot in enumerate(records["sourceRuns"]):
        role = f"sourceRun[{index}]"
        summary = source_inputs[index] if index < len(source_inputs) else None
        digest = source_digests[index] if index < len(source_digests) else None
        if (
            not isinstance(summary, dict)
            or set(summary) != {"role", "source"}
            or summary.get("role") != role
            or summary.get("source") != snapshot["path"].name
        ):
            problems.append(f"input_summary_invalid:{role}")
        if not _digest_shape(digest, snapshot["bytes_sha256"]):
            problems.append(f"digest_binding_invalid:{role}")

    findings = value.get("findings")
    if not isinstance(findings, list):
        problems.append("findings_invalid")
        findings = []
    for index, finding in enumerate(findings):
        if (
            not isinstance(finding, dict)
            or set(finding) != {"code", "role", "message"}
            or finding.get("code") not in _FINDING_CODES
            or not _nonempty_string(finding.get("role"))
            or not _nonempty_string(finding.get("message"))
        ):
            problems.append(f"finding_invalid:{index}")
    if status == "CONSISTENT" and findings:
        problems.append("consistent_output_has_findings")
    if status in {"CONTRADICTED", "INSUFFICIENT"} and not findings:
        problems.append("non_consistent_output_missing_findings")
    return problems


def _finding_text(finding: dict[str, Any]) -> str:
    return f"{finding['code']}:{finding['role']}:{finding['message']}"


def _execution_evidence(
    *,
    node_version: str,
    provider: dict[str, Any],
    completed: subprocess.CompletedProcess[bytes],
    records: dict[str, Any],
    output: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "release-skill-verify-records-execution",
        "contract_version": UPSTREAM_CONTRACT_VERSION,
        "provider": {
            "cli_sha256": provider["cli_sha256"],
            "bundle_sha256": provider["bundle_sha256"],
        },
        "command": "verify-records",
        "node_version": node_version,
        "exit_code": completed.returncode,
        "stdout_sha256": _sha256(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": _sha256(completed.stderr),
        "candidate": {
            "unit_id": output["unitId"],
            "target_version": output["targetVersion"],
        },
        "status": output["status"],
        "historical_terminal_status": output["historicalTerminalStatus"],
        "input_bytes_sha256": {
            "plan": records["plan"]["bytes_sha256"],
            "approval": records["approval"]["bytes_sha256"],
            "targetRun": records["targetRun"]["bytes_sha256"],
            "sourceRuns": [row["bytes_sha256"] for row in records["sourceRuns"]],
        },
        "output_digests": copy.deepcopy(output["digests"]),
    }


def _invoke_verify_records(
    *,
    node_runtime: Path,
    node_version: str,
    release_skill_cli: str,
    plan_path: str,
    approval_path: str,
    target_run_path: str,
    source_run_paths: list[str],
    expected_unit_id: str,
    expected_target_version: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(node_runtime, Path) or not _nonempty_string(node_version):
        raise TrustedVerifierError(
            UPSTREAM_BLOCKED_CODE, "foundation_node_runtime_invalid", blocked=True
        )
    node = _real_file(str(node_runtime), "foundation_node_runtime")
    provider = _trusted_provider_snapshot(release_skill_cli)
    records = {
        "plan": _record_snapshot(plan_path, "plan"),
        "approval": _record_snapshot(approval_path, "approval"),
        "targetRun": _record_snapshot(target_run_path, "target_run"),
        "sourceRuns": [
            _record_snapshot(path, f"source_run_{index}")
            for index, path in enumerate(source_run_paths)
        ],
    }
    command = [
        str(node), str(provider["cli"]), "verify-records",
        "--plan", str(records["plan"]["path"]),
        "--approval", str(records["approval"]["path"]),
        "--target-run", str(records["targetRun"]["path"]),
    ]
    for snapshot in records["sourceRuns"]:
        command.extend(["--source-run", str(snapshot["path"])])
    command.extend([
        "--unit", expected_unit_id,
        "--target-version", expected_target_version,
        "--json",
    ])
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TrustedVerifierError(
            UPSTREAM_BLOCKED_CODE,
            f"verify_records_process_unavailable:{exc}",
            blocked=True,
        ) from exc

    _assert_provider_unchanged(provider)
    _assert_snapshot_unchanged(records["plan"], "plan")
    _assert_snapshot_unchanged(records["approval"], "approval")
    _assert_snapshot_unchanged(records["targetRun"], "target_run")
    for index, snapshot in enumerate(records["sourceRuns"]):
        _assert_snapshot_unchanged(snapshot, f"source_run_{index}")

    try:
        output = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, f"verify_records_stdout_invalid:{exc}"
        ) from exc
    if not isinstance(output, dict):
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, "verify_records_stdout_not_object"
        )
    problems = _shape_problems(
        output,
        expected_unit_id=expected_unit_id,
        expected_target_version=expected_target_version,
        records=records,
    )
    if completed.returncode != _EXIT_CODES.get(output.get("status")):
        problems.append("exit_status_mismatch")
    if problems:
        raise TrustedVerifierError(
            UPSTREAM_INVALID_CODE, ",".join(problems)
        )
    return output, _execution_evidence(
        node_version=node_version,
        provider=provider,
        completed=completed,
        records=records,
        output=output,
    )


def audit_release_receipts(
    *,
    node_runtime: Path,
    node_version: str,
    release_skill_cli: str,
    plan_path: str,
    approval_path: str,
    target_run_path: str,
    source_run_paths: list[str],
    expected_unit_id: str,
    expected_target_version: str,
) -> dict[str, Any]:
    """Execute and consume the exact pinned public ``verify-records`` command.

    Result mapping is static over the upstream status: ``CONTRADICTED`` fails,
    ``INSUFFICIENT`` blocks, and ``CONSISTENT`` succeeds for this record check
    alone. Success here does not assert that the target run was published or
    verified; the upstream ``historicalTerminalStatus`` is preserved in the
    execution evidence and is not a success condition.
    """
    result = _base(expected_unit_id, expected_target_version)
    if not _nonempty_string(expected_unit_id) or not _nonempty_string(expected_target_version):
        result.update(
            status="FAILED",
            gate_findings=[f"{UPSTREAM_INVALID_CODE}:candidate_identity_missing"],
        )
        return result
    if not isinstance(source_run_paths, list) or not all(
        isinstance(path, str) for path in source_run_paths
    ):
        result.update(
            status="FAILED",
            gate_findings=[f"{UPSTREAM_INVALID_CODE}:source_run_paths_invalid"],
        )
        return result
    try:
        output, evidence = _invoke_verify_records(
            node_runtime=node_runtime,
            node_version=node_version,
            release_skill_cli=release_skill_cli,
            plan_path=plan_path,
            approval_path=approval_path,
            target_run_path=target_run_path,
            source_run_paths=source_run_paths,
            expected_unit_id=expected_unit_id,
            expected_target_version=expected_target_version,
        )
    except TrustedVerifierError as exc:
        if exc.blocked:
            result.update(status="BLOCKED", blocking_reasons=[str(exc)])
        else:
            result.update(status="FAILED", gate_findings=[str(exc)])
        return result

    result["evidence"] = [evidence]
    findings = [_finding_text(item) for item in output["findings"]]
    if output["status"] == "CONTRADICTED":
        result.update(status="FAILED", gate_findings=findings)
        return result
    if output["status"] == "INSUFFICIENT":
        result.update(status="BLOCKED", blocking_reasons=findings)
        return result
    # CONSISTENT: this static record set is internally consistent. The
    # upstream ``historicalTerminalStatus`` (VERIFIED, PUBLISHED, PARTIAL, or
    # absent) stays a provider fact in the execution evidence; it is neither
    # an additional success condition nor a veto over this record check.
    result["status"] = "SUCCEEDED"
    return result


__all__ = [
    "UPSTREAM_PROTOCOL_ID", "UPSTREAM_CONTRACT_VERSION",
    "PINNED_CLI_SHA256", "PINNED_BUNDLE_SHA256",
    "UPSTREAM_BLOCKED_CODE", "UPSTREAM_INVALID_CODE",
    "audit_release_receipts",
]
