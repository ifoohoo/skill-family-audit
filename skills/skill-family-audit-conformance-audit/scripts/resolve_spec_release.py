#!/usr/bin/env python3
"""阶段二规范发布解析器；不生成批准收据，也不使用回退规则源。"""

from __future__ import annotations

import json
import re
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BLOCKED_PREFIXES = ("README", "standards/", "docs/superpowers/specs/2026-07-19-skill-family-governance-discussion")
APPROVAL_DECISION_FIXED_PATH = "spec/user-decisions/current-spec-approval-subject.json"
GOVERNANCE_APPROVAL_RECEIPT_PATH = (
    "spec/user-decisions/current-spec-governance-approval-receipt.json"
)
FOUR_PLATFORM_SCOPE = "skill-family-audit:four-primary-platforms"
EXTERNAL_SCOPE = "skill-family-audit:external-conformance"
EXTERNAL_CONSUMER_FILES = (
    "spec/authority-index.json",
    "spec/applicable-rules.json",
)
EXTERNAL_INVENTORY_REF = "governance/rules/canonical-rule-inventory.json"
EXTERNAL_POLICY_REFS = (
    "spec/policies/release-gate.json",
    "spec/policies/non-exempt-baselines.json",
    "spec/policies/exception-policy.json",
    "spec/policies/monotonic-tightening.json",
    "governance/policies/non-waivable-mapping.json",
)
EXTERNAL_REQUIRED_REFS = frozenset(
    EXTERNAL_CONSUMER_FILES + (EXTERNAL_INVENTORY_REF,) + EXTERNAL_POLICY_REFS
)
EXTERNAL_SUMMARY_PATH = "candidate-summary.json"
EXTERNAL_RELEASE_INDEX_PATH = "release-index.json"
EXTERNAL_OPTIONAL_SPEC_FILES = frozenset({
    APPROVAL_DECISION_FIXED_PATH,
    GOVERNANCE_APPROVAL_RECEIPT_PATH,
})
APPROVAL_DECISION_FIELDS = {
    "schemaVersion", "decisionId", "status", "decidedAt", "approver",
    "approvedObject", "approvedCandidateId", "approvedCandidatePayloadDigest",
    "approvedCandidateSummaryDigest", "approvalPackageDigest",
    "nonExemptPolicyDigest",
}
APPROVAL_DECISION_FREEZE_FIELDS = {
    "approvedFreezeEvidenceRef",
    "approvedFreezeEvidenceFileDigest",
    "approvedFreezePackageDigest",
}
APPROVED_REFERENCE_SNAPSHOT_DIR = "reference-snapshot"


def _blocked(reason: str) -> dict[str, Any]:
    return {"status": "blocked", "active_release": None, "reason": reason}


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _validate_freeze_evidence_binding(
    decision: dict[str, Any],
    root: Path,
) -> str | None:
    """验证 1.1.0 决定对最终冻结证据的精确内容绑定。"""
    evidence_ref = decision.get("approvedFreezeEvidenceRef")
    evidence_file_digest = decision.get("approvedFreezeEvidenceFileDigest")
    package_digest = decision.get("approvedFreezePackageDigest")
    if (
        not isinstance(evidence_ref, str)
        or not evidence_ref.startswith(".codex/reconciliation/")
        or not evidence_ref.endswith(".json")
    ):
        return "decision_freeze_evidence_ref_invalid"
    if not isinstance(evidence_file_digest, str) or not HEX64.fullmatch(
        evidence_file_digest
    ):
        return "decision_freeze_evidence_file_digest_invalid"
    if not isinstance(package_digest, str) or not HEX64.fullmatch(package_digest):
        return "decision_freeze_package_digest_invalid"

    root_resolved = root.resolve()
    evidence_path = (root / evidence_ref).resolve()
    if root_resolved not in evidence_path.parents:
        return "decision_freeze_evidence_outside_root"
    if not evidence_path.is_file() or evidence_path.is_symlink():
        return "decision_freeze_evidence_missing_or_symlink"
    try:
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
    except (OSError, json.JSONDecodeError):
        return "decision_freeze_evidence_parse_error"
    if hashlib.sha256(evidence_bytes).hexdigest() != evidence_file_digest:
        return "decision_freeze_evidence_file_digest_mismatch"
    if not isinstance(evidence, dict):
        return "decision_freeze_evidence_not_object"
    if evidence.get("evidenceKind") != "skill_family_candidate_final_freeze":
        return "decision_freeze_evidence_kind_invalid"
    if evidence.get("status") != "FROZEN_AWAITING_CANDIDATE_GOVERNANCE_APPROVAL":
        return "decision_freeze_evidence_status_invalid"
    if evidence.get("packageDigest") != package_digest:
        return "decision_freeze_package_digest_mismatch"

    candidate = evidence.get("candidate")
    if not isinstance(candidate, dict):
        return "decision_freeze_candidate_missing"
    if candidate.get("candidateId") != decision.get("approvedCandidateId"):
        return "decision_freeze_candidate_id_mismatch"
    if (
        candidate.get("candidatePayloadDigest")
        != decision.get("approvedCandidatePayloadDigest")
    ):
        return "decision_freeze_candidate_payload_digest_mismatch"
    if (
        candidate.get("candidateSummarySha256")
        != decision.get("approvedCandidateSummaryDigest")
    ):
        return "decision_freeze_candidate_summary_digest_mismatch"

    authorization = evidence.get("authorization")
    if not isinstance(authorization, dict):
        return "decision_freeze_authorization_missing"
    if authorization.get("candidateFreezeCompleted") is not True:
        return "decision_freeze_not_completed"
    if authorization.get("candidateGovernanceApprovalGranted") is not False:
        return "decision_freeze_preapproved"
    for field in ("commit", "push", "tag", "publish"):
        if authorization.get(field) is not False:
            return f"decision_freeze_forbidden_authorization:{field}"
    return None


def _release_reference_digests(release: dict[str, Any]) -> dict[str, str] | None:
    """汇总发布引用与平台档案/投影的精确摘要。"""
    references = release.get("references")
    reference_digests = release.get("reference_digests")
    bindings = release.get("platformBindings")
    if (
        not isinstance(references, list)
        or not isinstance(reference_digests, dict)
        or set(references) != set(reference_digests)
        or not isinstance(bindings, list)
    ):
        return None

    expected = dict(reference_digests)
    for binding in bindings:
        if not isinstance(binding, dict):
            return None
        for ref_field, digest_field in (
            ("profileRef", "profileDigest"),
            ("projectionRef", "projectionDigest"),
        ):
            ref = binding.get(ref_field)
            digest = binding.get(digest_field)
            if not isinstance(ref, str) or not isinstance(digest, str):
                return None
            prior = expected.get(ref)
            if prior is not None and prior != digest:
                return None
            expected[ref] = digest
    return expected


def _approved_snapshot_root(root: Path, release: dict[str, Any]) -> Path | None:
    """返回已存在的批准引用快照；不存在时保持旧测试/迁移兼容路径。"""
    version = release.get("version")
    if not isinstance(version, str) or not version:
        return None
    snapshot_root = (
        root
        / ".codex"
        / "approval-history"
        / version
        / APPROVED_REFERENCE_SNAPSHOT_DIR
    )
    return snapshot_root if snapshot_root.exists() or snapshot_root.is_symlink() else None


def _validate_approved_reference_snapshot(
    root: Path,
    release: dict[str, Any],
    snapshot_root: Path,
) -> str | None:
    """验证批准快照集合闭包；任何缺失、篡改、符号链接或额外文件都失败关闭。"""
    expected = _release_reference_digests(release)
    if expected is None:
        return "approved_snapshot_release_reference_set_invalid"

    root_resolved = root.resolve()
    cursor = snapshot_root
    while cursor != root:
        if cursor.is_symlink():
            return "approved_snapshot_symlink_forbidden"
        cursor = cursor.parent
        if cursor == cursor.parent and cursor != root:
            return "approved_snapshot_outside_root"
    if not snapshot_root.is_dir():
        return "approved_snapshot_missing"
    snapshot_resolved = snapshot_root.resolve()
    if (
        snapshot_resolved != root_resolved
        and root_resolved not in snapshot_resolved.parents
    ):
        return "approved_snapshot_outside_root"

    actual_files: set[str] = set()
    for directory, dirnames, filenames in os.walk(snapshot_root, followlinks=False):
        directory_path = Path(directory)
        for dirname in dirnames:
            if (directory_path / dirname).is_symlink():
                return "approved_snapshot_symlink_forbidden"
        for filename in filenames:
            path = directory_path / filename
            if path.is_symlink() or not path.is_file():
                return "approved_snapshot_symlink_forbidden"
            actual_files.add(path.relative_to(snapshot_root).as_posix())
    if actual_files != set(expected):
        return "approved_snapshot_file_set_mismatch"

    for reference, expected_digest in expected.items():
        if (
            not isinstance(reference, str)
            or reference.startswith("/")
            or ".." in Path(reference).parts
            or not HEX64.fullmatch(str(expected_digest))
        ):
            return "approved_snapshot_reference_invalid"
        target = snapshot_root / reference
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected_digest:
            return "approved_snapshot_digest_mismatch"
    return None


def external_applicability_census(manifest: Any) -> list[dict[str, Any]] | None:
    """按 manifest 原有 ruleCategories 统计执行适用性，不另建排除域。"""
    if not isinstance(manifest, dict):
        return None
    categories = manifest.get("ruleCategories")
    if not isinstance(categories, list):
        return None
    rows: list[dict[str, Any]] = []
    for category in categories:
        if not isinstance(category, dict):
            return None
        rules = category.get("rules")
        if not isinstance(rules, list):
            return None
        applicabilities: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict):
                return None
            applicability = rule.get("applicability")
            if isinstance(applicability, str):
                applicabilities.add(applicability)
        rows.append({
            "categoryId": category.get("categoryId"),
            "ruleCount": len(rules),
            "applicabilities": sorted(applicabilities),
        })
    return rows


def _bounded_spec_files(root: Path) -> tuple[set[str] | None, str | None]:
    """枚举发布根 spec/ 下的普通文件；符号链接和越界路径失败关闭。"""
    spec = root / "spec"
    if spec.is_symlink() or not spec.is_dir():
        return None, "external_consumer_file_missing"
    root_resolved = root.resolve()
    actual: set[str] = set()
    for directory, dirnames, filenames in os.walk(spec, followlinks=False):
        directory_path = Path(directory)
        if directory_path.is_symlink():
            return None, "external_consumer_symlink"
        for dirname in dirnames:
            if (directory_path / dirname).is_symlink():
                return None, "external_consumer_symlink"
        for filename in filenames:
            path = directory_path / filename
            if path.is_symlink() or not path.is_file():
                return None, "external_consumer_symlink"
            resolved = path.resolve()
            if resolved != root_resolved and root_resolved not in resolved.parents:
                return None, "external_consumer_outside_root"
            actual.add(path.relative_to(root).as_posix())
    return actual, None


def external_consumer_file_digests(root: Path) -> tuple[dict[str, str] | None, str | None]:
    """从隔离发布根的两个消费文件重算摘要，并拒绝缺文件、多余文件和符号链接。"""
    actual, error = _bounded_spec_files(root)
    if error is not None or actual is None:
        return None, error or "external_consumer_file_missing"
    required = set(EXTERNAL_CONSUMER_FILES)
    if not required <= actual:
        return None, "external_consumer_file_missing"
    extra = actual - required - set(EXTERNAL_OPTIONAL_SPEC_FILES)
    if extra:
        return None, "external_consumer_extra_file"
    digests: dict[str, str] = {}
    for relative in EXTERNAL_CONSUMER_FILES:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            return None, "external_consumer_file_missing"
        digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests, None


def external_payload_digest(file_digests: dict[str, str]) -> str:
    """消费双文件载荷摘要。只覆盖这两个已冻结文件。"""
    return _canonical_digest({"files": {relative: file_digests[relative] for relative in EXTERNAL_CONSUMER_FILES}})


def _release_byte_source(root: Path, release: dict[str, Any], reference: str) -> Path:
    snapshot_root = _approved_snapshot_root(root, release)
    if snapshot_root is not None:
        return snapshot_root / reference
    return root / reference


def _validate_external_conformance_release(
    root: Path,
    release: dict[str, Any],
) -> str | None:
    """校验外部规范 scope 的身份、空平台绑定、重算摘要和适用性，不替代批准链。"""
    if release.get("platformBindings") != []:
        return "external_scope_platform_bindings_forbidden"
    if "projection_version" in release:
        return "external_scope_projection_version_forbidden"
    version = release.get("version")
    if (
        release.get("candidate_id")
        != f"skill-family-external-conformance:{version}"
        or release.get("release_id")
        != f"spec-release:skill-family-external-conformance:{version}"
    ):
        return "external_identity_mismatch"
    references = release.get("references")
    if set(references or []) != set(EXTERNAL_REQUIRED_REFS):
        return "external_reference_set_mismatch"

    file_digests, closure_error = external_consumer_file_digests(root)
    if closure_error is not None or file_digests is None:
        return closure_error or "external_consumer_file_missing"
    payload_digest = external_payload_digest(file_digests)
    if release.get("candidate_payload_digest") != payload_digest:
        return "external_payload_digest_mismatch"
    reference_digests = release.get("reference_digests")
    if not isinstance(reference_digests, dict):
        return "external_reference_set_mismatch"
    policy_map: dict[str, str] = {}
    for relative in EXTERNAL_POLICY_REFS:
        digest = reference_digests.get(relative)
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            return "external_reference_set_mismatch"
        policy_map[relative] = digest
    if release.get("approval_package_digest") != _canonical_digest(policy_map):
        return "external_policy_digest_mismatch"
    if (
        release.get("non_exempt_policy_digest")
        != policy_map["spec/policies/non-exempt-baselines.json"]
    ):
        return "external_policy_digest_mismatch"
    for relative, digest in file_digests.items():
        if reference_digests.get(relative) != digest:
            return "external_consumer_digest_mismatch"

    summary_path = root / EXTERNAL_SUMMARY_PATH
    if summary_path.is_symlink() or not summary_path.is_file():
        return "external_summary_missing"
    try:
        summary_bytes = summary_path.read_bytes()
        summary = json.loads(summary_bytes)
    except (OSError, json.JSONDecodeError):
        return "external_summary_invalid"
    if hashlib.sha256(summary_bytes).hexdigest() != release.get("candidate_summary_digest"):
        return "external_summary_digest_mismatch"
    if not isinstance(summary, dict):
        return "external_summary_invalid"
    if (
        summary.get("candidatePayloadDigest") != payload_digest
        or summary.get("candidateId") != release.get("candidate_id")
        or summary.get("version") != version
        or summary.get("scope") != EXTERNAL_SCOPE
    ):
        return "external_summary_identity_mismatch"

    try:
        authority = json.loads((root / "spec/authority-index.json").read_bytes())
        manifest = json.loads((root / "spec/applicable-rules.json").read_bytes())
    except (OSError, json.JSONDecodeError):
        return "external_consumer_parse_error"
    if not isinstance(authority, dict) or not isinstance(manifest, dict):
        return "external_consumer_parse_error"
    if (
        "release_digest" in authority
        or "candidateSpecReleases" in authority
        or "selfAudit" in authority
        or "test_fixture" in authority
        or "exclusionDomains" in authority
        or "exclusionDomains" in manifest
    ):
        return "external_authority_embeds_release_or_exclusion"
    identity = authority.get("identity")
    if (
        not isinstance(identity, dict)
        or identity.get("scope") != release.get("scope")
        or identity.get("version") != version
        or identity.get("releaseId") != release.get("release_id")
        or identity.get("candidateId") != release.get("candidate_id")
        or authority.get("scope") != release.get("scope")
        or authority.get("version") != version
    ):
        return "external_authority_identity_mismatch"
    applicability = authority.get("executionApplicability")
    manifest_sha256 = hashlib.sha256(
        (root / "spec/applicable-rules.json").read_bytes()
    ).hexdigest()
    if (
        not isinstance(applicability, dict)
        or applicability.get("manifestSha256") != manifest_sha256
    ):
        return "external_manifest_digest_mismatch"
    census = external_applicability_census(manifest)
    recorded = (authority.get("executionApplicability") or {}).get("categories")
    if census is None or recorded != census:
        return "external_applicability_not_preserved"
    lineage = authority.get("canonicalLineage")
    if not isinstance(lineage, dict):
        return "external_lineage_missing"
    inventory_path = _release_byte_source(root, release, EXTERNAL_INVENTORY_REF)
    if inventory_path.is_symlink() or not inventory_path.is_file():
        return "external_lineage_source_missing"
    try:
        inventory_bytes = inventory_path.read_bytes()
        inventory = json.loads(inventory_bytes)
    except (OSError, json.JSONDecodeError):
        return "external_lineage_source_invalid"
    if hashlib.sha256(inventory_bytes).hexdigest() != lineage.get("inventorySha256"):
        return "external_lineage_digest_mismatch"
    rules = inventory.get("canonical_rules") if isinstance(inventory, dict) else None
    if not isinstance(rules, list):
        return "external_lineage_identity_mismatch"
    canonical_ids = [
        rule.get("canonical_id")
        for rule in rules
        if isinstance(rule, dict)
    ]
    if (
        lineage.get("canonicalIds") != canonical_ids
        or lineage.get("businessDigest") != inventory.get("business_digest")
        or lineage.get("ruleCount") != len(canonical_ids)
    ):
        return "external_lineage_identity_mismatch"
    return None


def resolve_spec_release(
    index: dict[str, Any],
    approval_receipt: dict[str, Any] | None,
    root: Path = ROOT,
) -> dict[str, Any]:
    """解析一个精确发布；无收据返回 no_active_spec_package。"""
    if approval_receipt is None:
        return {"status": "no_active_spec_package", "active_release": None, "reason": "no_approval_receipt"}

    required = {
        "approver", "approved_at", "approved_object", "approval_package_digest",
        "spec_release_digest", "non_exempt_policy_digest",
    }
    if required - set(approval_receipt):
        return _blocked("approval_receipt_missing_fields")
    for field in ("approval_package_digest", "spec_release_digest", "non_exempt_policy_digest"):
        if not HEX64.fullmatch(str(approval_receipt[field])):
            return _blocked("approval_receipt_digest_invalid")

    releases = index.get("candidateSpecReleases", [])
    matches = [r for r in releases if r.get("release_digest") == approval_receipt["spec_release_digest"]]
    if len(matches) != 1:
        return _blocked("release_digest_not_unique")
    release = matches[0]

    if release.get("status") != "candidate":
        return _blocked("release_not_candidate")
    if any(r is not release and r.get("scope") == release.get("scope") and r.get("status") == "active" for r in releases):
        return _blocked("active_release_conflict_for_scope")
    if approval_receipt.get("approved_object") != release.get("release_id"):
        return _blocked("approved_object_mismatch")

    release_payload = dict(release)
    release_payload.pop("release_digest", None)
    if release.get("release_digest") != _canonical_digest(release_payload):
        return _blocked("release_object_digest_mismatch")

    policy = release.get("approval_policy")
    if not isinstance(policy, dict):
        return _blocked("approval_authority_policy_missing")
    allowed_approvers = policy.get("allowed_approvers")
    if not isinstance(allowed_approvers, list) or approval_receipt.get("approver") not in allowed_approvers:
        return _blocked("approver_not_authorized")

    # 只有已绑定并可回读决定文件的候选才可被收据激活。
    subject_status = policy.get("approvalSubjectStatus")
    if subject_status != "bound_to_confirmed_approver":
        return _blocked("approval_subject_not_bound")
    if subject_status == "bound_to_confirmed_approver":
        decision_ref = policy.get("decisionRef")
        decision_digest = policy.get("decisionDigest")
        if not isinstance(decision_ref, str) or not decision_ref:
            return _blocked("decision_ref_missing")
        if not isinstance(decision_digest, str) or not HEX64.fullmatch(decision_digest):
            return _blocked("decision_digest_invalid")

        # decisionRef 必须是固定路径
        if decision_ref != APPROVAL_DECISION_FIXED_PATH:
            return _blocked("decision_ref_not_fixed_path")

        # 读取决定文件并验证摘要
        decision_path = (root / decision_ref).resolve()
        if root.resolve() not in decision_path.parents and decision_path != root.resolve():
            return _blocked("decision_file_outside_root")
        if not decision_path.is_file():
            return _blocked("decision_file_missing")
        try:
            actual_digest = hashlib.sha256(decision_path.read_bytes()).hexdigest()
        except OSError:
            return _blocked("decision_file_read_error")
        if actual_digest != decision_digest:
            return _blocked("decision_digest_mismatch")

        # 解析并验证决定文件内容
        try:
            decision = json.loads(decision_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return _blocked("decision_file_parse_error")

        if not isinstance(decision, dict):
            return _blocked("decision_schema_fields_invalid")
        schema_version = decision.get("schemaVersion")
        expected_fields = (
            APPROVAL_DECISION_FIELDS
            if schema_version == "1.0.0"
            else APPROVAL_DECISION_FIELDS | APPROVAL_DECISION_FREEZE_FIELDS
            if schema_version == "1.1.0"
            else None
        )
        if expected_fields is None:
            return _blocked("decision_schema_version_invalid")
        if set(decision) != expected_fields:
            return _blocked("decision_schema_fields_invalid")
        if schema_version == "1.1.0":
            freeze_error = _validate_freeze_evidence_binding(decision, root)
            if freeze_error is not None:
                return _blocked(freeze_error)
        if not isinstance(decision.get("decisionId"), str) or not decision["decisionId"].strip():
            return _blocked("decision_id_empty")
        if decision.get("status") != "confirmed":
            return _blocked("decision_status_not_confirmed")
        if not isinstance(decision.get("approver"), str) or not decision["approver"].strip():
            return _blocked("decision_approver_empty")
        if decision.get("approvedObject") != release.get("release_id"):
            return _blocked("decision_approved_object_mismatch")
        if decision.get("approvedCandidateId") != release.get("candidate_id"):
            return _blocked("decision_candidate_id_mismatch")
        if (
            decision.get("approvedCandidatePayloadDigest")
            != release.get("candidate_payload_digest")
        ):
            return _blocked("decision_candidate_payload_digest_mismatch")
        if (
            decision.get("approvedCandidateSummaryDigest")
            != release.get("candidate_summary_digest")
        ):
            return _blocked("decision_candidate_summary_digest_mismatch")
        if decision.get("approvalPackageDigest") != release.get("approval_package_digest"):
            return _blocked("decision_approval_package_digest_mismatch")
        if decision.get("nonExemptPolicyDigest") != release.get("non_exempt_policy_digest"):
            return _blocked("decision_non_exempt_policy_digest_mismatch")
        # 批准者必须与决定文件中的 approver 一致
        if approval_receipt.get("approver") != decision.get("approver"):
            return _blocked("receipt_approver_mismatch_with_decision")
        decided_at = _parse_time(decision.get("decidedAt"))
        if decided_at is None:
            return _blocked("decision_time_invalid")

    approved_at = _parse_time(approval_receipt.get("approved_at"))
    locked_at = _parse_time(release.get("locked_at"))
    not_before = _parse_time(policy.get("not_before"))
    if approved_at is None or locked_at is None or not_before is None:
        return _blocked("approval_time_invalid")
    if decided_at < locked_at:
        return _blocked("decision_precedes_candidate_lock")
    if approved_at < max(locked_at, not_before):
        return _blocked("approval_precedes_candidate_lock")
    if approved_at < decided_at:
        return _blocked("approval_precedes_subject_decision")

    if release.get("approval_package_digest") != approval_receipt["approval_package_digest"]:
        return _blocked("approval_package_digest_mismatch")
    if release.get("non_exempt_policy_digest") != approval_receipt["non_exempt_policy_digest"]:
        return _blocked("non_exempt_policy_digest_mismatch")
    scope = release.get("scope")
    if scope == EXTERNAL_SCOPE:
        external_error = _validate_external_conformance_release(root, release)
        if external_error is not None:
            return _blocked(external_error)
    elif scope == FOUR_PLATFORM_SCOPE:
        if release.get("projection_version") != index.get("methodContracts", {}).get("projectionVersion"):
            return _blocked("projection_version_incompatible")
    else:
        return _blocked("unknown_release_scope")

    references = release.get("references", [])
    reference_digests = release.get("reference_digests")
    if not isinstance(reference_digests, dict) or set(reference_digests) != set(references):
        return _blocked("reference_digest_set_mismatch")
    snapshot_root = _approved_snapshot_root(root, release)
    if snapshot_root is not None:
        snapshot_error = _validate_approved_reference_snapshot(
            root,
            release,
            snapshot_root,
        )
        if snapshot_error is not None:
            return _blocked(snapshot_error)
    for reference in references:
        if reference.startswith(BLOCKED_PREFIXES):
            return _blocked("fallback_source_forbidden")
        target = (
            snapshot_root / reference
            if snapshot_root is not None
            else root / reference
        )
        resolved_target = target.resolve()
        expected_parent = (
            snapshot_root.resolve() if snapshot_root is not None else root.resolve()
        )
        if (
            resolved_target != expected_parent
            and expected_parent not in resolved_target.parents
        ):
            return _blocked("reference_outside_root")
        if not target.is_file() or target.is_symlink():
            return _blocked("reference_broken")
        expected_digest = reference_digests.get(reference)
        if not HEX64.fullmatch(str(expected_digest)) or hashlib.sha256(target.read_bytes()).hexdigest() != expected_digest:
            return _blocked("reference_digest_mismatch")

    return {"status": "active", "active_release": release, "reason": None}


def main() -> int:
    index = json.loads((ROOT / "spec/authority-index.json").read_text(encoding="utf-8"))
    receipt_path = ROOT / GOVERNANCE_APPROVAL_RECEIPT_PATH
    receipt = (
        json.loads(receipt_path.read_text(encoding="utf-8"))
        if receipt_path.is_file()
        else None
    )
    result = resolve_spec_release(index, receipt)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] in {"no_active_spec_package", "active"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
