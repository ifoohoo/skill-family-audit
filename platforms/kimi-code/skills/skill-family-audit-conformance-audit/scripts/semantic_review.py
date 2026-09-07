"""Audit-owned, read-only semantic review request and finalization contract.

This module never invokes the audited target.  It freezes one review request
from an already-created Foundation Task and validates the conformance Skill's
in-memory result against immutable rule and evidence identities.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable


METHOD_ID = "skill-family-audit:conformance-audit"
COGNITIVE_INDEPENDENCE = "not_attested"
BINDINGS_PATH = (
    Path(__file__).resolve().parent.parent
    / "refs"
    / "semantic-review-bindings.json"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REVIEW_STATUSES = {
    "PASS",
    "FAIL",
    "EVIDENCE_MISSING",
    "NOT_APPLICABLE",
    "REVIEW_REQUIRED",
}


class SemanticReviewError(RuntimeError):
    """The internal semantic review envelope failed deterministic validation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID", "semantic binding root must be an object"
        )
    return value


def load_bindings(
    canonical_rules: list[dict[str, Any]],
    path: Path = BINDINGS_PATH,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Validate candidate bindings against the canonical projection identities.

    The bindings file stores exactly three fact kinds: the canonical foreign
    key, the revision digest, and the required evidence roles.  Binding
    identity and lifecycle state are derived from the canonical projection
    (``semantic:<canonical_id>@<revision>`` and ``lifecycle_status``); the
    bindings file carries no hand-written status, no activation blockers,
    and no fixed runtime count.
    """
    document = _load_json(path)
    if (
        set(document)
        != {
            "kind",
            "schema_version",
            "method_id",
            "cognitive_independence",
            "bindings",
        }
        or document.get("kind")
        != "skill-family-audit.semantic-review-bindings"
        or document.get("schema_version") != "1.0.0"
        or document.get("method_id") != METHOD_ID
        or document.get("cognitive_independence") != COGNITIVE_INDEPENDENCE
        or not isinstance(document.get("bindings"), list)
    ):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID", "semantic binding header is invalid"
        )
    canonical = {
        (item.get("canonical_id"), item.get("revision_digest")): item
        for item in canonical_rules
        if isinstance(item, dict)
    }
    bindings: dict[tuple[str, str], dict[str, Any]] = {}
    binding_ids: set[str] = set()
    for item in document["bindings"]:
        if not isinstance(item, dict) or set(item) != {
            "canonical_id",
            "revision_digest",
            "required_evidence_roles",
        }:
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID", "semantic binding shape is invalid"
            )
        canonical_id = item.get("canonical_id")
        revision_digest = item.get("revision_digest")
        roles = item.get("required_evidence_roles")
        identity = (canonical_id, revision_digest)
        if (
            not isinstance(canonical_id, str)
            or not canonical_id
            or not isinstance(revision_digest, str)
            or not HEX64.fullmatch(revision_digest)
            or identity in bindings
            or identity not in canonical
            or not isinstance(canonical[identity].get("check_methods"), list)
            # 单一语义审阅通道同时承接语义审阅与外部行为证据审阅：
            # 绑定契约允许语义方法或行为验证方法，二者至少其一。
            or not (
                "semantic_review" in canonical[identity]["check_methods"]
                or "behavior_verification" in canonical[identity]["check_methods"]
            )
            or not isinstance(canonical[identity].get("revision"), int)
            or not isinstance(canonical[identity].get("lifecycle_status"), str)
            # lifecycle_status must be RETAINED_UNIMPLEMENTED、ACTIVE_SEMANTIC
            # 或 ACTIVE_MECHANICAL：激活规则的 binding 是正式执行契约；
            # ACTIVE_MECHANICAL 规则的 binding 只承载其语义/行为半区契约。
            or canonical[identity]["lifecycle_status"] not in (
                "RETAINED_UNIMPLEMENTED",
                "ACTIVE_SEMANTIC",
                "ACTIVE_MECHANICAL",
            )
            or not isinstance(roles, dict)
            or not roles
            or list(roles) != sorted(roles)
            or any(
                not isinstance(role, str)
                or not role
                or not isinstance(kinds, list)
                or not kinds
                or kinds != sorted(set(kinds))
                or not all(isinstance(kind, str) and kind for kind in kinds)
                for role, kinds in roles.items()
            )
        ):
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID",
                f"semantic binding identity or evidence contract is invalid: {canonical_id}",
            )
        binding_id = (
            f"semantic:{canonical_id}@{canonical[identity]['revision']}"
        )
        if binding_id in binding_ids:
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID",
                f"semantic binding identity collides: {canonical_id}",
            )
        binding_ids.add(binding_id)
        bindings[identity] = {
            "binding_id": binding_id,
            "canonical_id": canonical_id,
            "revision_digest": revision_digest,
            "required_evidence_roles": roles,
            "lifecycle_status": canonical[identity]["lifecycle_status"],
        }
    return bindings


def bound_rule_descriptors(
    rules: list[dict[str, Any]],
    canonical_lineage: dict[str, dict[str, str]],
    canonical_rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project active baseline rules onto the exact candidate semantic bindings."""
    canonical = {
        (item["canonical_id"], item["revision_digest"]): item
        for item in canonical_rules
        if isinstance(item, dict)
        and isinstance(item.get("canonical_id"), str)
        and isinstance(item.get("revision_digest"), str)
    }
    active_identities = set()
    for rule in rules:
        lineage = canonical_lineage.get(rule.get("ruleId"))
        if not isinstance(lineage, dict):
            continue
        identity = (
            lineage.get("canonical_id"),
            lineage.get("canonical_revision_digest"),
        )
        if rule.get("checkType") == "semantic" or (
            rule.get("checkType") == "static"
            and (
                "semantic_review" in canonical.get(identity, {}).get("check_methods", [])
                or "behavior_verification" in canonical.get(identity, {}).get("check_methods", [])
            )
        ):
            active_identities.add(identity)
    if not active_identities:
        return []
    candidate_document = _load_json(BINDINGS_PATH)
    candidate_identities = {
        (item.get("canonical_id"), item.get("revision_digest"))
        for item in candidate_document.get("bindings", [])
        if isinstance(item, dict)
    }
    if active_identities.isdisjoint(candidate_identities):
        return []
    bindings = load_bindings(canonical_rules, path=BINDINGS_PATH)
    descriptors = []
    for rule in rules:
        lineage = canonical_lineage.get(rule.get("ruleId"))
        if not isinstance(lineage, dict):
            continue
        identity = (
            lineage.get("canonical_id"),
            lineage.get("canonical_revision_digest"),
        )
        if identity not in active_identities:
            continue
        binding = bindings.get(identity)
        canonical_rule = canonical.get(identity)
        if binding is None or canonical_rule is None:
            continue
        descriptors.append({
            "baseline_rule_id": rule["ruleId"],
            "baseline_revision_digest": rule["revisionDigest"],
            "canonical_id": identity[0],
            "canonical_revision_digest": identity[1],
            "name": canonical_rule["name"],
            "obligation": canonical_rule["obligation"],
            "binding_id": binding["binding_id"],
            "required_evidence_roles": binding["required_evidence_roles"],
            "lifecycle_status": canonical_rule["lifecycle_status"],
            # Formal scope fields are copied from the same canonical rule
            # descriptor.  They are context for the reviewer only: no local
            # interpretation, default, or second applicability policy is
            # introduced here.
            "project_scope": canonical_rule["project_scope"],
            "applicability": canonical_rule["applicability"],
            "platform_scope": canonical_rule["platform_scope"],
            "adoption_mode": canonical_rule["adoption_mode"],
            "adjudication_note": canonical_rule["adjudication_note"],
            "evidence_requirements": canonical_rule["evidence_requirements"],
        })
    return sorted(descriptors, key=lambda item: item["canonical_id"])


def retained_trial_descriptors(
    canonical_rules: list[dict[str, Any]],
    canonical_ids: set[str] | list[str] | tuple[str, ...],
    path: Path | None = None,
) -> list[dict[str, Any]]:
    """Project explicitly targeted retained rules onto existing A-SEM bindings.

    Retained rules have no implementation-baseline carrier in the packaged
    runtime.  Keep the trial descriptor canonical-only instead of inventing a
    baseline rule identity; the existing semantic binding remains the sole
    source of evidence roles and binding identity.
    """
    requested = set(canonical_ids)
    bindings = load_bindings(
        canonical_rules,
        path=BINDINGS_PATH if path is None else path,
    )
    descriptors: list[dict[str, Any]] = []
    for canonical_rule in canonical_rules:
        canonical_id = canonical_rule.get("canonical_id")
        revision_digest = canonical_rule.get("revision_digest")
        identity = (canonical_id, revision_digest)
        methods = canonical_rule.get("check_methods")
        if (
            canonical_id not in requested
            or canonical_rule.get("lifecycle_status") != "RETAINED_UNIMPLEMENTED"
            or not isinstance(methods, list)
            or "semantic_review" not in methods
        ):
            continue
        binding = bindings.get(identity)
        if binding is None:
            continue
        descriptors.append({
            "canonical_id": canonical_id,
            "canonical_revision_digest": revision_digest,
            "name": canonical_rule["name"],
            "obligation": canonical_rule["obligation"],
            "binding_id": binding["binding_id"],
            "required_evidence_roles": binding["required_evidence_roles"],
            "lifecycle_status": canonical_rule["lifecycle_status"],
            "project_scope": canonical_rule["project_scope"],
            "applicability": canonical_rule["applicability"],
            "platform_scope": canonical_rule["platform_scope"],
            "adoption_mode": canonical_rule["adoption_mode"],
            "adjudication_note": canonical_rule["adjudication_note"],
            "evidence_requirements": canonical_rule["evidence_requirements"],
        })
    return sorted(descriptors, key=lambda item: item["canonical_id"])


def build_review_request(
    *,
    foundation_task_digest: str,
    evidence_set_digest: str,
    rule_set_digest: str,
    descriptors: list[dict[str, Any]],
    evidence_set: list[dict[str, Any]],
    digest_document: Callable[[Any], str],
) -> dict[str, Any]:
    """Freeze the exact review input after the Foundation Task already exists."""
    for label, value in (
        ("foundation_task_digest", foundation_task_digest),
        ("evidence_set_digest", evidence_set_digest),
        ("rule_set_digest", rule_set_digest),
    ):
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            raise SemanticReviewError(
                "SEMANTIC_REVIEW_REQUEST_INVALID", f"{label} must be a SHA-256 digest"
            )
    body = {
        "kind": "skill-family-audit.semantic-review-request",
        "schema_version": "1.0.0",
        "producer_method_id": METHOD_ID,
        "cognitive_independence": COGNITIVE_INDEPENDENCE,
        "foundation_task_digest": foundation_task_digest,
        "evidence_set_digest": evidence_set_digest,
        "rule_set_digest": rule_set_digest,
        "reviewed_rule_set_digest": digest_document([
            {
                **(
                    {
                        "baseline_rule_id": item["baseline_rule_id"],
                        "baseline_revision_digest": item["baseline_revision_digest"],
                    }
                    if "baseline_rule_id" in item
                    and "baseline_revision_digest" in item
                    else {}
                ),
                "canonical_id": item["canonical_id"],
                "canonical_revision_digest": item["canonical_revision_digest"],
            }
            for item in descriptors
        ]),
        "rules": descriptors,
        "evidence": [
            {
                "evidence_id": item["evidence_id"],
                "kind": item["kind"],
                "sha256": item["sha256"],
            }
            for item in evidence_set
        ],
    }
    return {**body, "review_request_digest": digest_document(body)}


def finalize_review(
    request: dict[str, Any],
    payload: dict[str, Any],
    *,
    digest_document: Callable[[Any], str],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Validate an internal Skill review and conservatively project its statuses."""
    if not isinstance(payload, dict):
        raise SemanticReviewError(
            "SEMANTIC_REVIEW_RESULT_INVALID", "semantic review result must be an object"
        )
    expected_header = {
        "schema_version": "2.0.0",
        "kind": "skill-family-audit.semantic-review-result",
        "producer_method_id": METHOD_ID,
        "cognitive_independence": COGNITIVE_INDEPENDENCE,
        "foundation_task_digest": request["foundation_task_digest"],
        "review_request_digest": request["review_request_digest"],
        "evidence_set_digest": request["evidence_set_digest"],
        "reviewed_rule_set_digest": request["reviewed_rule_set_digest"],
    }
    if set(payload) != {*expected_header, "reviews"} or any(
        payload.get(key) != value for key, value in expected_header.items()
    ):
        raise SemanticReviewError(
            "SEMANTIC_REVIEW_BINDING_MISMATCH",
            "semantic review result does not bind the frozen request",
        )
    reviews = payload.get("reviews")
    if not isinstance(reviews, list):
        raise SemanticReviewError(
            "SEMANTIC_REVIEW_RESULT_INVALID", "reviews must be an array"
        )
    expected_rules = {
        item["canonical_id"]: item for item in request.get("rules", [])
    }
    evidence = {
        item["evidence_id"]: item for item in request.get("evidence", [])
    }
    observed: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {
            "binding_id",
            "canonical_id",
            "rule_revision_digest",
            "status",
            "reason_code",
            "rationale",
            "evidence_refs",
        }:
            raise SemanticReviewError(
                "SEMANTIC_REVIEW_RESULT_INVALID", "review shape is invalid"
            )
        canonical_id = review.get("canonical_id")
        rule = expected_rules.get(canonical_id)
        status = review.get("status")
        refs = review.get("evidence_refs")
        if (
            rule is None
            or canonical_id in observed
            or review.get("binding_id") != rule["binding_id"]
            or review.get("rule_revision_digest")
            != rule["canonical_revision_digest"]
            or status not in REVIEW_STATUSES
            or not isinstance(review.get("reason_code"), str)
            or not review["reason_code"]
            or not isinstance(review.get("rationale"), str)
            or not review["rationale"].strip()
            or not isinstance(refs, list)
        ):
            raise SemanticReviewError(
                "SEMANTIC_REVIEW_RESULT_INVALID",
                f"review identity or status is invalid: {canonical_id}",
            )
        covered_roles: set[str] = set()
        normalized_refs = []
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) != {
                "evidence_id",
                "sha256",
                "locator",
                "role",
            }:
                raise SemanticReviewError(
                    "SEMANTIC_REVIEW_RESULT_INVALID", "evidence reference is invalid"
                )
            item = evidence.get(ref.get("evidence_id"))
            role = ref.get("role")
            if (
                item is None
                or ref.get("sha256") != item.get("sha256")
                or not isinstance(ref.get("locator"), str)
                or not ref["locator"].strip()
                or role not in rule["required_evidence_roles"]
                or item.get("kind") not in rule["required_evidence_roles"][role]
            ):
                raise SemanticReviewError(
                    "SEMANTIC_REVIEW_EVIDENCE_MISMATCH",
                    f"evidence reference does not match the frozen request: {canonical_id}",
                )
            covered_roles.add(role)
            normalized_refs.append(dict(ref))
        projected_status = status
        projected_reason = review["reason_code"]
        missing_roles = sorted(set(rule["required_evidence_roles"]) - covered_roles)
        if status == "PASS" and missing_roles:
            projected_status = "EVIDENCE_MISSING"
            projected_reason = "REQUIRED_EVIDENCE_ROLE_MISSING"
        elif status == "PASS" and rule["lifecycle_status"] not in {
            "ACTIVE_SEMANTIC",
            "ACTIVE_MECHANICAL",
        }:
            # 是否仍有保留阻塞由 canonical 投影的生命周期字段派生，不来自
            # bindings 文件的手写状态。
            projected_status = "REVIEW_REQUIRED"
            projected_reason = "SEMANTIC_ACTIVATION_BLOCKED"
        elif status == "FAIL" and not normalized_refs:
            projected_status = "EVIDENCE_MISSING"
            projected_reason = "FAILURE_EVIDENCE_MISSING"
        elif status == "NOT_APPLICABLE" and not normalized_refs:
            # 触发为假必须由至少一条冻结证据证明；没有触发观察的
            # NOT_APPLICABLE 是缺证，不是不适用。
            projected_status = "EVIDENCE_MISSING"
            projected_reason = "TRIGGER_FALSE_UNPROVEN"
        observed[canonical_id] = {
            "canonical_id": canonical_id,
            "rule_revision_digest": rule["canonical_revision_digest"],
            "binding_id": rule["binding_id"],
            "status": projected_status,
            "reason_code": projected_reason,
            "rationale": review["rationale"],
            "evidence_refs": normalized_refs,
            "missing_evidence_roles": missing_roles,
            "lifecycle_status": rule["lifecycle_status"],
            "submitted_status": status,
        }
    if set(observed) != set(expected_rules):
        raise SemanticReviewError(
            "SEMANTIC_REVIEW_COVERAGE_MISMATCH",
            "semantic review must cover every and only frozen rule identity",
        )
    result_digest = digest_document(payload)
    binding = {
        "producer_method_id": METHOD_ID,
        "cognitive_independence": COGNITIVE_INDEPENDENCE,
        "foundation_task_digest": request["foundation_task_digest"],
        "review_request_digest": request["review_request_digest"],
        "evidence_set_digest": request["evidence_set_digest"],
        "reviewed_rule_set_digest": request["reviewed_rule_set_digest"],
        "semantic_review_result_digest": result_digest,
    }
    return observed, binding
