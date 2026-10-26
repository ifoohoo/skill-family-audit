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
# 非机械审阅方法只按当前权威的 check_methods 取值：behavior_verification 已从
# 数据真源剥除（T1 账本修复、T6-1b 复核），消费侧不再保留该值。
NON_MECHANICAL_CHECK_METHODS = ("semantic_review",)


def review_identity(row: dict[str, Any]) -> tuple[str, str, str]:
    """Return the atomic rule-revision-method review identity."""
    revision_digest = row.get(
        "canonical_revision_digest", row.get("rule_revision_digest")
    )
    return row["canonical_id"], revision_digest, row["check_method"]


def _method_binding_id(binding_id: str, check_method: str) -> str:
    return f"{binding_id}#{check_method}"


class SemanticReviewError(RuntimeError):
    """The internal semantic review envelope failed deterministic validation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


_BINDING_REQUIRED_KEYS = {
    "canonical_id",
    "revision_digest",
    "required_evidence_roles",
}
_OPTIONAL_DEPENDENCY_FIELD = "professional_dependencies"
_OPTIONAL_WITNESS_FIELD = "independence_verification"
_INDEPENDENCE_WITNESS_KEYS = (
    "obligations_complete",
    "required_roles_checked",
    "cross_rule_relations_closed",
    "consumes_professional_result",
)


def _provider_catalog_path(manifest_path: Path | None = None) -> Path:
    """Find the catalog the current layout already publishes.

    A platform package carries ``platform-manifest.json``. The plugin source
    catalog remains ``manifest.json`` when no platform manifest is an ancestor.
    """
    if manifest_path is not None:
        return manifest_path
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "platform-manifest.json"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "manifest.json"
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            document = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        providers = document.get("professionalProviders") if isinstance(document, dict) else None
        if isinstance(providers, list):
            return candidate
    raise SemanticReviewError(
        "SEMANTIC_BINDINGS_INVALID",
        "professionalProviders catalog is missing",
    )


def professional_provider_ids(manifest_path: Path | None = None) -> list[str]:
    """Return provider ids from the same manifest.professionalProviders catalog."""
    path = _provider_catalog_path(manifest_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    providers = document.get("professionalProviders") if isinstance(document, dict) else None
    if not isinstance(providers, list) or not providers:
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "professionalProviders catalog is missing",
        )
    identifiers: list[str] = []
    for item in providers:
        identifier = item.get("id") if isinstance(item, dict) else None
        if not isinstance(identifier, str) or not identifier:
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID",
                "professionalProviders catalog is missing",
            )
        identifiers.append(identifier)
    if len(identifiers) != len(set(identifiers)):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "professionalProviders catalog is missing",
        )
    return identifiers


def independence_verified(witness: dict[str, Any] | None) -> bool:
    """True only for a complete witness that consumes no professional result."""
    if not isinstance(witness, dict) or set(witness) != set(_INDEPENDENCE_WITNESS_KEYS):
        return False
    if witness.get("consumes_professional_result") is not False:
        return False
    return all(
        witness.get(key) is True
        for key in _INDEPENDENCE_WITNESS_KEYS
        if key != "consumes_professional_result"
    )


def accept_professional_dependencies(
    value: Any,
    *,
    provider_ids: list[str] | set[str],
    independence_verification: dict[str, Any] | None = None,
) -> list[str]:
    """Accept one sorted unique provider_id array from the shared catalog.

    An empty array is accepted only when this binding row records a completed
    independence witness. Role names, file names, and review families are not
    consulted. A caller-supplied witness dictionary is not a second source.
    """
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "professional_dependencies must be a sorted unique provider_id array",
        )
    if value != sorted(set(value)):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "professional_dependencies must be a sorted unique provider_id array",
        )
    known = set(provider_ids)
    if any(item not in known for item in value):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "professional_dependencies contains an unknown provider_id",
        )
    if value == [] and not independence_verified(independence_verification):
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "empty professional_dependencies requires a completed independence verification",
        )
    return list(value)


def dependency_stage(description: dict[str, Any]) -> str:
    """Omitted or non-empty dependencies wait. Verified [] is early.

    Stage is never inferred from a file name, role, or review family.
    """
    if _OPTIONAL_DEPENDENCY_FIELD not in description:
        return "late"
    dependencies = description[_OPTIONAL_DEPENDENCY_FIELD]
    if dependencies == []:
        return "early"
    return "late"


def _copy_professional_dependencies(
    binding: dict[str, Any], target: dict[str, Any]
) -> None:
    if _OPTIONAL_DEPENDENCY_FIELD in binding:
        target[_OPTIONAL_DEPENDENCY_FIELD] = list(binding[_OPTIONAL_DEPENDENCY_FIELD])


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
    *,
    provider_ids: list[str] | None = None,
    independence_verifications: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Validate current bindings against the canonical projection identities.

    The bindings file stores the canonical foreign key, the revision digest,
    and the required evidence roles.  ``professional_dependencies`` and its
    on-row ``independence_verification`` are the only optional fields.  The
    witness stays on the row that production already loads; it is not copied
    into the returned description and cannot be supplied by a second
    dictionary.  Binding identity and lifecycle state are derived from the
    canonical projection (``semantic:<canonical_id>@<revision>`` and
    ``lifecycle_status``); the bindings file carries no hand-written status,
    no activation blockers, and no fixed runtime count.

    消费集合以当前权威投影为准：identity 不在当前 canonical 集合中的行属于
    历史绑定行，按迁移裁决原样保留、不重写、也不作为当前执行契约进入返回值。
    历史编号的可追溯性由规则来源去向表承担，不在这里补写。
    """
    if independence_verifications is not None:
        raise SemanticReviewError(
            "SEMANTIC_BINDINGS_INVALID",
            "independence witness must be recorded on the binding row",
        )
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
    seen_identities: set[tuple[Any, Any]] = set()
    resolved_provider_ids = provider_ids
    for item in document["bindings"]:
        if not isinstance(item, dict):
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID", "semantic binding shape is invalid"
            )
        extra = set(item) - _BINDING_REQUIRED_KEYS - {
            _OPTIONAL_DEPENDENCY_FIELD,
            _OPTIONAL_WITNESS_FIELD,
        }
        missing = _BINDING_REQUIRED_KEYS - set(item)
        if extra or missing:
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID", "semantic binding shape is invalid"
            )
        canonical_id = item.get("canonical_id")
        revision_digest = item.get("revision_digest")
        roles = item.get("required_evidence_roles")
        identity = (canonical_id, revision_digest)
        accepted_dependencies: list[str] | None = None
        if _OPTIONAL_DEPENDENCY_FIELD in item:
            if resolved_provider_ids is None:
                resolved_provider_ids = professional_provider_ids()
            witness = item.get(_OPTIONAL_WITNESS_FIELD)
            accepted_dependencies = accept_professional_dependencies(
                item[_OPTIONAL_DEPENDENCY_FIELD],
                provider_ids=resolved_provider_ids,
                independence_verification=witness if isinstance(witness, dict) else None,
            )
        if (
            not isinstance(canonical_id, str)
            or not canonical_id
            or not isinstance(revision_digest, str)
            or not HEX64.fullmatch(revision_digest)
            or identity in seen_identities
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
        seen_identities.add(identity)
        canonical_rule = canonical.get(identity)
        if canonical_rule is None:
            # 历史绑定行：旧编号只须能追溯到承接规则。历史行原样保留，
            # 不参与当前消费，也不改写为新的编号或摘要。
            continue
        if (
            not isinstance(canonical_rule.get("check_methods"), list)
            or not isinstance(canonical_rule.get("revision"), int)
            or not isinstance(canonical_rule.get("lifecycle_status"), str)
            # lifecycle_status must be RETAINED_UNIMPLEMENTED、ACTIVE_SEMANTIC
            # 或 ACTIVE_MECHANICAL：激活规则的 binding 是正式执行契约；
            # ACTIVE_MECHANICAL 规则的 binding 只承载其语义半区契约。
            # 规则是否需要非机械审阅由 check_methods 在消费侧判定，
            # 不在这里按方法封禁绑定行。
            or canonical_rule["lifecycle_status"] not in (
                "RETAINED_UNIMPLEMENTED",
                "ACTIVE_SEMANTIC",
                "ACTIVE_MECHANICAL",
            )
        ):
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID",
                f"semantic binding identity or evidence contract is invalid: {canonical_id}",
            )
        binding_id = f"semantic:{canonical_id}@{canonical_rule['revision']}"
        if binding_id in binding_ids:
            raise SemanticReviewError(
                "SEMANTIC_BINDINGS_INVALID",
                f"semantic binding identity collides: {canonical_id}",
            )
        binding_ids.add(binding_id)
        description = {
            "binding_id": binding_id,
            "canonical_id": canonical_id,
            "revision_digest": revision_digest,
            "required_evidence_roles": roles,
            "lifecycle_status": canonical_rule["lifecycle_status"],
        }
        if accepted_dependencies is not None:
            description[_OPTIONAL_DEPENDENCY_FIELD] = accepted_dependencies
        bindings[identity] = description
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
            and any(
                method
                in (canonical.get(identity, {}).get("check_methods") or [])
                for method in NON_MECHANICAL_CHECK_METHODS
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
        for check_method in sorted(
            set(canonical_rule["check_methods"])
            & set(NON_MECHANICAL_CHECK_METHODS)
        ):
            descriptors.append({
                "baseline_rule_id": rule["ruleId"],
                "baseline_revision_digest": rule["revisionDigest"],
                "canonical_id": identity[0],
                "canonical_revision_digest": identity[1],
                "check_method": check_method,
                "name": canonical_rule["name"],
                "obligation": canonical_rule["obligation"],
                "binding_id": _method_binding_id(
                    binding["binding_id"], check_method
                ),
                "required_evidence_roles": binding["required_evidence_roles"],
                "lifecycle_status": canonical_rule["lifecycle_status"],
            })
            _copy_professional_dependencies(binding, descriptors[-1])
            descriptors[-1].update({
                # Scope fields and exception_policy are copied verbatim from
                # the same canonical rule.  They are reviewer context only.
                "project_scope": canonical_rule["project_scope"],
                "applicability": canonical_rule["applicability"],
                "platform_scope": canonical_rule["platform_scope"],
                "adoption_mode": canonical_rule["adoption_mode"],
                "adjudication_note": canonical_rule["adjudication_note"],
                "evidence_requirements": canonical_rule["evidence_requirements"],
                "exception_policy": canonical_rule["exception_policy"],
            })
            _attach_condition_contract(descriptors[-1])
            _attach_mechanical_object_context(descriptors[-1], canonical_rule)
    return sorted(descriptors, key=review_identity)


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
            or not set(methods).intersection(NON_MECHANICAL_CHECK_METHODS)
        ):
            continue
        binding = bindings.get(identity)
        if binding is None:
            continue
        for check_method in sorted(
            set(methods).intersection(NON_MECHANICAL_CHECK_METHODS)
        ):
            descriptors.append({
                "canonical_id": canonical_id,
                "canonical_revision_digest": revision_digest,
                "check_method": check_method,
                "name": canonical_rule["name"],
                "obligation": canonical_rule["obligation"],
                "binding_id": _method_binding_id(
                    binding["binding_id"], check_method
                ),
                "required_evidence_roles": binding["required_evidence_roles"],
                "lifecycle_status": canonical_rule["lifecycle_status"],
            })
            _copy_professional_dependencies(binding, descriptors[-1])
            descriptors[-1].update({
                "project_scope": canonical_rule["project_scope"],
                "applicability": canonical_rule["applicability"],
                "platform_scope": canonical_rule["platform_scope"],
                "adoption_mode": canonical_rule["adoption_mode"],
                "adjudication_note": canonical_rule["adjudication_note"],
                "evidence_requirements": canonical_rule["evidence_requirements"],
                "exception_policy": canonical_rule["exception_policy"],
            })
            _attach_condition_contract(descriptors[-1])
            _attach_mechanical_object_context(descriptors[-1], canonical_rule)
    return sorted(descriptors, key=review_identity)


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
                "check_method": item["check_method"],
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


def public_condition_contract(canonical_id: str) -> dict[str, Any] | None:
    """JSON view of the one authority table. Finalize does not own a second copy."""
    branches = _SIX_RULE_CONDITIONS.get(canonical_id)
    if not isinstance(branches, dict):
        return None
    conditions = []
    for code, spec in branches.items():
        if spec.get("unknown"):
            branch_role = "unknown"
        elif spec.get("na"):
            branch_role = "not_applicable"
        else:
            branch_role = "pass"
        conditions.append({
            "reason_code": code,
            "allowed_statuses": sorted(spec["statuses"]),
            "pass_roles": list(spec["pass_roles"]),
            "branch_role": branch_role,
            "citation_required": True,
        })
    return {"authority": "DESIGN-025-12.2", "conditions": conditions}


def _attach_mechanical_object_context(descriptor: dict[str, Any], canonical_rule: dict[str, Any]) -> None:
    methods = sorted(set(canonical_rule.get("check_methods", [])) & {
        "static_scan", "schema_validation", "digest_verification",
    })
    if (canonical_rule.get("lifecycle_status") != "ACTIVE_SEMANTIC" or not methods
            or descriptor.get("canonical_id") in _SIX_RULE_CONDITIONS):
        return
    # Keep the rule's own object conditions in the existing request. These are
    # reviewer instructions, not a second method catalog or an NA inference.
    descriptor["evidence_requirements"] = [*descriptor["evidence_requirements"],
        "For this rule, independently review the actual mechanical objects required by its "
        "applicability and evidence requirements for these methods: " + ", ".join(methods) + ". "
        "Put the actual object-premise code in the existing reason_code field, not only in rationale. "
        "rationale explains that premise and the business conclusion; evidence_refs must cite actual bound materials. "
        "Do not submit a generic semantic reason_code with a mechanical code only in prose. "
        "One review identity has one reason_code: do not combine codes, encode a list, or repeat the review. "
        "If a mixed multi-method premise cannot be represented by one existing code, keep other methods unresolved. "
        "Use the existing reason_code and cite the checked scope in evidence_refs: "
        "MECHANICAL_OBJECTS_ABSENT only when every listed mechanical object is absent and not required; "
        "MACHINE_SCHEMA_NOT_ADOPTED only for schema_validation; "
        "STATIC_WIRING_NOT_ADOPTED only for static_scan; "
        "BYTE_CORRESPONDENCE_NOT_DECLARED only for digest_verification. "
        "Each absence code requires the corresponding object to be absent and not required by this rule. "
        "For actual checked missing inputs use SCHEMA_INPUTS_MISSING, STATIC_INPUTS_MISSING or "
        "DIGEST_INPUTS_MISSING and state required material, authorized checked locations and missing content. "
        "Use MECHANICAL_OBJECTS_PRESENT when the relevant declared objects and inputs exist; "
        "BYTE_BASELINE_OUTSIDE_MANAGED_FILES identifies an existing byte baseline outside Foundation managed-file-lock. "
        "SCHEMA_OUTSIDE_FOUNDATION_CONTRACTS identifies an existing adopted formal schema and its object outside "
        "Foundation project-manifest/managed-file-lock and Registry method structures; cite both actual inputs. "
        "Insufficient scope remains MECHANICAL_OBJECT_SCOPE_UNKNOWN. These codes never grant semantic PASS, "
        "waive required roles, infer absence from missing evidence, or attest a professional scan. "
        "The review status still assesses the full business obligation; a mechanical absence alone does not make the rule NOT_APPLICABLE."]


def _attach_condition_contract(descriptor: dict[str, Any]) -> None:
    contract = public_condition_contract(descriptor.get("canonical_id"))
    if contract is not None:
        descriptor["condition_contract"] = contract


# DESIGN-025 §12.2 condition codes stay on reason_code. They are not a status enum.
# pass_roles is the set required for PASS. na marks a code that may support
# NOT_APPLICABLE. unknown marks a code that cannot be PASS or NOT_APPLICABLE.
_SIX_RULE_CONDITIONS: dict[str, dict[str, dict[str, Any]]] = {
    "SFA-METHOD-005": {
        "METHOD005_NEW_ENTRY_PRESENT": {
            "pass_roles": ("independent_goal_evidence", "new_entry_declaration"),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "METHOD005_NEW_ENTRY_ABSENT": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "METHOD005_CONDITION_UNKNOWN": {
            "pass_roles": (),
            "unknown": True,
            "statuses": frozenset({"EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
    },
    "SFA-METHOD-011": {
        "METHOD011_SHARED_ENTRIES_PRESENT": {
            "pass_roles": ("duplicate_entry_inventory", "merge_or_rationale_record"),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "METHOD011_SHARED_ENTRIES_ABSENT": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "METHOD011_CONDITION_UNKNOWN": {
            "pass_roles": (),
            "unknown": True,
            "statuses": frozenset({"EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
    },
    "SFA-PUBLISH-014": {
        "PUBLISH014_RIGHTS_CHANGED": {
            "pass_roles": (
                "rights_facts_source",
                "license_artifact",
                "package_metadata",
                "public_metadata_surfaces",
                "rights_change_basis",
                "authorization_policy",
            ),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "PUBLISH014_RIGHTS_UNCHANGED": {
            "pass_roles": (
                "rights_facts_source",
                "license_artifact",
                "package_metadata",
                "public_metadata_surfaces",
                "rights_change_basis",
            ),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "PUBLISH014_NO_PUBLIC_UNIT": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "PUBLISH014_CONDITION_UNKNOWN": {
            "pass_roles": (),
            "unknown": True,
            "statuses": frozenset({"EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
    },
    "SFA-FOUNDATION-012": {
        "FOUNDATION012_TOKEN_MEASUREMENT_APPLIES": {
            "pass_roles": (
                "foundation_authority",
                "harness_consumer_source",
                "professional_proof",
                "token_measurement_basis",
                "token_estimate_record",
            ),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "FOUNDATION012_TOKEN_MEASUREMENT_NOT_APPLICABLE": {
            "pass_roles": (
                "foundation_authority",
                "harness_consumer_source",
                "professional_proof",
                "token_measurement_basis",
            ),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "FOUNDATION012_NO_CONSUMPTION": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "FOUNDATION012_CONDITION_UNKNOWN": {
            "pass_roles": (),
            "unknown": True,
            "statuses": frozenset({"EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
    },
    "SFA-FOUNDATION-014": {
        "FOUNDATION014_CONSUMPTION_PRESENT": {
            "pass_roles": (
                "consumer_parameters_and_mapping",
                "contracts_authority",
                "professional_proof",
                "registry_check_output",
            ),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "FOUNDATION014_CONSUMPTION_ABSENT": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "FOUNDATION014_CONDITION_UNKNOWN": {
            "pass_roles": (),
            "unknown": True,
            "statuses": frozenset({"EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
    },
    "SFA-REGISTRY-007": {
        "REGISTRY007_LIMITED": {
            "pass_roles": (
                "method_and_protocol_contract",
                "expression_limitation_disclosure",
                "upstream_extension_request",
            ),
            "statuses": frozenset({"PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
        "REGISTRY007_EXPRESSIBLE": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "REGISTRY007_NOT_ADOPTED": {
            "pass_roles": (),
            "na": True,
            "statuses": frozenset({
                "NOT_APPLICABLE", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED",
            }),
        },
        "REGISTRY007_CONDITION_UNKNOWN": {
            "pass_roles": (),
            "unknown": True,
            "statuses": frozenset({"EVIDENCE_MISSING", "REVIEW_REQUIRED"}),
        },
    },
}


def _project_review_status(
    *,
    canonical_id: str,
    status: str,
    reason_code: str,
    lifecycle_status: str,
    covered_roles: set[str],
    required_roles: set[str],
    has_refs: bool,
) -> tuple[str, str, list[str]]:
    """Project one review. Condition branches select roles; they do not judge prose."""
    full_missing = sorted(required_roles - covered_roles)
    branches = _SIX_RULE_CONDITIONS.get(canonical_id)
    if branches is None:
        projected_status = status
        projected_reason = reason_code
        missing_roles = full_missing
        if status == "PASS" and missing_roles:
            projected_status = "EVIDENCE_MISSING"
            projected_reason = "REQUIRED_EVIDENCE_ROLE_MISSING"
        elif status == "PASS" and lifecycle_status not in {
            "ACTIVE_SEMANTIC", "ACTIVE_MECHANICAL",
        }:
            projected_status = "REVIEW_REQUIRED"
            projected_reason = "SEMANTIC_ACTIVATION_BLOCKED"
        elif status == "FAIL" and not has_refs:
            projected_status = "EVIDENCE_MISSING"
            projected_reason = "FAILURE_EVIDENCE_MISSING"
        elif status == "NOT_APPLICABLE" and not has_refs:
            projected_status = "EVIDENCE_MISSING"
            projected_reason = "TRIGGER_FALSE_UNPROVEN"
        return projected_status, projected_reason, missing_roles

    condition = branches.get(reason_code)
    projected_status = status
    projected_reason = reason_code
    missing_roles = full_missing
    if condition is None:
        # A code that exists only outside this authority table is not a
        # condition judgment. Full roles and a generic PASS do not execute it.
        # Missing required material stays the existing evidence gap.
        if status == "PASS" and full_missing:
            return "EVIDENCE_MISSING", "REQUIRED_EVIDENCE_ROLE_MISSING", full_missing
        if status in {"PASS", "NOT_APPLICABLE"}:
            return "REVIEW_REQUIRED", reason_code, full_missing
        if status == "FAIL" and not has_refs:
            return "EVIDENCE_MISSING", "FAILURE_EVIDENCE_MISSING", full_missing
        return projected_status, projected_reason, missing_roles

    allowed = condition["statuses"]
    if status not in allowed:
        return "REVIEW_REQUIRED", reason_code, full_missing
    if status == "PASS":
        missing_roles = sorted(set(condition["pass_roles"]) - covered_roles)
        if missing_roles:
            return "EVIDENCE_MISSING", "REQUIRED_EVIDENCE_ROLE_MISSING", missing_roles
        if lifecycle_status not in {"ACTIVE_SEMANTIC", "ACTIVE_MECHANICAL"}:
            return "REVIEW_REQUIRED", "SEMANTIC_ACTIVATION_BLOCKED", missing_roles
        return status, reason_code, missing_roles
    if status == "NOT_APPLICABLE" and not has_refs:
        return "EVIDENCE_MISSING", "TRIGGER_FALSE_UNPROVEN", full_missing
    if status == "FAIL" and not has_refs:
        return "EVIDENCE_MISSING", "FAILURE_EVIDENCE_MISSING", full_missing
    return projected_status, projected_reason, missing_roles


def finalize_review(
    request: dict[str, Any],
    payload: dict[str, Any],
    *,
    digest_document: Callable[[Any], str],
    ) -> tuple[dict[tuple[str, str, str], dict[str, Any]], dict[str, Any]]:
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
        review_identity(item): item for item in request.get("rules", [])
    }
    if len(expected_rules) != len(request.get("rules", [])):
        raise SemanticReviewError(
            "SEMANTIC_REVIEW_REQUEST_INVALID",
            "semantic review request contains duplicate method obligations",
        )
    evidence = {
        item["evidence_id"]: item for item in request.get("evidence", [])
    }
    observed: dict[tuple[str, str, str], dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {
            "binding_id",
            "canonical_id",
            "check_method",
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
        check_method = review.get("check_method")
        identity = (
            canonical_id,
            review.get("rule_revision_digest"),
            check_method,
        )
        rule = expected_rules.get(identity)
        status = review.get("status")
        refs = review.get("evidence_refs")
        if (
            rule is None
            or identity in observed
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
        projected_status, projected_reason, missing_roles = _project_review_status(
            canonical_id=canonical_id,
            status=status,
            reason_code=review["reason_code"],
            lifecycle_status=rule["lifecycle_status"],
            covered_roles=covered_roles,
            required_roles=set(rule["required_evidence_roles"]),
            has_refs=bool(normalized_refs),
        )
        observed[identity] = {
            "canonical_id": canonical_id,
            "check_method": check_method,
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
