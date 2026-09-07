#!/usr/bin/env python3
"""从 canonical projection 派生原子方法义务。

Foundation 提供通用 strict-read 与 digest 机制；方法义务和 assurance 的领域
语义由 Audit 拥有。本模块只描述义务与未证明状态，实现绑定只能说明存在声明，
不能证明方法已经执行或实现已经得到保证。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
from typing import Any, Callable, Iterable


_EXECUTOR_CONTRACT_PATH = Path(__file__).resolve().parent / "executors/contracts.py"
_EXECUTOR_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "skill_family_audit_executor_contracts", _EXECUTOR_CONTRACT_PATH
)
if _EXECUTOR_CONTRACT_SPEC is None or _EXECUTOR_CONTRACT_SPEC.loader is None:
    raise ImportError(f"cannot load executor contracts: {_EXECUTOR_CONTRACT_PATH}")
_EXECUTOR_CONTRACTS = importlib.util.module_from_spec(_EXECUTOR_CONTRACT_SPEC)
_EXECUTOR_CONTRACT_SPEC.loader.exec_module(_EXECUTOR_CONTRACTS)
AGGREGATE_EVIDENCE_REFERENCE = (
    _EXECUTOR_CONTRACTS.AGGREGATE_EVIDENCE_REFERENCE
)
MANAGED_METHOD_OBSERVATION_SOURCES = (
    _EXECUTOR_CONTRACTS.MANAGED_METHOD_OBSERVATION_SOURCES
)
METHOD_SUBRESULT_STATUSES = _EXECUTOR_CONTRACTS.METHOD_SUBRESULT_STATUSES


CANONICAL_CHECK_METHODS = frozenset({
    "behavior_verification",
    "digest_verification",
    "schema_validation",
    "semantic_review",
    "static_scan",
})
MECHANICAL_CHECK_METHODS = frozenset({
    "digest_verification", "schema_validation", "static_scan",
})
NON_MECHANICAL_CHECK_METHODS = ("semantic_review", "behavior_verification")


def select_review_method(methods: Any) -> str | None:
    """Select the one internal review row allowed for a rule route."""
    if not isinstance(methods, (list, tuple, set, frozenset)):
        return None
    method_set = set(methods)
    for method in NON_MECHANICAL_CHECK_METHODS:
        if method in method_set:
            return method
    return None

FIELD_MISSING = "FIELD_MISSING"
FIELD_TYPE_ERROR = "FIELD_TYPE_ERROR"
CHECK_METHOD_ILLEGAL = "CHECK_METHOD_ILLEGAL"
CHECK_METHOD_DUPLICATE = "CHECK_METHOD_DUPLICATE"
CANONICAL_RULE_DUPLICATE = "CANONICAL_RULE_DUPLICATE"
CANONICAL_ID_INVALID = "CANONICAL_ID_INVALID"
REVISION_DIGEST_INVALID = "REVISION_DIGEST_INVALID"
OBLIGATION_DUPLICATE = "OBLIGATION_DUPLICATE"
EXECUTED_STATUS_FORBIDDEN = "EXECUTED_STATUS_FORBIDDEN"
DIGEST_RESULT_INVALID = "DIGEST_RESULT_INVALID"
OBJECT_KEYS_INVALID = "OBJECT_KEYS_INVALID"
EVIDENCE_BUNDLE_KIND_INVALID = "EVIDENCE_BUNDLE_KIND_INVALID"
EVIDENCE_OBLIGATION_SET_DIGEST_MISMATCH = (
    "EVIDENCE_OBLIGATION_SET_DIGEST_MISMATCH"
)
EVIDENCE_RECEIPT_DUPLICATE = "EVIDENCE_RECEIPT_DUPLICATE"
EVIDENCE_RECEIPT_UNKNOWN_OBLIGATION = "EVIDENCE_RECEIPT_UNKNOWN_OBLIGATION"
EVIDENCE_RECEIPT_STATUS_INVALID = "EVIDENCE_RECEIPT_STATUS_INVALID"
EVIDENCE_RECEIPT_RESULT_INVALID = "EVIDENCE_RECEIPT_RESULT_INVALID"
EVIDENCE_RECEIPT_RESULT_DIGEST_MISMATCH = (
    "EVIDENCE_RECEIPT_RESULT_DIGEST_MISMATCH"
)
TRUSTED_OBSERVATION_INVALID = "TRUSTED_OBSERVATION_INVALID"

EVIDENCE_BUNDLE_KIND = "skill-family-audit.rule-method-evidence-bundle"
EVIDENCE_BUNDLE_SCHEMA_VERSION = "1.0.0"
METHOD_RECEIPT_KIND = "skill-family-audit.method-obligation-receipt"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AssuranceError(ValueError):
    """带稳定错误码的受控输入或机制错误。"""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssuranceError(
            FIELD_TYPE_ERROR,
            f"{where}: expected object, got {type(value).__name__}",
        )
    return value


def _require_field(
    container: dict[str, Any], key: str, expected_type: type, where: str
) -> Any:
    if key not in container:
        raise AssuranceError(FIELD_MISSING, f"{where}: missing field {key}")
    value = container[key]
    if not isinstance(value, expected_type):
        raise AssuranceError(
            FIELD_TYPE_ERROR,
            f"{where}.{key}: expected {expected_type.__name__}, "
            f"got {type(value).__name__}",
        )
    return value


def _require_exact_keys(
    container: dict[str, Any], expected: set[str], where: str
) -> None:
    actual = set(container)
    if actual != expected:
        raise AssuranceError(
            OBJECT_KEYS_INVALID,
            f"{where}: expected keys {sorted(expected)}, got {sorted(actual)}",
        )


def obligation_identity(record: dict[str, str]) -> tuple[str, str, str]:
    return (
        record["canonical_id"],
        record["revision_digest"],
        record["check_method"],
    )


def _validate_rule_identity(
    canonical_id: str, revision_digest: str, where: str
) -> None:
    if not canonical_id or canonical_id.strip() != canonical_id:
        raise AssuranceError(
            CANONICAL_ID_INVALID,
            f"{where}.canonical_id must be a non-empty canonical identity",
        )
    if not HEX64.fullmatch(revision_digest):
        raise AssuranceError(
            REVISION_DIGEST_INVALID,
            f"{where}.revision_digest must be a lowercase SHA-256 digest",
        )




def derive_obligations(projection: Any) -> dict[str, Any]:
    """把 projection 中每条规则的 check_methods 原子化并确定性排序。"""
    document = _require_object(projection, "projection")
    rules = _require_field(document, "rules", list, "projection")
    seen_rules: set[str] = set()
    seen_obligations: set[tuple[str, str, str]] = set()
    records: list[dict[str, str]] = []

    for index, raw_rule in enumerate(rules):
        where = f"projection.rules[{index}]"
        rule = _require_object(raw_rule, where)
        canonical_id = _require_field(rule, "canonical_id", str, where)
        revision_digest = _require_field(rule, "revision_digest", str, where)
        _validate_rule_identity(canonical_id, revision_digest, where)
        methods = _require_field(rule, "check_methods", list, where)
        lifecycle_status = rule.get("lifecycle_status", "TERMINAL_PENDING")
        if not isinstance(lifecycle_status, str):
            raise AssuranceError(
                FIELD_TYPE_ERROR,
                f"{where}.lifecycle_status: expected str, "
                f"got {type(lifecycle_status).__name__}",
            )
        if canonical_id in seen_rules:
            raise AssuranceError(
                CANONICAL_RULE_DUPLICATE,
                f"duplicate canonical rule id: {canonical_id}",
            )
        seen_rules.add(canonical_id)
        seen_methods: set[str] = set()
        for method_index, method in enumerate(methods):
            method_where = f"{where}.check_methods[{method_index}]"
            if not isinstance(method, str):
                raise AssuranceError(
                    FIELD_TYPE_ERROR,
                    f"{method_where}: expected str, got {type(method).__name__}",
                )
            if method not in CANONICAL_CHECK_METHODS:
                raise AssuranceError(
                    CHECK_METHOD_ILLEGAL,
                    f"{method_where}: illegal or compound method {method!r}",
                )
            if method in seen_methods:
                raise AssuranceError(
                    CHECK_METHOD_DUPLICATE,
                    f"{where}: duplicate check method {method}",
                )
            seen_methods.add(method)
            identity = (canonical_id, revision_digest, method)
            if identity in seen_obligations:
                raise AssuranceError(
                    OBLIGATION_DUPLICATE,
                    f"duplicate obligation: {identity}",
                )
            seen_obligations.add(identity)
            records.append({
                "canonical_id": canonical_id,
                "revision_digest": revision_digest,
                "check_method": method,
                "lifecycle_status": lifecycle_status,
            })

    records.sort(key=obligation_identity)
    distribution: dict[str, int] = {}
    for record in records:
        method = record["check_method"]
        distribution[method] = distribution.get(method, 0) + 1
    return {
        "records": records,
        "total": len(records),
        "method_distribution": dict(sorted(distribution.items())),
    }


def _binding_rule_identity(binding: Any, index: int) -> tuple[str, str]:
    where = f"bindings[{index}]"
    item = _require_object(binding, where)
    status = item.get("status")
    execution_status = item.get("execution_status")
    if status == "EXECUTED" or execution_status == "EXECUTED":
        raise AssuranceError(
            EXECUTED_STATUS_FORBIDDEN,
            f"{where}: EXECUTED is not accepted by static assurance",
        )
    canonical_id = _require_field(item, "canonical_rule_id", str, where)
    revision_digest = _require_field(
        item, "canonical_revision_digest", str, where
    )
    _validate_rule_identity(canonical_id, revision_digest, where)
    return canonical_id, revision_digest


def declared_obligation_identities(
    obligations: Iterable[dict[str, str]], bindings_document: Any
) -> set[tuple[str, str, str]]:
    """把 rule-level binding 声明投影为“已声明但未证明”的义务集合。"""
    document = _require_object(bindings_document, "bindings document")
    bindings = _require_field(document, "bindings", list, "bindings document")
    by_rule: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    for record in obligations:
        identity = obligation_identity(record)
        key = identity[:2]
        by_rule.setdefault(key, set()).add(identity)

    declared: set[tuple[str, str, str]] = set()
    for index, binding in enumerate(bindings):
        key = _binding_rule_identity(binding, index)
        if key not in by_rule:
            # 历史孤儿或旧 revision 声明不属于当前义务集合；它们既不证明
            # 当前义务，也不应阻断从 canonical authority 派生当前账本。
            continue
        declared.update(by_rule[key])
    return declared


def _receipt_observation(
    evidence_bundle: Any,
    obligation_set_digest: str,
    obligations: Iterable[dict[str, str]],
    digest_document: Callable[[Any], str],
) -> tuple[int, int]:
    """Validate caller receipts without promoting them to execution proof.

    The bundle binds only caller-supplied bytes.  Until a receipt also binds
    existing W2/semantic result bytes, target/task digests, and executor
    provenance, a successful self-assertion remains untrusted evidence.
    """
    bundle = _require_object(evidence_bundle, "evidence bundle")
    _require_exact_keys(
        bundle,
        {"kind", "schema_version", "obligation_set_digest", "receipts"},
        "evidence bundle",
    )
    if (
        bundle["kind"] != EVIDENCE_BUNDLE_KIND
        or bundle["schema_version"] != EVIDENCE_BUNDLE_SCHEMA_VERSION
    ):
        raise AssuranceError(
            EVIDENCE_BUNDLE_KIND_INVALID,
            "evidence bundle kind or schema_version is unsupported",
        )
    declared_digest = bundle["obligation_set_digest"]
    if not isinstance(declared_digest, str) or declared_digest != obligation_set_digest:
        raise AssuranceError(
            EVIDENCE_OBLIGATION_SET_DIGEST_MISMATCH,
            "evidence bundle does not bind the current obligation set",
        )
    receipts = _require_field(bundle, "receipts", list, "evidence bundle")
    expected = {obligation_identity(record) for record in obligations}
    seen: set[tuple[str, str, str]] = set()
    untrusted_success = 0
    non_success = 0
    for index, raw_receipt in enumerate(receipts):
        where = f"evidence bundle.receipts[{index}]"
        receipt = _require_object(raw_receipt, where)
        _require_exact_keys(
            receipt,
            {
                "kind",
                "canonical_id",
                "revision_digest",
                "check_method",
                "execution_status",
                "result",
                "result_digest",
            },
            where,
        )
        if receipt["kind"] != METHOD_RECEIPT_KIND:
            raise AssuranceError(
                EVIDENCE_RECEIPT_RESULT_INVALID,
                f"{where}.kind is unsupported",
            )
        identity = (
            _require_field(receipt, "canonical_id", str, where),
            _require_field(receipt, "revision_digest", str, where),
            _require_field(receipt, "check_method", str, where),
        )
        _validate_rule_identity(identity[0], identity[1], where)
        if identity in seen:
            raise AssuranceError(
                EVIDENCE_RECEIPT_DUPLICATE,
                f"{where}: duplicate receipt for {identity}",
            )
        seen.add(identity)
        if identity not in expected:
            raise AssuranceError(
                EVIDENCE_RECEIPT_UNKNOWN_OBLIGATION,
                f"{where}: receipt does not bind a current obligation: {identity}",
            )
        execution_status = _require_field(
            receipt, "execution_status", str, where
        )
        if execution_status not in {"SUCCEEDED", "FAILED", "BLOCKED"}:
            raise AssuranceError(
                EVIDENCE_RECEIPT_STATUS_INVALID,
                f"{where}.execution_status is unsupported: {execution_status!r}",
            )
        result = _require_object(receipt["result"], f"{where}.result")
        _require_exact_keys(
            result, {"verdict", "evidence_digest"}, f"{where}.result"
        )
        verdict = _require_field(result, "verdict", str, f"{where}.result")
        evidence_digest = _require_field(
            result, "evidence_digest", str, f"{where}.result"
        )
        if verdict not in {"PASS", "FAIL", "BLOCKED"} or not HEX64.fullmatch(
            evidence_digest
        ):
            raise AssuranceError(
                EVIDENCE_RECEIPT_RESULT_INVALID,
                f"{where}.result has an invalid verdict or evidence_digest",
            )
        if (execution_status, verdict) not in {
            ("SUCCEEDED", "PASS"),
            ("FAILED", "FAIL"),
            ("BLOCKED", "BLOCKED"),
        }:
            raise AssuranceError(
                EVIDENCE_RECEIPT_STATUS_INVALID,
                f"{where}: execution_status and verdict are inconsistent",
            )
        result_digest = _require_field(receipt, "result_digest", str, where)
        if not HEX64.fullmatch(result_digest) or result_digest != digest_document(result):
            raise AssuranceError(
                EVIDENCE_RECEIPT_RESULT_DIGEST_MISMATCH,
                f"{where}: result_digest does not bind result",
            )
        if execution_status == "SUCCEEDED":
            untrusted_success += 1
        else:
            non_success += 1
    return untrusted_success, non_success


def assurance_report(
    projection: Any,
    bindings_document: Any | None,
    digest_document: Callable[[Any], str],
    evidence_bundle: Any | None = None,
    *,
    lifecycle_statuses: set[str] | None = None,
) -> dict[str, Any]:
    """输出义务账本；调用者 receipt 仅作观察，不提升完成证明。"""
    ledger = derive_obligations(projection)
    if lifecycle_statuses is not None:
        if (
            not isinstance(lifecycle_statuses, set)
            or not lifecycle_statuses
            or not all(
                isinstance(status, str) and status
                for status in lifecycle_statuses
            )
        ):
            raise AssuranceError(
                FIELD_TYPE_ERROR,
                "lifecycle_statuses must be a non-empty set of strings",
            )
        active_records = [
            record for record in ledger["records"]
            if record["lifecycle_status"] in lifecycle_statuses
        ]
        distribution: dict[str, int] = {}
        for record in active_records:
            method = record["check_method"]
            distribution[method] = distribution.get(method, 0) + 1
        ledger = {
            "records": active_records,
            "total": len(active_records),
            "method_distribution": dict(sorted(distribution.items())),
        }
    identities = [
        list(obligation_identity(record)) for record in ledger["records"]
    ]
    obligation_set_digest = digest_document(identities)
    if not isinstance(obligation_set_digest, str) or not obligation_set_digest:
        raise AssuranceError(
            DIGEST_RESULT_INVALID,
            "digest_document must return a non-empty string",
        )
    declared = (
        declared_obligation_identities(ledger["records"], bindings_document)
        if bindings_document is not None
        else set()
    )
    untrusted_success, non_success = (
        _receipt_observation(
            evidence_bundle,
            obligation_set_digest,
            ledger["records"],
            digest_document,
        )
        if evidence_bundle is not None
        else (0, 0)
    )
    records = []
    for obligation in ledger["records"]:
        identity = obligation_identity(obligation)
        records.append({
            **obligation,
            "assurance_status": (
                "DECLARED_NOT_PROVEN"
                if identity in declared
                else "NOT_PROVEN"
            ),
        })
    return {
        "obligation_set_digest": obligation_set_digest,
        "total": ledger["total"],
        "method_distribution": ledger["method_distribution"],
        "declared_not_proven": len(declared),
        "receipt_succeeded": 0,
        "receipt_untrusted": untrusted_success,
        "receipt_non_success": non_success,
        "proven": 0,
        "not_proven": ledger["total"],
        "complete": False,
        "records": records,
    }


def _project_trusted_conformance_observation(
    report: Any,
    observation: Any,
    expected_identity: Any,
    trusted_routes: Any,
    executor_family_of: Callable[[str], str],
    digest_document: Callable[[Any], str],
    *,
    finalized_semantic_reviews: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Purely project an in-process Conformance observation onto this ledger.

    This private entry performs no I/O.  Mechanical observations remain
    unchanged.  Only the current workflow's finalize_review return value may
    fill a mixed route's semantic obligation; the parameter is not reviewer
    authentication. Caller receipts remain confined to assurance_report.
    """
    base = _require_object(report, "assurance report")
    document = _require_object(observation, "trusted observation")
    expected_binding = _require_object(
        expected_identity, "trusted observation expected identity"
    )
    routes = _require_object(trusted_routes, "trusted routes")
    identity_fields = {
        "run_id", "target_digest", "target_type", "platform",
        "rule_set_digest", "semantic_request_digest", "trust_projection_digest",
    }
    _require_exact_keys(
        expected_binding,
        identity_fields,
        "trusted observation expected identity",
    )
    _require_exact_keys(document, {
        "kind", "schema_version", "run_id", "target_digest", "target_type",
        "platform", "rule_set_digest", "semantic_request_digest",
        "trust_projection_digest", "rule_results",
    }, "trusted observation")
    if (
        document["kind"]
        != "skill-family-audit.conformance-method-observation"
        or document["schema_version"] != "1.0.0"
    ):
        raise AssuranceError(
            TRUSTED_OBSERVATION_INVALID,
            "trusted observation kind or schema_version is unsupported",
        )
    for field in (
        "run_id", "target_type", "platform",
    ):
        value = document[field]
        if not isinstance(value, str) or not value:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"trusted observation.{field} must be non-empty",
            )
    for field in (
        "target_digest", "rule_set_digest", "semantic_request_digest",
        "trust_projection_digest",
    ):
        if not isinstance(document[field], str) or not HEX64.fullmatch(document[field]):
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"trusted observation.{field} must be a SHA-256 digest",
            )
    for field in identity_fields:
        if document[field] != expected_binding[field]:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"trusted observation.{field} does not bind the current run",
            )
    total = base.get("total")
    records_value = base.get("records")
    receipt_succeeded = base.get("receipt_succeeded")
    proven = base.get("proven")
    not_proven = base.get("not_proven")
    if (
        type(total) is not int
        or total < 0
        or not isinstance(records_value, list)
        or len(records_value) != total
        or type(receipt_succeeded) is not int
        or receipt_succeeded != 0
        or type(proven) is not int
        or proven != 0
        or type(not_proven) is not int
        or not_proven != total
        or base.get("complete") is not False
    ):
        raise AssuranceError(
            TRUSTED_OBSERVATION_INVALID,
            "assurance base ledger violates the pre-observation zero-proof invariant",
        )
    expected = {
        obligation_identity(record): record for record in base.get("records", [])
    }
    observed: dict[tuple[str, str, str], dict[str, Any]] = {}
    seen_results: set[tuple[str, str, str]] = set()
    results = _require_field(document, "rule_results", list, "trusted observation")
    for index, raw_result in enumerate(results):
        where = f"trusted observation.rule_results[{index}]"
        result = _require_object(raw_result, where)
        _require_exact_keys(result, {
            "canonical_id", "revision_digest", "baseline_rule_id",
            "executor_family", "result_digest", "result_payload",
            "check_method_subresults",
        }, where)
        canonical_id = _require_field(result, "canonical_id", str, where)
        revision_digest = _require_field(result, "revision_digest", str, where)
        _validate_rule_identity(canonical_id, revision_digest, where)
        baseline_rule_id = _require_field(result, "baseline_rule_id", str, where)
        executor_family = _require_field(result, "executor_family", str, where)
        result_digest = _require_field(result, "result_digest", str, where)
        result_payload = _require_object(
            result["result_payload"], f"{where}.result_payload"
        )
        aggregate_status = result_payload.get("status")
        route = routes.get((canonical_id, revision_digest))
        try:
            registered_executor_family = executor_family_of(baseline_rule_id)
        except (KeyError, ValueError, TypeError) as exc:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where} is not bound to the managed executor registry",
            ) from exc
        if (
            not baseline_rule_id
            or not executor_family
            or aggregate_status not in {
                "PASS", "FAIL", "EVIDENCE_MISSING",
                "NOT_APPLICABLE", "NOT_RUN",
            }
            or not HEX64.fullmatch(result_digest)
            or result_digest != digest_document(result_payload)
            or not isinstance(route, dict)
            or route.get("canonical_id") != canonical_id
            or route.get("revision_digest") != revision_digest
            or route.get("baseline_rule_id") != baseline_rule_id
            or registered_executor_family != executor_family
        ):
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where} does not bind its route, executor family, or result bytes",
            )
        payload_lineage = result_payload.get("canonical_lineage")
        expected_worker = (
            "deterministic-terminal-governance"
            if baseline_rule_id.startswith("gmin:")
            else "deterministic-first-tier-executor"
        )
        if (
            result_payload.get("rule_id") != baseline_rule_id
            or result_payload.get("worker") != expected_worker
            or result_payload.get("executor_family") != executor_family
            or payload_lineage != {
                "canonical_id": canonical_id,
                "revision_digest": revision_digest,
            }
            or result_payload.get("check_method_subresults")
            != result.get("check_method_subresults")
        ):
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where}.result_payload is not an actual bound executor result",
            )
        result_identity = (canonical_id, revision_digest, baseline_rule_id)
        if result_identity in seen_results:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where} duplicates a W2 result identity",
            )
        seen_results.add(result_identity)
        subresults = _require_field(
            result, "check_method_subresults", list, where
        )
        route_methods = route.get("check_methods")
        required_mechanical = route.get("required_mechanical_methods")
        if (
            not isinstance(route_methods, list)
            or not route_methods
            or len(route_methods) != len(set(route_methods))
            or any(method not in CANONICAL_CHECK_METHODS for method in route_methods)
            or not isinstance(required_mechanical, list)
            or not required_mechanical
            or len(required_mechanical) != len(set(required_mechanical))
            or sorted(set(route_methods) & MECHANICAL_CHECK_METHODS)
            != sorted(required_mechanical)
        ):
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where} has an invalid managed method route",
            )
        seen_methods: set[str] = set()
        required_rows: list[dict[str, Any]] = []
        for subindex, raw_subresult in enumerate(subresults):
            subwhere = f"{where}.check_method_subresults[{subindex}]"
            subresult = _require_object(raw_subresult, subwhere)
            _require_exact_keys(
                subresult,
                {"check_method", "status", "observation_source", "evidence"},
                subwhere,
            )
            method = _require_field(subresult, "check_method", str, subwhere)
            status = _require_field(subresult, "status", str, subwhere)
            source = _require_field(
                subresult, "observation_source", str, subwhere
            )
            evidence = _require_object(subresult.get("evidence"), f"{subwhere}.evidence")
            identity = (canonical_id, revision_digest, method)
            if (
                method in seen_methods
                or identity in observed
                or identity not in expected
                or status not in METHOD_SUBRESULT_STATUSES
                or not source
                or not evidence
            ):
                raise AssuranceError(
                    TRUSTED_OBSERVATION_INVALID,
                    f"{subwhere} is duplicate, unknown, or malformed",
                )
            seen_methods.add(method)
            is_required = method in required_mechanical
            single_required = (
                required_mechanical[0]
                if len(required_mechanical) == 1
                else None
            )
            if not is_required:
                if (
                    status != "NOT_RUN"
                    or source != "method_not_executed_by_mechanical_executor"
                    or evidence != {
                        "kind": "method_not_executed",
                        "reason": "non_mechanical_method",
                    }
                ):
                    raise AssuranceError(
                        TRUSTED_OBSERVATION_INVALID,
                        f"{subwhere} cannot claim a non-mechanical method",
                    )
            elif source == "executor_aggregate_single_mechanical_method":
                if (
                    method != single_required
                    or status != aggregate_status
                    or evidence != AGGREGATE_EVIDENCE_REFERENCE
                ):
                    raise AssuranceError(
                        TRUSTED_OBSERVATION_INVALID,
                        f"{subwhere} does not bind the single-method aggregate",
                    )
            elif source == "executor_method_subresults_invalid":
                if (
                    status != "EVIDENCE_MISSING"
                    or evidence.get("kind") != "executor_error_reference"
                    or evidence.get("field") != "evidence"
                    or not isinstance(evidence.get("code"), str)
                    or not evidence["code"]
                    or set(evidence) != {"kind", "field", "code"}
                ):
                    raise AssuranceError(
                        TRUSTED_OBSERVATION_INVALID,
                        f"{subwhere} has an invalid dispatcher failure reference",
                    )
            elif source in MANAGED_METHOD_OBSERVATION_SOURCES:
                raise AssuranceError(
                    TRUSTED_OBSERVATION_INVALID,
                    f"{subwhere} forges a dispatcher-owned observation source",
                )
            if is_required:
                required_rows.append(subresult)
            observed[identity] = {
                "status": status,
                "observation_source": source,
                "evidence": evidence,
                "result_digest": result_digest,
                "baseline_rule_id": baseline_rule_id,
                "executor_family": executor_family,
                "proof_eligible": False,
            }
        if seen_methods != set(route_methods):
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where} does not report the complete managed method route",
            )
        required_statuses = [row["status"] for row in required_rows]
        coherent = (
            len(required_rows) == len(required_mechanical)
            and (
                baseline_rule_id.startswith("gmin:")
                or len(required_mechanical) == 1
                or not all(status == "NOT_RUN" for status in required_statuses)
            )
            and (
                (
                    baseline_rule_id.startswith("gmin:")
                    and aggregate_status in {"PASS", "NOT_APPLICABLE", "FAIL"}
                    and all(
                        status == "NOT_RUN" for status in required_statuses
                    )
                )
                or (
                    aggregate_status == "PASS"
                    and all(status == "PASS" for status in required_statuses)
                )
                or (
                    aggregate_status == "NOT_APPLICABLE"
                    and all(
                        status == "NOT_APPLICABLE"
                        for status in required_statuses
                    )
                )
                or (
                    aggregate_status == "FAIL"
                    and "FAIL" in required_statuses
                )
                or (
                    aggregate_status == "EVIDENCE_MISSING"
                    and any(
                        status in {"EVIDENCE_MISSING", "NOT_RUN"}
                        for status in required_statuses
                    )
                )
                or (
                    len(required_mechanical) == 1
                    and aggregate_status == "NOT_RUN"
                    and required_statuses == ["NOT_RUN"]
                )
            )
        )
        if not coherent:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                f"{where} has incoherent aggregate and per-method statuses",
            )
        if aggregate_status == "PASS" and all(
            row["status"] == "PASS" for row in required_rows
        ):
            for row in required_rows:
                observed[(canonical_id, revision_digest, row["check_method"])][
                    "proof_eligible"
                ] = True
    for canonical_id, review in (finalized_semantic_reviews or {}).items():
        review_revision_digest = review.get("rule_revision_digest")
        route = routes.get((canonical_id, review_revision_digest))
        if route is None:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                "finalized review does not bind a known canonical route",
            )
        review_method = select_review_method(route.get("check_methods", []))
        if review_method is None:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                "finalized review route has no supported review method",
            )
        identity = (canonical_id, review_revision_digest, review_method)
        if identity not in expected:
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                "finalized review does not bind a known method obligation",
            )
        if (
            review.get("canonical_id") != canonical_id
            or review.get("rule_revision_digest") != identity[1]
            or review.get("lifecycle_status") != expected[identity]["lifecycle_status"]
            or review.get("status") not in {
                "PASS", "FAIL", "EVIDENCE_MISSING", "REVIEW_REQUIRED", "NOT_APPLICABLE",
            }
        ):
            raise AssuranceError(
                TRUSTED_OBSERVATION_INVALID,
                "finalized semantic review does not bind the managed obligation",
            )
        observed[identity] = {
            "status": review["status"],
            "observation_source": f"conformance-skill-{review_method}",
            "evidence": review,
            "result_digest": digest_document(review),
            "baseline_rule_id": route["baseline_rule_id"],
            "proof_eligible": review["status"] == "PASS",
        }
    records = []
    available = 0
    unavailable = 0
    proven = 0
    for record in base.get("records", []):
        identity = obligation_identity(record)
        method_observation = observed.get(identity)
        projected = dict(record)
        if method_observation is not None:
            status = method_observation["status"]
            projected["trusted_observation"] = {
                key: value for key, value in method_observation.items()
                if key != "proof_eligible"
            }
            if method_observation["proof_eligible"]:
                projected["assurance_status"] = "PROVEN"
                proven += 1
                available += 1
            elif status in {"EVIDENCE_MISSING", "NOT_RUN"}:
                projected["assurance_status"] = f"{status}_NOT_PROVEN"
                unavailable += 1
            else:
                projected["assurance_status"] = "TRUSTED_OBSERVED_NOT_PROVEN"
                available += 1
        records.append(projected)
    return {
        **base,
        "trusted_observation": document,
        "trusted_observed": available,
        "trusted_unavailable": unavailable,
        "receipt_succeeded": proven,
        "proven": proven,
        "not_proven": base["total"] - proven,
        "complete": False,
        "records": records,
    }


def trusted_observation_accepts_top_level(report: Any) -> bool:
    """Return whether observed method rows permit a top-level success.

    This is a run-local gate, not a claim that the global 814-rule obligation
    ledger is complete.  A trusted carrier may establish one mechanical
    method while leaving another method unexecuted; such a row remains useful
    evidence, but it cannot authorize ``SUCCEEDED``.
    """
    document = _require_object(report, "assurance report")
    observation = _require_object(
        document.get("trusted_observation"),
        "assurance report.trusted_observation",
    )
    results = _require_field(
        observation,
        "rule_results",
        list,
        "assurance report.trusted_observation",
    )
    records = {
        obligation_identity(record): record
        for record in _require_field(document, "records", list, "assurance report")
    }
    for index, raw_result in enumerate(results):
        where = f"assurance report.trusted_observation.rule_results[{index}]"
        result = _require_object(raw_result, where)
        payload = _require_object(result.get("result_payload"), f"{where}.result_payload")
        aggregate_status = payload.get("status")
        subresults = _require_field(
            result, "check_method_subresults", list, where
        )
        statuses = set()
        for subindex, raw_subresult in enumerate(subresults):
            subwhere = f"{where}.check_method_subresults[{subindex}]"
            method = _require_field(
                _require_object(raw_subresult, subwhere), "check_method", str, subwhere
            )
            record = records.get((result["canonical_id"], result["revision_digest"], method))
            if record is None or not isinstance(record.get("trusted_observation"), dict):
                return False
            statuses.add(record["trusted_observation"].get("status"))
        terminal_statuses = {"FAIL", "NOT_APPLICABLE", "PASS"}
        if (
            aggregate_status not in terminal_statuses
            or not statuses
            or not statuses <= terminal_statuses
        ):
            return False
        if aggregate_status == "PASS" and statuses != {"PASS"}:
            return False
        if (
            aggregate_status == "NOT_APPLICABLE"
            and statuses != {"NOT_APPLICABLE"}
        ):
            return False
    return True
