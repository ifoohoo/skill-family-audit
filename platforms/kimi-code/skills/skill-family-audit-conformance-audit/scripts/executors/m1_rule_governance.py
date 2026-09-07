"""M1 执行族：规则治理与不可豁免（W2-B1 共 7 条）。

证据面：
- 项目治理声明：exceptions.json / rule-overrides.json / release-gate-results.json /
  non-waivable-baselines.json；
- 本次运行装载的规范清单（ctx["manifest"]）与规范包索引（ctx["spec_index"]）。

不可豁免规则身份不由执行器硬编码（non-exempt-baselines 精确映射仍待用户内容
确认）；执行器消费项目自己声明的 ``non-waivable-baselines.json.rule_ids`` 作为
判定集合，未声明者按"未声明不可豁免集合"处理。

SFA-FOUNDATION-011 实施态候选已暂存并冻结收据投影依赖尚未完成：只核对三个独立子主张（Foundation 0.12.0 Profile SPI 观察、根导出调用冻结收据、独立非覆盖行为证据），只消费 conformance_workflow 投影的已验证证据，不读取目标树、不执行 scaffold/adopt-plan。独立验收前保持 RETAINED_UNIMPLEMENTED，由授权相位决定是否加入 CHECKS。
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .contracts import (
    VIOLATION_IMPACT_VOCABULARY,
    ExecutorEvidenceError,
    governance_dir,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

_OVERRIDE_ACTIONS = {"add_independent_rule", "tighten", "close", "override", "loosen", "waive"}
_FORBIDDEN_OVERRIDE_ACTIONS = {"close", "override", "loosen", "waive"}
_RELEASE_ID_RE = re.compile(r"^[^@\s]+@\d+\.\d+\.\d+$")
_NON_PASS_STATUSES = {"FAIL", "BLOCKED", "NOT_RUN", "EVIDENCE_MISSING", "TIMEOUT", "CANCELLED", "EXCEPTION"}


# ---------------------------------------------------------------------------
# 逐方法子结果（受管机械方法 digest_verification + schema_validation）
# ---------------------------------------------------------------------------


def _method_row(method: str, status: str, source: str, **evidence: Any) -> dict[str, Any]:
    return {
        "check_method": method,
        "status": status,
        "observation_source": source,
        "evidence": evidence or {"reason": status.lower()},
    }


def _finish(rows: list[dict[str, Any]], **evidence: Any) -> dict[str, Any]:
    """从逐方法行确定性推导聚合状态，与 contracts.validate_method_subresults 一致。"""
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
        raise ExecutorEvidenceError(
            "METHOD_RESULT_COMBINATION_INVALID", repr(sorted(statuses))
        )
    return {
        "status": status,
        "evidence": dict(evidence),
        "check_method_subresults": rows,
    }


def _schema_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "schema_validation", status, "executor_schema_validation_observation", **evidence
    )


def _digest_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "digest_verification", status, "executor_digest_verification_observation", **evidence
    )


def _documents_observed(
    ctx: dict[str, Any], names: tuple[str, ...]
) -> list[dict[str, Any]]:
    """字节级完整性观察：本次执行真实读取的治理声明文档（存在性与 sha256）。"""
    observations = []
    for name in names:
        path = governance_dir(ctx) / f"{name}.json"
        if path.is_file() and not path.is_symlink():
            observations.append({
                "document": name,
                "present": True,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
        else:
            observations.append({"document": name, "present": False})
    return observations


def _doc_digest_row(
    ctx: dict[str, Any], names: tuple[str, ...], status: str = "PASS", **evidence: Any
) -> dict[str, Any]:
    return _digest_row(status, documents=_documents_observed(ctx, names), **evidence)


def _non_waivable_ids(ctx: dict[str, Any]) -> set[str]:
    document = load_governance_document(ctx, "non-waivable-baselines")
    if document is None:
        return set()
    ids = document.get("rule_ids")
    if not isinstance(ids, list) or not all(isinstance(item, str) and item for item in ids):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "non-waivable-baselines.rule_ids 必须是唯一非空字符串数组",
        )
    if len(ids) != len(set(ids)):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "non-waivable-baselines.rule_ids 存在重复"
        )
    return set(ids)


def _exceptions(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "exceptions")
    if document is None:
        return None
    return rows_of(document, "exceptions", "exceptions")


def check_graph_026(ctx: dict[str, Any]) -> dict[str, Any]:
    """目标项目不得自行批准对上级强制规则的豁免。

    机械断言：任何已声明的豁免记录必须携带非空外部权威引用 authority_ref，
    且 approver 不得是目标项目自身。未声明任何豁免则无违反事实。
    """
    exceptions = _exceptions(ctx)
    if exceptions is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_exceptions"),
                _doc_digest_row(ctx, ("exceptions",)),
            ],
            declared_exceptions=0,
            mechanical_half=True,
        )
    violations = []
    for index, row in enumerate(exceptions):
        authority_ref = row.get("authority_ref")
        approver = row.get("approver")
        self_approved = (
            not isinstance(authority_ref, str)
            or not authority_ref
            or approver in {"target_project", "project_self", "self"}
        )
        if self_approved:
            violations.append({"index": index, "rule_id": row.get("rule_id")})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("exceptions",)),
            ],
            self_approved_exceptions=violations,
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row(
                "PASS", reason="schema_checks_passed", declared_exceptions=len(exceptions)
            ),
            _doc_digest_row(ctx, ("exceptions",)),
        ],
        declared_exceptions=len(exceptions),
        mechanical_half=True,
    )


def check_graph_027(ctx: dict[str, Any]) -> dict[str, Any]:
    """被标记为不可豁免的规则不得接受项目、技能族或发布政策例外。

    机械断言：已声明豁免不得覆盖项目自己声明的不可豁免规则集合。
    """
    exceptions = _exceptions(ctx)
    if exceptions is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_exceptions"),
                _doc_digest_row(ctx, ("exceptions", "non-waivable-baselines")),
            ],
            declared_exceptions=0,
            mechanical_half=True,
        )
    non_waivable = _non_waivable_ids(ctx)
    violations = [
        {"index": index, "rule_id": row.get("rule_id")}
        for index, row in enumerate(exceptions)
        if isinstance(row.get("rule_id"), str) and row["rule_id"] in non_waivable
    ]
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("exceptions", "non-waivable-baselines")),
            ],
            non_waivable_exceptions=violations,
            non_waivable_count=len(non_waivable),
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                declared_exceptions=len(exceptions),
                non_waivable_count=len(non_waivable),
            ),
            _doc_digest_row(ctx, ("exceptions", "non-waivable-baselines")),
        ],
        declared_exceptions=len(exceptions),
        non_waivable_count=len(non_waivable),
        mechanical_half=True,
    )


def check_nonwaive_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """不可豁免规则失败/未运行/证据不足时必须阻断正式发布；项目加严和普通例外无权放行。

    机械断言：
    1. 已声明门禁结果中，不可豁免规则处于非通过状态时必须 publication_blocked=true
       且 released!=true；
    2. 已声明豁免不得覆盖该规则（与 GRAPH-027 的不可豁免集合同源）。
    """
    document = load_governance_document(ctx, "release-gate-results")
    exceptions = _exceptions(ctx) or []
    non_waivable = _non_waivable_ids(ctx)
    if document is None:
        if non_waivable and exceptions:
            covered = [
                row.get("rule_id")
                for row in exceptions
                if isinstance(row.get("rule_id"), str) and row["rule_id"] in non_waivable
            ]
            if covered:
                return _finish(
                    [
                        _schema_row("FAIL", reason="waived_non_waivable"),
                        _doc_digest_row(
                            ctx,
                            ("release-gate-results", "exceptions", "non-waivable-baselines"),
                        ),
                    ],
                    waived_non_waivable=sorted(set(covered)),
                    gate_results_declared=False,
                    mechanical_half=True,
                )
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_gate_results"),
                _doc_digest_row(
                    ctx,
                    ("release-gate-results", "exceptions", "non-waivable-baselines"),
                ),
            ],
            gate_results_declared=False,
            non_waivable_count=len(non_waivable),
            mechanical_half=True,
        )
    rows = rows_of(document, "results", "release-gate-results")
    violations = []
    for index, row in enumerate(rows):
        rule_id = row.get("rule_id")
        status = row.get("status")
        is_non_waive = row.get("non_waivable") is True or (
            isinstance(rule_id, str) and rule_id in non_waivable
        )
        if not is_non_waive:
            continue
        if status in _NON_PASS_STATUSES and (
            row.get("publication_blocked") is not True or row.get("released") is True
        ):
            violations.append({"index": index, "rule_id": rule_id, "status": status})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(
                    ctx,
                    ("release-gate-results", "exceptions", "non-waivable-baselines"),
                ),
            ],
            released_non_waivable_failures=violations,
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                gate_results=len(rows),
                non_waivable_count=len(non_waivable),
            ),
            _doc_digest_row(
                ctx,
                ("release-gate-results", "exceptions", "non-waivable-baselines"),
            ),
        ],
        gate_results=len(rows),
        non_waivable_count=len(non_waivable),
        mechanical_half=True,
    )


def check_rule_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """规则违规影响必须明确为阻断、错误、告警或观察之一。

    机械断言：本次装载的规范清单中，canonical 终态规则实现
    （terminalRuleImplementations）的 failureImpact 必须在四值词表内，
    且全部规则定义（ruleCategories 与 terminalRuleImplementations）的
    revisionDigest 为 64 位十六进制。ruleCategories 是兼容检查器自身的
    基线结构规则，其修订锁定定义使用检查器独立的 critical/high 影响词表，
    不属于 canonical violation_impact 的约束对象。
    """
    manifest = ctx.get("manifest")
    if not isinstance(manifest, dict):
        return _finish(
            [
                _schema_row("EVIDENCE_MISSING", reason="manifest_not_in_context"),
                _digest_row("EVIDENCE_MISSING", reason="manifest_not_in_context"),
            ],
            reason="manifest_not_in_context",
        )
    violations = []
    checked = 0
    for category in manifest.get("ruleCategories", []):
        for rule in category.get("rules", []):
            checked += 1
            if not is_hex64(rule.get("revisionDigest")):
                violations.append(
                    {"rule_id": rule.get("ruleId"), "reason": "revision_digest_invalid"}
                )
    for rule in manifest.get("terminalRuleImplementations", []):
        checked += 1
        if rule.get("failureImpact") not in VIOLATION_IMPACT_VOCABULARY:
            violations.append(
                {"rule_id": rule.get("ruleId"), "failureImpact": rule.get("failureImpact")}
            )
        if not is_hex64(rule.get("revisionDigest")):
            violations.append(
                {"rule_id": rule.get("ruleId"), "reason": "revision_digest_invalid"}
            )
    if checked == 0:
        return _finish(
            [
                _schema_row("FAIL", reason="rule_manifest_empty"),
                _digest_row("PASS", reason="digest_checks_passed", rules_scanned=0),
            ],
            reason="rule_manifest_empty",
        )
    digest_violations = [
        v for v in violations if v.get("reason") == "revision_digest_invalid"
    ]
    schema_violations = [v for v in violations if "failureImpact" in v]
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_violations else "PASS",
                    reason=(
                        "schema_violations" if schema_violations else "schema_checks_passed"
                    ),
                    violations=schema_violations,
                ),
                _digest_row(
                    "FAIL" if digest_violations else "PASS",
                    reason=(
                        "digest_violations" if digest_violations else "digest_checks_passed"
                    ),
                    violations=digest_violations,
                ),
            ],
            violations=violations,
            checked=checked,
        )
    return _finish(
        [
            _schema_row(
                "PASS",
                reason="schema_checks_passed",
                checked=checked,
                vocabulary=list(VIOLATION_IMPACT_VOCABULARY),
            ),
            _digest_row("PASS", reason="digest_checks_passed", checked=checked),
        ],
        checked=checked,
        vocabulary=list(VIOLATION_IMPACT_VOCABULARY),
    )


def check_rule_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """项目只能新增独立规则或收紧上级规则，不得关闭、覆盖或放宽上级强制规则。

    机械断言：已声明规则覆盖动作只允许 add_independent_rule / tighten；
    出现 close / override / loosen / waive 即违反。
    """
    document = load_governance_document(ctx, "rule-overrides")
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_overrides"),
                _doc_digest_row(ctx, ("rule-overrides",)),
            ],
            declared_overrides=0,
            mechanical_half=True,
        )
    rows = rows_of(document, "overrides", "rule-overrides")
    violations = []
    for index, row in enumerate(rows):
        action = row.get("action")
        if action not in _OVERRIDE_ACTIONS:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"rule-overrides 第 {index} 行动作非法: {action!r}",
            )
        if action in _FORBIDDEN_OVERRIDE_ACTIONS:
            violations.append({"index": index, "rule_id": row.get("rule_id"), "action": action})
    if violations:
        return _finish(
            [
                _schema_row("FAIL", reason="schema_violations", violations=violations),
                _doc_digest_row(ctx, ("rule-overrides",)),
            ],
            forbidden_overrides=violations,
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", declared_overrides=len(rows)),
            _doc_digest_row(ctx, ("rule-overrides",)),
        ],
        declared_overrides=len(rows),
        mechanical_half=True,
    )


def check_rule_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """适用的不可豁免规则失败时必须阻断其约束的操作；项目和普通例外均不得放行。

    机械断言：与 NONWAIVE-003 同源事实，另外要求门禁结果行携带规则修订摘要
    （缺失修订的行不得声明放行）。
    """
    document = load_governance_document(ctx, "release-gate-results")
    non_waivable = _non_waivable_ids(ctx)
    exceptions = _exceptions(ctx) or []
    waived = sorted(
        {
            row.get("rule_id")
            for row in exceptions
            if isinstance(row.get("rule_id"), str) and row["rule_id"] in non_waivable
        }
    )
    if waived:
        return _finish(
            [
                _schema_row("FAIL", reason="waived_non_waivable"),
                _doc_digest_row(
                    ctx,
                    ("release-gate-results", "exceptions", "non-waivable-baselines"),
                ),
            ],
            waived_non_waivable=waived,
            mechanical_half=True,
        )
    if document is None:
        return _finish(
            [
                _schema_row("PASS", reason="no_declared_gate_results"),
                _doc_digest_row(
                    ctx,
                    ("release-gate-results", "exceptions", "non-waivable-baselines"),
                ),
            ],
            gate_results_declared=False,
            non_waivable_count=len(non_waivable),
            mechanical_half=True,
        )
    rows = rows_of(document, "results", "release-gate-results")
    violations = []
    for index, row in enumerate(rows):
        rule_id = row.get("rule_id")
        is_non_waive = row.get("non_waivable") is True or (
            isinstance(rule_id, str) and rule_id in non_waivable
        )
        if not is_non_waive:
            continue
        if row.get("status") in _NON_PASS_STATUSES:
            if row.get("operation_blocked") is not True or row.get("released") is True:
                violations.append({"index": index, "rule_id": rule_id})
            continue
        if row.get("status") == "PASS" and not is_hex64(row.get("revision_digest")):
            violations.append(
                {"index": index, "rule_id": rule_id, "reason": "revision_digest_missing"}
            )
    digest_violations = [
        v for v in violations if v.get("reason") == "revision_digest_missing"
    ]
    schema_violations = [v for v in violations if "reason" not in v]
    if violations:
        return _finish(
            [
                _schema_row(
                    "FAIL" if schema_violations else "PASS",
                    reason=(
                        "schema_violations" if schema_violations else "schema_checks_passed"
                    ),
                    violations=schema_violations,
                ),
                _digest_row(
                    "FAIL" if digest_violations else "PASS",
                    reason=(
                        "digest_violations" if digest_violations else "digest_checks_passed"
                    ),
                    violations=digest_violations,
                ),
            ],
            unblocked_non_waivable=violations,
            mechanical_half=True,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", gate_results=len(rows)),
            _doc_digest_row(
                ctx,
                ("release-gate-results", "exceptions", "non-waivable-baselines"),
            ),
        ],
        gate_results=len(rows),
        mechanical_half=True,
    )


def check_rule_023(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次规范发布必须具有主/次/修订版本，并以不可变内容摘要锁定规则修订集合。

    机械断言：规范包索引的 activeSpecRelease.releaseId 必须形如
    ``<name>@<major>.<minor>.<revision>``，且 contentDigest 与
    ruleManifestDigest 均为 64 位十六进制摘要。
    """
    index = ctx.get("spec_index")
    if not isinstance(index, dict):
        return _finish(
            [
                _schema_row("EVIDENCE_MISSING", reason="spec_index_not_in_context"),
                _digest_row("EVIDENCE_MISSING", reason="spec_index_not_in_context"),
            ],
            reason="spec_index_not_in_context",
        )
    release = index.get("activeSpecRelease")
    if not isinstance(release, dict):
        return _finish(
            [
                _schema_row("FAIL", reason="active_spec_release_missing"),
                _digest_row("PASS", reason="digest_checks_passed", no_release_digests=True),
            ],
            reason="active_spec_release_missing",
        )
    release_id = release.get("releaseId")
    if not isinstance(release_id, str) or not _RELEASE_ID_RE.fullmatch(release_id):
        return _finish(
            [
                _schema_row(
                    "FAIL",
                    reason="release_id_not_semver_triple",
                    releaseId=release_id,
                ),
                _digest_row("PASS", reason="digest_checks_passed", no_release_digests=True),
            ],
            reason="release_id_not_semver_triple",
            releaseId=release_id,
        )
    digest_errors = [
        field
        for field in ("contentDigest", "ruleManifestDigest")
        if not is_hex64(release.get(field))
    ]
    if digest_errors:
        return _finish(
            [
                _schema_row("PASS", reason="schema_checks_passed", releaseId=release_id),
                _digest_row(
                    "FAIL",
                    reason="release_digest_invalid",
                    fields=digest_errors,
                ),
            ],
            reason="release_digest_invalid",
            fields=digest_errors,
        )
    return _finish(
        [
            _schema_row("PASS", reason="schema_checks_passed", releaseId=release_id),
            _digest_row(
                "PASS",
                reason="digest_checks_passed",
                locked_digests=["contentDigest", "ruleManifestDigest"],
            ),
        ],
        releaseId=release_id,
        locked_digests=["contentDigest", "ruleManifestDigest"],
    )




def _foundation_verification_infra_codes() -> frozenset[str]:
    return frozenset({
        "FOUNDATION_PROFILE_SPI_MISSING",
        "FOUNDATION_PROFILE_SPI_PATH_SYMLINK",
        "FOUNDATION_NODE_UNAVAILABLE",
        "FOUNDATION_PROFILE_SPI_FAILED",
        "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
        "PROJECT_PROFILE_MISSING",
        "PROJECT_PROFILE_SYMLINK",
        "PROJECT_PROFILE_INVALID",
    })


def check_foundation_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """Project Profile 与 Provider Profile 必须分流调用不同公开入口（候选，未注册）。

    机械断言（schema_validation）：载体类型只来自真实 ``profile.json`` 文档
    的 ``kind`` 字段（"skill-family.project-profile" 或
    "skill-family.profile-descriptor"），绝不按文件名猜载体类型：
    - project-profile：只消费 scope 投影的 verifyProjectProfile 结构化结果
      （scope.foundation_profile），SPE0000 且完整才机械 PASS；
    - profile-descriptor：只通过公共 ``verifyProfile`` 入口校验，SPE0000 才
      PASS；SPE1008 表示入口被互换为 project 入口，判 FAIL；
    - 入口互换、载体非法或失败结果被解释成通过为 FAIL；
    - 触发后缺载体或真实 SPI 结果为 EVIDENCE_MISSING；
    - 两类载体及采用声明均不存在时为 NOT_APPLICABLE。
    行为验证与语义审阅不由本候选承担。
    """
    from pathlib import Path

    target = ctx.get("target")
    raw_scope = ctx.get("scope")
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    if not isinstance(target, (str, Path)) or not str(target):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="target_not_observable")],
            mechanical_half=True,
        )
    root = Path(target)
    try:
        target_is_dir = root.is_dir()
    except OSError:
        target_is_dir = False
    if not target_is_dir:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="target_not_observable")],
            mechanical_half=True,
        )
    project_profile = root / "profile.json"
    adoption_evidence = scope.get("project_adoption_evidence")
    carrier_claimed = bool(
        adoption_evidence.get("profile_carrier")
        if isinstance(adoption_evidence, dict)
        else False
    )
    carrier = (
        adoption_evidence.get("profile_carrier")
        if isinstance(adoption_evidence, dict)
        else None
    )
    if carrier is not None and carrier != "profile.json":
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_path_mismatch", claimed=carrier)],
            mechanical_half=True,
        )
    if project_profile.is_symlink():
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_is_symlink")],
            mechanical_half=True,
        )
    # 符号链接也算“存在”：先判载体非法（FAIL），再判缺文件（EVIDENCE_MISSING）
    try:
        profile_present = project_profile.exists()
    except OSError:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="profile_carrier_observation_unavailable")],
            mechanical_half=True,
        )
    if not profile_present and not carrier_claimed:
        return _finish(
            [_schema_row("NOT_APPLICABLE", reason="no_profile_carrier_declared")],
            mechanical_half=True,
        )
    if not profile_present:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="profile_carrier_declared_but_file_missing")],
            mechanical_half=True,
        )
    if not project_profile.is_file():
        return _finish(
            [_schema_row("FAIL", reason="profile_carrier_not_regular_file")],
            mechanical_half=True,
        )
    import json as _json

    try:
        document = _json.loads(project_profile.read_text(encoding="utf8"))
    except OSError as exc:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="profile_document_unreadable", error=str(exc)[:256])],
            mechanical_half=True,
        )
    except (UnicodeDecodeError, _json.JSONDecodeError) as exc:
        return _finish(
            [_schema_row("FAIL", reason="profile_document_invalid_json", error=str(exc)[:256])],
            mechanical_half=True,
        )
    if not isinstance(document, dict):
        return _finish(
            [_schema_row("FAIL", reason="profile_document_not_object")],
            mechanical_half=True,
        )
    kind = document.get("kind")
    if kind == "skill-family.project-profile":
        return _foundation_010_project_outcome(ctx, scope)
    if kind == "skill-family.profile-descriptor":
        return _foundation_010_provider_outcome(root)
    return _finish(
        [_schema_row("FAIL", reason="profile_carrier_kind_unknown", kind=kind)],
        mechanical_half=True,
    )


def _foundation_010_project_outcome(
    ctx: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any]:
    """Project Profile 分支：只消费 scope.foundation_profile 结构化结果。"""
    foundation_profile = scope.get("foundation_profile")
    if not isinstance(foundation_profile, dict) or not foundation_profile:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="verify_project_profile_result_missing")],
            mechanical_half=True,
        )
    code = foundation_profile.get("code")
    if not isinstance(code, str) or not code:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="verify_project_profile_result_missing")],
            mechanical_half=True,
        )
    if code == "SPE0000":
        if foundation_profile.get("foundation_profile_complete") is True:
            return _finish(
                [_schema_row("PASS", reason="schema_checks_passed", code=code)],
                mechanical_half=True,
            )
        return _finish(
            [_schema_row("FAIL", reason="verification_result_contradicts_success_code")],
            mechanical_half=True,
        )
    if code == "SPE1008":
        # SPE1008（project-profile-schema-invalid）在本规则下即入口互换：
        # 项目 Profile 被当作非项目载体处理或使用了错误入口。
        return _finish(
            [_schema_row("FAIL", reason="entry_swapped", code=code)],
            mechanical_half=True,
        )
    if code in _foundation_verification_infra_codes():
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="foundation_verification_unavailable", code=code)],
            mechanical_half=True,
        )
    return _finish(
        [_schema_row("FAIL", reason="profile_schema_pin_or_override_rejected", code=code)],
        mechanical_half=True,
    )


def _foundation_010_provider_outcome(target: Path) -> dict[str, Any]:
    """Provider descriptor 分支：只通过公共 verifyProfile 入口校验。"""
    import foundation_adoption_verifier as fal

    verification = fal.verify_profile(target, "profile.json")
    if not isinstance(verification, dict) or not verification:
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="verify_profile_result_missing")],
            mechanical_half=True,
        )
    code = verification.get("code")
    authority_ok = verification.get("authority_ok")
    if not isinstance(code, str) or not code or not isinstance(authority_ok, bool):
        return _finish(
            [_schema_row("EVIDENCE_MISSING", reason="verify_profile_result_missing")],
            mechanical_half=True,
        )
    if authority_ok is True and code == "SPE0000":
        return _finish(
            [_schema_row("PASS", reason="schema_checks_passed", code=code)],
            mechanical_half=True,
        )
    if authority_ok is True or code == "SPE0000":
        return _finish(
            [_schema_row("FAIL", reason="verification_result_contradicts_success_code", code=code)],
            mechanical_half=True,
        )
    if authority_ok is not True:
        if code in _foundation_verification_infra_codes():
            return _finish(
                [_schema_row("EVIDENCE_MISSING", reason="foundation_verification_unavailable", code=code)],
                mechanical_half=True,
            )
        return _finish(
            [_schema_row("FAIL", reason="profile_schema_pin_or_override_rejected", code=code)],
            mechanical_half=True,
        )


CHECKS = {
    "SFA-GRAPH-026": check_graph_026,
    "SFA-GRAPH-027": check_graph_027,
    "SFA-NONWAIVE-003": check_nonwaive_003,
    "SFA-RULE-005": check_rule_005,
    "SFA-RULE-007": check_rule_007,
    "SFA-RULE-009": check_rule_009,
    "SFA-RULE-023": check_rule_023,
    "SFA-FOUNDATION-010": check_foundation_010,
}
