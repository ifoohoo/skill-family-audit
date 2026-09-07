"""M5 执行族：上下文/隔离/自愈/运行框架（W2-B1 共 29 条）。

证据面：项目治理声明 context-budget.json / harness-interfaces.json /
isolation-policy.json / selfheal-policy.json / stage-isolation.json /
tier1-runtime.json / run-record.json。全部约束"已声明者"：文档缺失 =
无可判违反事实 → PASS；形状非法失败关闭。

SFA-CONTEXT-002 消费 W1 SG-33 冻结的 foundation 词元估算消费契约
（skill-family-contracts:token-estimate-consumption）语义：取数字段
tokens、接受裸整数降级形态与记录对象形态、降级不放宽阈值、失败关闭。
权威估算器（harness-node token-estimation，foundation 0.6.0）落地前，
启发式口径超限清单仅作证据（BIND-0020 登记）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import (
    ISOLATION_DIMENSIONS,
    SELFHEAL_POLICY_FIELDS,
    ExecutorEvidenceError,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

#: SFA-CONTEXT-002 强制干预阈值（告警线 2000 词元的 120%）。
CONTEXT_HARD_TOKENS = 2400
#: foundation 冻结的估算记录 kind（SFA-CONTEXT-028 谱系）。
TOKEN_RECORD_KIND = "skill-family.token-estimate-record"
#: 权威词元估算器身份（foundation 0.6.0 harness-node token-estimation）。
AUTHORITATIVE_ESTIMATORS = {
    "skill-family-harness-node:token-estimation",
    "skill-family-contracts:token-estimate-consumption",
}
#: 隔离维度必须携带的证明字段（SFA-ISOLATION-002~007）。
ISOLATION_PROOF_FIELDS = {
    "run_environment": ("unique_identity", "isolated_from_other_runs", "destructible"),
    "credential_inheritance": ("inherits_host_long_term_credentials",),
    "credentials": (),
    "network": ("default_deny",),
    "mounts": ("inputs_readonly",),
    "limits": ("killable_process_tree",),
}


def _consume_token_estimate(value: Any) -> tuple[int, str]:
    """按 foundation 冻结契约消费词元估算；失败关闭，绝不强转默认值。

    返回 (tokens, shape)；shape ∈ {record, degraded_integer}。
    """
    if isinstance(value, bool):
        raise ExecutorEvidenceError(
            "TOKEN_ESTIMATE_INVALID", "词元估算不得是布尔值"
        )
    if isinstance(value, int):
        if value < 0:
            raise ExecutorEvidenceError(
                "TOKEN_ESTIMATE_INVALID", "词元估算裸整数必须非负"
            )
        return value, "degraded_integer"
    if isinstance(value, dict):
        kind = value.get("kind")
        if kind is not None and kind != TOKEN_RECORD_KIND:
            raise ExecutorEvidenceError(
                "TOKEN_ESTIMATE_RECORD_KIND_MISMATCH",
                f"估算记录 kind 必须是 {TOKEN_RECORD_KIND}",
            )
        tokens = value.get("tokens")
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ExecutorEvidenceError(
                "TOKEN_ESTIMATE_TOKENS_INVALID",
                "估算记录 tokens 必须是非负整数（失败关闭，不得强转）",
            )
        return tokens, "record"
    raise ExecutorEvidenceError(
        "TOKEN_ESTIMATE_INVALID", "词元估算必须是裸非负整数或估算记录对象"
    )


def check_context_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """单个 SKILL.md 达到 2400 词元必须执行上下文减量或职责拆分。

    机械断言（消费 SG-33 冻结契约）：
    - 估算必须可消费（tokens 取数、降级形态合法、失败关闭）；
    - 双口径判定：逻辑源与最坏平台投影取较大者；
    - 权威估算器口径达到阈值必须声明干预（减量或拆分）；
    - 权威估算器落地前，启发式口径超限仅作证据，不强制整改。
    """
    document = load_governance_document(ctx, "context-budget")
    if document is None:
        return result("PASS", measurements_declared=0, mechanical_half=True)
    rows = rows_of(document, "measurements", "context-budget")
    violations = []
    evidence_only = []
    for index, row in enumerate(rows):
        estimator = row.get("estimator_source")
        if not isinstance(estimator, str) or not estimator:
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID",
                f"context-budget 第 {index} 行必须披露估算器来源（降级也不豁免）",
            )
        logical, logical_shape = _consume_token_estimate(row.get("logical_source_tokens"))
        worst, worst_shape = _consume_token_estimate(row.get("worst_projection_tokens"))
        decisive = max(logical, worst)
        authoritative = estimator in AUTHORITATIVE_ESTIMATORS
        if decisive >= CONTEXT_HARD_TOKENS:
            if authoritative:
                if row.get("intervention") not in {"context_reduction", "responsibility_split"}:
                    violations.append(
                        {"index": index, "skill": row.get("skill"), "tokens": decisive}
                    )
            else:
                evidence_only.append({"index": index, "skill": row.get("skill"), "tokens": decisive})
        if not authoritative and logical_shape == "record":
            # 记录形态是权威估算器专属；启发式只允许裸整数降级形态。
            violations.append(
                {"index": index, "skill": row.get("skill"), "reason": "heuristic_record_shape"}
            )
    if violations:
        return result(
            "FAIL",
            threshold_violations=violations,
            hard_threshold=CONTEXT_HARD_TOKENS,
            mechanical_half=True,
        )
    return result(
        "PASS",
        measurements=len(rows),
        evidence_only_over_limit=evidence_only,
        hard_threshold=CONTEXT_HARD_TOKENS,
        mechanical_half=True,
    )


def check_context_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """上下文减量不得删除安全边界、授权规则、失败语义或资源导航。

    机械断言：已声明减量动作的 removed_categories 不得包含四类安全内容。
    """
    document = load_governance_document(ctx, "context-budget")
    if document is None:
        return result("PASS", reductions_declared=0, mechanical_half=True)
    protected = {"safety_boundary", "authorization_rules", "failure_semantics", "resource_navigation"}
    violations = []
    for row in rows_of(document, "reductions", "context-budget"):
        removed = row.get("removed_categories") or []
        if not isinstance(removed, list) or not all(isinstance(item, str) for item in removed):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "context-budget.reductions.removed_categories 必须是字符串数组"
            )
        hit = sorted(set(removed) & protected)
        if hit:
            violations.append({"reduction": row.get("reduction_id"), "removed_protected": hit})
    if violations:
        return result("FAIL", reductions_removed_safety_content=violations, mechanical_half=True)
    return result("PASS", reductions_checked=True, mechanical_half=True)


def check_context_018(ctx: dict[str, Any]) -> dict[str, Any]:
    """命中正确性风险失效模式时必须先写正式检查点再换干净会话。

    机械断言：已声明 correctness/boundary/continuity 失效模式命中时，必须
    携带 checkpoint_ref 且 clean_session=true；未命中则无违反事实。
    """
    record = load_governance_document(ctx, "run-record")
    if record is None:
        return result("PASS", run_record_declared=False, mechanical_half=True)
    hits = [
        row
        for row in rows_of(record, "failure_mode_hits", "run-record")
        if row.get("affects_correctness") is True
        or row.get("affects_task_boundary") is True
        or row.get("affects_continuity") is True
    ]
    if not hits:
        return result("PASS", correctness_risk_hits=0, mechanical_half=True)
    violations = [
        {"failure_mode": row.get("failure_mode")}
        for row in hits
        if not is_hex64(row.get("checkpoint_ref")) or row.get("clean_session") is not True
    ]
    if violations:
        return result("FAIL", checkpoint_missing_before_session_switch=violations, mechanical_half=True)
    return result("PASS", correctness_risk_hits=len(hits), mechanical_half=True)


def check_harness_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """恢复机制不得通过跳过测试、减少证据、改写状态或放宽验收使任务通过。

    机械断言：已声明恢复动作不得包含四类降质动作。
    """
    document = load_governance_document(ctx, "harness-interfaces")
    if document is None:
        return result("PASS", harness_declared=False, mechanical_half=True)
    forbidden = {"skip_tests", "reduce_evidence", "rewrite_state", "loosen_acceptance"}
    violations = []
    for row in rows_of(document, "recovery_actions", "harness-interfaces"):
        hit = sorted(set(row.get("actions") or []) & forbidden)
        if hit:
            violations.append({"recovery": row.get("recovery_id"), "actions": hit})
    if violations:
        return result("FAIL", recovery_lowers_quality_gates=violations, mechanical_half=True)
    return result("PASS", recovery_actions_checked=True, mechanical_half=True)


# ---------------------------------------------------------------------------
# SFA-HARNESS-004 三角色核验（public_input_contract / consumer_implementation /
# version_bound_review_record）：材料与锚点定义、逐方法行助手与真实核验。
#
# 已发布语义锚点值引证：只读取证报告转录（h06-three-role-evidence.md §2）逐字项
# 与 spec/contracts 两份 schema 实读；只核对关键锚点（$id/const/required 键集），
# 不硬编码 schema 全文。目标根 = ctx["target"]（Audit 产品包根，与
# .skill-family-audit/governance 同级）。全部核验只读目标文件，不 import、不执行
# 目标代码。
# ---------------------------------------------------------------------------

#: 角色① governance-gate-run-evidence 合同锚点（取证报告 2c 逐字项）。
_H004_GATE_SCHEMA_ID = (
    "https://contracts.skill-family.example/skill-family-audit/"
    "candidate/v2/governance-gate-run-evidence.json"
)
_H004_GATE_KIND_CONST = "skill-family-audit.governance-gate-run-evidence"
_H004_GATE_RULE_ID_CONST = "SFA-GOVERNANCE-001"
_H004_GATE_REQUIRED = ("schemaVersion", "kind", "ruleId", "binding", "gates")
_H004_GATE_BINDING_KEYS = (
    "target_version", "target_digest", "task_id", "platform", "environment",
)
_H004_GATE_OBSERVATION_KEYS = (
    "id", "ran", "argv", "cwd", "env", "input_refs", "stdout", "stderr",
    "exit_code", "conclusion",
)
#: 角色① semantic-review-result v2 合同锚点（取证报告 2c 逐字项）。
_H004_SEMANTIC_SCHEMA_ID = "skill-family-audit:semantic-review-result"
_H004_SEMANTIC_KIND_CONST = "skill-family-audit.semantic-review-result"
_H004_SEMANTIC_PRODUCER_CONST = "skill-family-audit:conformance-audit"
_H004_SEMANTIC_REQUIRED = (
    "schema_version", "kind", "producer_method_id", "cognitive_independence",
    "foundation_task_digest", "review_request_digest", "evidence_set_digest",
    "reviewed_rule_set_digest", "reviews",
)
_H004_EVIDENCE_REF_KEYS = ("evidence_id", "sha256", "locator", "role")
_H004_CONSUMER_SCHEMAS = (
    "governance-gate-run-evidence.schema.json",
    "semantic-review-result.schema.json",
)
#: 四平台发布副本（contracts.REQUIRED_PLATFORMS；取证报告 2c 路径）。
_H004_REQUIRED_PLATFORMS = ("claude-code", "codex", "kimi-code", "workbuddy")
_H004_CONTRACT_REL_PATHS = (
    # (platform 内子目录, 发布副本文件名)
    ("shared/contracts", "governance-gate-run-evidence.schema.json"),
    ("foundation/quickstart-profile/schemas/consumer",
     "semantic-review-result.schema.json"),
)
#: 公开输入参数声明（SKILL.md --evidence-set 锚点；取证报告 2d，L26-34）。
_H004_SKILL_MD_REL = (
    "plugin-src/skills/skill-family-audit-conformance/SKILL.md"
)
#: 角色② 只读消费实现锚点：(target 根相对路径, 必须出现的文本锚点)。
#: 只做文本级核验，不执行目标代码。锚点出处：取证报告 §3a（rule_method_assurance
#: L81-83/L269-272）、§3b（conformance_workflow._load_evidence_set）、§3c
#: （m1_rule_governance_b2._governance_gate_behavior L5014+ docstring 合同）。
_H004_CONSUMER_ANCHORS = (
    (
        "plugin-src/skills/skill-family-audit-conformance/scripts/"
        "conformance_workflow.py",
        ("def _load_evidence_set(", "仅含 evidence_set 键"),
    ),
    (
        "plugin-src/skills/skill-family-audit-conformance/scripts/"
        "rule_method_assurance.py",
        (
            'EVIDENCE_BUNDLE_KIND = "skill-family-audit.'
            'rule-method-evidence-bundle"',
            'METHOD_RECEIPT_KIND = "skill-family-audit.method-obligation-receipt"',
            "def _receipt_observation(",
            "without promoting them to execution proof",
        ),
    ),
    (
        "plugin-src/skills/skill-family-audit-conformance/scripts/executors/"
        "m1_rule_governance_b2.py",
        (
            "def _governance_gate_behavior(",
            "这里仅重算",
            "并不会执行",
            "接受 scope 中的自填观察",
        ),
    ),
)
#: 角色③ 治理声明键与记录内容字段。声明键 = harness-interfaces 顶层键
#: （003/005/007 同文档同通道）；记录内容字段逐字引证 canonical 义务句 3 与
#: evidence_requirements 第 4 条（版本/审阅对象/输入输出绑定的既有审阅记录）。
_H004_REVIEW_RECORD_KEY = "version_bound_review_record"
_H004_RECORD_CONTENT_FIELDS = (
    "target_version", "reviewed_object", "input_binding", "output_binding",
)


def _method_row(method: str, status: str, source: str, **evidence: Any) -> dict[str, Any]:
    return {
        "check_method": method,
        "status": status,
        "observation_source": source,
        "evidence": evidence or {"reason": status.lower()},
    }


def _finish(rows: list[dict[str, Any]], **evidence: Any) -> dict[str, Any]:
    """从逐方法行确定性推导聚合状态（形态同 m2_entry_platform_b2._finish，
    与 contracts.validate_method_subresults 一致性同构）。"""
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


def _static_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "static_scan", status, "executor_static_scan_observation", **evidence
    )


def _schema_row(status: str, **evidence: Any) -> dict[str, Any]:
    return _method_row(
        "schema_validation", status, "executor_schema_validation_observation", **evidence
    )


def _h004_target_path(ctx: dict[str, Any], relative: str) -> Path:
    return Path(ctx["target"]).joinpath(*Path(relative).parts)


def _h004_read_json(ctx: dict[str, Any], relative: str) -> dict[str, Any] | None:
    """读目标根相对 JSON 文件；缺失返回 None；符号链接/不可读/解析失败失败关闭。"""
    path = _h004_target_path(ctx, relative)
    if path.is_symlink():
        raise ExecutorEvidenceError(
            "TARGET_FILE_UNREADABLE", f"目标文件不得是符号链接: {relative}"
        )
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(
            "TARGET_FILE_INVALID", f"目标文件无法解析: {relative}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "TARGET_FILE_INVALID", f"目标 JSON 顶层必须是对象: {relative}"
        )
    return value


def _h004_read_text(ctx: dict[str, Any], relative: str) -> str | None:
    """读目标根相对文本文件；缺失返回 None；符号链接/不可读失败关闭。"""
    path = _h004_target_path(ctx, relative)
    if path.is_symlink():
        raise ExecutorEvidenceError(
            "TARGET_FILE_UNREADABLE", f"目标文件不得是符号链接: {relative}"
        )
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExecutorEvidenceError(
            "TARGET_FILE_UNREADABLE", f"{relative}: {exc}"
        ) from exc


def _h004_gate_schema_errors(doc: Any) -> list[str]:
    """governance-gate-run-evidence schema 的 $id/const/required 键集锚点核验。"""
    if not isinstance(doc, dict):
        return ["gate_schema_not_object"]
    errors = []
    if doc.get("$id") != _H004_GATE_SCHEMA_ID:
        errors.append("gate_schema_id_drift")
    if doc.get("required") != list(_H004_GATE_REQUIRED):
        errors.append("gate_schema_required_drift")
    properties = doc.get("properties")
    if not isinstance(properties, dict):
        return errors + ["gate_schema_properties_missing"]
    kind = properties.get("kind")
    rule = properties.get("ruleId")
    binding = properties.get("binding")
    gates = properties.get("gates")
    if not isinstance(kind, dict) or kind.get("const") != _H004_GATE_KIND_CONST:
        errors.append("gate_kind_const_drift")
    if not isinstance(rule, dict) or rule.get("const") != _H004_GATE_RULE_ID_CONST:
        errors.append("gate_rule_id_const_drift")
    if not isinstance(binding, dict) or binding.get("required") != list(
        _H004_GATE_BINDING_KEYS
    ):
        errors.append("gate_binding_keys_drift")
    gate_items = gates.get("items") if isinstance(gates, dict) else None
    if not isinstance(gate_items, dict) or gate_items.get("required") != list(
        _H004_GATE_OBSERVATION_KEYS
    ):
        errors.append("gate_observation_keys_drift")
    return errors


def _h004_semantic_schema_errors(doc: Any) -> list[str]:
    """semantic-review-result schema 的 $id/const/required 键集锚点核验。"""
    if not isinstance(doc, dict):
        return ["semantic_schema_not_object"]
    errors = []
    if doc.get("$id") != _H004_SEMANTIC_SCHEMA_ID:
        errors.append("semantic_schema_id_drift")
    defs = doc.get("$defs")
    if not isinstance(defs, dict):
        return errors + ["semantic_defs_missing"]
    for key in ("internalReviewV2", "internalRuleReview", "evidenceRef"):
        if key not in defs:
            errors.append(f"semantic_def_missing:{key}")
    v2 = defs.get("internalReviewV2")
    if not isinstance(v2, dict):
        errors.append("semantic_v2_missing")
    else:
        v2props = v2.get("properties")
        if not isinstance(v2props, dict):
            errors.append("semantic_v2_properties_missing")
        else:
            for prop, expected in (
                ("kind", _H004_SEMANTIC_KIND_CONST),
                ("producer_method_id", _H004_SEMANTIC_PRODUCER_CONST),
            ):
                entry = v2props.get(prop)
                if not isinstance(entry, dict) or entry.get("const") != expected:
                    errors.append(f"semantic_{prop}_const_drift")
            independence = v2props.get("cognitive_independence")
            if (
                not isinstance(independence, dict)
                or independence.get("const") != "not_attested"
            ):
                errors.append("semantic_cognitive_independence_const_drift")
        if v2.get("required") != list(_H004_SEMANTIC_REQUIRED):
            errors.append("semantic_v2_required_drift")
    ref = defs.get("evidenceRef")
    if not isinstance(ref, dict):
        errors.append("semantic_evidence_ref_missing")
    else:
        refprops = ref.get("properties")
        if not isinstance(refprops, dict) or set(refprops) != set(_H004_EVIDENCE_REF_KEYS):
            errors.append("semantic_evidence_ref_keys_drift")
    return errors


def _h004_role_public_input_contract(
    ctx: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """角色①公开输入合同材料核验；返回 (verdict, evidence)。

    verdict ∈ {"ok", "missing", "invalid"}。既有文件存在但解析失败按家族先例
    失败关闭（抛 ExecutorEvidenceError）；解析成功但锚点/注册表/发布副本/声明
    不符以 invalid 返回（不实引用口径）。
    """
    gate_rel = "spec/contracts/governance-gate-run-evidence.schema.json"
    semantic_rel = "spec/contracts/semantic-review-result.schema.json"
    registry_rel = "spec/contracts/package.json"
    missing: list[str] = []
    invalid: list[dict[str, Any]] = []
    gate_doc = _h004_read_json(ctx, gate_rel)
    semantic_doc = _h004_read_json(ctx, semantic_rel)
    if gate_doc is None:
        missing.append(gate_rel)
    else:
        errors = _h004_gate_schema_errors(gate_doc)
        if errors:
            invalid.append({"material": gate_rel, "anchor_errors": errors})
    if semantic_doc is None:
        missing.append(semantic_rel)
    else:
        errors = _h004_semantic_schema_errors(semantic_doc)
        if errors:
            invalid.append({"material": semantic_rel, "anchor_errors": errors})
    registry = _h004_read_json(ctx, registry_rel)
    if registry is None:
        missing.append(registry_rel)
    else:
        schemas = registry.get("consumerSchemas")
        if not isinstance(schemas, list):
            invalid.append({
                "material": registry_rel,
                "anchor_errors": ["consumer_schemas_not_a_list"],
            })
        else:
            absent = [name for name in _H004_CONSUMER_SCHEMAS if name not in schemas]
            if absent:
                missing.extend(
                    f"{registry_rel} consumerSchemas:{name}" for name in absent
                )
    platform_missing: list[str] = []
    platform_drift: list[str] = []
    for platform in _H004_REQUIRED_PLATFORMS:
        for subdir, filename in _H004_CONTRACT_REL_PATHS:
            rel = f"generated/platforms/{platform}/{subdir}/{filename}"
            copy = _h004_read_json(ctx, rel)
            source = gate_doc if filename == "governance-gate-run-evidence.schema.json" else semantic_doc
            if copy is None:
                platform_missing.append(rel)
            elif source is not None and copy != source:
                platform_drift.append(rel)
    missing.extend(platform_missing)
    if platform_drift:
        invalid.append({
            "material": "generated/platforms/*",
            "anchor_errors": [
                f"platform_copy_drift:{rel}" for rel in platform_drift
            ],
        })
    skill_text = _h004_read_text(ctx, _H004_SKILL_MD_REL)
    if skill_text is None:
        missing.append(_H004_SKILL_MD_REL)
    elif "--evidence-set" not in skill_text or "SHA-256" not in skill_text:
        invalid.append({
            "material": _H004_SKILL_MD_REL,
            "anchor_errors": ["evidence_set_declaration_anchor_missing"],
        })
    if invalid:
        return "invalid", {"reason": "public_input_contract_reference_invalid",
                           "invalid": invalid}
    if missing:
        return "missing", {"reason": "public_input_contract_missing",
                           "missing": missing}
    return "ok", {
        "reason": "public_input_contract_valid",
        "schema_files_checked": 2,
        "platforms_checked": len(_H004_REQUIRED_PLATFORMS),
        "consumer_schema_registry": list(_H004_CONSUMER_SCHEMAS),
    }


def _h004_role_consumer_implementation(
    ctx: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """角色②实际消费实现源码锚点核验（只读文本级，不执行目标代码）。"""
    missing: list[str] = []
    invalid: list[dict[str, Any]] = []
    for relative, anchors in _H004_CONSUMER_ANCHORS:
        text = _h004_read_text(ctx, relative)
        if text is None:
            missing.append(relative)
            continue
        absent = [anchor for anchor in anchors if anchor not in text]
        if absent:
            invalid.append({
                "material": relative,
                "missing_anchors": absent,
            })
    if invalid:
        return "invalid", {"reason": "consumer_implementation_anchor_missing",
                           "invalid": invalid}
    if missing:
        return "missing", {"reason": "consumer_implementation_missing",
                           "missing": missing}
    return "ok", {
        "reason": "consumer_implementation_anchors_present",
        "materials_checked": len(_H004_CONSUMER_ANCHORS),
    }


def _h004_current_version(ctx: dict[str, Any]) -> str | None:
    """目标当前版本：沿 .skill-family-audit/governance/version-authority.json 的
    unique_truth_source 声明读取版本载体文件（缺省语义同 PKG 实测）。"""
    authority_path = (
        Path(ctx["target"]) / ".skill-family-audit" / "governance"
        / "version-authority.json"
    )
    if authority_path.is_symlink():
        raise ExecutorEvidenceError(
            "TARGET_FILE_UNREADABLE", "version-authority.json 不得是符号链接"
        )
    if not authority_path.is_file():
        return None
    try:
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutorEvidenceError(
            "TARGET_FILE_INVALID", f"version-authority.json 无法解析: {exc}"
        ) from exc
    if not isinstance(authority, dict):
        return None
    source_name = authority.get("unique_truth_source")
    if not isinstance(source_name, str) or not source_name:
        return None
    source = _h004_read_json(ctx, source_name)
    if source is None:
        return None
    version = source.get("version")
    return version if isinstance(version, str) and version else None


def _h004_role_version_bound_review_record(
    ctx: dict[str, Any], document: dict[str, Any] | None
) -> tuple[str, dict[str, Any]]:
    """角色③既有审阅记录引用核验；引用必须可回读闭合（存在+sha256+版本绑定）。"""
    if not isinstance(document, dict):
        return "missing", {"reason": "version_bound_review_record_missing",
                           "detail": "harness-interfaces 未声明"}
    record = document.get(_H004_REVIEW_RECORD_KEY)
    if record is None:
        return "missing", {"reason": "version_bound_review_record_missing",
                           "detail": "harness-interfaces 无该键"}
    if not isinstance(record, dict):
        return "missing", {"reason": "review_record_reference_incomplete",
                           "detail": "记录引用必须是对象"}
    file_value = record.get("file")
    sha_value = record.get("sha256")
    if (
        not isinstance(file_value, str)
        or not file_value
        or file_value.startswith("/")
    ):
        return "missing", {"reason": "review_record_reference_incomplete",
                           "detail": "file 引用缺失、非字符串或为绝对路径"}
    if not is_hex64(sha_value):
        return "missing", {"reason": "review_record_reference_incomplete",
                           "detail": "sha256 缺失或非法"}
    record_path = Path(ctx["target"]).joinpath(*Path(file_value).parts)
    try:
        record_path.resolve().relative_to(Path(ctx["target"]).resolve())
    except ValueError:
        return "invalid", {"reason": "review_record_file_unreadable",
                           "detail": "记录引用越出目标根"}
    if record_path.is_symlink() or not record_path.is_file():
        return "invalid", {"reason": "review_record_file_unreadable",
                           "detail": "记录文件不存在或为符号链接"}
    try:
        raw = record_path.read_bytes()
    except OSError as exc:
        return "invalid", {"reason": "review_record_file_unreadable",
                           "detail": str(exc)}
    import hashlib
    if hashlib.sha256(raw).hexdigest() != sha_value:
        return "invalid", {"reason": "review_record_digest_mismatch",
                           "detail": "实读摘要与声明不符"}
    try:
        content = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "invalid", {"reason": "review_record_content_invalid",
                           "detail": "记录内容不是 JSON 对象"}
    if not isinstance(content, dict):
        return "invalid", {"reason": "review_record_content_invalid",
                           "detail": "记录内容不是 JSON 对象"}
    current_version = _h004_current_version(ctx)
    if current_version is None:
        return "missing", {"reason": "current_version_undeterminable",
                           "detail": "目标当前版本权威链不可得"}
    if content.get("target_version") != current_version:
        return "invalid", {"reason": "review_record_version_mismatch",
                           "current_version": current_version}
    missing_fields = [
        field for field in _H004_RECORD_CONTENT_FIELDS[1:]
        if not content.get(field)
    ]
    if missing_fields:
        return "missing", {"reason": "review_record_fields_incomplete",
                           "missing_fields": missing_fields}
    return "ok", {
        "reason": "review_record_bound_to_current_version",
        "target_version": current_version,
        "record_file": file_value,
    }


def check_harness_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """只审计 Audit 产品自身的只读样例证据审阅能力（真实三角色核验）。

    目标身份必须由 ``target_scope`` 的 ``scope.plugin_project.plugin.id``
    确认。其他已确认产品不适用。Audit 目标按义务核验三角色：
    ① 公开输入合同（schema_validation 半区：spec/contracts 两份 schema 的
    $id/const/required 键集、四平台发布副本、consumerSchemas 注册表条目、
    SKILL.md evidence-set 参数声明锚点）；
    ② 实际消费实现（static_scan 半区：_load_evidence_set / _receipt_observation
    与 EVIDENCE_BUNDLE_KIND、METHOD_RECEIPT_KIND / _governance_gate_behavior
    的"不执行命令、不接受自填、摘要重算"合同锚点；只读文本级核验，不执行
    目标代码）；
    ③ 与该版本绑定的既有审阅记录（harness-interfaces 治理声明引用必须可回读
    闭合：文件真实存在、sha256 相符、版本与审阅对象/输入输出绑定字段核验）。
    缺失必要信息时如实报告缺证且 missing 只列真实缺失角色；清单存在不构成
    能力证明。旧的自填 ``sample_list_interface`` 与本次审阅宿主输入、执行行为
    均不构成目标能力证明。双机械方法分项行形态遵循 m2_entry_platform_b2
    双方法先例（executor_schema_validation_observation /
    executor_static_scan_observation）。
    """
    scope = ctx.get("scope")
    plugin_project = scope.get("plugin_project") if isinstance(scope, dict) else None
    plugin = plugin_project.get("plugin") if isinstance(plugin_project, dict) else None
    plugin_id = plugin.get("id") if isinstance(plugin, dict) else None
    if not isinstance(plugin_id, str) or not plugin_id:
        return _finish(
            [
                _schema_row(
                    "EVIDENCE_MISSING", reason="target_plugin_identity_unconfirmed"
                ),
                _static_row(
                    "EVIDENCE_MISSING", reason="target_plugin_identity_unconfirmed"
                ),
            ],
            reason="target_plugin_identity_unconfirmed",
            mechanical_half=True,
        )
    if plugin_id != "skill-family-audit":
        return _finish(
            [
                _schema_row(
                    "NOT_APPLICABLE",
                    reason="target_plugin_is_not_skill_family_audit",
                    target_plugin_id=plugin_id,
                ),
                _static_row(
                    "NOT_APPLICABLE",
                    reason="target_plugin_is_not_skill_family_audit",
                    target_plugin_id=plugin_id,
                ),
            ],
            reason="target_plugin_is_not_skill_family_audit",
            target_plugin_id=plugin_id,
            mechanical_half=True,
        )
    document = load_governance_document(ctx, "harness-interfaces")
    legacy_sample_list_present = (
        isinstance(document.get("sample_list_interface"), dict)
        if isinstance(document, dict)
        else False
    )
    role1, evidence1 = _h004_role_public_input_contract(ctx)
    role2, evidence2 = _h004_role_consumer_implementation(ctx)
    role3, evidence3 = _h004_role_version_bound_review_record(ctx, document)

    role_names = (
        "public_input_contract",
        "consumer_implementation",
        "version_bound_review_record",
    )
    role_verdicts = {
        role_names[0]: {"verdict": role1, **evidence1},
        role_names[1]: {"verdict": role2, **evidence2},
        role_names[2]: {"verdict": role3, **evidence3},
    }
    missing_roles = [
        name for name, entry in role_verdicts.items()
        if entry["verdict"] == "missing"
    ]
    invalid_roles = [
        name for name, entry in role_verdicts.items()
        if entry["verdict"] == "invalid"
    ]

    schema_status = {
        "ok": "PASS", "missing": "EVIDENCE_MISSING", "invalid": "FAIL",
    }[role1]
    static_failed = role2 == "invalid" or role3 == "invalid"
    static_missing = role2 == "missing" or role3 == "missing"
    if static_failed:
        static_status = "FAIL"
    elif static_missing:
        static_status = "EVIDENCE_MISSING"
    else:
        static_status = "PASS"
    rows = [
        _schema_row(schema_status, **evidence1),
        _static_row(
            static_status,
            consumer_implementation=role_verdicts["consumer_implementation"],
            version_bound_review_record=role_verdicts["version_bound_review_record"],
        ),
    ]
    evidence: dict[str, Any] = {
        "role_verdicts": role_verdicts,
        "legacy_sample_list_present": legacy_sample_list_present,
        "mechanical_half": True,
    }
    if invalid_roles:
        evidence["reason"] = role_verdicts[invalid_roles[0]].get(
            "reason", "audit_target_capability_reference_invalid"
        )
        evidence["invalid_roles"] = invalid_roles
    elif missing_roles:
        evidence["reason"] = "audit_target_capability_evidence_missing"
        evidence["missing"] = missing_roles
    return _finish(rows, **evidence)


def check_harness_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """初版必须提供版本化观察器绑定接口（六类声明字段）。

    机械断言：已声明 harness 必须携带版本化 observer_binding 接口且字段齐全。
    """
    document = load_governance_document(ctx, "harness-interfaces")
    if document is None:
        return result("PASS", harness_declared=False, mechanical_half=True)
    binding = document.get("observer_binding_interface")
    if not isinstance(binding, dict):
        return result("FAIL", reason="observer_binding_interface_missing", mechanical_half=True)
    required = {
        "version",
        "observer_provider",
        "protocol_version",
        "evidence_location",
        "event_categories",
        "health_decision_responsibility",
        "unavailability_handling",
    }
    missing = sorted(required - set(binding))
    if missing:
        return result("FAIL", observer_binding_fields_missing=missing, mechanical_half=True)
    return result("PASS", observer_binding_version=binding.get("version"), mechanical_half=True)


def check_harness_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """样例数量与重复次数必须按风险分级，不得全局固定数量替代覆盖。

    机械断言：已声明样例计划必须按规则风险分级；global_fixed_count=true
    或缺少分级即违反。
    """
    document = load_governance_document(ctx, "harness-interfaces")
    if document is None:
        return result("PASS", harness_declared=False, mechanical_half=True)
    plan = document.get("sample_plan")
    if not isinstance(plan, dict):
        return result("FAIL", reason="sample_plan_missing", mechanical_half=True)
    if plan.get("global_fixed_count") is True:
        return result("FAIL", reason="global_fixed_count_replaces_coverage", mechanical_half=True)
    tiers = rows_of({"tiers": plan.get("tiers")}, "tiers", "harness-interfaces.sample_plan")
    if not tiers:
        return result("FAIL", reason="risk_tiering_missing", mechanical_half=True)
    incomplete = [
        {"tier": row.get("tier_id")}
        for row in tiers
        if not row.get("risk_level") or row.get("sample_count") is None
    ]
    if incomplete:
        return result("FAIL", incomplete_tiers=incomplete, mechanical_half=True)
    return result("PASS", tiers=len(tiers), mechanical_half=True)


def _isolation_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "isolation-policy")


def check_isolation_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """安装钩子与目标业务执行均按不可信执行面处理；静态检查不豁免隔离。

    机械断言：已声明隔离政策 untrusted_surface 必须覆盖三类来源，且
    static_check_waives_isolation!=true。
    """
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    surface = policy.get("untrusted_surface") or []
    required = {"install_hooks", "dependency_scripts", "target_business_execution"}
    missing = sorted(required - set(surface)) if isinstance(surface, list) else sorted(required)
    violations = []
    if missing:
        violations.append({"reason": "untrusted_surface_incomplete", "missing": missing})
    if policy.get("static_check_waives_isolation") is True:
        violations.append({"reason": "static_check_waives_isolation"})
    if violations:
        return result("FAIL", isolation_surface_violations=violations, mechanical_half=True)
    return result("PASS", untrusted_surface=sorted(surface), mechanical_half=True)


def _isolation_dimension(policy: dict[str, Any], dimension: str) -> dict[str, Any] | None:
    dimensions = policy.get("dimensions")
    if not isinstance(dimensions, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "isolation-policy.dimensions 必须是对象"
        )
    value = dimensions.get(dimension)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            f"isolation-policy.dimensions.{dimension} 必须是对象",
        )
    return value


def check_isolation_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """隔离环境必须具有可证明身份、与其他运行隔离且可销毁。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    env = _isolation_dimension(policy, "run_environment")
    if env is None:
        return result("FAIL", reason="run_environment_dimension_missing", mechanical_half=True)
    violations = [
        field
        for field in ("unique_identity", "isolated_from_other_runs", "destructible")
        if env.get(field) is not True
    ]
    if not is_hex64(env.get("identity_proof_digest")):
        violations.append("identity_proof_digest_invalid")
    if violations:
        return result("FAIL", run_environment_defects=violations, mechanical_half=True)
    return result("PASS", run_environment="verifiable_isolated_destructible", mechanical_half=True)


def check_isolation_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """隔离执行不得继承宿主长期凭据。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    dimension = _isolation_dimension(policy, "credential_inheritance")
    if dimension is None:
        return result("FAIL", reason="credential_inheritance_dimension_missing", mechanical_half=True)
    if dimension.get("inherits_host_long_term_credentials") is not False:
        return result("FAIL", reason="host_long_term_credentials_inherited", mechanical_half=True)
    return result("PASS", host_credential_inheritance=False, mechanical_half=True)


def check_isolation_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """确需凭据时只注入最小短时测试凭据并记录引用和用途。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    dimension = _isolation_dimension(policy, "credentials")
    if dimension is None:
        return result("PASS", credentials_declared=False, mechanical_half=True)
    rows = dimension.get("injected") or []
    if not isinstance(rows, list) or not all(isinstance(item, dict) for item in rows):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "isolation-policy.credentials.injected 必须是对象数组"
        )
    violations = []
    for index, row in enumerate(rows):
        if (
            row.get("task_authorized") is not True
            or row.get("minimal_scope") is not True
            or row.get("short_lived") is not True
            or row.get("revocable") is not True
            or not row.get("reference")
            or not row.get("purpose")
        ):
            violations.append({"index": index, "credential": row.get("reference")})
    if violations:
        return result("FAIL", credentials_outside_policy=violations, mechanical_half=True)
    return result("PASS", injected_credentials=len(rows), mechanical_half=True)


def check_isolation_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """隔离网络默认拒绝并按端点白名单开放，独立记录实际连接。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    network = _isolation_dimension(policy, "network")
    if network is None:
        return result("FAIL", reason="network_dimension_missing", mechanical_half=True)
    violations = []
    if network.get("default_deny") is not True:
        violations.append("default_deny_missing")
    whitelist = network.get("whitelist") or []
    if not isinstance(whitelist, list):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "isolation-policy.network.whitelist 必须是数组"
        )
    for entry in whitelist:
        if not isinstance(entry, dict) or not entry.get("endpoint") or not entry.get("task_approval"):
            violations.append("whitelist_entry_unapproved")
    if network.get("independent_connection_log") is not True:
        violations.append("connection_log_missing")
    if violations:
        return result("FAIL", network_policy_defects=violations, mechanical_half=True)
    return result("PASS", network="default_deny_whitelisted_logged", mechanical_half=True)


def check_isolation_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """隔离输入只读，只有声明输出可写。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    mounts = _isolation_dimension(policy, "mounts")
    if mounts is None:
        return result("FAIL", reason="mounts_dimension_missing", mechanical_half=True)
    violations = []
    if mounts.get("inputs_readonly") is not True:
        violations.append("inputs_not_readonly")
    writable = mounts.get("writable_outputs") or []
    if not isinstance(writable, list) or not all(isinstance(item, str) and item for item in writable):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID",
            "isolation-policy.mounts.writable_outputs 必须是非空字符串数组",
        )
    if mounts.get("undeclared_paths_writable") is True:
        violations.append("undeclared_writable_paths")
    if violations:
        return result("FAIL", mount_policy_defects=violations, mechanical_half=True)
    return result("PASS", writable_outputs=writable, mechanical_half=True)


def check_isolation_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """隔离运行必须限制资源并可终止整个进程树。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    limits = _isolation_dimension(policy, "limits")
    if limits is None:
        return result("FAIL", reason="limits_dimension_missing", mechanical_half=True)
    required = (
        "process_tree",
        "time",
        "memory",
        "file_count",
        "storage",
        "unpack_expansion",
    )
    missing = [field for field in required if not isinstance(limits.get(field), (int, str)) or limits.get(field) in ("", None)]
    if limits.get("killable_process_tree") is not True:
        missing.append("killable_process_tree")
    if missing:
        return result("FAIL", limits_missing=missing, mechanical_half=True)
    return result("PASS", limits_declared=sorted(required), mechanical_half=True)


def check_isolation_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """必需隔离维度无法证明时行为检查必须受阻，不得降级告警。"""
    policy = _isolation_policy(ctx)
    if policy is None:
        return result("PASS", isolation_declared=False, mechanical_half=True)
    applicable = policy.get("applicable_dimensions") or list(ISOLATION_DIMENSIONS)
    if not isinstance(applicable, list) or not set(applicable) <= set(ISOLATION_DIMENSIONS):
        raise ExecutorEvidenceError(
            "GOVERNANCE_DOCUMENT_INVALID", "isolation-policy.applicable_dimensions 非法"
        )
    unproven = [
        dimension
        for dimension in applicable
        if _isolation_dimension(policy, dimension) is None
        or _isolation_dimension(policy, dimension).get("proven") is False
    ]
    if not unproven:
        return result("PASS", applicable_dimensions=applicable, mechanical_half=True)
    if policy.get("behavior_verification_state") != "blocked" or policy.get(
        "downgraded_to_warning"
    ) is True:
        return result(
            "FAIL", unproven_dimensions=unproven, behavior_state=policy.get("behavior_verification_state"), mechanical_half=True
        )
    return result("PASS", unproven_dimensions=unproven, behavior_state="blocked", mechanical_half=True)


def _selfheal_policy(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "selfheal-policy")


def check_selfheal_001(ctx: dict[str, Any]) -> dict[str, Any]:
    """自愈政策必须预先声明动作、重试、返工、预算、终止与升级条件。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    missing = [field for field in SELFHEAL_POLICY_FIELDS if field not in policy]
    if missing:
        return result("FAIL", policy_fields_missing=missing, mechanical_half=True)
    return result("PASS", policy_fields=list(SELFHEAL_POLICY_FIELDS), mechanical_half=True)


def _selfheal_actions(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return rows_of(policy, "recovery_actions", "selfheal-policy")


def check_selfheal_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """每次自动恢复必须同时满足预先声明的政策与本次用户授权。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    violations = [
        {"action": row.get("action_id")}
        for row in _selfheal_actions(policy)
        if not row.get("policy_clause")
        or row.get("task_authorization") is not True
        or row.get("generic_product_declaration_suffices") is True
    ]
    if violations:
        return result("FAIL", recoveries_without_authorization=violations, mechanical_half=True)
    return result("PASS", recovery_actions_bound=True, mechanical_half=True)


def check_selfheal_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得增加、替换或重新解释用户目标。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    violations = [
        {"action": row.get("action_id")}
        for row in _selfheal_actions(policy)
        if row.get("modifies_goal") is True or row.get("reinterprets_goal") is True
    ]
    if violations:
        return result("FAIL", goal_modifying_recoveries=violations, mechanical_half=True)
    return result("PASS", goal_preserved=True, mechanical_half=True)


def check_selfheal_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得取得原任务授权之外的权限。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    violations = [
        {"action": row.get("action_id")}
        for row in _selfheal_actions(policy)
        if row.get("acquires_extra_tools") is True
        or row.get("acquires_credentials") is True
        or row.get("acquires_system_privileges") is True
        or row.get("acquires_external_service_capabilities") is True
    ]
    if violations:
        return result("FAIL", privilege_expanding_recoveries=violations, mechanical_half=True)
    return result("PASS", privilege_boundary_held=True, mechanical_half=True)


def check_selfheal_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得向原任务未声明的对象写入。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    declared_writes = [
        path
        for path in (policy.get("original_write_set") or [])
        if isinstance(path, str) and path
    ]

    def _within_declared(path: str) -> bool:
        if path in declared_writes:
            return True
        parts = Path(path).parts
        for declared in declared_writes:
            declared_parts = Path(declared).parts
            if parts[: len(declared_parts)] == declared_parts:
                return True
        return False

    violations = []
    for row in _selfheal_actions(policy):
        for path in row.get("writes") or []:
            if not isinstance(path, str) or not _within_declared(path):
                violations.append({"action": row.get("action_id"), "path": path})
    if violations:
        return result("FAIL", recovery_writes_outside_declared_set=violations, mechanical_half=True)
    return result("PASS", recovery_write_closure_ok=True, mechanical_half=True)


def check_selfheal_006(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得超过已批准的资源预算。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    budget = policy.get("resource_budget")
    if not isinstance(budget, dict):
        return result("FAIL", reason="resource_budget_missing", mechanical_half=True)
    violations = []
    for row in _selfheal_actions(policy):
        usage = row.get("resource_usage") or {}
        if not isinstance(usage, dict):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "selfheal-policy.recovery_actions.resource_usage 必须是对象"
            )
        for key, used in usage.items():
            limit = budget.get(key)
            if isinstance(used, (int, float)) and isinstance(limit, (int, float)) and used > limit:
                violations.append({"action": row.get("action_id"), "resource": key})
    if violations:
        return result("FAIL", budget_exceeding_recoveries=violations, mechanical_half=True)
    return result("PASS", budget_keys=sorted(budget), mechanical_half=True)


def check_selfheal_007(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得新增原任务未授权的外部影响。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    authorized = set(policy.get("authorized_external_effects") or [])
    violations = []
    for row in _selfheal_actions(policy):
        for effect in row.get("external_effects") or []:
            if not isinstance(effect, str) or effect not in authorized:
                violations.append({"action": row.get("action_id"), "effect": effect})
    if violations:
        return result("FAIL", unauthorized_external_effects=violations, mechanical_half=True)
    return result("PASS", authorized_external_effects=sorted(authorized), mechanical_half=True)


def check_selfheal_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得放宽验收把失败重新标记为成功。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    violations = [
        {"action": row.get("action_id")}
        for row in _selfheal_actions(policy)
        if row.get("modifies_acceptance") is True
        or row.get("lowers_quality_gates") is True
        or row.get("relabels_failure_as_success") is True
    ]
    if violations:
        return result("FAIL", acceptance_lowering_recoveries=violations, mechanical_half=True)
    return result("PASS", acceptance_immutable=True, mechanical_half=True)


def check_selfheal_009(ctx: dict[str, Any]) -> dict[str, Any]:
    """自动恢复不得擅自改变业务语义。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    violations = [
        {"action": row.get("action_id")}
        for row in _selfheal_actions(policy)
        if row.get("replaces_algorithm") is True
        or row.get("narrows_output_scope") is True
        or row.get("changes_state_meaning") is True
        or row.get("adopts_unapproved_degradation") is True
    ]
    if violations:
        return result("FAIL", business_semantics_changed=violations, mechanical_half=True)
    return result("PASS", business_semantics_preserved=True, mechanical_half=True)


def check_selfheal_012(ctx: dict[str, Any]) -> dict[str, Any]:
    """超限或复验失败必须停止、写检查点并报告受阻。"""
    policy = _selfheal_policy(ctx)
    if policy is None:
        return result("PASS", selfheal_declared=False, mechanical_half=True)
    violations = []
    if policy.get("infinite_retry_allowed") is True:
        violations.append("infinite_retry_allowed")
    if policy.get("fabricate_success_on_limit") is True:
        violations.append("fabricate_success_on_limit")
    for row in _selfheal_actions(policy):
        exceeded = (
            row.get("authorization_exceeded") is True
            or row.get("budget_exceeded") is True
            or row.get("reverification_failed") is True
        )
        if exceeded and (
            row.get("stops") is not True
            or not row.get("checkpoint_ref")
            or row.get("reports_blocked") is not True
        ):
            violations.append({"action": row.get("action_id"), "reason": "limit_exceeded_without_stop"})
    if violations:
        return result("FAIL", limit_handling_invalid=violations, mechanical_half=True)
    return result("PASS", limit_handling="stop_checkpoint_blocked", mechanical_half=True)


def _stage_isolation(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "stage-isolation")


def check_stageiso_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """必须隔离能力缺失时工序受阻，不得报告降级成功。"""
    document = _stage_isolation(ctx)
    if document is None:
        return result("PASS", stage_isolation_declared=False, mechanical_half=True)
    violations = []
    for row in rows_of(document, "stages", "stage-isolation"):
        if row.get("isolation_required") is not True:
            continue
        unsatisfied = row.get("unsatisfied_dimensions") or []
        if not isinstance(unsatisfied, list):
            raise ExecutorEvidenceError(
                "GOVERNANCE_DOCUMENT_INVALID", "stage-isolation.stages.unsatisfied_dimensions 必须是数组"
            )
        if unsatisfied and (
            row.get("state") != "blocked" or row.get("reports_degraded_success") is True
        ):
            violations.append({"stage": row.get("stage_id"), "unsatisfied": unsatisfied})
    if violations:
        return result("FAIL", unsatisfied_isolation_not_blocked=violations, mechanical_half=True)
    return result("PASS", stages_checked=True, mechanical_half=True)


def check_stageiso_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """必须隔离工序不得静默回退入口主会话或共享高权限进程。"""
    document = _stage_isolation(ctx)
    if document is None:
        return result("PASS", stage_isolation_declared=False, mechanical_half=True)
    violations = [
        {"stage": row.get("stage_id"), "fallback": row.get("fallback")}
        for row in rows_of(document, "stages", "stage-isolation")
        if row.get("isolation_required") is True
        and row.get("fallback") in {"entry_main_session", "shared_high_privilege_process"}
    ]
    if violations:
        return result("FAIL", silent_isolation_fallbacks=violations, mechanical_half=True)
    return result("PASS", stages_checked=True, mechanical_half=True)


def _tier1_runtime(ctx: dict[str, Any]) -> dict[str, Any] | None:
    return load_governance_document(ctx, "tier1-runtime")


def check_tier1_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """第一档检查必须对受检目标只读，不得自动修复目标换取通过。"""
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", tier1_declared=False, mechanical_half=True)
    violations = []
    if document.get("target_readonly") is not True:
        violations.append("target_not_readonly")
    if document.get("auto_fix_target_to_pass") is True:
        violations.append("auto_fix_target_to_pass")
    remediation = document.get("remediation_route")
    if document.get("auto_fix_target_to_pass") is True and not isinstance(remediation, dict):
        violations.append("remediation_route_missing")
    elif isinstance(remediation, dict) and (
        remediation.get("independent") is not True or remediation.get("authorized") is not True
    ):
        violations.append("remediation_route_not_independent_authorized")
    if violations:
        return result("FAIL", tier1_readonly_violations=violations, mechanical_half=True)
    return result("PASS", target_readonly=True, mechanical_half=True)


def check_tier1_010(ctx: dict[str, Any]) -> dict[str, Any]:
    """缺少平台真实运行时，该平台与四平台联合第一档不得报告通过。"""
    document = _tier1_runtime(ctx)
    if document is None:
        return result("PASS", tier1_declared=False, mechanical_half=True)
    platforms = rows_of(document, "platforms", "tier1-runtime")
    violations = []
    joint_pass_claimed = document.get("joint_first_tier_pass") is True
    unavailable = []
    for row in platforms:
        runtime_present = row.get("runtime_present") is True
        if not runtime_present:
            unavailable.append(row.get("platform"))
            if row.get("tier1_pass") is True:
                violations.append({"platform": row.get("platform"), "reason": "pass_without_runtime"})
    if joint_pass_claimed and unavailable:
        violations.append({"joint": True, "unavailable": unavailable})
    if violations:
        return result("FAIL", tier1_pass_without_runtime=violations, mechanical_half=True)
    return result(
        "PASS",
        platforms_checked=len(platforms),
        unavailable_platforms=unavailable,
        mechanical_half=True,
    )


CHECKS = {
    "SFA-CONTEXT-002": check_context_002,
    "SFA-CONTEXT-004": check_context_004,
    "SFA-CONTEXT-018": check_context_018,
    "SFA-HARNESS-003": check_harness_003,
    "SFA-HARNESS-004": check_harness_004,
    "SFA-HARNESS-005": check_harness_005,
    "SFA-HARNESS-007": check_harness_007,
    "SFA-ISOLATION-001": check_isolation_001,
    "SFA-ISOLATION-002": check_isolation_002,
    "SFA-ISOLATION-003": check_isolation_003,
    "SFA-ISOLATION-004": check_isolation_004,
    "SFA-ISOLATION-005": check_isolation_005,
    "SFA-ISOLATION-006": check_isolation_006,
    "SFA-ISOLATION-007": check_isolation_007,
    "SFA-ISOLATION-009": check_isolation_009,
    "SFA-SELFHEAL-001": check_selfheal_001,
    "SFA-SELFHEAL-002": check_selfheal_002,
    "SFA-SELFHEAL-003": check_selfheal_003,
    "SFA-SELFHEAL-004": check_selfheal_004,
    "SFA-SELFHEAL-005": check_selfheal_005,
    "SFA-SELFHEAL-006": check_selfheal_006,
    "SFA-SELFHEAL-007": check_selfheal_007,
    "SFA-SELFHEAL-008": check_selfheal_008,
    "SFA-SELFHEAL-009": check_selfheal_009,
    "SFA-SELFHEAL-012": check_selfheal_012,
    "SFA-STAGEISO-002": check_stageiso_002,
    "SFA-STAGEISO-003": check_stageiso_003,
    "SFA-TIER1-008": check_tier1_008,
    "SFA-TIER1-010": check_tier1_010,
}
