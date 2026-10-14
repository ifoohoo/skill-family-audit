#!/usr/bin/env python3
"""Assess ordinary Audit results and static platform projections for release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


STATUSES = {
    "valid",
    "missing",
    "stale",
    "failed",
    "blocked",
    "exception_pass",
    "not_applicable",
}
PLATFORMS = {"claude-code", "codex", "kimi-code", "workbuddy"}
REQUIRED = {
    "conformance",
    "platforms",
    "exceptions",
    "release_policy",
}
ASSESSMENT_DOCUMENT_FIELDS = REQUIRED | {"release_class", "candidate_id"}
METHOD_IDENTITIES = {
    "conformance": "skill-family-audit:conformance-audit",
}
ACCEPTABLE_STATUSES = {"valid", "exception_pass", "not_applicable"}
# 缺项指引：只使用已存在的公开入口；统一专业协议不可用时明确能力缺口。
ENTRY_GUIDANCE = {
    "conformance": (
        "适用入口 skill-family-audit:conformance-audit（也可经 skill-family-audit:quickstart "
        "绑定证据后调用），按当前候选重新生成 conformance 结论；若原 conformance 结论报告适用专业项缺证，"
        "接续 foundation-adoption-review:foundation-engineering-check 取得或读取已有证明，再由 conformance 消费；"
        "本方法只消费结论，不重跑审计"
    ),
    "platform": (
        "请提供目标技能族当前候选的平台原始清单及文件摘要、平台身份和候选绑定；"
        "原 conformance 覆盖已声明需要专业结论时，可接续 foundation-adoption-review:foundation-engineering-check "
        "取得或读取已有证明，再经 skill-family-audit:conformance-audit 消费；本方法不重新生成投影"
    ),
    "exceptions": (
        "请提供 Audit 自带 spec/policies/exception-policy.json 的通用例外政策及其当前摘要、类型和候选绑定；"
        "它不是目标例外声明，不用本仓零记录声明代替其他目标的事实"
    ),
    "release_policy": (
        "能力缺口：本方法只消费已激活的发布政策证据，当前没有公开专业入口可生成发布政策结论，"
        "待提供方证据接入"
    ),
}
ENTRY_GUIDANCE_FALLBACK = (
    "能力缺口：本方法只消费已有权威证据，当前没有公开专业入口可生成该类专业结论"
)
METHOD_FIELDS = {
    "conformance": {
        "conformance_result",
        "rule_findings",
        "evidence_list",
        "remediation_plan",
    },
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_POLICY_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|$)", re.DOTALL)
_RELEASE_POLICY_BINDING = "spec/policies/release-gate.json"


class AssessmentError(RuntimeError):
    """The release assessment input is incomplete or contradictory."""


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssessmentError("ASSESSMENTS_NOT_OBJECT")
    return value


def _expected_contract(name: str) -> tuple[str, str]:
    if name in METHOD_IDENTITIES:
        return "method-result", METHOD_IDENTITIES[name]
    if name.startswith("platform:"):
        platform = name.split(":", 1)[1]
        return "platform-manifest", f"skill-family-audit:platform:{platform}"
    if name == "exceptions":
        return "exception-policy", "skill-family-audit:exception-policy"
    if name == "release_policy":
        return "release-policy", "skill-family-audit:release-policy"
    raise AssessmentError(f"UNKNOWN_ASSESSMENT:{name}")


def _conformance_content_error(domain_result: dict[str, Any]) -> str | None:
    result = domain_result.get("conformance_result")
    if not isinstance(result, dict):
        return "conformance_result 缺失"
    status = result.get("status")
    if status not in {"SUCCEEDED", "FAILED", "BLOCKED", "PARTIAL"}:
        return f"conformance 状态非法: {status!r}"
    rule_results = result.get("rule_results")
    if status in {"SUCCEEDED", "FAILED", "PARTIAL"}:
        if not isinstance(rule_results, list):
            return "conformance rule_results 必须是数组"
        if status == "SUCCEEDED" and not rule_results:
            return "conformance SUCCEEDED 但 rule_results 为空"
        for index, entry in enumerate(rule_results):
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("rule_id"), str)
                or not entry["rule_id"]
            ):
                return f"rule_results[{index}] 缺少合法 rule_id"
            if not isinstance(entry.get("status"), str) or not entry["status"]:
                return f"rule_results[{index}] 缺少合法 status"
    if "rule_results" in result:
        projection_error = _canonical_projection_error(
            rule_results,
            domain_result.get("rule_findings"),
            result.get("coverage"),
        )
        if projection_error:
            return projection_error
    return None


def _canonical_row_identity(entry: dict[str, Any], index: int) -> tuple[str | None, str | None]:
    """返回 (canonical 身份, 错误)。无标记行的身份是 rule_id。"""
    lineage = entry.get("canonical_lineage")
    canonical_only = entry.get("canonical_only") is True
    if lineage is None and not canonical_only:
        rule_id = entry.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            return None, f"rule_results[{index}] 缺少合法 rule_id"
        return rule_id, None
    if lineage is not None:
        if not isinstance(lineage, dict):
            return None, f"rule_results[{index}] canonical_lineage 必须是对象"
        canonical_id = lineage.get("canonical_id")
    else:
        canonical_id = entry.get("canonical_id")
        if (
            entry.get("rule_id") != canonical_id
            or "baseline_rule_id" in entry
            or "baseline_revision_digest" in entry
        ):
            return None, f"rule_results[{index}] canonical_only 不得伪造基线身份"
    if not isinstance(canonical_id, str) or not canonical_id:
        return None, f"rule_results[{index}] 缺少 in-scope canonical 身份"
    return canonical_id, None


def _canonical_projection_error(
    rule_results: Any,
    rule_findings: Any,
    coverage: Any,
) -> str | None:
    """rule_results 是 in-scope canonical 投影；rule_findings 可以多出无标记诊断行。

    没有外部 in-scope 身份列表时，不凭空补缺行。coverage.in_scope_count
    存在时必须等于投影条数。全无标记且彼此相等的旧夹具仍按 rule_id 通过。
    任一行为已标记时，全部行都必须有 lineage 或明确 canonical_only。
    """
    if not isinstance(rule_results, list):
        return "conformance rule_results 必须是数组"
    if not isinstance(rule_findings, list):
        return "rule_findings 必须是数组"
    identities: list[str] = []
    marked_any = False
    unmarked_any = False
    for index, entry in enumerate(rule_results):
        if not isinstance(entry, dict):
            return f"rule_results[{index}] 缺少合法 rule_id"
        lineage = entry.get("canonical_lineage")
        canonical_only = entry.get("canonical_only") is True
        if lineage is not None or canonical_only:
            marked_any = True
        else:
            unmarked_any = True
        canonical_id, error = _canonical_row_identity(entry, index)
        if error:
            return error
        identities.append(canonical_id or "")
    if marked_any and unmarked_any:
        return "rule_results 混用已标记 canonical 行与无标记行"
    if len(identities) != len(set(identities)):
        return "rule_results 未恰好覆盖每条 in-scope canonical 一次"
    remaining = list(rule_findings)
    for entry in rule_results:
        try:
            remaining.remove(entry)
        except ValueError:
            return "rule_findings 未覆盖 rule_results 的 canonical 投影"
    for extra in remaining:
        if not isinstance(extra, dict):
            return "rule_findings 超集行必须是对象"
        if extra.get("canonical_lineage") is not None or extra.get("canonical_only") is True:
            return "rule_findings 超集行不得带 lineage 或 canonical_only"
    if isinstance(coverage, dict) and "in_scope_count" in coverage:
        if coverage.get("in_scope_count") != len(rule_results):
            return "rule_results 条数与 coverage.in_scope_count 不一致"
    return None


def _content_error(name: str, domain_result: dict[str, Any]) -> str | None:
    """校验 conformance 输出必然关系，不重新执行审计。"""
    if name == "conformance":
        return _conformance_content_error(domain_result)
    return None


def _method_error(name: str, document: dict[str, Any], status: str) -> str | None:
    state = document.get("state")
    outputs = document.get("outputs")
    domain_result = outputs.get("domainResult") if isinstance(outputs, dict) else None
    if state not in {"succeeded", "failed"} or not isinstance(domain_result, dict):
        return "Foundation Result 缺少领域结果或终态"
    if set(domain_result) != METHOD_FIELDS[name]:
        return "Audit 领域结果字段不完整"
    content_error = _content_error(name, domain_result)
    if content_error:
        return f"Audit 领域结果内容自相矛盾: {content_error}"
    if status == "valid" and state != "succeeded":
        return f"Foundation Result 终态为 {state}，不得声称 valid"
    if status in {"blocked", "failed"} and state == "succeeded":
        return f"Foundation Result 终态为 {state}，不得声称受阻或失败"
    return None


def _platform_error(
    platform: str,
    document: dict[str, Any],
    candidate_id: str,
) -> str | None:
    family_id, version = candidate_id.split(":", 1)
    # Foundation 0.22.0 的公开 host sourceAliases；只做平台身份薄适配。
    # codebuddy 与 workbuddy 是两个公开宿主身份，不能混同。
    source_aliases = {
        "claude-code": "claude", "openai-codex": "codex", "kimi": "kimi-code",
    }
    platform_id = document.get("platformId")
    if isinstance(platform_id, str):
        platform_id = source_aliases.get(platform_id, platform_id)
    if (
        document.get("familyId") != family_id
        or platform_id != source_aliases.get(platform, platform)
        or document.get("version") != version
    ):
        return "平台静态清单对象、版本或平台身份不符"
    return None


def _exception_policy_error(document: dict[str, Any]) -> str | None:
    """消费通用政策的实际形态，不认证发布目标的例外声明或记录有效性。"""
    required = {
        "exception_id", "target_object", "target_rule_id",
        "target_revision_digest", "scope", "treatment",
    }
    fields = document.get("requiredExceptionFields")
    constraints = document.get("exceptionConstraints")
    records = document.get("currentExceptions")
    if (
        document.get("policyId") != "exception-policy"
        or not isinstance(document.get("schemaVersion"), str)
        or not document["schemaVersion"]
        or document.get("status") not in {"candidate", "active"}
        or not isinstance(fields, list)
        or any(not isinstance(field, str) for field in fields)
        or len(fields) != len(required)
        or set(fields) != required
        or "statusLifecycle" in document
        or "statusTransitions" in document
        or not isinstance(constraints, list)
        or not constraints
        or not isinstance(records, list)
    ):
        return "不是通用例外政策的当前形态"
    for index, constraint in enumerate(constraints):
        if (
            not isinstance(constraint, dict)
            or not all(isinstance(constraint.get(key), str) and constraint[key].strip()
                       for key in ("constraintId", "rule"))
            or constraint.get("violationImpact") not in {"block", "error", "warning"}
        ):
            return f"例外政策 exceptionConstraints[{index}] 内容不完整"
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not all(
            isinstance(record.get(key), str) and record[key].strip() for key in required
        ):
            return f"例外政策 currentExceptions[{index}] 缺少对象、规则或处理事项"
    return None


def _semantic_error(
    name: str,
    document: dict[str, Any],
    status: str,
    candidate_id: str,
) -> str | None:
    if name in METHOD_IDENTITIES:
        return _method_error(name, document, status)
    if name.startswith("platform:"):
        return _platform_error(name.split(":", 1)[1], document, candidate_id)
    if name == "exceptions":
        return _exception_policy_error(document)
    if name == "release_policy":
        return None if document.get("status") == "active" else "发布政策未激活"
    return "未知证据类别"


def entry_guidance(name: str) -> str:
    """返回该类缺项实际适用的接入或检查入口；无公开入口时如实说明能力缺口。"""
    key = "platform" if name.startswith("platform:") else name
    return ENTRY_GUIDANCE.get(key, ENTRY_GUIDANCE_FALLBACK)


def _with_guidance(name: str, row: dict[str, Any]) -> dict[str, Any]:
    """缺项行在既有 reason 字段上补充适用入口；不改状态，不新增字段。"""
    if row["status"] in ACCEPTABLE_STATUSES:
        return row
    reason = str(row.get("reason", ""))
    guidance = entry_guidance(name)
    row["reason"] = f"{reason}；{guidance}" if reason else guidance
    return row


def check_evidence(name: str, value: Any, candidate_id: str) -> dict[str, Any]:
    return _with_guidance(name, _check_evidence_row(name, value, candidate_id))


def _release_policy_markdown_document(path: Path) -> dict[str, Any] | None:
    """接受已登记的 RP-001 形态：YAML 前言 status，正文绑定发布门 JSON。

    不要求绑定文件在活树中存在，也不把任意 Markdown 当成发布政策。
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    match = _RELEASE_POLICY_FRONT_MATTER.match(text)
    if match is None or _RELEASE_POLICY_BINDING not in text:
        return None
    status = None
    for line in match.group(1).splitlines():
        body = line.split("#", 1)[0].strip()
        if body.startswith("status:"):
            status = body.split(":", 1)[1].strip().strip("'\"")
            break
    if not status:
        return None
    return {"status": status}


def _check_evidence_row(name: str, value: Any, candidate_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "missing", "reason": f"{name} 未提供"}
    status = value.get("status")
    if status not in STATUSES:
        return {"status": "failed", "reason": f"{name} 状态非法"}
    result: dict[str, Any] = {"status": status, "reason": str(value.get("reason", ""))}
    if status not in {"valid", "exception_pass", "not_applicable"}:
        return result

    path_value = value.get("path")
    expected_digest = value.get("digest")
    expected_type, expected_identity = _expected_contract(name)
    if (
        not isinstance(path_value, str)
        or not isinstance(expected_digest, str)
        or value.get("evidence_type") != expected_type
        or value.get("identity") != expected_identity
        or value.get("candidate_id") != candidate_id
    ):
        return {"status": "missing", "reason": f"{name} 缺少路径、摘要、类型或候选绑定"}
    path = Path(path_value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        return {"status": "missing", "reason": f"{name} 证据文件缺失或路径不可信"}
    actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result.update({
        "path": str(path),
        "digest": actual_digest,
        "evidence_type": expected_type,
        "identity": expected_identity,
        "candidate_id": candidate_id,
    })
    if expected_digest != actual_digest:
        result.update({"status": "stale", "reason": f"{name} 摘要陈旧"})
        return result
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        if name == "release_policy":
            document = _release_policy_markdown_document(path)
            if document is None:
                result.update({"status": "failed", "reason": f"{name} 不是已登记的权威发布政策形态"})
                return result
        else:
            result.update({"status": "failed", "reason": f"{name} 证据不是 JSON"})
            return result
    if not isinstance(document, dict):
        result.update({"status": "failed", "reason": f"{name} 证据顶层不是对象"})
        return result
    semantic_error = _semantic_error(name, document, status, candidate_id)
    if semantic_error:
        result.update({"status": "failed", "reason": f"{name}: {semantic_error}"})
    return result


def assess(
    document: dict[str, Any],
    expected_candidate_id: str | None = None,
) -> dict[str, Any]:
    unknown_sections = sorted(set(document) - ASSESSMENT_DOCUMENT_FIELDS)
    if unknown_sections:
        raise AssessmentError(f"ASSESSMENTS_UNKNOWN:{unknown_sections}")
    missing_sections = sorted(REQUIRED - set(document))
    if missing_sections:
        raise AssessmentError(f"ASSESSMENTS_INCOMPLETE:{missing_sections}")
    release_class = document.get("release_class")
    if release_class not in {"candidate", "stable"}:
        raise AssessmentError("RELEASE_CLASS_INVALID")
    candidate_id = document.get("candidate_id")
    if (
        not isinstance(candidate_id, str)
        or ":" not in candidate_id
        or (expected_candidate_id is not None and candidate_id != expected_candidate_id)
    ):
        raise AssessmentError("CANDIDATE_IDENTITY_INVALID")
    if release_class == "stable" and candidate_id.split(":", 1)[1].endswith("-candidate"):
        raise AssessmentError("STABLE_RELEASE_REJECTS_CANDIDATE_VERSION")

    rows = {
        name: check_evidence(name, document[name], candidate_id)
        for name in ("conformance", "exceptions", "release_policy")
    }
    platforms = document["platforms"]
    if not isinstance(platforms, dict) or set(platforms) != PLATFORMS:
        raise AssessmentError("PLATFORM_SET_INCOMPLETE")
    rows["platforms"] = {
        platform: check_evidence(f"platform:{platform}", platforms[platform], candidate_id)
        for platform in sorted(PLATFORMS)
    }
    statuses = [
        *[row["status"] for name, row in rows.items() if name != "platforms"],
        *[row["status"] for row in rows["platforms"].values()],
    ]
    passed = all(status in ACCEPTABLE_STATUSES for status in statuses)
    if release_class == "stable":
        passed = passed and all(status == "valid" for status in statuses)
    return {
        "schema_version": "1.0.0",
        "release_class": release_class,
        "candidate_id": candidate_id,
        "execution_status": "SUCCEEDED" if passed else "BLOCKED",
        "assessments": rows,
        "source_results_reexecuted": False,
        "stable_policy_applied": release_class == "stable",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assessments", type=Path, required=True)
    parser.add_argument("--candidate-id")
    args = parser.parse_args()
    try:
        result = assess(load(args.assessments), args.candidate_id)
    except (AssessmentError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"execution_status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["execution_status"] == "SUCCEEDED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
