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
    "behavior",
    "runtime",
    "platforms",
    "exceptions",
    "release_policy",
}
METHOD_IDENTITIES = {
    "conformance": "skill-family-audit:conformance-audit",
    "behavior": "skill-family-audit:behavior-audit",
    "runtime": "skill-family-audit:runtime-audit",
}
METHOD_FIELDS = {
    "conformance": {
        "conformance_result",
        "rule_findings",
        "evidence_list",
        "remediation_plan",
    },
    "behavior": {
        "behavior_result",
        "execution_records",
        "evidence_list",
        "regression_record",
    },
    "runtime": {
        "runtime_result",
        "governance_findings",
        "evidence_list",
    },
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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
        return "non-waivable-policy", "skill-family-audit:non-waivable-policy"
    if name == "release_policy":
        return "release-policy", "skill-family-audit:release-policy"
    raise AssessmentError(f"UNKNOWN_ASSESSMENT:{name}")


def _conformance_content_error(domain_result: dict[str, Any]) -> str | None:
    result = domain_result.get("conformance_result")
    if not isinstance(result, dict):
        return "conformance_result 缺失"
    status = result.get("status")
    if status not in {"SUCCEEDED", "FAILED", "BLOCKED"}:
        return f"conformance 状态非法: {status!r}"
    rule_results = result.get("rule_results")
    if status in {"SUCCEEDED", "FAILED"}:
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
    if "rule_results" in result and domain_result.get("rule_findings") != rule_results:
        return "rule_findings 与 rule_results 不一致"
    return None


def _behavior_content_error(domain_result: dict[str, Any]) -> str | None:
    result = domain_result.get("behavior_result")
    if not isinstance(result, dict):
        return "behavior_result 缺失"
    status = result.get("overall_status")
    if status not in {"SUCCEEDED", "FAILED", "BLOCKED"}:
        return f"behavior 状态非法: {status!r}"
    records = domain_result.get("execution_records")
    if not isinstance(records, list):
        return "behavior execution_records 必须是数组"
    if status == "SUCCEEDED" and not records:
        return "behavior SUCCEEDED 但 execution_records 为空"
    for index, entry in enumerate(records):
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("fixture_id"), str)
            or not entry["fixture_id"]
        ):
            return f"execution_records[{index}] 缺少合法 fixture_id"
        if not isinstance(entry.get("status"), str) or not entry["status"]:
            return f"execution_records[{index}] 缺少合法 status"
    return None


def _runtime_content_error(domain_result: dict[str, Any]) -> str | None:
    result = domain_result.get("runtime_result")
    if not isinstance(result, dict):
        return "runtime_result 缺失"
    status = result.get("execution_status")
    if status not in {"SUCCEEDED", "BLOCKED", "FAILED"}:
        return f"runtime 状态非法: {status!r}"
    findings = domain_result.get("governance_findings")
    evidence_list = domain_result.get("evidence_list")
    if not isinstance(findings, list) or not isinstance(evidence_list, list):
        return "runtime governance_findings 或 evidence_list 必须是数组"
    if status == "SUCCEEDED":
        if findings:
            return "runtime SUCCEEDED 但 governance_findings 非空"
        if not evidence_list:
            return "runtime SUCCEEDED 但 evidence_list 为空"
    elif not findings:
        return f"runtime {status} 但 governance_findings 为空"
    return None


def _content_error(name: str, domain_result: dict[str, Any]) -> str | None:
    """内容级语义校验（FM-02 修复）。

    发布评估只校验方法输出契约可证明的必然关系，不重新计算任何审计（与
    SKILL.md 边界一致）。此前仅做字段集合检查，自我一致的伪造 Foundation
    Result（如 SUCCEEDED 却无任何规则结果）可通过；以下不变式均来自真实
    方法实现：

    - conformance：workflow 中 status 由 ``rules and not failed`` 决定，
      SUCCEEDED 必然执行过规则（rule_results 非空），且 rule_findings
      与 rule_results 同源；
    - behavior：plan.fixtures 非空且执行记录必须覆盖全部 fixture，
      SUCCEEDED 必然有非空 execution_records；
    - runtime：governance_findings 由错误列表派生，SUCCEEDED 必然无发现
      且 evidence_list 非空，非 SUCCEEDED 必然有发现。
    """
    if name == "conformance":
        return _conformance_content_error(domain_result)
    if name == "behavior":
        return _behavior_content_error(domain_result)
    if name == "runtime":
        return _runtime_content_error(domain_result)
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
    files = document.get("files")
    foundation = document.get("foundationProjection")
    if (
        document.get("familyId") != family_id
        or document.get("platformId") != platform
        or document.get("version") != version
        or not isinstance(files, list)
        or document.get("fileCount") != len(files)
        or not HEX64.fullmatch(str(document.get("sourceDigest", "")))
        or not HEX64.fullmatch(str(document.get("projectionDigest", "")))
        or not isinstance(foundation, dict)
        or foundation.get("path") != "foundation/quickstart-profile/foundation-projection.json"
        or not HEX64.fullmatch(str(foundation.get("bundleDigest", "")))
    ):
        return "平台静态清单身份、文件闭包或 Foundation provenance 非法"
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
        return None if document.get("status") in {"candidate", "active"} else "例外政策状态非法"
    if name == "release_policy":
        return None if document.get("status") == "active" else "发布政策未激活"
    return "未知证据类别"


def check_evidence(name: str, value: Any, candidate_id: str) -> dict[str, Any]:
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
        for name in ("conformance", "behavior", "runtime", "exceptions", "release_policy")
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
    acceptable = {"valid", "exception_pass", "not_applicable"}
    passed = all(status in acceptable for status in statuses)
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
