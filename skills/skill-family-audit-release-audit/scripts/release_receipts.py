"""Release Skill 上游公开验证器的薄消费适配层。

Audit 不复制 Release Skill 的计划/运行摘要、Schema 摘要、检查点、批准、
lineage 或状态判定逻辑，也不读取相邻 Release Skill 工作树。release-audit
只消费上游公开验证器（离线、只读、零网络、零写入）的结构化输出；上游公开
验证器尚未发布期间，空输入与任何调用方提供的对象或路径都不解释为上游
权威输出，确定性返回 BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE。
SFA-PUBLISH-017、SFA-PUBLISH-018 及其 receipt 成功路径保持关闭。
"""
from __future__ import annotations

from typing import Any

UPSTREAM_PROTOCOL_ID = "release-skill.public-release-verifier"
UPSTREAM_BLOCKED_CODE = "UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE"


def _closed_result(
    *,
    expected_unit_id: str,
    expected_target_version: str,
    provided: bool,
) -> dict[str, Any]:
    """上游验证器未发布时的确定性领域结果；不读取、不解释调用方输入。"""
    base = {
        "protocol_id": "skill-family-audit.release-receipt-audit",
        "protocol_version": "2.0.0",
        "upstream_protocol": UPSTREAM_PROTOCOL_ID,
        "candidate": {
            "unit_id": expected_unit_id,
            "target_version": expected_target_version,
        },
        "gate_findings": [],
        "blocking_reasons": [],
        "evidence": [],
    }
    if not expected_unit_id or not expected_target_version:
        base.update(
            status="FAILED",
            gate_findings=["候选 unit id 和 target version 必须为非空字符串"],
        )
        return base
    if provided:
        reason = (
            "Release Skill 尚未发布公开只读验证器，无法审计发布收据链；"
            "调用方提供的验证器输出不解释为上游权威输出"
        )
    else:
        reason = "Release Skill 尚未发布公开只读验证器，无法审计发布收据链"
    base.update(
        status="BLOCKED",
        blocking_reasons=[reason + "（" + UPSTREAM_BLOCKED_CODE + "）"],
    )
    return base


def audit_release_verifier_output(
    verifier_output: dict[str, Any] | None,
    *,
    expected_unit_id: str,
    expected_target_version: str,
) -> dict[str, Any]:
    """薄消费上游公开验证器输出，返回 Audit 领域结果。

    上游公开验证器尚未发布：不校验、不解释任何调用方提供的对象。该对象
    不能把不存在的上游能力伪装成已发布，也不能构造 SUCCEEDED；空输入与
    任何对象都确定性返回 BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE。
    """
    return _closed_result(
        expected_unit_id=expected_unit_id,
        expected_target_version=expected_target_version,
        provided=verifier_output is not None,
    )


def audit_release_receipts(
    *,
    verifier_output_path: str | None,
    expected_unit_id: str,
    expected_target_version: str,
) -> dict[str, Any]:
    """保留本函数名作为 release-audit 内部的稳定适配入口。

    上游公开验证器尚未发布：无论路径是否提供，都不加载、不校验、不解释
    调用方提供的文件，确定性返回
    BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE。
    """
    return _closed_result(
        expected_unit_id=expected_unit_id,
        expected_target_version=expected_target_version,
        provided=verifier_output_path is not None,
    )


__all__ = [
    "UPSTREAM_PROTOCOL_ID",
    "UPSTREAM_BLOCKED_CODE",
    "audit_release_verifier_output",
    "audit_release_receipts",
]
