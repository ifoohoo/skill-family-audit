#!/usr/bin/env python3
"""汇总前三类审计与完整发布门禁，不静默重跑任何上游审计。"""

from __future__ import annotations

import argparse
from datetime import datetime
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
    "runtime_packages",
    "adoption_lock",
    "exceptions",
    "verification_tier",
    "release_policy",
}
METHOD_IDENTITIES = {
    "conformance": "skill-family-audit:conformance-audit",
    "behavior": "skill-family-audit:behavior-audit",
    "runtime": "skill-family-audit:runtime-audit",
}
EVIDENCE_TYPES = {
    "conformance": "method-result",
    "behavior": "method-result",
    "runtime": "method-result",
    "runtime_packages": "runtime-package-manifest",
    "adoption_lock": "registry-adoption-lock",
    "exceptions": "non-waivable-policy",
    "verification_tier": "platform-lifecycle-receipt",
    "release_policy": "release-policy",
}
EVIDENCE_IDENTITIES = {
    "runtime_packages": "skill-family-audit:runtime-packages",
    "adoption_lock": "skill-family-audit:registry-adoption-lock",
    "exceptions": "skill-family-audit:non-waivable-policy",
    "verification_tier": "skill-family-audit:platform-lifecycle",
    "release_policy": "skill-family-audit:release-policy",
}
RESULT_REQUIRED = {
    "schema_version",
    "run_id",
    "stage_id",
    "attempt",
    "execution_status",
    "summary",
    "outputs",
    "domain_results",
    "evidence",
    "missing_inputs",
    "warnings",
    "errors",
    "side_effects",
    "producer",
    "usage",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERIFIED_PLATFORM_LIFECYCLES = {
    "verified_session_scoped",
    "verified_isolated_config_root",
    "verified_session_scoped_explicit_skills_dir",
    "verified_persistent_install_cleanup_advisory",
}
RELEASE_REQUIRED_LIFECYCLE_ACTIONS = {
    "manifest", "install", "discover", "minimalInvoke", "uninstall",
}
LIFECYCLE_ACTIONS = RELEASE_REQUIRED_LIFECYCLE_ACTIONS | {"cleanup"}
BLOCKED_PLATFORM_LIFECYCLES = {
    "blocked_session_scoped_evidence_incomplete",
    "plugin_packaging_available_lifecycle_not_run",
}


class AssessmentError(RuntimeError):
    pass


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _process_evidence_valid(value: Any) -> bool:
    """Validate the observable process boundary behind one lifecycle action."""
    if not isinstance(value, dict):
        return False
    process = value.get("process")
    if not isinstance(process, dict):
        return False
    duration = process.get("durationMs")
    before_count = process.get("workspaceFileCountBefore")
    after_count = process.get("workspaceFileCountAfter")
    normalized_command = process.get("normalizedCommand")
    normalized_events = process.get("normalizedEvents")
    command_digest = process.get("commandDigest")
    output_digest = process.get("outputDigest")
    return all((
        isinstance(duration, int) and not isinstance(duration, bool)
        and duration >= 0,
        process.get("exitCode") == 0,
        process.get("processEnded") is True,
        process.get("timedOut") is False,
        process.get("workspaceUnchanged") is True,
        isinstance(normalized_command, list),
        bool(normalized_command),
        all(isinstance(item, str) and bool(item) for item in normalized_command),
        isinstance(normalized_events, list),
        all(isinstance(item, dict) for item in normalized_events),
        HEX64.fullmatch(str(command_digest or "")) is not None,
        command_digest != "0" * 64,
        command_digest == _canonical_digest(normalized_command),
        HEX64.fullmatch(str(output_digest or "")) is not None,
        output_digest != "0" * 64,
        output_digest == _canonical_digest(normalized_events),
        HEX64.fullmatch(
            str(process.get("workspaceBeforeDigest", ""))
        ) is not None,
        process.get("workspaceBeforeDigest")
        == process.get("workspaceAfterDigest"),
        isinstance(before_count, int) and not isinstance(before_count, bool),
        before_count >= 0,
        before_count == after_count,
    ))


def _action_evidence_ref_valid(
    platform_id: str,
    platform: dict[str, Any],
    reference: Any,
) -> bool:
    """Resolve public lifecycle refs instead of accepting non-empty strings."""
    if not isinstance(reference, str) or not reference:
        return False
    if reference.startswith("file:"):
        relative = reference.removeprefix("file:")
        path = Path(relative)
        return all((
            bool(relative),
            not path.is_absolute(),
            ".." not in path.parts,
            relative
            == f"generated/platforms/{platform_id}/platform-manifest.json",
        ))
    if not reference.startswith("evidence."):
        return False
    current: Any = platform.get("evidence")
    for part in reference.split(".")[1:]:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return _process_evidence_valid(current)


def _cleanup_advisory_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    safe = {
        "classification": "non_blocking_physical_cleanup_advisory",
        "sensitiveStatePresent": False,
        "residualWithinCandidateBoundary": True,
        "functionalUninstallVerified": True,
        "postUninstallDiscoverable": False,
        "postUninstallInvocable": False,
        "autoLoadRegistrationPresent": False,
        "sourceStateUnchanged": True,
        "isolatedStateRootDestroyedOnHarnessExit": True,
    }
    if any(value.get(key) != expected for key, expected in safe.items()):
        return False
    file_count = value.get("residualFileCount")
    byte_count = value.get("residualByteCount")
    entries = value.get("residualEntries")
    integrations = value.get("integrationActivity")
    if not all((
        isinstance(value.get("residualScope"), str)
        and bool(value["residualScope"]),
        isinstance(value.get("manualCleanupBoundary"), str)
        and bool(value["manualCleanupBoundary"]),
        isinstance(file_count, int) and not isinstance(file_count, bool)
        and file_count >= 0,
        isinstance(byte_count, int) and not isinstance(byte_count, bool)
        and byte_count >= 0,
        isinstance(value.get("residualPresent"), bool),
        value.get("residualPresent") is (file_count > 0),
        isinstance(entries, list),
        file_count == len(entries or []),
        isinstance(integrations, dict),
        set(integrations or {})
        == {"hooks", "connectors", "mcpServers", "backgroundProcesses"},
    )):
        return False
    if any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("path"), str)
        or not entry["path"]
        or HEX64.fullmatch(str(entry.get("sha256", ""))) is None
        or entry.get("sha256") == "0" * 64
        or not isinstance(entry.get("byteCount"), int)
        or isinstance(entry.get("byteCount"), bool)
        or entry.get("byteCount") < 0
        or entry.get("classification")
        not in {"candidate_payload", "known_host_metadata"}
        for entry in entries
    ):
        return False
    for entry in entries:
        if entry["classification"] == "candidate_payload":
            if (
                entry.get("candidateMatch") is not True
                or not isinstance(entry.get("candidatePath"), str)
                or not entry["candidatePath"]
            ):
                return False
        elif not all((
            entry.get("candidateMatch") is False,
            entry.get("candidatePath") is None,
            entry["path"].endswith("/.orphaned_at")
            or entry["path"] == ".orphaned_at",
            entry.get("byteCount") == 13,
        )):
            return False
    if not all((
        byte_count == sum(entry["byteCount"] for entry in entries),
        value.get("residualEntriesDigest") == _canonical_digest(entries),
        value.get("unknownResidualPaths") == [],
        value.get("sensitiveStateFindings") == [],
        value.get("privateStateFindings") == [],
    )):
        return False
    for fact in integrations.values():
        if not isinstance(fact, dict):
            return False
        status = fact.get("status")
        definitions = fact.get("detectedDefinitions")
        active = fact.get("activeIdentifiers")
        refs = fact.get("evidenceRefs")
        if not all(isinstance(items, list) for items in (definitions, active, refs)):
            return False
        if active:
            return False
        if status == "not_applicable":
            if definitions or refs:
                return False
        elif status == "stopped":
            if not definitions or not refs:
                return False
        else:
            return False
    return True


def _physical_cleanup_matches_advisory(
    platform: dict[str, Any], advisory: dict[str, Any],
) -> bool:
    cleanup = platform.get("evidence", {}).get("physicalCleanup")
    if not isinstance(cleanup, dict):
        return False
    return all((
        cleanup.get("isolatedConfigRootDestroyedOnHarnessExit") is True,
        cleanup.get("sensitiveStatePresent") is False,
        cleanup.get("residualPresent") == advisory.get("residualPresent"),
        cleanup.get("residualFileCount") == advisory.get("residualFileCount"),
        cleanup.get("residualByteCount") == advisory.get("residualByteCount"),
        cleanup.get("residualEntries") == advisory.get("residualEntries"),
        cleanup.get("residualEntriesDigest")
        == advisory.get("residualEntriesDigest"),
        cleanup.get("unknownResidualPaths")
        == advisory.get("unknownResidualPaths"),
        cleanup.get("sensitiveStateFindings")
        == advisory.get("sensitiveStateFindings"),
        cleanup.get("privateStateFindings")
        == advisory.get("privateStateFindings"),
        cleanup.get("residualWithinCandidateBoundary")
        == advisory.get("residualWithinCandidateBoundary"),
    ))


def _kimi_after_signals(after: dict[str, Any]) -> dict[str, bool] | None:
    process = after.get("process")
    if not isinstance(process, dict):
        return None
    events = process.get("normalizedEvents")
    if not isinstance(events, list):
        return None
    skill_name = "skill-family-audit-help"
    marker = "SFA_HELP_CANDIDATE_V1"
    requested = False
    loaded = False
    assistant_contents: list[str] = []
    host_contents: list[str] = []
    for event in events:
        item = event.get("value") if isinstance(event, dict) else None
        if not isinstance(item, dict):
            continue
        calls = item.get("tool_calls")
        for call in calls if isinstance(calls, list) else []:
            function = call.get("function", {}) if isinstance(call, dict) else {}
            if function.get("name") != "Skill":
                continue
            try:
                arguments = json.loads(function.get("arguments", "{}"))
            except (json.JSONDecodeError, TypeError):
                arguments = {}
            requested = requested or arguments.get("skill") == skill_name
        content = item.get("content")
        if isinstance(content, str):
            if f'Skill "{skill_name}" loaded inline.' in content:
                loaded = True
            if item.get("role") == "assistant":
                assistant_contents.append(content)
            else:
                host_contents.append(content)
    rejection = re.compile(
        r"(?i)(?:skill[^\n]{0,80}(?:not found|unknown|not installed|unavailable)|"
        r"(?:不存在|未安装|不可用)[^\n]{0,80}skill)"
    )
    return {
        "skillToolRequested": requested,
        "skillLoadConfirmedByTool": loaded,
        "skillToolRejectedByHost": requested and not loaded and any(
            rejection.search(content) for content in host_contents
        ),
        "markerObservedInAssistantResult": any(
            marker in content for content in assistant_contents
        ),
        "modelReportedUnavailable": any(
            "不可用" in content or "不存在" in content
            for content in assistant_contents
        ),
    }


def _kimi_host_route_rejected(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    names = value.get("availableSkillNames")
    if (
        not isinstance(names, list)
        or names != sorted(set(names))
        or any(not isinstance(name, str) or not name for name in names)
    ):
        return False
    target = "skill-family-audit-help"
    return all((
        value.get("source") == "isolated_session_config",
        value.get("inventoryObserved") is True,
        value.get("inventoryDigest") == _canonical_digest(names),
        value.get("targetSkill") == target,
        value.get("targetAbsent") is (target not in names),
        value.get("targetAbsent") is True,
    ))


def _claude_lifecycle_valid(platform: dict[str, Any]) -> bool:
    if platform.get("lifecycleStatus") != (
        "verified_persistent_install_cleanup_advisory"
    ):
        return True
    evidence = platform.get("evidence", {})
    after = evidence.get("after", {})
    plugin_after = evidence.get("pluginAfter", {})
    advisory = platform.get("cleanupAdvisory", {})
    return all((
        platform.get("sourceSettingsUnchanged") is True,
        plugin_after.get("candidateAbsent") is True,
        after.get("outcome") == "unavailable",
        after.get("directInvocationRequested") is True,
        after.get("clientInitObserved") is True,
        after.get("candidateDiscoveredByClient") is False,
        after.get("candidatePluginCount") == 0,
        after.get("markerObservedInFinalResult") is False,
        _physical_cleanup_matches_advisory(platform, advisory),
    ))


def _codex_lifecycle_valid(platform: dict[str, Any]) -> bool:
    if platform.get("lifecycleStatus") != "verified_isolated_config_root":
        return True
    evidence = platform.get("evidence", {})
    return all((
        platform.get("isolatedConfigRootOptionObserved") is True,
        platform.get("isolatedStateChainVerified") is True,
        platform.get("candidateTreeDigestMatch") is True,
        platform.get("sourceAuthUnchanged") is True,
        platform.get("isolatedAuthIsRegularFile") is True,
        platform.get("isolatedAuthMode") == 0o600,
        platform.get("mutationAttempted") is True,
        evidence.get("pluginList", {}).get("candidateDiscovered") is True,
        evidence.get("minimalInvoke", {}).get("markerObserved") is True,
        evidence.get("pluginRemove", {}).get("pluginRemoved") is True,
        evidence.get("marketplaceRemove", {}).get("marketplaceRemoved") is True,
        evidence.get("pluginAfter", {}).get("installedCount") == 0,
        evidence.get("pluginAfter", {}).get("candidateCacheRemoved") is True,
    ))


def _kimi_lifecycle_valid(platform: dict[str, Any]) -> bool:
    if platform.get("lifecycleStatus") != (
        "verified_persistent_install_cleanup_advisory"
    ):
        return True
    evidence = platform.get("evidence", {})
    install = evidence.get("pluginInstall", {})
    uninstall = evidence.get("pluginUninstall", {})
    plugin_after = evidence.get("pluginAfter", {})
    after = evidence.get("after", {})
    host_route = evidence.get("hostInventoryAfter", {})
    cleanup = evidence.get("physicalCleanup", {})
    advisory = platform.get("cleanupAdvisory", {})
    signals = _kimi_after_signals(after)
    if signals is None or any(
        after.get(key) is not expected for key, expected in signals.items()
    ):
        return False
    host_route_rejected = _kimi_host_route_rejected(host_route)
    if (
        after.get("hostRouteRejected") is not host_route_rejected
    ):
        return False
    deterministic_rejection = bool(
        host_route_rejected
        or (
            after.get("skillToolRequested") is True
            and after.get("skillToolRejectedByHost") is True
        )
    )
    return all((
        platform.get("sourceCredentialStateUnchanged") is True,
        platform.get("sourceSettingsUnchanged") is True,
        platform.get("fullPluginLifecycleVerified") is False,
        install.get("trustChoiceConfirmed") is True,
        install.get("candidateInstalled") is True,
        install.get("managedTreeMatchesCandidate") is True,
        evidence.get("pluginList", {}).get("candidateListed") is True,
        uninstall.get("removeChoiceConfirmed") is True,
        uninstall.get("candidateAbsentFromInstallRecord") is True,
        plugin_after.get("installRecordEmpty") is True,
        plugin_after.get("candidateListed") is False,
        plugin_after.get("nativeListObserved") is True,
        after.get("outcome") == "unavailable",
        after.get("directInvocationRequested") is True,
        after.get("skillLoadConfirmedByTool") is False,
        after.get("markerObservedInAssistantResult") is False,
        deterministic_rejection,
        after.get("unavailabilityBasis")
        == "native_registry_absence_and_host_route_rejection",
        cleanup.get("managedCopyRetainedAfterNativeUninstall") is True,
        advisory.get("residualWithinCandidateBoundary")
        == install.get("managedTreeMatchesCandidate"),
        _physical_cleanup_matches_advisory(platform, advisory),
    ))


def _workbuddy_lifecycle_valid(platform: dict[str, Any]) -> bool:
    if platform.get("lifecycleStatus") != (
        "verified_persistent_install_cleanup_advisory"
    ):
        return True
    evidence = platform.get("evidence", {})
    install = evidence.get("pluginInstall", {})
    marketplace_after = evidence.get("marketplaceAfter", {})
    after = evidence.get("after", {})
    advisory = platform.get("cleanupAdvisory", {})
    return all((
        platform.get("projectionValid") is True,
        platform.get("mutationAttempted") is True,
        platform.get("independentClientEvidence") is True,
        platform.get("clientProbeAttempted") is True,
        platform.get("sourceAuthUnchanged") is True,
        platform.get("sourceSettingsUnchanged") is True,
        install.get("registryEnabled") is True,
        install.get("marketplacePathMatchesCandidate") is True,
        install.get("candidateTreeDigestMatch") is True,
        install.get("nativeInstallStatusObserved") is True,
        marketplace_after.get("candidateAbsent") is True,
        marketplace_after.get("pluginRegistryAbsent") is True,
        after.get("outcome") == "unavailable",
        after.get("directInvocationRequested") is True,
        after.get("clientInitObserved") is True,
        after.get("candidateDiscoveredByClient") is False,
        after.get("skillLoadConfirmedByTool") is False,
        after.get("markerObservedInFinalResult") is False,
        not after.get("unexpectedToolsUsed"),
        _physical_cleanup_matches_advisory(platform, advisory),
    ))


def _non_waivable_mapping_semantically_valid(value: dict[str, Any]) -> bool:
    """稳定发布必须语义验证不可豁免映射：NW-01..NW-10 精确、唯一且完整。

    Schema 只约束结构；此函数验证：
    - 10 个映射的 baseline_id 必须恰好覆盖 NW-01..NW-10
    - 每个映射的 mapped_rules 非空
    - 每个映射的 policy_summary_digest 非零
    - 顶层 summary 非空
    - status 为 approved（而非 pending_user_approval）
    """
    if not isinstance(value, dict):
        return False
    if value.get("policy_digest_status") != "approved":
        return False
    mappings = value.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != 10:
        return False
    expected_ids = {f"NW-{i:02d}" for i in range(1, 11)}
    actual_ids = set()
    for mapping in mappings:
        if not isinstance(mapping, dict):
            return False
        bid = mapping.get("baseline_id", "")
        if bid not in expected_ids:
            return False
        if bid in actual_ids:
            return False
        actual_ids.add(bid)
        if mapping.get("status") != "approved":
            return False
        mapped_rules = mapping.get("mapped_rules")
        if not isinstance(mapped_rules, list) or not mapped_rules:
            return False
        rule_ids: set[str] = set()
        for rule in mapped_rules:
            if not isinstance(rule, dict):
                return False
            rule_id = rule.get("canonical_rule_id")
            revision = rule.get("revision_digest")
            if (
                not isinstance(rule_id, str)
                or not rule_id
                or rule_id in rule_ids
                or not HEX64.fullmatch(str(revision))
                or revision == "0" * 64
            ):
                return False
            rule_ids.add(rule_id)
        digest = mapping.get("policy_summary_digest", "")
        if not HEX64.fullmatch(str(digest)) or digest == "0" * 64:
            return False
    if actual_ids != expected_ids:
        return False
    summary = value.get("summary")
    if not isinstance(summary, dict) or not summary:
        return False
    biz_digest = value.get("business_digest", "")
    if not HEX64.fullmatch(str(biz_digest)) or biz_digest == "0" * 64:
        return False
    return True


def _release_policy_semantically_valid(value: dict[str, Any]) -> bool:
    """稳定发布必须语义验证发布策略所需规则、唯一性、启用状态和 enforcement。

    Schema 只约束结构；此函数验证：
    - rules 非空
    - rule_id 唯一
    - status 为 active
    - 每个 rule 有 enforcement 字段（不接受缺省 optional 伪造）
    """
    if not isinstance(value, dict):
        return False
    if value.get("status") != "active":
        return False
    rules = value.get("rules")
    if not isinstance(rules, list) or len(rules) != 4:
        return False
    expected = {
        "RELEASE-001": "required",
        "RELEASE-002": "required",
        "RELEASE-003": "required",
        "RELEASE-004": "recommended",
    }
    actual: dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            return False
        rid = rule.get("rule_id", "")
        if not isinstance(rid, str) or not rid:
            return False
        if rid in actual:
            return False
        desc = rule.get("description", "")
        if not isinstance(desc, str) or not desc:
            return False
        actual[rid] = rule.get("enforcement")
    return actual == expected


def _lifecycle_receipt_semantically_valid(
    value: dict[str, Any], candidate_id: str,
) -> bool:
    """独立重算动作、cleanup 安全告警和顶层聚合，拒绝只改状态字段。"""
    platforms = value.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != PLATFORMS:
        return False
    release_blocking: list[str] = []
    advisory_platforms: list[str] = []
    all_verified = True
    any_verified = False
    binding = value.get("candidateBinding")
    if not isinstance(binding, dict):
        return False
    platform_digests = binding.get("platformDigests")
    projection_digests = binding.get("platformProjectionDigests")
    payload_digest = binding.get("candidatePayloadDigest")
    if not all((
        binding.get("candidateId") == candidate_id,
        HEX64.fullmatch(str(payload_digest or "")) is not None,
        payload_digest != "0" * 64,
        binding.get("candidateTreeUnchanged") is True,
        binding.get("candidatePlatformTreesMatchGenerated") is True,
        binding.get("platformProjectionDigestsMatch") is True,
        isinstance(platform_digests, dict),
        set(platform_digests or {}) == PLATFORMS,
        isinstance(projection_digests, dict),
        set(projection_digests or {}) == PLATFORMS,
        all(
            HEX64.fullmatch(str((platform_digests or {}).get(pid, "")))
            is not None
            for pid in PLATFORMS
        ),
        platform_digests == projection_digests,
    )):
        return False
    for platform_id in sorted(PLATFORMS):
        platform = platforms.get(platform_id)
        if not isinstance(platform, dict):
            return False
        actions = platform.get("lifecycleActions")
        if not isinstance(actions, dict) or set(actions) != LIFECYCLE_ACTIONS:
            return False
        for action in actions.values():
            required_action_fields = {
                "attempted", "blockingReasons", "evidenceRefs", "scope", "status",
            }
            if (
                not isinstance(action, dict)
                or not required_action_fields.issubset(action)
            ):
                return False
            status = action.get("status")
            evidence_refs = action.get("evidenceRefs")
            blocking_reasons = action.get("blockingReasons")
            if (
                not isinstance(evidence_refs, list)
                or not isinstance(blocking_reasons, list)
                or not isinstance(action.get("scope"), str)
                or not action["scope"]
                or any(not isinstance(reason, str) or not reason for reason in blocking_reasons)
                or any(
                    not _action_evidence_ref_valid(platform_id, platform, reference)
                    for reference in evidence_refs
                )
            ):
                return False
            if status not in {"verified", "blocked"}:
                return False
            if status == "verified":
                any_verified = True
                if (
                    action.get("attempted") is not True
                    or not evidence_refs
                    or blocking_reasons != []
                ):
                    return False
            elif not blocking_reasons:
                return False
        if any(actions[name]["status"] != "verified" for name in RELEASE_REQUIRED_LIFECYCLE_ACTIONS):
            release_blocking.append(platform_id)
        if actions["cleanup"]["status"] != "verified":
            all_verified = False
            if platform_id not in release_blocking:
                advisory_platforms.append(platform_id)
                if not _cleanup_advisory_valid(platform.get("cleanupAdvisory")):
                    return False
        if any(actions[name]["status"] != "verified" for name in LIFECYCLE_ACTIONS):
            all_verified = False
        platform_validator = {
            "claude-code": _claude_lifecycle_valid,
            "codex": _codex_lifecycle_valid,
            "kimi-code": _kimi_lifecycle_valid,
            "workbuddy": _workbuddy_lifecycle_valid,
        }[platform_id]
        if not platform_validator(platform):
            return False
    release_blocking.sort()
    advisory_platforms.sort()
    release_required = not release_blocking
    if all_verified:
        expected_status = "VERIFIED"
    elif release_required and advisory_platforms:
        expected_status = "REQUIRED_ACTIONS_VERIFIED_WITH_ADVISORIES"
    elif any_verified:
        expected_status = "PARTIALLY_VERIFIED_WITH_BLOCKERS"
    else:
        expected_status = "BLOCKED"
    return all((
        value.get("allLifecycleVerified") is all_verified,
        value.get("releaseRequiredLifecycleVerified") is release_required,
        value.get("releaseBlockingPlatforms") == release_blocking,
        value.get("advisoryPlatforms") == advisory_platforms,
        value.get("status") == expected_status,
    ))


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssessmentError(f"ASSESSMENTS_INVALID:{exc}") from exc
    if not isinstance(value, dict):
        raise AssessmentError("ASSESSMENTS_INVALID:top-level")
    return value


def _contract_root() -> Path:
    installed = Path(__file__).resolve().parents[3] / "shared/contracts"
    source = Path(__file__).resolve().parents[4] / "spec/contracts"
    for candidate in (installed, source):
        if (candidate / "result.schema.json").is_file():
            return candidate
    raise AssessmentError("RESULT_SCHEMA_UNAVAILABLE")


def _schema_errors(
    value: Any,
    schema: dict[str, Any],
    schema_root: Path,
    pointer: str = "$",
    document_schema: dict[str, Any] | None = None,
) -> list[str]:
    document_schema = document_schema or schema
    reference = schema.get("$ref")
    if isinstance(reference, str):
        file_part, _, fragment = reference.partition("#")
        if file_part.startswith(("http:", "https:", "/")) or ".." in Path(
            file_part
        ).parts:
            return [f"{pointer}: unsafe $ref"]
        child_document = document_schema
        if file_part:
            target = schema_root / file_part
            try:
                resolved = target.resolve(strict=True)
                resolved.relative_to(schema_root.resolve(strict=True))
                child_document = json.loads(
                    resolved.read_text(encoding="utf-8")
                )
            except (OSError, ValueError, json.JSONDecodeError):
                return [f"{pointer}: unresolved $ref {reference}"]
        child: Any = child_document
        if fragment:
            if not fragment.startswith("/"):
                return [f"{pointer}: unsupported $ref fragment"]
            try:
                for raw in fragment[1:].split("/"):
                    key = raw.replace("~1", "/").replace("~0", "~")
                    child = child[key]
            except (KeyError, TypeError):
                return [f"{pointer}: unresolved $ref {reference}"]
        if not isinstance(child, dict):
            return [f"{pointer}: $ref target is not a schema"]
        return _schema_errors(
            value,
            child,
            schema_root,
            pointer,
            child_document,
        )
    errors: list[str] = []
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and not any(
        isinstance(branch, dict)
        and not _schema_errors(
            value, branch, schema_root, pointer, document_schema
        )
        for branch in any_of
    ):
        errors.append(f"{pointer}: anyOf mismatch")
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        match_count = sum(
            1
            for branch in one_of
            if isinstance(branch, dict)
            and not _schema_errors(
                value, branch, schema_root, pointer, document_schema
            )
        )
        if match_count != 1:
            errors.append(f"{pointer}: oneOf mismatch")
    for child_schema in schema.get("allOf", []):
        errors.extend(
            _schema_errors(
                value,
                child_schema,
                schema_root,
                pointer,
                document_schema,
            )
        )
    condition = schema.get("if")
    if isinstance(condition, dict):
        condition_errors = _schema_errors(
            value,
            condition,
            schema_root,
            pointer,
            document_schema,
        )
        branch = schema.get("then") if not condition_errors else schema.get(
            "else"
        )
        if isinstance(branch, dict):
            errors.extend(
                _schema_errors(
                    value,
                    branch,
                    schema_root,
                    pointer,
                    document_schema,
                )
            )
    negated = schema.get("not")
    if isinstance(negated, dict) and not _schema_errors(
        value,
        negated,
        schema_root,
        pointer,
        document_schema,
    ):
        errors.append(f"{pointer}: forbidden by not")
    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }
    if isinstance(expected_type, str):
        if expected_type in type_matches and not type_matches[expected_type]:
            return [f"{pointer}: expected {expected_type}"]
    elif isinstance(expected_type, list) and not any(
        type_matches.get(item, False) for item in expected_type
    ):
        return [f"{pointer}: expected one of {expected_type}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{pointer}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{pointer}: enum mismatch")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{pointer}: minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{pointer}: maxLength")
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, value) is None:
            errors.append(f"{pointer}: pattern")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{pointer}: date-time format")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value):
            errors.append(f"{pointer}: minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{pointer}: maximum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{pointer}: minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{pointer}: maxItems")
        if schema.get("uniqueItems") is True:
            encoded = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{pointer}: uniqueItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, child in enumerate(value):
                errors.extend(
                    _schema_errors(
                        child,
                        item_schema,
                        schema_root,
                        f"{pointer}/{index}",
                        document_schema,
                    )
                )
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{pointer}: missing {name}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in sorted(set(value) - set(properties)):
                errors.append(f"{pointer}: unknown {name}")
        for name, child in value.items():
            child_schema = properties.get(name)
            if isinstance(child_schema, dict):
                errors.extend(
                    _schema_errors(
                        child,
                        child_schema,
                        schema_root,
                        f"{pointer}/{name}",
                        document_schema,
                    )
                )
    return errors


def _method_identity_matches(
    producer: dict[str, Any],
    expected: str,
) -> bool:
    short = expected.rsplit(":", 1)[-1]
    method_ref = producer.get("method_ref")
    skill = producer.get("skill")
    return (
        method_ref == expected and skill in {short, expected}
    ) or (method_ref is None and skill == expected)


def _contract_schema_path(filename: str) -> Path:
    root = _contract_root()
    direct = root / filename
    if direct.is_file():
        return direct
    source_project = Path(__file__).resolve().parents[4]
    source_fallbacks = {
        "non-waivable-candidate.schema.json": (
            source_project
            / "governance/schemas/non-waivable-candidate.schema.json"
        ),
        "release-policy.schema.json": (
            source_project
            / "spec/packages/common-governance/schemas/"
            "release_policy.schema.json"
        ),
    }
    fallback = source_fallbacks.get(filename)
    if fallback is not None and fallback.is_file():
        return fallback
    raise AssessmentError(f"CONTRACT_SCHEMA_UNAVAILABLE:{filename}")


def _contract_valid(value: dict[str, Any], filename: str) -> bool:
    try:
        schema_path = _contract_schema_path(filename)
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (AssessmentError, OSError, json.JSONDecodeError):
        return False
    return not _schema_errors(value, schema, schema_path.parent)


def _method_evidence_error(
    evidence: list[Any],
    result_path: Path,
    candidate_id: str,
    declared_root: Any,
) -> str | None:
    """验证成功 Result 引用的证据字节，且不允许路径逃逸。"""

    try:
        adjacent_root = result_path.parent.resolve(strict=True)
    except OSError:
        return "Result 相邻证据根不可解析"
    roots = [adjacent_root]
    if declared_root is not None:
        if not isinstance(declared_root, str):
            return "声明的 evidence_root 非法"
        root_path = Path(declared_root)
        if (
            not root_path.is_absolute()
            or root_path.is_symlink()
            or not root_path.is_dir()
        ):
            return "声明的 evidence_root 缺失或路径不可信"
        try:
            roots.append(root_path.resolve(strict=True))
        except OSError:
            return "声明的 evidence_root 不可解析"

    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            return f"成功 Result 的 evidence[{index}] 非对象"
        if item.get("candidate_id") != candidate_id:
            return "成功 Result 的证据未完整绑定当前候选"
        raw_path = item.get("path")
        expected_digest = item.get("content_digest")
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or not isinstance(expected_digest, str)
            or HEX64.fullmatch(expected_digest) is None
        ):
            return f"成功 Result 的 evidence[{index}] 路径或摘要非法"
        file_part, fragment_marker, fragment = raw_path.partition("#")
        if (
            not file_part
            or (fragment_marker and not fragment.startswith("/"))
        ):
            return f"成功 Result 的 evidence[{index}] JSON Pointer 非法"
        candidate_path = Path(file_part)
        if not candidate_path.is_absolute():
            base = roots[-1] if declared_root is not None else adjacent_root
            candidate_path = base / candidate_path
        try:
            resolved = candidate_path.resolve(strict=True)
        except (OSError, RuntimeError):
            return f"成功 Result 的 evidence[{index}] 文件不存在"
        containing_root = next(
            (
                root
                for root in roots
                if resolved == root or root in resolved.parents
            ),
            None,
        )
        if containing_root is None:
            return f"成功 Result 的 evidence[{index}] 路径逃逸允许根"
        cursor = candidate_path
        while cursor != cursor.parent:
            if cursor.is_symlink():
                return f"成功 Result 的 evidence[{index}] 路径包含符号链接"
            if cursor in roots:
                break
            cursor = cursor.parent
        if not resolved.is_file():
            return f"成功 Result 的 evidence[{index}] 不是普通文件"
        try:
            if fragment_marker:
                pointed: Any = json.loads(
                    resolved.read_text(encoding="utf-8")
                )
                for raw_component in fragment[1:].split("/"):
                    component = raw_component.replace("~1", "/").replace(
                        "~0", "~"
                    )
                    if isinstance(pointed, list):
                        if not component.isdecimal():
                            raise KeyError(component)
                        pointed = pointed[int(component)]
                    elif isinstance(pointed, dict):
                        pointed = pointed[component]
                    else:
                        raise KeyError(component)
                actual_bytes = json.dumps(
                    pointed,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            else:
                actual_bytes = resolved.read_bytes()
            actual_digest = hashlib.sha256(actual_bytes).hexdigest()
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            IndexError,
            ValueError,
            TypeError,
        ):
            return (
                f"成功 Result 的 evidence[{index}] 文件不可读或"
                " JSON Pointer 无法解析"
            )
        if actual_digest != expected_digest:
            return f"成功 Result 的 evidence[{index}] content_digest 不匹配"
    return None


def _semantic_error(
    name: str,
    document: dict[str, Any],
    claimed_status: str,
    candidate_id: str,
    document_path: Path,
    declared_evidence_root: Any = None,
) -> str | None:
    if name in METHOD_IDENTITIES:
        schema_root = _contract_root()
        schema = json.loads(
            (schema_root / "result.schema.json").read_text(encoding="utf-8")
        )
        errors = _schema_errors(document, schema, schema_root)
        if errors:
            return f"Result Schema 校验失败: {errors[0]}"
        producer = document.get("producer")
        execution_status = document.get("execution_status")
        if (
            not isinstance(producer, dict)
            or not _method_identity_matches(
                producer, METHOD_IDENTITIES[name]
            )
            or execution_status
            not in {
                "SUCCEEDED",
                "SUCCEEDED_WITH_WARNINGS",
                "FAILED",
                "BLOCKED",
                "NEEDS_INPUT",
                "SKIPPED",
                "CANCELLED",
            }
        ):
            return "Result 合同版本、生产者身份或终态非法"
        succeeded = execution_status in {"SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"}
        if claimed_status == "valid" and not succeeded:
            return f"Result 终态为 {execution_status}，不得声称 valid"
        if claimed_status in {"blocked", "failed"} and succeeded:
            return f"Result 终态为 {execution_status}，不得声称受阻或失败"
        if succeeded:
            if not document.get("domain_results"):
                return "成功 Result 缺少领域结果"
            evidence = document.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                return "成功 Result 的证据未完整绑定当前候选"
            evidence_error = _method_evidence_error(
                evidence,
                document_path,
                candidate_id,
                declared_evidence_root,
            )
            if evidence_error:
                return evidence_error
        return None
    if name.startswith("platform:"):
        platform = name.split(":", 1)[1]
        candidate_version = candidate_id.split(":", 1)[1]
        if not _contract_valid(document, "platform-manifest.schema.json"):
            return "平台清单不满足完整公共 Schema"
        lifecycle_status = document.get("lifecycleStatus")
        expected_blocked = lifecycle_status in BLOCKED_PLATFORM_LIFECYCLES
        expected_verified = lifecycle_status in VERIFIED_PLATFORM_LIFECYCLES
        release_blocked = document.get("blocked")
        blocking_reasons = document.get("blockingReasons")
        advisories = document.get("advisories")
        if (
            document.get("familyId") != "skill-family-audit"
            or document.get("platformId") != platform
            or document.get("version") != candidate_version
            or not (expected_blocked or expected_verified)
            or document.get("fileCount") != len(document.get("files", []))
            or not HEX64.fullmatch(
                str(document.get("projectionDigest", ""))
            )
            or not HEX64.fullmatch(str(document.get("sourceDigest", "")))
            or not isinstance(release_blocked, bool)
            or not isinstance(blocking_reasons, list)
            or not isinstance(advisories, list)
            or any(not isinstance(reason, str) for reason in blocking_reasons)
            or any(not isinstance(reason, str) or not reason for reason in advisories)
            or (release_blocked and not blocking_reasons)
            or (not release_blocked and blocking_reasons)
            or (
                lifecycle_status == "verified_persistent_install_cleanup_advisory"
                and not advisories
            )
        ):
            return "平台清单身份、生命周期或投影摘要非法"
        if claimed_status == "valid" and not expected_verified:
            return "平台生命周期未 verified，不得声称 valid"
        if claimed_status == "blocked" and not expected_blocked:
            return "平台生命周期已验证，不得声称 blocked"
        return None
    validators = {
        "runtime_packages": lambda value: _contract_valid(
            value, "runtime-packages.schema.json"
        ),
        "adoption_lock": lambda value: _contract_valid(
            value, "registry-adoption-lifecycle.schema.json"
        )
        and value.get("familyId") == "skill-family-audit",
        "exceptions": lambda value: (
            _contract_valid(value, "non-waivable-candidate.schema.json")
        ),
        "verification_tier": lambda value: (
            _contract_valid(value, "platform-lifecycle-receipt.schema.json")
            and _lifecycle_receipt_semantically_valid(value, candidate_id)
        ),
        "release_policy": lambda value: (
            _contract_valid(value, "release-policy.schema.json")
            and value.get("status") == "active"
        ),
    }
    validator = validators.get(name)
    if validator is None or not validator(document):
        return "证据内容不满足该类别的语义合同"
    return None


def _expected_contract(name: str) -> tuple[str, str]:
    if name in METHOD_IDENTITIES:
        return "method-result", METHOD_IDENTITIES[name]
    if name.startswith("platform:"):
        platform = name.split(":", 1)[1]
        return (
            "platform-manifest",
            f"skill-family-audit:platform:{platform}",
        )
    return EVIDENCE_TYPES[name], EVIDENCE_IDENTITIES[name]


def check_evidence(
    name: str,
    value: Any,
    candidate_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "missing", "reason": f"{name} 未提供"}
    status = value.get("status")
    if status not in STATUSES:
        return {"status": "failed", "reason": f"{name} 状态非法"}
    result = {"status": status, "reason": str(value.get("reason", ""))}
    path_value = value.get("path")
    expected = value.get("digest")
    evidence_type = value.get("evidence_type")
    identity = value.get("identity")
    bound_candidate = value.get("candidate_id")
    if status in {"valid", "exception_pass", "not_applicable"} and (
        not isinstance(path_value, str)
        or not isinstance(expected, str)
        or len(expected) != 64
        or not isinstance(evidence_type, str)
        or not evidence_type
        or not isinstance(identity, str)
        or not identity
        or bound_candidate != candidate_id
    ):
        return {
            "status": "missing",
            "reason": f"{name} 可接受状态缺少路径、摘要、类型或身份",
        }
    expected_type, expected_identity = _expected_contract(name)
    if (
        status in {"valid", "exception_pass", "not_applicable"}
        and (
            evidence_type != expected_type
            or identity != expected_identity
        )
    ):
        return {
            "status": "failed",
            "reason": f"{name} 证据类型或身份不匹配",
        }
    if path_value is not None:
        path = Path(path_value)
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            return {"status": "missing", "reason": f"{name} 证据文件缺失或路径不可信"}
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        result.update({
            "path": str(path),
            "digest": actual,
            "evidence_type": evidence_type,
            "identity": identity,
            "candidate_id": bound_candidate,
        })
        if expected != actual:
            result.update({"status": "stale", "reason": f"{name} 摘要陈旧"})
        else:
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                result.update({
                    "status": "failed",
                    "reason": f"{name} 证据不是 JSON 对象",
                })
            else:
                if not isinstance(document, dict):
                    result.update({
                        "status": "failed",
                        "reason": f"{name} 证据顶层不是对象",
                    })
                elif status in {"valid", "exception_pass", "not_applicable"}:
                    semantic_error = _semantic_error(
                        name,
                        document,
                        status,
                        candidate_id,
                        path,
                        value.get("evidence_root"),
                    )
                    if semantic_error:
                        result.update({
                            "status": "failed",
                            "reason": f"{name}: {semantic_error}",
                        })
                    elif name.startswith("platform:"):
                        result.update({
                            "lifecycle_status": document["lifecycleStatus"],
                            "release_blocked": document["blocked"],
                            "blocking_reasons": document["blockingReasons"],
                            "projection_digest": document["projectionDigest"],
                        })
                    elif name == "verification_tier":
                        result.update({
                            "release_required_lifecycle_verified": document[
                                "releaseRequiredLifecycleVerified"
                            ],
                            "platform_digests": document["candidateBinding"][
                                "platformDigests"
                            ],
                        })
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
        or not candidate_id.startswith("skill-family-audit:")
        or (
            expected_candidate_id is not None
            and candidate_id != expected_candidate_id
        )
    ):
        raise AssessmentError("CANDIDATE_IDENTITY_INVALID")
    # 稳定发布不得接受 *-candidate 版本标识
    if release_class == "stable":
        version_part = candidate_id.split(":", 1)[-1] if ":" in candidate_id else candidate_id
        if version_part.endswith("-candidate"):
            raise AssessmentError("STABLE_RELEASE_REJECTS_CANDIDATE_VERSION")
    rows = {
        name: check_evidence(name, document[name], candidate_id)
        for name in (
            "conformance",
            "behavior",
            "runtime",
            "runtime_packages",
            "adoption_lock",
            "exceptions",
            "verification_tier",
            "release_policy",
        )
    }
    platforms = document["platforms"]
    if not isinstance(platforms, dict) or set(platforms) != PLATFORMS:
        raise AssessmentError("PLATFORM_SET_INCOMPLETE")
    rows["platforms"] = {
        platform: check_evidence(
            f"platform:{platform}", platforms[platform], candidate_id
        )
        for platform in sorted(PLATFORMS)
    }
    verification_digests = rows["verification_tier"].get("platform_digests", {})
    if isinstance(verification_digests, dict):
        for platform, row in rows["platforms"].items():
            if (
                row.get("status") == "valid"
                and row.get("projection_digest") != verification_digests.get(platform)
            ):
                row.update({
                    "status": "failed",
                    "reason": f"platform:{platform} 未绑定生命周期收据中的候选投影摘要",
                })
    flattened = [
        *[row["status"] for key, row in rows.items() if key != "platforms"],
        *[row["status"] for row in rows["platforms"].values()],
    ]
    acceptable = {"valid", "exception_pass", "not_applicable"}
    passed = all(status in acceptable for status in flattened)
    if release_class == "stable":
        # 稳定发布必须全部 valid，不得用 not_applicable 或 exception_pass 替代
        stable_required = ("conformance", "behavior", "runtime", "adoption_lock")
        passed = (
            passed
            and all(
                rows[name]["status"] == "valid"
                for name in stable_required
            )
            and all(row["status"] == "valid" for row in rows["platforms"].values())
            and all(
                row.get("release_blocked") is False
                for row in rows["platforms"].values()
            )
            and rows["runtime_packages"]["status"] == "valid"
            and rows["verification_tier"]["status"] == "valid"
            and rows["verification_tier"].get(
                "release_required_lifecycle_verified"
            ) is True
            and rows["release_policy"]["status"] == "valid"
            # exceptions 的 not_applicable 不能替代 stable 所需的有效权威证据
            and rows["exceptions"]["status"] == "valid"
        )
        # 语义验证不可豁免映射和发布策略
        if passed:
            exceptions_path = document["exceptions"].get("path")
            release_policy_path = document["release_policy"].get("path")
            try:
                if exceptions_path:
                    exc_doc = json.loads(Path(exceptions_path).read_text(encoding="utf-8"))
                    if not _non_waivable_mapping_semantically_valid(exc_doc):
                        passed = False
                if release_policy_path:
                    rp_doc = json.loads(Path(release_policy_path).read_text(encoding="utf-8"))
                    if not _release_policy_semantically_valid(rp_doc):
                        passed = False
            except (OSError, json.JSONDecodeError, ValueError):
                passed = False
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
    parser.add_argument("--assessments-ref", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = assess(load(Path(args.assessments_ref).resolve(strict=True)))
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ) + "\n"
        if args.output:
            output = Path(args.output).resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if result["execution_status"] == "SUCCEEDED" else 1
    except (AssessmentError, OSError, ValueError) as exc:
        print(json.dumps({
            "execution_status": "BLOCKED",
            "error": str(exc),
        }, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
