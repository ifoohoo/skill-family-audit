#!/usr/bin/env python3
"""P5 静态编排蓝图（OrchestrationBlueprint）拓扑与治理审查器，兼含目标画像适用率分流。

职责边界：
1. 结构契约委托 Foundation Contracts `validateOrchestrationBlueprint` 校验；
2. 静态图语义与治理规则由本模块只读判定：
   - BP-SELF-REVIEW：审阅角色（reviewer）禁止携带写权限、禁止非空 allowedWriteSet、禁止非 fresh 上下文或降级变体；所有具备 final_veto 裁决权的审阅/审批节点禁止降级使用轻量级模型档位（fast_lightweight）；
   - BP-HITL-DOMINATOR：从 entryNodeId 到达任意具备 external_side_effect 节点的全部有向可达路径（含返工回边与失败/拒绝跳转），必须被声明覆盖 external_side_effect 的 hitlGates 严格支配（O(V+E) 全局已访问 BFS）；
   - BP-PARALLEL-WRITE-DISJOINT：同一父节点并发派生的 share/inherit 工作区分支写集互斥、单节点 fanOut>1 共享工作区自冲突拦截，以及父子委派写集单调收窄；
   - BP-EVIDENCE-VERIFIER：critical=true 的预期证据必须指定 verifiedBy 且不得等于 producedBy；
   - BP-CONTEXT-EAGER-BUDGET：单节点 eager 加载参考材料的累计预估 Token 不得突破上下文预警阈值；
3. 目标画像适用率分流（target_profile）：在不改动 282 条规则全集账本的前提下，按受审项目画像统计真实适用规则覆盖率（万分比 Bp）。
"""

from __future__ import annotations

import argparse
from collections import deque
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import conformance_check as checker  # noqa: E402

ORCHESTRATION_BLUEPRINT_SCHEMA_ID = (
    "https://contracts.skill-family.example/v1/orchestration-blueprint.json"
)
PROFESSIONAL_CONCLUSION_SCHEMA_ID = (
    "https://contracts.skill-family.example/v1/professional-conclusion.json"
)
PROVIDER_ID = "skill-family-audit"
PROVIDER_ENTRY = "skill-family-audit:blueprint-audit"
BLUEPRINT_RULE_IDS = [
    "BP-SELF-REVIEW",
    "BP-HITL-DOMINATOR",
    "BP-PARALLEL-WRITE-DISJOINT",
    "BP-EVIDENCE-VERIFIER",
    "BP-CONTEXT-EAGER-BUDGET",
]
TARGET_PROFILES = (
    "general_skill_family",
    "orchestrated_multi_agent",
    "platform_governance_provider",
)
DEFAULT_MODEL_WINDOW_TOKENS = 128_000
_GLOB_META_RE = re.compile(r"[*?\[]")


def _find_contracts_entry() -> Path:
    for ancestor in Path(__file__).resolve().parents:
        for rel in (
            "foundation/profile-spi/node_modules/skill-family-contracts/src/index.mjs",
            "generated/platforms/codex/foundation/profile-spi/node_modules/skill-family-contracts/src/index.mjs",
        ):
            cand = ancestor / rel
            if cand.is_file() and not cand.is_symlink():
                return cand.resolve(strict=True)
    raise RuntimeError("FOUNDATION_CONTRACTS_CLOSURE_MISSING")


def _call_contracts_bridge(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    node_path, _ = checker.foundation_node_runtime()
    entry = _find_contracts_entry()
    script = (
        "import { pathToFileURL } from 'node:url';"
        "let raw=''; for await (const c of process.stdin) raw+=c;"
        "const req=JSON.parse(raw);"
        "const mod=await import(pathToFileURL(req.entry).href);"
        "let out;"
        "if (req.action==='validate-blueprint') {"
        "  const r=mod.validateOrchestrationBlueprint(req.doc);"
        "  const d=r.valid?mod.digestDocument(req.doc):null;"
        "  out={valid:r.valid,errors:r.errors||[],digest:d};"
        "} else if (req.action==='validate-conclusion') {"
        "  const r=mod.validateDocument(req.doc,{schemaId:req.schemaId,dialect:'2020-12',policy:'strict'});"
        "  out={valid:r.valid,errors:r.errors||[]};"
        "} else { throw new Error('unknown action'); }"
        "process.stdout.write(JSON.stringify(out));"
    )
    proc = subprocess.run(
        [str(node_path), "--input-type=module", "-e", script],
        input=json.dumps({"entry": str(entry), "action": action, **payload}),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Foundation contracts bridge failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _provider_version() -> str:
    for ancestor in Path(__file__).resolve().parents:
        for rel in ("platform-manifest.json", "plugin-src/manifest.json", "package.json"):
            cand = ancestor / rel
            if cand.is_file() and not cand.is_symlink():
                try:
                    ver = json.loads(cand.read_text(encoding="utf-8")).get("version")
                    if isinstance(ver, str) and ver:
                        return ver
                except (OSError, json.JSONDecodeError):
                    continue
    return "1.1.68"


def _norm_glob_pat(pat: str) -> str:
    s = pat.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _patterns_overlap(pat_a: str, pat_b: str) -> bool:
    a = _norm_glob_pat(pat_a)
    b = _norm_glob_pat(pat_b)
    if a == b or a in {"*", "**"} or b in {"*", "**"}:
        return True
    prefix_a = _GLOB_META_RE.split(a, maxsplit=1)[0].rstrip("/")
    prefix_b = _GLOB_META_RE.split(b, maxsplit=1)[0].rstrip("/")
    if not prefix_a or not prefix_b:
        return True
    if prefix_a == prefix_b or prefix_a.startswith(prefix_b + "/") or prefix_b.startswith(prefix_a + "/"):
        return True
    return fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a)


def _pattern_covered_by_set(child_pat: str, parent_patterns: list[str]) -> bool:
    c = _norm_glob_pat(child_pat)
    c_prefix = _GLOB_META_RE.split(c, maxsplit=1)[0].rstrip("/")
    for raw_p in parent_patterns:
        p = _norm_glob_pat(raw_p)
        if p in {"*", "**"} or c == p:
            return True
        if p.endswith("/**"):
            base = p[:-3]
            if c_prefix and (c_prefix == base or c_prefix.startswith(base + "/")):
                return True
        if not _GLOB_META_RE.search(c) and fnmatch.fnmatchcase(c, p):
            return True
    return False


def _unguarded_paths_exist(
    entry_node_id: str,
    target_node_id: str,
    nodes_by_id: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    hitl_gates: list[dict[str, Any]],
) -> bool:
    """O(V + E) global-visited BFS: return True if ANY transition sequence reaches target_node_id
    from entry_node_id without crossing an HITL gate whose coversSideEffects includes external_side_effect.
    """
    guarded_before: set[str] = set()
    guarded_after: set[str] = set()
    guarded_edges: set[str] = set()
    for gate in hitl_gates:
        covers = gate.get("coversSideEffects") or []
        if "external_side_effect" not in covers:
            continue
        placement = gate.get("placement")
        if placement == "before_node" and gate.get("attachToNodeId"):
            guarded_before.add(gate["attachToNodeId"])
        elif placement == "after_node" and gate.get("attachToNodeId"):
            guarded_after.add(gate["attachToNodeId"])
        elif placement == "on_edge" and gate.get("edgeId"):
            guarded_edges.add(gate["edgeId"])

    if entry_node_id in guarded_before or target_node_id in guarded_before:
        return False

    adj: dict[str, list[tuple[str | None, str]]] = {}
    # Include all directed edges (including rework_feedback)
    for edge in edges:
        adj.setdefault(edge["fromNodeId"], []).append((edge["edgeId"], edge["toNodeId"]))
    # Include node onFailure fallback routes
    for nid, node in nodes_by_id.items():
        fail_route = (node.get("onFailure") or {}).get("route")
        if isinstance(fail_route, str) and fail_route in nodes_by_id and fail_route != nid:
            adj.setdefault(nid, []).append((None, fail_route))
    # Include HITL gate onReject routes from attached nodes/edges
    for gate in hitl_gates:
        reject_route = (gate.get("onReject") or {}).get("route")
        if not isinstance(reject_route, str) or reject_route not in nodes_by_id:
            continue
        attach = gate.get("attachToNodeId")
        if isinstance(attach, str) and attach in nodes_by_id:
            adj.setdefault(attach, []).append((None, reject_route))

    visited: set[str] = {entry_node_id}
    queue: deque[str] = deque([entry_node_id])
    while queue:
        cur = queue.popleft()
        if cur == target_node_id:
            return True
        if cur in guarded_after:
            continue
        for edge_id, nxt in adj.get(cur, []):
            if edge_id is not None and edge_id in guarded_edges:
                continue
            if nxt in guarded_before:
                continue
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def evaluate_blueprint_document(blueprint: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate and audit an OrchestrationBlueprint, returning (audit_report, professional_conclusion)."""
    val = _call_contracts_bridge("validate-blueprint", {"doc": blueprint})
    if not val.get("valid"):
        first = (val.get("errors") or [{}])[0]
        raise ValueError(
            f"BLUEPRINT_SCHEMA_INVALID:{first.get('instancePath', '$')}:{first.get('message', 'invalid')}"
        )
    bp_digest = val["digest"]
    findings: list[dict[str, Any]] = []

    tools_by_id = {t["toolId"]: t for t in blueprint.get("toolContracts", [])}
    nodes_by_id = {n["nodeId"]: n for n in blueprint.get("nodes", [])}
    edges = blueprint.get("edges", [])
    hitl_gates = blueprint.get("hitlGates", [])

    # 1. BP-SELF-REVIEW & Veto Model Tier Gate
    for node in blueprint.get("nodes", []):
        nid = node["nodeId"]
        role = node["role"]
        authority = node.get("decisionAuthority")
        model_tier = node.get("modelTier")

        if (authority == "final_veto" or role in {"reviewer", "approver"}) and model_tier == "fast_lightweight":
            findings.append({
                "ruleId": "BP-SELF-REVIEW",
                "severity": "critical",
                "nodeId": nid,
                "summary": f"审阅或终裁节点 {nid}（role={role}, authority={authority}）严禁降级使用轻量模型档位 fast_lightweight",
            })

        if role != "reviewer":
            continue
        bad_reasons: list[str] = []
        if node["sideEffectCeiling"] != "read_only":
            bad_reasons.append(f"sideEffectCeiling={node['sideEffectCeiling']}（必须为 read_only）")
        if node.get("allowedWriteSet"):
            bad_reasons.append(f"allowedWriteSet 非空：{node['allowedWriteSet']}")
        mutating_tools = [
            tid
            for tid in node.get("allowedTools", [])
            if tools_by_id.get(tid, {}).get("sideEffectClass") != "read_only"
        ]
        if mutating_tools:
            bad_reasons.append(f"绑定了非只读工具：{mutating_tools}")
        ctx_mode = node["isolation"]["contextMode"]
        if ctx_mode != "fresh":
            bad_reasons.append(f"审阅节点 isolation.contextMode={ctx_mode}（必须为 fresh，禁止 forked 或 summary_handoff）")
        degrade_rules = [
            fb for fb in node.get("hostFallbackPolicy", []) if fb.get("action") == "degrade_to_variant"
        ]
        if degrade_rules:
            bad_reasons.append("审阅节点禁止配置 degrade_to_variant 自动降级")
        indep = node.get("independence")
        if not isinstance(indep, dict) or not indep.get("forbidWriteTools") or not indep.get("requireFreshContext"):
            bad_reasons.append("缺少 independence(requireFreshContext=true, forbidWriteTools=true) 声明")
        if bad_reasons:
            findings.append({
                "ruleId": "BP-SELF-REVIEW",
                "severity": "critical",
                "nodeId": nid,
                "summary": f"审阅节点 {nid} 违反独立只读审阅约束：{'；'.join(bad_reasons)}",
            })

    # 2. BP-HITL-DOMINATOR
    entry_id = blueprint["entryNodeId"]
    for node in blueprint.get("nodes", []):
        nid = node["nodeId"]
        has_ext_tool = any(
            tools_by_id.get(tid, {}).get("sideEffectClass") == "external_side_effect"
            for tid in node.get("allowedTools", [])
        )
        if node["sideEffectCeiling"] == "external_side_effect" or has_ext_tool:
            if _unguarded_paths_exist(entry_id, nid, nodes_by_id, edges, hitl_gates):
                findings.append({
                    "ruleId": "BP-HITL-DOMINATOR",
                    "severity": "critical",
                    "nodeId": nid,
                    "summary": f"存在从入口 {entry_id} 未经覆盖 external_side_effect 的 HITL 门禁即可到达外部副作用节点 {nid} 的执行路径",
                })

    # 3. BP-PARALLEL-WRITE-DISJOINT (sibling overlap, fanOut>1 self-conflict, and parent->child write-set narrowing)
    for node in blueprint.get("nodes", []):
        nid = node["nodeId"]
        fan_out = node.get("fanOut")
        ws_mode = node["isolation"]["workspaceMode"]
        write_set = node.get("allowedWriteSet") or []
        if isinstance(fan_out, dict) and fan_out.get("maxConcurrency", 1) > 1 and ws_mode in {"share", "inherit"} and write_set:
            findings.append({
                "ruleId": "BP-PARALLEL-WRITE-DISJOINT",
                "severity": "high",
                "nodeId": nid,
                "summary": f"节点 {nid} 配置 fanOut(maxConcurrency={fan_out['maxConcurrency']}) 但使用共享工作区 {ws_mode} 且存在非空写集 {write_set}，并发分支将发生自写冲突",
            })

    spawn_targets_by_parent: dict[str, list[str]] = {}
    for edge in edges:
        if edge["edgeKind"] == "delegate_spawn":
            spawn_targets_by_parent.setdefault(edge["fromNodeId"], []).append(edge["toNodeId"])
            p_node = nodes_by_id.get(edge["fromNodeId"])
            c_node = nodes_by_id.get(edge["toNodeId"])
            if p_node and c_node:
                p_writes = p_node.get("allowedWriteSet") or []
                c_writes = c_node.get("allowedWriteSet") or []
                # If parent explicitly constrains its write set (non-empty), child write set cannot exceed parent
                if p_writes and c_writes:
                    escaped = [cw for cw in c_writes if not _pattern_covered_by_set(cw, p_writes)]
                    if escaped:
                        findings.append({
                            "ruleId": "BP-PARALLEL-WRITE-DISJOINT",
                            "severity": "critical",
                            "nodeId": c_node["nodeId"],
                            "summary": f"受托子节点 {c_node['nodeId']} 的 allowedWriteSet {escaped} 超出父节点 {p_node['nodeId']} 的授权写集 {p_writes}",
                        })

    for parent_id, child_ids in spawn_targets_by_parent.items():
        share_children = [
            nodes_by_id[cid]
            for cid in child_ids
            if cid in nodes_by_id and nodes_by_id[cid]["isolation"]["workspaceMode"] in {"share", "inherit"}
        ]
        for i in range(len(share_children)):
            for j in range(i + 1, len(share_children)):
                na, nb = share_children[i], share_children[j]
                overlaps = [
                    (pa, pb)
                    for pa in na.get("allowedWriteSet", [])
                    for pb in nb.get("allowedWriteSet", [])
                    if _patterns_overlap(pa, pb)
                ]
                if overlaps:
                    findings.append({
                        "ruleId": "BP-PARALLEL-WRITE-DISJOINT",
                        "severity": "high",
                        "nodeId": parent_id,
                        "summary": f"父节点 {parent_id} 并发派生的共享工作区子节点 {na['nodeId']} 与 {nb['nodeId']} 存在重叠写集：{overlaps}",
                    })

    # 4. BP-EVIDENCE-VERIFIER
    for ev in blueprint.get("expectedEvidence", []):
        if not ev.get("critical"):
            continue
        prod = ev.get("producedBy")
        ver = ev.get("verifiedBy")
        if not ver or ver == prod or ver not in nodes_by_id:
            findings.append({
                "ruleId": "BP-EVIDENCE-VERIFIER",
                "severity": "critical",
                "evidenceKey": ev["evidenceKey"],
                "summary": f"关键预期证据 {ev['evidenceKey']} 必须指定独立存在的核验节点（producedBy={prod}, verifiedBy={ver}）",
            })

    # 5. BP-CONTEXT-EAGER-BUDGET
    default_warn_bp = blueprint["budgetAndSafetyPolicy"]["contextPolicy"]["warnRatioBp"]
    for node in blueprint.get("nodes", []):
        nid = node["nodeId"]
        warn_bp = (node.get("contextPolicyOverride") or {}).get("warnRatioBp", default_warn_bp)
        eager_tokens = 0
        for sb in node.get("skillBindings", []):
            for ref in sb.get("references", []):
                if ref.get("loadPolicy") == "eager" and isinstance(ref.get("estimatedTokens"), int):
                    eager_tokens += ref["estimatedTokens"]
        max_eager = (DEFAULT_MODEL_WINDOW_TOKENS * warn_bp) // 10000
        if eager_tokens > max_eager:
            findings.append({
                "ruleId": "BP-CONTEXT-EAGER-BUDGET",
                "severity": "high",
                "nodeId": nid,
                "summary": f"节点 {nid} 的 eager 参考资料累计预估 {eager_tokens} tokens，超过窗口预警预算上限 {max_eager} tokens（{warn_bp} Bp）",
            })

    status = "FAILED" if findings else "SUCCEEDED"
    report = {
        "schemaVersion": 1,
        "kind": "skill-family-audit.blueprint-audit-report",
        "blueprintId": blueprint["blueprintId"],
        "skillFamilyId": blueprint["skillFamilyId"],
        "version": blueprint["version"],
        "blueprintDigestSha256": bp_digest,
        "status": status,
        "checkedRules": list(BLUEPRINT_RULE_IDS),
        "blockingFindingsCount": len(findings),
        "findings": findings,
    }
    conclusion = {
        "schemaVersion": 1,
        "kind": "skill-family.professional-conclusion",
        "provider": {
            "id": PROVIDER_ID,
            "version": _provider_version(),
            "entry": PROVIDER_ENTRY,
        },
        "subject": {
            "ref": f"pkg:{blueprint['skillFamilyId']}@{blueprint['version']}",
            "revision": f"sha256:{bp_digest}",
        },
        "scope": {
            "checked": list(BLUEPRINT_RULE_IDS),
            "limitations": [],
        },
        "outcome": {
            "completion": "complete",
            "code": "BLUEPRINT_AUDIT_CLEAR" if status == "SUCCEEDED" else "BLUEPRINT_AUDIT_FINDINGS",
            "summary": (
                "编排蓝图通过反自审、HITL 支配树、并发写集互斥、关键证据复核与上下文预算静态审计。"
                if status == "SUCCEEDED"
                else f"编排蓝图静态审计检出 {len(findings)} 项拓扑或权限违规。"
            ),
        },
        "details": report,
    }
    c_val = _call_contracts_bridge(
        "validate-conclusion",
        {"schemaId": PROFESSIONAL_CONCLUSION_SCHEMA_ID, "doc": conclusion},
    )
    if not c_val.get("valid"):
        raise RuntimeError(f"blueprint professional-conclusion invalid: {c_val.get('errors')}")
    return report, conclusion


def classify_target_profile(target_root: Path) -> str:
    """Classify a target skill-family repository into one of the three governance profiles."""
    if (target_root / "spec/methods").is_dir() or (target_root / "packages/skill-family-audit").is_dir():
        return "platform_governance_provider"
    for p in target_root.rglob("*.json"):
        if any(seg in p.parts for seg in (".git", "node_modules", "dist", "generated")):
            continue
        if p.name.endswith("blueprint.json"):
            return "orchestrated_multi_agent"
    return "general_skill_family"


def summarize_applicable_coverage(
    conformance_domain_result: dict[str, Any],
    *,
    target_profile: str | None = None,
    target_root: Path | None = None,
) -> dict[str, Any]:
    """Compute true applicable rule signal-to-noise metrics without altering the 282-rule ledger."""
    resolved_profile = (
        target_profile
        if target_profile is not None
        else (classify_target_profile(target_root) if target_root is not None else "general_skill_family")
    )
    if resolved_profile not in TARGET_PROFILES:
        raise ValueError(f"unknown target_profile: {resolved_profile}")
    rule_results = conformance_domain_result.get("conformance_result", {}).get("rule_results", [])
    total = len(rule_results)
    not_applicable = sum(1 for r in rule_results if r.get("status") == "NOT_APPLICABLE")
    applicable = total - not_applicable
    passed = sum(1 for r in rule_results if r.get("status") == "PASS")
    failed = sum(1 for r in rule_results if r.get("status") == "FAIL")
    evaluated_applicable = passed + failed
    applicable_coverage_bp = (evaluated_applicable * 10000 // applicable) if applicable > 0 else 10000
    applicable_density_bp = (applicable * 10000 // total) if total > 0 else 0
    return {
        "target_profile": resolved_profile,
        "total_in_scope_rules": total,
        "applicable_rule_count": applicable,
        "not_applicable_rule_count": not_applicable,
        "applicable_passed_count": passed,
        "applicable_failed_count": failed,
        "applicable_coverage_ratio_bp": applicable_coverage_bp,
        "applicable_density_bp": applicable_density_bp,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static P5 OrchestrationBlueprint semantic auditor")
    parser.add_argument("--blueprint", required=False, help="Absolute path to OrchestrationBlueprint JSON")
    parser.add_argument("--report-output", required=False, help="Optional exclusive output path for report JSON")
    parser.add_argument("--conclusion-output", required=False, help="Optional exclusive output path for professional-conclusion JSON")
    parser.add_argument("--summarize-conformance", required=False, help="Optional path to conformance domain result JSON")
    parser.add_argument("--target-root", required=False, help="Optional target repository root for automatic profile classification")
    args = parser.parse_args(argv)

    if args.summarize_conformance:
        conf_doc = json.loads(Path(args.summarize_conformance).resolve(strict=True).read_text(encoding="utf-8"))
        t_root = Path(args.target_root).resolve(strict=True) if args.target_root else None
        summary = summarize_applicable_coverage(conf_doc, target_root=t_root)
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if not args.blueprint:
        raise ValueError("--blueprint is required unless --summarize-conformance is specified")

    bp_path = Path(args.blueprint).resolve(strict=True)
    blueprint = json.loads(bp_path.read_text(encoding="utf-8"))
    report, conclusion = evaluate_blueprint_document(blueprint)

    for raw_out, payload in ((args.report_output, report), (args.conclusion_output, conclusion)):
        if not raw_out:
            continue
        out = Path(raw_out)
        if not out.is_absolute() or out.exists() or out.is_symlink():
            raise ValueError(f"Output path must be a new absolute path: {raw_out}")
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        finally:
            os.close(fd)

    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["status"] == "SUCCEEDED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
