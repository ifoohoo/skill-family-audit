#!/usr/bin/env python3
"""把两个只读 Audit 方法接到 Foundation Quickstart Profile v2。

Quickstart 只绑定调用方已经提供的证据文件。它可以启动 Audit 自身的领域
方法进程，但不得启动、观察、恢复、续接或调度受检目标。Task 创建、Result
包装与交换复验全部委托候选内的 Foundation runner；结果只经 stdout 或宿主
Result 返回，不创建任务、结果或路由收据目录。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


INTENTS = {
    "conformance": ("规范检查", "规范符合", "conformance", "规范结论"),
    "release": ("发布审计", "release"),
}
HUMAN_CONFORMANCE_INTENTS = (
    "准备发布",
    "发布准备",
    "冻结候选",
    "完整审计",
    "全量规范",
    "完整规范",
)
METHODS = {
    "conformance": "skill-family-audit:conformance-audit",
    "release": "skill-family-audit:release-audit",
}
SCRIPT_NAMES = {
    "conformance": "conformance_workflow.py",
    "release": "release_audit.py",
}
FORBIDDEN_METHOD_OPTIONS = {
    "fixture-manifest",
    "foundation-task-digest",
    "isolation-profile",
    "maturity-level",
    "observation-target-type",
    "observer",
    "output-dir",
    "plugin-project-observation",
    "profile-selection-reason",
    "recovery",
    "resume",
    "runtime-evidence",
    "runtime-schema-provider-root",
    "semantic-review-preflight",
    "semantic-review-stdin",
}
HUMAN_ROUTE_OPTIONS = {
    "canonical-rule-id",
    "execution-profile",
    "semantic-group-id",
    "semantic-selector",
}
METHOD_CLI_TO_PARAM_MAPPING: dict[str, dict[str, str]] = {
    "conformance": {
        "target": "target_project_path",
        "target-type": "scope_selector",
    },
    "release": {
        "target-project": "target_project_path",
        "assessments-ref": "assessments_ref",
    },
}
FOUNDATION_PROFILE_EXPECTED = {
    "id": "quickstart-profile",
    "version": 2,
    "taskContract": (
        "https://contracts.skill-family.example/"
        "quickstart-profile/v2/task.json"
    ),
    "resultContract": (
        "https://contracts.skill-family.example/"
        "quickstart-profile/v2/result.json"
    ),
}
_ABS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/[^\s」』”'\"）)]+")
_PROFILE_SCOPE = {
    "economy": "普通规范检查，只跑本地预筛，不调用语义模型",
    "mechanical": "只检查确定性规则",
    "targeted": "只检查请求中的精确规则或语义组",
    "full": "完整规范检查，包含确定性检查和实际语义审阅",
}


class RouteError(RuntimeError):
    """请求无法形成合法的只读 Audit Task。"""


def absolute_paths_in_request(request: str) -> list[str]:
    """从自然语言请求中提取规范化绝对路径，不去猜测相对目录。"""
    found: list[str] = []
    for match in _ABS_PATH_RE.finditer(request):
        value = match.group(0).rstrip("。．，,;；、")
        if os.path.isabs(value) and value not in found:
            found.append(value)
    return found


def identified_scope_statement(target: str, profile: str) -> str:
    """完整意图明确后，先说明已识别目标和范围。"""
    scope = _PROFILE_SCOPE.get(profile, profile)
    return "已识别目标 {}，检查范围：{}。开始执行。".format(target, scope)


def _locked_human_profile(request: str, method_args: list[str]) -> dict[str, Any]:
    """人类入口在问路径之前就把档位锁死；未出现完整/确定性/精确组时用 economy。"""
    intent = _human_intent(request)
    profiles = _option_values(method_args, "execution-profile")
    if len(profiles) > 1:
        raise RouteError("HUMAN_ROUTE_PROFILE_AMBIGUOUS")
    has_selectors = bool(
        _option_values(method_args, "canonical-rule-id")
        or _option_values(method_args, "semantic-selector")
        or _option_values(method_args, "semantic-group-id")
    )
    if profiles:
        profile, reason = profiles[0], "explicit_profile"
    elif intent == "release_preparation":
        profile, reason = "full", "release_preparation"
    elif intent == "complete_audit":
        profile, reason = "full", "complete_audit"
    elif has_selectors:
        profile, reason = (
            "targeted",
            "registered_group_name_group_id_or_canonical_rule_id",
        )
    elif intent == "deterministic_only":
        profile, reason = "mechanical", "deterministic_only"
    else:
        profile, reason = "economy", "ordinary_conformance"
    return {
        "ask_profile": False,
        "intent": intent,
        "execution_profile": profile,
        "selection_reason": reason,
    }


def _path_is_under(child: str, parent: str) -> bool:
    try:
        Path(child).relative_to(parent)
    except ValueError:
        return False
    return Path(child) != Path(parent)


def _usable_declared_units(
    products: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """只接受两个以上互不嵌套的声明发布单元；丢掉 generated 投影和产品子目录捷径。"""
    if not isinstance(products, list) or len(products) < 2:
        return []
    rows: list[dict[str, Any]] = []
    for product in products:
        name = product.get("name")
        path = product.get("path")
        difference = product.get("difference")
        if not isinstance(name, str) or not name:
            raise RouteError("PRODUCT_OPTION_INVALID")
        if not isinstance(path, str) or not path:
            raise RouteError("PRODUCT_OPTION_INVALID")
        if not isinstance(difference, str) or not difference:
            raise RouteError("PRODUCT_OPTION_INVALID")
        if "/generated/platforms/" in path.replace("\\", "/"):
            continue
        basis = product.get("recommend_basis")
        recommend = (
            product.get("recommend") is True
            and isinstance(basis, str)
            and bool(basis.strip())
        )
        rows.append({
            "name": name,
            "path": path,
            "difference": difference,
            "recommend": recommend,
            "recommend_basis": basis.strip() if recommend else "",
        })
    independent = [
        row
        for row in rows
        if not any(
            _path_is_under(row["path"], other["path"])
            for other in rows
            if other["path"] != row["path"]
        )
    ]
    if len(independent) < 2:
        return []
    return independent


def _is_workspace_root_of_units(
    path: str, units: list[dict[str, Any]]
) -> bool:
    """唯一路径是工作区根：含 ≥2 个独立单元，且自身不是其中任一产品路径。"""
    if len(units) < 2:
        return False
    root = Path(path)
    unit_paths = [Path(row["path"]) for row in units]
    if any(item == root for item in unit_paths):
        return False
    return all(_path_is_under(str(item), str(root)) for item in unit_paths)


def _product_choice_options(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    for product in units:
        recommended = product["recommend"] is True
        name = product["name"]
        path = product["path"]
        label = "{}（{}）".format(name, path)
        if recommended:
            label = "{}（推荐）".format(label)
        difference = product["difference"]
        basis = product.get("recommend_basis")
        if recommended and isinstance(basis, str) and basis:
            difference = "{} 推荐依据：{}。".format(difference.rstrip("。"), basis)
        options.append({
            "name": name,
            "label": label,
            "path": path,
            "difference": difference,
            "recommended": recommended,
        })
    return options


def _clarification_question(
    request: str,
    method_args: list[str],
    *,
    products: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    parsed = parse_method_args(method_args)
    if parsed.get("evidence-set") or parsed.get("target"):
        return None
    paths = absolute_paths_in_request(request)
    units = _usable_declared_units(products)
    options: list[dict[str, Any]] = []
    if len(paths) > 1:
        for path in paths:
            options.append({
                "name": path,
                "label": path,
                "path": path,
                "difference": "会检查该路径指向的项目；不会检查请求里的其他路径。",
                "recommended": False,
            })
    elif len(paths) == 1:
        if not _is_workspace_root_of_units(paths[0], units):
            return None
        options = _product_choice_options(units)
    else:
        options = _product_choice_options(units)
    if len(options) == 1:
        return None
    if options:
        options.sort(key=lambda row: (not row["recommended"], row["label"]))
        return {
            "question": "需要检查哪个项目？",
            "options": options,
        }
    return {
        "question": "需要检查哪个项目？请给出项目名称和路径。",
        "options": [],
    }


_HELP_ENTRY = "skill-family-audit:help"
_SETUP_ENTRY = "skill-family-audit:setup"


def _keeps_existing_audit_route(request: str, method_args: list[str]) -> bool:
    """完整审计、发布准备、确定性检查或已有精确选择器时，不转交。"""
    if _human_intent(request) != "ordinary_conformance":
        return True
    if any(
        _option_values(method_args, name)
        for name in (
            "canonical-rule-id",
            "semantic-selector",
            "semantic-group-id",
            "execution-profile",
        )
    ):
        return True
    lowered = request.lower()
    audit_terms = (
        *(term for terms in INTENTS.values() for term in terms),
        *HUMAN_CONFORMANCE_INTENTS,
    )
    return any(term.lower() in lowered for term in audit_terms)


def _existing_entry_handoff(request: str, method_args: list[str]) -> str | None:
    """只识别 Quickstart 正文已写明的能力咨询和 Audit 自身环境诊断。

    环境诊断优先于能力询问。不新增意图，也不把请求送进 conformance 人类路由。
    """
    if _keeps_existing_audit_route(request, method_args):
        return None
    text = request.strip()
    setup = (
        "运行环境" in text
        or "静态平台投影" in text
        or (
            "规范包" in text
            and any(token in text for token in ("诊断", "自身"))
        )
        or "环境诊断" in text
        or "先看看环境缺什么" in text
        or (
            "诊断" in text
            and "环境" in text
            and "不要开始审计" in text
        )
    )
    if setup:
        return _SETUP_ENTRY
    help_request = (
        "能做什么" in text
        or "适用范围" in text
        or "支持范围" in text
        or any(token in text for token in ("了解能力", "哪些能力", "什么能力", "有什么能力"))
        or any(token in text for token in ("了解依赖", "哪些依赖", "什么依赖", "有什么依赖"))
        or (
            "下一步" in text
            and any(token in text for token in ("了解", "能做", "先别", "？", "?"))
        )
    )
    if help_request:
        return _HELP_ENTRY
    return None


def human_entry_decision(
    request: str,
    method_args: list[str],
    *,
    products: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """宿主入口决策：两类咨询先转交；其余档位已定，只在缺少路径或多发布单元时提问。"""
    entry = _existing_entry_handoff(request, method_args)
    if entry is not None:
        return {
            "handoff": entry,
            "clarification": None,
        }
    locked = _locked_human_profile(request, method_args)
    return {
        **locked,
        "clarification": _clarification_question(
            request, method_args, products=products
        ),
    }


USER_VISIBLE_QUESTION_KEYS = ("question", "options")
USER_VISIBLE_OPTION_KEYS = ("name", "path", "difference", "recommended", "label")
USER_VISIBLE_PROFESSIONAL_QUESTION_KEYS = ("question", "options")
USER_VISIBLE_PROFESSIONAL_OPTION_KEYS = (
    "name",
    "purpose",
    "limitation",
    "recommended",
    "label",
    "entry_ref",
    "proof_present",
)
PROFESSIONAL_SCAN_QUESTION = "本次要加入哪些专业检查？可多选，也可暂不扫描。"
PROFESSIONAL_SCAN_UNANSWERED = "unanswered"
PROFESSIONAL_SCAN_EMPTY = "empty"
PROFESSIONAL_SCAN_SELECTED = "selected"
PROFESSIONAL_SCAN_NO_QUESTION = "no_question"


def human_entry_clarification(
    request: str,
    method_args: list[str],
    *,
    products: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """面向用户的问题 payload：只有 question 与 options。

    不询问档位、证据 JSON、临时目录或规范包。内部 intent、档位、方法编号
    不进入本返回值；宿主程序读 human_entry_decision。products 只接受两个
    以上互不嵌套的声明发布单元。
    """
    decision = human_entry_decision(request, method_args, products=products)
    return decision["clarification"]


def _professional_candidate_rows(
    candidates: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Normalize host-provided session candidates; never execute commands."""
    if candidates is None:
        return []
    if not isinstance(candidates, list):
        raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict):
            raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
        ident = item.get("id")
        name = item.get("name")
        purpose = item.get("purpose")
        limitation = item.get("limitation")
        available = item.get("available")
        if (
            not isinstance(ident, str)
            or not ident.strip()
            or not isinstance(name, str)
            or not name.strip()
            or not isinstance(purpose, str)
            or not purpose.strip()
            or not isinstance(limitation, str)
            or not limitation.strip()
            or not isinstance(available, bool)
        ):
            raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
        ident = ident.strip()
        if ident in seen:
            raise RouteError("PROFESSIONAL_SCAN_ID_DUPLICATE")
        seen.add(ident)
        entry_ref = item.get("entry_ref")
        if entry_ref is None:
            entry_ref = ""
        if not isinstance(entry_ref, str):
            raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
        entry_ref = entry_ref.strip()
        basis = item.get("recommend_basis")
        recommend = (
            item.get("recommend") is True
            and isinstance(basis, str)
            and bool(basis.strip())
        )
        kind = item.get("kind") if isinstance(item.get("kind"), str) else ""
        unavailable_reason = item.get("unavailable_reason")
        if not isinstance(unavailable_reason, str):
            unavailable_reason = ""
        next_step = item.get("next_step")
        if not isinstance(next_step, str):
            next_step = ""
        proof_present = item.get("proof_present") is True
        recheck_requested = item.get("recheck_requested") is True
        scan_available = available is True and bool(entry_ref)
        if proof_present and not recheck_requested:
            role = "reuse"
        elif scan_available:
            role = "selectable"
        else:
            role = "unavailable"
            if not unavailable_reason:
                if not available:
                    unavailable_reason = "当前没有可用的只读专业入口。"
                elif not entry_ref:
                    unavailable_reason = "没有公开只读入口，不能虚构可调用入口。"
        if role == "unavailable" and not next_step:
            next_step = (
                "记录专业能力缺口，继续其他检查；"
                "不要手写通过证明，也不要在 Audit 内补造检查器。"
            )
        rows.append({
            "id": ident,
            "name": name.strip(),
            "purpose": purpose.strip(),
            "limitation": limitation.strip(),
            "available": available,
            "entry_ref": entry_ref,
            "proof_present": proof_present,
            "recheck_requested": recheck_requested,
            "recommend": recommend,
            "recommend_basis": basis.strip() if recommend else "",
            "kind": kind.strip(),
            "unavailable_reason": unavailable_reason.strip(),
            "next_step": next_step.strip(),
            "role": role,
        })
    return rows


_DEFAULT_CATALOG_EXCLUDED_IDS = frozenset({"sfa", "failure_diagnosis"})
_DEFAULT_CATALOG_EXCLUDED_KINDS = frozenset({"failure", "failure_diagnosis", "sfa"})


def _locate_professional_provider_manifest() -> Path:
    """从本文件已解析路径向上找清单；不接受符号链接。"""
    here = Path(__file__).resolve()
    nearest_platform: Path | None = None
    source_manifest: Path | None = None
    for ancestor in here.parents:
        if nearest_platform is None:
            candidate = ancestor / "platform-manifest.json"
            if candidate.is_file() and not candidate.is_symlink():
                nearest_platform = candidate
        if source_manifest is None and (ancestor / "generated" / "platforms").is_dir():
            candidate = ancestor / "plugin-src" / "manifest.json"
            if candidate.is_file() and not candidate.is_symlink():
                source_manifest = candidate
    chosen = nearest_platform or source_manifest
    if chosen is None:
        raise RouteError("PROFESSIONAL_PROVIDERS_MISSING")
    return chosen


def _load_current_professional_provider_rows() -> list[dict[str, Any]]:
    """已加载的 conformance_check 优先，否则按平台清单、源码清单定位。"""
    host = sys.modules.get("conformance_check")
    if host is not None and hasattr(host, "load_professional_provider_rows"):
        try:
            rows = host.load_professional_provider_rows()
        except RuntimeError as exc:
            message = str(exc)
            if "PROFESSIONAL_PROVIDERS_MISSING" in message:
                raise RouteError("PROFESSIONAL_PROVIDERS_MISSING") from exc
            raise RouteError(message) from exc
        if not isinstance(rows, list) or not rows:
            raise RouteError("PROFESSIONAL_PROVIDERS_MISSING")
        return rows
    document = load(_locate_professional_provider_manifest())
    rows = document.get("professionalProviders")
    if not isinstance(rows, list) or not rows:
        raise RouteError("PROFESSIONAL_PROVIDERS_MISSING")
    return rows


def _catalog_text(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
    return value.strip()


def _candidates_from_professional_providers(
    *,
    registry_adopted: bool,
) -> list[dict[str, Any]]:
    """从当前清单构造候选。entry_ref 只用 scanEntryRef；没有入口则不可选。"""
    candidates: list[dict[str, Any]] = []
    for row in _load_current_professional_provider_rows():
        if not isinstance(row, dict):
            raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
        ident = row.get("id")
        if not isinstance(ident, str) or not ident.strip():
            raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
        ident = ident.strip()
        kind = row.get("kind") if isinstance(row.get("kind"), str) else ""
        kind = kind.strip()
        if ident in _DEFAULT_CATALOG_EXCLUDED_IDS or kind in _DEFAULT_CATALOG_EXCLUDED_KINDS:
            continue
        if not registry_adopted and (ident == "registry" or kind == "registry"):
            continue
        entry = row.get("scanEntryRef")
        if entry is None:
            entry = ""
        if not isinstance(entry, str):
            raise RouteError("PROFESSIONAL_SCAN_CANDIDATE_INVALID")
        entry = entry.strip()
        candidates.append({
            "id": ident,
            "name": _catalog_text(row, "name"),
            "purpose": _catalog_text(row, "purpose"),
            "limitation": _catalog_text(row, "limitation"),
            "available": bool(entry),
            "entry_ref": entry,
            "kind": kind,
            "proof_present": False,
            "recheck_requested": False,
            "recommend": False,
        })
    return candidates


def _professional_scan_rows(
    candidates: list[dict[str, Any]] | None,
    *,
    registry_adopted: bool,
) -> list[dict[str, Any]]:
    if candidates is None:
        candidates = _candidates_from_professional_providers(
            registry_adopted=registry_adopted
        )
    return _professional_candidate_rows(candidates)


def _professional_scan_options(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    for row in rows:
        if row["role"] != "selectable":
            continue
        purpose = row["purpose"]
        if row["recommend"]:
            purpose = "{} 推荐依据：{}。".format(
                purpose.rstrip("。"), row["recommend_basis"]
            )
        label = row["name"]
        if row["recommend"]:
            label = "{}（推荐）".format(label)
        options.append({
            "name": row["name"],
            "purpose": purpose,
            "limitation": row["limitation"],
            "recommended": row["recommend"],
            "label": label,
            "entry_ref": row["entry_ref"],
            "proof_present": row["proof_present"],
        })
    options.sort(key=lambda item: (not item["recommended"], item["label"]))
    return options


def professional_scan_clarification(
    candidates: list[dict[str, Any]] | None,
    *,
    registry_adopted: bool = False,
) -> dict[str, Any] | None:
    """面向用户的专业扫描多选：只有 question 与 options。

    candidates 为 None 时从当前清单构造候选，不表示没有候选。显式 [] 才是没有候选。
    与 human_entry_clarification 的产品单选分开。无可用扫描选项时返回 None。
    选项含公开入口 entry_ref 和已有证明 proof_present，不含内部标识、证据 JSON或临时路径。
    不读证明，不验证证明。推荐不会预提交。
    已传入的候选列表忽略 registry_adopted。
    """
    options = _professional_scan_options(
        _professional_scan_rows(candidates, registry_adopted=registry_adopted)
    )
    if not options:
        return None
    return {
        "question": PROFESSIONAL_SCAN_QUESTION,
        "options": options,
    }


def professional_scan_decision(
    candidates: list[dict[str, Any]] | None,
    selection: list[str] | None = None,
    *,
    registry_adopted: bool = False,
) -> dict[str, Any]:
    """把专业扫描选择交回宿主；不执行扫描、不检查证明、不创建 Task。

    candidates 为 None 时从当前清单构造候选；找不到清单抛
    PROFESSIONAL_PROVIDERS_MISSING，不得当成无可选项并允许开始。显式 []
    仍是没有候选。仅当确有可选项且 selection 为 None 时表示尚未回答，不得开始。
    真正没有可选项时沿现有 no_question、can_start_audit=True 继续，并说明现成
    证明复用、入口不可用或无适用项。适用缺证仍未通过。[] 表示显式空选择，可以
    继续 Audit，但不表示通过或不适用；非空列表为已选标识。推荐项不会预填为授权。
    已传入的候选列表忽略 registry_adopted。
    """
    rows = _professional_scan_rows(candidates, registry_adopted=registry_adopted)
    by_id = {row["id"]: row for row in rows}
    selectable = [row for row in rows if row["role"] == "selectable"]
    reused = [row for row in rows if row["role"] == "reuse"]
    unavailable = [row for row in rows if row["role"] == "unavailable"]
    clarification = professional_scan_clarification(
        candidates, registry_adopted=registry_adopted
    )
    authorized: list[dict[str, Any]] = []
    if selection is None:
        if selectable:
            answer_state = PROFESSIONAL_SCAN_UNANSWERED
            can_start = False
        else:
            answer_state = PROFESSIONAL_SCAN_NO_QUESTION
            can_start = True
    else:
        if not isinstance(selection, list) or any(
            not isinstance(item, str) or not item.strip() for item in selection
        ):
            raise RouteError("PROFESSIONAL_SCAN_SELECTION_INVALID")
        chosen = [item.strip() for item in selection]
        seen: set[str] = set()
        for ident in chosen:
            if ident in seen:
                raise RouteError(f"PROFESSIONAL_SCAN_DUPLICATE_SELECTION:{ident}")
            seen.add(ident)
            row = by_id.get(ident)
            if row is None:
                raise RouteError(f"PROFESSIONAL_SCAN_UNKNOWN:{ident}")
            if row["role"] != "selectable":
                raise RouteError(f"PROFESSIONAL_SCAN_UNAVAILABLE:{ident}")
            authorized.append({
                "id": row["id"],
                "name": row["name"],
                "entry_ref": row["entry_ref"],
                "purpose": row["purpose"],
                "limitation": row["limitation"],
            })
        if chosen:
            answer_state = PROFESSIONAL_SCAN_SELECTED
            can_start = True
        elif selectable:
            answer_state = PROFESSIONAL_SCAN_EMPTY
            can_start = True
        else:
            answer_state = PROFESSIONAL_SCAN_NO_QUESTION
            can_start = True
    limitation = ""
    next_step = (
        "由宿主按已核实的只读入口执行选中的专业扫描，收集材料后再创建 Audit Task。"
    )
    if not selectable:
        if unavailable and not reused:
            limitation = "；".join(
                "{}：{}".format(row["name"], row["unavailable_reason"])
                for row in unavailable
            )
            next_step = unavailable[0]["next_step"]
        elif reused and not unavailable:
            limitation = "已有专业证明默认复用，不默认重新扫描。"
            next_step = "继续 Audit，汇总已有证明覆盖的结论；本入口不检查证明真伪。"
        elif reused and unavailable:
            limitation = "已有证明默认复用；其余专业入口不可用，不能虚构可调用入口。"
            next_step = (
                "继续 Audit；不可用项记录缺口。"
                "适用且无扫描、无证明的项目记为未通过，不把未选当成不适用。"
            )
        else:
            limitation = "当前没有可加入的专业扫描候选。"
            next_step = (
                "继续 Audit；适用项没有扫描结果或证明时记为未通过，"
                "不把未选当成不适用。"
            )
    elif unavailable:
        limitation = "；".join(
            "{}：{}".format(row["name"], row["unavailable_reason"])
            for row in unavailable
        )
    return {
        "answer_state": answer_state,
        "can_start_audit": can_start,
        "authorized_scans": authorized,
        "reused_proofs": [
            {
                "id": row["id"],
                "name": row["name"],
                "purpose": row["purpose"],
                "limitation": row["limitation"],
            }
            for row in reused
        ],
        "unavailable": [
            {
                "id": row["id"],
                "name": row["name"],
                "reason": row["unavailable_reason"],
                "next_step": row["next_step"],
            }
            for row in unavailable
        ],
        "empty_selection_authorizes_scan": False,
        "empty_selection_means_pass": False,
        "empty_selection_means_not_applicable": False,
        "clarification": clarification,
        "limitation": limitation,
        "next_step": next_step,
    }


def load_professional_providers(manifest_path: Path | None = None) -> list[dict[str, Any]]:
    """Provider descriptors come only from the current platform or source manifest."""
    host = sys.modules.get("conformance_check")
    if manifest_path is None:
        if host is not None and hasattr(host, "load_professional_provider_rows"):
            try:
                return host.load_professional_provider_rows()
            except RuntimeError as exc:
                raise RouteError(str(exc)) from exc
        raise RouteError("PROFESSIONAL_PROVIDERS_MISSING")
    document = load(manifest_path)
    rows = document.get("professionalProviders")
    if not isinstance(rows, list) or not rows:
        raise RouteError("PROFESSIONAL_PROVIDERS_MISSING")
    return rows


def consume_professional_proof(payload: dict[str, Any]) -> dict[str, Any]:
    """Read a locatable proof via the host adapter; do not execute commands."""
    host = sys.modules.get("conformance_check")
    if host is None or not hasattr(host, "consume_professional_proof"):
        raise RouteError("PROFESSIONAL_PROOF_ADAPTER_MISSING")
    try:
        return host.consume_professional_proof(payload)
    except (RuntimeError, TypeError) as exc:
        raise RouteError(str(exc)) from exc


def _load_conformance_workflow():
    """从同一平台包装载 workflow，复用 `_derived_evidence_set` 既有签名。"""
    loaded = sys.modules.get("conformance_workflow")
    if loaded is not None and hasattr(loaded, "_derived_evidence_set"):
        return loaded
    host = sys.modules.get("conformance_check")
    host_file = getattr(host, "__file__", None)
    if not isinstance(host_file, str):
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    module_path = Path(host_file).resolve().parent / "conformance_workflow.py"
    if module_path.is_symlink() or not module_path.is_file():
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    spec = importlib.util.spec_from_file_location(
        "skill_family_audit_conformance_workflow_for_entry", module_path
    )
    if spec is None or spec.loader is None:
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    module = importlib.util.module_from_spec(spec)
    if str(module_path.parent) not in sys.path:
        sys.path.insert(0, str(module_path.parent))
    spec.loader.exec_module(module)
    return module


def prepare_conformance_evidence_document(target: Path) -> dict[str, Any]:
    """创建 Task 前从目标路径派生真实证据集合；不写入文件。"""
    if not isinstance(target, Path):
        target = Path(target)
    raw = str(target)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise RouteError("target 必须是规范化绝对路径")
    if target.is_symlink():
        raise RouteError("target 不得是符号链接")
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise RouteError(f"target 不可用: {exc}") from exc
    if not resolved.is_dir() and not resolved.is_file():
        raise RouteError("target 必须是真实目录或普通文件")
    workflow = _load_conformance_workflow()
    evidence_set = workflow._derived_evidence_set(resolved)
    if not isinstance(evidence_set, list) or not evidence_set:
        raise RouteError("DERIVED_EVIDENCE_SET_EMPTY")
    return {"evidence_set": evidence_set}


def runtime_setup_advice(error: str) -> str:
    """缺运行时只指向 setup，不自动安装。"""
    return (
        "运行时或 Foundation Bundle 不可用：{}。"
        "请先调用 skill-family-audit:setup 查看诊断，不要自动安装 Node 或依赖。"
    ).format(error)


def is_pre_rule_selection_failure(response: dict[str, Any]) -> bool:
    domain = response.get("conformance_result") if isinstance(response, dict) else None
    return (
        isinstance(domain, dict)
        and domain.get("status") == "BLOCKED"
        and domain.get("failure_stage") == "before_rule_selection"
    )


def _foundation_host(runner: Path | None = None):
    host = sys.modules.get("conformance_check")
    if host is None:
        raise RouteError("FOUNDATION_TRANSPORT_MISSING")
    return host.foundation_host_for(__file__, runner)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RouteError("JSON 顶层必须是对象")
    return value


def _trusted_input_file(value: str | None, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
    ):
        raise RouteError(f"{label} 必须是规范化绝对路径")
    raw = Path(value)
    if raw.is_symlink():
        raise RouteError(f"{label} 不得是符号链接")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise RouteError(f"{label} 不可用: {exc}") from exc
    if resolved != raw or not resolved.is_file():
        raise RouteError(f"{label} 必须是真实普通文件")
    return resolved


# 只承认「检查……是否符合规范」这一词序，间隔不跨句。
# 「不符合规范」不含「是否符合规范」，否定的发布说法不会因此变成符合性检查。
_CONFORMANCE_WORD_ORDER = re.compile(
    r"检查[^。！？!?\n]{0,160}是否符合规范"
)


def select_intent(request: str) -> str:
    matches = [
        name
        for name, terms in INTENTS.items()
        if any(term.lower() in request.lower() for term in terms)
    ]
    if "conformance" not in matches and _CONFORMANCE_WORD_ORDER.search(request):
        matches.append("conformance")
    if not matches and any(term in request.lower() for term in HUMAN_CONFORMANCE_INTENTS):
        return "conformance"
    if len(matches) != 1:
        raise RouteError("INTENT_AMBIGUOUS" if matches else "INTENT_UNRECOGNIZED")
    return matches[0]


def parse_method_args(method_args: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    index = 0
    while index < len(method_args):
        item = method_args[index]
        if item.startswith("--") and index + 1 < len(method_args):
            parsed[item[2:]] = method_args[index + 1]
            index += 2
        else:
            index += 1
    return parsed


def _option_values(method_args: list[str], option: str) -> list[str]:
    """Return every value supplied for one value-taking CLI option."""
    values: list[str] = []
    index = 0
    expected = f"--{option}"
    while index < len(method_args):
        if method_args[index] == expected:
            if index + 1 >= len(method_args) or method_args[index + 1].startswith("--"):
                raise RouteError(f"METHOD_OPTION_VALUE_MISSING:{option}")
            values.append(method_args[index + 1])
            index += 2
        else:
            index += 1
    return values


def _without_options(method_args: list[str], options: set[str]) -> list[str]:
    """Remove Quickstart-only value options before invoking the domain method."""
    result: list[str] = []
    index = 0
    while index < len(method_args):
        item = method_args[index]
        if item.startswith("--") and item[2:] in options:
            if index + 1 >= len(method_args):
                raise RouteError(f"METHOD_OPTION_VALUE_MISSING:{item[2:]}")
            index += 2
        else:
            result.append(item)
            index += 1
    return result


def _foundation_strict_json(
    runner: Path, path: Path, label: str
) -> tuple[dict[str, Any], str]:
    try:
        receipt = call_foundation(
            runner,
            "read-file-strict",
            {"root": str(path.parent), "path": path.name, "encoding": "utf8"},
        )
        content = receipt.get("content")
        digest = receipt.get("sha256")
        if (
            not isinstance(content, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RouteError(f"{label}_STRICT_READ_INVALID")
        value = json.loads(content)
    except (OSError, json.JSONDecodeError, RouteError) as exc:
        if isinstance(exc, RouteError):
            raise
        raise RouteError(f"{label}_STRICT_READ_INVALID:{exc}") from exc
    if not isinstance(value, dict):
        raise RouteError(f"{label}_STRICT_READ_INVALID")
    return value, digest


def _load_source_dispositions(
    runner: Path, projection_path: Path
) -> tuple[list[Any] | None, str | None, str | None]:
    """Strict-read the 旧编号去向 segment of the public canonical projection.

    Returns ``(rows, reason, digest)``. 缺失、不可读或结构非法时返回
    ``rows=None`` 与原因；此时已在当前清单内的编号不受影响，未命中的请求仍按
    既有 ``unresolved_selector`` 失败关闭。本函数只读公开投影，不读私有库存。
    """
    if projection_path.is_symlink() or not projection_path.is_file():
        return None, "projection_missing", None
    try:
        projection, digest = _foundation_strict_json(
            runner, projection_path, "HUMAN_ROUTE_DISPOSITIONS"
        )
    except RouteError:
        return None, "projection_unreadable", None
    rows = projection.get("source_dispositions")
    if not isinstance(rows, list) or not rows:
        return None, "dispositions_absent", digest
    return rows, None, digest


def _load_human_route_module(
    runner: Path,
) -> tuple[Any, dict[str, Any], list[str], dict[str, str], tuple[Any, ...]]:
    """Load the conformance-owned route helpers and their managed authorities."""
    host = sys.modules.get("conformance_check")
    host_file = getattr(host, "__file__", None)
    if not isinstance(host_file, str):
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    scripts = Path(host_file).resolve().parent
    module_path = scripts / "conformance_human_route.py"
    refs = scripts.parent / "refs"
    registry_path = refs / "semantic-rule-groups.json"
    routing_path = refs / "method-assurance-trust-projection.json"
    if any(path.is_symlink() or not path.is_file() for path in (module_path, registry_path, routing_path)):
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    spec = importlib.util.spec_from_file_location(
        "skill_family_audit_conformance_human_route", module_path
    )
    if spec is None or spec.loader is None:
        raise RouteError("HUMAN_ROUTE_SUPPORT_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    registry, registry_digest = _foundation_strict_json(
        runner, registry_path, "HUMAN_ROUTE_REGISTRY"
    )
    routing, routing_file_digest = _foundation_strict_json(
        runner, routing_path, "HUMAN_ROUTE_ROUTING"
    )
    trust_projection_digest = routing.get("projection_digest")
    if (
        not isinstance(trust_projection_digest, str)
        or len(trust_projection_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in trust_projection_digest
        )
    ):
        raise RouteError("HUMAN_ROUTE_ROUTING_INVALID")
    first_tier_static = routing.get("routing", {}).get("first_tier_static")
    if not isinstance(first_tier_static, list):
        raise RouteError("HUMAN_ROUTE_ROUTING_INVALID")
    deterministic_rule_ids = sorted({
        row.get("canonical_id")
        for row in first_tier_static
        if isinstance(row, dict) and isinstance(row.get("canonical_id"), str)
    })
    if len(deterministic_rule_ids) != len(first_tier_static):
        raise RouteError("HUMAN_ROUTE_ROUTING_INVALID")
    return module, registry, deterministic_rule_ids, {
        "registry_digest": registry_digest,
        "routing_file_digest": routing_file_digest,
        "trust_projection_digest": trust_projection_digest,
    }, _load_source_dispositions(runner, refs / "canonical-rule-projection.json")


def _human_intent(request: str) -> str:
    normalized = request.lower()
    if any(token in normalized for token in ("准备发布", "发布准备", "冻结候选")):
        return "release_preparation"
    if any(token in normalized for token in ("完整审计", "全量规范", "完整规范")):
        return "complete_audit"
    if any(token in normalized for token in ("确定性", "静态合同", "schema", "摘要")):
        return "deterministic_only"
    return "ordinary_conformance"


def _request_selectors(request: str, registry: dict[str, Any]) -> list[str]:
    """Extract only exact registered selector text from a human request."""
    candidates: list[str] = []
    for group in registry.get("groups", []):
        if not isinstance(group, dict):
            continue
        for value in (group.get("group_id"), group.get("name")):
            if isinstance(value, str) and value and value in request:
                candidates.append(value)
        for rule in group.get("rules", []):
            value = rule.get("canonical_id") if isinstance(rule, dict) else None
            if isinstance(value, str) and value and value in request:
                candidates.append(value)
    return candidates


def resolve_conformance_human_route(
    request: str, method_args: list[str], runner: Path
) -> tuple[dict[str, Any], dict[str, Any], Any, str, dict[str, str]]:
    """Materialize one human-facing profile before Task creation."""
    (
        module,
        registry,
        deterministic_rule_ids,
        route_identity,
        dispositions_state,
    ) = _load_human_route_module(runner)
    source_dispositions, dispositions_reason, _ = dispositions_state
    profiles = _option_values(method_args, "execution-profile")
    if len(profiles) > 1:
        raise RouteError("HUMAN_ROUTE_PROFILE_AMBIGUOUS")
    exact_rule_ids = _option_values(method_args, "canonical-rule-id")
    explicit_selectors = [
        *_option_values(method_args, "semantic-selector"),
        *_option_values(method_args, "semantic-group-id"),
    ]
    if exact_rule_ids and explicit_selectors:
        raise RouteError("HUMAN_ROUTE_INVALID:targeted_selection_ambiguous")
    selectors = (
        explicit_selectors
        if exact_rule_ids
        else [*explicit_selectors, *_request_selectors(request, registry)]
    )
    intent = _human_intent(request)
    _assert_source_numbers_runnable(
        module, source_dispositions, [*(exact_rule_ids or []), *selectors]
    )
    try:
        route = module.resolve_human_route(
            profiles[0] if profiles else None,
            intent,
            selectors,
            registry,
            deterministic_rule_ids,
            exact_rule_ids or None,
            source_dispositions,
        )
    except ValueError as exc:
        message = str(exc)
        if source_dispositions is None and any(
            code in message
            for code in ("unresolved_selector", "source_number_successor_unresolved")
        ):
            # 未命中且没有公开去向投影：保持既有失败形态，附上投影缺口语义。
            message = "{}（旧编号去向投影不可用：{}）".format(
                message, dispositions_reason
            )
        raise RouteError(f"HUMAN_ROUTE_INVALID:{message}") from exc
    return route, registry, module, intent, route_identity


def _assert_source_numbers_runnable(module, source_dispositions, requested_ids) -> None:
    """Fail closed when every requested 旧编号 has already exited.

    去向了结（已退出，或合并承接尚未生效）的编号只解释、不运行；当请求中没有任何
    可运行编号时，本次不产生检查结论，以明确解释失败关闭，而不是静默跑别的规则。
    """
    if source_dispositions is None or not requested_ids:
        return
    interpretation = module.interpret_source_numbers(requested_ids, source_dispositions)
    explanations = interpretation["explanations"]
    blocked = [row for row in explanations if not row["runnable"]]
    if not blocked:
        return
    explained = {row["source_id"] for row in explanations}
    if any(row["runnable"] for row in explanations):
        return
    if any(value not in explained for value in requested_ids):
        return
    raise RouteError(
        "HUMAN_ROUTE_SOURCE_NUMBER_EXITED:" + "；".join(row["detail"] for row in blocked)
    )


def assert_release_preparation_input(
    method_args: list[str], evidence_set: list[dict[str, Any]]
) -> None:
    """准备发布只接受一个冻结候选源码树。"""
    parsed = parse_method_args(method_args)
    source_trees = [
        row
        for row in evidence_set
        if isinstance(row, dict) and row.get("kind") == "source_tree"
    ]
    if (
        parsed.get("target-type") != "release_artifact"
        or len(evidence_set) != 1
        or len(source_trees) != 1
        or parsed.get("target") != source_trees[0].get("path")
    ):
        raise RouteError(
            "RELEASE_PREPARATION_INPUT_INVALID:准备发布需要 release_artifact、"
            "唯一 source_tree，且 --target 必须绑定同一候选目录"
        )


def extract_execution_plan(stderr: str) -> dict[str, Any]:
    prefix = "SFA_EXECUTION_PLAN "
    rows = [line[len(prefix):] for line in stderr.splitlines() if line.startswith(prefix)]
    if len(rows) != 1:
        raise RouteError("EXECUTION_PLAN_EVENT_INVALID")
    try:
        event = json.loads(rows[0])
    except json.JSONDecodeError as exc:
        raise RouteError("EXECUTION_PLAN_EVENT_INVALID") from exc
    if not isinstance(event, dict):
        raise RouteError("EXECUTION_PLAN_EVENT_INVALID")
    return event


def assert_plan_event_binding(
    plan: dict[str, Any],
    domain: dict[str, Any],
    route_identity: dict[str, str],
    canonical_rule_ids: list[str] | None = None,
) -> None:
    coverage = domain.get("coverage") or {}
    metrics = domain.get("execution_metrics") or {}
    assurance = domain.get("method_assurance")
    trusted_observation = (
        assurance.get("trusted_observation")
        if isinstance(assurance, dict)
        else None
    )
    selected_count = coverage.get("selected_count")
    deterministic_count = coverage.get("selected_deterministic_rule_count")
    selected_semantic_count = (
        selected_count - deterministic_count
        if isinstance(selected_count, int)
        and not isinstance(selected_count, bool)
        and isinstance(deterministic_count, int)
        and not isinstance(deterministic_count, bool)
        and selected_count >= deterministic_count
        else None
    )
    expected = {
        "kind": "skill-family-audit.execution-plan",
        "execution_profile": domain.get("execution_profile"),
        "target_digest": domain.get("target_digest"),
        "requested_semantic_group_ids": coverage.get(
            "requested_semantic_group_ids", []
        ),
        "canonical_rule_ids": sorted(canonical_rule_ids or []),
        "selected_semantic_group_ids": coverage.get(
            "selected_semantic_group_ids", []
        ),
        "selected_deterministic_rule_count": coverage.get(
            "selected_deterministic_rule_count"
        ),
        "selected_semantic_rule_count": selected_semantic_count,
        "semantic_rules_skipped_missing_evidence_count": metrics.get(
            "semantic_rules_skipped_missing_evidence_count", 0
        ),
        "semantic_group_registry_digest": route_identity["registry_digest"],
        "routing_file_digest": route_identity["routing_file_digest"],
        "trust_projection_digest": route_identity["trust_projection_digest"],
    }
    plan_fields = set(expected) | {
        "selection_reason",
        "estimated_context_count",
        "estimated_input_tokens",
        "semantic_input_budget",
    }
    if (
        set(plan) != plan_fields
        or selected_semantic_count is None
        or any(plan.get(key) != value for key, value in expected.items())
    ):
        raise RouteError("PLAN_EVENT_BINDING_MISMATCH")
    semantic_rules_sent = metrics.get("semantic_rules_sent_to_model_count", 0)
    if (
        coverage.get("semantic_group_registry_digest")
        != route_identity["registry_digest"]
        or not isinstance(assurance, dict)
        or "trust_projection_digest" in assurance
        or not isinstance(trusted_observation, dict)
        or trusted_observation.get("trust_projection_digest")
        != route_identity["trust_projection_digest"]
        or not isinstance(plan.get("selection_reason"), str)
        or not plan["selection_reason"]
        or not isinstance(plan.get("estimated_context_count"), int)
        or isinstance(plan.get("estimated_context_count"), bool)
        or plan["estimated_context_count"] < metrics.get(
            "semantic_context_count", 0
        )
        or not isinstance(plan.get("estimated_input_tokens"), int)
        or isinstance(plan.get("estimated_input_tokens"), bool)
        or plan["estimated_input_tokens"] < metrics.get(
            "estimated_input_tokens", 0
        )
        or not (
            semantic_rules_sent is None
            or (
                isinstance(semantic_rules_sent, int)
                and not isinstance(semantic_rules_sent, bool)
            )
        )
        or (
            isinstance(semantic_rules_sent, int)
            and plan["selected_semantic_rule_count"] < semantic_rules_sent
        )
        or (
            plan.get("execution_profile") in {"mechanical", "economy"}
            and plan.get("semantic_input_budget") != 0
        )
    ):
        raise RouteError("PLAN_EVENT_BINDING_MISMATCH")


def transport_summary(intent: str, state: str) -> str:
    if state == "succeeded":
        if intent == "conformance":
            return (
                "Audit 领域结果已完成传输；请以 domainResult 与 human_summary "
                "判断审计结论。"
            )
        return f"{METHODS[intent]} completed"
    return f"{METHODS[intent]} failed"


def domain_result_summary(response: dict[str, Any]) -> dict[str, str]:
    """Keep a bounded diagnostic summary when a domain result is invalid."""
    domain = response.get("conformance_result")
    if not isinstance(domain, dict):
        return {}
    return {
        key: value
        for key in ("status", "reason_code", "summary", "failure_stage")
        if isinstance((value := domain.get(key)), str) and value
    }


def execution_method_args(
    intent: str,
    method_args: list[str],
    operation_id: str,
    foundation_task_digest: str | None = None,
) -> list[str]:
    """Bind the conformance CLI identity to the enclosing Foundation Task."""
    if intent != "conformance":
        return list(method_args)
    declared = parse_method_args(method_args).get("run-id")
    if declared is not None and declared != operation_id:
        raise RouteError("METHOD_RUN_ID_MISMATCH")
    bound = list(method_args)
    if declared is None:
        bound.extend(["--run-id", operation_id])
    if foundation_task_digest is not None:
        if (
            not isinstance(foundation_task_digest, str)
            or len(foundation_task_digest) != 64
            or any(character not in "0123456789abcdef" for character in foundation_task_digest)
        ):
            raise RouteError("FOUNDATION_TASK_DIGEST_INVALID")
        bound.extend(["--foundation-task-digest", foundation_task_digest])
    return bound


def _conformance_evidence(path_value: str | None) -> tuple[Path, list[dict[str, Any]]]:
    path = _trusted_input_file(path_value, "evidence_set 文件")
    document = load(path)
    if set(document) != {"evidence_set"}:
        raise RouteError("EVIDENCE_SET_DOCUMENT_INVALID")
    evidence_set = document.get("evidence_set")
    if not isinstance(evidence_set, list) or not evidence_set:
        raise RouteError("EVIDENCE_SET_DOCUMENT_INVALID")
    return path, evidence_set


def extract_business_parameters(
    intent: str, method_args: list[str]
) -> tuple[dict[str, Any], Path]:
    parsed = parse_method_args(method_args)
    forbidden = sorted(set(parsed) & FORBIDDEN_METHOD_OPTIONS)
    if forbidden:
        raise RouteError(f"METHOD_OPTION_FORBIDDEN:{forbidden}")
    parameters: dict[str, Any] = {}
    for cli_name, field in METHOD_CLI_TO_PARAM_MAPPING[intent].items():
        if cli_name in parsed:
            parameters[field] = parsed[cli_name]

    if intent == "conformance":
        if not parsed.get("evidence-set"):
            raise RouteError(
                "EVIDENCE_SET_NOT_MATERIALIZED:自然语言入口须先调用 "
                "prepare_conformance_evidence_document，由宿主把派生证据集合"
                "写入目标外临时文件后再创建 Task；旧证据文件输入继续有效"
            )
        resource, evidence_set = _conformance_evidence(parsed.get("evidence-set"))
        parameters["evidence_set"] = evidence_set
        if parsed.get("professional-consumption"):
            consumption_path = _trusted_input_file(
                parsed.get("professional-consumption"),
                "professional consumption",
            )
            consumption = load(consumption_path)
            if "command" in consumption:
                raise RouteError("PROFESSIONAL_CONSUMPTION_COMMAND_REJECTED")
            parameters["professional_consumption"] = consumption
        if "scope_selector" in parameters:
            parameters["scope_selector"] = {
                "single_skill": "skill",
                "family_source": "plugin",
                "project_adoption": "plugin",
                "release_artifact": "release",
            }.get(parameters["scope_selector"], parameters["scope_selector"])
        return parameters, resource

    resource = _trusted_input_file(parsed.get("assessments-ref"), "assessments 文件")
    unit_id = parsed.get("unit-id")
    version = parsed.get("target-version")
    if not unit_id or not version:
        raise RouteError("METHOD_PARAM_MISSING:candidate_release_ref")
    parameters["candidate_release_ref"] = f"{unit_id}:{version}"
    return parameters, resource


def find_platform_manifest(explicit: str | None = None) -> Path:
    if explicit:
        return _trusted_input_file(explicit, "platform manifest")
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "platform-manifest.json"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise RouteError("PLATFORM_MANIFEST_MISSING")


def find_foundation_runner(
    explicit: str | None = None, *, platform_root: Path | None = None
) -> Path:
    raw = explicit or os.environ.get("SFA_AUDIT_BUNDLE_RUNNER_REF")
    if not raw and platform_root is not None:
        candidate = platform_root / "foundation/quickstart-profile/runner.mjs"
        if candidate.is_file() or candidate.is_symlink():
            raw = str(candidate)
    if not raw:
        raise RouteError(runtime_setup_advice("FOUNDATION_RUNNER_MISSING"))
    try:
        return _foundation_host(Path(raw)).verify_foundation_bundle(raw)
    except RuntimeError as exc:
        raise RouteError(runtime_setup_advice(str(exc))) from exc


def call_foundation(
    runner: Path, operation: str, payload: dict[str, Any]
) -> dict[str, Any]:
    try:
        return _foundation_host(runner).call_foundation_mechanism(
            runner, {"operation": operation, **payload}
        )
    except RuntimeError as exc:
        code = operation.upper().replace("-", "_")
        raise RouteError(f"FOUNDATION_{code}_FAILED:{exc}") from exc


def validate_by_schema_id(runner: Path, schema_id: str, document: Any) -> dict[str, Any]:
    """Validate one document through the ordered Foundation batch mechanism."""
    return validate_many_by_schema_id(runner, [(schema_id, document)])[0]


def validate_many_by_schema_id(
    runner: Path, requests: list[tuple[str, Any]]
) -> list[dict[str, Any]]:
    """Validate ordered consumer documents without copying Foundation validators."""
    if not requests or any(
        not isinstance(schema_id, str) or not schema_id
        for schema_id, _document in requests
    ):
        raise RouteError("FOUNDATION_VALIDATION_BATCH_INVALID")
    try:
        host = _foundation_host(runner)
        host.verify_foundation_bundle(str(runner.with_name("validators.mjs")))
        outcome = host.call_foundation_mechanism(
            runner,
            {
                "operation": "validate-many-by-schema-id",
                "requests": [
                    {"schemaId": schema_id, "document": document}
                    for schema_id, document in requests
                ],
            },
        )
    except RuntimeError as exc:
        raise RouteError(f"FOUNDATION_VALIDATE_FAILED:{exc}") from exc
    rows = outcome.get("results")
    if not isinstance(rows, list) or len(rows) != len(requests):
        raise RouteError("FOUNDATION_VALIDATION_BATCH_INVALID")
    results: list[dict[str, Any]] = []
    for index, (row, (schema_id, _document)) in enumerate(zip(rows, requests)):
        if (
            not isinstance(row, dict)
            or row.get("inputIndex") != index
            or row.get("schemaId") != schema_id
            or not isinstance(row.get("result"), dict)
            or not isinstance(row["result"].get("valid"), bool)
        ):
            raise RouteError("FOUNDATION_VALIDATION_BATCH_INVALID")
        results.append(row["result"])
    return results


def resolve_method_contract(platform_root: Path, intent: str) -> tuple[str, str]:
    contract_path = platform_root / "shared" / "methods" / f"{intent}-audit.json"
    if contract_path.is_symlink() or not contract_path.is_file():
        raise RouteError("METHOD_CONTRACT_MISSING")
    binding = load(contract_path).get("strictIOBinding")
    if (
        not isinstance(binding, dict)
        or binding.get("foundationProfile") != FOUNDATION_PROFILE_EXPECTED
    ):
        raise RouteError("METHOD_CONTRACT_INVALID")
    parameter_ref = binding.get("parameterSchema", {}).get("$ref")
    result_ref = binding.get("outputSchema", {}).get("$ref")
    if not isinstance(parameter_ref, str) or not isinstance(result_ref, str):
        raise RouteError("METHOD_CONTRACT_INVALID")
    return parameter_ref, result_ref


def create_foundation_task(
    runner: Path,
    resource: Path,
    *,
    operation_id: str,
    method: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    return call_foundation(
        runner,
        "create-task",
        {
            "root": str(resource.parent),
            "observationPath": resource.name,
            "observationId": f"{method}-input-evidence",
            "operationId": operation_id,
            "method": method,
            "parameters": parameters,
            "run": operation_id,
            "stage": method,
            "attempt": 1,
        },
    )


def wrap_foundation_result(
    runner: Path,
    task: dict[str, Any],
    *,
    state: str,
    summary: str = "",
    domain_result: Any = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"task": task, "state": state, "errors": errors or []}
    if state == "succeeded":
        payload.update(
            {
                "summary": summary,
                "outputs": [],
                "evidence": [],
                "domainResult": domain_result,
            }
        )
    return call_foundation(runner, "wrap-result", payload)


def assert_foundation_exchange(
    runner: Path,
    resource_root: Path,
    task: dict[str, Any],
    result: dict[str, Any],
) -> None:
    outcome = call_foundation(
        runner,
        "verify-exchange",
        {"root": str(resource_root), "task": task, "result": result},
    )
    if outcome.get("valid") is not True:
        raise RouteError(
            "FOUNDATION_ASSERT_EXCHANGE_FAILED:"
            + json.dumps(outcome, ensure_ascii=False, sort_keys=True)
        )


def resolve_method_script(intent: str, platform: str, manifest_path: Path) -> Path:
    manifest = load(manifest_path)
    if manifest.get("platformId") != platform:
        raise RouteError("PLATFORM_PACKAGE_MISMATCH")
    mappings = [
        item
        for item in manifest.get("logicalMappings", [])
        if isinstance(item, dict) and item.get("logicalName") == METHODS[intent]
    ]
    if len(mappings) != 1:
        raise RouteError("METHOD_MAPPING_INVALID")
    skill_path = mappings[0].get("path")
    if not isinstance(skill_path, str) or not skill_path.endswith("/SKILL.md"):
        raise RouteError("METHOD_MAPPING_INVALID")
    script = manifest_path.parent / Path(skill_path).parent / "scripts" / SCRIPT_NAMES[intent]
    if script.is_symlink() or not script.is_file():
        raise RouteError("METHOD_IMPLEMENTATION_MISSING")
    return script


def _python_binary() -> str:
    return os.environ.get("SFA_PYTHON_BIN") or sys.executable or "python3"


def _bind_missing_conformance_scope(method_args: list[str]) -> list[str]:
    """唯一源码证据缺少 target-type 时补上；已声明则不读证据、不改写。"""
    parsed = parse_method_args(method_args)
    if "target-type" in parsed:
        return method_args
    if "evidence-set" not in parsed:
        return method_args
    _evidence_file, evidence_set = _conformance_evidence(parsed.get("evidence-set"))
    source_trees = [
        item
        for item in evidence_set
        if isinstance(item, dict) and item.get("kind") == "source_tree"
    ]
    if len(source_trees) > 1:
        raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
    if source_trees:
        raw_path = source_trees[0].get("path")
        source_kind = "source_tree"
    else:
        source_files = [
            item
            for item in evidence_set
            if isinstance(item, dict) and item.get("kind") == "source_file"
        ]
        if len(source_files) != 1:
            raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
        raw_path = source_files[0].get("path")
        source_kind = "source_file"
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or not os.path.isabs(raw_path)
        or os.path.normpath(raw_path) != raw_path
    ):
        raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
    scope_path = Path(raw_path)
    if scope_path.is_symlink():
        raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
    try:
        resolved = scope_path.resolve(strict=True)
    except OSError as exc:
        raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED") from exc
    if resolved != scope_path or not (resolved.is_file() or resolved.is_dir()):
        raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
    if source_kind == "source_tree" and scope_path.is_dir():
        workflow = _load_conformance_workflow()
        excluded = workflow.PLUGIN_PROJECT_SCAN_EXCLUDED_PARTS
        matched = [
            skill_path
            for skill_path in scope_path.rglob("SKILL.md")
            if skill_path.is_file()
            and not skill_path.is_symlink()
            and not any(
                part in excluded
                for part in skill_path.relative_to(scope_path).parts
            )
        ]
        if not matched:
            raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
        target_type = "family_source"
    elif scope_path.is_file() and scope_path.name == "SKILL.md":
        target_type = "single_skill"
    else:
        raise RouteError("CONFORMANCE_SCOPE_UNRESOLVED")
    bound = list(method_args)
    if "target" not in parsed:
        bound.extend(["--target", raw_path])
    bound.extend(["--target-type", target_type])
    return bound


def run(args: argparse.Namespace) -> dict[str, Any]:
    intent = select_intent(args.request)
    method_args = json.loads(args.method_args_json)
    if not isinstance(method_args, list) or any(
        not isinstance(item, str) for item in method_args
    ):
        raise RouteError("METHOD_ARGS_INVALID")
    if intent == "conformance":
        method_args = _bind_missing_conformance_scope(method_args)

    manifest_path = find_platform_manifest(args.platform_manifest)
    platform_root = manifest_path.parent
    script = resolve_method_script(intent, args.platform, manifest_path)
    runner = find_foundation_runner(args.foundation_runner, platform_root=platform_root)
    parameter_schema_id, result_schema_id = resolve_method_contract(platform_root, intent)
    parameters, resource = extract_business_parameters(intent, method_args)
    human_route: dict[str, Any] | None = None
    human_registry: dict[str, Any] | None = None
    human_module: Any = None
    human_intent: str | None = None
    route_identity: dict[str, str] | None = None
    routed_method_args = list(method_args)
    human_explanations: list[dict[str, Any]] = []
    if intent == "conformance":
        (
            human_route,
            human_registry,
            human_module,
            human_intent,
            route_identity,
        ) = resolve_conformance_human_route(args.request, method_args, runner)
        if human_intent == "release_preparation":
            assert_release_preparation_input(
                method_args, parameters["evidence_set"]
            )
        parameters["execution_profile"] = human_route["execution_profile"]
        if human_route["semantic_group_ids"]:
            parameters["semantic_group_ids"] = human_route["semantic_group_ids"]
        if human_route["canonical_rule_ids"]:
            parameters["canonical_rule_ids"] = human_route["canonical_rule_ids"]
        routed_method_args = _without_options(method_args, HUMAN_ROUTE_OPTIONS)
        routed_method_args.extend(
            ["--execution-profile", human_route["execution_profile"]]
        )
        for group_id in human_route["semantic_group_ids"]:
            routed_method_args.extend(["--semantic-group-id", group_id])
        for canonical_id in human_route["canonical_rule_ids"]:
            routed_method_args.extend(["--canonical-rule-id", canonical_id])
        routed_method_args.extend(
            ["--profile-selection-reason", human_route["selection_reason"]]
        )
        human_explanations = human_route["source_number_explanations"]
    task = create_foundation_task(
        runner,
        resource,
        operation_id=args.run_id,
        method=f"{intent}-audit",
        parameters=parameters,
    )
    task_digest = call_foundation(
        runner,
        "digest-document",
        {"document": task},
    ).get("digest")
    invocation_args = execution_method_args(
        intent,
        routed_method_args,
        args.run_id,
        foundation_task_digest=task_digest,
    )

    parameter_outcome = validate_by_schema_id(runner, parameter_schema_id, parameters)
    if not parameter_outcome["valid"]:
        result = wrap_foundation_result(
            runner,
            task,
            state="rejected",
            errors=[{
                "code": "SFC2003",
                "message": "Method parameters violate the Audit domain contract.",
                "details": {
                    "schemaId": parameter_schema_id,
                    "errors": parameter_outcome["errors"],
                },
            }],
        )
        assert_foundation_exchange(runner, resource.parent, task, result)
        return {
            "execution_status": "REJECTED",
            "intent": intent,
            "method_id": METHODS[intent],
            "method_exit_code": None,
            "result_state": "rejected",
            "result": result,
        }

    completed = subprocess.run(
        [_python_binary(), str(script), *invocation_args],
        text=True,
        capture_output=True,
        env={**os.environ, "SFA_AUDIT_BUNDLE_RUNNER_REF": str(runner)},
        check=False,
    )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError:
        response = {"raw_stdout": completed.stdout[:1000]}
    if not isinstance(response, dict):
        response = {"value": response}
    execution_plan: dict[str, Any] | None = None
    if intent == "conformance":
        try:
            execution_plan = extract_execution_plan(
                completed.stderr if isinstance(completed.stderr, str) else ""
            )
        except RouteError:
            execution_plan = None
    state = "failed"
    errors: list[dict[str, Any]] = []
    domain_result: Any = None
    human_summary: Any = None
    if intent == "conformance":
        result_outcome = validate_by_schema_id(runner, result_schema_id, response)
        pre_rule_failure = is_pre_rule_selection_failure(response)
        if pre_rule_failure:
            domain = response["conformance_result"]
            try:
                human_summary = human_module.render_human_summary(
                    domain,
                    human_registry,
                    {"intent": human_intent},
                )
            except (KeyError, TypeError, ValueError):
                human_summary = None
            state = "failed"
            domain_result = None
            errors = [{
                "code": "SFC2004",
                "message": domain.get("summary") or "检查在规则选择前被阻断",
                "details": {
                    "failure_stage": "before_rule_selection",
                    "reason_code": domain.get("reason_code"),
                    "summary": domain.get("summary"),
                },
            }]
        elif result_outcome["valid"]:
            try:
                if execution_plan is None or route_identity is None:
                    raise RouteError("EXECUTION_PLAN_EVENT_INVALID")
                assert_plan_event_binding(
                    execution_plan,
                    response["conformance_result"],
                    route_identity,
                    human_route["canonical_rule_ids"],
                )
                if (
                    execution_plan.get("selection_reason")
                    != human_route["selection_reason"]
                ):
                    raise RouteError("PLAN_EVENT_BINDING_MISMATCH")
                human_summary = human_module.render_human_summary(
                    response["conformance_result"],
                    human_registry,
                    {"intent": human_intent},
                )
                state = "succeeded"
                domain_result = response
            except (KeyError, TypeError, ValueError, RouteError) as exc:
                state = "failed"
                domain_result = None
                errors = [{
                    "code": "SFC2004",
                    "message": "Audit domain result cannot render the required human summary.",
                    "details": {"error": str(exc)},
                }]
        else:
            details: dict[str, Any] = {
                "schemaId": result_schema_id,
                "errors": result_outcome["errors"],
            }
            diagnostic = domain_result_summary(response)
            if diagnostic:
                details["domainResultSummary"] = diagnostic
            errors = [{
                "code": "SFC2004",
                "message": "Audit domain result violates the method contract.",
                "details": details,
            }]
    else:
        status = response.get("execution_status")
        domain_succeeded = completed.returncode == 0 and (
            not isinstance(status, str) or status.startswith("SUCCEEDED")
        )
        if domain_succeeded:
            result_outcome = validate_by_schema_id(runner, result_schema_id, response)
            if result_outcome["valid"]:
                state = "succeeded"
                domain_result = response
            else:
                errors = [{
                    "code": "SFC2004",
                    "message": "Audit domain result violates the method contract.",
                    "details": {
                        "schemaId": result_schema_id,
                        "errors": result_outcome["errors"],
                    },
                }]
        else:
            errors = [{
                "code": "SFC2004",
                "message": "Audit domain method did not complete successfully.",
            }]
    summary = transport_summary(intent, state)
    result = wrap_foundation_result(
        runner,
        task,
        state=state,
        summary=summary,
        domain_result=domain_result,
        errors=errors,
    )
    assert_foundation_exchange(runner, resource.parent, task, result)
    response_payload = {
        "execution_status": "SUCCEEDED" if state == "succeeded" else "FAILED",
        "intent": intent,
        "method_id": METHODS[intent],
        "method_exit_code": completed.returncode,
        "result_state": state,
        "result": result,
    }
    if human_summary is not None:
        response_payload["human_summary"] = human_summary
    if human_explanations:
        response_payload["source_number_explanations"] = human_explanations
    if execution_plan is not None:
        response_payload["execution_plan"] = execution_plan
    return response_payload


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--request", required=True)
    value.add_argument("--platform", required=True)
    value.add_argument("--method-args-json", required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--platform-manifest")
    value.add_argument("--foundation-runner")
    return value


def main() -> int:
    try:
        manifest_hint = next(
            (
                sys.argv[index + 1]
                for index, value in enumerate(sys.argv[:-1])
                if value == "--platform-manifest"
            ),
            None,
        )
        if manifest_hint:
            platform_root = Path(manifest_hint).resolve(strict=True).parent
            checker_dir = next(
                (
                    path.parent
                    for path in platform_root.glob(
                        "skills/*/scripts/conformance_check.py"
                    )
                    if path.is_file() and not path.is_symlink()
                ),
                None,
            )
            if checker_dir is not None and str(checker_dir) not in sys.path:
                sys.path.insert(0, str(checker_dir))
            __import__("conformance_check")
        result = run(parser().parse_args())
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if result["execution_status"] == "SUCCEEDED":
            return 0
        if result["execution_status"] == "REJECTED":
            return 2
        return 1
    except (RouteError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "execution_status": "BLOCKED",
                    "error": str(exc),
                    "completion_state": "not_started",
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
