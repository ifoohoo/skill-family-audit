"""M3 执行族：路径/程序/运行状态/任务结果（W2-B3 批，7 条）。

本模块覆盖 B3 批 execution_family=M3、violation_impact=warning/observe 的
7 条规则，全部被终态裁决为机械方法 static_scan 且
behavior_verification_also_required=true；执行器只覆盖机械半区
（evidence 携 mechanical_half=true），行为义务继续挂账。

证据面（与 B1/B2 M3 一致，失败关闭）：
- SFA-PROGRAM-003/004 对目标受检根做只读静态扫描：技能目录（含 SKILL.md）
  下的 ``references/`` 只允许按需文档，``assets/`` 不得承载运行时业务程序；
- 目标项目治理声明 ``<target>/.skill-family-audit/governance/<name>.json``：
  runtime-state-contracts（waiting_user 行扩展 + session_endings 新轴，
  SFA-STATE-005/008）、task-result-contracts（entry_exemptions 新轴，
  SFA-TASK-003/004/005）。

治理声明缺省语义沿用 B1：
- 约束"已声明者"的规则：文档缺失 = 无可判违反事实 → PASS；
- 文档存在但形状非法 → ExecutorEvidenceError（失败关闭，绝不静默放行）；
- 文档存在且出现结构性违反 → FAIL。

执行器只消费目标事实，绝不修改目标；不消费模型语义结论。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import (
    ExecutorEvidenceError,
    load_governance_document,
    result,
    rows_of,
)

# ---------------------------------------------------------------------------
# 词表
# ---------------------------------------------------------------------------

#: SFA-PROGRAM-003：references/ 允许的按需文档扩展名。
REFERENCE_DOCUMENT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".rst", ".json",
    ".yaml", ".yml", ".csv", ".toml", ".xml",
}

#: SFA-PROGRAM-004：assets/ 禁止承载的运行时程序扩展名。
PROGRAM_FILE_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".py", ".pyc", ".pyo",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rb", ".pl", ".php", ".lua", ".ps1", ".bat", ".cmd",
    ".exe", ".bin", ".so", ".dylib", ".dll",
    ".class", ".jar", ".wasm",
}

#: 静态扫描跳过的无关目录。
SCAN_SKIPPED_DIRECTORIES = {
    "node_modules", ".git", "__pycache__", ".skill-family-audit",
}

#: SFA-STATE-005：等待用户状态允许的补充类别。
WAITING_USER_SUPPLEMENT_KINDS = {
    "explicit_input",
    "explicit_choice",
    "authorization",
}

#: SFA-TASK-005：quickstart 允许豁免落盘的前置阶段。
QUICKSTART_PRE_WORK_PHASES = {
    "understanding_intent",
    "enumerating_candidates",
    "gathering_necessary_information",
}

#: SFA-TASK-004：setup 豁免必须逐项声明未产生的修改类别。
SETUP_MODIFICATION_FIELDS = (
    "produced_configuration",
    "produced_dependencies",
    "produced_hooks",
    "produced_other_project_modification",
)


def _doc(ctx: dict[str, Any], name: str) -> dict[str, Any] | None:
    return load_governance_document(ctx, name)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _target_root(ctx: dict[str, Any]) -> Path:
    """目标扫描根：D3 起采用声明是项目 Profile，扫描根即受检目标本身。"""
    return Path(str(ctx["target"]))


def _skill_dirs(root: Path) -> list[Path]:
    """返回根内全部技能目录（含 SKILL.md 的目录），确定性排序。"""
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        has_skill_md = False
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SCAN_SKIPPED_DIRECTORIES:
                    stack.append(entry)
            elif entry.is_file() and entry.name == "SKILL.md":
                has_skill_md = True
        if has_skill_md:
            found.append(current)
    return sorted(found, key=lambda path: str(path))


def _iter_files(directory: Path):
    """深度优先枚举目录内常规文件；符号链接单独产出供失败关闭判定。"""
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                yield entry
            elif entry.is_dir():
                if entry.name not in SCAN_SKIPPED_DIRECTORIES:
                    stack.append(entry)
            elif entry.is_file():
                yield entry


def _is_executable_bit(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & 0o111)


# ---------------------------------------------------------------------------
# PROGRAM：目录职责真实扫描（references / assets）
# ---------------------------------------------------------------------------


def check_program_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """参考资料目录只存按需文档。

    机械断言（真实扫描）：技能 ``references/`` 内只允许按需文档扩展名的
    常规文件；可执行程序（含可执行位、程序扩展名、符号链接）伪装成参考
    资料即违反。
    """
    root = _target_root(ctx)
    violations = []
    scanned = 0
    for skill_dir in _skill_dirs(root):
        references = skill_dir / "references"
        if not references.is_dir() or references.is_symlink():
            continue
        scanned += 1
        for entry in _iter_files(references):
            relative = entry.relative_to(root).as_posix()
            if entry.is_symlink():
                violations.append({"path": relative, "reason": "symlink_disguised_as_document"})
                continue
            if entry.suffix.lower() not in REFERENCE_DOCUMENT_EXTENSIONS:
                violations.append({"path": relative, "reason": "program_disguised_as_reference"})
            elif _is_executable_bit(entry):
                violations.append({"path": relative, "reason": "executable_bit_on_reference"})
    if violations:
        return result("FAIL", references_holding_programs=violations, mechanical_half=True)
    return result("PASS", references_dirs_scanned=scanned, mechanical_half=True)


def check_program_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """资源目录存放输出资产。

    机械断言（真实扫描）：技能 ``assets/`` 用于输出模板、静态资源和可复制
    资产；出现运行时业务程序（程序扩展名、可执行位或符号链接）即违反。
    """
    root = _target_root(ctx)
    violations = []
    scanned = 0
    for skill_dir in _skill_dirs(root):
        assets = skill_dir / "assets"
        if not assets.is_dir() or assets.is_symlink():
            continue
        scanned += 1
        for entry in _iter_files(assets):
            relative = entry.relative_to(root).as_posix()
            if entry.is_symlink():
                violations.append({"path": relative, "reason": "symlink_disguised_as_asset"})
                continue
            if entry.suffix.lower() in PROGRAM_FILE_EXTENSIONS:
                violations.append({"path": relative, "reason": "runtime_program_in_assets"})
            elif _is_executable_bit(entry):
                violations.append({"path": relative, "reason": "executable_bit_in_assets"})
    if violations:
        return result("FAIL", assets_carrying_runtime_programs=violations, mechanical_half=True)
    return result("PASS", assets_dirs_scanned=scanned, mechanical_half=True)


# ---------------------------------------------------------------------------
# STATE：等待用户与检查点完结（runtime-state-contracts）
# ---------------------------------------------------------------------------


def check_state_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """等待用户的适用条件。

    机械断言：已声明等待用户状态的结果必须可从现有检查点续接，并声明
    续接所需的补充类别（明确输入、选择或授权）。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", declared_results=0, mechanical_half=True)
    rows = rows_of(document, "results", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(rows):
        if row.get("primary_state") != "waiting_user":
            continue
        problems = []
        if row.get("resumable_from_existing_checkpoint") is not True:
            problems.append("not_resumable_from_existing_checkpoint")
        if not _nonempty_str(row.get("checkpoint_ref")):
            problems.append("checkpoint_ref_missing")
        supplements = row.get("expected_supplements")
        if (
            not isinstance(supplements, list)
            or not supplements
            or not all(kind in WAITING_USER_SUPPLEMENT_KINDS for kind in supplements)
        ):
            problems.append("expected_supplements_missing_or_invalid")
        if problems:
            violations.append(
                {"index": index, "run_id": row.get("run_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", waiting_user_without_resume_conditions=violations, mechanical_half=True
        )
    return result("PASS", declared_results=len(rows), mechanical_half=True)


def check_state_008(ctx: dict[str, Any]) -> dict[str, Any]:
    """完整检查点允许结束会话。

    机械断言：已声明结束并供后续会话续接的执行会话，必须在结束前完整
    写入 SFA-STATE-007 要求的结果与检查点。
    """
    document = _doc(ctx, "runtime-state-contracts")
    if document is None:
        return result("PASS", session_endings_declared=0, mechanical_half=True)
    rows = rows_of(document, "session_endings", "runtime-state-contracts")
    violations = []
    for index, row in enumerate(rows):
        problems = []
        if not _nonempty_str(row.get("checkpoint_ref")):
            problems.append("checkpoint_ref_missing")
        if row.get("state007_checkpoint_written") is not True:
            problems.append("state007_checkpoint_not_fully_written")
        if row.get("state007_result_written") is not True:
            problems.append("state007_result_not_fully_written")
        if problems:
            violations.append(
                {"index": index, "session": row.get("session_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", session_ended_before_complete_checkpoint=violations, mechanical_half=True
        )
    return result("PASS", session_endings=len(rows), mechanical_half=True)


# ---------------------------------------------------------------------------
# TASK：固定入口豁免前置条件（task-result-contracts）
# ---------------------------------------------------------------------------


def _entry_exemptions(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = _doc(ctx, "task-result-contracts")
    if document is None:
        return None
    return rows_of(document, "entry_exemptions", "task-result-contracts")


def check_task_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """纯说明帮助不要求运行文件。

    机械断言：已声明 help 豁免（不生成规范化任务和结果文件）必须满足
    前置条件——只提供纯说明、未开始诊断、未开始业务执行。
    """
    rows = _entry_exemptions(ctx)
    if rows is None:
        return result("PASS", entry_exemptions_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("entry") != "help" or row.get("claims_task_result_exemption") is not True:
            continue
        problems = []
        if row.get("pure_explanation") is not True:
            problems.append("not_pure_explanation")
        if row.get("started_diagnosis") is True:
            problems.append("started_diagnosis")
        if row.get("started_business_execution") is True:
            problems.append("started_business_execution")
        if problems:
            violations.append(
                {"index": index, "run_id": row.get("run_id"), "problems": problems}
            )
    if violations:
        return result(
            "FAIL", help_exemption_without_preconditions=violations, mechanical_half=True
        )
    return result("PASS", entry_exemptions=len(rows), mechanical_half=True)


def check_task_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """无修改初始化可只返回诊断。

    机械断言：已声明 setup 豁免（只返回面向人的诊断、不创建完整业务运行
    目录）必须未产生配置、依赖、钩子或其他项目修改。
    """
    rows = _entry_exemptions(ctx)
    if rows is None:
        return result("PASS", entry_exemptions_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("entry") != "setup" or row.get("claims_diagnostic_only_exemption") is not True:
            continue
        produced = [
            field for field in SETUP_MODIFICATION_FIELDS if row.get(field) is True
        ]
        if produced:
            violations.append(
                {"index": index, "run_id": row.get("run_id"), "produced": produced}
            )
    if violations:
        return result(
            "FAIL", setup_exemption_with_project_modifications=violations, mechanical_half=True
        )
    return result("PASS", entry_exemptions=len(rows), mechanical_half=True)


def check_task_005(ctx: dict[str, Any]) -> dict[str, Any]:
    """快速入口理解意图时不要求落盘。

    机械断言：已声明 quickstart 豁免（不生成业务任务和结果文件）的阶段
    必须处于理解意图、枚举候选或收集必要信息阶段。
    """
    rows = _entry_exemptions(ctx)
    if rows is None:
        return result("PASS", entry_exemptions_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        if row.get("entry") != "quickstart" or row.get("claims_task_result_exemption") is not True:
            continue
        phase = row.get("phase")
        if phase not in QUICKSTART_PRE_WORK_PHASES:
            violations.append(
                {"index": index, "run_id": row.get("run_id"), "phase": phase}
            )
    if violations:
        return result(
            "FAIL", quickstart_exemption_beyond_pre_work_phases=violations, mechanical_half=True
        )
    return result("PASS", entry_exemptions=len(rows), mechanical_half=True)


CHECKS = {
    "SFA-PROGRAM-003": check_program_003,
    "SFA-PROGRAM-004": check_program_004,
    "SFA-STATE-005": check_state_005,
    "SFA-STATE-008": check_state_008,
    "SFA-TASK-003": check_task_003,
    "SFA-TASK-004": check_task_004,
    "SFA-TASK-005": check_task_005,
}
