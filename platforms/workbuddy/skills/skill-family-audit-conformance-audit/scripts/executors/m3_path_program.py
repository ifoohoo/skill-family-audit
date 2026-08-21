"""M3 执行族：路径收容与确定性程序（W2-B1 共 7 条，方法 static_scan）。

证据面：
- 目标文件树真实扫描（逐段符号链接解析、特殊文件识别）；
- 项目治理声明：write-closure.json / program-contracts.json /
  extension-declarations.json。

路径类规则对目标做只读静态扫描（目标根 = project_adoption 的安装根，
否则为 ctx["target"]）；程序与写入类规则消费治理声明，文档缺失 = 无可判
违反事实 → PASS（约束"已声明者"），形状非法失败关闭。
"""
from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path
from typing import Any

from .contracts import (
    ExecutorEvidenceError,
    is_hex64,
    load_governance_document,
    result,
    rows_of,
)

#: 目标树扫描时排除的缓存/版本控制目录（与观察投影口径一致并加 .git）。
SCAN_EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".git", "node_modules"}


def _scan_root(ctx: dict[str, Any]) -> Path:
    # D3：项目 Profile 采用不存在已安装子树；扫描根就是受检目标本身。
    return Path(str(ctx["target"]))


def _iter_scan_paths(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in SCAN_EXCLUDED_PARTS]
        base = Path(dirpath)
        for name in filenames:
            yield base / name


def _segment_escape(root: Path, path: Path) -> bool:
    """逐段检查符号链接链：任一段为符号链接且指向根外即越界。"""
    current = path
    while current != current.parent:
        if current.is_symlink():
            try:
                linked = Path(os.readlink(current))
                resolved = linked if linked.is_absolute() else (current.parent / linked)
                resolved.relative_to(root)
            except (ValueError, OSError):
                return True
        current = current.parent
    return False


def check_extension_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """未知必需扩展必须阻断执行，不得忽略、降级或透传冒充支持。

    机械断言：已声明 required=true 的扩展必须 recognized=true 且携带
    schema_ref；存在未识别必需扩展而 execution_allowed=true 即违反。
    """
    document = load_governance_document(ctx, "extension-declarations")
    if document is None:
        return result("PASS", extensions_declared=0, mechanical_half=True)
    rows = rows_of(document, "extensions", "extension-declarations")
    violations = []
    for index, row in enumerate(rows):
        if row.get("required") is not True:
            continue
        recognized = row.get("recognized") is True and bool(row.get("schema_ref"))
        if not recognized and row.get("execution_allowed") is not False:
            violations.append({"index": index, "extension": row.get("id")})
    if violations:
        return result("FAIL", unknown_required_extensions_not_blocked=violations, mechanical_half=True)
    return result("PASS", extensions_declared=len(rows), mechanical_half=True)


def check_path_002(ctx: dict[str, Any]) -> dict[str, Any]:
    """路径经逐段符号链接解析后落到授权边界之外必须拒绝。

    机械断言（真实扫描）：目标扫描面内任一符号链接段解析出授权根之外即
    违反；仅比较路径文字前缀不构成证明。
    """
    root = _scan_root(ctx)
    escapes = []
    for path in _iter_scan_paths(root):
        if _segment_escape(root, path):
            escapes.append(path.relative_to(root).as_posix())
    if escapes:
        return result("FAIL", symlink_escapes=sorted(escapes), mechanical_half=True)
    return result("PASS", scanned_root=root.name, mechanical_half=True)


def check_path_003(ctx: dict[str, Any]) -> dict[str, Any]:
    """遇到契约未声明的设备、管道、套接字等特殊文件必须拒绝处理。

    机械断言（真实扫描）：目标扫描面只允许常规文件与目录；出现 FIFO、
    套接字、块/字符设备等特殊文件即违反。
    """
    root = _scan_root(ctx)
    specials = []
    for path in _iter_scan_paths(root):
        try:
            mode = path.lstat().st_mode
        except OSError:
            continue
        if not stat_module.S_ISREG(mode):
            specials.append(path.relative_to(root).as_posix())
    if specials:
        return result("FAIL", undeclared_special_files=sorted(specials), mechanical_half=True)
    return result("PASS", scanned_root=root.name, mechanical_half=True)


def _write_closure(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "write-closure")
    if document is None:
        return None
    return rows_of(document, "writes", "write-closure")


def _resolve_within(root: Path, relative: str) -> bool:
    candidate = (root / relative)
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def check_path_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """解析后的写入目标位于授权根之外时必须拒绝。

    机械断言：已声明写入集合逐条解析后必须全部位于授权根（目标根）内；
    绝对路径、遍历或符号链接逃逸即违反。
    """
    rows = _write_closure(ctx)
    if rows is None:
        return result("PASS", writes_declared=0, mechanical_half=True)
    root = _scan_root(ctx)
    violations = []
    for index, row in enumerate(rows):
        relative = row.get("path")
        if not isinstance(relative, str) or not relative or relative.startswith(("/", "\\")):
            violations.append({"index": index, "path": relative, "reason": "not_posix_relative"})
            continue
        if ".." in Path(relative).parts:
            violations.append({"index": index, "path": relative, "reason": "path_traversal"})
            continue
        if not _resolve_within(root, relative):
            violations.append({"index": index, "path": relative, "reason": "outside_authorized_root"})
    if violations:
        return result("FAIL", writes_outside_root=violations, mechanical_half=True)
    return result("PASS", writes_declared=len(rows), mechanical_half=True)


def _program_contracts(ctx: dict[str, Any]) -> list[dict[str, Any]] | None:
    document = load_governance_document(ctx, "program-contracts")
    if document is None:
        return None
    return rows_of(document, "programs", "program-contracts")


def check_program_013(ctx: dict[str, Any]) -> dict[str, Any]:
    """确定性程序必须显式接收输入、输出与授权写入集合，不得依赖 CWD。

    机械断言：已声明程序必须显式声明 inputs/outputs/write_set 且
    cwd_dependence!=true。
    """
    rows = _program_contracts(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        missing = [
            field
            for field in ("inputs", "outputs", "write_set")
            if not isinstance(row.get(field), list)
        ]
        if missing or row.get("cwd_dependence") is True:
            violations.append(
                {"index": index, "program": row.get("id"), "missing": missing}
            )
    if violations:
        return result("FAIL", programs_without_explicit_resources=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_program_015(ctx: dict[str, Any]) -> dict[str, Any]:
    """正式输出必须先写临时位置、验证后原子提交。

    机械断言：已声明正式输出必须携带 staging_path 且
    validation_before_commit=true、atomic_commit=true。
    """
    rows = _program_contracts(ctx)
    if rows is None:
        return result("PASS", programs_declared=0, mechanical_half=True)
    violations = []
    for index, row in enumerate(rows):
        for output in row.get("formal_outputs") or []:
            if not isinstance(output, dict):
                raise ExecutorEvidenceError(
                    "GOVERNANCE_DOCUMENT_INVALID",
                    "program-contracts.formal_outputs 行必须是对象",
                )
            if (
                not isinstance(output.get("staging_path"), str)
                or not output.get("staging_path")
                or output.get("validation_before_commit") is not True
                or output.get("atomic_commit") is not True
            ):
                violations.append({"program": row.get("id"), "output": output.get("path")})
    if violations:
        return result("FAIL", outputs_without_atomic_validation=violations, mechanical_half=True)
    return result("PASS", programs_declared=len(rows), mechanical_half=True)


def check_write_004(ctx: dict[str, Any]) -> dict[str, Any]:
    """实际执行只能落在获授权计划摘要绑定的写入集合内。

    机械断言：已声明执行写入必须逐条位于计划写入集合内，且计划必须绑定
    64 位十六进制授权摘要；集合外写入或计划摘要缺失即违反。
    """
    rows = _write_closure(ctx)
    if rows is None:
        return result("PASS", writes_declared=0, mechanical_half=True)
    document = load_governance_document(ctx, "write-closure")
    plan_digest = document.get("plan_digest") if isinstance(document, dict) else None
    if not is_hex64(plan_digest):
        return result("FAIL", reason="plan_digest_missing_or_invalid", mechanical_half=True)
    planned = set()
    for row in rows:
        if row.get("in_plan") is True:
            path = row.get("path")
            if isinstance(path, str) and path:
                planned.add(path)
    violations = [
        {"index": index, "path": row.get("path")}
        for index, row in enumerate(rows)
        if row.get("executed") is True
        and not (isinstance(row.get("path"), str) and row.get("path") in planned)
    ]
    if violations:
        return result("FAIL", executed_writes_outside_plan=violations, mechanical_half=True)
    return result(
        "PASS", writes_declared=len(rows), plan_digest=plan_digest, mechanical_half=True
    )


CHECKS = {
    "SFA-EXTENSION-003": check_extension_003,
    "SFA-PATH-002": check_path_002,
    "SFA-PATH-003": check_path_003,
    "SFA-PATH-004": check_path_004,
    "SFA-PROGRAM-013": check_program_013,
    "SFA-PROGRAM-015": check_program_015,
    "SFA-WRITE-004": check_write_004,
}
