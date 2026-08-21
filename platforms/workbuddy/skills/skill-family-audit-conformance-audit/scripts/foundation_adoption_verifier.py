#!/usr/bin/env python3
"""Foundation Profile SPI 验证器：进程外调用 Foundation 0.8.0 verifyProjectProfile。

职责：
- 项目根 profile.json 只通过公共入口
  ``verifyProjectProfile({projectRoot, profileRelPath})`` 校验；
- SPI 运行闭包来自平台包内机械投影的 Foundation 0.8.0 隔离安装
  （``foundation/profile-spi/``），或来自显式绑定
  ``SFA_FOUNDATION_PROFILE_SPI_ROOT``（隔离测试用）；不依赖 PATH、
  全局 npm 或被审项目的 node_modules；
- 通过 ``conformance_check.foundation_node_runtime()`` 使用受控
  Node 22 入口（绝对路径、无符号链接路径链、版本 >=22.22.2 <23）；
- SPI 缺失、入口为符号链接、Node 失败、非 JSON 输出、非对象结果、
  以及任何非 SPE0000 结果全部失败关闭。

边界：
- ``verifyProfile()`` 只用于 Profile 提供者描述符；项目 Profile
  永远不走该入口，也不把项目文档转换成描述符；
- Audit 不复制 Foundation 的 Schema、摘要算法或自加严规则，
  只做领域编排与失败关闭判定。
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import conformance_check as foundation_bridge

SCRIPTS_DIR = Path(__file__).resolve().parent

REQUIRED_FOUNDATION_PACKAGES = [
    "skill-family-contracts",
    "skill-family-harness-node",
    "skill-family-engineering-kit",
]

SPI_ENTRY_RELATIVE = (
    "node_modules/skill-family-engineering-kit/profile-spi/index.mjs"
)
SPI_PROVENANCE_RELATIVE = "foundation-profile-spi-projection.json"
SPI_PROVENANCE_KIND = "skill-family.foundation-profile-spi-projection"
SPI_INVOCATION_TIMEOUT_SECONDS = 60


class VerificationError(RuntimeError):
    """验证失败，携带稳定错误码。"""
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code = code


def _reject_symlink(path: Path, code: str) -> None:
    """Map the canonical host's trust-boundary failure into Audit vocabulary."""
    try:
        foundation_bridge._check_path_chain_no_symlinks(path, code)
    except RuntimeError as exc:
        raise VerificationError(code, str(exc)) from exc


def _closure_root_candidates() -> list[Path]:
    """Resolve the single SPI closure root: explicit binding, else package walk.

    An explicit ``SFA_FOUNDATION_PROFILE_SPI_ROOT`` is exclusive so isolated
    tests never silently fall through to a host installation.  In a generated
    platform package the closure sits next to ``platform-manifest.json``;
    the walk stops at the first real manifest ancestor.
    """
    explicit = os.environ.get("SFA_FOUNDATION_PROFILE_SPI_ROOT", "")
    if explicit:
        return [Path(explicit)]
    for ancestor in SCRIPTS_DIR.parents:
        marker = ancestor / "platform-manifest.json"
        if marker.is_symlink():
            raise VerificationError(
                "FOUNDATION_PROFILE_SPI_MISSING",
                f"平台清单是符号链接: {marker}",
            )
        if marker.is_file():
            return [ancestor / "foundation" / "profile-spi"]
    return []


def resolve_profile_spi_entry() -> tuple[Path, Path]:
    """Return ``(closure_root, entry)`` after full containment validation."""
    candidates = _closure_root_candidates()
    if not candidates:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            "未绑定 Foundation Profile SPI 运行闭包"
            "（平台包 foundation/profile-spi 或 SFA_FOUNDATION_PROFILE_SPI_ROOT）",
        )
    root = candidates[0]
    if root.is_symlink() or not root.is_dir():
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            f"Profile SPI 运行闭包根不存在或为符号链接: {root}",
        )
    _reject_symlink(root, "FOUNDATION_PROFILE_SPI_PATH_SYMLINK")
    entry = root / SPI_ENTRY_RELATIVE
    if entry.is_symlink() or not entry.is_file():
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            f"Profile SPI 入口缺失或为符号链接: {entry}",
        )
    _reject_symlink(entry, "FOUNDATION_PROFILE_SPI_PATH_SYMLINK")
    provenance_path = root / SPI_PROVENANCE_RELATIVE
    if provenance_path.is_symlink() or not provenance_path.is_file():
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            f"Profile SPI 闭包缺少来源证明: {provenance_path}",
        )
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            f"Profile SPI 来源证明不可读: {exc}",
        ) from exc
    if (
        not isinstance(provenance, dict)
        or provenance.get("kind") != SPI_PROVENANCE_KIND
        or provenance.get("entry") != SPI_ENTRY_RELATIVE
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            "Profile SPI 来源证明 kind 或 entry 绑定不匹配",
        )
    return root, entry


def verify_project_profile(
    project_root: Path, profile_rel_path: str = "profile.json"
) -> dict[str, Any]:
    """Verify a project-root profile through Foundation Profile SPI v3.

    ``verifyProfile`` is intentionally not used here: it is descriptor-only.
    Every failure mode returns a closed result carrying a stable Audit code;
    the caller decides the domain consequence.
    """
    project_root = Path(project_root).resolve()
    try:
        closure_root, entry = resolve_profile_spi_entry()
    except VerificationError as exc:
        return {
            "foundation_profile_complete": False,
            "code": exc.code,
            "blockers": [str(exc)],
        }
    try:
        node_path, node_version = foundation_bridge.foundation_node_runtime()
    except RuntimeError as exc:
        return {
            "foundation_profile_complete": False,
            "code": "FOUNDATION_NODE_UNAVAILABLE",
            "blockers": [str(exc)],
        }
    script = (
        "const { verifyProjectProfile } = await import(process.argv[1]); "
        "const r = await verifyProjectProfile({projectRoot: process.argv[2], "
        "profileRelPath: process.argv[3]}); "
        "process.stdout.write(JSON.stringify(r));"
    )
    try:
        completed = subprocess.run(
            [
                str(node_path),
                "--input-type=module",
                "-e",
                script,
                entry.as_uri(),
                str(project_root),
                profile_rel_path,
            ],
            capture_output=True,
            text=True,
            timeout=SPI_INVOCATION_TIMEOUT_SECONDS,
            cwd=str(closure_root),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "foundation_profile_complete": False,
            "code": "FOUNDATION_PROFILE_SPI_FAILED",
            "blockers": [f"Profile SPI Node 调用失败: {exc}"],
        }
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        return {
            "foundation_profile_complete": False,
            "code": "FOUNDATION_PROFILE_SPI_FAILED",
            "blockers": [
                f"Profile SPI Node 进程退出码 {completed.returncode}: {detail[:512]}"
            ],
        }
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {
            "foundation_profile_complete": False,
            "code": "FOUNDATION_PROFILE_SPI_FAILED",
            "blockers": [
                "Profile SPI 输出不是合法 JSON: "
                + completed.stdout[:256]
            ],
        }
    if not isinstance(result, dict):
        return {
            "foundation_profile_complete": False,
            "code": "FOUNDATION_PROFILE_SPI_FAILED",
            "blockers": ["Profile SPI 返回非对象结果"],
        }
    result["foundation_profile_complete"] = result.get("code") == "SPE0000"
    result["node_version"] = node_version
    result["closure_root"] = str(closure_root)
    if not result["foundation_profile_complete"]:
        result.setdefault("blockers", []).append(
            "Foundation Profile SPI 拒绝项目 Profile: "
            f"code={result.get('code')} reason={result.get('reason', '')}"
        )
    return result
