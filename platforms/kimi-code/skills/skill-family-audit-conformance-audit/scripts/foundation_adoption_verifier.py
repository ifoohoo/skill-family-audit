#!/usr/bin/env python3
"""Foundation Profile SPI 验证器：进程外调用 Foundation 0.15.0 verifyProjectProfile。

职责：
- 项目根 profile.json 只通过公共入口
  ``verifyProjectProfile({projectRoot, profileRelPath})`` 校验；
- 生产 SPI 运行闭包只来自当前平台包 ``platform-manifest.json`` 所绑定的
  ``foundation/profile-spi/``；环境变量不能替换该 authority；
- 直接单元测试可通过函数参数注入一个完整临时平台根下的闭包；
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
import re
import subprocess
from pathlib import Path
from typing import Any

import conformance_check as foundation_bridge

SCRIPTS_DIR = Path(__file__).resolve().parent

REQUIRED_FOUNDATION_PACKAGES = (
    "skill-family-contracts",
    "skill-family-harness-node",
    "skill-family-engineering-kit",
)

SPI_ENTRY_RELATIVE = (
    "node_modules/skill-family-engineering-kit/profile-spi/index.mjs"
)
SPI_PROVENANCE_RELATIVE = "foundation-profile-spi-projection.json"
SPI_PROVENANCE_KIND = "skill-family.foundation-profile-spi-projection"
PLATFORM_MANIFEST_RELATIVE = "platform-manifest.json"
FOUNDATION_RUNNER_RELATIVE = "foundation/quickstart-profile/runner.mjs"
PROFILE_SPI_ROOT_RELATIVE = "foundation/profile-spi"
PROFILE_SPI_PROJECTION_PATH = (
    f"{PROFILE_SPI_ROOT_RELATIVE}/{SPI_PROVENANCE_RELATIVE}"
)
PROFILE_SPI_ENTRY_PATH = f"{PROFILE_SPI_ROOT_RELATIVE}/{SPI_ENTRY_RELATIVE}"
FOUNDATION_PROJECTION_PATH = (
    "foundation/quickstart-profile/foundation-projection.json"
)
FOUNDATION_BUNDLE_ROOT = "foundation/quickstart-profile"
FOUNDATION_MECHANISMS_PATH = (
    "foundation/quickstart-profile/mechanisms-cli.mjs"
)
SPI_INVOCATION_TIMEOUT_SECONDS = 60
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def _production_platform_root() -> Path | None:
    """Find only the real platform package that contains this script."""
    for ancestor in SCRIPTS_DIR.parents:
        marker = ancestor / PLATFORM_MANIFEST_RELATIVE
        if marker.is_symlink():
            raise VerificationError(
                "FOUNDATION_PROFILE_SPI_MISSING",
                f"平台清单是符号链接: {marker}",
            )
        if marker.is_file():
            return ancestor
    return None


def _injected_platform_root(profile_spi_root: Path) -> Path:
    root = Path(profile_spi_root)
    if not root.is_absolute():
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            "测试注入的 Profile SPI 闭包必须是绝对路径",
        )
    if root.name != "profile-spi" or root.parent.name != "foundation":
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            "测试注入必须指向完整平台根下的 foundation/profile-spi",
        )
    return root.parent.parent


def _foundation_mechanism(platform_root: Path, request: dict[str, Any]) -> dict[str, Any]:
    runner = platform_root / FOUNDATION_RUNNER_RELATIVE
    try:
        result = foundation_bridge.call_foundation_mechanism(runner, request)
    except RuntimeError as exc:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            f"平台 Foundation 机制不可用: {exc}",
        ) from exc
    if not isinstance(result, dict):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "平台 Foundation 机制返回非对象",
        )
    return result


def _strict_read_json(
    platform_root: Path, relative: str, expected_sha256: str | None = None
) -> dict[str, Any]:
    if expected_sha256 is None:
        closure = _foundation_mechanism(platform_root, {
            "operation": "resource-closure",
            "root": str(platform_root),
            "resources": [{"path": relative, "role": "input"}],
        })
        resources = closure.get("resources")
        if not isinstance(resources, list) or len(resources) != 1:
            raise VerificationError(
                "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
                f"Foundation resource-closure 未返回唯一资源: {relative}",
            )
        expected_sha256 = resources[0].get("sha256")
    if not isinstance(expected_sha256, str) or not HEX64.fullmatch(expected_sha256):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            f"authority 摘要无效: {relative}",
        )
    strict = _foundation_mechanism(platform_root, {
        "operation": "read-file-strict",
        "root": str(platform_root),
        "path": relative,
        "encoding": "utf8",
        "expectedSha256": expected_sha256,
    })
    content = strict.get("content")
    if not isinstance(content, str):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            f"authority 不是 UTF-8 文本: {relative}",
        )
    try:
        value = json.loads(content)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            f"authority 不是合法 JSON: {relative}",
        ) from exc
    if not isinstance(value, dict):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            f"authority 不是 JSON 对象: {relative}",
        )
    return value


def _validate_profile_spi_authority(platform_root: Path, root: Path) -> None:
    manifest = _strict_read_json(platform_root, PLATFORM_MANIFEST_RELATIVE)
    foundation_projection = manifest.get("foundationProjection")
    profile_spi = (
        foundation_projection.get("profileSpi")
        if isinstance(foundation_projection, dict)
        else None
    )
    files = manifest.get("files")
    if (
        not isinstance(foundation_projection, dict)
        or not isinstance(profile_spi, dict)
        or not isinstance(files, list)
        or profile_spi.get("path") != PROFILE_SPI_PROJECTION_PATH
        or profile_spi.get("entry") != PROFILE_SPI_ENTRY_PATH
        or PROFILE_SPI_PROJECTION_PATH not in files
        or PROFILE_SPI_ENTRY_PATH not in files
        or root != platform_root / PROFILE_SPI_ROOT_RELATIVE
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "platform-manifest 未精确绑定 Profile SPI 路径",
        )
    _validate_foundation_bundle_authority(
        platform_root, foundation_projection, files
    )
    projection_digest = profile_spi.get("projectionSha256")
    provenance = _strict_read_json(
        platform_root, PROFILE_SPI_PROJECTION_PATH, projection_digest
    )
    source = provenance.get("source")
    packages = provenance.get("packages")
    profile = provenance.get("profile")
    declared_source = foundation_projection.get("source")
    declared_profile = foundation_projection.get("profile")
    receipt_sha256 = profile_spi.get("receiptSha256")
    if (
        provenance.get("kind") != SPI_PROVENANCE_KIND
        or provenance.get("schemaVersion") != 1
        or provenance.get("entry") != SPI_ENTRY_RELATIVE
        or provenance.get("closureSha256") != profile_spi.get("closureSha256")
        or not isinstance(source, dict)
        or {
            "repository": source.get("repository"),
            "baseCommit": source.get("baseCommit"),
        }
        != declared_source
        or not isinstance(profile, dict)
        or not isinstance(declared_profile, dict)
        or {"id": profile.get("id"), "version": profile.get("version")}
        != {"id": declared_profile.get("id"), "version": declared_profile.get("version")}
        or not isinstance(receipt_sha256, str)
        or not HEX64.fullmatch(receipt_sha256)
        or source.get("receiptSha256") != receipt_sha256
        or not isinstance(packages, list)
        or [item.get("name") for item in packages if isinstance(item, dict)]
        != sorted(REQUIRED_FOUNDATION_PACKAGES)
        or any(
            not isinstance(item, dict)
            or item.get("version") != "0.15.0"
            or not HEX64.fullmatch(str(item.get("sha256", "")))
            for item in packages
        )
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Profile SPI provenance 与平台 Foundation authority 不匹配",
        )
    records = provenance.get("files")
    if (
        not isinstance(records, list)
        or provenance.get("fileCount") != len(records)
        or not records
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Profile SPI 闭包文件清单无效",
        )
    expected: dict[str, str] = {}
    for record in records:
        relative = record.get("path") if isinstance(record, dict) else None
        digest = record.get("sha256") if isinstance(record, dict) else None
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not HEX64.fullmatch(digest)
            or relative in expected
            or f"{PROFILE_SPI_ROOT_RELATIVE}/{relative}" not in files
        ):
            raise VerificationError(
                "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
                "Profile SPI 闭包文件记录无效",
            )
        expected[relative] = digest
    if SPI_ENTRY_RELATIVE not in expected:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Profile SPI 入口未被闭包摘要覆盖",
        )
    observed = _foundation_mechanism(platform_root, {
        "operation": "resource-closure",
        "root": str(root),
        "resources": [
            {"path": relative, "role": "input"}
            for relative in expected
        ],
    }).get("resources")
    if (
        not isinstance(observed, list)
        or {item.get("path"): item.get("sha256") for item in observed}
        != expected
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Profile SPI 闭包真实文件摘要漂移",
        )
    digest_result = _foundation_mechanism(platform_root, {
        "operation": "digest-document",
        "document": records,
    })
    if digest_result.get("digest") != provenance.get("closureSha256"):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Profile SPI 闭包清单摘要漂移",
        )


def _validate_foundation_bundle_authority(
    platform_root: Path,
    foundation_projection: dict[str, Any],
    manifest_files: list[Any],
) -> None:
    """Bind the manifest's Foundation identity to the real managed Bundle."""
    if not all(isinstance(item, str) for item in manifest_files):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "platform-manifest files 必须是路径字符串",
        )
    manifest_file_set = set(manifest_files)
    required = {
        FOUNDATION_PROJECTION_PATH,
        FOUNDATION_RUNNER_RELATIVE,
        FOUNDATION_MECHANISMS_PATH,
    }
    if (
        foundation_projection.get("path") != FOUNDATION_PROJECTION_PATH
        or not required.issubset(manifest_file_set)
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "platform-manifest 未绑定固定 Foundation Bundle 入口",
        )
    provenance = _strict_read_json(platform_root, FOUNDATION_PROJECTION_PATH)
    payload = provenance.get("payload")
    records = payload.get("files") if isinstance(payload, dict) else None
    declared_profile = foundation_projection.get("profile")
    declared_source = foundation_projection.get("source")
    if (
        provenance.get("kind") != "skill-family.foundation-projection"
        or provenance.get("schemaVersion") != 1
        or not isinstance(payload, dict)
        or payload.get("digest") != foundation_projection.get("bundleDigest")
        or provenance.get("profile") != declared_profile
        or not isinstance(provenance.get("source"), dict)
        or {
            "repository": provenance["source"].get("repository"),
            "baseCommit": provenance["source"].get("baseCommit"),
        }
        != declared_source
        or not isinstance(records, list)
        or not records
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Foundation projection 与 platform-manifest 身份不匹配",
        )
    expected: dict[str, str] = {}
    for record in records:
        relative = record.get("path") if isinstance(record, dict) else None
        digest = record.get("sha256") if isinstance(record, dict) else None
        platform_relative = (
            f"{FOUNDATION_BUNDLE_ROOT}/{relative}"
            if isinstance(relative, str)
            else None
        )
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not HEX64.fullmatch(digest)
            or relative in expected
            or platform_relative not in manifest_file_set
        ):
            raise VerificationError(
                "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
                "Foundation payload 未被 platform-manifest 完整覆盖",
            )
        expected[relative] = digest
    if not {"runner.mjs", "mechanisms-cli.mjs"}.issubset(expected):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Foundation payload 缺少固定执行入口",
        )
    observed = _foundation_mechanism(platform_root, {
        "operation": "resource-closure",
        "root": str(platform_root / FOUNDATION_BUNDLE_ROOT),
        "resources": [
            {"path": relative, "role": "input"}
            for relative in expected
        ],
    }).get("resources")
    if (
        not isinstance(observed, list)
        or {item.get("path"): item.get("sha256") for item in observed}
        != expected
    ):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Foundation Bundle 真实成员摘要漂移",
        )
    digest_result = _foundation_mechanism(platform_root, {
        "operation": "digest-document",
        "document": records,
    })
    if digest_result.get("digest") != foundation_projection.get("bundleDigest"):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_AUTHORITY_INVALID",
            "Foundation Bundle payload 摘要漂移",
        )


def resolve_profile_spi_entry(
    profile_spi_root: Path | None = None,
) -> tuple[Path, Path]:
    """Return ``(closure_root, entry)`` after full containment validation."""
    platform_root = (
        _injected_platform_root(profile_spi_root)
        if profile_spi_root is not None
        else _production_platform_root()
    )
    if platform_root is None:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_MISSING",
            "当前脚本不在具有 platform-manifest.json 的平台包内",
        )
    root = platform_root / PROFILE_SPI_ROOT_RELATIVE
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
    _validate_profile_spi_authority(platform_root, root)
    return root, entry


def verify_project_profile(
    project_root: Path,
    profile_rel_path: str = "profile.json",
    *,
    profile_spi_root: Path | None = None,
) -> dict[str, Any]:
    """Verify a project-root profile through Foundation Profile SPI v3.

    ``verifyProfile`` is intentionally not used here: it is descriptor-only.
    Every failure mode returns a closed result carrying a stable Audit code;
    the caller decides the domain consequence.
    """
    project_root = Path(project_root).resolve()
    try:
        closure_root, entry = resolve_profile_spi_entry(profile_spi_root)
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


# ---------------------------------------------------------------------------
# 固定公共入口调用支持（P3 第二批 Foundation/MIGRATE 候选函数消费）
#
# 与 verify_project_profile 共用同一闭包解析、同一 Node 22 运行时与失败关闭
# 语义：任何 Foundation 根入口都只能通过这里在已验证 Profile SPI 闭包内执行。
# 所有新函数统一返回关闭字典：成功携带真实 Foundation 输出并追加
# ``authority_ok: True``；基础设施失败返回
# ``{"authority_ok": False, "code": <稳定码>, "blockers": [...]}``。
# 错误码只使用 Foundation 既有稳定码（SPI_RESULT_CODES / FOUNDATION_* /
# SFC20xx / AUD-*），本模块不复制、不新增第二套码表。
# ---------------------------------------------------------------------------


def _invoke_closure_entry(
    script: str,
    argv: list[str],
    *,
    payload: str | None = None,
    profile_spi_root: Path | None = None,
) -> dict[str, Any]:
    """在已验证 Profile SPI 闭包内执行固定 Node 脚本并返回 JSON 对象结果。

    argv 之前总是插入 SPI 入口 URI（脚本用不到时可以忽略）；cwd 固定在闭包
    根，使裸说明符 ``skill-family-harness-node`` / ``skill-family-contracts``
    只解析受管闭包内的真实包。任何失败都以 VerificationError 失败关闭。
    """
    closure_root, entry = resolve_profile_spi_entry(profile_spi_root)
    try:
        node_path, node_version = foundation_bridge.foundation_node_runtime()
    except RuntimeError as exc:
        raise VerificationError(
            "FOUNDATION_NODE_UNAVAILABLE", str(exc)
        ) from exc
    try:
        completed = subprocess.run(
            [
                str(node_path),
                "--input-type=module",
                "-e",
                script,
                entry.as_uri(),
                *argv,
            ],
            input=payload.encode("utf-8") if payload is not None else None,
            capture_output=True,
            timeout=SPI_INVOCATION_TIMEOUT_SECONDS,
            cwd=str(closure_root),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_FAILED", f"闭包 Node 调用失败: {exc}"
        ) from exc
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        detail = (stderr or stdout).strip()
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_FAILED",
            f"闭包 Node 进程退出码 {completed.returncode}: {detail[:512]}",
        )
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_FAILED",
            f"闭包输出不是合法 JSON: {stdout[:256]}",
        ) from exc
    if not isinstance(value, dict):
        raise VerificationError(
            "FOUNDATION_PROFILE_SPI_FAILED", "闭包返回非对象结果"
        )
    value["node_version"] = node_version
    value["closure_root"] = str(closure_root)
    return value


def _closed_failure(code: str, detail: str) -> dict[str, Any]:
    return {"authority_ok": False, "code": code, "blockers": [detail]}


def verify_profile(
    profile_root: Path,
    descriptor_rel_path: str = "profile.json",
    *,
    profile_spi_root: Path | None = None,
) -> dict[str, Any]:
    """Provider descriptor 只通过公共 ``verifyProfile`` 入口校验（固定调用）。

    与 verify_project_profile 平行；任何失败模式都返回携带稳定 Foundation
    错误码的关闭结果，调用方决定领域后果。绝不用 verifyProjectProfile 校验
    descriptor，也绝不用文件名猜测载体类型。
    """
    script = (
        "const { verifyProfile } = await import(process.argv[1]); "
        "const r = await verifyProfile({profileRoot: process.argv[2], "
        "descriptorRelPath: process.argv[3]}); "
        "process.stdout.write(JSON.stringify(r));"
    )
    try:
        result = _invoke_closure_entry(
            script,
            [str(Path(profile_root).resolve()), descriptor_rel_path],
            profile_spi_root=profile_spi_root,
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = result.get("code") == "SPE0000"
    if not result["authority_ok"]:
        result.setdefault("blockers", []).append(
            "Foundation Profile SPI 拒绝 provider descriptor: "
            f"code={result.get('code')} reason={result.get('reason', '')}"
        )
    return result


def estimate_tokens(
    text: str, *, profile_spi_root: Path | None = None
) -> dict[str, Any]:
    """用真实 ``estimateTokens`` 重放输入文本，返回真实估算记录。

    记录携带真实估算器身份（estimator.id/version）、算法、分词明细与 tokens
    输出，供机械候选函数与消费者记录逐项比对；绝不手写估算器元数据。

    （SFA-814 批次传输修复：文本改经 stdin payload 异步流读取。上下文文本是
    规范 JSON 序列化文档，体积可超过进程 argv 单参上限（macOS ~1MB，E2BIG）；
    且 harness 导入会把 fd 0 切到 O_NONBLOCK，同步 readFileSync(0) 在管道尚未
    填满时必然 EAGAIN —— 异步流读取对阻塞/非阻塞 stdin 均稳定。payload 传输
    与流拼接不改变任何估算语义与输出字节。）
    """
    script = (
        "import { estimateTokens } from 'skill-family-harness-node'; "
        "process.stdin.setEncoding('utf8'); "
        "let raw = ''; for await (const chunk of process.stdin) raw += chunk; "
        "process.stdout.write(JSON.stringify(estimateTokens(raw)));"
    )
    try:
        result = _invoke_closure_entry(
            script, [], payload=text, profile_spi_root=profile_spi_root
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = True
    return result


def contracts_authority(*, profile_spi_root: Path | None = None) -> dict[str, Any]:
    """Contracts 0.15.0 根导出的真实 registry、mandatory rules 与检查入口。

    只投影 registry 的对象身份（object/$id/file）与协议、mandatory 规则 ID、
    检查类型和合同版本；不复制完整对象清单，完整 schema 由 Foundation 闭包
    持有。返回 ``schemas`` 每项为 {"object", "$id", "file"}。
    """
    script = (
        "import { loadRegistry, MANDATORY_RULES, CHECK_TYPES, CONTRACTS_VERSION } "
        "from 'skill-family-contracts'; "
        "const registry = loadRegistry(); "
        "process.stdout.write(JSON.stringify({"
        "contractsVersion: CONTRACTS_VERSION,"
        "schemas: registry.schemas.map((entry) => "
        "({object: entry.object, $id: entry.$id, file: entry.file})),"
        "protocols: registry.protocols,"
        "mandatoryRuleIds: MANDATORY_RULES.map((rule) => rule.ruleId),"
        "checkTypes: CHECK_TYPES,"
        "}));"
    )
    try:
        result = _invoke_closure_entry(
            script, [], profile_spi_root=profile_spi_root
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = True
    return result


def check_contracts_operation(
    operation: str, params: dict[str, Any], *, profile_spi_root: Path | None = None
) -> dict[str, Any]:
    """真实 ``checkOperation`` 对消费者实际参数的检查结果。

    返回 {ok, code, errors}（code 为 null / SFC2002 / SFC2003）。参数经
    stdin 传递，避免命令行长度与转义问题。
    """
    script = (
        "import { checkOperation } from 'skill-family-contracts'; "
        "let raw = ''; for await (const chunk of process.stdin) raw += chunk; "
        "const params = JSON.parse(raw); "
        "process.stdout.write(JSON.stringify(checkOperation(process.argv[2], params)));"
    )
    try:
        result = _invoke_closure_entry(
            script,
            [operation],
            payload=json.dumps(params, ensure_ascii=False),
            profile_spi_root=profile_spi_root,
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = True
    return result


def describe_audit_surface(*, profile_spi_root: Path | None = None) -> dict[str, Any]:
    """真实 Audit Surface 三坐标与摘要（describeAuditSurface + digestAuditSurface）。

    摘要一律由 Foundation 计算；Audit 不实现 canonical JSON 或 digest。
    """
    script = (
        "import { describeAuditSurface, digestAuditSurface } from "
        "'skill-family-contracts'; "
        "const surface = describeAuditSurface(); "
        "process.stdout.write(JSON.stringify({"
        "kind: surface.kind,"
        "schemaVersion: surface.schemaVersion,"
        "contractsVersion: surface.contractsVersion,"
        "auditSurfaceVersion: surface.auditSurfaceVersion,"
        "contractObjects: surface.contractObjects,"
        "mandatoryRuleIds: surface.mandatoryRuleIds,"
        "checkTypes: surface.checkTypes,"
        "surfaceDigest: digestAuditSurface(surface),"
        "}));"
    )
    try:
        result = _invoke_closure_entry(
            script, [], profile_spi_root=profile_spi_root
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = True
    return result


def describe_baseline_pin(
    frozen_at: str,
    note: str,
    *,
    supersedes: str | None = None,
    provenance: str | None = None,
    profile_spi_root: Path | None = None,
) -> dict[str, Any]:
    """用真实 ``describeBaselinePin`` 物化预期 baseline pin。

    枚举字段（frozenAt/note/supersedes/provenance）与默认值语义由 Foundation
    0.15.0 决定；摘要由 Foundation 计算。frozenAt 或 note 非法时 Foundation
    抛出 TypeError，本函数以 FOUNDATION_PROFILE_SPI_FAILED 失败关闭返回。
    """
    script = (
        "import { describeBaselinePin } from 'skill-family-contracts'; "
        "const frozenAt = process.argv[2]; "
        "const note = process.argv[3]; "
        "const supersedes = process.argv[4] === '__audit_none__' "
        "? null : process.argv[4]; "
        "const provenance = process.argv[5] === '__audit_none__' "
        "? undefined : process.argv[5]; "
        "process.stdout.write(JSON.stringify("
        "describeBaselinePin({frozenAt, note, supersedes, provenance})));"
    )
    try:
        result = _invoke_closure_entry(
            script,
            [
                frozen_at,
                note,
                supersedes if supersedes is not None else "__audit_none__",
                provenance if provenance is not None else "__audit_none__",
            ],
            profile_spi_root=profile_spi_root,
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = True
    return result


def verify_baseline_pin(
    pin: dict[str, Any], *, profile_spi_root: Path | None = None
) -> dict[str, Any]:
    """真实 ``verifyBaselinePin`` 校验结果（{ok, findings}）。

    findings 使用 Foundation 命名空间码 AUD-LOCK-001 / AUD-BASE-001；
    Audit 不解释、不改写。
    """
    script = (
        "import { verifyBaselinePin } from 'skill-family-contracts'; "
        "let raw = ''; for await (const chunk of process.stdin) raw += chunk; "
        "process.stdout.write(JSON.stringify(verifyBaselinePin(JSON.parse(raw))));"
    )
    try:
        result = _invoke_closure_entry(
            script,
            [],
            payload=json.dumps(pin, ensure_ascii=False),
            profile_spi_root=profile_spi_root,
        )
    except VerificationError as exc:
        return _closed_failure(exc.code, str(exc))
    result["authority_ok"] = True
    return result
