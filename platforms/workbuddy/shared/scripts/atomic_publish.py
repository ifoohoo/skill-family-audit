"""Audit adapter for Foundation's candidate fixed-set publisher."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from collections.abc import Collection, Mapping
from pathlib import Path


class AtomicPublishError(Exception):
    """A fixed artifact set could not be published atomically."""


def _foundation_host():
    host = sys.modules.get("conformance_check")
    if host is not None:
        return host
    platform_root = Path(__file__).resolve().parents[2]
    script = (
        platform_root
        / "skills/skill-family-audit-conformance-audit/scripts/conformance_check.py"
    )
    if script.is_symlink() or not script.is_file():
        raise AtomicPublishError("AUDIT_FOUNDATION_HOST_MISSING")
    spec = importlib.util.spec_from_file_location("conformance_check", script)
    if spec is None or spec.loader is None:
        raise AtomicPublishError("AUDIT_FOUNDATION_HOST_INVALID")
    host = importlib.util.module_from_spec(spec)
    sys.modules["conformance_check"] = host
    spec.loader.exec_module(host)
    return host


def _foundation_refusal_code(message: str) -> str:
    """把 Foundation fixed-set 机制的拒绝原因映射为稳定失败码。

    失败码与 Foundation 发布回执的 error.code 命名一致：
    TARGET_EXISTS（目标已占用）、PATH_UNSAFE（目标/源路径不安全）。
    """
    if "target must be absent" in message:
        return "TARGET_EXISTS"
    if (
        "targetParent" in message
        or "targetSegment" in message
        or "sourceRoot must" in message
    ):
        return "PATH_UNSAFE"
    return "REFUSED"


def _call_fixed_operation(operation: str, params: dict) -> dict:
    if operation not in {
        "create-fixed-set-publication-manifest",
        "publish-fixed-set",
    }:
        raise AtomicPublishError("AUDIT_FOUNDATION_OPERATION_NOT_ALLOWED")
    host = _foundation_host()
    try:
        result = host.call_foundation_cli(
            host.foundation_runner(),
            "mechanisms-cli.mjs",
            {"operation": operation, "params": params},
        )
    except Exception as exc:
        code = _foundation_refusal_code(str(exc))
        # 保留 Foundation 原始拒绝原因（含机制名与具体字段），使既有
        # 断言（如 bundle 篡改场景的 "payload member digest mismatch"）
        # 与稳定失败码契约同时可匹配；失败码本身不受影响。
        raise AtomicPublishError(
            f"Foundation fixed-set publication refused: {code}: {exc}"
        ) from exc
    if not isinstance(result, dict):
        raise AtomicPublishError("Foundation fixed-set operation returned invalid response")
    return result


def publish_fixed_artifact_set(
    *,
    output_dir: str,
    artifact_bytes: Mapping[str, bytes],
    filenames: Collection[str],
    publisher_id: str,
) -> None:
    """Stage exactly ``filenames`` and publish them through Foundation."""

    expected = frozenset(filenames)
    if (
        not isinstance(artifact_bytes, dict)
        or not expected
        or set(artifact_bytes) != expected
        or any(not isinstance(value, bytes) for value in artifact_bytes.values())
    ):
        actual = set(artifact_bytes) if isinstance(artifact_bytes, dict) else set()
        raise AtomicPublishError(
            "artifact file set or byte payload mismatch; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    if not publisher_id or any(
        character not in "abcdefghijklmnopqrstuvwxyz-" for character in publisher_id
    ):
        raise AtomicPublishError(
            "publisher_id must be a lowercase hyphenated identifier"
        )

    # 仅做请求构造所需的最小形状校验；规范化绝对路径与真实父目录语义
    # 由 Foundation fixed-set 机制验证（失败码 PATH_UNSAFE / TARGET_EXISTS）。
    if not isinstance(output_dir, str) or not output_dir:
        raise AtomicPublishError("output_dir must be a non-empty string")
    if not os.path.isabs(output_dir):
        raise AtomicPublishError("output_dir must be an absolute path")
    parent, output_name = os.path.split(output_dir)
    if not parent or output_name in {"", ".", ".."}:
        raise AtomicPublishError("output_dir must name a child directory")
    source_root = Path(
        tempfile.mkdtemp(prefix=f".{publisher_id}-{output_name}-", dir=parent)
    )
    try:
        for filename in sorted(expected):
            target = source_root / filename
            with target.open("xb") as stream:
                stream.write(artifact_bytes[filename])
            target.chmod(0o600)
        source_root.chmod(0o700)
        params = {
            "sourceRoot": str(source_root),
            "targetParent": parent,
            "targetSegment": output_name,
        }
        manifest = _call_fixed_operation(
            "create-fixed-set-publication-manifest", params
        )
        if manifest.get("kind") != "skill-family.fixed-set-publication-manifest":
            raise AtomicPublishError(
                "Foundation fixed-set manifest returned invalid contract"
            )
        receipt = _call_fixed_operation(
            "publish-fixed-set", {**params, "manifest": manifest}
        )
        if (
            receipt.get("status") != "succeeded"
            or receipt.get("commitState") != "rename-committed"
            or receipt.get("verification") != "verified"
            or receipt.get("durability") != "synced"
        ):
            code = receipt.get("error", {}).get("code", "REFUSED")
            raise AtomicPublishError(f"Foundation fixed-set publication refused: {code}")
    finally:
        if source_root.exists() and source_root.parent == Path(parent):
            shutil.rmtree(source_root)


__all__ = ["AtomicPublishError", "publish_fixed_artifact_set"]
