"""Atomically publish the fixed release-audit artifact set."""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import secrets
import sys


FILENAMES = frozenset(
    {
        "task.json",
        "result.json",
        "release-result.json",
        "gate-findings.json",
        "evidence-list.json",
        "blocking-reasons.json",
    }
)


class ReleasePublishError(Exception):
    """The fixed artifact set could not be published without replacement."""


def _validate_payloads(artifact_bytes: dict[str, bytes]) -> None:
    if not isinstance(artifact_bytes, dict):
        raise ReleasePublishError("artifact_bytes 必须是对象")
    actual = set(artifact_bytes)
    if actual != FILENAMES:
        raise ReleasePublishError(
            "artifact 文件集合不一致; "
            f"missing={sorted(FILENAMES - actual)}, extra={sorted(actual - FILENAMES)}"
        )
    if any(not isinstance(content, bytes) for content in artifact_bytes.values()):
        raise ReleasePublishError("每个 artifact 内容必须是 bytes")


def _validate_output_path(output_dir: str) -> tuple[str, str]:
    if not isinstance(output_dir, str) or not output_dir:
        raise ReleasePublishError("output_dir 必须是非空字符串")
    if not os.path.isabs(output_dir) or os.path.normpath(output_dir) != output_dir:
        raise ReleasePublishError("output_dir 必须是规范化绝对路径")
    parent, name = os.path.split(output_dir)
    if not parent or name in {"", ".", ".."}:
        raise ReleasePublishError("output_dir 必须命名一个子目录")
    if not os.path.isdir(parent):
        raise ReleasePublishError("output_dir 父目录必须已存在")
    if os.path.realpath(parent) != parent:
        raise ReleasePublishError("output_dir 父目录或祖先含符号链接")
    return parent, name


def _open_child_dir(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    return os.open(name, flags, dir_fd=parent_fd)


def validate_output_target(output_dir: str) -> None:
    """Preflight a destination before any receipt processing."""
    parent, name = _validate_output_path(output_dir)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    parent_fd = os.open(parent, flags)
    try:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ReleasePublishError("output_dir 已存在")
    finally:
        os.close(parent_fd)


def _rename_no_replace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        function = libc.renameatx_np
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            0x00000004,  # RENAME_EXCL
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            0x00000001,  # RENAME_NOREPLACE
        )
    else:
        raise ReleasePublishError(
            "当前平台不支持 no-replace 原子目录重命名"
        )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ReleasePublishError("output_dir 已存在")
        raise OSError(error_number, os.strerror(error_number))


def publish_artifacts(
    *,
    output_dir: str,
    artifact_bytes: dict[str, bytes],
) -> dict[str, str]:
    """Publish all six files with one same-directory no-replace rename."""
    _validate_payloads(artifact_bytes)
    parent, output_name = _validate_output_path(output_dir)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    parent_fd = os.open(parent, flags)
    temp_name = f".release-audit-{output_name}-{secrets.token_hex(8)}"
    temp_fd: int | None = None
    written: list[str] = []
    published = False
    try:
        try:
            os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ReleasePublishError("output_dir 已存在")

        os.mkdir(temp_name, mode=0o700, dir_fd=parent_fd)
        temp_fd = _open_child_dir(parent_fd, temp_name)
        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for filename in sorted(FILENAMES):
            file_fd = os.open(filename, file_flags, 0o600, dir_fd=temp_fd)
            written.append(filename)
            try:
                view = memoryview(artifact_bytes[filename])
                while view:
                    count = os.write(file_fd, view)
                    if count <= 0:
                        raise OSError("release artifact 写入不完整")
                    view = view[count:]
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
        os.fsync(temp_fd)
        _rename_no_replace(parent_fd, temp_name, output_name)
        published = True
        os.fsync(parent_fd)
    except ReleasePublishError:
        raise
    except OSError as exc:
        raise ReleasePublishError(f"原子发布失败: {exc}") from exc
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if not published:
            cleanup_fd: int | None = None
            try:
                cleanup_fd = _open_child_dir(parent_fd, temp_name)
                for filename in reversed(written):
                    try:
                        os.unlink(filename, dir_fd=cleanup_fd)
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, OSError):
                pass
            finally:
                if cleanup_fd is not None:
                    os.close(cleanup_fd)
            try:
                os.rmdir(temp_name, dir_fd=parent_fd)
            except (FileNotFoundError, OSError):
                pass
        os.close(parent_fd)
    return {
        name: hashlib.sha256(content).hexdigest()
        for name, content in sorted(artifact_bytes.items())
    }


__all__ = [
    "FILENAMES",
    "ReleasePublishError",
    "publish_artifacts",
    "validate_output_target",
]
