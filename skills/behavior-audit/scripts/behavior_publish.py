"""Atomically publish the fixed behavior-audit artifact set."""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import sys


_FILENAMES = frozenset(
    {
        "behavior-result.json",
        "execution-records.json",
        "evidence-list.json",
        "regression-record.json",
    }
)


class BehaviorPublishError(Exception):
    """Raised when the fixed artifact set cannot be published atomically."""


def _validate_payloads(artifact_bytes: dict[str, bytes]) -> None:
    if not isinstance(artifact_bytes, dict):
        raise BehaviorPublishError("artifact_bytes must be an object")
    actual = set(artifact_bytes)
    if actual != _FILENAMES:
        missing = sorted(_FILENAMES - actual)
        extra = sorted(actual - _FILENAMES)
        raise BehaviorPublishError(
            f"artifact file set mismatch; missing={missing}, extra={extra}"
        )
    for filename, content in artifact_bytes.items():
        if not isinstance(content, bytes):
            raise BehaviorPublishError(f"{filename} content must be bytes")


def _validate_output_path(output_dir: str) -> tuple[str, str]:
    if not isinstance(output_dir, str) or not output_dir:
        raise BehaviorPublishError("output_dir must be a non-empty string")
    if not os.path.isabs(output_dir):
        raise BehaviorPublishError("output_dir must be absolute")
    normalized = os.path.normpath(output_dir)
    if normalized != output_dir:
        raise BehaviorPublishError("output_dir must already be normalized")
    parent, name = os.path.split(output_dir)
    if not parent or name in {"", ".", ".."}:
        raise BehaviorPublishError("output_dir must name a child directory")
    if not os.path.isdir(parent):
        raise BehaviorPublishError("output_dir parent must be an existing directory")
    if os.path.realpath(parent) != parent:
        raise BehaviorPublishError("output_dir parent or ancestor contains a symlink")
    return parent, name


def validate_output_target(output_dir: str) -> None:
    """Fail before fixture execution when the requested destination is unusable."""

    parent, output_name = _validate_output_path(output_dir)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(parent, flags)
    try:
        try:
            os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise BehaviorPublishError("output_dir already exists")
    finally:
        os.close(parent_fd)


def parent_fd_for_child(parent_fd: int, child_name: str) -> int:
    """Open a child directory without following a replacement symlink."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(child_name, flags, dir_fd=parent_fd)


def _rename_no_replace(parent_fd: int, source: str, destination: str) -> None:
    """Atomically rename a sibling directory while refusing any destination."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        renameatx_np = libc.renameatx_np
        renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            0x00000004,  # RENAME_EXCL from <sys/stdio.h>
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_fd,
            source_bytes,
            parent_fd,
            destination_bytes,
            0x00000001,  # RENAME_NOREPLACE from <linux/fs.h>
        )
    else:
        raise BehaviorPublishError(
            "atomic no-replace directory rename is unavailable on this platform"
        )

    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise BehaviorPublishError("output_dir already exists")
        raise OSError(error_number, os.strerror(error_number))


def publish_artifacts(
    *,
    output_dir: str,
    artifact_bytes: dict[str, bytes],
) -> None:
    """Publish the four behavior-domain files with one no-replace rename."""

    _validate_payloads(artifact_bytes)
    parent, output_name = _validate_output_path(output_dir)
    parent_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd = os.open(parent, parent_flags)
    temp_name = f".behavior-audit-{output_name}-{secrets.token_hex(8)}"
    temp_fd: int | None = None
    written: list[str] = []
    published = False
    try:
        try:
            os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise BehaviorPublishError("output_dir already exists")

        os.mkdir(temp_name, mode=0o700, dir_fd=parent_fd)
        temp_fd = parent_fd_for_child(parent_fd, temp_name)

        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for filename in sorted(_FILENAMES):
            file_fd = os.open(filename, file_flags, 0o600, dir_fd=temp_fd)
            written.append(filename)
            try:
                view = memoryview(artifact_bytes[filename])
                while view:
                    count = os.write(file_fd, view)
                    if count <= 0:
                        raise OSError("short write while publishing behavior artifacts")
                    view = view[count:]
                os.fsync(file_fd)
            finally:
                os.close(file_fd)

        os.fsync(temp_fd)
        _rename_no_replace(parent_fd, temp_name, output_name)
        published = True
        os.fsync(parent_fd)
    except BehaviorPublishError:
        raise
    except OSError as exc:
        raise BehaviorPublishError(f"atomic publish failed: {exc}") from exc
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if not published:
            cleanup_fd: int | None = None
            try:
                cleanup_fd = parent_fd_for_child(parent_fd, temp_name)
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

    return None
