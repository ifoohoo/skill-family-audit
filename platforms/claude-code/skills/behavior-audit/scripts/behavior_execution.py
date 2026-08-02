"""behavior-audit 进程与副作用执行引擎。

只实现已验证 fixture plan 的进程执行、严格快照、期望核对和已知副作用清理。
不构造公共信封、报告或 CLI。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# 公共异常
# ---------------------------------------------------------------------------


class BehaviorExecutionError(Exception):
    """调用边界损坏或无法可靠快照时抛出。

    仅在输入校验失败、快照操作失败或路径安全检查失败时使用。
    执行失败（退出码不匹配等）通过返回记录表达，不抛此异常。
    """


# ---------------------------------------------------------------------------
# 公共 API
# ---------------------------------------------------------------------------


def snapshot_tree(root: str) -> dict[str, dict[str, Any]]:
    """对目录树做严格快照，不跟随符号链接，不跳过隐藏文件/目录。

    Parameters
    ----------
    root
        要快照的目录绝对路径。

    Returns
    -------
    dict
        键为相对于 *root* 的路径（``/`` 分隔，不含前导 ``./``），
        值为节点信息字典：

        - file:      ``{"type": "file", "digest": "<sha256hex>"}``
        - directory: ``{"type": "directory"}``
        - symlink:   ``{"type": "symlink", "target": "<lexical_target>"}``
        - other:     ``{"type": "other", "mode": <int>}``

    Raises
    ------
    BehaviorExecutionError
        任何 lstat、scandir 或文件读取失败均抛出，禁止跳过。
    """
    if not os.path.isabs(root):
        raise BehaviorExecutionError(f"快照根必须是绝对路径: {root}")
    _reject_symlink_ancestors(root, "snapshot root")
    resolved_root = os.path.realpath(root)
    if not os.path.isdir(resolved_root):
        raise BehaviorExecutionError(f"快照根不是目录: {root}")
    snapshot: dict[str, dict[str, Any]] = {}

    def _walk(dir_path: str, rel_prefix: str) -> None:
        try:
            entries = list(os.scandir(dir_path))
        except OSError as exc:
            raise BehaviorExecutionError(
                f"scandir 失败: {dir_path}: {exc}"
            ) from exc

        for entry in entries:
            rel = f"{rel_prefix}{entry.name}"

            # -- lstat（不跟随符号链接） --
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BehaviorExecutionError(
                    f"lstat 失败: {entry.path}: {exc}"
                ) from exc

            if entry.is_symlink():
                try:
                    target = os.readlink(entry.path)
                except OSError as exc:
                    raise BehaviorExecutionError(
                        f"readlink 失败: {entry.path}: {exc}"
                    ) from exc
                snapshot[rel] = {"type": "symlink", "target": target}

            elif entry.is_file(follow_symlinks=False):
                try:
                    with open(entry.path, "rb") as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()
                except OSError as exc:
                    raise BehaviorExecutionError(
                        f"读取文件失败: {entry.path}: {exc}"
                    ) from exc
                snapshot[rel] = {"type": "file", "digest": digest}

            elif entry.is_dir(follow_symlinks=False):
                snapshot[rel] = {"type": "directory"}
                _walk(entry.path, f"{rel}/")

            else:
                snapshot[rel] = {"type": "other", "mode": st.st_mode}

    _walk(resolved_root, "")
    return snapshot


def diff_snapshots(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    """比较两个快照，返回差异集合。

    Returns
    -------
    dict
        ``{"added": set[str], "removed": set[str], "modified": set[str]}``

        - added:    在 *after* 中存在、*before* 中不存在的路径
        - removed:  在 *before* 中存在、*after* 中不存在的路径
        - modified: 两者均存在但节点信息不同（含类型变化）的路径
    """
    before_keys = frozenset(before)
    after_keys = frozenset(after)

    added = set(after_keys - before_keys)
    removed = set(before_keys - after_keys)
    modified = {
        k for k in (before_keys & after_keys) if before[k] != after[k]
    }

    return {"added": added, "removed": removed, "modified": modified}


def run_fixture(
    *,
    fixture: dict[str, Any],
    sandbox_root: str,
    target_project_root: str,
    isolation_max_wall_seconds: float,
) -> dict[str, Any]:
    """执行单个 fixture 并返回 JSON 可序列化的执行记录。

    只有调用边界损坏或无法可靠快照时抛 ``BehaviorExecutionError``。
    执行失败、期望不匹配、副作用未知等均通过返回记录的 ``status`` 字段表达，
    不抛弃任何失败证据。

    Parameters
    ----------
    fixture
        已由 ``behavior_fixture.load_and_validate_fixture_plan()`` 规范化的
        fixture 元素，字段包括
        ``fixture_id, category, executable, argv, cwd, write_set,
        expected_output_files, timeout_seconds, environment, expected``。
    sandbox_root
        sandbox 根目录绝对路径。
    target_project_root
        被审计项目根目录绝对路径。
    isolation_max_wall_seconds
        隔离层最大墙钟时间上限（秒）。
    """

    # ------------------------------------------------------------------
    # 0. 提取 fixture 字段
    # ------------------------------------------------------------------
    fixture_id: str = fixture["fixture_id"]
    category: str = fixture["category"]
    executable: str = fixture["executable"]
    argv: list[str] = list(fixture["argv"])
    cwd: str = fixture["cwd"]
    write_set: list[str] = list(fixture["write_set"])
    expected_output_files: list[dict[str, str]] = [
        dict(item) for item in fixture["expected_output_files"]
    ]
    timeout_cfg: float = float(fixture["timeout_seconds"])
    fixture_env: dict[str, str] = dict(fixture.get("environment") or {})
    expected: dict[str, Any] = fixture["expected"]

    sandbox_resolved = os.path.realpath(sandbox_root)
    target_resolved = os.path.realpath(target_project_root)

    # ------------------------------------------------------------------
    # 1. 路径安全校验（需求 2）
    #    cwd、executable、argv[0]、write_set 必须为绝对路径且位于 sandbox 内；
    #    不信任任何相对路径。
    # ------------------------------------------------------------------
    _assert_absolute_within(cwd, sandbox_resolved, "cwd")
    _assert_absolute_within(executable, sandbox_resolved, "executable")
    if not argv or argv[0] != executable:
        raise BehaviorExecutionError("argv[0] 必须与已验证 executable 完全相同")
    _assert_absolute_within(argv[0], sandbox_resolved, "argv[0]")
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise BehaviorExecutionError(f"executable 不再是可执行普通文件: {executable}")
    if not os.path.isdir(cwd):
        raise BehaviorExecutionError(f"cwd 不再是目录: {cwd}")
    for ws in write_set:
        _assert_absolute_within(ws, sandbox_resolved, "write_set entry")

    # ------------------------------------------------------------------
    # 2. 执行前快照（需求 2）
    # ------------------------------------------------------------------
    target_snap_before = snapshot_tree(target_project_root)
    sandbox_snap_before = snapshot_tree(sandbox_root)

    # ------------------------------------------------------------------
    # 3. write_set 执行前存在性记录（需求 6）
    #    "允许的 write_set 在执行前必须不存在"
    # ------------------------------------------------------------------
    existed_before: dict[str, bool] = {
        ws: os.path.lexists(ws) for ws in write_set
    }
    preexisting = sorted(ws for ws, existed in existed_before.items() if existed)
    if preexisting:
        raise BehaviorExecutionError(
            f"write_set 在执行前已存在，拒绝覆盖: {preexisting}"
        )

    # ------------------------------------------------------------------
    # 4. 构建最小无秘密环境（需求 3）
    # ------------------------------------------------------------------
    env = _build_minimal_env(fixture_env, cwd)
    env_keys = sorted(env)
    env_digest = hashlib.sha256(
        "\n".join(f"{k}={env[k]}" for k in env_keys).encode()
    ).hexdigest()

    # ------------------------------------------------------------------
    # 5. 执行进程（需求 3、4）
    # ------------------------------------------------------------------
    timeout = min(timeout_cfg, isolation_max_wall_seconds)
    start_utc = datetime.now(timezone.utc)
    start_mono = time.monotonic()

    proc_record = _capture_process(executable, argv, cwd, env, timeout)

    end_mono = time.monotonic()
    end_utc = datetime.now(timezone.utc)
    duration = end_mono - start_mono

    # ------------------------------------------------------------------
    # 6. 执行后快照
    # ------------------------------------------------------------------
    target_snap_after = snapshot_tree(target_project_root)
    sandbox_snap_after = snapshot_tree(sandbox_root)

    # ------------------------------------------------------------------
    # 7. target diff（需求 5）
    #    任何新增、修改、删除或节点类型变化 → UNKNOWN；
    #    停止进一步清理未知目标，不得返回通过。
    # ------------------------------------------------------------------
    target_diff = diff_snapshots(target_snap_before, target_snap_after)
    target_changed = bool(
        target_diff["added"]
        or target_diff["removed"]
        or target_diff["modified"]
    )
    side_effect_status = "UNKNOWN" if target_changed else "CLEAN"

    # ------------------------------------------------------------------
    # 8. sandbox diff（需求 6）
    #    变化只允许等于 write_set 路径或位于某个 write_set 目录路径之下；
    #    允许的 write_set 在执行前必须不存在。其他变化均 UNKNOWN。
    # ------------------------------------------------------------------
    sandbox_diff = diff_snapshots(sandbox_snap_before, sandbox_snap_after)
    all_sandbox_changes = (
        sandbox_diff["added"]
        | sandbox_diff["removed"]
        | sandbox_diff["modified"]
    )

    unknown_writes: list[str] = []
    for rel_path in sorted(all_sandbox_changes):
        abs_path = os.path.join(sandbox_resolved, rel_path)
        allowed = False
        for ws in write_set:
            if existed_before[ws]:
                continue  # 执行前已存在 → 不允许写入
            if abs_path == ws or abs_path.startswith(ws + os.sep):
                allowed = True
                break
        if not allowed:
            unknown_writes.append(rel_path)

    if unknown_writes:
        side_effect_status = "UNKNOWN"

    # ------------------------------------------------------------------
    # 9. 期望核对（需求 7）
    #    exit code、stdout/stderr SHA-256、expected output 文件集合和内容摘要；
    #    缺件、多余输出、类型错误或摘要错误均失败。
    # ------------------------------------------------------------------
    actual_created_files = {
        os.path.join(sandbox_resolved, rel)
        for rel in sandbox_diff["added"]
        if sandbox_snap_after[rel].get("type") == "file"
        and any(
            os.path.join(sandbox_resolved, rel) == ws
            or os.path.join(sandbox_resolved, rel).startswith(ws + os.sep)
            for ws in write_set
        )
    }
    expected_judgment, expected_failures, output_evidence = _check_expected(
        proc_record,
        expected,
        expected_output_files,
        actual_created_files,
    )

    # ------------------------------------------------------------------
    # 10. 清理已授权写入（需求 8）
    #     只清理本轮前不存在的 write_set：先文件/符号链接，再目录（递归）。
    #     清理前再次确认路径在 sandbox，拒绝符号链接祖先逃逸。
    # ------------------------------------------------------------------
    cleanup_evidence = _cleanup_authored_writes(
        write_set, existed_before, sandbox_resolved
    )

    # ------------------------------------------------------------------
    # 11. 清理后验证（需求 9）
    #     sandbox 必须逐字典等于执行前快照；否则 cleanup_status=FAILED。
    # ------------------------------------------------------------------
    sandbox_snap_after_cleanup = snapshot_tree(sandbox_root)
    cleanup_diff = diff_snapshots(
        sandbox_snap_before, sandbox_snap_after_cleanup
    )
    cleanup_has_residual = bool(
        cleanup_diff["added"]
        or cleanup_diff["removed"]
        or cleanup_diff["modified"]
    )
    cleanup_status = (
        "FAILED"
        if cleanup_has_residual or cleanup_evidence["failed"]
        else "OK"
    )

    # ------------------------------------------------------------------
    # 12. 总体状态（需求 10）
    #     status=SUCCEEDED 只允许所有合取门禁为真。
    # ------------------------------------------------------------------
    all_gates_ok = (
        expected_judgment == "PASS"
        and not proc_record["timed_out"]
        and proc_record["launch_error"] is None
        and side_effect_status == "CLEAN"
        and cleanup_status == "OK"
    )
    status = "SUCCEEDED" if all_gates_ok else "FAILED"

    # ------------------------------------------------------------------
    # 13. 组装返回记录（需求 10）
    # ------------------------------------------------------------------
    return {
        # 身份 / 分类
        "fixture_id": fixture_id,
        "category": category,
        "executable": executable,
        "argv": argv,
        "cwd": cwd,
        # 时间
        "start_time": start_utc.isoformat(),
        "end_time": end_utc.isoformat(),
        "duration_seconds": round(duration, 6),
        # 进程结果
        "exit_code": proc_record["exit_code"],
        "timed_out": proc_record["timed_out"],
        "launch_error": proc_record["launch_error"],
        "timeout_seconds": timeout,
        # 摘要（不记录原始值）
        "stdout_sha256": proc_record["stdout_sha256"],
        "stderr_sha256": proc_record["stderr_sha256"],
        "env_keys": env_keys,
        "env_digest": env_digest,
        # 期望判定
        "expected": {
            "exit_code": expected["exit_code"],
            "stdout_digest": expected["stdout_digest"],
            "stderr_digest": expected["stderr_digest"],
            "output_files": expected.get("output_files") or {},
        },
        "expected_judgment": expected_judgment,
        "expected_failures": expected_failures,
        # 输出证据
        "output_file_evidence": output_evidence,
        # diff
        "target_diff": {
            "added": sorted(target_diff["added"]),
            "removed": sorted(target_diff["removed"]),
            "modified": sorted(target_diff["modified"]),
        },
        "sandbox_diff": {
            "added": sorted(sandbox_diff["added"]),
            "removed": sorted(sandbox_diff["removed"]),
            "modified": sorted(sandbox_diff["modified"]),
        },
        # 未知写入
        "unknown_writes": unknown_writes,
        "side_effect_status": side_effect_status,
        # 清理
        "cleanup_evidence": cleanup_evidence,
        "cleanup_status": cleanup_status,
        # 总体
        "status": status,
    }


# ---------------------------------------------------------------------------
# 内部辅助函数（不导出）
# ---------------------------------------------------------------------------


def _assert_absolute_within(
    path: str,
    boundary_resolved: str,
    label: str,
) -> None:
    """验证 *path* 为绝对路径且 ``os.path.realpath`` 后位于 *boundary_resolved* 内。

    Raises
    ------
    BehaviorExecutionError
        路径不是绝对路径或解析后逃逸出边界。
    """
    if not os.path.isabs(path):
        raise BehaviorExecutionError(
            f"{label} 不是绝对路径: {path}"
        )
    _reject_symlink_ancestors(path, label)
    resolved = os.path.realpath(path)
    if resolved == boundary_resolved:
        return
    if not resolved.startswith(boundary_resolved + os.sep):
        raise BehaviorExecutionError(
            f"{label} 位于 sandbox 外: {path} "
            f"(resolved={resolved}, boundary={boundary_resolved})"
        )


def _reject_symlink_ancestors(path: str, label: str) -> None:
    current = os.path.abspath(path)
    while True:
        if os.path.islink(current):
            raise BehaviorExecutionError(
                f"{label} 包含符号链接路径组件: {current}"
            )
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def _build_minimal_env(
    fixture_env: dict[str, str], cwd: str
) -> dict[str, str]:
    """构建固定最小无秘密环境，叠加 fixture 明确环境。

    fixture_env 覆盖最小环境中的同名键。
    """
    reserved = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "PWD",
        "OLDPWD",
        "SHELL",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
    }
    conflicts = sorted(reserved & set(fixture_env))
    if conflicts:
        raise BehaviorExecutionError(
            f"fixture environment 不得覆盖隔离保留键: {conflicts}"
        )
    env: dict[str, str] = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": cwd,
        "TMPDIR": cwd,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    env.update(fixture_env)
    return env


def _capture_process(
    executable: str,
    argv: list[str],
    cwd: str,
    env: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    """用 ``Popen`` 执行进程，捕获原始 stdout/stderr，处理超时。

    机械要求：

    - ``shell=False``, ``stdin=DEVNULL``, ``start_new_session=True``
    - 超时时 ``SIGTERM`` → 进程组，短暂等待；仍存活则 ``SIGKILL``；
      最终必须 ``communicate/wait`` 回收并保存已捕获输出。
    """
    timed_out = False
    stdout = b""
    stderr = b""
    launch_error = None

    try:
        proc = subprocess.Popen(
            argv,
            executable=executable,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        launch_error = f"{type(exc).__name__}: {exc}"
        return {
            "exit_code": None,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "timed_out": False,
            "launch_error": launch_error,
        }

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        # SIGTERM → 进程组
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError:
            pass
        # 短暂等待（5 秒）优雅退出
        try:
            stdout, stderr = proc.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            # 仍存活 → SIGKILL → 进程组
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
            # 最终必须回收
            stdout, stderr = proc.communicate()

    return {
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "timed_out": timed_out,
        "launch_error": launch_error,
    }


def _check_expected(
    proc_record: dict[str, Any],
    expected: dict[str, Any],
    expected_output_files: list[dict[str, str]],
    actual_created_files: set[str],
) -> tuple[str, list[str], dict[str, dict[str, Any]]]:
    """机械核对退出码、stdout/stderr 摘要、输出文件集合与内容摘要。

    Returns
    -------
    (judgment, failures, output_evidence)

    judgment
        ``"PASS"`` 或 ``"FAIL"``
    failures
        失败原因字符串列表
    output_evidence
        路径 → ``{"exists": bool, "type": str|None, "digest": str|None}``
    """
    failures: list[str] = []
    if proc_record["launch_error"] is not None:
        failures.append(f"launch_error: {proc_record['launch_error']}")
    if proc_record["timed_out"]:
        failures.append("process timed out")

    # -- 退出码 --
    if proc_record["exit_code"] != expected["exit_code"]:
        failures.append(
            f"exit_code: expected={expected['exit_code']}, "
            f"actual={proc_record['exit_code']}"
        )

    # -- stdout 摘要 --
    if proc_record["stdout_sha256"] != expected["stdout_digest"]:
        failures.append(
            f"stdout_digest: expected={expected['stdout_digest']}, "
            f"actual={proc_record['stdout_sha256']}"
        )

    # -- stderr 摘要 --
    if proc_record["stderr_sha256"] != expected["stderr_digest"]:
        failures.append(
            f"stderr_digest: expected={expected['stderr_digest']}, "
            f"actual={proc_record['stderr_sha256']}"
        )

    # -- 输出文件：集合 + 内容摘要 --
    expected_digests = {
        item["path"]: item["content_digest"]
        for item in expected_output_files
    }
    declared_expected = {
        item["path"]: item["content_digest"]
        for item in expected.get("output_files", [])
    }
    if declared_expected != expected_digests:
        failures.append(
            "normalized expected_output_files 与 expected.output_files 不一致"
        )
    if actual_created_files != set(expected_digests):
        failures.append(
            "output file set mismatch: "
            f"expected={sorted(expected_digests)}, "
            f"actual={sorted(actual_created_files)}"
        )
    output_evidence: dict[str, dict[str, Any]] = {}

    for path, expected_digest in expected_digests.items():
        evidence: dict[str, Any] = {
            "exists": False,
            "type": None,
            "digest": None,
        }

        if not os.path.lexists(path):
            # 缺件
            failures.append(f"output file missing: {path}")

        elif not os.path.isfile(path):
            # 类型错误
            evidence["exists"] = True
            evidence["type"] = "not_regular_file"
            failures.append(f"output file wrong type: {path}")

        else:
            # 正常文件 → 核对摘要
            evidence["exists"] = True
            evidence["type"] = "file"
            try:
                with open(path, "rb") as fh:
                    actual_digest = hashlib.sha256(fh.read()).hexdigest()
            except OSError as exc:
                failures.append(f"output file unreadable: {path}: {exc}")
                output_evidence[path] = evidence
                continue

            evidence["digest"] = actual_digest
            if actual_digest != expected_digest:
                failures.append(
                    f"output file digest mismatch: {path}: "
                    f"expected={expected_digest}, "
                    f"actual={actual_digest}"
                )

        output_evidence[path] = evidence

    judgment = "PASS" if not failures else "FAIL"
    return judgment, failures, output_evidence


def _cleanup_authored_writes(
    write_set: list[str],
    existed_before: dict[str, bool],
    sandbox_resolved: str,
) -> dict[str, list[str]]:
    """清理本轮前不存在的 write_set 条目。

    流程（需求 8）：

    1. 只处理本轮前不存在的条目。
    2. 清理前再次确认路径在 sandbox，拒绝符号链接祖先逃逸。
    3. 先删除文件和符号链接，再递归删除目录。
    4. 对明确授权且本轮新建的目录可以递归删除。

    Returns
    -------
    ``{"cleaned": [...], "failed": [...]}``
    """
    cleaned: list[str] = []
    failed: list[str] = []

    # 分类：本轮前不存在且当前仍存在的条目
    file_entries: list[str] = []
    dir_entries: list[str] = []

    for ws in write_set:
        if existed_before[ws]:
            continue  # 执行前已存在，不清理
        if not os.path.lexists(ws):
            continue  # 已不存在，无需清理

        # 安全检查：解析后必须在 sandbox 内
        resolved = os.path.realpath(ws)
        in_sandbox = (
            resolved == sandbox_resolved
            or resolved.startswith(sandbox_resolved + os.sep)
        )
        if not in_sandbox:
            failed.append(ws)
            continue

        try:
            st = os.lstat(ws)
        except OSError:
            failed.append(ws)
            continue

        if stat.S_ISDIR(st.st_mode):
            dir_entries.append(ws)
        else:
            # 普通文件、符号链接、其他
            file_entries.append(ws)

    # 第一轮：删除文件和符号链接
    for path in file_entries:
        try:
            os.unlink(path)
            cleaned.append(path)
        except OSError:
            failed.append(path)

    # 第二轮：递归删除目录（明确授权且本轮新建）
    for path in dir_entries:
        try:
            shutil.rmtree(path)
            cleaned.append(path)
        except FileNotFoundError:
            # 嵌套 write_set 场景：已被前一轮或更早条目间接删除
            cleaned.append(path)
        except OSError:
            failed.append(path)

    return {"cleaned": cleaned, "failed": failed}
