#!/usr/bin/env python3
"""第一档静态符合性检查器：8 条规则全覆盖。

Foundation 机制传输层（C04 perf-worker 前置批，2026-09-07）：从"每请求 spawn
一个 CLI 进程"改为"一个常驻 Node worker 进程内反复调用冻结 bundle 官方导出的
``runMechanismCli``"。语义等价论证与频率摊薄裁决见 EV
``c04-perf-worker-prerequisite-20260907/design-adjudication.md`` §3（用户 D1–D4
逐字授权在档）。本模块只承载传输层；校验链（路径链/符号链接/文件/provenance/
receipt/import-closure 全量 sha256/版本区间）一字不弱化，频率按授权摊薄：
node 运行时与 bundle 每 checker 进程校验一次（内容级缓存，见各函数 docstring），
self-check 由"每请求一次独立 spawn"改为"worker 启动时一次 + fail-closed"。
"""
from __future__ import annotations

import argparse
import atexit
import base64
import hashlib
import json
import os
import re
import select
import subprocess
import sys
import threading
from pathlib import Path

CHECKER_METHOD_ID = "skill-family-audit:conformance-audit"
CHECKER_VERSION = "0.4.0-conformance-repair"
RULE_FIELDS = {"ruleId", "revisionDigest", "description", "applicability", "checkType", "failureImpact", "remediation"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FAMILY_NAME_RE = re.compile(r"^[a-z][a-z0-9-]+$")
FRONTMATTER_BOUNDARY = re.compile(r"^---\s*$")
FOUNDATION_PROFILE_EXPECTED = {"id": "quickstart-profile", "version": 2}
FOUNDATION_RECEIPT_KIND = "skill-family.source-authority-receipt"
NODE_VERSION_MIN = (22, 22, 2)
NODE_VERSION_EXCLUSIVE_MAX = (23, 0, 0)
NODE_VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)")
FOUNDATION_FIXED_ENTRIES = frozenset({
    "runner.mjs",
    "validators.mjs",
    "mechanisms-cli.mjs",
    "adoption-cli.mjs",
})


class FoundationNodeRuntimeError(RuntimeError):
    """The explicitly bound Foundation Node runtime is not trustworthy."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code = code


# ---------------------------------------------------------------------------
# C04 常驻 worker 传输层（实现规格：delegation-perf-worker.md §3.1）
#
# 启动命令形态（argv 索引经实测修正，见代码下方说明与终报）：
#   node --input-type=module -e '<worker 源码>' <node 自身路径> <cli 绝对路径>
# process.argv = [node, node-自身路径(argv[1]), cli 路径(argv[2])]。argv[1] 必须是
# 一个真实存在的、不等于 cli realpath 的文件：mechanisms-cli.mjs 底部 main guard
# 比较 realpathSync(import.meta.url) 与 realpathSync(process.argv[1])——若 argv[1]
# 恰好是 cli 自身，导入该模块会触发 main guard（顶层 await 并发消费真实 stdin，
# 造成死锁与帧损坏）；argv[1] 若不存在则 guard 内 realpathSync 抛 ENOENT 使模块
# 求值失败。此处取 node 自身路径作 argv[1]（spawn 时刻必然存在且恒不等于 cli）。
# 传入路径一律经 Popen argv 传递，不经 shell，无引号注入面。
#
# worker 协议（纯传输内握手，非新观察合同）：
#   1. 启动即导入 cli（路径来自 argv[2]，worker 不自行选路），随后以注入流执行
#      一次 {"operation":"self-check","params":{}}（与移除的每请求 self-check
#      请求字节逐字节相同）；valid!==true 或返回码非 0 → stderr 记因后退非零
#      （fail-closed），不进入帧循环。
#   2. self-check 通过后向 stdout 回写一行 {"ready":true}（启动握手；使 Python
#      侧能把"启动失败"与旧的 FOUNDATION_CLI_SELF_CHECK_FAILED 语义对应）。
#   3. 之后按行读 stdin 帧：每帧 = base64(精确请求字节)；解码后以注入流调用
#      runMechanismCli，回写一行 {"code":<0|2>,"out_b64":…,"err_b64":…}，out/err
#      为 CLI 形态下 stdout/stderr 的精确字节（逐字节与旧 subprocess 形态相同）。
#   4. 帧内未捕获异常 → 回写错误帧（code=2 + worker_error 封套）后退非零。
# ---------------------------------------------------------------------------

_FOUNDATION_WORKER_STARTUP_TIMEOUT = 120.0
_FOUNDATION_WORKER_REQUEST_TIMEOUT = 300.0
_WORKER_READY_PREFIX = '{"ready":true}'

_FOUNDATION_WORKER_SOURCE = r"""
const { pathToFileURL } = await import("node:url");
const { Readable, Writable } = await import("node:stream");
const { createHash } = await import("node:crypto");
const { appendFileSync, writeSync } = await import("node:fs");

const TRACE_PATH = process.env.SFA_AUDIT_MECHANISM_TRACE || "";
const cliPath = process.argv[2];
if (!cliPath) {
  writeSync(2, JSON.stringify({ worker_error: "missing cli path argv" }) + "\n");
  process.exit(3);
}
function stdoutLine(text) {
  // 帧输出一律走 process.stdout.write（node 内部处理非阻塞 pipe fd 的
  // 背压/部分写/EAGAIN）；fs.writeSync 对 stdout pipe 是单次非阻塞写，
  // 大帧（>pipe 容量）会部分写截断或抛 EAGAIN（见 c04 传输修复记录）。
  return new Promise((resolve, reject) => {
    process.stdout.write(text, (err) => (err ? reject(err) : resolve()));
  });
}
function traceLine(reqBuf, code, outBuf, errBuf) {
  if (!TRACE_PATH) return;
  try {
    const line =
      JSON.stringify({
        req_b64: reqBuf.toString("base64"),
        code: code,
        out_sha256: createHash("sha256").update(outBuf).digest("hex"),
        out_len: outBuf.length,
        err_sha256: createHash("sha256").update(errBuf).digest("hex"),
      }) + "\n";
    appendFileSync(TRACE_PATH, line, "utf8");
  } catch (_err) {
    /* trace is best-effort; never affects the request path */
  }
}
let runMechanismCli;
try {
  const mod = await import(pathToFileURL(cliPath).href);
  runMechanismCli = mod.runMechanismCli;
} catch (cause) {
  writeSync(2, JSON.stringify({
    worker_error: "cli import failed",
    message: String((cause && cause.message) || cause),
  }) + "\n");
  process.exit(3);
}
if (typeof runMechanismCli !== "function") {
  writeSync(2, JSON.stringify({ worker_error: "cli exports no runMechanismCli" }) + "\n");
  process.exit(3);
}
async function executeOnce(requestBytes) {
  const outChunks = [];
  const errChunks = [];
  const output = new Writable({
    write(chunk, _enc, cb) { outChunks.push(Buffer.from(chunk)); cb(); },
  });
  const error = new Writable({
    write(chunk, _enc, cb) { errChunks.push(Buffer.from(chunk)); cb(); },
  });
  const code = await runMechanismCli({
    input: Readable.from([Buffer.from(requestBytes)]),
    output: output,
    error: error,
  });
  return {
    code: code,
    out: Buffer.concat(outChunks),
    err: Buffer.concat(errChunks),
  };
}
const selfCheckRequest = Buffer.from(
  JSON.stringify({ operation: "self-check", params: {} }),
  "utf8"
);
let selfCheck;
try {
  selfCheck = await executeOnce(selfCheckRequest);
} catch (cause) {
  const message = String((cause && cause.message) || cause);
  traceLine(selfCheckRequest, -1, Buffer.alloc(0), Buffer.from(message, "utf8"));
  writeSync(2, JSON.stringify({ worker_error: "self-check crashed", message: message }) + "\n");
  process.exit(4);
}
traceLine(selfCheckRequest, selfCheck.code, selfCheck.out, selfCheck.err);
let selfCheckValid = false;
try {
  const parsed = JSON.parse(selfCheck.out.toString("utf8"));
  selfCheckValid = Boolean(parsed && parsed.valid === true);
} catch (_err) {
  selfCheckValid = false;
}
if (selfCheck.code !== 0 || !selfCheckValid) {
  writeSync(2, JSON.stringify({
    worker_error: "self-check failed",
    code: selfCheck.code,
    err: selfCheck.err.toString("utf8").slice(0, 4000),
  }) + "\n");
  process.exit(4);
}
await stdoutLine(JSON.stringify({ ready: true }) + "\n");
let buffer = Buffer.alloc(0);
for await (const chunk of process.stdin) {
  buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
  let nl;
  while ((nl = buffer.indexOf(10)) !== -1) {
    const frame = buffer.subarray(0, nl);
    buffer = buffer.subarray(nl + 1);
    let requestBytes;
    try {
      requestBytes = Buffer.from(frame.toString("utf8"), "base64");
    } catch (_err) {
      writeSync(2, JSON.stringify({ worker_error: "bad base64 frame" }) + "\n");
      process.exit(5);
    }
    let outcome;
    try {
      outcome = await executeOnce(requestBytes);
    } catch (cause) {
      const message = String((cause && cause.message) || cause);
      const errBuf = Buffer.from(JSON.stringify({ worker_error: true, message: message }), "utf8");
      await stdoutLine(JSON.stringify({
        code: 2,
        out_b64: "",
        err_b64: errBuf.toString("base64"),
      }) + "\n");
      process.exit(6);
    }
    // Trace 只由 Python 侧传输层每请求追加（design §3.4）；worker 只写启动
    // self-check 一条（worker 内部事件，Python 侧不可见）。
    await stdoutLine(JSON.stringify({
      code: outcome.code,
      out_b64: outcome.out.toString("base64"),
      err_b64: outcome.err.toString("base64"),
    }) + "\n");
  }
}
process.exit(0);
"""


# 每进程状态：node 运行时缓存 / bundle 校验缓存 / 常驻 worker。
# 缓存不跨进程（模块状态即进程状态）；失败结果一律不缓存（负例每次重新全量校验）。
_NODE_RUNTIME_CACHE: dict[str, tuple[Path, str]] = {}
# 缓存值 = (entry, 全量校验闭包元数据快照 {resolved path: (st_mtime_ns, st_size)})。
# 哨兵覆盖首次全量链实际读取/校验的每个文件（入口/foundation-projection.json/
# receipt 源 foundation-handoff.json 或 foundation-pin.json/import-closure 全部成员）；
# 快照任一成员 stat 失配即视为内容可能变化并重跑与首次逐字节相同的全量链
# （R-G4 修复裁决 2026-09-07：入口单文件哨兵放过了只改闭包其他成员的篡改序列）。
_BUNDLE_VERIFY_CACHE: dict[str, tuple[Path, dict[str, tuple[int, int]]]] = {}
_FOUNDATION_WORKER: dict | None = None  # {node_path, cli, proc, trace_path}
_FOUNDATION_WORKER_LOCK = threading.Lock()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bundle_snapshot_note(path: Path) -> tuple[int, int]:
    """取 (st_mtime_ns, st_size) 元数据哨兵；stat 失败以 (-1,-1) 全不匹配表示，
    使任何成员缺失/不可读都触发重跑全量链（fail-closed 语义）。"""
    try:
        s = path.stat()
    except OSError:
        return (-1, -1)
    return (s.st_mtime_ns, s.st_size)


def _bundle_snapshot_matches(snapshot: dict[str, tuple[int, int]]) -> bool:
    """快照全部成员当前 stat 与记录一致才命中；任一成员变化即触发重跑。"""
    for recorded_path, expected in snapshot.items():
        if _bundle_snapshot_note(Path(recorded_path)) != expected:
            return False
    return True


def _check_path_chain_no_symlinks(path: Path, error_code: str = "FOUNDATION_RUNNER_SYMLINK") -> None:
    """检查路径完整链上无符号链接：对原始绝对路径逐段执行 lstat 风格检查。

    不调用 resolve()，避免中间层符号链接被消解后逃逸检查。
    任一已存在路径分量或最终入口为符号链接即失败关闭。
    """
    if not path.is_absolute():
        raise RuntimeError(error_code)
    current = path
    while current != current.parent:
        if current.is_symlink():
            raise RuntimeError(error_code)
        current = current.parent


def verify_foundation_bundle(entry_ref: str) -> Path:
    """Verify one fixed entry's static import closure before Node imports it.

    频率（C04 授权摊薄 + R-G4 修复裁决 2026-09-07，design-adjudication.md
    §3.2）：完整校验链（符号链接路径链/provenance/receipt/payload 摘要/
    import-closure 全量 sha256）对同一 resolved realpath 每 checker 进程首次
    调用执行一次；此后该 realpath 的校验结果按内容级缓存复用。缓存命中带全量
    校验闭包元数据快照哨兵：首次全量链执行时对每个实际读取/校验的文件（入口、
    foundation-projection.json、receipt 源 foundation-handoff.json 或
    foundation-pin.json、import-closure 全部成员）记录 (resolved path,
    st_mtime_ns, st_size)；命中条件 = 入口 stat 匹配且快照全部成员 stat 均与
    当前一致才直接返回；任一成员变化都视为内容可能变化，重跑与首次完全相同的
    全量校验链（校验链一字不弱化；首校验失败照抛原错误码且不入缓存）。语义代价
    （如实记录）：同进程内 mtime+size 双保持的恶意篡改不探测——旧形态每请求
    全哈希已按 §3.2 摊薄取代，本快照哨兵为对该已接受风险的收紧，堵住测试序列
    式普通篡改（只改入口以外闭包成员、不改入口元数据）在缓存期不被发现的缺口。
    """
    raw = Path(entry_ref).expanduser()
    symlink_error = (
        "FOUNDATION_RUNNER_SYMLINK"
        if raw.name == "runner.mjs"
        else "FOUNDATION_BUNDLE_MEMBER_SYMLINK"
    )
    invalid_error = (
        "FOUNDATION_RUNNER_INVALID"
        if raw.name == "runner.mjs"
        else "FOUNDATION_ENTRY_INVALID"
    )
    _check_path_chain_no_symlinks(raw, symlink_error)
    if not raw.is_file() or raw.name not in FOUNDATION_FIXED_ENTRIES:
        raise RuntimeError(invalid_error)
    entry = raw.resolve(strict=True)
    if not entry.is_file():
        raise RuntimeError(invalid_error)
    try:
        entry_stat = entry.stat()
    except OSError:
        entry_stat = None
    cached = _BUNDLE_VERIFY_CACHE.get(str(entry))
    if cached is not None and entry_stat is not None:
        cached_entry, cached_snapshot = cached
        if (
            cached_entry == entry
            and entry_stat.st_mtime_ns
            == cached_snapshot.get(str(entry), (-1, -1))[0]
            and entry_stat.st_size
            == cached_snapshot.get(str(entry), (-1, -1))[1]
            and _bundle_snapshot_matches(cached_snapshot)
        ):
            return cached_entry

    snapshot: dict[str, tuple[int, int]] = {}

    def _note(path: Path) -> None:
        """记录校验闭包成员当前 (st_mtime_ns, st_size)；stat 先于该文件内容读取。"""
        snapshot[str(path)] = _bundle_snapshot_note(path)

    bundle_root = entry.parent
    provenance_raw = bundle_root / "foundation-projection.json"
    for member in (provenance_raw, entry):
        _check_path_chain_no_symlinks(member, "FOUNDATION_BUNDLE_MEMBER_SYMLINK")
        if not member.is_file():
            raise RuntimeError("FOUNDATION_BUNDLE_MEMBER_MISSING")

    provenance_path = provenance_raw.resolve(strict=True)
    _note(provenance_path)
    provenance = _load(provenance_path)
    if provenance.get("kind") != "skill-family.foundation-projection":
        raise RuntimeError("FOUNDATION_BUNDLE_PROVENANCE_INVALID")
    profile = provenance.get("profile")
    if (
        not isinstance(profile, dict)
        or profile.get("id") != FOUNDATION_PROFILE_EXPECTED["id"]
        or profile.get("version") != FOUNDATION_PROFILE_EXPECTED["version"]
    ):
        raise RuntimeError("FOUNDATION_BUNDLE_PROVENANCE_INVALID")
    payload = provenance.get("payload")
    files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(files, list) or not files:
        raise RuntimeError("FOUNDATION_BUNDLE_PAYLOAD_INVALID")
    declared: dict[str, str] = {}
    for record in files:
        relative = record.get("path") if isinstance(record, dict) else None
        digest = record.get("sha256") if isinstance(record, dict) else None
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or relative in declared
        ):
            raise RuntimeError("FOUNDATION_BUNDLE_PAYLOAD_INVALID")
        declared[relative] = digest
    source = provenance.get("source")
    if not isinstance(source, dict):
        raise RuntimeError("FOUNDATION_RECEIPT_INVALID")
    handoff_raw = bundle_root.parent / "foundation-handoff.json"
    pin_raw = bundle_root.parent / "foundation-pin.json"
    if handoff_raw.is_file():
        _check_path_chain_no_symlinks(handoff_raw, "FOUNDATION_RECEIPT_INVALID")
        _note(handoff_raw.resolve(strict=True))
        handoff = _load(handoff_raw)
        receipt = handoff.get("receipt")
        if (
            handoff.get("kind") != "skill-family-audit.foundation-handoff"
            or handoff.get("schemaVersion") != 2
            or handoff.get("source") != {
                "repository": source.get("repository"),
                "baseCommit": source.get("baseCommit"),
            }
            or not isinstance(receipt, dict)
            or set(receipt) != {"kind", "sha256"}
            or receipt.get("kind") != FOUNDATION_RECEIPT_KIND
            or not HEX64.fullmatch(receipt.get("sha256", ""))
            or handoff.get("payloadDigest") != payload.get("digest")
            or handoff.get("provenanceDigest") != _sha256(provenance_raw)
        ):
            raise RuntimeError("FOUNDATION_RECEIPT_INVALID")
    else:
        _check_path_chain_no_symlinks(pin_raw, "FOUNDATION_RECEIPT_INVALID")
        if not pin_raw.is_file():
            raise RuntimeError("FOUNDATION_RECEIPT_INVALID")
        _note(pin_raw.resolve(strict=True))
        pin = _load(pin_raw)
        pin_profile = pin.get("profile")
        pin_source = pin.get("source")
        if (
            pin.get("schemaVersion") != "1.0"
            or not isinstance(pin_profile, dict)
            or {key: pin_profile.get(key) for key in ("id", "version")} != {
                "id": profile.get("id"), "version": profile.get("version")
            }
            or not isinstance(pin_source, dict)
            or {
                "repository": pin_source.get("repository"),
                "baseCommit": pin_source.get("baseCommit"),
            } != {
                "repository": source.get("repository"),
                "baseCommit": source.get("baseCommit"),
            }
            or pin.get("bundle", {}).get("payloadSha256") != payload.get("digest")
        ):
            raise RuntimeError("FOUNDATION_RECEIPT_INVALID")

    pending = [entry]
    checked: set[str] = set()
    import_pattern = re.compile(r'(?:from\s*|import\s*)["\'](\.[^"\']+)["\']')
    while pending:
        member = pending.pop()
        _check_path_chain_no_symlinks(member, "FOUNDATION_BUNDLE_MEMBER_SYMLINK")
        if not member.is_file():
            raise RuntimeError("FOUNDATION_BUNDLE_MEMBER_MISSING")
        resolved = member.resolve(strict=True)
        try:
            relative = resolved.relative_to(bundle_root).as_posix()
        except ValueError as exc:
            raise RuntimeError("FOUNDATION_BUNDLE_IMPORT_ESCAPE") from exc
        if relative in checked:
            continue
        _note(resolved)
        if declared.get(relative) != _sha256(resolved):
            raise RuntimeError("FOUNDATION_BUNDLE_MEMBER_DIGEST_MISMATCH")
        checked.add(relative)
        if resolved.suffix == ".mjs":
            source = resolved.read_text(encoding="utf-8")
            pending.extend(resolved.parent / match for match in import_pattern.findall(source))
    _note(entry)  # 入口幂等兜底入快照（闭包循环已记录；此处保证存储态含入口）
    _BUNDLE_VERIFY_CACHE[str(entry)] = (entry, snapshot)
    return entry


def _reject_ambiguous_runner_role() -> None:
    if "SFA_FOUNDATION_RUNNER_REF" in os.environ:
        raise RuntimeError("FOUNDATION_RUNNER_ROLE_AMBIGUOUS")


def _package_root() -> Path | None:
    """从本脚本位置向上寻找包根（以 generated/platforms 目录存在为标识）。

    plugin-src 源树与 generated 平台投影树中的脚本副本都能定位到同一个包根；
    找不到时返回 None（例如被仓外独立安装时），调用方保持失败关闭。
    """
    here = Path(__file__).resolve(strict=True)
    for ancestor in (here.parent, *here.parents):
        if (ancestor / "generated" / "platforms").is_dir():
            return ancestor
    return None


def _host_platform_root() -> Path | None:
    """返回当前执行副本所属的受管平台根（自身 runner marker 的最近祖先）。

    plugin-src 源树脚本不属于任何平台副本时返回 None（调用方回退到仓内全量
    候选，保持确定性排序）。任何路径分量或入口为符号链接即视为不成立，
    与 ``_check_path_chain_no_symlinks`` 的失败关闭语义一致。
    """
    here = Path(__file__).resolve(strict=True)
    for ancestor in (here.parent, *here.parents):
        marker = ancestor / "foundation" / "quickstart-profile" / "runner.mjs"
        if marker.is_file() and not marker.is_symlink():
            return ancestor
    return None


def _default_audit_bundle_candidates() -> list[Path]:
    """仓内默认可发现的 Audit Foundation Bundle 候选（确定性排序）。

    候选来自仓库自身受管平台投影 ``generated/platforms/<platform>/foundation/
    quickstart-profile/runner.mjs``；当执行副本本身位于某个平台投影内时（如
    codex 投影脚本在未显式绑定 runner 的环境下运行），该副本所属平台的
    runner 前置到候选首位（去重后仍保留其余仓内候选），避免 host gate 把
    本平台 caller 误判为其它平台的越界调用；plugin-src 源树执行不属于任何
    平台副本，候选顺序不变。任何候选在使用前仍经过 ``verify_foundation_bundle``
    全量校验（provenance、receipt、payload 摘要、import 闭包），默认推断不放宽
    任何校验。
    """
    root = _package_root()
    if root is None:
        return []
    platforms = root / "generated" / "platforms"
    candidates: list[Path] = []
    if platforms.is_dir() and not platforms.is_symlink():
        for platform_dir in sorted(platforms.iterdir(), key=lambda item: item.name):
            runner = platform_dir / "foundation" / "quickstart-profile" / "runner.mjs"
            if runner.is_file() and not runner.is_symlink():
                candidates.append(runner)
    own_root = _host_platform_root()
    if own_root is not None:
        own_runner = own_root / "foundation" / "quickstart-profile" / "runner.mjs"
        if own_runner in candidates:
            candidates = [
                own_runner,
                *(candidate for candidate in candidates if candidate != own_runner),
            ]
    return candidates


def foundation_runner() -> Path:
    """Resolve only Audit's Bundle for schemas, canonical data and closures."""
    _reject_ambiguous_runner_role()
    configured = os.environ.get("SFA_AUDIT_BUNDLE_RUNNER_REF")
    if configured:
        return verify_foundation_bundle(configured)
    # D2 仓内默认可发现绑定：显式 env 优先；未显式绑定时按确定性顺序尝试仓内
    # 受管投影 Bundle，每个候选都走完整 verify_foundation_bundle 校验。
    candidate_errors: list[str] = []
    for candidate in _default_audit_bundle_candidates():
        try:
            return verify_foundation_bundle(str(candidate))
        except RuntimeError as exc:
            candidate_errors.append(f"{candidate}: {exc}")
    detail = (
        f"（仓内默认候选校验失败: {'; '.join(candidate_errors)}）"
        if candidate_errors
        else "（未找到仓内默认 Bundle；可运行工作区 scripts/setup-self-audit-env.sh 生成显式绑定）"
    )
    raise RuntimeError(
        "FOUNDATION_AUDIT_RUNNER_MISSING: 需要通过 SFA_AUDIT_BUNDLE_RUNNER_REF 显式绑定 Audit 的受管 Foundation Bundle"
        + detail
    )


def _validate_node_runtime(raw: Path) -> tuple[Path, str]:
    """对单个 Node 运行时入口执行全量校验（路径链、文件、版本区间）。

    频率（C04 授权摊薄，design-adjudication.md §3.2；用户 D2 明文授权）：同一
    入口路径每 checker 进程只 spawn 一次 ``node --version`` 做完整校验，成功结果
    (path, version) 按 str(raw) 缓存；失败仍抛 FoundationNodeRuntimeError 原错误码
    且不缓存（负例每次重新全量校验）。缓存不跨进程；env 读取本身不缓存。
    """
    cached = _NODE_RUNTIME_CACHE.get(str(raw))
    if cached is not None:
        return cached
    if not raw.is_absolute():
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_NOT_ABSOLUTE", f"Node.js 入口必须是绝对路径: {raw}"
        )
    try:
        _check_path_chain_no_symlinks(raw, "NODE_PATH_SYMLINK")
    except RuntimeError as exc:
        raise FoundationNodeRuntimeError(
            "NODE_PATH_SYMLINK", f"Node.js 路径链包含符号链接: {raw}"
        ) from exc
    if not raw.is_file():
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_MISSING_FILE", f"Node.js 入口文件不存在: {raw}"
        )
    try:
        completed = subprocess.run(
            [str(raw), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_UNAVAILABLE", f"Node.js 版本探测失败: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_UNAVAILABLE",
            f"Node.js --version 失败: {completed.stderr.strip()}",
        )
    version = completed.stdout.strip()
    match = NODE_VERSION_RE.match(version)
    if not match:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_VERSION_UNPARSEABLE", f"Node.js 版本字符串无法解析: {version}"
        )
    parsed = tuple(int(match.group(index)) for index in range(1, 4))
    if parsed < NODE_VERSION_MIN or parsed >= NODE_VERSION_EXCLUSIVE_MAX:
        raise FoundationNodeRuntimeError(
            "FOUNDATION_NODE_VERSION_INCOMPATIBLE",
            f"Node.js 版本 {version} 不在 >=22.22.2 <23 范围内",
        )
    _NODE_RUNTIME_CACHE[str(raw)] = (raw, version)
    return raw, version


def _default_node_candidates() -> list[Path]:
    """主机上默认可发现的 Node 22 运行时候选（确定性排序）。

    候选只来自受版本约束限定的常规安装位置（Homebrew Cellar 的 node@22、
    nvm 的 v22.* 安装），每个候选在使用前都经过与显式绑定完全相同的全量
    校验（绝对路径、无符号链接路径链、入口文件存在、版本 >=22.22.2 <23），
    默认推断不放宽任何校验。
    """
    candidates: list[Path] = []
    cellar_roots = [Path("/opt/homebrew/Cellar/node@22"), Path("/usr/local/Cellar/node@22")]
    for cellar in cellar_roots:
        if cellar.is_dir() and not cellar.is_symlink():
            for version_dir in sorted(cellar.iterdir(), key=lambda item: item.name):
                entry = version_dir / "bin" / "node"
                if entry.is_file() and not entry.is_symlink():
                    candidates.append(entry)
    nvm_root = Path.home() / ".nvm" / "versions" / "node"
    if nvm_root.is_dir() and not nvm_root.is_symlink():
        for version_dir in sorted(nvm_root.iterdir(), key=lambda item: item.name):
            if not version_dir.name.startswith("v22"):
                continue
            entry = version_dir / "bin" / "node"
            if entry.is_file() and not entry.is_symlink():
                candidates.append(entry)
    return candidates


def foundation_node_runtime() -> tuple[Path, str]:
    """Resolve the explicit, real Node 22 runtime used by every Bundle CLI."""
    ref = os.environ.get("SFA_FOUNDATION_NODE")
    if ref:
        return _validate_node_runtime(Path(ref))
    # D2 仓内默认可发现绑定：显式 env 优先；未显式绑定时按确定性顺序探测
    # 主机常规 Node 22 安装位置，每个候选都走与显式绑定相同的全量校验。
    candidate_errors: list[str] = []
    for candidate in _default_node_candidates():
        try:
            return _validate_node_runtime(candidate)
        except FoundationNodeRuntimeError as exc:
            candidate_errors.append(f"{candidate}: {exc.code}")
    detail = (
        f"（默认候选校验失败: {'; '.join(candidate_errors)}）"
        if candidate_errors
        else "（未找到默认 Node 22 候选；可运行工作区 scripts/setup-self-audit-env.sh 生成显式绑定）"
    )
    raise FoundationNodeRuntimeError(
        "FOUNDATION_NODE_MISSING",
        "SFA_FOUNDATION_NODE 环境变量未设置" + detail,
    )


def call_foundation_cli(runner: Path, cli_name: str, request: dict) -> object:
    """Call one fixed CLI from the already verified managed Bundle.

    self-check（C04 授权摊薄，design-adjudication.md §3.2）：由"每请求独立 spawn
    一次 self-check"改为"常驻 worker 启动时一次 + fail-closed"——worker 在进入帧
    循环前以注入流执行逐字节相同的 self-check 请求，valid!==true 或返回码非 0
    即退非零（Python 侧映射为 FOUNDATION_CLI_SELF_CHECK_FAILED）。
    verify_foundation_bundle 与 foundation_node_runtime 在此仍逐请求调用，但内部
    缓存使完整校验链只在每进程首次（或内容元数据变化时）执行。
    """
    if cli_name != "mechanisms-cli.mjs":
        raise RuntimeError("FOUNDATION_CLI_NOT_ALLOWED")
    runner = verify_foundation_bundle(str(runner))
    cli = verify_foundation_bundle(str(runner.parent / cli_name))
    node_path, _node_version = foundation_node_runtime()
    return _run_foundation_cli(node_path, cli, request)


def _trace_transport_request(
    trace_path: str, request_bytes: bytes, code: int, out_bytes: bytes, err_bytes: bytes
) -> None:
    """SFA_AUDIT_MECHANISM_TRACE=<path> 观测 trace（可选；默认 off 零行为差异）。

    NDJSON 行：{"req_b64","code","out_sha256","out_len","err_sha256"}；帧内容与
    CLI 形态请求/响应字节一一对应（V5 等价差分的真实请求流来源）。best-effort，
    任何写失败不影响请求路径。
    """
    if not trace_path:
        return
    try:
        with open(trace_path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "req_b64": base64.b64encode(request_bytes).decode("ascii"),
                        "code": code,
                        "out_sha256": hashlib.sha256(out_bytes).hexdigest(),
                        "out_len": len(out_bytes),
                        "err_sha256": hashlib.sha256(err_bytes).hexdigest(),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        return


def _drain_worker_stderr(proc) -> str:
    try:
        return (proc.stderr.read() or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""


def _read_worker_line(proc, timeout: float) -> bytes | None:
    """Read one newline-terminated line from the worker stdout; None on EOF.

    timeout=None 时阻塞读（与旧 subprocess.run 无超时语义一致）；超时抛
    TimeoutError 由调用方按 fail-closed 处理。
    """
    if timeout is not None:
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError(f"Foundation CLI worker did not respond within {timeout:.0f}s")
    return proc.stdout.readline()


def _terminate_worker_proc(proc) -> None:
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _ensure_foundation_worker(node_path: Path, cli: Path) -> dict:
    """Start (or reuse) the resident Node worker; must be called under the lock.

    worker 启动 = spawn + 启动 self-check + ready 握手。启动失败（import 失败、
    self-check 非 valid、超时、进程早退）一律 fail-closed：非 ready 退出即抛
    RuntimeError，其中 self-check 失败映射为旧的 FOUNDATION_CLI_SELF_CHECK_FAILED
    语义（错误码/消息不变）。worker 参数（node/cli）变化时重启（进程内同时只
    保留一个 worker）。
    """
    global _FOUNDATION_WORKER
    current = _FOUNDATION_WORKER
    if current is not None and (
        current["node_path"] != node_path or current["cli"] != cli
    ):
        _terminate_worker_proc(current["proc"])
        current = None
        _FOUNDATION_WORKER = None
    if current is not None:
        proc = current["proc"]
        if proc.poll() is None:
            return current
        _drain_worker_stderr(proc)
        current = None
        _FOUNDATION_WORKER = None
    trace_path = os.environ.get("SFA_AUDIT_MECHANISM_TRACE", "")
    proc = subprocess.Popen(
        [
            str(node_path),
            "--input-type=module",
            "-e",
            _FOUNDATION_WORKER_SOURCE,
            str(node_path),  # argv[1]：真实存在的非 cli 文件（见模块顶部说明）
            str(cli),        # argv[2]：cli 绝对路径（worker 按此导入，不自行选路）
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        ready_line = _read_worker_line(proc, _FOUNDATION_WORKER_STARTUP_TIMEOUT)
    except TimeoutError as exc:
        _terminate_worker_proc(proc)
        raise RuntimeError(
            f"Foundation CLI worker startup timed out: {exc}"
        ) from exc
    if not ready_line:
        _terminate_worker_proc(proc)
        detail = _drain_worker_stderr(proc)
        if "self-check" in detail:
            raise RuntimeError("FOUNDATION_CLI_SELF_CHECK_FAILED")
        raise RuntimeError(detail.strip() or "Foundation CLI worker failed to start")
    try:
        ready = json.loads(ready_line.decode("utf-8", errors="strict")).get("ready")
    except (UnicodeDecodeError, json.JSONDecodeError):
        ready = None
    if ready is not True:
        _terminate_worker_proc(proc)
        raise RuntimeError("Foundation CLI worker returned an invalid ready frame")
    worker = {"node_path": node_path, "cli": cli, "proc": proc, "trace_path": trace_path}
    _FOUNDATION_WORKER = worker
    return worker


def _shutdown_foundation_worker() -> None:
    """atexit：终止常驻 worker，关闭管道。"""
    global _FOUNDATION_WORKER
    try:
        _FOUNDATION_WORKER_LOCK.acquire(timeout=10)
    except Exception:
        return
    try:
        current = _FOUNDATION_WORKER
        _FOUNDATION_WORKER = None
        if current is not None:
            _terminate_worker_proc(current["proc"])
            for stream in ("stdin", "stdout", "stderr"):
                try:
                    getattr(current["proc"], stream).close()
                except Exception:
                    pass
    finally:
        _FOUNDATION_WORKER_LOCK.release()


atexit.register(_shutdown_foundation_worker)


def _run_foundation_cli(node_path: Path, cli: Path, request: dict) -> object:
    """Call one fixed CLI via the resident worker.

    签名与返回/异常语义与旧 subprocess 形态不变：request 以
    ``base64(json.dumps(request, ensure_ascii=False).encode("utf-8"))`` 一行写入
    worker 管道（base64 解码后与旧 CLI stdin 字节逐字节相同），读一行响应帧；
    out/err 字节解码走原有的 utf-8 strict decode / returncode!=0 → RuntimeError /
    JSONDecodeError → RuntimeError 路径。worker 死亡、帧损坏、管道断裂、超时 →
    RuntimeError fail-closed（后续调用自动重启 worker）。
    """
    with _FOUNDATION_WORKER_LOCK:
        worker = _ensure_foundation_worker(node_path, cli)
        proc = worker["proc"]
        request_bytes = json.dumps(request, ensure_ascii=False).encode("utf-8")
        frame = base64.b64encode(request_bytes).decode("ascii") + "\n"
        try:
            assert proc.stdin is not None
            proc.stdin.write(frame.encode("ascii"))
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            _terminate_worker_proc(proc)
            raise RuntimeError(f"Foundation CLI worker pipe write failed: {exc}") from exc
        try:
            response_line = _read_worker_line(
                proc, _FOUNDATION_WORKER_REQUEST_TIMEOUT
            )
        except TimeoutError as exc:
            _terminate_worker_proc(proc)
            raise RuntimeError(f"Foundation CLI worker request timed out: {exc}") from exc
        if not response_line:
            _terminate_worker_proc(proc)
            detail = _drain_worker_stderr(proc)
            raise RuntimeError(
                detail.strip()
                or "Foundation CLI worker terminated unexpectedly during a request"
            )
        try:
            response_frame = json.loads(
                response_line.decode("utf-8", errors="strict")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _terminate_worker_proc(proc)
            raise RuntimeError("Foundation CLI returned an invalid response frame") from exc
        if not isinstance(response_frame, dict):
            _terminate_worker_proc(proc)
            raise RuntimeError("Foundation CLI returned an invalid response frame")
        code = response_frame.get("code")
        try:
            out_bytes = base64.b64decode(response_frame["out_b64"])
            err_bytes = base64.b64decode(response_frame["err_b64"])
        except (KeyError, TypeError, ValueError) as exc:
            _terminate_worker_proc(proc)
            raise RuntimeError("Foundation CLI returned an invalid response frame") from exc
        if not isinstance(code, int):
            _terminate_worker_proc(proc)
            raise RuntimeError("Foundation CLI returned an invalid response frame")
        _trace_transport_request(
            worker["trace_path"], request_bytes, code, out_bytes, err_bytes
        )
    # 以下解码/判定路径与旧 subprocess 形态逐字相同。
    try:
        stdout = out_bytes.decode("utf-8", errors="strict")
        stderr = err_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Foundation CLI returned invalid UTF-8") from exc
    if code != 0:
        raise RuntimeError(stderr.strip() or "Foundation CLI failed")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Foundation CLI returned invalid JSON") from exc


def call_foundation_mechanism(runner: Path, request: dict) -> dict:
    """Invoke one of the Bundle's fixed, domain-neutral mechanisms."""
    operation = str(request.get("operation", ""))
    params = (
        {"document": request.get("document")}
        if operation in {"canonical-json", "digest-document"}
        else {key: value for key, value in request.items() if key != "operation"}
    )
    result = call_foundation_cli(
        runner,
        "mechanisms-cli.mjs",
        {"operation": operation, "params": params},
    )
    if operation == "canonical-json":
        if (
            not isinstance(result, dict)
            or set(result) != {"text"}
            or not isinstance(result.get("text"), str)
        ):
            raise RuntimeError("Foundation canonical-json returned invalid response")
        return result
    if not isinstance(result, dict):
        raise RuntimeError("Foundation mechanism returned non-object")
    return result


def _foundation(request: dict) -> dict:
    return call_foundation_mechanism(foundation_runner(), request)


def _digest(value: object) -> str:
    return str(
        _foundation({"operation": "digest-document", "document": value})["digest"]
    )


def _file_digest(path: Path) -> str:
    closure = _foundation({
        "operation": "resource-closure",
        "root": str(path.parent),
        "resources": [{"path": path.name, "role": "input"}],
    })
    return str(closure["resources"][0]["sha256"])


def foundation_host_for(module_file: str, runner: Path | None = None) -> object:
    """Return this single host only to a sibling in the same managed platform tree."""
    caller = Path(module_file).resolve(strict=True)
    host_file = Path(__file__).resolve(strict=True)
    verified_runner = (
        foundation_runner()
        if runner is None
        else verify_foundation_bundle(str(runner))
    )
    platform_root = verified_runner.parents[2]
    same_platform = (
        platform_root in host_file.parents and platform_root in caller.parents
    )
    source_root = next(
        (ancestor for ancestor in host_file.parents if ancestor.name == "plugin-src"),
        None,
    )
    same_source = (
        source_root is not None
        and source_root in caller.parents
        and platform_root.parent == source_root.parent / "generated" / "platforms"
    )
    if not (same_platform or same_source):
        raise RuntimeError("FOUNDATION_HOST_CALLER_OUTSIDE_PLATFORM")
    return sys.modules.get(__name__) or sys.modules.get("conformance_check")


def _relative_name(value: str) -> str:
    return Path(value).name if value else ""


def _checker_summary() -> dict:
    return {"method_id": CHECKER_METHOD_ID, "version": CHECKER_VERSION,
            "content_digest": _file_digest(Path(__file__).resolve())}


def _result(status: str, reason: str = "", index: dict | None = None, target: str = "") -> dict:
    index = index or {}
    active = index.get("activeSpecRelease") or {}
    return {"status": status, "summary": "规范检查被阻断" if status == "BLOCKED" else "规范检查失败",
            "error_code": reason, "counts": {"total": 0, "pass": 0, "fail": 0, "not_run": 0, "blocked": int(status == "BLOCKED"), "evidence_missing": 0},
            "rule_results": [], "scan_summary": {"skill_files": [], "agent_files": [], "script_files": [], "manifest_files": []},
            "input_summary": {"target": _relative_name(target), "target_is_relative": True},
            "rule_release_summary": {"release_id": active.get("releaseId", ""), "release_digest": active.get("contentDigest", ""), "rule_manifest_digest": active.get("ruleManifestDigest", "")},
            "checker_summary": _checker_summary(), "warnings": [], "blocked_reason": reason}


def _blocked(code: str, index: dict | None = None, target: str = "") -> dict:
    return _result("BLOCKED", code, index, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_package(package: Path, test_fixture: bool) -> tuple[dict | None, dict | None, str | None]:
    index_path, rules_path = package / "authority-index.json", package / "applicable-rules.json"
    if not index_path.is_file() or not rules_path.is_file():
        return None, None, "SPEC_PACKAGE_INCOMPLETE"
    try:
        index, manifest = _load(index_path), _load(rules_path)
    except (OSError, json.JSONDecodeError):
        return None, None, "SPEC_PACKAGE_INVALID_JSON"
    if index.get("test_fixture") is True and not test_fixture:
        return index, None, "EXTERNAL_SPEC_REQUIRES_TEST_FIXTURE"
    if test_fixture and index.get("test_fixture") is not True:
        return index, None, "SPEC_PACKAGE_NOT_TEST_FIXTURE"
    return index, manifest, None


SELF_AUDIT_SPEC_SUBPATH = ("spec", "self-audit")


def self_audit_spec_package_default() -> Path | None:
    """默认发现路径下的仓内自审规范包。

    仅当 authority-index.json 与 applicable-rules.json 同时存在时返回目录；
    无法定位包根（如仓外独立安装）时返回 None，调用方保持失败关闭。
    """
    root = _package_root()
    if root is None:
        return None
    spec_dir = root.joinpath(*SELF_AUDIT_SPEC_SUBPATH)
    if (
        (spec_dir / "authority-index.json").is_file()
        and (spec_dir / "applicable-rules.json").is_file()
    ):
        return spec_dir
    return None


def _refs_root() -> Path:
    """统一锚定源树 refs，使 generated 投影副本中的脚本也校验同一权威数据。"""
    root = _package_root()
    if root is None:
        return Path(__file__).resolve().parent.parent / "refs"
    return root / "plugin-src" / "skills" / "skill-family-audit-conformance" / "refs"


def verify_self_audit_freshness(spec_dir: Path) -> str | None:
    """校验自审规范包摘要新鲜性；陈旧或非法时返回错误码。

    默认发现路径只接受 ``selfAudit: true`` 的规范包（外部规范必须显式
    --spec-package 提供）；记录摘要必须与当前 refs 权威数据对齐，包内
    applicable-rules.json 必须与 refs 字节一致。任何漂移都拒绝使用。
    """
    try:
        index = _load(spec_dir / "authority-index.json")
    except (OSError, json.JSONDecodeError):
        return "SELF_AUDIT_SPEC_INVALID"
    if index.get("selfAudit") is not True:
        return "SELF_AUDIT_SPEC_REJECTED"
    recorded = index.get("recordedDigests")
    if not isinstance(recorded, dict):
        return "SELF_AUDIT_SPEC_INVALID"
    refs = _refs_root()
    root = _package_root()
    anchored_files = {
        "conformance_trust_policy": refs / "conformance-trust-policy.json",
        "canonical_rule_projection": refs / "canonical-rule-projection.json",
    }
    if root is not None:
        anchored_files["canonical_rule_inventory"] = (
            root / "governance" / "rules" / "canonical-rule-inventory.json"
        )
        anchored_files["governance_axis_adjudication_records"] = (
            root / "spec" / "packages" / "skill-development"
            / "governance-axis-adjudication-records.json"
        )
    for key, path in anchored_files.items():
        expected_digest = recorded.get(key)
        if not isinstance(expected_digest, str) or not HEX64.fullmatch(expected_digest):
            return "SELF_AUDIT_SPEC_INVALID"
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            return "SELF_AUDIT_SPEC_STALE"
    tp_record = recorded.get("trust_policy_projection")
    if not isinstance(tp_record, dict):
        return "SELF_AUDIT_SPEC_INVALID"
    try:
        trust = _load(refs / "conformance-trust-policy.json")
        projection = _load(refs / "canonical-rule-projection.json")
    except (OSError, json.JSONDecodeError):
        return "SELF_AUDIT_SPEC_STALE"
    live = trust.get("canonical_rule_projection", {})
    for field in ("digest", "source_digest", "business_digest", "total_rules"):
        if tp_record.get(field) != live.get(field):
            return "SELF_AUDIT_SPEC_STALE"
    if (
        projection.get("source_digest") != live.get("source_digest")
        or projection.get("business_digest") != live.get("business_digest")
    ):
        return "SELF_AUDIT_SPEC_STALE"
    refs_manifest_path = refs / "applicable-rules.json"
    spec_manifest_path = spec_dir / "applicable-rules.json"
    if not refs_manifest_path.is_file() or not spec_manifest_path.is_file():
        return "SELF_AUDIT_SPEC_STALE"
    refs_manifest_bytes = refs_manifest_path.read_bytes()
    spec_manifest_bytes = spec_manifest_path.read_bytes()
    if (
        recorded.get("refs_applicable_rules") != hashlib.sha256(refs_manifest_bytes).hexdigest()
        or recorded.get("spec_applicable_rules") != hashlib.sha256(spec_manifest_bytes).hexdigest()
        or spec_manifest_bytes != refs_manifest_bytes
    ):
        return "SELF_AUDIT_SPEC_STALE"
    return None


def _scan(target: Path) -> dict:
    result = {"skill_files": [], "agent_files": [], "script_files": [], "manifest_files": []}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in {"node_modules", "__pycache__"}]
        for filename in files:
            rel = (Path(root) / filename).relative_to(target).as_posix()
            if filename == "SKILL.md": result["skill_files"].append(rel)
            elif filename.endswith((".py", ".sh")): result["script_files"].append(rel)
            elif filename.endswith(".md") and "agent" in filename.lower(): result["agent_files"].append(rel)
            elif filename == "manifest.json" or filename.endswith(".plugin.json"): result["manifest_files"].append(rel)
    return result


def _parse_frontmatter(content: str) -> tuple[dict | None, str | None]:
    """解析 YAML frontmatter，返回 (data, error)。最小实现：只支持简单键值对。"""
    lines = content.split("\n")
    if not lines or not FRONTMATTER_BOUNDARY.match(lines[0]):
        return None, "no_frontmatter_boundary"
    end_idx = None
    for i in range(1, len(lines)):
        if FRONTMATTER_BOUNDARY.match(lines[i]):
            end_idx = i
            break
    if end_idx is None:
        return None, "unclosed_frontmatter"
    fm_lines = lines[1:end_idx]
    data = {}
    for line in fm_lines:
        raw_line = line
        line = line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if raw_line[:1].isspace():
            return None, "unsupported_nested_frontmatter"
        if ":" not in line:
            return None, "malformed_frontmatter_line"
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            return None, "empty_frontmatter_key"
        if key in data:
            return None, f"duplicate_key:{key}"
        if value.startswith('"') != value.endswith('"'):
            return None, f"unclosed_quote:{key}"
        if value.startswith("'") != value.endswith("'"):
            return None, f"unclosed_quote:{key}"
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        elif value.lower() in ("true", "yes"):
            value = True
        elif value.lower() in ("false", "no"):
            value = False
        elif value.isdigit():
            value = int(value)
        data[key] = value
    if not isinstance(data, dict):
        return None, "frontmatter_not_mapping"
    return data, None


def _extract_family_from_path(rel_path: str, target: Path) -> str:
    """从相对路径和目标目录提取 family 名称。

    - 如果 SKILL.md 在子目录中（如 `family/SKILL.md`），family 是第一级目录
    - 如果 SKILL.md 在目标根目录（如 `SKILL.md`），family 是目标目录名
    """
    parts = Path(rel_path).parts
    if len(parts) > 1:
        return parts[0]
    return target.name


def _check(rule_id: str, scan: dict, target: Path) -> dict:
    """执行单条规则检查，返回 {status, evidence}。"""
    if rule_id == "structure:skills-exist":
        has_skills = len(scan["skill_files"]) > 0
        return {"status": "PASS" if has_skills else "FAIL",
                "evidence": {"skill_files": scan["skill_files"], "count": len(scan["skill_files"])}}

    if rule_id == "structure:skill-frontmatter-exists":
        evidence = []
        all_have = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            has_fm = bool(re.search(r"^---\s*$", content, re.MULTILINE) and
                         content.index("---") == 0 and
                         content.count("---") >= 2)
            evidence.append({"file": rel, "has_frontmatter": has_fm})
            if not has_fm:
                all_have = False
        return {"status": "PASS" if all_have else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:skill-frontmatter-valid":
        evidence = []
        all_valid = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            valid = error is None and isinstance(data, dict)
            evidence.append({"file": rel, "valid": valid, "error": error})
            if not valid:
                all_valid = False
        return {"status": "PASS" if all_valid else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:skill-name-present":
        evidence = []
        all_present = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            has_name = error is None and isinstance(data, dict) and "name" in data and data["name"]
            evidence.append({"file": rel, "has_name": has_name, "error": error})
            if not has_name:
                all_present = False
        return {"status": "PASS" if all_present else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:skill-description-present":
        evidence = []
        all_present = True
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            has_desc = error is None and isinstance(data, dict) and "description" in data and data["description"]
            evidence.append({"file": rel, "has_description": has_desc, "error": error})
            if not has_desc:
                all_present = False
        return {"status": "PASS" if all_present else "FAIL", "evidence": {"files": evidence}}

    if rule_id == "structure:entry-count":
        # 入口技能：frontmatter 有非空 name、不是内部技能且没有显式禁止用户调用。
        entry_count = 0
        evidence = []
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            name = data.get("name") if isinstance(data, dict) else None
            is_internal = isinstance(data, dict) and data.get("internal") is True
            user_invocable = data.get("user-invocable") if isinstance(data, dict) else None
            is_entry = bool(
                error is None
                and isinstance(name, str)
                and name.strip()
                and not is_internal
                and user_invocable is not False
            )
            if is_entry:
                entry_count += 1
            evidence.append({
                "file": rel,
                "is_entry": is_entry,
                "is_internal": is_internal,
                "user_invocable": user_invocable,
                "error": error,
            })
        return {"status": "PASS" if entry_count > 0 else "FAIL",
                "evidence": {"entry_count": entry_count, "files": evidence}}

    if rule_id == "naming:family-name-format":
        families = set()
        evidence = []
        all_valid = True
        for rel in scan["skill_files"]:
            family = _extract_family_from_path(rel, target)
            if family and family not in families:
                families.add(family)
                valid = bool(FAMILY_NAME_RE.match(family))
                evidence.append({"family": family, "valid": valid})
                if not valid:
                    all_valid = False
        if not families:
            return {"status": "FAIL", "evidence": {"reason": "no_families_found"}}
        return {"status": "PASS" if all_valid else "FAIL", "evidence": {"families": evidence}}

    if rule_id == "visibility:internal-not-user-invocable":
        # 检查是否有内部技能同时标记为 user-invocable: true
        violations = []
        evidence = []
        parse_errors = []
        for rel in scan["skill_files"]:
            content = (target / rel).read_text(encoding="utf-8")
            data, error = _parse_frontmatter(content)
            if error or not isinstance(data, dict):
                evidence.append({"file": rel, "parsed": False, "error": error})
                parse_errors.append({"file": rel, "error": error})
                continue
            # 检查是否为内部技能
            is_internal = data.get("internal") is True or data.get("internal") == "true"
            user_invocable = data.get("user-invocable") is True or data.get("user-invocable") == "true"
            has_violation = is_internal and user_invocable
            evidence.append({"file": rel, "is_internal": is_internal, "user_invocable": user_invocable,
                           "violation": has_violation})
            if has_violation:
                violations.append(rel)
        if parse_errors:
            return {
                "status": "NOT_RUN",
                "evidence": {"reason": "frontmatter_unavailable", "parse_errors": parse_errors, "files": evidence},
            }
        return {"status": "FAIL" if violations else "PASS",
                "evidence": {"violations": violations, "files": evidence}}

    # --- 四条 scope 规则（FM-03 残留标注）---
    # 下列四条分支对 conformance_check.py 兼容入口是死代码，刻意保留不删除：
    # 1. 四条 scope 规则的 applicability 分别为 single_skill / family_source /
    #    release_artifact / project_adoption（见 0.1.27-candidate
    #    refs/applicable-rules.json），本入口的 run_conformance_check 只处理
    #    applicability ∈ {"all", "skill"} 的规则，四类目标由
    #    conformance_workflow.py 按显式 target_type 专属分支承担
    #    （scope:*-complete 的按 target 类型语义在 conformance_workflow.py
    #    L2021-2046 附近，含 project_adoption 的 Foundation 采用完整性校验）。
    # 2. 保留分支以防规则投影回归到本入口时 fail-closed（返回 FAIL 而非误放行）。
    # 3. 本入口只审计 skill 目标，此处出现的目标类型规则不得在此混入错误分母。
    # --- 四条 scope 规则：fail-closed，通过正常 ruleCategories 执行 ---
    if rule_id == "scope:single-skill-complete":
        has_skills = len(scan.get("skill_files", [])) > 0
        return {"status": "PASS" if has_skills else "FAIL",
                "evidence": {"skill_files": scan.get("skill_files", []), "count": len(scan.get("skill_files", []))}}

    if rule_id == "scope:family-source-complete":
        family_files = (
            [f for f in scan.get("script_files", []) if "plugin-src" in f or "spec" in f]
            + scan.get("manifest_files", [])
            + scan.get("skill_files", [])
        )
        return {"status": "PASS" if family_files else "FAIL",
                "evidence": {"family_files": family_files, "count": len(family_files)}}

    if rule_id == "scope:release-artifact-complete":
        artifact_files = scan.get("manifest_files", [])
        return {"status": "PASS" if artifact_files else "FAIL",
                "evidence": {"artifact_files": artifact_files, "count": len(artifact_files)}}

    if rule_id == "scope:project-adoption-present":
        adoption_files = scan.get("skill_files", []) + scan.get("manifest_files", [])
        return {"status": "PASS" if adoption_files else "FAIL",
                "evidence": {"adoption_files": adoption_files, "count": len(adoption_files)}}

    return {"status": "EVIDENCE_MISSING", "evidence": {"reason": "unknown_checker", "rule_id": rule_id}}


def run_conformance_check(target_path: str, project_root: str, spec_version_ref: str | None = None,
                          spec_package: str | None = None, test_fixture: bool = False,
                          output_path: str | None = None) -> dict:
    target, root = Path(target_path).resolve(), Path(project_root).resolve()
    if not target.exists(): return _blocked("TARGET_NOT_FOUND", target=target_path)
    if output_path:
        resolved = Path(output_path).resolve()
        try: resolved.relative_to(root)
        except ValueError: return _blocked("OUTPUT_OUTSIDE_AUTHORIZED_ROOT", target=target_path)
        output = resolved
    else: output = None
    if spec_package:
        index, manifest, error = _validate_package(Path(spec_package).resolve(), test_fixture)
        if error: return _blocked(error, index, target_path)
        self_audit = index.get("selfAudit") is True
    else:
        # D2 自审默认发现路径：无显式规范包时只接受本仓裁决权威派生的
        # 自审规范包（selfAudit: true，摘要新鲜性逐条校验）；外部规范必须
        # 显式 --spec-package 提供。自审包缺失时维持原失败关闭结论。
        spec_dir = self_audit_spec_package_default()
        if spec_dir is None:
            return _blocked("NO_ACTIVE_APPROVED_SPEC", target=target_path)
        freshness_error = verify_self_audit_freshness(spec_dir)
        if freshness_error:
            return _blocked(freshness_error, target=target_path)
        index, manifest, error = _validate_package(spec_dir, test_fixture)
        if error: return _blocked(error, index, target_path)
        self_audit = True
    if manifest.get("checkerMethodId") != CHECKER_METHOD_ID:
        return _blocked("UNKNOWN_CHECKER", index, target_path)
    scan, results = _scan(target), []
    for category in manifest.get("ruleCategories", []):
        for rule in category.get("rules", []):
            # 该兼容入口只审计 skill；四类目标由 conformance_workflow.py
            # 按显式 target_type 过滤和执行，不能在这里混入错误分母。
            if rule.get("applicability") not in {"all", "skill"}:
                continue
            rule_id = rule.get("ruleId", "unknown")
            expected = rule.get("revisionDigest")
            actual = _digest({k: v for k, v in rule.items() if k != "revisionDigest"})
            if set(rule) != RULE_FIELDS or not HEX64.fullmatch(str(expected)):
                outcome = {"status": "NOT_RUN", "evidence": {"reason": "invalid_rule_definition"}}
            elif expected != actual:
                outcome = {"status": "BLOCKED", "evidence": {"reason": "rule_revision_digest_mismatch"}}
            else:
                try:
                    outcome = _check(rule_id, scan, target)
                except Exception as exc:
                    outcome = {"status": "NOT_RUN", "evidence": {"reason": "checker_exception", "exception_type": type(exc).__name__}}
            results.append({"rule_id": rule_id, "rule_revision_digest": expected or "", **outcome})
    counts = {key: sum(r["status"] == label for r in results) for key, label in
              {"pass":"PASS", "fail":"FAIL", "not_run":"NOT_RUN", "blocked":"BLOCKED", "evidence_missing":"EVIDENCE_MISSING"}.items()}
    counts["total"] = len(results)
    if counts["blocked"]:
        status, error_code = "BLOCKED", "RULE_BLOCKED"
    elif not counts["total"]:
        status, error_code = "FAILED", "RULE_MANIFEST_EMPTY"
    elif counts["evidence_missing"]:
        status, error_code = "FAILED", "RULE_EVIDENCE_MISSING"
    elif counts["not_run"]:
        status, error_code = "FAILED", "RULE_NOT_RUN"
    elif counts["fail"]:
        status, error_code = "FAILED", "RULE_FAILED"
    else:
        status, error_code = "SUCCEEDED", ""
    result = {"status": status, "summary": "规范检查通过" if status == "SUCCEEDED" else "规范检查失败",
              "error_code": error_code, "counts": counts,
              "rule_results": results,
              "scan_summary": scan, "input_summary": {"target": target.name, "target_is_relative": True},
              "rule_release_summary": {"release_id": "", "release_digest": "", "rule_manifest_digest": ""},
              "checker_summary": _checker_summary(), "warnings": [], "blocked_reason": "",
              "test_fixture": index.get("test_fixture") is True,
              "self_audit": self_audit,
              "publication_eligible": index.get("test_fixture") is not True and index.get("selfAudit") is not True}
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result



def publication_consumption_error(result: dict) -> str | None:
    """发布门禁消费前的固定拒绝规则；测试夹具结果永不具备发布资格。"""
    if result.get("test_fixture") is True or result.get("publication_eligible") is False:
        return "TEST_FIXTURE_RESULT_NOT_PUBLISHABLE"
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target_path"); parser.add_argument("--project-root", default="."); parser.add_argument("--spec-version")
    parser.add_argument("--spec-package"); parser.add_argument("--test-fixture", action="store_true"); parser.add_argument("--output")
    args = parser.parse_args()
    result = run_conformance_check(args.target_path, args.project_root, args.spec_version, args.spec_package, args.test_fixture, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["status"] == "SUCCEEDED" else 2 if result["status"] == "BLOCKED" else 1)


if __name__ == "__main__": main()
