#!/usr/bin/env python3
"""不可变发行物的隔离安装、公开入口解析、严格入口调用与清理闭环。

支持四平台 provider：codex、claude-code、kimi-code、workbuddy。
命令执行边界可通过 CommandExecutor 协议替换，测试不依赖本机登录态。
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


class InstallError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Utility functions (unchanged)
# ---------------------------------------------------------------------------


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def tree_digest(root: Path) -> str:
    """计算目录树摘要：全部普通文件计入，符号链接或非普通文件稳定失败关闭。"""
    rows: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise InstallError("INSTALL_TREE_IRREGULAR_FILE")
        if path.is_dir():
            continue
        if not path.is_file():
            raise InstallError("INSTALL_TREE_IRREGULAR_FILE")
        rows[path.relative_to(root).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    return hashlib.sha256(canonical(rows)).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise InstallError(f"{path} 顶层必须是对象")
    return value


def consume_quickstart_task(argv: list[str]) -> dict[str, Any] | None:
    if not os.environ.get("SFA_NORMALIZED_TASK_REF"):
        return None
    path = Path(os.environ.get("SFA_RUNTIME_CONTRACTS_REF", ""))
    if not path.is_absolute() or path.is_symlink():
        raise InstallError("NORMALIZED_TASK_BINDING_INVALID")
    resolved = path.resolve(strict=True)
    spec = importlib.util.spec_from_file_location(
        "behavior_install_quickstart_contracts", resolved
    )
    if spec is None or spec.loader is None:
        raise InstallError("NORMALIZED_TASK_BINDING_INVALID")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.consume_normalized_task(
            method_id="skill-family-audit:behavior-audit",
            script_path=__file__,
            argv=argv,
        )
    except module.NormalizedTaskBindingError as exc:
        raise InstallError(f"NORMALIZED_TASK_BINDING_INVALID:{exc}") from exc


# ---------------------------------------------------------------------------
# Command executor protocol (可替换测试边界)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


class CommandExecutor(Protocol):
    """可替换的命令执行边界；测试注入 mock 实现。"""

    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult: ...


class DefaultCommandExecutor:
    """使用 subprocess.run 的默认命令执行器。"""

    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        completed = subprocess.run(
            argv, text=True, capture_output=True, env=env, cwd=cwd
        )
        return CommandResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )


# ---------------------------------------------------------------------------
# PTY executor protocol (Kimi Code 需要 PTY 驱动 /plugins 交互)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PTYResult:
    output: str
    returncode: int
    success: bool


class PTYExecutor(Protocol):
    """可替换的 PTY 执行边界；Kimi Code 通过 PTY 发送 /plugins 命令。"""

    def run_plugin_command(
        self,
        executable: str,
        command: str,
        state_root: Path,
        env: dict[str, str],
        *,
        timeout: int = 45,
    ) -> PTYResult: ...


class DefaultPTYExecutor:
    """使用系统 script 分配 PTY 的默认执行器。"""

    def run_plugin_command(
        self,
        executable: str,
        command: str,
        state_root: Path,
        env: dict[str, str],
        *,
        timeout: int = 45,
    ) -> PTYResult:
        import threading

        chunks: list[bytes] = []
        process = subprocess.Popen(
            ["/usr/bin/script", "-q", "/dev/null", executable],
            cwd=state_root,
            env={**env, "KIMI_CODE_HOME": str(state_root), "TERM": "xterm-256color"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        def drain() -> None:
            assert process.stdout is not None
            while True:
                data = os.read(process.stdout.fileno(), 1024)
                if not data:
                    return
                chunks.append(data)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        assert process.stdin is not None
        try:
            import time
            time.sleep(1.0)
            process.stdin.write(command.encode("utf-8") + b"\r")
            process.stdin.flush()
            time.sleep(0.2)
            process.stdin.write(b"\r")
            process.stdin.flush()

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                time.sleep(0.1)

            if process.poll() is None:
                process.stdin.write(b"/exit\r")
                process.stdin.flush()
                time.sleep(0.1)
                process.stdin.write(b"\r")
                process.stdin.flush()
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        finally:
            reader.join(timeout=2)

        output = b"".join(chunks).decode("utf-8", errors="replace")
        return PTYResult(
            output=output,
            returncode=process.returncode or 0,
            success=process.returncode == 0,
        )


# ---------------------------------------------------------------------------
# Provider specification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderSpec:
    """四平台 provider 确定规格。"""
    platform_id: str
    executable_names: list[str]
    config_home_env: str
    marketplace_rel_path: str
    marketplace_json_rel_path: str
    plugin_selector_template: str
    install_commands: list[list[str]]
    discover_commands: list[list[str]]
    uninstall_commands: list[list[str]]
    skill_root_template: str
    quickstart_root_template: str
    allowed_providers: list[str] = field(default_factory=list)
    marketplace_name: str = ""
    has_marketplace: bool = True
    use_pty: bool = False


_PROVIDER_REGISTRY: dict[str, ProviderSpec] = {}


def _register_provider(spec: ProviderSpec) -> None:
    _PROVIDER_REGISTRY[spec.platform_id] = spec


def resolve_provider(platform: str) -> ProviderSpec:
    spec = _PROVIDER_REGISTRY.get(platform)
    if spec is None:
        raise InstallError("INSTALL_PROVIDER_UNSUPPORTED")
    return spec


# --- Codex provider ---

def _codex_install_commands(
    marketplace_root: str, plugin_selector: str, codex_exec: str,
) -> list[list[str]]:
    return [
        [codex_exec, "plugin", "marketplace", "add", marketplace_root, "--json"],
        [codex_exec, "plugin", "add", plugin_selector, "--json"],
    ]


def _codex_uninstall_commands(
    marketplace_name: str, plugin_selector: str, codex_exec: str,
) -> list[list[str]]:
    return [
        [codex_exec, "plugin", "remove", plugin_selector, "--json"],
        [codex_exec, "plugin", "marketplace", "remove", marketplace_name, "--json"],
    ]


_register_provider(ProviderSpec(
    platform_id="codex",
    executable_names=["codex"],
    config_home_env="CODEX_HOME",
    marketplace_rel_path="plugins/cache/skill-family-audit-local-test/skill-family-audit",
    marketplace_json_rel_path="platforms/codex/.agents/plugins/marketplace.json",
    plugin_selector_template="skill-family-audit@{marketplace_name}",
    install_commands=[],  # built dynamically
    discover_commands=[["{executable}", "plugin", "list", "--json"]],
    uninstall_commands=[],  # built dynamically
    skill_root_template="{install_root}/skills/behavior-audit",
    quickstart_root_template="{install_root}/skills/quickstart",
    allowed_providers=["codex-cli-local-marketplace"],
    marketplace_name="skill-family-audit-local-test",
    has_marketplace=True,
))

# --- Claude Code provider ---

def _claude_install_commands(
    marketplace_root: str, plugin_selector: str, executable: str,
) -> list[list[str]]:
    return [
        [executable, "plugin", "marketplace", "add", marketplace_root],
        [executable, "plugin", "install", plugin_selector],
    ]


def _claude_uninstall_commands(
    marketplace_name: str, plugin_selector: str, executable: str,
) -> list[list[str]]:
    return [
        [executable, "plugin", "uninstall", plugin_selector],
        [executable, "plugin", "marketplace", "remove", marketplace_name],
    ]


_register_provider(ProviderSpec(
    platform_id="claude-code",
    executable_names=["claude"],
    config_home_env="CLAUDE_CONFIG_DIR",
    marketplace_rel_path="plugins/cache/skill-family-audit-local/skill-family-audit",
    marketplace_json_rel_path="platforms/claude-code/.claude-plugin/marketplace.json",
    plugin_selector_template="skill-family-audit@{marketplace_name}",
    install_commands=[],
    discover_commands=[["{executable}", "plugin", "list", "--json"]],
    uninstall_commands=[],
    skill_root_template="{install_root}/skills/behavior-audit",
    quickstart_root_template="{install_root}/skills/quickstart",
    allowed_providers=["claude-code-local-marketplace"],
    marketplace_name="skill-family-audit-local",
    has_marketplace=True,
))

# --- Kimi Code provider ---

def _kimi_install_commands(
    marketplace_root: str, plugin_selector: str, executable: str,
) -> list[list[str]]:
    return [
        [executable, "plugin", "install", marketplace_root],
    ]


def _kimi_uninstall_commands(
    marketplace_name: str, plugin_selector: str, executable: str,
) -> list[list[str]]:
    return [
        [executable, "plugin", "remove", "skill-family-audit"],
    ]


_register_provider(ProviderSpec(
    platform_id="kimi-code",
    executable_names=["kimi"],
    config_home_env="KIMI_CODE_HOME",
    marketplace_rel_path="plugins/managed/skill-family-audit",
    marketplace_json_rel_path="platforms/kimi-code/kimi.plugin.json",
    plugin_selector_template="skill-family-audit",
    install_commands=[],
    discover_commands=[["{executable}", "plugin", "list"]],
    uninstall_commands=[],
    skill_root_template="{install_root}/skills/skill-family-audit-behavior-audit",
    quickstart_root_template="{install_root}/skills/skill-family-audit-quickstart",
    allowed_providers=["kimi-code-native-plugin"],
    marketplace_name="",
    has_marketplace=False,
    use_pty=True,
))

# --- WorkBuddy provider ---

def _workbuddy_install_commands(
    marketplace_root: str, plugin_selector: str, executable: str,
) -> list[list[str]]:
    return [
        [executable, "plugin", "marketplace", "add", marketplace_root],
        [executable, "plugin", "install", plugin_selector, "--scope", "user"],
    ]


def _workbuddy_uninstall_commands(
    marketplace_name: str, plugin_selector: str, executable: str,
) -> list[list[str]]:
    return [
        [executable, "plugin", "uninstall", plugin_selector, "--scope", "user"],
        [executable, "plugin", "marketplace", "remove", marketplace_name],
    ]


_register_provider(ProviderSpec(
    platform_id="workbuddy",
    executable_names=["codebuddy", "cbc"],
    config_home_env="CODEBUDDY_CONFIG_DIR",
    marketplace_rel_path="plugins/cache/skill-family-audit-local/skill-family-audit",
    marketplace_json_rel_path="platforms/workbuddy/.codebuddy-plugin/marketplace.json",
    plugin_selector_template="skill-family-audit@{marketplace_name}",
    install_commands=[],
    discover_commands=[["{executable}", "plugin", "marketplace", "list"]],
    uninstall_commands=[],
    skill_root_template="{install_root}/skills/skill-family-audit-behavior-audit",
    quickstart_root_template="{install_root}/skills/skill-family-audit-quickstart",
    allowed_providers=["workbuddy-local-marketplace"],
    marketplace_name="skill-family-audit-local",
    has_marketplace=True,
))


# ---------------------------------------------------------------------------
# Provider-specific logic
# ---------------------------------------------------------------------------


def resolve_executable(provider: ProviderSpec) -> tuple[Path, str]:
    """解析 provider 可执行文件；缺失时 fail closed。"""
    for name in provider.executable_names:
        resolved = shutil.which(name)
        if resolved:
            executable = Path(resolved).resolve(strict=True)
            return executable, name
    raise InstallError("INSTALL_PROVIDER_MISSING")


def verify_executable_version(
    executable: Path, expected_version: str, executor: CommandExecutor,
) -> str:
    """验证 provider 版本；不匹配时 fail closed。"""
    result = executor.run([str(executable), "--version"])
    actual_version = result.stdout.strip()
    if result.returncode != 0 or actual_version != expected_version:
        raise InstallError("INSTALL_PROVIDER_VERSION_MISMATCH")
    return actual_version


def validate_provider_artifact(
    provider: ProviderSpec, artifact: Path,
) -> None:
    """验证 provider 所需的 artifact marketplace 或 manifest 存在。"""
    if provider.has_marketplace:
        marketplace_path = artifact / provider.marketplace_json_rel_path
        if not marketplace_path.is_file():
            raise InstallError("CODEX_MARKETPLACE_MISSING")
    else:
        manifest_path = artifact / provider.marketplace_json_rel_path
        if not manifest_path.is_file():
            raise InstallError("PLUGIN_MANIFEST_MISSING")


def build_install_commands_for(
    provider: ProviderSpec, marketplace_root: str, executable: Path,
) -> list[list[str]]:
    """构建 provider 特定的安装命令。"""
    executable_str = str(executable)
    plugin_selector = provider.plugin_selector_template.format(
        marketplace_name=provider.marketplace_name,
    )
    if provider.platform_id == "codex":
        return _codex_install_commands(
            marketplace_root, plugin_selector, executable_str,
        )
    if provider.platform_id == "claude-code":
        return _claude_install_commands(
            marketplace_root, plugin_selector, executable_str,
        )
    if provider.platform_id == "kimi-code":
        return _kimi_install_commands(
            marketplace_root, plugin_selector, executable_str,
        )
    if provider.platform_id == "workbuddy":
        return _workbuddy_install_commands(
            marketplace_root, plugin_selector, executable_str,
        )
    raise InstallError("INSTALL_PROVIDER_UNSUPPORTED")


def build_uninstall_commands_for(
    provider: ProviderSpec, executable: Path,
) -> list[list[str]]:
    """构建 provider 特定的卸载命令。"""
    executable_str = str(executable)
    plugin_selector = provider.plugin_selector_template.format(
        marketplace_name=provider.marketplace_name,
    )
    if provider.platform_id == "codex":
        return _codex_uninstall_commands(
            provider.marketplace_name, plugin_selector, executable_str,
        )
    if provider.platform_id == "claude-code":
        return _claude_uninstall_commands(
            provider.marketplace_name, plugin_selector, executable_str,
        )
    if provider.platform_id == "kimi-code":
        return _kimi_uninstall_commands(
            provider.marketplace_name, plugin_selector, executable_str,
        )
    if provider.platform_id == "workbuddy":
        return _workbuddy_uninstall_commands(
            provider.marketplace_name, plugin_selector, executable_str,
        )
    raise InstallError("INSTALL_PROVIDER_UNSUPPORTED")


def _write_json_file(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def setup_codex_marketplace(
    artifact: Path, provider: ProviderSpec, config_home: Path,
) -> str:
    """为 Codex 创建本地 marketplace 结构；返回 marketplace root 路径字符串。"""
    platform_source = artifact / "platforms" / "codex"
    marketplace_root = config_home / "marketplace"
    plugin_dest = marketplace_root / "skill-family-audit"
    marketplace_manifest = marketplace_root / ".agents/plugins/marketplace.json"
    shutil.copytree(platform_source, plugin_dest)
    _write_json_file(marketplace_manifest, {
        "name": provider.marketplace_name,
        "interface": {
            "displayName": "Skill Family Audit local test",
            "shortDescription": "isolated lifecycle test",
            "category": "Developer Tools",
        },
        "plugins": [{
            "name": "skill-family-audit",
            "source": {"source": "local", "path": "./skill-family-audit"},
            "policy": {
                "installation": "AVAILABLE",
                "authentication": "ON_INSTALL",
            },
            "category": "Developer Tools",
            "description": "isolated lifecycle test",
        }],
    })
    return str(marketplace_root)


def setup_claude_code_marketplace(
    artifact: Path, provider: ProviderSpec, config_home: Path,
) -> str:
    """为 Claude Code 创建本地 marketplace 结构。"""
    platform_source = artifact / "platforms" / "claude-code"
    marketplace_root = config_home / "marketplace"
    plugin_dest = marketplace_root / "skill-family-audit"
    marketplace_manifest = marketplace_root / ".claude-plugin/marketplace.json"
    shutil.copytree(platform_source, plugin_dest)
    _write_json_file(marketplace_manifest, {
        "name": provider.marketplace_name,
        "plugins": [{
            "name": "skill-family-audit",
            "source": "./skill-family-audit",
            "description": "isolated lifecycle test",
        }],
    })
    return str(marketplace_root)


def setup_workbuddy_marketplace(
    artifact: Path, provider: ProviderSpec, config_home: Path,
) -> str:
    """为 WorkBuddy 创建本地 marketplace 结构。"""
    platform_source = artifact / "platforms" / "workbuddy"
    marketplace_root = config_home / "marketplace"
    plugin_dest = marketplace_root / "skill-family-audit"
    marketplace_manifest = marketplace_root / ".codebuddy-plugin/marketplace.json"
    shutil.copytree(platform_source, plugin_dest)
    _write_json_file(marketplace_manifest, {
        "name": provider.marketplace_name,
        "plugins": [{
            "name": "skill-family-audit",
            "source": "./skill-family-audit",
            "description": "isolated lifecycle test",
        }],
    })
    return str(marketplace_root)


def setup_provider_marketplace(
    provider: ProviderSpec, artifact: Path, config_home: Path,
) -> str:
    """按 provider 规格创建或定位 marketplace；返回 marketplace root 路径。"""
    if provider.platform_id == "codex":
        return setup_codex_marketplace(artifact, provider, config_home)
    if provider.platform_id == "claude-code":
        return setup_claude_code_marketplace(artifact, provider, config_home)
    if provider.platform_id == "workbuddy":
        return setup_workbuddy_marketplace(artifact, provider, config_home)
    if provider.platform_id == "kimi-code":
        validate_provider_artifact(provider, artifact)
        return str(artifact / "platforms" / "kimi-code")
    raise InstallError("INSTALL_PROVIDER_UNSUPPORTED")


def parse_installed_path_from_output(
    install_commands: list[dict[str, Any]],
    config_home: Path,
    provider: ProviderSpec,
) -> Path:
    """仅 Codex 允许从 --json 输出解析 installedPath。"""
    if provider.platform_id != "codex":
        raise InstallError("INSTALL_PROVIDER_RESULT_INVALID")
    for record in reversed(install_commands):
        stdout = record.get("_stdout", "")
        if not stdout:
            continue
        decoder = json.JSONDecoder()
        for index, char in enumerate(stdout):
            if char != "{":
                continue
            try:
                value, _ = decoder.raw_decode(stdout[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and "installedPath" in value:
                return _resolve_and_validate_provider_path(
                    value["installedPath"], config_home,
                )
    raise InstallError("INSTALL_PROVIDER_RESULT_INVALID")


def _resolve_and_validate_provider_path(
    raw_path: str,
    config_home: Path,
) -> Path:
    """统一验证 provider 发现结果路径：resolve(strict=True)、真实目录、严格位于 config_home 之下。

    路径必须是真实目录且严格位于 config_home 内部（不能等于 config_home 本身）。
    越界返回 INSTALL_PROVIDER_PATH_ESCAPE；发现状态缺失返回 INSTALL_DISCOVERY_FAILED。
    """
    try:
        resolved = Path(raw_path).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise InstallError("INSTALL_DISCOVERY_FAILED") from exc
    if not resolved.is_dir() or resolved.is_symlink():
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    if config_home not in resolved.parents:
        raise InstallError("INSTALL_PROVIDER_PATH_ESCAPE")
    return resolved


def _discover_install_root(
    provider: ProviderSpec,
    config_home: Path,
    install_commands: list[dict[str, Any]],
    platform: str,
) -> Path:
    """按 provider 特定逻辑发现安装根目录；无法证明时 fail closed。

    - Codex: 从 --json installedPath 解析
    - Claude Code: 从 CLAUDE_CONFIG_DIR/plugins/installed/ 读取 registry
    - Kimi Code: 从 KIMI_CODE_HOME/plugins/installed.json 读取
    - WorkBuddy: 从 settings.json enabledPlugins + known_marketplaces.json installLocation 解析
    """
    if provider.platform_id == "codex":
        return parse_installed_path_from_output(
            install_commands, config_home, provider,
        )

    if provider.platform_id == "claude-code":
        return _discover_claude_install_root(config_home)

    if provider.platform_id == "kimi-code":
        return _discover_kimi_install_root(config_home)

    if provider.platform_id == "workbuddy":
        return _discover_workbuddy_install_root(config_home)

    raise InstallError("INSTALL_PROVIDER_UNSUPPORTED")


def _discover_claude_install_root(config_home: Path) -> Path:
    """从 CLAUDE_CONFIG_DIR 的 installed plugin registry 解析安装根。"""
    registry = config_home / "plugins" / "installed_plugins.json"
    if not registry.is_file():
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    try:
        data = json.loads(registry.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise InstallError("INSTALL_DISCOVERY_FAILED") from exc
    entries = data.get("plugins", {}).get(
        "skill-family-audit@skill-family-audit-local"
    ) if isinstance(data, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    install_path = entries[0].get("installPath") if isinstance(entries[0], dict) else None
    if isinstance(install_path, str):
        return _resolve_and_validate_provider_path(install_path, config_home)
    raise InstallError("INSTALL_DISCOVERY_FAILED")


def _discover_kimi_install_root(config_home: Path) -> Path:
    """从 KIMI_CODE_HOME/plugins/installed.json 解析安装根。"""
    installed_json = config_home / "plugins" / "installed.json"
    if not installed_json.is_file():
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    try:
        data = json.loads(installed_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, list):
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    for entry in plugins:
        if isinstance(entry, dict) and entry.get("id") == "skill-family-audit":
            root_value = entry.get("root")
            if not isinstance(root_value, str):
                raise InstallError("INSTALL_DISCOVERY_FAILED")
            return _resolve_and_validate_provider_path(root_value, config_home)
    raise InstallError("INSTALL_DISCOVERY_FAILED")


def _discover_workbuddy_install_root(config_home: Path) -> Path:
    """从 settings.json enabledPlugins + known_marketplaces.json 解析安装根。

    WorkBuddy 不返回 installedPath；必须从两个状态文件交叉验证。
    """
    settings_path = config_home / "settings.json"
    marketplaces_path = config_home / "plugins" / "known_marketplaces.json"
    if not settings_path.is_file() or not marketplaces_path.is_file():
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        marketplaces = json.loads(marketplaces_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    plugin_selector = "skill-family-audit@skill-family-audit-local"
    enabled_plugins = settings.get("enabledPlugins", {})
    if not isinstance(enabled_plugins, dict) or enabled_plugins.get(plugin_selector) is not True:
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    marketplace_entry = marketplaces.get("skill-family-audit-local", {})
    if not isinstance(marketplace_entry, dict):
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    install_location = marketplace_entry.get("installLocation")
    if not isinstance(install_location, str) or not install_location:
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    return _resolve_and_validate_provider_path(install_location, config_home)


def _verify_install_root(
    install_root: Path,
    provider: ProviderSpec,
) -> None:
    """验证安装根目录存在且包含预期结构。"""
    if not install_root.is_dir():
        raise InstallError("INSTALL_DISCOVERY_FAILED")
    skill_root = resolve_skill_root(install_root, provider)
    behavior_entry = skill_root / "scripts" / "behavior_audit.py"
    quickstart_entry = resolve_quickstart_entry(install_root, provider)
    if not behavior_entry.is_file() or not quickstart_entry.is_file():
        raise InstallError("INSTALLED_ENTRY_MISSING")


def resolve_skill_root(
    install_root: Path, provider: ProviderSpec,
) -> Path:
    """解析 skill 根目录。"""
    template = provider.skill_root_template
    return Path(template.format(install_root=install_root))


def resolve_quickstart_entry(
    install_root: Path, provider: ProviderSpec,
) -> Path:
    """解析 Quickstart 公开入口脚本路径。"""
    quickstart_root = Path(
        provider.quickstart_root_template.format(install_root=install_root)
    )
    return quickstart_root / "scripts" / "quickstart_route.py"


# ---------------------------------------------------------------------------
# Main run function (refactored for four-platform support)
# ---------------------------------------------------------------------------


def _build_environment(
    provider: ProviderSpec, config_home: Path,
) -> dict[str, str]:
    """构建隔离环境变量；WorkBuddy 需同时设置两个配置目录。"""
    env = {**os.environ, provider.config_home_env: str(config_home)}
    if provider.platform_id == "workbuddy":
        env["WORKBUDDY_CONFIG_DIR"] = str(config_home)
    return env


def _verify_uninstalled_state(provider: ProviderSpec, config_home: Path) -> None:
    """从 provider 的权威隔离状态证明候选已不再注册。"""
    if provider.platform_id == "claude-code":
        path = config_home / "plugins" / "installed_plugins.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"plugins": {}}
        if "skill-family-audit@skill-family-audit-local" in data.get("plugins", {}):
            raise InstallError("UNINSTALL_STATE_STILL_PRESENT")
    elif provider.platform_id == "kimi-code":
        path = config_home / "plugins" / "installed.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"plugins": []}
        if any(isinstance(item, dict) and item.get("id") == "skill-family-audit" for item in data.get("plugins", [])):
            raise InstallError("UNINSTALL_STATE_STILL_PRESENT")
    elif provider.platform_id == "workbuddy":
        settings_path = config_home / "settings.json"
        market_path = config_home / "plugins" / "known_marketplaces.json"
        settings = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.is_file() else {}
        markets = json.loads(market_path.read_text(encoding="utf-8")) if market_path.is_file() else {}
        if (
            "skill-family-audit@skill-family-audit-local" in settings.get("enabledPlugins", {})
            or "skill-family-audit-local" in markets
        ):
            raise InstallError("UNINSTALL_STATE_STILL_PRESENT")


def run(
    args: argparse.Namespace,
    quickstart_binding: dict[str, Any] | None = None,
    executor: CommandExecutor | None = None,
    pty_executor: PTYExecutor | None = None,
) -> dict[str, Any]:
    if executor is None:
        executor = DefaultCommandExecutor()
    if pty_executor is None:
        pty_executor = DefaultPTYExecutor()

    artifact = Path(args.artifact).resolve(strict=True)
    isolation = Path(args.isolation_root).resolve(strict=True)
    output = Path(args.receipt_output).resolve()
    authorization = load_json(Path(args.install_authorization).resolve(strict=True))

    if not artifact.is_dir() or artifact.is_symlink():
        raise InstallError("发行物必须是无符号链接的真实目录")

    # --- Resolve provider ---
    provider = resolve_provider(args.platform)

    # --- Validate provider-platform binding ---
    if args.provider not in provider.allowed_providers:
        raise InstallError("INSTALL_AUTHORIZATION_PROVIDER_MISMATCH")

    if authorization.get("granted") is not True:
        raise InstallError("INSTALL_AUTHORIZATION_MISSING")
    if authorization.get("platform") != args.platform:
        raise InstallError("INSTALL_AUTHORIZATION_PLATFORM_MISMATCH")
    if authorization.get("provider") != args.provider:
        raise InstallError("INSTALL_AUTHORIZATION_PROVIDER_MISMATCH")

    # --- Resolve and verify executable ---
    provider_executable, _executable_name = resolve_executable(provider)
    provider_executable_digest = hashlib.sha256(
        provider_executable.read_bytes()
    ).hexdigest()
    provider_version = verify_executable_version(
        provider_executable, args.provider_version, executor,
    )

    # --- Validate authorization bindings ---
    actual_digest = tree_digest(artifact)
    if actual_digest != args.artifact_digest:
        raise InstallError("ARTIFACT_DIGEST_MISMATCH")
    if authorization.get("artifact_digest") != actual_digest:
        raise InstallError("INSTALL_AUTHORIZATION_ARTIFACT_MISMATCH")
    if authorization.get("isolation_root") != str(isolation):
        raise InstallError("INSTALL_AUTHORIZATION_ISOLATION_MISMATCH")
    if (
        authorization.get("provider_executable_digest")
        != provider_executable_digest
    ):
        raise InstallError("INSTALL_AUTHORIZATION_PROVIDER_DIGEST_MISMATCH")

    # --- Validate provider artifact ---
    validate_provider_artifact(provider, artifact)

    # --- Setup isolated config home ---
    config_home = isolation / "provider-home"
    if config_home.exists():
        raise InstallError("INSTALL_ROOT_NOT_EMPTY")
    if output == config_home or config_home in output.parents:
        raise InstallError("RECEIPT_MUST_SURVIVE_CLEANUP")

    installed_digest = ""
    install_root = config_home / "placeholder"
    public_entry = install_root / "placeholder"
    strict_entry = install_root / "placeholder"
    public_entry_digest = ""
    public_completed: subprocess.CompletedProcess[str] | None = None
    response: dict[str, Any] | None = None
    cleanup_status = "pending"
    install_commands: list[dict[str, Any]] = []
    uninstall_commands: list[dict[str, Any]] = []

    try:
        config_home.mkdir()
        environment = _build_environment(provider, config_home)

        # --- Setup marketplace ---
        marketplace_root = setup_provider_marketplace(
            provider, artifact, config_home,
        )

        if provider.use_pty:
            # --- Kimi: PTY-driven /plugins install ---
            candidate_plugin = str(artifact / "platforms" / args.platform)
            pty_result = pty_executor.run_plugin_command(
                str(provider_executable),
                f"/plugins install {candidate_plugin}",
                config_home,
                environment,
            )
            install_commands.append({
                "argv": [
                    str(provider_executable), "<interactive>",
                    f"/plugins install <candidate-plugin>",
                ],
                "exit_code": pty_result.returncode,
                "stdout_digest": hashlib.sha256(
                    pty_result.output.encode()
                ).hexdigest(),
                "stderr_digest": "",
                "pty_success": pty_result.success,
            })
            if not pty_result.success:
                raise InstallError("INSTALL_PROVIDER_FAILED")
        else:
            # --- Claude/WorkBuddy/Codex: CLI install commands ---
            raw_install_commands = build_install_commands_for(
                provider, marketplace_root, provider_executable,
            )
            for command in raw_install_commands:
                result = executor.run(command, env=environment)
                record: dict[str, Any] = {
                    "argv": command,
                    "exit_code": result.returncode,
                    "stdout_digest": hashlib.sha256(
                        result.stdout.encode()
                    ).hexdigest(),
                    "stderr_digest": hashlib.sha256(
                        result.stderr.encode()
                    ).hexdigest(),
                }
                # Codex 需要从 stdout 解析 installedPath；临时保存，收据前删除
                if provider.platform_id == "codex":
                    record["_stdout"] = result.stdout
                install_commands.append(record)
                if result.returncode != 0:
                    raise InstallError("INSTALL_PROVIDER_FAILED")

        # --- Discover install root (provider-specific) ---
        install_root = _discover_install_root(
            provider, config_home, install_commands, args.platform,
        )
        _verify_install_root(install_root, provider)
        installed_digest = tree_digest(install_root)

        # --- Verify installed tree matches platform source ---
        platform_source = artifact / "platforms" / args.platform
        platform_digest = tree_digest(platform_source)
        if installed_digest != platform_digest:
            raise InstallError("INSTALLED_ARTIFACT_DIGEST_MISMATCH")

        # --- Resolve skill root and entries ---
        skill_root = resolve_skill_root(install_root, provider)
        public_entry = resolve_quickstart_entry(install_root, provider)
        strict_entry = skill_root / "scripts/behavior_audit.py"
        if not public_entry.is_file() or not strict_entry.is_file():
            raise InstallError("INSTALLED_ENTRY_MISSING")
        public_entry_digest = hashlib.sha256(
            public_entry.read_bytes()
        ).hexdigest()

        # --- Validate invocation args ---
        invocation = json.loads(args.invocation_args_json)
        if not isinstance(invocation, list) or any(
            not isinstance(item, str) for item in invocation
        ):
            raise InstallError("INVOCATION_ARGS_INVALID")

        # --- Invoke public entry ---
        route_output = isolation / "behavior-public-route"
        public_completed = subprocess.run(
            [
                "python3",
                str(public_entry),
                "--request",
                "执行行为验证",
                "--platform",
                args.platform,
                "--authorization",
                str(Path(args.method_authorization).resolve(strict=True)),
                "--method-args-json",
                json.dumps(invocation, ensure_ascii=False),
                "--run-id",
                args.run_id,
                "--workspace-root",
                str(isolation),
                "--output-dir",
                str(route_output),
                "--platform-manifest",
                str(install_root / "platform-manifest.json"),
            ],
            cwd=install_root,
            text=True,
            capture_output=True,
        )
        try:
            parsed = json.loads(public_completed.stdout)
        except json.JSONDecodeError as exc:
            raise InstallError("PUBLIC_ENTRY_RESULT_INVALID") from exc
        if not isinstance(parsed, dict):
            raise InstallError("PUBLIC_ENTRY_RESULT_INVALID")
        response = parsed

        # --- Uninstall (provider-specific) ---
        if provider.use_pty:
            # --- Kimi: PTY-driven /plugins remove ---
            remove_result = pty_executor.run_plugin_command(
                str(provider_executable),
                "/plugins remove skill-family-audit",
                config_home,
                environment,
            )
            uninstall_commands.append({
                "argv": [
                    str(provider_executable), "<interactive>",
                    "/plugins remove <candidate-plugin>",
                ],
                "exit_code": remove_result.returncode,
                "stdout_digest": hashlib.sha256(
                    remove_result.output.encode()
                ).hexdigest(),
                "stderr_digest": "",
                "pty_success": remove_result.success,
            })
            if not remove_result.success:
                raise InstallError("UNINSTALL_PROVIDER_FAILED")
        else:
            # --- Claude/WorkBuddy/Codex: CLI uninstall commands ---
            raw_uninstall_commands = build_uninstall_commands_for(
                provider, provider_executable,
            )
            for command in raw_uninstall_commands:
                result = executor.run(command, env=environment)
                uninstall_commands.append({
                    "argv": command,
                    "exit_code": result.returncode,
                    "stdout_digest": hashlib.sha256(
                        result.stdout.encode()
                    ).hexdigest(),
                    "stderr_digest": hashlib.sha256(
                        result.stderr.encode()
                    ).hexdigest(),
                })
                if result.returncode != 0:
                    raise InstallError("UNINSTALL_PROVIDER_FAILED")

        if provider.platform_id == "codex":
            listed = executor.run(
                [str(provider_executable), "plugin", "list", "--json"],
                env=environment,
            )
            try:
                listed_value = json.loads(listed.stdout)
            except json.JSONDecodeError as exc:
                raise InstallError("UNINSTALL_DISCOVERY_INVALID") from exc
            uninstall_commands.append({
                "argv": [str(provider_executable), "plugin", "list", "--json"],
                "exit_code": listed.returncode,
                "stdout_digest": hashlib.sha256(listed.stdout.encode()).hexdigest(),
                "stderr_digest": hashlib.sha256(listed.stderr.encode()).hexdigest(),
            })
            if listed.returncode != 0 or "skill-family-audit" in json.dumps(listed_value):
                raise InstallError("UNINSTALL_STATE_STILL_PRESENT")
        else:
            _verify_uninstalled_state(provider, config_home)

    finally:
        if config_home.exists():
            shutil.rmtree(config_home)
        cleanup_status = "clean"

    assert public_completed is not None and response is not None
    outer_result = response.get("result")
    if not isinstance(outer_result, dict):
        raise InstallError("PUBLIC_ENTRY_RESULT_INVALID")
    outer_result = copy.deepcopy(outer_result)
    if quickstart_binding is not None:
        outer_result["extensions"] = [
            item
            for item in outer_result.get("extensions", [])
            if not isinstance(item, dict)
            or item.get("extension_id")
            != "skill-family-audit:quickstart-task-binding"
        ]
        outer_result["extensions"].append(quickstart_binding)
    response = copy.deepcopy(response)
    response["result"] = outer_result

    # 收据中不记录 raw stdout；只保留 digest
    for record in install_commands:
        record.pop("_stdout", None)

    receipt = {
        "schema_version": "1.0.0",
        "status": (
            "passed"
            if public_completed.returncode == 0
            and response.get("execution_status") == "SUCCEEDED"
            else "failed"
        ),
        "artifact": {
            "digest": actual_digest,
            "source": str(artifact),
            "installed_digest": installed_digest,
            "installed_platform_digest": installed_digest,
        },
        "installation": {
            "platform": args.platform,
            "provider": args.provider,
            "provider_version": provider_version,
            "provider_executable": str(provider_executable),
            "provider_executable_digest": provider_executable_digest,
            "root": str(install_root),
            "commands": install_commands,
            "authorization_digest": hashlib.sha256(
                Path(args.install_authorization).read_bytes()
            ).hexdigest(),
        },
        "uninstallation": {
            "commands": uninstall_commands,
        },
        "invocation": {
            "public_entry": public_entry.relative_to(install_root).as_posix(),
            "public_entry_digest": public_entry_digest,
            "strict_entry": strict_entry.relative_to(install_root).as_posix(),
            "public_entry_exit_code": public_completed.returncode,
            "method_authorization_digest": hashlib.sha256(
                Path(args.method_authorization).read_bytes()
            ).hexdigest(),
            "result": response,
        },
        "result": outer_result,
        "time_boundary": {
            "started_at": args.started_at,
            "ended_at": args.ended_at,
        },
        "cleanup": {
            "status": cleanup_status,
            "install_root_exists": config_home.exists(),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(receipt) + b"\n")
    return receipt


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--artifact", required=True)
    value.add_argument("--artifact-digest", required=True)
    value.add_argument(
        "--platform",
        required=True,
        choices=["codex", "claude-code", "kimi-code", "workbuddy"],
    )
    value.add_argument("--provider", required=True)
    value.add_argument("--provider-version", required=True)
    value.add_argument("--install-authorization", required=True)
    value.add_argument("--method-authorization", required=True)
    value.add_argument("--isolation-root", required=True)
    value.add_argument("--invocation-args-json", required=True)
    value.add_argument("--receipt-output", required=True)
    value.add_argument("--started-at", required=True)
    value.add_argument("--ended-at", required=True)
    value.add_argument("--run-id", required=True)
    return value


def main() -> int:
    binding = None
    try:
        raw_argv = sys.argv[1:]
        binding = consume_quickstart_task(raw_argv)
        receipt = run(parser().parse_args(raw_argv), binding)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 0 if receipt["status"] == "passed" else 1
    except (InstallError, OSError, ValueError, json.JSONDecodeError) as exc:
        import behavior_contracts
        run_id = "run-behavior-install-unknown"
        try:
            task_ref = os.environ.get("SFA_NORMALIZED_TASK_REF", "")
            if task_ref:
                run_id = json.loads(Path(task_ref).read_text()).get("run_id", run_id)
        except Exception:
            pass
        error_obj = behavior_contracts.build_error(
            error_code="BEHAVIOR_INSTALL.INSTALL_FAILED",
            category="EXECUTION_EXCEPTION",
            stage_id="behavior-install",
            message=str(exc),
            affected_resources=[],
            evidence=[],
            retry_possible=False,
            remediation="修正安装参数或环境后重试",
        )
        result_envelope = behavior_contracts.build_result_envelope(
            run_id=run_id,
            stage_id="behavior-install",
            execution_status="BLOCKED",
            summary=f"行为安装失败: {exc}",
            outputs=[],
            domain_results=[],
            evidence=[],
            missing_inputs=[],
            warnings=[],
            errors=[error_obj],
        )
        if binding is not None:
            result_envelope.setdefault("extensions", []).append(binding)
        print(json.dumps(result_envelope, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
