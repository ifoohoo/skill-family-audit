---
name: "setup"
description: 检查环境并生成精确计划和模拟结果。安装依赖、写配置、改钩子或写采用锁需要单独授权。
user-invocable: true
internal: false
argument-hint: "[额外检查选项]"
---
<!-- platform-projection: platform=claude-code; logical=skill-family-audit:setup; source=skills/skill-family-audit/setup -->

# skill-family-audit:setup

生命周期探针标记：`SFA_SETUP_DRY_RUN_V1`。该固定标记仅用于隔离客户端证明本技能正文已被实际加载，不授权写入或安装。

## 目的

检查运行环境、规范包完整性和平台支持状态，生成精确环境摘要和模拟安装结果。默认只检查和计划，不执行写入操作。

## 输入

- 可选：额外检查选项（如 `--verbose`、`--platform <id>`）

## 行为

1. **环境检查**：验证 Python 版本、spec/ 目录完整性、authority-index.json 可解析性
2. **规范状态**：检查规范发布状态、方法注册表、平台能力档案
3. **平台探测**：只读检查当前平台的客户端版本和已暴露命令，并回读独立生命周期收据；只采信客户端初始化清单、技能工具结果和前后状态链，不采信模型自述替代证据
4. **模拟结果**：生成安装计划摘要（不实际安装）
5. **输出摘要**：以结构化 JSON 格式输出环境摘要

## 写入边界

- 默认只读检查，不写入任何文件
- 安装依赖、写配置、改钩子或写采用锁需要单独授权
- 授权请求会在摘要中明确列出所需操作

## 输出

<!-- BEGIN GENERATED PLATFORM SUPPORT -->
平台状态只从 `spec/platforms/support-matrix.json` 读取：

```json
{
  "claude-code": "verified_persistent_install_cleanup_advisory",
  "codex": "verified_isolated_config_root",
  "kimi-code": "verified_persistent_install_cleanup_advisory",
  "workbuddy": "verified_persistent_install_cleanup_advisory"
}
```
<!-- END GENERATED PLATFORM SUPPORT -->

```json
{
  "environment": {
    "python_version": "3.x.y",
    "spec_directory": true,
    "authority_index": true,
    "approval_status": "no_active_approval_receipt"
  },
  "platforms": [
    {
      "platform_id": "claude-code",
      "client_detected": false,
      "status": "blocked_candidate",
      "observed_capabilities": [],
      "unverified_capabilities": ["install", "discover", "invoke", "uninstall"]
    }
  ],
  "actions_required": [],
  "warnings": []
}
```

## 边界

- 不修改目标项目
- 不自动安装依赖
- 不形成稳定发布事实
- 规范批准前只报告候选状态
- Claude Code 2.1.220 只可报告独立 `CLAUDE_CONFIG_DIR` 中已验证的持久安装、发现、调用和功能卸载；即时缓存清理、升级与回滚仍受阻
- Kimi Code 0.31.0 只可报告原生 `/plugins` 已验证的持久安装、发现、调用和功能卸载；托管副本清理、升级与回滚仍受阻；`--skills-dir` 仍是独立会话级能力层
- WorkBuddy 5.3.8 只可报告独立配置根中已验证的持久安装、发现、调用和功能卸载；即时物理清理、升级与回滚仍受阻
- Codex 只可在独立 `CODEX_HOME` 中执行 marketplace/add/remove 变更，并使用隔离认证副本而不是源认证文件链接
