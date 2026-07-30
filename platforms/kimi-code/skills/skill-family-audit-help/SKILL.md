---
name: "skill-family-audit-help"
description: 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。
user-invocable: true
internal: false
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:help; source=skills/skill-family-audit/help -->

# skill-family-audit:help

生命周期探针标记：`SFA_HELP_CANDIDATE_V1`。该固定标记仅用于隔离客户端证明本技能正文已被实际加载，不表示平台生命周期已经通过。

## 目的

向用户说明 skill-family-audit 技能族的能力边界、平台支持、依赖、使用方式和诊断方法。纯说明，不写入任何文件。

## 能力概述

skill-family-audit 提供技能族规范检查能力，包括四个公开业务方法：

| 方法 | 说明 | 成熟度 |
|---|---|---|
| `conformance-audit` | 规范符合性检查：静态规则扫描、清单校验、模板合规 | experimental（第一档） |
| `behavior-audit` | 验证外部隔离证明与授权后执行内容绑定夹具，并审计副作用 | experimental（第一档） |
| `runtime-audit` | 消费 Loop Agent 权威运行证据，验证身份、事件链与成熟度 | experimental（第一档） |
| `release-audit` | 消费 Release Skill 0.2.7 不可变收据链，审计发布资格 | experimental（第一档） |

## 人类入口

| 入口 | 说明 |
|---|---|
| `skill-family-audit:help` | 本入口 — 说明能力与使用方式 |
| `skill-family-audit:setup` | 检查环境并生成精确计划和模拟结果 |
| `skill-family-audit:quickstart` | 将自然语言请求转换为规范化任务并正式运行 |

## 支持矩阵

| 平台 | 操作系统 | 处理器 | 运行时 | 状态 |
|---|---|---|---|---|
| Claude Code 2.1.206 | 本机候选 | 会话级 `--plugin-dir` | 已验证发现、`help`/`setup` 最小调用和会话结束后的功能卸载；持久生命周期仍受阻 |
| Codex | 本机候选 | `.codex-plugin/plugin.json` + 独立 `CODEX_HOME` | 已验证本地 marketplace 安装、发现、最小调用、卸载和清理；升级与回滚未验证 |
| Kimi Code 0.27.0 | 本机候选 | 显式 `--skills-dir` | 已验证 `help`/`quickstart` 内联加载、最小调用和移除参数后的功能卸载；无持久插件安装接口 |
| WorkBuddy 5.3.5 / CodeBuddy CLI 2.115.0 | 本机候选 | `.codebuddy-plugin/plugin.json` + 会话级 `--plugin-dir` | 已验证 `help`/`quickstart` 发现、调用和功能卸载；marketplace 持久生命周期未验证 |

> Claude Code 与 WorkBuddy 的“功能卸载”表示移除 `--plugin-dir` 后的新会话不再发现候选，不表示 marketplace 删除或物理清理。Kimi Code 的结论同样只覆盖显式技能目录。Codex 仅在独立 `CODEX_HOME` 中变更，源认证与用户配置保持不变。

## 依赖

- Python 3.10+
- 候选内 `shared/contracts` 公共合同闭包
- Runtime 需要显式提供 Loop Agent 0.1.x provider 根
- Release 需要显式提供 Release Skill 0.2.7 provider 根
- 无需外部网络连接
- 只有 Behavior 会在调用方已证明的隔离环境中执行内容绑定夹具

## 最小示例

```
# 查看帮助
/skill-family-audit:help

# 检查环境
/skill-family-audit:setup

# 运行规范检查
/skill-family-audit:quickstart 对 /path/to/project 进行规范检查
```

## 诊断

如果出现问题：

1. 确认 spec/ 目录存在且 authority-index.json 可解析
2. 确认 Python 3.10+ 可用
3. 运行 `skill-family-audit:setup` 检查环境摘要
4. 运行确定性构建的 `--check`，确认候选包没有手改、缺失或陈旧文件
5. 查看平台探针中“已观察事实”和“仍受阻能力”，不要把候选结构当成客户端支持证明

## 下一步

- 首次使用：运行 `skill-family-audit:setup`
- 已有环境：运行 `skill-family-audit:quickstart` 开始规范检查
- 了解规范：参见 spec/authority-index.json
