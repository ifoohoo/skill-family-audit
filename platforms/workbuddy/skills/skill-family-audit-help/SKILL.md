---
name: "skill-family-audit-help"
description: 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。
user-invocable: true
internal: false
---
<!-- platform-projection: platform=workbuddy; logical=skill-family-audit:help; source=skills/skill-family-audit/help -->

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
| `release-audit` | 消费 Release Skill 0.3.0 不可变收据链，审计发布资格 | experimental（第一档） |

## 人类入口

| 入口 | 说明 |
|---|---|
| `skill-family-audit:help` | 本入口 — 说明能力与使用方式 |
| `skill-family-audit:setup` | 检查环境并生成精确计划和模拟结果 |
| `skill-family-audit:quickstart` | 将自然语言请求转换为规范化任务并正式运行 |

## 支持矩阵

<!-- BEGIN GENERATED PLATFORM SUPPORT -->
| 平台 | 已测试客户端 | 运行状态 | 当前候选 consumer verification | 阻断项 | 非阻断告警 |
|---|---|---|---|---|---|
| Claude Code | 2.1.220 | `verified_persistent_install_cleanup_advisory` | `not_run_for_current_candidate` | 尚未验证升级与回滚 | 原生卸载允许缓存延迟清理；候选已不可发现和调用，隔离根退出时销毁 |
| Codex | 0.145.0 | `verified_isolated_config_root` | `verified_prior_candidate_only` | 当前修订候选尚未执行 consumer verification；尚未验证升级与回滚 | 无 |
| Kimi Code | 0.31.0 | `verified_persistent_install_cleanup_advisory` | `not_run_for_current_candidate` | 尚未验证升级与回滚 | Kimi Code 0.31.0 原生卸载移除安装记录但保留非活动托管副本；隔离根退出时销毁 |
| WorkBuddy | 5.3.8 | `verified_persistent_install_cleanup_advisory` | `not_run_for_current_candidate` | 尚未验证升级与回滚 | 不把隔离根销毁扩大为宿主原生卸载后的即时物理清理保证 |
<!-- END GENERATED PLATFORM SUPPORT -->

> 唯一平台支持真源为 `spec/platforms/support-matrix.json`。Claude Code、Kimi Code 与 WorkBuddy 已在独立配置根中验证持久安装、发现、调用和功能卸载；即时物理清理保持真实未验证并列为非阻断告警。升级、回滚与当前候选 consumer verification 仍未闭合。

## 依赖

- Python 3.11+
- 候选内 `shared/contracts` 公共合同闭包
- Runtime 需要显式提供 Loop Agent 0.1.x provider 根
- Release 需要显式提供 Release Skill 0.3.0 provider 根
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
2. 确认 Python 3.11+ 可用
3. 运行 `skill-family-audit:setup` 检查环境摘要
4. 运行确定性构建的 `--check`，确认候选包没有手改、缺失或陈旧文件
5. 查看平台探针中“已观察事实”和“仍受阻能力”，不要把候选结构当成客户端支持证明

## 下一步

- 首次使用：运行 `skill-family-audit:setup`
- 已有环境：运行 `skill-family-audit:quickstart` 开始规范检查
- 了解规范：参见 spec/authority-index.json
