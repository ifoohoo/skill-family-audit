---
name: "help"
description: 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。
user-invocable: true
internal: false
---
<!-- platform-projection: platform=codex; logical=skill-family-audit:help; source=skills/skill-family-audit/help -->

# skill-family-audit:help

## 目的

向用户说明 skill-family-audit 技能族的能力边界、平台支持、依赖、使用方式和诊断方法。纯说明，不写入任何文件。

## 能力概述

skill-family-audit 提供技能族规范检查能力，包括四个公开业务方法：

| 方法 | 说明 | 成熟度 |
|---|---|---|
| `conformance-audit` | 规范符合性检查：静态规则扫描、清单校验、模板合规 | experimental（第一档） |
| `behavior-audit` | 执行调用方显式提供的内容绑定夹具，并审计结果与副作用 | experimental（第一档） |
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
| 平台 | 静态投影 | 消费验证 | 说明 |
|---|---|---|---|
| Claude Code | `available` | `manual_unverified` | 安装与调用由消费者按宿主文档人工验证，不阻断候选发布 |
| Codex | `available` | `manual_unverified` | 安装与调用由消费者按宿主文档人工验证，不阻断候选发布 |
| Kimi Code | `available` | `manual_unverified` | 只支持人工安装或会话级 --skills-dir；可选会话 smoke 失败记为 manual_unverified，不阻断候选发布 |
| WorkBuddy | `available` | `manual_unverified` | 安装与调用由消费者按宿主文档人工验证，不阻断候选发布 |
<!-- END GENERATED PLATFORM SUPPORT -->

> 唯一平台支持真源为 `spec/platforms/support-matrix.json`。该矩阵只声明静态投影；安装与调用由消费者按宿主文档人工验证。Kimi 只支持人工安装或会话级 `--skills-dir`，可选 smoke 不阻断发布。

## 依赖

- Python 3.11+
- 候选内 `foundation/quickstart-profile` 自包含合同与运行时闭包
- Runtime 需要显式提供 Loop Agent 0.1.x provider 根
- Release 需要显式提供 Release Skill 0.3.0 provider 根
- 无需外部网络连接
- Behavior 只执行调用方显式提供的命令或夹具，不安装插件

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
5. 把静态投影与宿主实机支持分开判断；未人工验证时保持 `manual_unverified`

## 下一步

- 首次使用：运行 `skill-family-audit:setup`
- 已有环境：运行 `skill-family-audit:quickstart` 开始规范检查
- 了解规范：参见 spec/authority-index.json
