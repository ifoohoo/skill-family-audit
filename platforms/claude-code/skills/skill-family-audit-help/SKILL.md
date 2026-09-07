---
name: "skill-family-audit-help"
description: 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。
user-invocable: true
internal: false
---
<!-- platform-projection: platform=claude-code; logical=skill-family-audit:help; source=skills/skill-family-audit/help -->

# skill-family-audit:help

## 目的

向用户说明 skill-family-audit 技能族的能力边界、平台支持、依赖、使用方式和诊断方法。纯说明，不写入任何文件。

## 能力概述

<!-- BEGIN GENERATED CAPABILITY CATALOG -->
族级能力：`cap:skill-family-audit.family`（技能族审计）。

| 公开方法 | 业务切片 | 成熟度 |
|---|---|---|
| `skill-family-audit:conformance-audit` | 根据版本化正式规则和证据判断技能族规范符合性 | `experimental` |
| `skill-family-audit:release-audit` | 判断技能族版本是否满足稳定发布的全部门禁条件 | `experimental` |
<!-- END GENERATED CAPABILITY CATALOG -->

## 人类入口

<!-- BEGIN GENERATED ENTRY CATALOG -->
| 入口 | 说明 |
|---|---|
| `skill-family-audit:help` | 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。 |
| `skill-family-audit:setup` | 默认只读诊断环境、规范包和静态平台投影；需要安装或配置时输出精确计划，经用户确认后执行机械步骤并复验。 |
| `skill-family-audit:quickstart` | 把自然语言审计请求路由到两个只读公开方法，并用 Foundation Quickstart Profile 绑定调用方证据与领域结果。 |
<!-- END GENERATED ENTRY CATALOG -->

## 选择检查范围

`quickstart` 会把人类请求转换成一个明确的执行档位：

| 请求 | 档位 | 含义 |
|---|---|---|
| 普通规范检查 | `economy` | 执行本地预筛，语义模型调用数为 0 |
| 已知语义组、组名称或 canonical rule ID | `targeted` | 只检查所选语义范围，并保留局部结论 |
| 明确只查 Schema、摘要或静态规则 | `mechanical` | 只运行确定性规则 |
| 明确完整审计或准备发布 | `full` | 执行完整符合性审计 |

`PARTIAL` 表示选定范围已经完成，不表示项目完整符合。Quickstart 返回的 `human_summary` 先展示领域状态；Foundation 外层 `succeeded` 仅说明 Task/Result 传输与交换成功。`full` 通过后，仍需独立完成项目门禁、四宿主资格、release-audit 和发布授权。

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
- Release 需要显式提供 Release Skill 0.3.0 provider 根
- 无需外部网络连接

Audit 不执行、观察、恢复、续接或调度受检技能。行为与运行材料必须由调用方先行产生，再作为 `conformance-audit` 的证据输入。

## 最小示例

下列命令由正式入口和方法契约生成，可用于查看目录、诊断环境并启动两个公开方法：

<!-- BEGIN GENERATED MINIMAL EXAMPLES -->
```text
# 查看能力和入口目录
/skill-family-audit:help

# 运行只读环境诊断
/skill-family-audit:setup

# 规范符合性检查
/skill-family-audit:quickstart 使用 /absolute/path/evidence-set.json 执行 skill-family-audit:conformance-audit

# 发布门禁检查
/skill-family-audit:quickstart 使用 /absolute/path/release-audit-input.json 执行 skill-family-audit:release-audit
```
<!-- END GENERATED MINIMAL EXAMPLES -->

整改复核必须提供绑定最新材料字节的新 evidence set，并沿用原失败范围的精确 group ID。材料变化后重新运行；旧结论不能沿用。

本地候选接线成功不等于正式兼容资格。正式资格以候选内 Foundation pin/projection、上游 capability catalog 和发布门禁当前机器状态为准。

## 诊断

如果出现问题：

1. 确认 `spec/` 目录存在且 `authority-index.json` 可解析
2. 确认 Python 3.11+ 可用
3. 运行 `skill-family-audit:setup` 检查环境摘要
4. 运行确定性构建的 `--check`，确认候选包没有手改、缺失或陈旧文件
5. 把静态投影与宿主实机支持分开判断；未人工验证时保持 `manual_unverified`

## 下一步

- 首次使用：运行 `skill-family-audit:setup`
- 已有环境：运行 `skill-family-audit:quickstart` 开始规范检查
- 了解规范：参见 spec/authority-index.json
