---
name: "skill-family-audit-help"
description: 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。
user-invocable: true
internal: false
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:help; source=skills/skill-family-audit/help -->

# skill-family-audit:help

## 目的

向用户说明 skill-family-audit 技能族能做什么、支持哪些平台、依赖什么、怎么用，以及出了问题怎么诊断。这里只做说明，不写入任何文件。

## 能力概述

<!-- BEGIN GENERATED CAPABILITY CATALOG -->
族级能力：`cap:skill-family-audit.family`（技能族审计）。

| 公开方法 | 业务切片 | 成熟度 |
|---|---|---|
| `skill-family-audit:conformance-audit` | 根据版本化正式规则和证据判断技能族规范符合性 | `experimental` |
| `skill-family-audit:release-audit` | 发布治理材料的静态检查：消费调用方记录与既有权威结论逐项判定发布门禁，不判断目标运行是否有效，不代替用户批准发布 | `experimental` |
<!-- END GENERATED CAPABILITY CATALOG -->

## 人类入口

<!-- BEGIN GENERATED ENTRY CATALOG -->
| 入口 | 说明 |
|---|---|
| `skill-family-audit:help` | 说明 skill-family-audit 的能力、适用范围、依赖、支持矩阵、最小示例、诊断和下一步。 |
| `skill-family-audit:setup` | 默认只读诊断环境、规范包和静态平台投影；需要安装或配置时输出精确计划，经用户确认后执行机械步骤并复验。 |
| `skill-family-audit:quickstart` | 把自然语言审计请求路由到两个只读公开方法，并用 Foundation Quickstart Profile 绑定调用方证据与领域结果。 |
<!-- END GENERATED ENTRY CATALOG -->

三个通用入口之外，两个业务方法可以直接调用。按方法 ID `skill-family-audit:conformance-audit` 或 `skill-family-audit:release-audit` 发起，也可以运行候选投影里对应方法的脚本。quickstart 只做分诊、输入绑定和完整档审阅衔接，不是调用前置条件。内部工序不新增公开入口。路径已经写明时，做完整规范检查直接说明目标和意图即可。普通「规范检查」没写完整，也没写精确组时，直接走经济档，不必询问档位、证据 JSON、临时目录或规范包。没有路径时只问项目路径，不要把生成投影或产品子目录列为选项。

候选标记只说明品质和批准状态，不构成调用禁令。真实依赖缺失、输入不合法，或缺少适用的专业结论时，如实报告，并保留失败判定。

## 选择检查范围

`quickstart` 会把用户的请求收成一个明确的执行档位：

| 请求 | 档位 | 含义 |
|---|---|---|
| 普通规范检查 | `economy` | 执行本地预筛，语义模型调用数为 0 |
| 已知语义组、组名称或 canonical rule ID | `targeted` | 只检查所选语义范围，并保留局部结论 |
| 明确只查 Schema、摘要或静态规则 | `mechanical` | 只运行确定性规则 |
| 明确完整审计或准备发布 | `full` | 执行完整符合性审计 |

`PARTIAL` 固定表示选定范围已经完成，但不能证明项目完整符合，也不能单独作为发布资格。Quickstart 返回的 `human_summary` 先展示领域状态，并区分这三种情况：尚未开始检查；已经检查了一部分，但还没有完成；这次选定的范围已经处理完，发现了符合、不符合或缺证。Foundation 外层 `succeeded` 只说明 Task/Result 的传输和交换成功。规则选择前失败时，外层保持失败。`full` 必须走完实际语义审阅和结果消费，不能在预检处结束。通过之后，项目门禁、四宿主资格、release-audit 和发布授权仍要单独完成。

## 支持矩阵

<!-- BEGIN GENERATED PLATFORM SUPPORT -->
| 平台 | 静态投影 | 消费验证 | 说明 |
|---|---|---|---|
| Claude Code | `available` | `manual_unverified` | 安装与调用由消费者按宿主文档人工验证，不阻断候选发布 |
| Codex | `available` | `manual_unverified` | 安装与调用由消费者按宿主文档人工验证，不阻断候选发布 |
| Kimi Code | `available` | `manual_unverified` | 只支持人工安装或会话级 --skills-dir；可选会话 smoke 失败记为 manual_unverified，不阻断候选发布 |
| WorkBuddy | `available` | `manual_unverified` | 安装与调用由消费者按宿主文档人工验证，不阻断候选发布 |
<!-- END GENERATED PLATFORM SUPPORT -->

> 平台支持只以 `spec/platforms/support-matrix.json` 为准。这份矩阵只声明静态投影。安装和调用由消费者按宿主文档人工核对。Kimi 只支持人工安装，或会话级 `--skills-dir`。可选 smoke 不阻断发布。

## 依赖

- Python 3.11+
- 候选内 `foundation/quickstart-profile` 自包含合同与运行时闭包
- Release 需要显式提供 Release Skill 0.9.17 provider 根
- 无需外部网络连接

Audit 不执行、不观察、不恢复、不续接，也不调度受检技能，也不判断失败模式和实际运行效果。运行记录不是必备材料。只有某条规则的证据角色确实要求运行类材料时，才消费它。缺少适用的专业结论时，报告缺项，并指向对应提供方的检查或接入入口。

和提供方的结果不一致时，先核对目标、采用版本、适用范围与双方职责，再按实际原因解释。不默认 Audit 有错，也不改写提供方结论。项目名称、目录与临时托管关系只作个案事实，不构成所有技能族的通用义务。改名或换目录不等于符合规范。受影响的结果仍按实际适用要求审阅。

## 最小示例

下面这些命令由正式入口和方法契约生成，用来查看目录、诊断环境，并启动两个公开方法。

路径已经写明的完整检查，不必先准备证据文件：

```text
/skill-family-audit:quickstart 对 /absolute/path/to/project 做一次完整规范检查
```

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

整改复核必须提供绑定最新材料字节的新 evidence set，并沿用原失败范围的精确 group ID。材料变了就要重新运行。旧结论不能沿用。

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
- 已有环境：运行 `skill-family-audit:quickstart` 开始规范检查，也可以直接调用两个业务方法
- 了解规范：参见 spec/authority-index.json
