---
name: "skill-family-audit-quickstart"
description: 把自然语言审计请求路由到四个公开方法，并用 Foundation Quickstart profile 绑定同一个 PluginProjectObservation 和领域结果。
user-invocable: true
internal: false
argument-hint: "<自然语言请求，如：对 /path/to/project 进行规范检查>"
---
<!-- platform-projection: platform=codex; logical=skill-family-audit:quickstart; source=skills/skill-family-audit/quickstart -->

# skill-family-audit:quickstart

## 目的

将用户的自然语言请求路由到正确的公开业务方法（`skill-family-audit:conformance-audit` /
`skill-family-audit:behavior-audit` / `skill-family-audit:runtime-audit` /
`skill-family-audit:release-audit`），由 Foundation 创建和校验 operation request/result，执行 Audit 领域方法并返回结构化领域结果。

## 输入

- 自然语言请求，包含：
  - 目标路径或项目
  - 检查意图（规范检查、行为验证等）

## 路由规则

| 用户意图 | 路由目标 | 前置条件 |
|---|---|---|
| "规范检查" / "规范符合" / "conformance" | `skill-family-audit:conformance-audit` | 生效规范发布、方法解析收据和输入摘要均有效；缺一即阻断 |
| "行为验证" / "行为检查" / "behavior" | `skill-family-audit:behavior-audit` | 必须提供内容绑定夹具、外部隔离证明、执行授权、精确选择器和独占输出目录 |
| "运行时审计" / "runtime" | `skill-family-audit:runtime-audit` | 必须提供 Loop Agent 0.1.x provider 根、权威证据包、成熟度等级和独占输出目录 |
| "发布审计" / "release" | `skill-family-audit:release-audit` | 必须提供 Release Skill 0.3.0 provider 根、不可变 plan/run 收据、目标单元和版本 |

## 行为

1. **解析请求**：识别目标路径、检查意图和平台
2. **创建交换**：调用 Foundation runner 创建 Task 与单一 observation Resource
3. **路由执行**：将任务委派到对应内部能力
4. **记录决策**：记录原始请求、补全逻辑和用户选择
5. **返回结果**：由同一 Foundation runner 包装并校验领域 Result

## 选择等待

当候选会改变以下内容时，必须等待用户选择：
- 检查结果
- 执行成本
- 权限范围
- 副作用

无法形成合法任务时不得启动内部能力。

## 边界

- 不能把四个方法合并为一个过宽权限方法
- 语义路由工序没有业务写权限
- 只能路由到四个已注册的公开方法
- 不直接执行具体检查逻辑
- 不实现第二套 Task/Result/Resource、摘要算法或运行状态机
- 只有与当前候选身份一致的治理状态才能进入方法执行；待批候选不得复用旧批准
- 缺少外部证据、隔离证明或权威收据时必须返回 `BLOCKED`，不能合成成功证据
