---
name: "skill-family-audit-conformance-audit"
description: 根据版本化正式规则和证据判断技能族规范符合性。不执行被测代码。
user-invocable: false
internal: true
method-id: "skill-family-audit:conformance-audit"
---
<!-- platform-projection: platform=workbuddy; logical=skill-family-audit:conformance-audit; source=skills/skill-family-audit-conformance -->

# conformance-audit

## 目的

对目标技能族执行静态规范符合性检查：扫描 SKILL.md、AGENTS.md、脚本、模板和目录结构，逐条检查适用规则，生成结构化任务、逐规则结果、证据清单和中文报告。

不执行被测代码。只检查、报告和生成整改计划，不自动修改目标项目。

## 方法契约

- **method_id**: `skill-family-audit:conformance-audit`
- **capability**: 根据版本化正式规则和证据判断技能族规范符合性
- **composability**: closed_leaf
- **codeExecution**: false
- **sideEffects**: read-only
- **idempotency**: read_only_repeatable

## 输入

| 参数 | 类型 | 说明 |
|---|---|---|
| target_project_path | string | 目标技能族项目绝对路径 |
| spec_version_ref | string | 规范版本引用（可选，默认当前权威索引） |
| scope_selector | string | 检查范围选择器（可选） |
| platform_filter | string | 平台过滤器（可选） |

## 检查规则类别

### 结构规则
- 入口技能存在且格式正确
- 内部技能存在且标记为 internal
- Worker Agent 文件存在且格式正确
- Stage Map 和 Workflow Map 可解析

### 契约规则
- task.schema.json 合规
- result.schema.json 合规
- 资源引用有效
- 程序所有权绑定正确

### 命名规则
- family 名称符合 01-naming.md
- 入口、工序、Worker 短名称一致
- 无冲突或重复身份

### 隐藏规则
- 内部技能不出现在普通用户发现结果中
- 脚本和执行单元不进入方法注册表

## 输出

| 输出 | 说明 |
|---|---|
| conformance_result | 整体通过/失败/部分通过 |
| rule_findings | 逐条规则的检查结果 |
| evidence_list | 证据资源引用列表 |
| remediation_plan | 整改计划（如有） |

## 执行流程

1. 加载权威索引和方法契约
2. 扫描目标项目结构
3. 逐条检查适用规则
4. 生成证据和结果
5. 输出规范化结果和中文报告

## 状态

- **maturity**: experimental
- **status**: candidate（第一档）
- **当前限制**: 只完成正常路径静态检查，行为检查留待第二档
