---
name: "conformance-audit"
description: 根据版本化正式规则和证据判断技能族规范符合性。不执行被测代码。
user-invocable: false
internal: true
method-id: "skill-family-audit:conformance-audit"
---
<!-- platform-projection: platform=claude-code; logical=skill-family-audit:conformance-audit; source=skills/skill-family-audit-conformance -->

# conformance-audit

## 目的

对单个技能、插件源码、实际发行包或目标项目执行规范符合性检查。先按受检对象运行确定性检查；只有活动规则明确要求语义判断时，才消费与当前目标和规则集合绑定的结构化结果。

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
| `--target` | path | 受检对象路径 |
| `--target-type` | enum | `single_skill`、`family_source`、`release_artifact` 或 `project_adoption` |
| `--spec-package` | path | 受信任规范包；测试夹具必须显式使用 `--allow-test-fixture` |
| `--platform` | enum | 规则适用平台，默认 `all` |
| `--semantic-result` | path | 仅在适用语义规则存在时提供隔离 Worker Result |
| `--output-dir` / `--run-id` | path/string | 唯一允许写入的输出目录和本次运行身份 |

## 受检对象

- `single_skill`：绑定单个 `SKILL.md` 字节并检查技能范围规则。
- `family_source`：绑定完整源码树；当目标包含私有 workspace 合同时，强制消费进程外 verifier 的真实收据，不从目标加载或执行 verifier。
- `release_artifact`：验证候选身份、payload 摘要以及公开 JSON 引用闭包。
- `project_adoption`：验证采用锁、安装根、平台清单、版本和安装内容摘要。

## 规则与信任

- 候选内信任策略只绑定 761 条规则投影。
- 每条权威规则保留原始身份、修订、effect、采用状态和适用范围；`candidate_undetermined` 只进入适用性报告，不自动成为阻断规则。
- 实现基线规则与权威 761 条规则分开标识，不冒充已批准业务规则。
- 语义结果必须通过 Schema，并绑定规则修订、目标内容摘要和范围内现存 evidence。

## 输出

| 输出 | 说明 |
|---|---|
| conformance_result | 整体通过/失败/部分通过 |
| rule_findings | 逐条规则的检查结果 |
| evidence_list | 证据资源引用列表 |
| remediation_plan | 整改计划（如有） |

## 执行流程

1. 校验规范包及候选内冻结信任根。
2. 按受检对象适配器闭合目标范围和内容摘要。
3. 对 workspace 目标校验进程外 verifier 原始收据、verifier 字节、实际 argv、公开清单和输入树摘要。
4. 计算 761 条规则的逐条适用性，只执行已生效且适用的规则。
5. 运行确定性检查并按需合并隔离语义 Result。
6. 输出逐规则结果、领域证据和标记为 `unapplied` 的整改计划；Task/Result 由 Foundation 包装。

## 状态

- **maturity**: experimental
- **status**: candidate
- **当前限制**: 当前冻结规范权威尚未批准生产采用，761 条规则均保持 `candidate_undetermined`；因此生产调用必须诚实 `BLOCKED`，测试夹具结果不得用于发布资格。
