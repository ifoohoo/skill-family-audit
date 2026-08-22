---
name: "skill-family-audit-conformance-audit"
description: 根据版本化正式规则和证据判断技能族规范符合性。不执行被测代码。
user-invocable: false
internal: true
method-id: "skill-family-audit:conformance-audit"
---
<!-- platform-projection: platform=codex; logical=skill-family-audit:conformance-audit; source=skills/skill-family-audit-conformance -->

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
- `project_adoption`：以项目根 `profile.json`（Foundation 项目 Profile）为唯一采用证明。通过平台包自带的离线 Profile SPI 运行闭包，在受控 Node 22 进程中调用 Foundation Engineering Kit 0.8.1 公开入口 `verifyProjectProfile()`：项目 Profile 合同外壳、`adoption.foundation_pin` 逐包真实文件摘要比对（GK-4）、仅加严 override 政策；Audit 另行核对采用的 Foundation profile/包版本与自身冻结基线一致。profile 缺失、符号链接、pin 摘要不匹配、任何非 `SPE0000` 结果或运行时不可用一律失败关闭。旧采用锁合同已按 D-8（2026-08-18）废弃，其全部现役消费与产出路径已随 D3 移除；对应历史 Schema 文件仅作为只读历史记录保留。

## 规则与信任

- 候选内信任策略只绑定 814 条规则投影。
- 每条权威规则保留原始身份、修订、effect、采用状态和适用范围；`candidate_undetermined` 只进入适用性报告，不自动成为阻断规则。
- 实现基线规则与权威 814 条规则分开标识，不冒充已批准业务规则。
- `project_adoption` 只有在可执行权威规则集合非空且已完整覆盖时才能成功。集合为空或覆盖不完整时，顶层返回 `FAILED`，实现基线标记为 `NON_PASSING`，命令退出码非零。
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
4. 计算 814 条规则的逐条适用性，只执行已生效且适用的规则。
5. 运行确定性检查并按需合并隔离语义 Result。
6. 输出逐规则结果、领域证据和标记为 `unapplied` 的整改计划；Task/Result 由 Foundation 包装。

## 状态

- **maturity**: experimental
- **status**: candidate
- **当前限制**: 当前冻结规范权威尚未批准生产采用；814 条投影规则中 761 条权威类别仍为 `candidate_undetermined`，53 条第 26 批归并的闭包后 intake 条文治理轴待裁决；因此生产调用必须诚实 `BLOCKED`，测试夹具结果不得用于发布资格。

## Foundation 采用边界

- `project_adoption` 是 Audit 拥有的领域合同；Foundation 迁移清单结构、路径收容、整文件退出和引用级退出评估仍由 Foundation 拥有。
- Audit 只调用受管 Foundation Bundle 内的固定 CLI：通用机制由 `mechanisms-cli.mjs` 提供，采用检查和 Quickstart 交换由 `adoption-cli.mjs` 提供。Bundle 位置由已校验的 receipt 和 runner 绑定；用户不得改用 sibling import、临时环境变量或 fallback 入口。
- Foundation 迁移语义由进程外 Foundation 权威入口提供，Audit 不复制 migration manifest Schema 或评估函数。
- 本范围审计的是公共 Harness 生产权威切换，不是整个工程骨架采用。
