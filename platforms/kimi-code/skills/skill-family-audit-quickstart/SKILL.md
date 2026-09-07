---
name: "skill-family-audit-quickstart"
description: 把自然语言审计请求路由到两个只读公开方法，并用 Foundation Quickstart Profile 绑定调用方证据与领域结果。
user-invocable: true
internal: false
argument-hint: "<自然语言请求，如：对 /path/to/project 进行规范检查>"
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:quickstart; source=skills/skill-family-audit/quickstart -->

# skill-family-audit:quickstart

## 目的

将用户的自然语言请求路由到 `skill-family-audit:conformance-audit` 或
`skill-family-audit:release-audit`。Foundation 创建并校验 Task/Result，Audit 领域方法只读消费调用方证据，结果直接返回宿主或 stdout，不创建结果目录。

规范检查由 Quickstart 显式选择执行档位。普通请求使用 `economy`，语义模型调用数为 0；已知语义组、组名称或 canonical rule ID 使用 `targeted`；明确只查确定性规则使用 `mechanical`；明确完整审计或准备发布才使用 `full`。底层方法省略档位时仍兼容为 `full`，该兼容规则不适用于人类入口。

## 输入

- 自然语言请求，包含检查意图。
- 规范检查必须提供证据集合 JSON 文件。该文件只含 `evidence_set` 数组，各证据项绑定绝对规范路径与 SHA-256。
- 发布检查必须提供 assessments 文件、Release Skill plan/run 收据、发布单元和目标版本。

## 路由规则

| 用户意图 | 路由目标 | 前置条件 |
|---|---|---|
| "规范检查" / "规范符合" / "conformance" | `skill-family-audit:conformance-audit` | 必须提供证据集合文件；单项证据不足只影响对应规则，不拒绝整个审阅请求 |
| "发布审计" / "release" | `skill-family-audit:release-audit` | 必须提供 assessments、Release Skill 0.3.0 provider 根、不可变 plan/run 收据、目标单元和版本 |

## 行为

1. **解析请求**：识别检查意图、执行档位和精确选择器。无法解析的组或规则在创建 Task 前拒绝，不猜测范围。
2. **绑定证据**：调用 Foundation runner，把证据集合文件或 assessments 文件绑定为 Task Resource。
3. **路由审阅**：规范检查显式传 `--execution-profile`；`targeted` 再传排序去重后的 `--semantic-group-id`。一次运行不会自动启动推荐的下一档。
4. **返回结果**：由同一 Foundation runner 包装并校验领域 Result，再通过 stdout 或宿主结果返回。

`human_summary` 按固定顺序说明本次运行、领域结论、覆盖范围、语义成本、主要问题和唯一主动作。Foundation 外层 `succeeded` 只表示 Task/Result 传输与交换成功；审计结论以 `domainResult` 中的领域状态为准。`PARTIAL` 固定表示选定范围已完成，不能证明项目完整符合，也不能单独作为发布资格。

## 最小示例

普通检查显式选择 `economy`，不调用语义模型：

```text
/skill-family-audit:quickstart 使用 /absolute/path/evidence-set.json 对项目进行规范检查
```

已知语义范围时，在请求中写精确组 ID、组名称或 canonical rule ID；Quickstart 会解析成 `targeted`：

```text
/skill-family-audit:quickstart 使用 /absolute/path/evidence-set.json 检查 group-id-or-canonical-rule-id
```

复核整改时，重新生成绑定最新材料字节的新 evidence set，并沿用原失败范围的精确 group ID：

```text
/skill-family-audit:quickstart 使用 /absolute/path/new-evidence-set.json 复核整改 group-id
```

以上命令会创建绑定新目标与证据摘要的运行。材料字节变化后，旧结论不能沿用。

准备发布时，先完成正式生成并冻结候选字节，再明确要求完整规范审计：

```text
/skill-family-audit:quickstart 对冻结候选准备发布并进行完整规范审计
```

## 宿主内消费审阅结果

用户认可的审阅来源已经回读实际任务、材料和逐条理由后，宿主可以复用已存在的 Python 函数组合一次内部消费。执行前确认用户认可任务与范围、审阅者不是原实现者、原始记录可回读，且争议交人工裁决。该路径不新增 runner 或认证标记，也不把调用方参数当作来源证明。

具体函数顺序、同一 Task 摘要的来源、结果 Schema 校验和 Result 交换见同一平台包中的逻辑 Skill `skill-family-audit:conformance-audit` 的“宿主程序内消费已接受的审阅结果”。宿主必须忠实消费该次原始审阅记录；缺少理由或证据时保持 `EVIDENCE_MISSING`，不能为绑定成功重填摘要或形成语义 `PASS`。

`quickstart_route.run` 的普通 CLI 路径仍只接受外部 v1 待审证据；`--semantic-review-stdin` 会拒绝，即使输入自称 `PASS` 且摘要字段齐全。认可来源的真实性、审阅职责分离和接受范围由宿主主审负责，程序内函数只校验内容绑定。正式测试可用明确标记的规范夹具验证这条传输路径，但不能把夹具结果写成生产语义通过记录。

## 选择等待

无法形成合法的只读任务时不得启动领域方法。证据无法证明某条规则时，该规则返回 `EVIDENCE_MISSING` 或 `REVIEW_REQUIRED`；不得合成 `PASS`。

## 边界

本地候选接线成功不等于正式兼容资格。正式资格以候选内 Foundation pin/projection、上游 capability catalog 和发布门禁当前机器状态为准。

- 只能路由到两个已注册的公开方法
- 语义路由工序没有业务写权限
- 不直接执行具体检查逻辑
- 不实现第二套 Task/Result/Resource、摘要算法或运行状态机
- 不执行、观察、恢复、续接或调度受检技能
- 只有与当前候选身份一致的治理状态才能进入方法执行；待批候选不得复用旧批准
- 缺少发布权威收据时返回 `BLOCKED`；规范证据不足时保留逐规则未获证状态
