---
name: "skill-family-audit-release-audit"
description: 审计技能族发布门禁、摘要链和稳定发布条件。只消费已有权威证据。
user-invocable: true
internal: false
method-id: "skill-family-audit:release-audit"
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:release-audit; source=skills/skill-family-audit-release -->

# release-audit

## 目的

审计技能族的发布门禁、摘要链和稳定发布条件。只消费已有权威证据，不补造证据，也不复制外部发布工具的计划、批准、发布或协调状态机。

这是对发布治理材料做纯静态检查。它消费调用方提供的评估记录和既有权威结论，并可单向投影为 `professional-conclusion` 供下游发布方只读消费。不判断目标运行是否有效，也不代替用户批准发布。

方法只返回 `release_result`、`gate_findings`、`evidence_list` 和 `blocking_reasons`。公共 Task/Result 和证据 Resource 的绑定，由 Foundation Quickstart Profile 提供。领域结果通过 stdout 或宿主 Result 返回。

## 方法契约

- **method_id**: `skill-family-audit:release-audit`
- **capability**: 审计发布门禁和稳定发布条件
- **composability**: closed_leaf
- **codeExecution**: true
- **sideEffects**: read-only（`processExecution: "none"`）
- **重复调用**: 只读静态检查，不创建结果目录。同一冻结输入再次调用不增加写入，不改变受检目标

## 当前状态

- **maturity**: experimental
- **status**: candidate
- **单向解耦边界**: Audit 仅做纯静态评估汇总并单向签发 `professional-conclusion`，不启动任何外部发布 CLI 子进程，消除双向依赖环路。

## 运行接口

运行接口为 `--release-audit-input`（可选附加 `--conclusion-output` 在受审目录外独占写出共同证明）：

```text
python3 scripts/release_audit.py --release-audit-input <冻结的 release-audit-input JSON> [--conclusion-output <外部共同证明绝对路径>]
```

输入文档携带候选身份（unit id 与 target version）、发布评估引用（`assessments_ref`）及可选的显式静态记录绑定（`records`）。当四类发布评估与显式静态记录摘要一致时，检查通过（退出码 0）；缺项或受阻时返回 `BLOCKED`（退出码 1）；记录损坏或矛盾时返回 `FAILED`（退出码 2）。

## 人类呈现

向用户说明这次发布审计时，只按本次实际返回来讲结论、依据、限制和下一步。结论来自 `release_result`。依据是 `gate_findings`、`evidence_list` 和 `blocking_reasons` 里的实际记录。这是静态记录检查，不推断目标已经发布，也不推断已经获得发布批准。没有对应记录时，不补空栏目。机器返回和只读边界保持原样，不另写报告文件。

## 边界

- 只消费已有权威证据
- 不补造证据
- `processExecution` 固定为 `none`，不启动外部发布 CLI 子进程
- 只读取调用方显式指定的评估与静态记录路径，不扫描受检目录，不跟随记录内未声明路径
- 发布评估只接受 `conformance`、`platforms`、`exceptions` 和 `release_policy` 四类输入
- `platforms` 消费目标技能族的原始平台清单，只核对对象、版本、平台身份、文件路径和摘要，以及外层候选、类型和身份绑定。宿主别名按 Foundation 已发布公开身份处理，不要求其他产品填写 Audit 专有的 `files`、`fileCount`、`sourceDigest`、`projectionDigest` 或 `foundationProjection` 字段
- 平台行的 `valid` 仅表示静态身份与记录绑定有效，不代表专业闭包通过。专业结论和覆盖范围沿原 conformance 链通过 `conformance_result.professional_consumption` 如实承载，本方法不据裸平台清单推断或重算闭包，不新增通用适用性判断或强制扫描
- `valid` 表示输入记录有效、可供本方法消费，不表示原领域结论全部通过。Foundation Result 的 `state=succeeded` 说明传输完成；原 `conformance_result.status`、专业结论和覆盖范围仍按原记录解释。专业输入按原合同可选，本方法不强制要求领域状态为 `SUCCEEDED` 或 Foundation 项存在且为 `pass`，也不改写原失败、受阻或特殊处理结论。稳定发布保留原有的各输入记录状态均为 `valid` 条件，不将它解释为所有原领域结论全部通过
- `exceptions` 消费 Audit 自带的 `spec/policies/exception-policy.json` 通用例外政策，证据类型为 `exception-policy`，身份为 `skill-family-audit:exception-policy`。政策必须包含实际记录约定、约束条件和 `currentExceptions` 数组；仅含 `status` 的薄文件不通过
- 通用例外政策不认证发布目标的例外声明。`currentExceptions` 是 Audit 当前产品实例的唯一真源；本仓 `rule-exception-declaration` 的 `scope=skill-family-audit-current-product` 不随外层 `candidate_id` 改绑成其他目标无例外的事实
- 特殊处理记录须对应当前对象、规则、范围和处理事项；不因缺少批准人、统一期限或作者不同而拒绝。若记录自身约定的期限或条件已失效，或与当前对象事项不符，不得视为有效特殊处理，须按当前事实重新检查原要求
- 缺项（结论不可用）结果在既有 `reason` 中说明适用的检查或接入入口。conformance 指向 `skill-family-audit:conformance-audit`，平台缺项时要求提供目标当前候选的原始清单与绑定；若原 conformance 结论报告适用专业项缺证，可接续 `foundation-adoption-review:foundation-engineering-check` 取得或读取已有证明，再由 `skill-family-audit:conformance-audit` 消费新的结论。例外政策缺项时指向 `spec/policies/exception-policy.json`，要求提供真实政策及摘要、类型和候选绑定；没有公开专业入口时，如实说明能力缺口，不静默重做专业工作，不要求 failure-auditor 报告
- 失败模式和运行效果报告不属于发布评估所需输入
- 和提供方的结果不一致时，先核对目标、采用版本、适用范围与双方职责，按实际原因解释。不默认 Audit 有错，不改写提供方结论，不新建冲突裁决机制
- 项目名称、目录与临时托管只作个案事实，不提升为通用义务。改名或换目录不等于符合要求
- 对 conformance 结果只做内容级一致性校验，不重跑审计
- 不复制外部发布工具的计划、批准、发布或协调状态机
- 不判断受检目标的运行有效性；运行效果不属于本方法结论
- 不把候选治理批准解释为正式发布批准
- 不创建结果目录，不调用 Audit 自有发布桥
