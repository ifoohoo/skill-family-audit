---
name: "skill-family-audit-release-audit"
description: 审计技能族发布门禁、摘要链和稳定发布条件。只消费已有权威证据。
user-invocable: true
internal: false
method-id: "skill-family-audit:release-audit"
---
<!-- platform-projection: platform=workbuddy; logical=skill-family-audit:release-audit; source=skills/skill-family-audit-release -->

# release-audit

## 目的

审计技能族的发布门禁、摘要链和稳定发布条件。只消费已有权威证据，不补造证据，也不复制 Release Skill 的计划、批准、发布或协调状态机。

这是对发布治理材料做静态检查。它消费调用方提供的记录和既有权威结论。不判断目标运行是否有效，也不代替用户批准发布。

方法只返回 `release_result`、`gate_findings`、`evidence_list` 和 `blocking_reasons`。公共 Task/Result 和证据 Resource 的绑定，由 Foundation Quickstart Profile 提供。领域结果通过 stdout 或宿主 Result 返回。

## 方法契约

- **method_id**: `skill-family-audit:release-audit`
- **capability**: 审计发布门禁和稳定发布条件
- **composability**: closed_leaf
- **codeExecution**: true
- **sideEffects**: read-only
- **重复调用**: 只读静态检查，不创建结果目录。同一冻结输入再次调用不增加写入，不改变受检目标

## 当前状态

- **maturity**: experimental
- **status**: candidate
- **上游边界**: 直接调用 Release Skill 0.9.17 的公共 `verify-records` 命令。Audit 在执行前后核对 CLI 和自包含 bundle 的精确公开字节，再核对原始记录摘要、stdout、退出码、候选身份和上游输出摘要。不复制计划、批准、摘要、lineage 或状态转换算法。

## 运行接口

唯一运行接口是 `--release-audit-input`：

```text
python3 scripts/release_audit.py --release-audit-input <冻结的 release-audit-input JSON>
```

输入文档携带候选身份（unit id 与 target version）、发布评估引用、Release Skill CLI 绝对路径，以及显式的 plan、approval、target run 和 source runs 绝对路径。Audit 通过既有 Foundation host 取得受管 Node 22 运行时，不接受调用方指定解释器，也不通过 `PATH` 查找可执行文件。它同样不接受调用方内嵌的验证器 JSON 作为成功依据。

固定命令返回 `CONSISTENT` 时，本次静态记录检查通过（Audit 退出码 0）。返回 `INSUFFICIENT` 时阻塞（Audit 退出码 1）。出现 `CONTRADICTED`、字节锁不符、输出形状非法、候选或退出码不一致时，检查失败（Audit 退出码 2）。括号里是 Audit 自己的退出码。上游固定命令的期望退出码另计：`CONSISTENT` 是 0，`CONTRADICTED` 是 1，`INSUFFICIENT` 是 2。这组数字只用来核对固定命令的退出码和它返回的状态是否一致。

通过只表示这组记录在静态上一致，不表示目标运行已经发布或已经验证。上游历史终态（`VERIFIED`、`PUBLISHED`、`PARTIAL`，或缺失）作为提供方事实留在证据里。它们不构成额外的成功条件，也不阻断本次检查通过。领域结果经 stdout 返回。

## 人类呈现

向用户说明这次发布审计时，只按本次实际返回来讲结论、依据、限制和下一步。结论来自 `release_result`。依据是 `gate_findings`、`evidence_list` 和 `blocking_reasons` 里的实际记录。这是静态记录检查，不推断目标已经发布，也不推断已经获得发布批准。没有对应记录时，不补空栏目。机器返回和只读边界保持原样，不另写报告文件。

## 边界

- 只消费已有权威证据
- 不补造证据
- Node 22 只由既有 Foundation host 提供，不接受输入或环境中的解释器路径
- 只执行 Release Skill 0.9.17 `verify-records`，CLI 与 bundle 必须匹配固定公开字节锁
- 只读取调用方显式指定的记录路径，不扫描 `.release-skill`，不跟随记录内路径
- 调用方内嵌的验证器输出不能形成成功结果
- 发布评估只接受 `conformance`、`platforms`、`exceptions` 和 `release_policy` 四类输入
- 缺项（结论不可用）的结果，在既有 `reason` 上说明适用的检查或接入入口。conformance 指向 `skill-family-audit:conformance-audit`。平台投影指向 `skill-family-audit:setup`。没有公开专业入口时，如实说明能力缺口，不静默重做专业工作，不要求 failure-auditor 报告
- 失败模式和运行效果报告不属于发布评估所需输入
- 和提供方的结果不一致时，先核对目标、采用版本、适用范围与双方职责，按实际原因解释。不默认 Audit 有错，不改写提供方结论，不新建冲突裁决机制
- 项目名称、目录与临时托管只作个案事实，不提升为通用义务。改名或换目录不等于符合要求
- 对 conformance 结果只做内容级一致性校验，不重跑审计
- 不复制 Release Skill 的计划、批准、发布或协调状态机
- 不判断受检目标的运行有效性；运行效果不属于本方法结论
- 不把候选治理批准解释为正式发布批准
- 不创建结果目录，不调用 Audit 自有发布桥
