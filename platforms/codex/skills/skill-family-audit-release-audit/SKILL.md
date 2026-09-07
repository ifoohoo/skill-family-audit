---
name: "skill-family-audit-release-audit"
description: 审计技能族发布门禁、摘要链和稳定发布条件。只消费已有权威证据。
user-invocable: false
internal: true
method-id: "skill-family-audit:release-audit"
---
<!-- platform-projection: platform=codex; logical=skill-family-audit:release-audit; source=skills/skill-family-audit-release -->

# release-audit

## 目的

审计技能族的发布门禁、摘要链和稳定发布条件。只消费已有权威证据，不补造证据，不复制
Release Skill 的计划、批准、发布或协调状态机。

方法只返回 `release_result`、`gate_findings`、`evidence_list` 和 `blocking_reasons`。公共
Task/Result 与证据 Resource 绑定由 Foundation Quickstart Profile 提供，领域结果通过 stdout 或宿主 Result 返回。

## 方法契约

- **method_id**: `skill-family-audit:release-audit`
- **capability**: 审计发布门禁和稳定发布条件
- **composability**: closed_leaf
- **codeExecution**: false
- **sideEffects**: read-only

## 当前状态

- **maturity**: experimental
- **status**: candidate
- **上游边界**: Release Skill 公开只读验证器尚未发布，正式成功路径关闭。空输入与任何调用方
  提供的验证器对象都确定性返回 `BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE`；该对象
  不解释为上游权威输出，也不能把不存在的上游能力伪装成已发布。

## 运行接口

唯一运行接口是 `--release-audit-input`：

```text
python3 scripts/release_audit.py --release-audit-input <冻结的 release-audit-input JSON>
```

输入文档携带候选身份（unit id 与 target version）、发布评估引用和 `release_verifier_output`
字段（对象或 null）。上游公开验证器尚未发布期间，无论该字段为空还是提供对象，结果都稳定为
`BLOCKED/UPSTREAM_RELEASE_VERIFIER_UNAVAILABLE`，领域结果经 stdout 返回，退出码 1；输入文档
非法或边界校验失败时失败关闭，退出码 2。

## 边界

- 只消费已有权威证据
- 不补造证据
- 不把调用方提供的验证器对象解释为上游权威输出
- 发布评估只接受 `conformance`、`platforms`、`exceptions` 和 `release_policy` 四类输入
- 对 conformance 结果只做内容级一致性校验，不重跑审计
- 不复制 Release Skill 的计划、批准、发布或协调状态机
- 不把候选治理批准解释为正式发布批准
- 不创建结果目录，不调用 Audit 自有发布桥
