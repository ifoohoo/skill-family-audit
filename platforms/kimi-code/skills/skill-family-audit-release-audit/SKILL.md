---
name: "skill-family-audit-release-audit"
description: 审计技能族发布门禁、摘要链和稳定发布条件。只消费已有权威证据。
user-invocable: false
internal: true
method-id: "skill-family-audit:release-audit"
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:release-audit; source=skills/skill-family-audit-release -->

# release-audit

## 目的

审计技能族的发布计划、批准记录、发布/协调/验证运行链、消费者门禁和稳定发布条件。只消费
Release Skill `0.3.0` 的版本化不可变收据，不补造证据，不复制其状态机。

方法只返回 `release_result`、`gate_findings`、`evidence_list` 和 `blocking_reasons`；公共
Task/Result 与 observation 绑定由 Foundation Quickstart profile 提供。

## 方法契约

- **method_id**: `skill-family-audit:release-audit`
- **capability**: 审计发布门禁和稳定发布条件
- **composability**: closed_leaf
- **codeExecution**: false
- **sideEffects**: read-only

## 当前状态

- **maturity**: experimental
- **status**: candidate
- **资格边界**: 第一档收据消费已完成；只有 `verify/VERIFIED` 的完整权威链可成功

## 运行接口

```text
python3 scripts/release_audit.py \
  --target-project <绝对目录> \
  --provider-root <Release Skill 0.3.0 插件根> \
  --plan <release-plan.json> \
  --run <release-run.json> \
  --unit-id <发布单元> \
  --target-version <目标候选版本> \
  --runtime-context <运行上下文 JSON>
```

缺少顶层 plan/run 时输出 `BLOCKED`；引用的权威文件缺失、摘要错误、身份或谱系矛盾时输出
`FAILED`；`PUBLISHED` 仍不是最终成功。

## 边界

- 只消费已有权威证据
- 不补造证据
- 不重新计算前三类审计
- 对三类方法结果只做内容级一致性校验（如 SUCCEEDED 必须有规则结果/执行记录/证据引用），不重跑任何审计
- 不复制 Release Skill 的计划、批准、发布或协调状态机
- 不把候选治理批准解释为正式发布批准
