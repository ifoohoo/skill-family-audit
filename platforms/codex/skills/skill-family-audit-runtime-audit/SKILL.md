---
name: "skill-family-audit-runtime-audit"
description: 消费 loop-agent 的权威运行证据，审计技能族运行时行为。不复制观察与恢复算法。
user-invocable: false
internal: true
method-id: "skill-family-audit:runtime-audit"
---
<!-- platform-projection: platform=codex; logical=skill-family-audit:runtime-audit; source=skills/skill-family-audit-runtime -->

# runtime-audit

## 目的

消费 loop-agent 产生的权威运行证据，审计技能族运行时行为，包括 provider 身份验证、进程生命周期、隔离画像、观察器事件序号、终态唯一性和资源清理。

## 方法契约

- **method_id**: `skill-family-audit:runtime-audit`
- **capability**: 消费权威运行证据进行运行时审计
- **composability**: closed_leaf
- **codeExecution**: false
- **sideEffects**: read-only

## 当前状态

- **maturity**: experimental
- **status**: candidate
- **候选身份**: 从当前已安装不可变候选的 `platform-manifest.json` 解析，禁止在 Skill 中硬编码旧版本。
- **资格边界**: 第一档实现已完成；真实平台完整生命周期和稳定成熟度资格仍取决于外部证据

## 运行接口

```text
python3 runtime_audit.py \
  --target-project <绝对路径> \
  --runtime-evidence <证据包 JSON> \
  --maturity-level <candidate_ready|consumer_qualified|stable> \
  --platform <平台标识> \
  --provider-root <受信任 provider 安装根绝对路径> \
  --output-dir <不存在或为空的独占目录>
```

## 输出产物

| 文件 | 说明 |
|---|---|
| `runtime-result.json` | 领域结果：运行治理审计结论 |
| `governance-findings.json` | 治理发现清单 |
| `evidence.json` | 证据引用列表 |
| `report.zh-CN.md` | 人类可读审计报告 |

## 成熟度等级

| 等级 | 最低要求 |
|---|---|
| `candidate_ready` | provider 身份、进程证据、任务定义、任务结果、隔离画像、观察器事件 |
| `consumer_qualified` | 候选就绪全部 + 清理证明、封存记录、终局化请求 |
| `stable` | 消费方资格全部 + 真实矩阵（≥2 不同领域消费方）+ 控制场景覆盖 |

## 失败关闭语义

- 缺失必需证据 → `BLOCKED`
- 缺少冻结档案认可、由 provider 产出并绑定当前 bundle 的收据 → `BLOCKED`
- 摘要篡改、Schema 不匹配、身份矛盾 → `FAILED`
- 事件乱序、重复终态、终态后事件 → `FAILED`
- 输出目录非空、相对路径、符号链接逃逸 → CLI 拒绝执行

## 消费边界

- 只消费 loop-agent 的权威运行证据
- caller 构造的 bundle 即使通过结构与摘要校验，也不得标记为 `verified`
- 不复制观察与恢复算法
- 不创建本地 Task/Result/Resource；领域结果由 Foundation Quickstart profile 包装
- 不把进程退出码或文字自报直接升级为业务通过
- 不得把第一档实现或候选治理状态伪装为稳定资格
