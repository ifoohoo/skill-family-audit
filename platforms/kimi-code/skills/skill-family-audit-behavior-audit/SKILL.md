---
name: "skill-family-audit-behavior-audit"
description: 在明确平台、模型、样例和限制下，验证技能族行为是否满足业务验收。需要隔离执行环境。
user-invocable: false
internal: true
method-id: "skill-family-audit:behavior-audit"
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:behavior-audit; source=skills/skill-family-audit-behavior -->

# behavior-audit

## 目的

在最低隔离画像内执行目标技能族的行为样例，验证其是否满足业务验收标准。

## 方法契约

- **method_id**: `skill-family-audit:behavior-audit`
- **capability**: 在隔离环境中验证技能族行为
- **composability**: closed_leaf
- **codeExecution**: true（在隔离画像内）
- **sideEffects**: write-project-artifacts
- **isolation**: required

## 当前状态

- **maturity**: experimental
- **status**: candidate
- **资格边界**: 第一档实现已完成；平台真实调用与稳定资格尚未完成

## 运行接口

```text
python3 scripts/behavior_audit.py \
  --target-project <绝对目录> \
  --fixture-manifest <内容绑定的夹具清单> \
  --sandbox-root <外部已建立的隔离根> \
  --platform-selector <平台> \
  --model-selector <模型> \
  --scope-selector <范围> \
  --now-utc <带时区时间> \
  --runtime-context <运行上下文 JSON>
```

输出目录由运行上下文显式授权。入口验证夹具清单、隔离画像、执行授权和选择器，使用
`shell=False` 启动绑定摘要的可执行文件，记录目标项目前后快照、未知副作用、超时和清理结果，
最后原子发布公共信封、领域结果、证据与中文报告。

## 边界

- 只能在最低隔离画像内执行
- 不得绕过规范化任务、授权或独占输出目录
- 不创建沙箱，不把测试目录冒充隔离证明
- 未知写入、目标项目漂移、超时或清理失败均失败关闭
