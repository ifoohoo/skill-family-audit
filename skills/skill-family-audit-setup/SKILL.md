---
name: "skill-family-audit-setup"
description: 默认只读诊断环境、规范包和静态平台投影；需要安装或配置时输出精确计划，经用户确认后执行机械步骤并复验。
user-invocable: true
internal: false
argument-hint: "[额外检查选项]"
---
<!-- platform-projection: platform=codex; logical=skill-family-audit:setup; source=skills/skill-family-audit/setup -->

# skill-family-audit:setup

## 目的

检查运行环境、规范包完整性和静态平台投影。默认只读诊断；诊断发现需要安装或配置变更时，形成精确计划并取得用户授权后执行，执行后复验。

## 输入

- 可选：额外检查选项（如 `--verbose`、`--platform <id>`）

## 固定流程

1. **检查（只读）**：验证 Python 版本、spec/ 目录完整性、authority-index.json 可解析性；检查规范发布状态、方法注册表、平台能力档案；检查四平台 manifest、Skill 映射与资源闭包
2. **形成精确计划**：诊断发现需要安装或配置变更时，输出精确命令、目标路径、写入与联网影响面和预期结果；无待处理项时明确报告"无需修改"
3. **展示并取得授权**：向用户展示完整计划并等待明确确认；检查或展示计划本身不构成执行授权
4. **执行已批准计划**：仅在用户明确确认后执行，且只执行已批准的机械步骤（依赖安装、hook 或配置写入类）；计划变化后原授权不得继续使用
5. **复验**：执行后重新运行只读检查确认目标状态达成，以结构化 JSON 返回检查结果、执行结果与人工验证建议

## 写入边界

- 默认只读：未获用户明确确认前不写入任何文件、不安装依赖、不修改配置
- 授权执行仅限计划内的机械步骤；语义判断、计划变更和范围扩大必须回到用户确认
- 执行必须幂等：相同环境与计划重复执行不产生额外副作用，不重复下载或重复写入
- 已有文件、已有配置或用户修改与计划冲突时停止并交用户裁决，不得覆盖安装
- 禁止用户无感的自主安装或覆盖安装

## 输出

<!-- BEGIN GENERATED PLATFORM SUPPORT -->
平台状态只从 `spec/platforms/support-matrix.json` 读取：

```json
{
  "claude-code": "static_projection_available",
  "codex": "static_projection_available",
  "kimi-code": "manual_unverified",
  "workbuddy": "static_projection_available"
}
```
<!-- END GENERATED PLATFORM SUPPORT -->

```json
{
  "environment": {
    "python_version": "3.x.y",
    "spec_directory": true,
    "authority_index": true,
    "approval_status": "no_active_approval_receipt"
  },
  "platforms": [
    {
      "platform_id": "claude-code",
      "client_detected": false,
      "status": "blocked_candidate",
      "observed_capabilities": [],
      "unverified_capabilities": ["manual_install", "manual_invoke"]
    }
  ],
  "actions_required": [],
  "warnings": []
}
```

## 边界

- 不修改受检目标项目；规范检查对受检目标只读由 SFA-PERM-008 独立约束
- 不形成稳定发布事实
- 规范批准前只报告候选状态
- 四平台只声明静态投影，不从候选结构推断宿主安装成功
- Kimi 只给出人工安装说明；可选 `--skills-dir` smoke 失败时报告 `manual_unverified`，不阻断候选发布
