---
name: "skill-family-audit-setup"
description: 只读检查环境、规范包和静态平台投影，返回可执行的下一步。
user-invocable: true
internal: false
argument-hint: "[额外检查选项]"
---
<!-- platform-projection: platform=workbuddy; logical=skill-family-audit:setup; source=skills/skill-family-audit/setup -->

# skill-family-audit:setup

## 目的

检查运行环境、规范包完整性和静态平台投影。默认只读，不执行安装或配置写入。

## 输入

- 可选：额外检查选项（如 `--verbose`、`--platform <id>`）

## 行为

1. **环境检查**：验证 Python 版本、spec/ 目录完整性、authority-index.json 可解析性
2. **规范状态**：检查规范发布状态、方法注册表、平台能力档案
3. **平台投影**：检查四平台 manifest、Skill 映射与资源闭包
4. **输出摘要**：以结构化 JSON 格式返回检查结果与人工验证建议

## 写入边界

- 默认只读检查，不写入任何文件
- 不自动安装插件，不写配置或采用锁

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

- 不修改目标项目
- 不自动安装依赖
- 不形成稳定发布事实
- 规范批准前只报告候选状态
- 四平台只声明静态投影，不从候选结构推断宿主安装成功
- Kimi 只给出人工安装说明；可选 `--skills-dir` smoke 失败时报告 `manual_unverified`，不阻断候选发布
