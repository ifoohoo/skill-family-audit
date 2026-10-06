---
name: "skill-family-audit-setup"
description: 默认只读诊断环境、规范包和静态平台投影；需要安装或配置时输出精确计划，经用户确认后执行机械步骤并复验。
user-invocable: true
internal: false
argument-hint: "[额外检查选项]"
---
<!-- platform-projection: platform=claude-code; logical=skill-family-audit:setup; source=skills/skill-family-audit/setup -->

# skill-family-audit:setup

## 目的

检查当前 Python、规范索引、候选批准状态、平台客户端环境和静态投影能不能看见。默认只做只读诊断。诊断发现需要安装或修改配置时，先写出精确计划，得到用户授权后再执行，执行后再复验。

## 输入

- 可选：额外检查选项（如 `--verbose`、`--platform <id>`）

## 固定流程

本入口分三类动作：只读检查、差距分析、获准变更。依赖和配置已经满足时，保持现状就是正常结论。升级或补装依赖只作为选项列出，不默认跟踪最新版本。

1. **检查（只读）**：用「人类呈现」里的那一条命令，运行本入口自带的确定性诊断程序。程序读取当前 Python 进程、规范索引、候选摘要和批准收据，再从当前进程环境和可执行文件搜索路径探测四个平台客户端。静态平台 manifest 只说明投影在不在，不冒充客户端已经安装、已经被发现或调用成功。
2. **分析（只读）**：诊断发现需要安装或修改配置时，写出精确命令、目标路径、写入影响、联网影响和预期结果，并说明每个选项的后果。没有待处理项时，明确报告"无需修改"，并把保持现状列为可选结果。
3. **展示选项并取得授权**：把完整计划和选项展示给用户，等待明确确认。检查本身，以及展示计划，都不构成执行授权。
4. **执行已批准计划（获准变更）**：只有用户明确确认之后才执行，并且只执行已经批准的机械步骤，例如依赖安装、hook 或配置写入。计划一旦变化，原来的授权就不能继续用。不自行升级依赖。
5. **复验**：执行之后重新做只读检查，确认目标状态已经达到。用结构化 JSON 返回检查结果、执行结果和人工验证建议。

不要搜索文件系统、家目录、其他插件、README 或 `package.json`。脚本路径、插件根和第一条工具调用只出现在「人类呈现」，本节不另给命令。

这个程序只读文件、进程环境和可执行文件搜索路径。没检测到平台客户端时，只记入 `warnings`，不用静态投影把它写成成功。不要调用 `main()`，也不要用脚本退出码代替「人类呈现」的四个字段。

## 写入边界

- 默认只读：没得到用户明确确认之前，不写任何文件，不安装依赖，不修改配置
- 授权之后只执行计划里的机械步骤。语义判断、计划变更和范围扩大，必须回到用户确认
- 执行必须幂等：同样的环境和计划再执行一次，不产生额外副作用，不重复下载，也不重复写入
- 已有文件、已有配置或用户改动和计划冲突时，停下来交给用户裁决，不得覆盖安装
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

诊断结果的 `environment` 保留实际的 Python、规范、批准和平台环境事实。`actions_required` 只列关键事实缺失。`warnings` 列出没检测到客户端、旧批准收据和当前候选不匹配这类非阻断事实。结果里不写生成时间，方便同一环境反复核对。

## 人类呈现

第一条工具调用是一条 `python3 -c`。脚本是本 `SKILL.md` 同目录的 `scripts/setup_diagnostics.py`。不搜索文件系统、家目录、其他插件、README 或 `package.json`。`SKILL_MD_ABSOLUTE_PATH` 只替换为加载本技能时已经得到的本文件绝对路径，不要为此列目录或检索。插件根是该脚本路径向上第一个同时含有 `skills/` 和插件清单的目录。插件清单只认该目录下的 `platform-manifest.json`、`manifest.json`、`plugin.json`、`kimi.plugin.json`，或 `.claude-plugin`、`.codex-plugin`、`.codebuddy-plugin` 中的 `plugin.json`；这条判断只在下面这一条命令内完成。同一条命令用 importlib 按文件路径加载，调用已有的 `collect_diagnostics(插件根)`，再把得到的字典交给已有的 `present_setup_diagnosis`。不要调用 `main()`。stdout 只打印返回对象的 `conclusion`、`basis`、`limits`、`next_step`。在这条 stdout 回到上下文之前，不要列出目录、不要检索、不要阅读该脚本或其他插件文件，也不要发出第二条工具调用；这条命令返回前不阅读脚本。用户回复先写出这四个字段，再写一句实际范围：这次只读诊断覆盖当前加载插件的环境事实，不覆盖目标项目业务。conclusion 为 missing_prerequisite 时，就绪情况只写「本次不是环境已经就绪。」这一句，不附加可见项或事实齐全的描述；然后写还缺前提并写「本次结论是这一种。」；再写要改环境时必须先得到授权，并写明这次没有安装、没有改配置。conclusion 为 ready 时写环境已经就绪是本次结论，并点名另外两种不是。conclusion 为 change_needs_authorization 时写要改环境时必须先得到授权是本次结论，并点名另外两种不是。不要自动安装，不要运行目标项目业务，然后停止。不要安装。不要打开 README、`package.json` 或 Help。不另写报告文件。

```text
python3 -c 'import importlib.util, json, sys; from pathlib import Path; skill = Path(r"SKILL_MD_ABSOLUTE_PATH").resolve(); script = skill.parent / "scripts" / "setup_diagnostics.py"; names = ("platform-manifest.json", "manifest.json", "plugin.json", "kimi.plugin.json"); nested_names = (".claude-plugin", ".codex-plugin", ".codebuddy-plugin"); plugin = next((candidate for candidate in script.resolve().parents if (candidate / "skills").is_dir() and (any((candidate / name).is_file() for name in names) or any((candidate / dirname / "plugin.json").is_file() for dirname in nested_names))), None); sys.exit(1) if plugin is None else None; spec = importlib.util.spec_from_file_location("setup_diagnostics", script); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); presented = mod.present_setup_diagnosis(mod.collect_diagnostics(plugin)); print(json.dumps({key: presented[key] for key in ("conclusion", "basis", "limits", "next_step")}, ensure_ascii=False))'
```

## 边界

- 不修改受检目标项目。规范检查对受检目标只读，由 SFA-PERM-008 单独约束
- 不形成稳定发布事实
- 候选标记说明品质和批准状态，不构成调用禁令。批准收据和当前候选不一致时，作为非阻断告警报告
- 四个平台只声明静态投影，不从候选结构推断宿主已经安装成功
- Kimi 只给出人工安装说明。可选 `--skills-dir` smoke 失败时，报告 `manual_unverified`，不阻断候选发布
