# Skill Family Audit

技能族规范、四个严格审计方法和四平台投影的唯一公开发布源。

当前版本 `0.1.26-candidate` 是尚未批准的本地修订候选，
不声明为稳定发布。候选批准不等于 Release Skill 计划批准、生产发布确认
或任何远端写入授权。

## 当前能力

该候选提供 `help`、`setup` 和 `quickstart` 入口，并包含一致性、行为、
运行时与发布四类严格审计方法。Claude Code、Codex、Kimi Code 和
WorkBuddy 使用各自的静态平台投影。平台清单与资源闭包通过构建检查，
宿主安装和调用由消费者人工验证。

本版本泛化了受检对象侧的目标身份绑定：一致性、行为、运行时和发布审计
方法现在原生支持任意 PluginProject 的 1..N 个 logicalSkills（N=1 是
正常路径，不是兼容模式）。marketplace 名、plugin selector 和入口路径
从目标观察结果读取，不再硬编码为 Audit 自身身份。

## 安装

<!-- release-skill:capability:safe-first-command -->

该项目是插件技能族，不是 npm 库；`npm install` 不是受支持的安装入口。
只有在公开仓库出现与版本匹配的 Git 标签和 GitHub Release 后，Codex
用户才应以冻结标签作为第一条安全安装路径：

```sh
codex plugin marketplace add ifoohoo/skill-family-audit \
  --ref skill-family-audit-v0.1.26-candidate --json
codex plugin add skill-family-audit@skill-family-audit --json
# 安装后先在 Codex 中调用 skill-family-audit 的 help 技能。
```

在正式发布完成前，只能从本仓库冻结的候选目录进行隔离验证：

```text
dist/candidate/0.1.26-candidate/platforms/<platform>
```

四个平台目录都是静态、自包含投影。Kimi 只支持人工安装或会话级
`--skills-dir`；可选 smoke 失败只记录 `manual_unverified`，不阻断候选发布。

## 发布边界

<!-- release-skill:capability:external-write-boundary -->

公开发布内容由工作区根目录的 `.release-skill/project.yaml` 精确列举。
私有运行证据、批准材料、迁移账本和工作区控制文件均不属于公开 payload。
任何候选批准、远端绑定、推送、标签或发布都需要单独授权。

候选发布门只检查公开字节、四平台静态闭包、Foundation provenance 和审计
方法回归。不得把候选批准解释为四个平台已经完成宿主安装验证。

## 失败诊断

如果公开标签或 GitHub Release 尚不存在，或者安装命令返回失败，应立即
停止，不得改用未冻结的默认分支或本地候选冒充公开版本。Release Skill
返回 `GATE_FAILED` 表示生产门禁未通过；此时必须修复门禁并重新生成计划，
不能沿用旧计划、旧批准或跳过失败步骤。
