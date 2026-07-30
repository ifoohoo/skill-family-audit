# Skill Family Audit

技能族规范、四个严格审计方法和四平台投影的唯一公开发布源。

当前版本 `0.1.7-candidate` 已获得候选治理批准，但仍是候选版本，
不声明为稳定发布。候选批准不等于 Release Skill 计划批准、生产发布确认
或任何远端写入授权。

## 当前能力

该候选提供 `help`、`setup` 和 `quickstart` 入口，并包含一致性、行为、
运行时与发布四类严格审计方法。Claude Code、Codex、Kimi Code 和
WorkBuddy 使用各自的平台投影；没有完成实机生命周期验证的能力会保持
失败关闭，不会被描述为已支持。

## 安装

<!-- release-skill:capability:safe-first-command -->

该项目是插件技能族，不是 npm 库；`npm install` 不是受支持的安装入口。
只有在公开仓库出现与版本匹配的 Git 标签和 GitHub Release 后，Codex
用户才应以冻结标签作为第一条安全安装路径：

```sh
codex plugin marketplace add ifoohoo/skill-family-audit \
  --ref skill-family-audit-v0.1.7-candidate --json
codex plugin add skill-family-audit@skill-family-audit --json
# 安装后先在 Codex 中调用 skill-family-audit 的 help 技能。
```

在正式发布完成前，只能从本仓库冻结的候选目录进行隔离验证：

```text
dist/candidate/0.1.7-candidate/platforms/<platform>
```

其中 Codex 投影可通过本地 marketplace 在独立 `CODEX_HOME` 中验证；
Claude Code 使用 `--plugin-dir` 做会话级验证；Kimi Code 使用显式
`--skills-dir`；WorkBuddy 当前只验证静态 manifest。请勿把这些预演步骤
解释为持久安装、升级、回滚或公开发布承诺。

## 发布边界

<!-- release-skill:capability:external-write-boundary -->

公开发布内容由工作区根目录的 `.release-skill/project.yaml` 精确列举。
私有运行证据、批准材料、迁移账本和工作区控制文件均不属于公开 payload。
任何候选批准、远端绑定、推送、标签或发布都需要单独授权。

本候选仅在 Codex 中完成安装、发现、最小调用、卸载和清理闭环。
Claude Code、Kimi Code 与 WorkBuddy 仍有生命周期阻塞，不得把候选批准
或 Codex 安装成功解释为四平台稳定支持。

## 失败诊断

如果公开标签或 GitHub Release 尚不存在，或者安装命令返回失败，应立即
停止，不得改用未冻结的默认分支或本地候选冒充公开版本。Release Skill
返回 `GATE_FAILED` 表示生产门禁未通过；此时必须修复门禁并重新生成计划，
不能沿用旧计划、旧批准或跳过失败步骤。
