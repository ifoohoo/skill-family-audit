# agent-method-registry

[English](README.md)

面向 agent 编码项目的确定性方法注册表：维护方法（技能/工作流）的规范目录，按文件系统验证解析提供者，并诊断注册表健康度。适用于 CLI 工具、Node 库和 CI 流水线的本地确定性使用。

## 它能做什么

- **v1（稳定）**：catalog/overlay 校验、effective index 构建与查询、provider 解析与文件系统验证、doctor 诊断。
- **v2（0.2.0 起）**：技能族 SPI 的运行时侧——校验 implementation descriptor、依据可信 inventory 验证已安装 bundle、生成 capability projection、应用项目显式 binding、严格解析 Method Query，并产出与内容绑定的 run method lock。

## 工作方式：一条确定的制品链

v2 的运行时链路是单向的，每一环只消费上一环的权威产物：

```text
观察插件文件系统
  → 可信 inventory（经权威 validator 校验的安装清单）
  → capability projection（每个 service 的完整候选与六维状态）
  → 项目显式 binding（五服务原子绑定）
  → Method Query 严格解析（strict resolve）
  → run method lock（16 个字段的内容锁）
  → 执行前文件系统复验（reverify）
```

对应到 API：

1. `buildEffectiveIndex({ inventoryEntries, ... })` 把发现的安装事实变成经校验的 `preparedInventory` 和 projection；
2. `queryEffectiveIndex({ methodQueryCandidate })` 做推荐（recommendation）或准备（prepare）；prepare 成功后签发进程本地的 `preparedQueryHandle`；
3. `resolveEntry` 用句柄加精确 `serviceIdentity` 生成 `runMethodLock`；
4. `verifyProvider` 在执行前重新核对文件系统，内容漂移即失败。

技能族无需复制 Registry 的摘要算法：候选事实进去，由 Registry 规范化、校验、签名的完整文档出来。

## Family API 与 SPI 模型

用 Java 作类比（仅限职责边界）：

- Family API 类似 interface/API contract；
- family implementation descriptor 类似 `implements` 声明；
- trusted inventory、project binding 与 registry resolve 共同承担受约束 SPI/`ServiceLoader` 的职责；
- 本包不是 JVM bytecode verifier，也不使用 Java classloader。

身份分类与边界：Registry 把受支持的 ID 确定性分类为 `STANDARD`、`THIRD_PARTY` 或 `PROJECT`，并核对 API、service 与项目归属是否前后一致：

```text
STANDARD     artifact.<family>-family
             artifact.<family>.<service>

THIRD_PARTY  <reverse-domain>.<family>-family
             <reverse-domain>.<family>.<service>

PROJECT      project.<authority>.<family>-family
             project.<authority>.<family>.<service>
             projectAuthority = project.<authority>
```

早期 v2 文档中保留 `-family` 的 service namespace（例如
`artifact.<family>-family.<service>`）继续兼容；新文档应使用上面的规范写法。分类只能证明字符串和制品关系一致，不等于 authority 真实性认证。第三方域名归属和项目 authority 的来源证明仍由独立 attestation 协议负责。

## 三条关键规则

- **状态正交**：已安装不等于已启用、兼容、可信或唯一解析。零个或多个合格候选都 fail closed；Registry 不按 first-entry、最高版本或未声明的 builtin fallback 自动选择。
- **`executable` 判别**：推荐条目携带 `executable` 布尔值，由与 prepare 相同的六状态门（INSTALLED、ENABLED、COMPATIBLE、VERIFIED、EXPLICIT_BINDING、project-binding）派生。`where-am-i` 等消费者只读这个布尔值，不重算六状态逻辑。`UNIQUE_COMPATIBLE` 条目会出现，但始终 `executable: false`。
- **观察不等于信任**：`observed` 只是安全读取到的 realpath 与实际 bundle digest；显式 binding、conformance、authorization 和 provider re-verification 仍然 fail closed。

在已配置项目内，`where-am-i` 是面向用户的入口：它把项目事实与 projection 结合，推荐下一步动作及应使用的技能。外层规划器若已有结构化 Method Query 可直接查询 Registry，但仍须提供调用方要求的 project-facts/context/proof/version-lock preflight 证据。

## 安装

```bash
npm install agent-method-registry
```

需要 Node.js `>=22.0.0`。

## 快速开始

```javascript
import {
  validateCatalog,
  validateProjectOverlay,
  buildEffectiveIndex,
  queryEffectiveIndex,
  resolveEntry,
  verifyProvider,
  diagnoseRegistry,
} from 'agent-method-registry';
```

## 公开 API

包根暴露恰好 **7 个函数**加 `ERROR_CODES` 和领域类型：

| 函数 | 用途 |
|------|------|
| `validateCatalog` | 验证 v1 catalog 或带显式 discriminator 的 v2 implementation/inventory/run-lock/migration-plan 文档 |
| `validateProjectOverlay` | 验证 v1 project overlay 或 v2 project binding/projection 文档 |
| `buildEffectiveIndex` | 构建确定性 v1 index 或 v2 capability projection |
| `queryEffectiveIndex` | 查询 v1 index、推荐 v2 服务，或准备一次已授权的 v2 执行 |
| `resolveEntry` | 解析 v1 provider，或执行 v2 strict resolve 并生成 run method lock |
| `verifyProvider` | 依据文件系统验证 v1 路径或 v2 inventory/bundle/run-lock 证据 |
| `diagnoseRegistry` | 诊断 schema、projection、snapshot、binding、provider、lock 与 migration 健康度 |

TypeScript overload 在输入为 v1 文档时保留原有 v1 结果类型。公开 schema 通过 package subpath 定位（如 `agent-method-registry/schemas/implementation.schema.json`），不增加新的运行时函数。

### v2 生产者流程

```javascript
const projection = buildEffectiveIndex({
  familyApi,
  implementations,
  inventoryEntries: discoveredInstallations, // 非空数组
  bindings,
});

const query = queryEffectiveIndex({
  index: projection.index,
  purpose: 'prepare', // 只读发现使用 'recommendation'
  methodQueryCandidate: {
    mode: 'standard',
    intent: 'author',
    kind: 'workflow',
    projectFactsEvidence,
    authorization,
  },
});
```

要点：

- `methodQueryCandidate` 恰好五个顶层字段；Registry 先验证 `projectFactsEvidence` envelope 的内容摘要，再派生 target artifact、contract revision、candidate services 与 query digest。
- 推荐结果只暴露 provider 状态元数据，绝不含句柄；只有 prepare 同时证明已安装、已启用、兼容、可信、项目显式绑定和授权后，才签发进程内 `preparedQueryHandle`。
- `executable: true` 时条目的六个状态字段为唯一可执行组合；`false` 时报告实际状态。该标志与 prepare 门由 Registry 内部同一函数派生，调用方不得重算。

## CLI

```bash
# 验证目录文件
agent-method-registry validate --catalog catalog.yaml --project overlay.yaml

# 构建有效索引
agent-method-registry index --catalog catalog.yaml --out index.json

# 查询索引
agent-method-registry query --index index.json
agent-method-registry query --index index.json --domain artifact --kind workflow

# v2 推荐查询：candidate 是唯一查询来源，结果不含句柄
agent-method-registry query --index projection.json --candidate candidate.json

# 解析特定条目
agent-method-registry resolve --index index.json --ref my-plugin.entity.author --host claude-code --plugin-root ./plugins/my-plugin

# 预览 v1→v2 迁移；apply 前必须审阅 plan 与 collision
agent-method-registry migrate --catalog catalog.yaml --project project.yaml \
  --migration-context migration-context.json --dry-run --out-plan migration-plan.json \
  --transaction-root .
```

v1 catalog/overlay/query/resolve 协议继续兼容。v2 migration 提供显式 dry-run、apply 与基于 snapshot 的 rollback；rollback 写入前会验证每个目标仍与 apply 产物逐字节一致，apply 后的任何用户改动都会让整次恢复在零写入状态下失败。

所有 CLI 命令向 stdout 输出单个 JSON 信封：

```json
{
  "ok": true,
  "data": { "..." },
  "diagnostics": []
}
```

退出码：`0` = 成功，`1` = 数据/索引/条目错误，`2` = 格式错误的调用。

## 安全边界

<!-- release-skill:capability:safe-first-command -->
安全的第一条命令是 `agent-method-registry --help`：只读、不写任何文件。`validate`、`query`、`resolve`、`diagnose` 同样只读取你显式给出的输入。

<!-- release-skill:capability:external-write-boundary -->
外部写入边界：本包是确定性的本地工具，不发起网络请求、不做任何外部写入。唯一的文件写入来自你显式指定的参数：`--out`（索引）、`--out-plan`（迁移计划），以及限制在 `--transaction-root` 内的 migration `--apply`。

## 许可证

[Apache-2.0](LICENSE)

本项目由广州市风荷科技有限公司与 `agent-method-registry` contributors 共同维护，归属信息见 [NOTICE](NOTICE)。
