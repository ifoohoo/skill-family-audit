# 宿主程序内消费已接受的审阅结果（按需参考）

本文档是 `SKILL.md`「语义审阅结果接入」的按需参考资料（SFA-CONTEXT-003
授权手段：把长流程资料迁入按需参考）。授权规则、失败语义与四项接受条件
以 `SKILL.md` 为权威入口文本；本文只展开调用顺序、逐项判断和报告，
不建立第二真源。

按下列已有函数逐步调用。必要短调用和参数文件允许；不要临时编写大型调用程序
或仓外 driver，不要重写编排、遍历合并或结果规范化。测试夹具带
`test_fixture: true` 只证明传输，不代表生产语义通过。完整档不能在预检结果处结束。

模块均在同一已发现平台包内：

| 模块 | 路径 | 函数 |
|---|---|---|
| Quickstart 路由 | 逻辑 Skill `skill-family-audit:quickstart` 的 `scripts/quickstart_route.py` | `human_entry_decision`、`human_entry_clarification`、`identified_scope_statement`、`professional_scan_clarification`、`professional_scan_decision`、`prepare_conformance_evidence_document`、`extract_business_parameters`、`resolve_conformance_human_route`、`resolve_method_contract`、`create_foundation_task`、`call_foundation`、`validate_by_schema_id`、`wrap_foundation_result`、`assert_foundation_exchange` |
| 领域工作流 | 本 Skill 的 `scripts/conformance_workflow.py` | `run_workflow`、`plan_staged_full_audit`、`combine_final_stage`、`combine_staged_round`、`parser`、`_merge_semantic_context_results`、`before_rule_selection_result`、`workflow.WorkflowError` |
| 人类摘要 | 本 Skill 的 `scripts/conformance_human_route.py` | `render_human_summary` |

`runner` 来自同一平台包的受管 Bundle。产品单选用
`human_entry_clarification` 的 `question` 与 `options`；专业扫描多选用
`professional_scan_clarification`。`human_entry_decision` 与
`professional_scan_decision` 供宿主程序读取内部字段，不要把内部字段展示给用户。

## 入口（宿主程序）

`quickstart.human_entry_decision(request, method_args, products=declared_units_or_none)`
返回 `ask_profile`、`intent`、`execution_profile`、`selection_reason`、
`clarification`。`ask_profile` 恒为 false；未出现完整、确定性或精确组时
`execution_profile` 为普通预筛。无绝对路径时 `clarification` 只问路径。
唯一绝对路径若是含多个声明产品的工作区根，仍问选哪个产品；已绑定
`--target` 或 `evidence-set`，或路径已指向其中一个产品时不再问。
`products` 仅在声明发布单元多于一个时传入；不要把 `generated/platforms`
或 `packages/` 子目录列为产品。

`quickstart.human_entry_clarification(...)` 在仍需提问时返回：

```text
{"question": str, "options": [{"name", "path", "difference", "recommended", "label"}, ...]}
```

没有问题则返回 `None`。把该对象直接交给问答控件：展示 `question` 与选项的
名称、路径、差别和推荐标记。不要附加内部字段。

目标确定后、`prepare_conformance_evidence_document` 之前，宿主按真实公开入口构造候选。用户已点名专业提供方时，无论请求是否携带绝对路径，都承接该选择；按当前目录的 `name`、`label`、`entry_ref` 对齐对应行，读取 `id` 并将已明确的标识列表交给 `professional_scan_decision`。只有仍未决定的选择才调用专业扫描多选，它与产品单选分开。候选是本次会话数据，不做成持久目录，也不携带可执行命令。

`quickstart.professional_scan_clarification(candidates)` 有可选项时返回。下例仅列部分展示字段；完整选项还含公开入口 `entry_ref` 和已有证明状态 `proof_present`：

```text
{"question": "本次要加入哪些专业检查？可多选，也可暂不扫描。",
 "options": [{"name", "purpose", "limitation", "recommended", "label"}, ...]}
```

没有可加入的扫描时返回 `None`，不虚构选项。展示专业名称、用途、局限、推荐标记，以及公开 `entry_ref` 和已有证明状态 `proof_present`；内部标识、证据 JSON 和临时路径不对外展示。推荐项不预填为已选。

`quickstart.professional_scan_decision(candidates, selection=None)` 返回
`answer_state`、`can_start_audit`、`authorized_scans`、`reused_proofs`、
`unavailable`。仅当确有可选项且 `selection` 为 `None` 时表示尚未回答，不得开始。
`candidates` 为 `None` 时从当前清单的 `professionalProviders` 构造候选，不虚构清单外专业方。
定位优先用已加载的 `conformance_check.load_professional_provider_rows`；否则从本文件已解析路径向上，
先取最近的非符号链接 `platform-manifest.json`，再取含 `generated/platforms` 的祖先下的
`plugin-src/manifest.json`。找不到就抛 `RouteError` `PROFESSIONAL_PROVIDERS_MISSING`，
不得当成无可选项并允许开始。`registry_adopted` 默认 false，只有 true 时默认清单才包含 `registry`。
`sfa`、`failure_diagnosis` 和 `kind=failure` 不进入可选项。`entry_ref` 只用清单的 `scanEntryRef`，
有入口才可选；默认 `proof_present`、`recheck_requested`、`recommend` 均为 false。
`None` 且仍有可选项时，`answer_state` 为 `unanswered`，`can_start_audit` 为 false，不得开始领域检查。
已传入的候选列表忽略 `registry_adopted`。真正没有可选项时仍沿现有 `no_question`、
`can_start_audit=True` 继续，并说明现成证明复用、入口不可用或无适用项。
适用缺证仍未通过，没有可选项不等于通过。`[]` 表示
明确不选，可以继续 Audit，但不表示通过或不适用；标识列表只授权所列只读扫描。
未知、重复或不可用标识抛 `RouteError`，不要忽略或替换。已有证明默认进入
`reused_proofs`，只有 `recheck_requested=True` 才进入可选项。
路由函数不启动进程、不检查证明、不创建 Task。失效诊断不是内置合规候选。

专业扫描由所选公开提供方完成。所选范围包含静态公共调用关系时，应按提供方合同阅读必要目标调用处、实际采用的公开入口、参数及失败合同；适用但未完成的项须由专业方在原结果中标为 `insufficient`，不可仅写一句范围限制而漏掉该项。Audit 保留并消费专业原结论，不代做专业审阅、不重判提供方内部机制，也不要求所有消费者统一版本。刷新证明另写新路径，原审阅和证明保留。

构造多选候选和创建 Task 之前，宿主按目标里已经存在的采用材料裁剪 Registry。目标没有既有 Registry 采用登记时，不把 registry 放进候选，也不把它送进适用缺证。用户未选择不等于不适用。工作流不扫描目标，也不改写已绑定的 applicable 或 selected。

提供方描述仅从当前平台或源码清单的 `professionalProviders` 读取，通过 `load_professional_providers` 获取。宿主依据实际安装状态发现所选公开入口，不得基于证明正文中的命令进行追溯，亦不可将登记状态误认为已安装发布。已有专业证明时优先调用对应 reader；若需刷新，则另写新证明。把真实宿主选择和可定位的 `proof_root`/`proof_path` 写入 `--professional-consumption`；reader 原始 JSON 有实际返回就完整加入，交由 `extract_business_parameters` 处理。`targeted` 仍进入同一次 `create_foundation_task` 与 `validate_by_schema_id`。完整档的专业消费只进入 `late` 或 `final` 的阶段参数，不写入 `audit_input`。

当证明可定位但 reader 未返回原始 JSON 时，仍应传入真实宿主选择与证明定位信息，`reader_result` 字段可省略，不得伪造 reader 结果、状态、动作或入口可用性。不得手填 status、version_relation、reader_status、baseline 或通过摘要。工作流从这些输入调用 `consume_professional_proof`，严格读取并核对身份与原始结论，基准由同一清单派生。同版本缺少 reader 返回仍未通过；有实际返回则完整传递。版本政策仅执行 `semver.valid/compare` 判断：可读高版本身份按政策通过，低版本未通过并建议刷新；同版本须比较未经改写的完整共同证明，并核验顶层 provider 的 `id`、`version`、`entry`，任一缺失或错配均不通过。

高低版本政策不变。高版本证明按政策接受，与本次是否实际开展检查为两个独立事实。同版匹配后再采用 reader 的 `pass` / `not_pass` / `unavailable`；同版本 partial、unverified 或范围不匹配不计完成。FOUNDATION-012/014 使用该次消费结果。结果出现在 `conformance_result.professional_consumption` 与 `render_human_summary` 中的 `coverage.professional_items` 及 `blocking_findings`。摘要中需列出通过与未通过项，保留原 `conclusion` 的范围、发现与局限。完整且 `completion=complete` 的原生 `not_pass` 使用已有 `REVIEW_REQUIRED`，沿用九级顺序取待处理动作；缺证、未完成或读取不可用情形分别保留其真实原因。

现有发布收据消费仍委托 release-skill 0.9.17 的 `verify-records` 接口，与专业证明的 `read-proof` 分开处理。未知提供方按未知输入拒绝；`docs` 的 `siteBuildingRequired` 为 `false`，机械证明身份为 `skill-family-doc-render`。

## 本次请求与材料留存

入口阶段保留本次完整审计请求及后续业务补充原文，包括工作区根、产品身份、例外和运行目录。仅当后续回复只有专业选择时，才沿用前次请求。按这些事实调用原入口解析器，已确定的 `target`、`target_type`、`execution_profile` 和精确选择器不得回退默认值。业务原话由宿主保存，不向 Task 添加合同之外的字段。

`full` / `targeted` 使用用户指定或明确允许的目标外持久运行目录；未获准写入的目录不可使用。沿用宿主普通文件写入工具，不新增 writer、恢复程序或状态文件。

专业选择须先确定，不能将尚未回答的选项视为允许启动。完整档沿现有 `plan_staged_full_audit` 固定共同 `audit_input`；已核实无专业依赖且满足原材料就绪条件的 `early` 可先行，不等待尚未返回的专业证明。`professional_dependencies` 按每条绑定的全部义务、必需角色及必要关系逐一核实；只有已核实的空数组 `[]` 可提前进入 `early`，缺字段或非空仍进入 `late`。所选、相互独立的只读专业检查可与独立 `early` 由宿主原生工具并行执行。

真实专业输入供相应 `late Task` 消费：实际取得的 producer、reader 原返回和消费材料在该 Task 冻结前保存，不能倒填 `audit_input` 或 `early`。没有实际 reader 原返回时省略该字段，仍传入真实选择和证明定位，由原严格消费及版本政策判断。`targeted` 等单 Task 路径沿原合同准备本次输入，不套用分阶段绑定。专业失败不缩小全局应执行集合。

每步返回后立即保存真实对象：证据集合、原始请求及参数、原 Task、预检与审阅请求、逐项原始审阅、最终领域结果、Foundation Result 和实际回复。不要等临时进程退出或变量丢失后再补，不要用摘要、旧请求或新建 Task 重构原对象。序列化只保存原值；对象缺失就报告缺失。材料保留供回读，不按临时清理逻辑删除。

## 加载同一平台的模块

当目标、档位与专业选择已确定，且本次执行获准启动时，宿主程序需在每个短Python调用的开头执行同平台初始化。该初始化确保所有模块加载与执行均在统一平台上下文中进行。每个短调用可独立新建进程，一个确定性阶段的现有函数可在一次普通 Python 脚本调用内依次执行。同一阶段内的短调用通过该阶段已保存的原 Task、请求、上下文与结果续接。完整档的 `early`、`late`、`final` 各自使用本阶段 Task，跨阶段按下节原接口传递并组合原件。

平台根路径与当前运行环境的绑定由 `QUICKSTART_SKILL_MD_ABSOLUTE_PATH` 确定，该路径指向本次发现的 `Quickstart SKILL.md` 文件的绝对路径。Node与PATH环境变量遵循当前平台的现行要求。模块加载、`sys.path` 插入顺序与`sys.modules`注册次序严格依照下方代码实现，确保路径解析与模块导入的确定性。

```python
import importlib.util
import json
import sys
from pathlib import Path

skill = Path(r"QUICKSTART_SKILL_MD_ABSOLUTE_PATH").resolve(strict=True)
qspec = importlib.util.spec_from_file_location("quickstart_route", skill.parent / "scripts/quickstart_route.py")
quickstart = importlib.util.module_from_spec(qspec)
qspec.loader.exec_module(quickstart)
manifest_path = quickstart.find_platform_manifest()
platform_root = manifest_path.parent
platform = json.loads(manifest_path.read_text(encoding="utf-8"))["platformId"]
checker_path = next(path for path in platform_root.glob("skills/*/scripts/conformance_check.py") if path.is_file() and not path.is_symlink())
sys.path.insert(0, str(checker_path.parent))
cspec = importlib.util.spec_from_file_location("conformance_check", checker_path)
checker = importlib.util.module_from_spec(cspec)
sys.modules["conformance_check"] = checker
cspec.loader.exec_module(checker)
runner = quickstart.find_foundation_runner(platform_root=platform_root)
wspec = importlib.util.spec_from_file_location("conformance_workflow", checker_path.with_name("conformance_workflow.py"))
workflow = importlib.util.module_from_spec(wspec)
sys.modules["conformance_workflow"] = workflow
wspec.loader.exec_module(workflow)
human = workflow.conformance_human_route
```

`find_foundation_runner` 返回的 `runner` 路径为经原Bundle校验的合法路径，该路径实际被 `call_foundation` 用作公开机制入口。每个新短调用均可通过该函数重新获取，确保路径一致性。`conformance_check` 与 `conformance_workflow` 模块必须在 `sys.modules` 中注册为全局可访问名称，以支持后续调用。

`mechanisms-cli.mjs` 与 `adoption-cli.mjs` 均位于同平台 `foundation/quickstart-profile` 目录下。后续通过 `quickstart` 调用 Quickstart 函数，通过 `workflow` 调用领域工作流函数，通过 `human` 调用摘要函数。`platform_root`、`platform` 与 `runner` 采用实际返回值，所有调用均在已绑定的平台上下文中执行。

平台绑定需实际核对。模块或 Bundle 缺失、跨平台绑定时，保留原异常并按原边界停止。当派发原生审阅时，宿主需提供本次实际解析的平台根路径、该包内请求与返回合同的定位信息。身份与摘要读取当前 `request` 内容。所有模块加载与路径解析结果均以真实运行时状态为准，供原生审阅者直接使用。后续步骤依赖当前已保存的原件与合同，继续执行下一阶段。

## 审阅消费（阶段内同一 Task，完整档跨阶段组合）

`targeted`、经济档、机械档和发布审计仍是一次 Task，不传 `--audit-phase`、`--stage-rules`、`--staged-round`。完整档 `full` 使用 `early`、`late`、`final`。`plan_staged_full_audit` 冻结共同 `audit_input`。缺 `professional_dependencies` 表示独立性尚未核实，机械方法与语义方法都等待到 `late`；已核实的 `[]` 进入 `early`；非空依赖进入 `late`。`audit_input` 只在首个真实阶段内联一次：有已核实独立规则时是 `early`，否则是首个 `late`。后续阶段和 `final` 用 `audit_input_ref` 回读原文件并核对 `audit_input_digest`，不得倒填。`early` / `late` 把 `--audit-phase` 和 `--stage-rules` 传给现有 `run_workflow`。阶段内部仍用 `_merge_semantic_context_results` 合并该阶段自己的 context，并保留该阶段原 Task、父请求摘要和 新3.0结果合同的四项摘要。`final` 传 `--audit-phase final` 与 `--staged-round`，只调用 `combine_final_stage`（其内部调用 `combine_staged_round`）组合原 `stage_results`，不再调用 `run_workflow`，不把不同阶段拼成一份内部审阅结果，也不重签早期或晚期判断。提供方失败不缩小冻结的应执行集合。下面的步骤 1 至 5 是每个审阅阶段内部的工序；步骤 6 按阶段收尾。

每一步均按依赖顺序等待当前函数返回，核对返回值后进入下一步。依赖明确的确定性工序可在同一次既有工具调用内依次完成等待、沿原 API校验及必要原件保存，不必为每个函数单独返回模型；Task 原值仍须立即保存，失败仍按原逻辑传播。需要语义判断、真实选择或处理真实失败时，再交回模型。宿主将步骤 6转入后台时，沿现有前台等待或 TaskOutput等支持的续接方式等待真实领域结果，再完成步骤 7、8；不因内部任务标为完成、进程退出 0或只读到执行计划就宣称 Task completed。后台中止、前台恢复与实际回复各自保留；未观察的退出码和成因保持未知。已获取 Task、预检请求或某项 `reviews` 时直接复用，不因屏幕未显示输出而重复调用创建或预检。不新增 runner、缓存、状态文件或恢复程序。身份字段从当前返回值或该项 `request` 读取，不手抄修订、binding 或摘要。

1. `document = quickstart.prepare_conformance_evidence_document(target)`  
   返回 `{"evidence_set": [...]}`，复用 `_derived_evidence_set`。按同一平台 Quickstart「输入」完成已获准外部材料的承接，再将证据集合写入上文已允许的目标外持久文件，作为后续 `--evidence-set`。已有显式证据文件则按原合同直接绑定，不重复派生或偷换材料。

2. `parameters, resource = quickstart.extract_business_parameters("conformance", method_args)`  
   专业消费文件用 `--professional-consumption`，仅含真实宿主选择、可定位证明和实际取得的 reader 原始返回；没有 reader 原返回时省略 `reader_result`，不补造 JSON；该内容进入同一 `parameters`。工作流再调用既有消费路径。Task 创建前须沿用 Quickstart `run` 中已有的档位解析与参数绑定：  

   1. **输入来源**  
      同平台模块已加载，`quickstart.extract_business_parameters` 调用完成。`request` 为完整业务原话，`method_args` 保留实际目标、范围、证据集合及专业消费参数（`professional_consumption`），`parameters` 为该函数原始返回值，`runner` 使用同平台原始值。

   2. **实际组装逻辑**

      按现有路由函数的返回值组装参数：

   ```python
   human_route, group_registry, human, human_intent, route_identity = (
       quickstart.resolve_conformance_human_route(request, method_args, runner)
   )
   parameters["execution_profile"] = human_route["execution_profile"]
   if human_route["semantic_group_ids"]:
       parameters["semantic_group_ids"] = human_route["semantic_group_ids"]
   if human_route["canonical_rule_ids"]:
       parameters["canonical_rule_ids"] = human_route["canonical_rule_ids"]
   routed_args = quickstart._without_options(method_args, quickstart.HUMAN_ROUTE_OPTIONS)
   routed_args.extend(["--execution-profile", human_route["execution_profile"]])
   for group_id in human_route["semantic_group_ids"]:
       routed_args.extend(["--semantic-group-id", group_id])
   for canonical_id in human_route["canonical_rule_ids"]:
       routed_args.extend(["--canonical-rule-id", canonical_id])
   routed_args.extend(["--profile-selection-reason", human_route["selection_reason"]])
   ```

   3. **后续使用与合同边界**  
      - `selection_reason` 仅通过 `routed_args` 传递至工作流与原执行计划，不扩展 Task 合同字段。  
      - 后续两次工作流共用由 `quickstart.execution_method_args` 生成的 `invocation_args`，确保目标、范围、证据、专业参数、执行档位及选择理由完整保留。  
      - 对于 `execution_profile` 为 `full` 的场景，需在早期（early）和晚期（late）阶段分别补入 `--audit-phase` 与 `--stage-rules` 参数。  
      - 最终阶段仅组合原阶段结果，不引入新逻辑。  
      - 若未显式选择语义组或规则，不以空列表代替，保留解析器原始默认行为。

   `parameter_schema, result_schema = quickstart.resolve_method_contract(platform_root, "conformance")`  
   `parameter_schema` 与 `result_schema` 均为该函数返回的 Schema ID 字符串，直接传给 `validate_by_schema_id`；不转为 `Path`，也不按文件路径解析。调用参数的类型错误由原职责纠正，不修改校验器、序列化器或原结果。  
   保留 `extract_business_parameters` 返回的全部参数，包括由 `--target-type` 映射的 `scope_selector`、原 `evidence_set` 和专业消费。读取  
   `quickstart.validate_by_schema_id(runner, parameter_schema, parameters)` 的返回值，仅当 `valid is True` 时才创建 Task；否则按原错误停止，不丢弃缺项继续。

3. `targeted` 仍执行一次 `task = quickstart.create_foundation_task(runner, resource, operation_id=run_id, method="conformance-audit", parameters=parameters)`。完整档的这一次调用只绑定首个真实阶段：`quickstart_route.run` 在 `execution_profile == "full"` 时把 `plan_staged_full_audit` 的 `first_stage_parameters` 并入 parameters，不在规则选择前失败之后再创建 `late` 或 `final`。后续阶段各自另建 Task，`final` 不重签。  
   等待返回后再取 `foundation_task_digest = quickstart.call_foundation(runner, "digest-document", {"document": task})["digest"]`。  
   立即保存该 `task` 的完整原值，再进行后续调用；不使用记忆中的旧 Task 或另一次创建结果替换本次返回值。

4. 沿 Quickstart `run` 的既有参数组装，并调用  
   `quickstart.execution_method_args("conformance", routed_args, run_id, foundation_task_digest=foundation_task_digest)`  
   取得 `invocation_args`。`routed_args` 包含原方法参数、已解析档位、非空精确选择器和原 `profile_selection_reason`；不要手写一份不完整的 `argparse.Namespace`。  
   第一次按档位解析参数，再调用 `workflow.run_workflow(args)`。`targeted`、经济档、机械档和发布准备（`release_preparation`）使用 `workflow.parser().parse_args([*invocation_args, "--semantic-review-preflight"])`，不传 `--audit-phase`、`--stage-rules`、`--staged-round`。完整档的 `early` / `late` 使用 `workflow.parser().parse_args([*invocation_args, "--semantic-review-preflight", "--audit-phase", audit_phase, "--stage-rules", stage_rules_path])`。`audit_phase` 只能是该阶段的 `early` 或 `late`。`stage_rules_path` 指向内容为 `{"stage_rules": [...]}` 的真实普通文件，不要传裸数组，也不要借用 `--canonical-rule-id` 代替阶段子集。预检不传 `--staged-round`。其中：  
   - `semantic_review_preflight=True`  
   - `internal_semantic_review=None`  
   - `internal_semantic_context_results=None`  
   并传入已冻结的 `target`、`evidence_set`、`target_type`、`run_id`、`execution_profile`、`foundation_task_digest`、`platform`。缺 `--audit-phase` 时完整档会落回未分阶段的整次引擎。  
   进程内与 CLI `main()` 同样消费失败，不要自行拼只含 status/reason/summary 的残缺 JSON：

   ```text
   try:
       workflow_result = workflow.run_workflow(args)
   except (workflow.WorkflowError, OSError, ValueError) as exc:
       if getattr(exc, "failure_stage", None) == "before_rule_selection":
           workflow_result = workflow.before_rule_selection_result(
               exc, evidence_set=getattr(exc, "evidence_set", None)
           )
       elif getattr(exc, "result", None) is not None:
           workflow_result = exc.result
       else:
           raise
   ```

   成功时返回 `{"semantic_review_request": request, "semantic_context_plan": context_plan}`。这不是最终报告。完整档未指定精确选择器时，保留解析器默认的 `semantic_group_ids=None`、`canonical_rule_ids=None`，不改为空列表。等待此次返回后方可进入步骤 5。

5. 预检返回后，主控依据实际处理对象、共享证据及必要关系，从 `context_plan["contexts"]` 中筛选出明确相关的原 context，组成可独立完成的短组，并为每组分配宿主原生新上下文。原 context 是冻结的审阅对象，宿主原生新上下文是承载该相关组的独立模型会话，二者身份不混同。分派前结合完整 `control`、必要正文及完整输出判断组的可执行性，不将一个 `review_family` 固定为长期累积会话，也不强制凑足预算中的8批。总名额为4时，主控占1个，最多允许3个子职责并行运行，不得虚报名额。

   每个原生新上下文完整传入当前 `control`、`permissions`、`untrusted_data`、冻结绑定材料及判断所需的必要关系，不继承父会话完整历史，不传递其他组答案或旧审计结果。同字节正文的组内复用按第3点处理，不减少原身份或材料。Codex 可通过 `fork_turns=none` 显式获取无历史继承的新上下文；不得声称其他平台已验证该行为。原生新上下文不保证认知独立，`cognitive_independence=not_attested` 表示未作此项证明，四项接受条件保持不变。若当前宿主无可用原生新上下文，记录受影响分支的能力缺口并停止该完整档消费，不回退到持续累积单一会话冒充完成，也不以删减义务或截断原文容纳更多项。

   组内按原计划必要顺序逐项消费 `context["request"]`，每项独立交回 `{"context_digest": 当前 context_digest, "reviews": 该项 reviews}`。已有短调用可读取多个原 context，并及时保存本组实际形成的多项原结果，不强制每次模型往返只处理一个 context 或逐文件写入等待。结果按原 context 身份保留，使用现有 `context_results` 数组（原阶段结果文件中的 `contexts`）承载，不合并成新上下文或统一输出，不生成脱离各原 request 的总答案再拆配。普通文件可承载多项原结果，沿用现有写入工具与合并函数，不新增批协议、批摘要、runner、缓存、内容仓或调度器。

   无前序上下文依赖的相关组可由宿主原生并行执行；共享前序上下文的组仍按原顺序执行。主控仅保留归属、结果定位与必要跨组事实，按原 context 身份进行宿主原生并行汇合。阶段内合法乱序可接受。组间或跨规则判断出现分歧时，回读原规则与原证据解释，保留原结果，不投票、不覆盖子结果。单项非阻断发现保留原结果，继续其余可独立执行项；全部项完成并收齐后，步骤6仍使用原 `_merge_semantic_context_results` 合并。真实必需输入缺失、权限拒绝或合同失败关闭仍保护对应分支，不绕过其停止条件。不新增实现代码、调度器、批协议、合并入口或第二套结果合同。

   不得重组 `context_plan`、改写原 `request`，禁止以 `for i in …; judgement-00$i.json` 等方式拼接文件名。不跨独立原生上下文假称共享记忆；压缩后无法确认正文仍可用时真实补读，不将必要重读一概算作冗余。所有原 context 的完整 control、permissions、untrusted_data 及必要关系均独立保留，不因共享正文而合并或简化。每项判断基于自身完整 request 与绑定材料，真实依赖顺序不可绕过。原结果身份与内容不变，不另造批协议或把多项合成一个审阅对象。

   `reviews` 覆盖该项冻结规则子集，字段以该项
   `request["control"]["result_contract"]["required_review_fields"]` 为准。`result_contract` 只规定输出形状，不提供审计事实，也不预填结论。旧语义答案、旧摘要或旧通过结论不能代替本次审计的规则和证据。

   判断次序如下，不得添加规则未写的标准：

   1. 读完整当前规则。先阅读本项 `request` 的完整当前 `control`，核清义务、适用条件、证据角色、例外、平台和判断所需合同，再判断规则要求什么；不凭标题或旧答案推断。
      可在原短调用中直接显示本项完整对象；`index` 为当前上下文的位置：

      ```python
      context = context_plan["contexts"][index]
      print(json.dumps(context["request"]["control"], ensure_ascii=False, indent=2))
      ```

      阅读该完整 `control` 后再核材料和作判断，不按字段过滤，也不只取标题、首几行或摘要。禁止把 `adjudication_note` 或控制正文截成 400/200 字代替完整读取。工具显示截断时，沿既有读取工具补读完本项内容；不能将已输出或文件存在当作已经阅读。不为显示另建脚本、API 或框架。
      已标明为历史的修订或裁决注记只用于追溯，不增加当前规则未写的义务；现行解释仍按其效力使用，不能把所有裁决注记都当成历史或无效。注记与当前规则若有影响判断的冲突，回交主控核对规范事实，不当场改标准。
   2. 核对实际处理对象。按当前绑定材料确认规则所指的对象、实际行为和本次主张的特殊处理。包版本不能替代实际作用对象，也不能仅因版本不同就断言既有例外或批准不再覆盖；按当前义务和实际事项判断，并保留旧记录、旧批准。
      没有明确反例时保留不足或争议。实际新事项需要新处置时，由有权职责沿原流程处理，不能改绑旧批准。初始化义务先核实是否实际发生相应行为，再判断适用性；采用声明不能证明初始化已经触发。
      不能仅凭默认骨架文件缺失、采用计划冲突或专业结果为 `insufficient`，就认定违反当前规则。先核该规则是否实际要求这一对象或行为、义务是否已触发、适用范围与例外，再核是否存在违反证据；不能把未完成或缺少材料直接改写为已证违规，也不能因此免除实际适用的义务。
   3. 阅读绑定支持材料的实际内容，再辨认它证明什么。按判断真正依赖的内容阅读该项 `untrusted_data.resources` 已绑定的材料，包括必要的调用方、配置和规则指定证据。

      同一原生相关规则组内已确实读过且字节未变的相同完整正文，可仅展示一次，即使对应不同路径、平台或角色；每个原 `request` 的完整 `control`、`permissions`、`untrusted_data` 和每条原引用身份仍须保留，不得互换 `evidence_id`、SHA-256、定位符或角色，不改写冻结材料。仍需核对已读正文支持本项义务。

      输出前应结合工具返回容量组织读取批次，互不依赖的字段读取可合并；已读原文可保留在同一执行职责的现有变量或 REPL（交互式执行环境）的内存中，避免过大输出后重叠重读。工具已截断时仍须按既有工具真实补读缺失部分；不得跨独立原生上下文假称共享记忆，压缩后无法确认正文仍可用时亦须真实补读，不将必要重读一概当作冗余。

      SHA-256、导入、签名、文件存在和目录遍历都不能代替内容阅读。未读过的 adapter、矩阵或源码不能写入理由；无法阅读或不能确认时如实说明不足。不要求遍历与本项无关的全部历史。版权与署名须读取实际的权威归属材料（`authority`）和 `LICENSE` 内容，不能沿用旧审计答案。下列对象不是同一事实：

      - 清单或声明，如插件清单中的能力字段；
      - 一次真实运行输出，如词元估算记录或注册表检查输出；
      - 业务验收或追溯关系，如方法是否满足某项验收、图上是否覆盖全部适用关系。

      候选角色名称不能改变文件内容：将一份清单标为运行记录，并不能使其变为运行记录。当前审计自动生成的结果，不可视为被审对象原有记录。

      许可证和权利判断须读到实际 `LICENSE` 条款及相关权利材料；平台投影（adapter）、矩阵、收据和图关系须读到本项判断依赖的内容，包括必要调用处、真实运行记录或关系端点与适用覆盖。文件存在、前几行注释、元数据或数量统计不能代替这些阅读。尚未读取或无法核对的部分保留为不足，不扩大到无关历史或未授权路径。

      敏感材料或密钥的存在与未发现结论，仅限实际读取或扫描覆盖的路径、材料类型和范围；保留原有界扫描的限制。某范围未发现，不能推成全项目或 `HOME` 均无敏感材料。不得扩大权限、读取未授权秘密或输出敏感值。
   4. 按当前规则、实际对象和已读材料作出判断，填写结论与实际引用。`binding_id`、`canonical_id`、`check_method`、`rule_revision_digest` 直接取该项 `request` 的当前规则对象。引用从该规则现有 `evidence_refs` 选择，逐个保留完整对象及原角色、定位和摘要；不另建按规则 ID 或角色手写的字典，不从其他规则或旧请求借用引用。引用角色须符合材料的真实用途。不能按排序重标角色，也不能删去支持原理由的引用，却保留旧理由求通过。角色或引用的纠正涉及语义时，重新审阅受影响本项的判断与理由，同时保留原始值和纠正后的结果。缺少真正支持某角色的材料时保持缺证。单纯格式或拼写错误沿原职责纠正，不新增规划链。语义字段仅填本次实际判断。

   审阅者必须阅读支持判断的材料，并仅引用已经绑定且确实支持理由的 `evidence_id` / SHA-256 / 定位符 / 角色。可选用冻结候选的无重复子集，顺序不限；未知、重复、换摘要、改定位或换角色会被拒绝。按材料种类预选的候选不是判断依据；没有网络调用不能直接推出不处理敏感数据。`PASS` 必须覆盖 binding 声明的全部证据角色。材料无法支持义务时保持 `EVIDENCE_MISSING`，不给予无依据的 `PASS` 或 `NA`。条件规则按义务与实际适用性判断，仅存在被忽略的本地缓存不能直接判违规。规则文本自身冲突、无法同时满足时，本条不能确认目标违规，按现有未获证或待审状态报告。

   将该项原始 `request`、实际判断依据及交回的 `context_digest` 与 `reviews` 立即保存到已允许的持久运行目录。不用旧上下文或事后重建的结果替换本项材料。

6. 全部项交回后，或步骤 4 返回正常的空审阅计划时，按档位调用已有函数，不另写执行器。

   `targeted`、经济档、机械档和发布准备（`release_preparation`）不传 `--audit-phase`、`--stage-rules`、`--staged-round`。先用 `workflow.parser().parse_args(invocation_args)` 取得与首次相同的冻结参数，再执行下面的非 `final` 片段并调用 `run_workflow`。

   完整档的 `early` 或 `late` 必须把阶段参数传进同一次工作流。`audit_phase` 只能是该阶段的 `early` 或 `late`。`stage_rules_path` 是普通文件，内容为 `{"stage_rules": [...]}`。不要传裸数组，也不要借用 `--canonical-rule-id` 代替阶段子集。缺 `--audit-phase` 时，未分阶段的整次引擎会继续执行。先解析阶段参数，再执行同一段非 `final` 片段：

   ```python
   args = workflow.parser().parse_args([
       *invocation_args,
       "--audit-phase", audit_phase,
       "--stage-rules", stage_rules_path,
   ])
   ```

   完整档收尾使用 `final`。这一步不再调用 `run_workflow`。把原 `audit_input` 与各阶段原结果写成 `{"audit_input", "stages"}`，路径交给 `--staged-round`。`parser` 与 `combine_final_stage` 都是已加载的 `workflow` 上的函数。`main()` 见到 `--audit-phase final` 时调用同一个 `combine_final_stage`，`combine_final_stage` 再调用 `combine_staged_round`。组合保留各阶段原摘要，不重签，也不把各阶段拼成一份 semantic-review-result v2。

   ```python
   final_args = workflow.parser().parse_args([
       *invocation_args,
       "--audit-phase", "final",
       "--staged-round", staged_round_path,
   ])
   workflow_result = workflow.combine_final_stage(final_args)
   ```

   非 `final` 片段如下。此时：

   - `semantic_review_preflight` 设为 `False`  
   - `internal_semantic_review` 保持 `None`  
   - `internal_semantic_context_results` 仅在存在实际审阅上下文时传入 `context_results`；当且仅当满足以下全部条件时，该字段保持 `None`：  
     - `request.reason_code == "NO_REVIEW_READY_RULES"`  
     - `request.rules` 为空列表  
     - `context_plan.contexts` 为空列表  
     - `context_plan.blocked_rule_ids` 为空列表  

   此分支不产生内部审阅结果，禁止将 `None` 替换为 `[]`。其他分支保留原 `context_results` 和原停点，不因空 contexts 而略过预算或输入错误。正常空计划沿同一次 Task 的原工作流完成确定性检查或缺证终态，再做步骤 7、8 的校验与六段报告。`final` 不执行这一段。

   若出现预算阻塞、真实必需输入缺失、权限拒绝或其他合同错误，仍沿用原失败关闭逻辑，不得以空 `contexts` 作为替代条件跳过检查。

   进程内按步骤4的异常捕获机制处理，不自行构造结果。具体实现如下：

   ```python
   no_review_ready_rules = (
       request.get("reason_code") == "NO_REVIEW_READY_RULES"
       and request["rules"] == []
       and context_plan["contexts"] == []
       and context_plan["blocked_rule_ids"] == []
   )
   args.semantic_review_preflight = False
   args.internal_semantic_review = None
   args.internal_semantic_context_results = None if no_review_ready_rules else context_results
   try:
       import contextlib
       import io

       workflow_stderr = io.StringIO()
       with contextlib.redirect_stderr(workflow_stderr):
           workflow_result = workflow.run_workflow(args)
   except (workflow.WorkflowError, OSError, ValueError) as exc:
       if getattr(exc, "failure_stage", None) == "before_rule_selection":
           workflow_result = workflow.before_rule_selection_result(
               exc, evidence_set=getattr(exc, "evidence_set", None)
           )
       elif getattr(exc, "result", None) is not None:
           workflow_result = exc.result
       else:
           raise
   ```

   有实际审阅上下文时，`run_workflow` 内部调用 `workflow._merge_semantic_context_results(request, context_plan, context_results)`，合并结果后进行最终化处理。宿主不得重写该合并逻辑，也不得自行构造父级的 `internal_semantic_review`。不同时提供 `internal_semantic_review` 与 `internal_semantic_context_results`。

   如需查看合并结果，可直接调用：
   `workflow._merge_semantic_context_results(request, context_plan, context_results)`
   其中：
   - `request` 为步骤4生成的 `semantic_review_request`
   - `context_plan` 为步骤4生成的 `semantic_context_plan`
   - `context_results` 为步骤5保存的实际审阅结果数组

   返回值为 `(payload, metrics)`，其指标含义如下：
   - `metrics["semantic_model_call_count"]`：表示模型实际调用次数，`None` 表示未观察到，`0` 表示真实零次，正整数表示实测次数
   - `metrics["semantic_rules_sent_to_model_count"]`：表示实际发送至模型的规则数量，`None` 表示未观察到记录，`0` 表示真实未发送，正整数表示实测数量

   **严禁**用 `len(context_results)` 冒充模型调用次数，也**严禁**用请求计划中的规则数量冒充实际提交数量。请求范围、实际提交行数、最终规则状态属于不同口径，必须区分。

7. `quickstart.validate_by_schema_id(runner, result_schema, workflow_result)`  
   读取 schema 校验返回的 `valid` 与原错误，但先沿 Quickstart 的 `is_pre_rule_selection_failure` 判断失败阶段，再选择原包装分支：  
   - 规则选择前失败：`status=BLOCKED`、`failure_stage=before_rule_selection`。即使 schema 合法，外层 Foundation 仍失败：沿原 `state="failed"`、`domain_result=None`、错误码 `SFC2004` 包装，保留原 `failure_stage`、`reason_code` 和 `summary`；不能转入成功传输分支。  
   - 规则已选出后的失败：使用 `exc.result`，信封含 `execution_profile`、`coverage`、`execution_metrics`、`rule_results`；未执行保持 `NOT_RUN`。不要把后置失败改标为选择前失败，不要自行拼只含 status/reason/summary 的残缺 JSON。  
   只有规则已选且结果通过 schema 校验及原执行计划绑定、摘要检查时，才沿原 `succeeded` 路径传输完整 `workflow_result`，其中合法的领域 `BLOCKED` / `FAILED` 不改写为领域通过。成功传输使用原 `quickstart.transport_summary("conformance", "succeeded")` 作为非空 summary，`domain_result` 传完整 `workflow_result`，不用空串或手写通过结论。schema 无效、计划或摘要检查失败、未捕获异常均沿原失败路径处理，不伪造合法结果。  
   沿现有 `wrap_foundation_result` → `assert_foundation_exchange` 保存实际 Foundation Result，并另存本次完整 `workflow_result`，包括选择前的原失败对象；不只存摘要，不因包装中的 `domain_result=None` 丢弃原领域失败材料。

   `result_schema` 沿步骤 2 保持原 Schema ID 字符串。`assert_foundation_exchange` 成功时返回 `None`，保留原断言调用和真实成功或异常记录；不将 `None` 改造为 `valid=true` 收据。不得用 `try/except` 吞掉该断言异常，也不得把命令 stdout/stderr 经 `2>&1 | tail` 截掉断言行；完整输出须保留 OK 或 raised 原文。失败应进入 `failed`，不得靠 exit 0 与残页声称交换成功。语义判断需纠正时，先取得并保留实际重新审阅的结果，再交步骤 8 的原摘要函数呈现；不能在摘要中改写机器状态。

8. `human.render_human_summary(domain_result, group_registry, journey_facts, professional_context=professional_context)`  
   `domain_result` 取已消费的 `workflow_result["conformance_result"]`，包括 `exc.result` 信封。  
   `journey_facts` 带上宿主实际观察的 `semantic_model_call_count`、`semantic_context_count`、`semantic_rules_sent_to_model_count`；未观察则传 `None`，摘要渲染为 `unknown`。不以上下文数或结果数量推算调用次数。

   实际回复完整呈现函数返回的六段：`run_identity`、`decision_scope`、`coverage`、`semantic_cost`、`blocking_findings`、`next_action`。可用自然中文组织正文，但须保留这六段中实际返回的全部字段与含义，不能删减成仅报总数的短结论。真实零、未知和 `partial` 均照实呈现，不因零值而省略。发生后台中止或前台恢复时，说明宿主实际观察到的过程；恢复后的终态不能证明原链曾自主、不中断地完成。

   阻断发现逐项保留 canonical ID、状态、原因与检查范围。`coverage.professional_items` 中已存在的 `partial` / `not_pass` 专业证明单独说明，保留其原声明对象、范围、发现和局限；与专业缺证分开，不混入 canonical 缺证数量，也不把未完成解释为目标全面失败。

   覆盖段直接读取本次 `domain_result` 的计数，不从规则行、方法记录或旧答案重建：

   - 业务语义审阅条数只统计当前请求中 `review_purpose=semantic_conclusion` 对应的原 `semantic_review`，机械对象前提不计入该数，人类摘要 `coverage.semantic_reviews_consumed_count` 为实际写入 `semantic_review` 的规则数。禁止用 `selected_semantic_rule_count`（范围内选定减去确定性规则数）冒充已审阅条数。
   - 原 `coverage` 说明本次范围内、选定、已处理和未运行的规则数量；它不能代替方法保证或可执行覆盖。
   - `coverage.method_assurance` 保留当前方法保证的 `total`、`method_distribution`、`declared_not_proven`、`receipt_succeeded`、`receipt_untrusted`、`receipt_non_success`、`proven`、`not_proven`、`trusted_observed`、`trusted_unavailable` 和 `complete`。这些字段分别反映方法义务、声明或收据观察以及当前可信观察的范围，不是专业证明结论；不展开完整方法记录。
   - `coverage.canonical_executable_coverage` 保留当前 `required_executable_rule_count`、`covered_executable_rule_count`、`complete` 和 `reason_code`，说明应覆盖与已覆盖的可执行规则及其完整性，不把方法义务数量当作规则数量。
   - 上述字段缺失时保持未知，不补成零或 `PASS`；已有的真实零值照实呈现。`method_assurance.complete` 全局常为 false，不因此新增顶层失败条件，也不改变原符合性判断。

   同时保留以下区别：

   - `decision_scope` 说明检查是否走完，保持原 `completion_state` 的 `not_started`、`incomplete`、`scope_processed` 三种状态；`can_prove_complete_conformance` 才表示目标符合。范围内含 `NOT_APPLICABLE` 时用 coverage 的 `scope_rule_label`（范围内规则），不称「全部适用规则」。
   - `semantic_cost` 中的 `semantic_context_count`、`semantic_rules_sent_to_model_count` 与 `semantic_model_call_count` 是不同字段。未观察的调用次数保持 `unknown`。
   - `blocking_findings` 按目标事实、Audit 检查器内部异常（`issue_type` 为 `audit_executor_contract_failure` 或 `execution_or_context_contract_failure`）和缺专业材料分诊。不把内部异常说成用户缺一份材料。
   - `next_action` 仅保留函数给出的一个优先动作，保持其中 `primary_action` 的原值与拼写，不附加新的选择菜单。
   - 专业缺证：当前材料已写明提供方和可核对的检查或接入入口时，按该入口指向；无精确入口依据时写明尚待确认，不编造方法名，不要求用户编写证明文件。
   - 包版本不等于旧操作或旧候选的例外身份，不据此推断旧候选例外已切换，也不建议直接改绑旧批准或旧记录。
   - 不用人类摘要改写 `domain_result` 中的机器状态。规则冲突导致无法判断时，说明 Audit 尚不能作出该条结论，不将其写成已确认的目标违规。

`--semantic-review-stdin` 仍以退出码 2、顶层 `BLOCKED` 和 `SEMANTIC_REVIEW_PRODUCER_UNTRUSTED` 失败关闭。


### 定向单 Task 的校验与传输示例

本示例聚焦 `targeted` 流程中步骤6至8的完整执行路径，不覆盖 `early`、`late` 或 `final` 阶段的逻辑。输入包括同一 Task 的完整 `workflow_result`、本次调用中完整保留的标准错误流（`io.StringIO` 形式，即 `workflow_stderr`）、已知的 Schema ID、路由对象及前文已确定的 `runner` 实例。`journey_facts` 仅包含宿主实际观测到的信息，未观测项保持为 `None`。

```python
result_outcome = quickstart.validate_by_schema_id(runner, result_schema, workflow_result)
state = "failed"
domain_result = None
human_sections = None
errors = []
if quickstart.is_pre_rule_selection_failure(workflow_result):
    domain = workflow_result["conformance_result"]
    errors = [{
        "code": "SFC2004",
        "message": domain.get("summary") or "检查在规则选择前被阻断",
        "details": {
            "failure_stage": "before_rule_selection",
            "reason_code": domain.get("reason_code"),
            "summary": domain.get("summary"),
        },
    }]
elif not result_outcome["valid"]:
    errors = [{
        "code": "SFC2004",
        "message": "Audit domain result violates the method contract.",
        "details": {"schemaId": result_schema, "errors": result_outcome["errors"]},
    }]
else:
    try:
        execution_plan = quickstart.extract_execution_plan(workflow_stderr.getvalue())
        quickstart.assert_plan_event_binding(
            execution_plan, workflow_result["conformance_result"],
            route_identity, human_route["canonical_rule_ids"],
        )
        if execution_plan.get("selection_reason") != human_route["selection_reason"]:
            raise quickstart.RouteError("PLAN_EVENT_BINDING_MISMATCH")
        human_sections = human.render_human_summary(
            workflow_result["conformance_result"], group_registry, journey_facts,
            professional_context=task["params"]["parameters"].get("professional_consumption"),
        )
        state = "succeeded"
        domain_result = workflow_result
    except (KeyError, TypeError, ValueError, quickstart.RouteError) as exc:
        errors = [{
            "code": "SFC2004",
            "message": "Audit domain result cannot render the required human summary.",
            "details": {"error": str(exc)},
        }]
result = quickstart.wrap_foundation_result(
    runner, task, state=state,
    summary=quickstart.transport_summary("conformance", state),
    domain_result=domain_result, errors=errors,
)
quickstart.assert_foundation_exchange(runner, resource.parent, task, result)
```

#### 结果含义与留存


- `state = "succeeded"` 仅表示当前 Task 的校验、计划绑定、选择理由及人类摘要生成均通过，**不改变领域状态**。若原始 `domain_result` 中存在 `FAILED` 或 `BLOCKED`，仍保留其值。
- 示例中的选择前失败、Schema 无效及计划/摘要校验失败，均按原分支包装为 `SFC2004` 错误码，保留原始上下文信息。
- 即使 `domain_result` 为 `None`，原始 `workflow_result` 仍被完整保留，**不因中间失败而丢弃**。
- `human_sections` 为严格顺序的六段对象列表，每段以 `section` 标识，依次为 `run_identity`、`decision_scope`、`coverage`、`semantic_cost`、`blocking_findings`、`next_action`，完整呈现各段的实际字段。
- `assert_foundation_exchange` 成功时返回 `None`，失败时原样抛出异常；不将 `None` 包装成 `valid=true` 收据。
- 所有原始输出、`Foundation Result` 及断言结果均按前文要求完整留存，不以状态码或封装结果替代真实业务行为。


## 专业材料与阶段绑定

`audit_input` 与原始 `Task.parameters.evidence_set` 保持冻结，不作任何修改。晚期 `Task` 通过 `professional_consumption` 输入字段定位原专业证明，由严格读取接口生成阶段内语义证据视图，包含基础证据及 `receipt`、`path`、`sha256`、`evidence_id`，宿主直接使用预检返回的请求及上下文，不手工补写证据集合。

### SFA-COMPOSE-012 的分支字段核对

SFA-COMPOSE-012 的静态扫描消费 `runBranchFieldCheck` 所选 `IfStatement` 字段与直接 `enum`/`const` 原结论，仅以该检查实际返回的原始机械判断为依据。

### SFA-METHOD-003 的入口声明核对

该规则采用 `static_scan` 方法，按原件实际采用的公开入口，选择 `runPublicSurfaceBindingCheck` 或 `runSkillSurfaceBindingCheck` 路径。所选路径按各自原 API 的完整范围核收，业务语义独立审阅。

第一条路径 `runPublicSurfaceBindingCheck` 作用于全部六组直接声明的原始比较，绑定下列来源。

- Skill 声明  

- 路由声明  

- 共同 Method JSON  

- Task Schema  

- Result Schema  

- Parameters Schema  

- DomainResult Schema  

所有七类来源均需提供完整的摘要与闭包，缺失任一来源或其内容失鲜，均阻止通过。

第二条路径 `runSkillSurfaceBindingCheck` 于 Foundation 0.38.0 首次引入，其比较内容如下。

- 实际 Skill 名称与共同 `methodId` 的一致性  

- 实际 `parameterLiteral` 与 `parameterName`、等号及实际 `methodValue` 拼成的直接赋值字符串匹配  

- `implementationRef` 实际文件与 `naturalSkill` 实际文件的一致性  

- `protocolRef` 实际文件与 `commonMethod` 实际文件的一致性  

该路径绑定下列来源。

- `naturalSkill`  

- `parameterDeclaration`  

- `commonMethod`  

- `implementation-reference`  

- `protocol-reference`  

不同角色可指向同一文件，不强制唯一性。该路径的执行独立于第一条路径，其通过与否不依赖于 003 的旧路径结果。

### SFA-METHOD-012 的方法身份核对

该规则在真实同业务方法身份的前提下执行，若未引用 `Registry` 对象，则按原件实际公开入口选择路径。其路径结构与 003 类似，但范围与条件不同。

第一条路径 `runPublicSurfaceBindingCheck` 仅将第1、2组方法身份比较用于本规则判断。第3至第6组 Schema URI 的业务发现保留，其结果独立于本规则的方法身份判断。Skill 声明、路由声明、共同 Method JSON、Task Schema、Result Schema、Parameters Schema 与 DomainResult Schema 共七类来源仍须完整绑定当前原摘要及闭包，缺失或失鲜会阻止通过。

第二条路径 `runNativeEntryBindingCheck` 于 Foundation 0.37.0 首次引入，其比较内容如下。

- 平台 source 实际文件与所选共同清单的一致性  

- `physicalName` 与平台 Skill 名称的一致性  

- `logicalName` 与所选共同方法 `logicalName` 的一致性  

- 共同 `logicalName` 与公共源 Skill 名称的一致性  

该路径绑定下列来源。

- 平台清单  

- 共同清单  

- 声明来源  

- 平台 Skill  

- 公共源 Skill  

五类来源的摘要与闭包必须全部完整。不同角色可指向同一文件。该路径采用目标现有清单及 Skill，不强制新增 Python 路由、Method JSON 或 Task/Result/Parameters/DomainResult 四个接口 Schema。

0.37.0 是该原生入口的首次公开版本，后续版本仍可按原合同采用。`Registry` 仅在真实采用时启用对应路径，固定入口映射不强制登记。未采用 `Registry` 的对象不触发其路径。

### SFA-ARTIFACT-027 的原生投影核对

Foundation 0.38.0 首次公开的 `runNativeProjectionCheck` 支持该原生投影路径，`static_scan` 消费下列四组身份比较。

- 平台 source 实际文件与所选共同清单的一致性  

- `physicalName` 与平台 Skill 名称的一致性  

- `logicalName` 与所选共同 `logicalName` 的一致性  

- 共同 `logicalName` 与公共源 Skill 名称的一致性  

`digest_verification` 消费原 API 的完整字节比较结果。原 API 对直接 YAML `name` 标量的原生名称差异按自身规则处理，Skill 的其余所有字节，以及明示资源对的完整原字节均参与比对，正文、权限、协议和资源差异均保留。

`S` 与 `D` 分别核对自身完整选集、所有实际来源的当前摘要与闭包。部分投影或单一维度通过，不能代整条通过。未完成状态需明确标注。

### SFA-ARTMETHOD-001 与 SFA-ARTMETHOD-005 的固定 Schema 采用核对

该规则组采用 `schema_validation` 方法，消费 Foundation 0.38.0 首次公开的 `runFixedSchemaUseCheck` 原结论。

- **SFA-ARTMETHOD-001** 核对实际制品类型、合同身份及版本声明的 `declaration` 原比较。当声明范围、资源与闭包自身完整时，独立保留真实 PASS 或 FAIL。即使父结论因可选 005 实现不支持而为 partial，父级 partial 也原样保留，不强制补全。

- **SFA-ARTMETHOD-005** 需核对 `declaration` 及实际实现所使用的 Schema、同一数据、校验早于业务解释的 `implementation` 原比较。实现不完整或不支持时，真实状态为未完成，不从 001 补齐 005。只有真实反例才可判定为 FAIL。

该规则作用范围为固定实际采用链的静态消费，非通用语言或一般控制流解析器，不认证任意运行效果。

### SFA-REGISTRY-005 的协议结构核对

该规则通过 `diagnoseRegistry` 执行 `schema_validation`，作用范围为实际引用且已采用的 `Registry` 公开协议对象的原 schema 检查。`semantic_review` 需额外核对业务对象标签与真实输入输出，非空或结构合法不证明语义正确。未采用该协议的对象不强制登记。

### SFA-WORKER-011 的共享实现核对

该规则按实际对象分别消费静态扫描和字节核验原结论。

- `static_scan` 消费 `runStaticReferenceCheck` 原件，验证实际复用同一共享实现的真实入口及固定文件引用是否已确认。动态 resolver 不在有限检查范围内，普通映射不视为 Registry，路径存在不证明同职责。

- `digest_verification` 消费 `runSelectedArtifactCheck` 原件，验证真实共享实现副本及可信既有字节基准的原 bytes 结论。若缺真实复制组或基准，不造对象。

`Registry` 仅在真实采用时保留其路径，未采用无需登记。

### 共同接受边界

- 原 reader/conclusion、同 Task 目标、实际绑定来源、当前摘要与闭包必须全部对应完整。

- 缺必要原件、来源失鲜、选集不完整或接口不支持时，保留真实不足状态，目标反例与未完成状态需分开说明。

- 专业项版本政策原样执行，按高版本政策接受与实际机械方法完成分别判断。

- 完整选集、共同业务条件、公共性、共享职责及全部领域义务由独立语义审阅判断。

- 既有原件与固定阶段视图继续使用，不修改旧 Task 或运行受检业务。

- 以目标真实采用为依据，不为配合工具强制补 Python、Registry、Method JSON 或新 Schema。

当用户选择的 Foundation 只读检查覆盖目标对象，且目标已明确承诺同级技能目录逐字节同步时，优先复用可合法回读的已有证明和目录核验原件。需新核验且具备相应授权时，由所选专业环境调用其精确已发布公开接口 `verifyPeerAdapterDirectories({ request, peerRoots })`。该调用仅执行真实目录的完整文件集合、原始字节、闭包和技能逻辑映射的只读比较，不涉及目标业务脚本运行、构建或安装，也不复制或扩充冻结 Bundle 的命令接口。无需为此让目标新增受管文件锁（`managed-file-lock`）或 Profile（能力档案）。实际采用的精确环境须在结果中记录。

原调用参数 `{request, peerRoots}` 与原返回结果必须完整保存至获准的目标外专业输出目录。其中，`request.peers` 覆盖本次声明的全部实际目录；`logicalMappings` 依据现有声明与真实技能映射；`peerId` 唯一，`hostId` 可因实际消费者重复；`pathCategory` 与 `peerRoots` 对应真实位置。根目录参与比较不代表其为编辑真源或登记过的 Profile。调用失败时保留原始错误，不转换为违规或编造部分成功结果，不新增包装 `kind` 或证明格式。

Foundation 沿既有 `native_role_separation` 专业检查核对共同权威、源与生成物关系、同步机制，通过 `sourceRefs` 直接引用实际依据和本次目录核验的原输入、原返回。仅覆盖部分或无法确认的项保持 `insufficient`。沿现有 `proof-create/read-proof` 保存和读取；专业语义 `pass` 本身不是机械字节核验，目录 `verified` 也不是权威判断。

调用方在获准范围内为原 `late Task` 指定 `proof_root`。现有阶段证据视图仅在该根内严格回读同一检查中 `sourceRefs` 直接绑定的目录核验原输入、原返回，将其作为普通读取记录（`receipt`）纳入同一请求的实际引用。证明、Task 目标、原调用参数、原返回及精确方法范围必须对应。`sourceRefs` 不授予额外读取权限，不追随命令或任意外根路径，也不靠 `basename` 猜文件；合法 `reuse`、`scan`、`refresh` 沿用原动作身份。结果生产、上下文核收和 `final` 收尾均回读同一份阶段视图。

当前 3.0.0 请求中，`SFA-SOURCE-001` 与 `SFA-SOURCE-002` 的 `digest_verification` 方法需目录字节核验与同目标、覆盖完整共同权威及同步关系的原专业结论共同支持。目录一致仅为局部证据；若对应角色检查尚为 `insufficient`、对象尚不明确、缺少原结果，或完整共同权威与同步关系未由原专业结论确认，整条规则不能记为 `PASS`。真实完整组合须由完整目录核验与完整专业角色结论共同构成。来源要求由原请求的 `review_purpose` 和方法身份确定；删除原输入、返回或引用不能让缺口变为高版本机械通过。原已完成机械输出优先，旧合同兼容不变。此目录核验不自动覆盖 `SFA-SOURCE-013` 的发行资源闭包、其他规则或整个目标。

原机械前提已实际核查必要材料、获准位置和缺失内容，并由本次合法引用确认 `DIGEST_INPUTS_MISSING` 时，保留原 `EVIDENCE_MISSING` 正确终态。真实缺输入与对象未知、未执行、专业范围不足不同，不能互换；局部目录结果不能掩盖该缺口，尚未完成的范围不记通过。

`final` 仅从原始 `late Task` 重建同一证据视图，核验原 `Task`、父请求、上下文与引用，不再次调用目录核验。字节漂移、替换或任务错配仍拒绝通过。取得专业证明不自动使 `FOUNDATION-012/014` 语义通过，原对象、范围、不完整项和限制仍须参与判断。

高版本专业证明项按原政策接受；这与证明复用、本次是否调用检查以及原调用是否完整完成分别说明。报告保留 `selected`、`action` 及原 `conclusion` 的 `outcome`、`scope`、`limitations`。`action=scan` 或 `refresh` 只是所选动作，不能证明已完成本次目录核验；`reuse` 也不是新扫描。实际尝试但未开展、部分完成或完整完成，以原结果为准。不得因 `version_policy` 断言本次未调用检查，也不得因原 reader 的 `not_pass` 撤销已批准的高版本接受。

### 一、SFA-CONTEXT-033的原义务、效力与新修订

SFA-CONTEXT-033的原义务与warning效力维持不变，仍由semantic_review与static_scan共同承担。semantic_review基于真实技能与长参考资料，判断长材料何时需要读取、条件是否可理解，以及是否要求每次触发均无差别加载。语义审阅不要求先取得静态扫描结果，也不强制目标新增context-budget或其他业务JSON。static_scan则仅核对对象前提已确认的完整实际固定阅读引用、解析基准、来源字面量与目标普通文件之间的关系，其输入为runStaticReferenceCheck的原始结论及匹配reader，不判断自然语言条件，不引入context-budget或其他扩展字段。原skill_structure_scan角色保留，conditional_loading_source为语义审阅提供真实源；机械前提继续保留object_scope_contract，并使用fixed_reference_result绑定实际原件。

在语义缺条件但固定引用有效时，可出现语义失败而静态通过的情形；反之，语义通过但引用未核全时，整体仍判定为未通过。两种方法的判断结果独立，局部路径或字节结果不代替完整业务判断。静态方法不承担语义完整性验证责任，语义方法亦不替代静态核验。

### 二、SFA-PLAT-005的原义务、效力与新增语义方法

SFA-PLAT-005的原义务、block效力、static_scan与digest_verification保持不变，新增独立的semantic_review并形成新修订。semantic_review实际阅读共同源、适配规则、生成器与平台清单包装，判断业务派生关系、是否重复维护协议，以及本轮选集是否完整；纯计划、目录角色或成功日志不能代替其功能。语义审阅不要求先取得静态结果。本条不新增公共证明格式或共享聚合器。

static_scan仅核对同一映射的完整源与生成根方向，以及真实固定生成器/清单引用，必须分别消费runSourceGeneratedCheck与runStaticReferenceCheck两种公共原结论及匹配reader。两者同Task、同目标，并通过相同声明文件的当前原摘要相接；此项绑定不代替审阅者确认真实同一映射及完整选集。digest_verification使用真实可信的先前生成收据或权威源基准，消费runSelectedArtifactCheck对完整声明输出的原始bytes结果；允许各平台确有不同的适配，不能以本次输出的当前哈希自证。

原generator_adaptation_facts、projection_manifest_surface角色继续提供源材料，drift_check_record用于字节校验；语义绑定新增source_projection_authority角色。静态机械前提保留object_scope_contract，增加fixed_projection_reference_result与source_generated_direction_result两种原件角色。所有方法独立核收，不以新修订回写历史覆盖旧修订、绑定历史、Task及原结果。

### 三、状态区分、真实发现与方法计数含义

公共检查返回不完整时，需按实际事实区分：已从当前绑定的有效来源读到真实固定引用，原记录明确报告必需目标缺失，保留checked_required_input_missing与EVIDENCE_MISSING；仅动态、不支持、未执行或无法确认关系的情况，保留NOT_RUN与原始不足。不能仅根据incomplete标签推断状态。

已确认的方向冲突或字节漂移保留FAIL，不以其他方法通过覆盖。适用项缺少必要原件亦不得通过。每个方法独立核收，局部路径或字节结果不代替完整业务判断。旧修订、绑定历史、Task及原结果保持原义，不以新修订回写历史覆盖。

新增的SFA-PLAT-005语义方法令当前方法集合增加一项，实际计数由权威生成器派生，不代表任何一项已经执行或通过。

## 核清实际对象再判断

每条现行义务的判断，必须基于当前实际承担的角色与已绑定材料，不得依据目录名、角色标签或文件数量推导额外要求。历史父工程记录和受审身份，不能单独证明当前插件承担某种生态角色，或已经采用制品图、Registry、领域规范组合。判断流程应遵循以下顺序：先确认受检对象在当前上下文中的真实角色与采用关系，再据此确定本条义务所需的必需材料。同一对象在不同规则下的事实解释必须保持一致，不同义务可得出不同结论，禁止将其他义务的结论直接复制为本条结论。

- `scripts` 目录不自动代表内部实现不公开。若 `README` 或 `Skill` 中明确说明用途、调用方式与支持边界，相关辅助工具可属于公开支持范围；未独立注册为 `Skill` 本身，不能证明违规。不得将全部脚本自动视为公开能力。
- `author` 是作者元数据，`LICENSE` 中的版权所有者是权利归属，两者无需一致。须先查阅约定事实源、版权条款、变更依据与所需授权；若无法获取相关材料，应说明缺证，不得仅因作者与版权主体不同即要求修改作者字段或历史版权。
- 公开包快照与父工程配置属于不同范围。包内缺失某份工程文件，不能证明父工作区未采用、豁免或校验；无法取得获准工程材料时，报告本次材料缺口，不得断言整个工程违规，也不得据此免除真实义务。
- `userInvocable` 仅说明人类可调用，不能单独证明其承担领域助手角色，或已由 `Registry` 解析为方法提供方。判断须基于真实角色与解析对象。
- 插件编辑真源与消费者站点内容真源为不同对象。消费者站点配置的权威性，不能证明插件自身多副本维护符合规范；对同一插件源码及投影关系的判断，须使用一致的事实解释。
- 平台族与宿主安装标识为不同计数对象。须先核实合并、别名与映射关系，再判断支持范围冲突。错误的计数理由应纠正；若存在独立真实反例，仍保留对应结论。

条件前提未核清时，不能将“未提供父工程材料”作为目标缺证；必须先确认当前对象是否实际依赖该材料，且该依赖是否构成义务。无采用且规则不要求采用的情形，必须基于实际范围与事实引用判断，不得预填 NA 或补造治理文件。

CONTEXT-003的审阅以当前Task的入口材料组织方式、代表任务合同与按需读取条件为判断对象，不强制目标提供历史任务的计量证明。确认是否触及干预线时，需核对本轮已取得的Foundation公共估算及其来源、输入摘要、逻辑源、平台投影和最大值，计量仅作为判断适用条件的依据，组织方式仍须独立审阅正文内容。同轮CONTEXT-001已有原件仍可按原合同合法读取，不因本次审阅流程而失效。

已取得的CONTEXT-002原计量结果通过同一Task审阅上下文中的untrusted_data.resources数组传入，各资源行的mechanical_observations数组承载这些原计量数据。原数据保留measurements、foundation_source_authority、assessment_required与原status等字段，其中assessment_required为原评估需求数组，不作状态改写。EVIDENCE_MISSING状态保持不变，已取得的计量不因干预评估未完成或对象前提未知而被丢弃，也不得据此推定为通过。这些数据供本项审阅使用，不能自动产生审计结论，也不新增证明格式。

合法引用仅限当前冻结请求允许回读的原件，不得倒填Task或context信息。确有需要且获准时，可沿现有公共估算调用对已绑定原文进行复测，保留原返回结果。无法合法读取或复测时，应认定Audit审阅输入不足，保留未完成状态，且不将补证义务转嫁至目标。超过干预线仅触发组织设计审阅流程，仍需实际读取并核对正文内容，不得直接判失败，也不因存在引用或按需材料即判定通过。

## 条件判断、恢复与同对象一致性

对六条条件规则，须从当前请求准确读取 `reason_code`、`allowed_statuses` 与证据角色。`METHOD005_NEW_ENTRY_ABSENT` 与 `METHOD011_SHARED_ENTRIES_ABSENT` 为本请求中实际列出的代码示例，不得以近义代码替代；适用条件未知时，`reason_code` 应选择对应 `*_CONDITION_UNKNOWN`，其值为标识符而非状态，实际 `status` 由 `allowed_statuses` 字段定义。`rationale` 中提及的代码仅用于说明判断依据，不得替代 `reason_code` 字段；真正支持判断的引用必须完整放入 `evidence_refs`。

原 context 内必要纠正须基于原始请求与已保存的判断进行核对。若返回 `REVIEW_REQUIRED` 或 `EVIDENCE_MISSING` 仅因代码拼写错误，且原材料支持对应分支，应在原上下文内重新审阅并修正，保留首次原结果与纠正后的真实返回，再交由原合并与 finalize 流程。代码拼写修正不改变事实判断，材料不足或前提未知时仍应明确保留不足状态，不可批量修改状态或泛化 finalizer，不得重复触发其他 context 的重跑。

METHOD-004 的业务价值流与方法划分不因未采用 Registry 而退出；METHOD-002 仍保留对 Registry 的限定要求。PROGRAM-012/013 适用性以当前义务、适用范围与实际行为为准，位于 `scripts`、仅读或不调用模型、属辅助工具者，不自动排除；需检查适用程序的实际输入输出、退出与错误合同。ARTIFACT-028 按其依赖、安装与环境诊断对象判断，未联网不构成排除实际配置存在性诊断的理由。所有判断均基于当前事实，不预设通过或失败，未确认对象或材料不充分时应明确保留不足。

PLAT-033 需比对同一能力、同一次变更的实际发布承诺。交叉查阅 `README`、`Skill`、变更记录与版本说明中关于“已分发”与“尚未发布”的表述，确认是否指向同一对象与时期。无关功能的包版本变化不能自动消解真实矛盾，不同版本安装示例亦不能单独证明冲突。专业结论中的版本关系应以当前消费返回的实际结果为准，同版不视为高版本接受，不预填目标结论，引用支持判断的具体材料。

## 提交按用途区分的审阅结果

新冻结请求与结果使用3.0.0版本规范。每项审阅严格保留 `review_purpose`、`binding_id`、`canonical_id`、`check_method`、`rule_revision_digest`，以及 `status`、`reason_code`、`rationale`、`evidence_refs`。原Task、父请求、上下文及四摘要绑定关系不变，不自行构造或重签父级结果。旧v1外部材料仍处于待审状态，旧v2内部结果仅依据旧合同读取，不得补足用途后视为新判断。

`review_purpose=semantic_conclusion` 仅对应原 `semantic_review` 方法，用于判定完整业务义务是否成立；六条条件规则继续按本次 `condition_contract` 判断，保留原必需角色与合法 `reason_code`。机械对象缺失不自动导致整条规则不适用，机械前提亦不可替代语义判断。

`review_purpose=mechanical_object_premise` 仅用于请求中已明确绑定的 `static_scan`、`schema_validation`、`digest_verification` 三种机械方法。每种方法须独立读取其完整规则与本次绑定的输入材料，核清实际待检对象及输入条件。纯机械规则不产生 `semantic_review` 贡献；对象前提仍须由 LLM 核清。沿用请求中的 `object_scope_contract` 角色和现有证据种类。目标缺少语义角色或专业证明，不阻断对象前提审阅；不要求目标补造否定声明、Registry、Schema 或证明。

`evidence_refs` 中的 `evidence_id`、`role`、`locator`、`sha256` 四字段共同决定实际待检对象选集，其效力不可在 `rationale` 中通过自然语言描述排除已引用对象，即使该对象被列为背景信息，仍须作为待检实体纳入处理范围。所选制品的结构检查引用精确待检文件与实际采用的 Schema；字节检查引用实际声明逐字节对应的文件及基准。`source_tree` 的引用将自动纳入树内所有对应原记录作为选集组成部分，不能仅引用整树却声称仅检查单个文件。选集边界严格服从当前专业入口的既有输入合同，不得将局部文件选取逻辑泛化至所有入口。

采用说明与业务正文仍须完整阅读以确认事实与语义，阅读它们并不自动使其成为当前方法的 JSON 待检对象。在所选制品的结构与字节两个维度中，现有消费者按当前合同识别 Schema、原证明及只属于另一维度的对象。其余显式引用必须具备对应的原检查记录，不能用自然语言范围解析或后缀过滤改变现有消费边界。

核对能力制品的图引用关系时，须引用本 Task 已绑定的完整源树、原生索引、完整声明能力端点与原生追溯路径、配置与锁信息，以及对应原 `proof/reader`。Registry 有效索引核对须引用完整源树、准确的 `manifest`、`catalog` 及可选的 `project` 信息。SKILL 正文仍须完整阅读，用于内部与公共用途的语义分类，但不得混作 Registry 的 JSON 输入。本前提只界定对象与输入条件；同对象原件的实际消费仍沿既有合同进行，不由前提产生机械通过或失败结论。

| 实际情况 | status及reason_code | 应交回的事实 |
| --- | --- | --- |
| 对象不存在，且本义务不要求采用 | NOT_APPLICABLE；`static_scan` 用 `STATIC_WIRING_NOT_ADOPTED`，`schema_validation` 用 `MACHINE_SCHEMA_NOT_ADOPTED`，`digest_verification` 用 `BYTE_CORRESPONDENCE_NOT_DECLARED` | 引用完整已查范围和不要求采用的依据，仅本方法不适用 |
| 已实际检查必要输入并确认缺失 | EVIDENCE_MISSING；分别用 `STATIC_INPUTS_MISSING`、`SCHEMA_INPUTS_MISSING`、`DIGEST_INPUTS_MISSING` | 写明本义务要求的材料、已核对的获准位置及实际缺失内容；Audit预检未做或专业不可用不属于这类目标缺证 |
| 对象和输入存在 | REVIEW_REQUIRED，三方法均可用 `MECHANICAL_OBJECTS_PRESENT`；`digest_verification` 存在受管文件范围外基准可用 `BYTE_BASELINE_OUTSIDE_MANAGED_FILES`；`schema_validation` 存在Foundation合同外Schema可用 `SCHEMA_OUTSIDE_FOUNDATION_CONTRACTS` | 引用实际对象；只能据此选择或消费同对象同方法同范围的真实专业输出，不从前提产生机械PASS或FAIL |
| 对象或适用性无法确认 | REVIEW_REQUIRED，`MECHANICAL_OBJECT_SCOPE_UNKNOWN` | 说明未知范围，保留原方法未执行；无材料不等于未采用 |

`reason_code` 必须填写请求中列出的精确代码，不得仅在 `rationale` 中说明，亦不得以散文解析补足代码。每项前提必须具备原四字段 `evidence_refs` 和非空理由，引用支持本方法的事实。前提禁止使用 `PASS`、`FAIL`；同规则下不同方法应分别返回，可一个为 `NA` 而另一个待检查，不得使用 `MECHANICAL_OBJECTS_ABSENT` 总括新3.0判断，不得拼接代码、编码列表或重复同身份 `review`。原判断只涉及可定位的拼写或引用问题时，应在原 `context` 真实复核，保存首次及纠正后的返回；材料不足则保持不足，不批量修改状态。

已有真实机械终态继续优先保留；前提自身不构成第二条方法贡献。`STATE-007/TASK-015` 使用现有指令与说明性样例，不要求旧运行记录，不运行目标，不将LLM阅读视为Schema校验。专业版本政策和职责不变，实际调用、原证明复用与政策接受分别说明；目录比较的局部 `verified` 不自动证明共同源码权威、生成关系或整条业务义务通过。

## 按实际原因说明阻断

六段报告须逐项保留原 `reason` 与 `evidence`，说明对象、检查范围、责任与下一步。仅当具体反例证明目标与规则要求不一致时，才要求目标修复。目标材料未提供时，说明实际所需材料与获准范围；原专业检查因输入或能力不足未完成时，保留其具体范围；`Audit` 未派发、未完成对象判断、漏接材料或内部异常由 `Audit` 处理。不得将全部缺证与未执行项归责于目标，不得要求目标改业务、补造证明或创建私有治理 `JSON` 来掩盖 `Audit` 未完成。

`next_action.primary_action` 保持函数原值与含义。`fix_failed_rules` 仅解释为修复已有充分反例的目标问题，不将 `Audit` 未完成项混入其中。状态与责任仍在现有报告中说明，不新增责任分类状态机，不修改旧报告或原结果。

## 专业动作来源与报告生成上下文

调用 `render_human_summary` 时，通过可选参数 `professional_context` 传入已校验的 `Task.parameters.professional_consumption`。该参数仅用于补充报告中 `selected` 与 `action` 的显示内容，不改变 `domain_result`、`Task`、`audit_input`、专业结论或高版本接受政策的任何语义。

若无有效 `professional_context`，或同一提供方在多个原始 `late Task` 中出现且上下文无法唯一对应，则 `selected`、`action`、`scan_performed_this_time` 均为 `None`，人类报告中应写为 `unknown`。不得依据 `version_policy` 推断本次未执行扫描，不得将 `action=scan` 的计划状态误写为已完成扫描。实际检查范围与执行状态仍以原始 `conclusion` 中的 `outcome`、`scope`、`details.review` 记录为准。

完整档必须先成功完成 `combine_final_stage` 的阶段绑定核验，再从最终 `Task` 的 `stage_results` 取原 `late Task` 的定位，沿已有 `_load_stage_json` 和 `_task_parameters` 读取原输入。不得用最终 `Task` 的缺省选择覆盖原 `late` 选择，也不得添加第二个 `reader` 或持久账本。Quickstart 两处原始摘要调用仅从当前已校验 `Task` 传入该参数。

现有步骤8调用签名更新为：
`human.render_human_summary(domain_result, group_registry, journey_facts, professional_context=professional_context)`

其余六段顺序与动作不变。

报告中的取消、权限拒绝及恢复过程，按实际来源说明操作主体。人类业务回答、主控操作和工具返回须区分；主控经宿主消息恢复会话，不因消息使用 user 角色就变成人类指令。主控取消重试不记为用户取消，不产生新的用户授权，也不从墙钟中扣为人类等待。无法确认主体时保留未知，原失败、操作记录及恢复结果分别保留。

## 2026-11-04：规则恢复的静态审阅边界

### 两条机器方法的范围

`ERROR002`的S复用既有受限材料安全扫描，仅表示本条实际绑定的完整错误合同、源码和说明性样例，在同一内容摘要下完成了有限形状观察。原发现必须保留；扫描发现合成标记不自动等于泄密，扫描完成也不表示脱敏或整条业务合格。L另行判断稳定错误含义、真实敏感性及授权、诊断信息是否足够。缺原观察、选集不全、摘要变化、截断或不可读时，S不能完成；`sanitized`或`used_as_stable_code`的自报值不能替代观察。

`TASK019`的C实际核对示例与其采用的权威结构；L核对唯一权威内容及修订、示例对应关系，以及公开校验方式是否实际消费该内容或准确对应同一合同修订。通用校验器实现版本无须与领域结构版本相同。D只检查真实采用的内容摘要、受管副本或内容寻址关系，基准须来自既有合法独立权威。通过`Foundation0.36.0`的`runSelectedArtifactCheck`及原`reader`消费`checks.bytes`，不把`checks.schema`、`bytes=null`、相同版本字符串或本次自算摘要当成D通过。经实际核查没有采用这种字节关系且不要求新增时，仅D可有据不适用，C/L仍须完成；真实合同要求的既有基准缺失、尚未核清对象、公共工具不支持，分别保留缺证、未知和专业覆盖不足。

### 证据角色和交付边界

`ARTIFACT001` 允许真实静态政策与源码说明承载生命周期设计，须依据实际采用的锁及生命周期义务索取原证据，无关专业证明不得替代。  
`ARTIFACT025` 不要求生成帮助，沿用 `source_file` 等已有材料类型；人工维护的一致帮助可进入语义审阅，但声明生成关系时仍须核验真实来源。  
`ARTIFACT027` 不改变规则与绑定，仅按现行四平台公共入口生成条件取得新观察，不额外要求联合发行。

`METHOD003` 仅基于现有条件处理实际对象前提，`L` 继续完整审阅，不引入新限制或覆盖范围。  
`METHOD012` 历史专业覆盖差额如实保留；当存在匹配的 `runNativeEntryBindingCheck` 真实原件时，可消费其实际覆盖的四组身份比较部分，但不自动补齐 `L` 或其他未覆盖义务，也不表示全部专业责任已通过。

## METHOD009 机械对象前提与适用性判定

当内部实现在用户可见界面或宿主技术管理界面中出现时，须进行完整语义审阅。static_scan 适用于实际采用的结构化内部身份与普通公共目录、注册项或接线之间，可按既有合同核对的对应关系。若经充分核查确认该对象未被采用且本义务不要求新增，则仅静态检查不适用，完整语义义务仍须保留。工具不支持、身份或适用性未知、必要材料缺失，均视为未完成状态，不能认定为不适用。已有结构的路径或别名尚未核清时，也应保留未知。

在机械对象存在时，使用 REVIEW_REQUIRED 与 MECHANICAL_OBJECTS_PRESENT 标记前提状态，并消费同对象原有检查结果。对象或适用性未知时使用 REVIEW_REQUIRED 与 MECHANICAL_OBJECT_SCOPE_UNKNOWN。确认必要输入缺失时使用 EVIDENCE_MISSING 与 STATIC_INPUTS_MISSING。对象存在但公共工具未覆盖时，消费者保留 NOT_RUN。若经充分核查确认无该对象且不要求新增，则使用 NOT_APPLICABLE 与 STATIC_WIRING_NOT_ADOPTED，该状态仅适用于 static_scan，semantic_review 仍须独立完成完整判断。前提不能返回 PASS 或 FAIL，也不能从语义通过复制机械通过。

普通内部引用、正向推荐、否定例子、用途明确的技术管理可见性均需进行完整语义审阅。公共 CLI调用内部实现属于正常封装行为，不能据此违规，须核对真实公共业务合同。自然语言正文仅用于语义理解，不自动转化为 Registry 的 JSON 待检对象。引用已有结构与源范围作为对象前提判断依据，逐个给出原状态和精确代码。

证据角色沿用 object_scope_contract 和原四字段，所有材料均使用现有文件，无需新建专用文档。沿用 Registry 实际采用者检查及其他既有专业职责，不新增本地检查器。历史 Task 及审计结果保留原始内容，新 Task 采用新修订规则重新验收。当前原生前提审阅用途为 mechanical_object_premise，所有操作均基于已有证据与原四字段，不预置验收场景结论。


## 2026-11-09：三条新修订的方法分工

### 1. 新修订方法身份与职责划分

SFA-CONTEXT-002 第8修订、SFA-ARTMETHOD-001 和 SFA-ARTMETHOD-005 第4修订均新增 `semantic_review` 职责，作为独立于原有 `static_scan` 与 `schema_validation` 的新判断环节。三条规则在业务义务、效力范围、平台适用性及原终态判定逻辑上保持不变。新 `semantic_review` 仅用于新创建的 Task 判断，旧修订版本、原计量状态及已有结果维持不变，不因新规则重签为新判断结果。

新方法职责如下：
- **SFA-CONTEXT-002**：依据实际计量核对超线后的减量或职责拆分评估、结果及必要业务信息保留情况。
- **SFA-ARTMETHOD-001**：核验正式制品的性质、操作方法、类型、版本及权威来源的可解析性。
- **SFA-ARTMETHOD-005**：独立核验解释前的选择依据，确认所选合同与实际对象、版本及兼容政策的一致性。

---

### 2. SFA-CONTEXT-002 的 S 实际计量与 L 执行边界

**S 实际计量来源与触发机制**  
S 读取同一逻辑源和全部声明投影的实际字节，保留估算器身份、来源、全部估算值及最大值。当计量达到 2400 词元时，触发评估要求，但完整计量本身不因此失败。预算声明或 `intervention` 字段不能替代真实计量，亦不构成减量或拆分成立的证明。

**L 的证据角色与材料要求**  
L 使用两个角色执行核验：
- `entry_material_organization`：材料种类为 `manifest`、`policy`、`source_file`。
- `skill_structure_scan`：材料种类同上。

L 需核对超线后的减量或职责拆分评估、结果，以及必要业务信息是否保留。阈值以下时，依据完整计量判断条件义务；以下情形不预填“不适用”，也不强制补造实施历史：
- 缺少完整原计量；
- 仅有声明未提供实际计量；
- 材料不足；
- 已有结果违反要求。

**资源行读取与上下文一致性**  
计量沿 `untrusted_data.resources[*].mechanical_observations` 传入 L。按当前 `canonical_id` 与 `binding_id` 选择本条资源行，再核对同一 Task、原 `canonical_lineage`、S 状态、`measurements`、阈值及 `foundation_source_authority`。不得移用 SFA-CONTEXT-003 的结论，不改写原计量状态，不新增上下文字段、证明或目标预算文件。

**assessment_required 的含义边界**  
`assessment_required` 仅保留由实际计量触发的评估需求与已有材料，不能视为评估已完成。缺完整原计量时，不得签发完整判断。

---

### 3. SFA-ARTMETHOD-001 与 SFA-ARTMETHOD-005 的 L 完整义务与执行路径

**共同证据角色与材料要求**  
两条规则均使用 `public_artifact_method_contract` 角色，材料种类为 `manifest`、`policy`、`source_file`。必要合同、方法正文与真实采用资料必须进入读集。

**正式文稿与机器格式的适用性**  
正式文稿合同不能因非 Schema 而整体不适用；仅当依据完整材料确认：
- 无机器格式采用；
- 不要求新建机器格式；
方可有据判定对应 C 分支“不适用”。

**混合采用的核收规则**  
混合采用情形需分别核收。以下情形保留原状态：
- 缺输入；
- 对象未知；
- 工具不支持；
- 真实违反。

**C 的真实专业比较义务**  
- **SFA-ARTMETHOD-001**：保留实际声明比较，沿用 `runFixedSchemaUseCheck` 专业结果及读取路径核实际机器合同。
- **SFA-ARTMETHOD-005**：除实际声明比较外，还需完成三项真实比较：
  1. 真实实现的 Schema；
  2. 同一数据；
  3. 验证先于业务解释。

**禁止替代行为**  
版本字串、通用运行声明或样例结构通过，不能替代对应方法所需的原比较。L 不得补签仍适用的 C。

---

### 4. 阶段依赖与结果核收

**专业依赖共享机制**  
现有 `professional_dependencies` 在同一绑定的各方法间共享。两条 ARTMETHOD 新绑定保留 `foundation` 依赖，避免 C 在专业结果返回前提前执行。

**L 的正文义务归属**  
L 的正文义务仍由 Audit 判断，不因新方法引入而转移。

**SFA-CONTEXT-002 的本地计量机制**  
计量由既有本地机械路径产生，新绑定无外部专业结果依赖；但不免除真实计量与同 Task 绑定要求。

**阶段与方法账本机制**  
方法账本、阶段汇合、严格身份及摘要校验沿原路径执行，新方法不能用旧结果或局部工具成功代替。

**权威数量派生机制**  
当前方法及数量从权威源生成，不手填历史分母。