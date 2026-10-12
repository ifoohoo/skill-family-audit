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
| 领域工作流 | 本 Skill 的 `scripts/conformance_workflow.py` | `run_workflow`、`_merge_semantic_context_results`、`before_rule_selection_result`、`WorkflowError` |
| 人类摘要 | 本 Skill 的 `scripts/conformance_human_route.py` | `render_human_summary` |

`runner` 来自同一平台包的受管 Bundle。产品单选用
`human_entry_clarification` 的 `question` 与 `options`；专业扫描多选用
`professional_scan_clarification`。`human_entry_decision` 与
`professional_scan_decision` 供宿主程序读取内部字段，不要把内部字段展示给用户。

## 入口（宿主程序）

`human_entry_decision(request, method_args, products=declared_units_or_none)`
返回 `ask_profile`、`intent`、`execution_profile`、`selection_reason`、
`clarification`。`ask_profile` 恒为 false；未出现完整、确定性或精确组时
`execution_profile` 为普通预筛。无绝对路径时 `clarification` 只问路径。
唯一绝对路径若是含多个声明产品的工作区根，仍问选哪个产品；已绑定
`--target` 或 `evidence-set`，或路径已指向其中一个产品时不再问。
`products` 仅在声明发布单元多于一个时传入；不要把 `generated/platforms`
或 `packages/` 子目录列为产品。

`human_entry_clarification(...)` 在仍需提问时返回：

```text
{"question": str, "options": [{"name", "path", "difference", "recommended", "label"}, ...]}
```

没有问题则返回 `None`。把该对象直接交给问答控件：展示 `question` 与选项的
名称、路径、差别和推荐标记。不要附加内部字段。

目标确定后、`prepare_conformance_evidence_document` 之前，宿主按真实公开入口构造候选。用户已点名专业提供方时，无论请求是否携带绝对路径，都承接该选择；按当前目录的 `name`、`label`、`entry_ref` 对齐对应行，读取 `id` 并将已明确的标识列表交给 `professional_scan_decision`。只有仍未决定的选择才调用专业扫描多选，它与产品单选分开。候选是本次会话数据，不做成持久目录，也不携带可执行命令。

`professional_scan_clarification(candidates)` 有可选项时返回。下例仅列部分展示字段；完整选项还含公开入口 `entry_ref` 和已有证明状态 `proof_present`：

```text
{"question": "本次要加入哪些专业检查？可多选，也可暂不扫描。",
 "options": [{"name", "purpose", "limitation", "recommended", "label"}, ...]}
```

没有可加入的扫描时返回 `None`，不虚构选项。展示专业名称、用途、局限、推荐标记，以及公开 `entry_ref` 和已有证明状态 `proof_present`；内部标识、证据 JSON 和临时路径不对外展示。推荐项不预填为已选。

`professional_scan_decision(candidates, selection=None)` 返回
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

提供方描述仅从当前平台或源码清单的 `professionalProviders` 读取，通过 `load_professional_providers` 获取。宿主依据实际安装状态发现所选公开入口，不得基于证明正文中的命令进行追溯，亦不可将登记状态误认为已安装发布。已有专业证明时优先调用对应 reader；若需刷新，则另写新证明。把真实宿主选择和可定位的 `proof_root`/`proof_path` 写入 `--professional-consumption`；reader 原始 JSON 有实际返回就完整加入，交由 `extract_business_parameters` 处理，进入同一 `create_foundation_task` 与 `validate_by_schema_id` 流程。

当证明可定位但 reader 未返回原始 JSON 时，仍应传入真实宿主选择与证明定位信息，`reader_result` 字段可省略，不得伪造 reader 结果、状态、动作或入口可用性。不得手填 status、version_relation、reader_status、baseline 或通过摘要。工作流从这些输入调用 `consume_professional_proof`，严格读取并核对身份与原始结论，基准由同一清单派生。同版本缺少 reader 返回仍未通过；有实际返回则完整传递。版本政策仅执行 `semver.valid/compare` 判断：可读高版本身份按政策通过，低版本未通过并建议刷新；同版本须比较未经改写的完整共同证明，并核验顶层 provider 的 `id`、`version`、`entry`，任一缺失或错配均不通过。

高低版本政策不变，同版匹配后再采用 reader 的 `pass` / `not_pass` / `unavailable`。FOUNDATION-012/014 使用该次消费结果。结果出现在 `conformance_result.professional_consumption` 与 `render_human_summary` 中的 `coverage.professional_items` 及 `blocking_findings`。摘要中需列出通过与未通过项，保留原 `conclusion` 的范围、发现与局限。完整且 `completion=complete` 的原生 `not_pass` 使用已有 `REVIEW_REQUIRED`，沿用九级顺序取待处理动作；缺证、未完成或读取不可用情形分别保留其真实原因。

现有发布收据消费仍委托 release-skill 0.9.17 的 `verify-records` 接口，与专业证明的 `read-proof` 分开处理。未知提供方按未知输入拒绝；`docs` 的 `siteBuildingRequired` 为 `false`，机械证明身份为 `skill-family-doc-render`。

## 本次请求与材料留存

入口阶段保留本次完整审计请求及后续业务补充原文，包括工作区根、产品身份、例外和运行目录。仅当后续回复只有专业选择时，才沿用前次请求。按这些事实调用原入口解析器，已确定的 `target`、`target_type`、`execution_profile` 和精确选择器不得回退默认值。业务原话由宿主保存，不向 Task 添加合同之外的字段。

`full` / `targeted` 使用用户指定或明确允许的目标外持久运行目录；未获准写入的目录不可使用。沿用宿主普通文件写入工具，不新增 writer、恢复程序或状态文件。专业准备先于 Task 冻结；已取得的 producer、reader 原返回和消费材料在冻结前保存。没有实际 reader 原返回时省略该字段，仍传入真实选择和证明定位，由原严格消费及版本政策判断。

每步返回后立即保存真实对象：证据集合、原始请求及参数、原 Task、预检与审阅请求、逐项原始审阅、最终领域结果、Foundation Result 和实际回复。不要等临时进程退出或变量丢失后再补，不要用摘要、旧请求或新建 Task 重构原对象。序列化只保存原值；对象缺失就报告缺失。材料保留供回读，不按临时清理逻辑删除。

## 加载同一平台的模块

目标、档位和专业选择已确定，且允许开始后，先在新的 Python 进程执行下段，再在同一进程接续原八步，避免混入其他平台的同名模块。`QUICKSTART_SKILL_MD_ABSOLUTE_PATH` 只换成本次已发现平台包中的 Quickstart `SKILL.md` 绝对路径；Node 和 `PATH` 沿用该平台的现行运行要求。本段只加载并核验运行依赖，不创建 Task，也不执行领域检查。

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

顺序不能倒置：先从已发现的 Quickstart 定位 `platform-manifest.json`，以清单所在目录作为 `platform_root`；把同平台 checker 所在目录加入 `sys.path`，并在加载前注册 `sys.modules["conformance_check"]`，再调用 `find_foundation_runner(platform_root=platform_root)`。它返回经原 Bundle 校验的 runner 路径；缺模块、缺 Bundle 或跨平台绑定时保留原异常并停止，不换用其他来源。

`mechanisms-cli.mjs` 与 `adoption-cli.mjs` 位于同一平台的 `foundation/quickstart-profile`，不在 `profile-spi`。后续 Quickstart 函数通过 `quickstart` 调用，领域工作流函数通过 `workflow` 调用，摘要函数通过 `human` 调用；`platform_root`、`platform` 和 `runner` 均沿用上段实际返回值，不另猜路径或重写传输调用。

## 审阅消费（同一 Task）

每一步均等待当前函数返回，读取返回值后进入下一步。宿主将步骤 6 转入后台时，沿现有前台等待或 TaskOutput 等支持的续接方式等待真实领域结果，再完成步骤 7、8；不因内部任务标为完成、进程退出 0 或只读到执行计划就宣称 Task completed。后台中止、前台恢复与实际回复各自保留；未观察的退出码和成因保持未知。已获取 Task、预检请求或某项 `reviews` 时直接复用，不因屏幕未显示输出而重复调用创建或预检。不新增 runner、缓存、状态文件或恢复程序。身份字段从当前返回值或该项 `request` 读取，不手抄修订、binding 或摘要。

1. `document = prepare_conformance_evidence_document(target)`  
   返回 `{"evidence_set": [...]}`，复用 `_derived_evidence_set`。按同一平台 Quickstart「输入」完成已获准外部材料的承接，再将证据集合写入上文已允许的目标外持久文件，作为后续 `--evidence-set`。已有显式证据文件则按原合同直接绑定，不重复派生或偷换材料。

2. `parameters, resource = extract_business_parameters("conformance", method_args)`  
   专业消费文件用 `--professional-consumption`，仅含真实宿主选择、可定位证明和实际取得的 reader 原始返回；没有 reader 原返回时省略 `reader_result`，不补造 JSON；该内容进入同一 `parameters`。工作流再调用既有消费路径。Task 创建前须沿用 Quickstart `run` 中已有的档位解析与参数绑定：  
   `human_route, group_registry, human_module, human_intent, route_identity = resolve_conformance_human_route(request, method_args, runner)`。  
   此处 `request` 为本次完整业务原话。将返回的 `execution_profile` 写入 `parameters`；非空 `semantic_group_ids`、`canonical_rule_ids` 也从该返回值绑定。  
   不得假定 `extract_business_parameters` 已自动复制这些字段。将同一档位、选择器和目标传给后续两次 `run_workflow`，不得通过省略参数回退默认。  
   `parameter_schema, result_schema = resolve_method_contract(platform_root, "conformance")`  
   `parameter_schema` 与 `result_schema` 均为该函数返回的 Schema ID 字符串，直接传给 `validate_by_schema_id`；不转为 `Path`，也不按文件路径解析。调用参数的类型错误由原职责纠正，不修改校验器、序列化器或原结果。  
   保留 `extract_business_parameters` 返回的全部参数，包括由 `--target-type` 映射的 `scope_selector`、原 `evidence_set` 和专业消费。读取  
   `validate_by_schema_id(runner, parameter_schema, parameters)` 的返回值，仅当 `valid is True` 时才创建 Task；否则按原错误停止，不丢弃缺项继续。

3. `task = create_foundation_task(runner, resource, operation_id=run_id, method="conformance-audit", parameters=parameters)`  
   等待返回后再取 `foundation_task_digest = call_foundation(runner, "digest-document", {"document": task})["digest"]`。  
   立即保存该 `task` 的完整原值，再进行后续调用；不使用记忆中的旧 Task 或另一次创建结果替换本次返回值。

4. 沿 Quickstart `run` 的既有参数组装，并调用  
   `execution_method_args("conformance", routed_args, run_id, foundation_task_digest=foundation_task_digest)`  
   取得 `invocation_args`。`routed_args` 包含原方法参数、已解析档位、非空精确选择器和原 `profile_selection_reason`；不要手写一份不完整的 `argparse.Namespace`。  
   第一次使用 `workflow.parser().parse_args([*invocation_args, "--semantic-review-preflight"])` 取得参数后调用 `run_workflow(args)`，其中：  
   - `semantic_review_preflight=True`  
   - `internal_semantic_review=None`  
   - `internal_semantic_context_results=None`  
   并传入已冻结的 `target`、`evidence_set`、`target_type`、`run_id`、`execution_profile`、`foundation_task_digest`、`platform`。  
   进程内与 CLI `main()` 同样消费失败，不要自行拼只含 status/reason/summary 的残缺 JSON：

   ```text
   try:
       workflow_result = run_workflow(args)
   except (WorkflowError, OSError, ValueError) as exc:
       if getattr(exc, "failure_stage", None) == "before_rule_selection":
           workflow_result = before_rule_selection_result(
               exc, evidence_set=getattr(exc, "evidence_set", None)
           )
       elif getattr(exc, "result", None) is not None:
           workflow_result = exc.result
       else:
           raise
   ```

   成功时返回 `{"semantic_review_request": request, "semantic_context_plan": context_plan}`。这不是最终报告。完整档未指定精确选择器时，保留解析器默认的 `semantic_group_ids=None`、`canonical_rule_ids=None`，不改为空列表。等待此次返回后方可进入步骤 5。

5. 按 `context_plan["contexts"]` 的现有顺序逐项处理，一项完成后再进入下一项。对每一项，先读完整当前规则，再核实际处理对象、阅读绑定材料，最后判断并引用当前证据；按以下四步完成后，交回 `{"context_digest": 当前 context_digest, "reviews": 该项 reviews}`。  
   不要先生成全部判断再拆成多个文件，不要自行把多项合成一批。禁止用 `for i in …; judgement-00$i.json` 这类批写拼两位数文件名。不要在同一助手消息里后台并行多个 Agent。短调用应对 `for context in context_plan["contexts"]` 审阅 `context["request"]`，保存一项结果后再处理下一项；全部项保存后进入步骤 6。
   同一宿主会话内逐项读取、判断和保存，不为每项另起模型、门禁或独立审阅，也不在扫描中修复目标。单项非阻断发现保留原结果，继续本批其余可独立执行的项；全部项完成并收齐问题后，再沿步骤 6 合并。真实必需输入缺失、权限拒绝或原合同失败关闭仍保护对应分支，不绕过原停点。

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
   3. 阅读绑定支持材料的实际内容，再辨认它证明什么。按判断真正依赖的内容阅读该项 `untrusted_data.resources` 已绑定的材料，包括必要的调用方、配置和规则指定证据。共用材料已经确实读过且字节未变时，可以沿用，但要确认它支持本项判断。SHA-256、导入、签名、文件存在和目录遍历都不能代替内容阅读。未读过的 adapter、矩阵或源码不能写入理由；无法阅读或不能确认时如实说明不足。不要求遍历与本项无关的全部历史。版权与署名须读取实际的权威归属材料（`authority`）和 `LICENSE` 内容，不能沿用旧审计答案。下列对象不是同一事实：
      - 清单或声明，如插件清单中的能力字段；
      - 一次真实运行输出，如词元估算记录或注册表检查输出；
      - 业务验收或追溯关系，如方法是否满足某项验收、图上是否覆盖全部适用关系。
      候选角色名称不能改变文件内容：将一份清单标为运行记录，并不能使其变为运行记录。当前审计自动生成的结果，不可视为被审对象原有记录。
      许可证和权利判断须读到实际 `LICENSE` 条款及相关权利材料；平台投影（adapter）、矩阵、收据和图关系须读到本项判断依赖的内容，包括必要调用处、真实运行记录或关系端点与适用覆盖。文件存在、前几行注释、元数据或数量统计不能代替这些阅读。尚未读取或无法核对的部分保留为不足，不扩大到无关历史或未授权路径。
      敏感材料或密钥的存在与未发现结论，仅限实际读取或扫描覆盖的路径、材料类型和范围；保留原有界扫描的限制。某范围未发现，不能推成全项目或 `HOME` 均无敏感材料。不得扩大权限、读取未授权秘密或输出敏感值。
   4. 按当前规则、实际对象和已读材料作出判断，填写结论与实际引用。`binding_id`、`canonical_id`、`check_method`、`rule_revision_digest` 直接取该项 `request` 的当前规则对象。引用从该规则现有 `evidence_refs` 选择，逐个保留完整对象及原角色、定位和摘要；不另建按规则 ID 或角色手写的字典，不从其他规则或旧请求借用引用。引用角色须符合材料的真实用途。不能按排序重标角色，也不能删去支持原理由的引用，却保留旧理由求通过。角色或引用的纠正涉及语义时，重新审阅受影响本项的判断与理由，同时保留原始值和纠正后的结果。缺少真正支持某角色的材料时保持缺证。单纯格式或拼写错误沿原职责纠正，不新增规划链。语义字段仅填本次实际判断。

   审阅者必须阅读支持判断的材料，并仅引用已经绑定且确实支持理由的 `evidence_id` / SHA-256 / 定位符 / 角色。可选用冻结候选的无重复子集，顺序不限；未知、重复、换摘要、改定位或换角色会被拒绝。按材料种类预选的候选不是判断依据；没有网络调用不能直接推出不处理敏感数据。`PASS` 必须覆盖 binding 声明的全部证据角色。材料无法支持义务时保持 `EVIDENCE_MISSING`，不给予无依据的 `PASS` 或 `NA`。条件规则按义务与实际适用性判断，仅存在被忽略的本地缓存不能直接判违规。规则文本自身冲突、无法同时满足时，本条不能确认目标违规，按现有未获证或待审状态报告。

   将该项原始 `request`、实际判断依据及交回的 `context_digest` 与 `reviews` 立即保存到已允许的持久运行目录，再进入下一项。不用旧上下文或事后重建的结果替换本项材料。

6. 全部项交回后，或步骤4返回正常的空审阅计划时，先用 `workflow.parser().parse_args(invocation_args)` 取得与首次相同的冻结参数，再次调用 `run_workflow`。此时：

   - `semantic_review_preflight` 设为 `False`  
   - `internal_semantic_review` 保持 `None`  
   - `internal_semantic_context_results` 仅在存在实际审阅上下文时传入 `context_results`；当且仅当满足以下全部条件时，该字段保持 `None`：  
     - `request.reason_code == "NO_REVIEW_READY_RULES"`  
     - `request.rules` 为空列表  
     - `context_plan.contexts` 为空列表  
     - `context_plan.blocked_rule_ids` 为空列表  

   此分支不产生内部审阅结果，禁止将 `None` 替换为 `[]`。其他分支保留原 `context_results` 和原停点，不因空 contexts 而略过预算或输入错误。正常空计划沿同一次 Task 的原工作流完成确定性检查或缺证终态，再做步骤 7、8 的校验与六段报告。

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
       workflow_result = run_workflow(args)
   except (WorkflowError, OSError, ValueError) as exc:
       if getattr(exc, "failure_stage", None) == "before_rule_selection":
           workflow_result = before_rule_selection_result(
               exc, evidence_set=getattr(exc, "evidence_set", None)
           )
       elif getattr(exc, "result", None) is not None:
           workflow_result = exc.result
       else:
           raise
   ```

   有实际审阅上下文时，`run_workflow` 内部调用 `_merge_semantic_context_results(request, context_plan, context_results)`，合并结果后进行最终化处理。宿主不得重写该合并逻辑，也不得自行构造父级 v2 的 `internal_semantic_review`。不同时提供 `internal_semantic_review` 与 `internal_semantic_context_results`。

   如需查看合并结果，可直接调用：
   `_merge_semantic_context_results(request, context_plan, context_results)`
   其中：
   - `request` 为步骤4生成的 `semantic_review_request`
   - `context_plan` 为步骤4生成的 `semantic_context_plan`
   - `context_results` 为步骤5保存的实际审阅结果数组

   返回值为 `(payload, metrics)`，其指标含义如下：
   - `metrics["semantic_model_call_count"]`：表示模型实际调用次数，`None` 表示未观察到，`0` 表示真实零次，正整数表示实测次数
   - `metrics["semantic_rules_sent_to_model_count"]`：表示实际发送至模型的规则数量，`None` 表示未观察到记录，`0` 表示真实未发送，正整数表示实测数量

   **严禁**用 `len(context_results)` 冒充模型调用次数，也**严禁**用请求计划中的规则数量冒充实际提交数量。请求范围、实际提交行数、最终规则状态属于不同口径，必须区分。

7. `validate_by_schema_id(runner, result_schema, workflow_result)`  
   读取 schema 校验返回的 `valid` 与原错误，但先沿 Quickstart 的 `is_pre_rule_selection_failure` 判断失败阶段，再选择原包装分支：  
   - 规则选择前失败：`status=BLOCKED`、`failure_stage=before_rule_selection`。即使 schema 合法，外层 Foundation 仍失败：沿原 `state="failed"`、`domain_result=None`、错误码 `SFC2004` 包装，保留原 `failure_stage`、`reason_code` 和 `summary`；不能转入成功传输分支。  
   - 规则已选出后的失败：使用 `exc.result`，信封含 `execution_profile`、`coverage`、`execution_metrics`、`rule_results`；未执行保持 `NOT_RUN`。不要把后置失败改标为选择前失败，不要自行拼只含 status/reason/summary 的残缺 JSON。  
   只有规则已选且结果通过 schema 校验及原执行计划绑定、摘要检查时，才沿原 `succeeded` 路径传输完整 `workflow_result`，其中合法的领域 `BLOCKED` / `FAILED` 不改写为领域通过。成功传输使用原 `transport_summary("conformance", "succeeded")` 作为非空 summary，`domain_result` 传完整 `workflow_result`，不用空串或手写通过结论。schema 无效、计划或摘要检查失败、未捕获异常均沿原失败路径处理，不伪造合法结果。  
   沿现有 `wrap_foundation_result` → `assert_foundation_exchange` 保存实际 Foundation Result，并另存本次完整 `workflow_result`，包括选择前的原失败对象；不只存摘要，不因包装中的 `domain_result=None` 丢弃原领域失败材料。

   `result_schema` 沿步骤 2 保持原 Schema ID 字符串。`assert_foundation_exchange` 成功时返回 `None`，保留原断言调用和真实成功或异常记录；不将 `None` 改造为 `valid=true` 收据。不得用 `try/except` 吞掉该断言异常，也不得把命令 stdout/stderr 经 `2>&1 | tail` 截掉断言行；完整输出须保留 OK 或 raised 原文。失败应进入 `failed`，不得靠 exit 0 与残页声称交换成功。语义判断需纠正时，先取得并保留实际重新审阅的结果，再交步骤 8 的原摘要函数呈现；不能在摘要中改写机器状态。

8. `render_human_summary(domain_result, group_registry, journey_facts)`  
   `domain_result` 取已消费的 `workflow_result["conformance_result"]`，包括 `exc.result` 信封。  
   `journey_facts` 带上宿主实际观察的 `semantic_model_call_count`、`semantic_context_count`、`semantic_rules_sent_to_model_count`；未观察则传 `None`，摘要渲染为 `unknown`。不以上下文数或结果数量推算调用次数。

   实际回复完整呈现函数返回的六段：`run_identity`、`decision_scope`、`coverage`、`semantic_cost`、`blocking_findings`、`next_action`。可用自然中文组织正文，但须保留这六段中实际返回的全部字段与含义，不能删减成仅报总数的短结论。真实零、未知和 `partial` 均照实呈现，不因零值而省略。发生后台中止或前台恢复时，说明宿主实际观察到的过程；恢复后的终态不能证明原链曾自主、不中断地完成。

   阻断发现逐项保留 canonical ID、状态、原因与检查范围。`coverage.professional_items` 中已存在的 `partial` / `not_pass` 专业证明单独说明，保留其原声明对象、范围、发现和局限；与专业缺证分开，不混入 canonical 缺证数量，也不把未完成解释为目标全面失败。

   覆盖段直接读取本次 `domain_result` 的计数，不从规则行、方法记录或旧答案重建：

   - 语义审阅条数以预检 `semantic_context_plan["contexts"]` 各项 `canonical_ids` 合计为准（完整档权威打包条数），人类摘要 `coverage.semantic_reviews_consumed_count` 为实际写入 `semantic_review` 的规则数。禁止用 `selected_semantic_rule_count`（范围内选定减去确定性规则数）冒充已审阅条数。
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
