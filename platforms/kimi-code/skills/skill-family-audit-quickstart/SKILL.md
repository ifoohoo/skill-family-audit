---
name: "skill-family-audit-quickstart"
description: 把自然语言审计请求路由到两个只读公开方法，并用 Foundation Quickstart Profile 绑定调用方证据与领域结果。
user-invocable: true
internal: false
argument-hint: "<自然语言请求，如：对 /path/to/project 进行规范检查>"
---
<!-- platform-projection: platform=kimi-code; logical=skill-family-audit:quickstart; source=skills/skill-family-audit/quickstart -->

# skill-family-audit:quickstart

## 目的

本入口先按请求种类分诊。能力咨询转交当前已发现平台包中的 `skill-family-audit:help`。检查 Audit 自身运行环境、规范包或静态平台投影，转交当前已发现平台包中的 `skill-family-audit:setup`。规范检查或发布审计才路由到 `skill-family-audit:conformance-audit` 或 `skill-family-audit:release-audit`。

审计请求里，用户说明检查哪个项目、检查到什么程度即可。证据文件、临时目录、平台执行器和审阅结果绑定由本入口与宿主协作处理。审计目标项目的工程配置、结构或公共调用关系时，走规范审计。

本入口只做分诊、输入绑定和完整档审阅衔接。完整档的领域合同、认可来源和接受
条件以 `skill-family-audit:conformance-audit` 为准；Task、预检、逐项审阅、
消费和报告的调用顺序以该方法的 `refs/host-semantic-review-consumption.md`
为准。调用方可以绕过本入口，直接按方法 ID 调用两个业务方法，或运行候选投影中
对应方法的脚本；quickstart 不是调用前置条件。

规范检查由 Quickstart 显式选择执行档位。普通请求使用 `economy`，语义模型调用数为 0；已知语义组、组名称或 canonical rule ID 使用 `targeted`；明确只查确定性规则使用 `mechanical`；明确完整审计或准备发布才使用 `full`。底层方法省略档位时仍兼容为 `full`，该兼容规则不适用于人类入口。

## 咨询和环境诊断先转交

先确认请求目的，沿当前已发现平台包中的公开入口处理：

1. 若用户咨询能力、适用范围、依赖关系、支持范围或需下一步指引，转交 `skill-family-audit:help`，结束流程，不启动审计。
2. 若用户意图检查 Audit 自身运行环境、规范包或静态平台投影（如「环境诊断」「先看看环境缺什么」），转交 `skill-family-audit:setup`。诊断、计划与安装确认沿用该入口合同，不推进为目标项目审计。
3. 若用户明确要求审计目标项目（含工程配置），则进入 `human_entry_decision` 与专业扫描选择流程。完整保留本次请求及后续补充内容，按实际已确定的工作区根、产品身份、范围限制与运行目录说明检查对象；缺失事实应注明“尚未确定”，不依赖固定措辞抽取，也不要求回显内部技能安装路径。审计范围限制及读取、安装、发布、修改文件等权限边界须原意保留，不能遗漏任何限制。
4. 若用户要审计已有发布材料，转交 `skill-family-audit:release-audit`，沿原发布输入合同处理。

用户若明确表示“暂不开始检查”，应说明已选路由与已识别范围后停止。专业扫描选择未回答时，仅澄清仍缺的业务信息；不得将非交互会话、提问失败或尚未回复视为“空选择”。尚未回答时，只允许探测 `professional_scan_decision(candidates, None)` 或省略 `selection`；不得调用 `professional_scan_decision(None, [])`。该命令仅在用户明确空选择之后使用。在目标或选择未确定前，禁止开启符合性技能审阅、派生证据、创建 Task 或启动专业扫描。`help` 与 `setup` 转交不新增注册方法。

当用户已点名具体专业提供方时，无论请求中是否包含绝对路径，均承接该选择。宿主使用当前专业目录中的 `name`、`label`、`entry_ref` 对齐所选项，从对应目录行读取 `id`，并将已明确的标识列表传递给 `professional_scan_decision(candidates, selection)`。不强制传 `None` 重问，不硬编码提供方标识，也不新建自然语言解析器。名称、入口或多项选择存在歧义时，仅询问缺失部分。`candidates` 为 `None` 时沿用当前目录，已构造候选则复用同一份。选择决定不替代目标识别；本次完整请求、已确定参数与精确选择器继续传入原始人类路由。

当 `can_start_audit` 为 `true` 且用户允许开始后，宿主按 `authorized_scans` 加载实际存在的所选公开专业入口。登记不等于已安装；入口不存在时如实标记为不可用，不可虚构入口或扫描器。仅执行所选入口的只读能力，已有证明优先复用，专业返回与 Audit 消费分别按各自合同完成。

用户明确回复「暂不扫描」或明确空选择后，下一条工具先执行下面的决定命令。未返回允许开始时停止，不读取其他脚本、不创建 Task。允许开始后，用本次完整请求和已确定的方法参数调用 `human_entry_decision`，按返回的档位继续：只有 `economy` 且没有待澄清问题时，才在同一命令中执行单次 `run`；`full` / `targeted` 不执行这个快捷调用，随后加载同一平台的符合性技能及 `refs/host-semantic-review-consumption.md`，按原工序完成审阅。明确机械档仍按原机械档合同执行，不套经济档模板。空选择不是不适用，也不是通过。

`SKILL_MD_ABSOLUTE_PATH` 使用本 Quickstart 技能文件的绝对路径。`USER_REQUEST_TEXT` 使用本会话最新真实审计请求，逐字保留后续补充的工作区根、产品身份、例外和运行目录原句；仅当后续回复只有专业选择时，才沿用前次请求。`METHOD_ARGS_JSON` 使用已经确定的方法参数列表；没有参数才用 `[]`，不得丢弃已选产品或精确选择器。`TARGET_ABSOLUTE_PATH` 使用本次已确定工作区根，不能替换为安装根或默认产品子目录。反斜杠和双引号按代码语法转义，不改变原话。stdout 的决定字段供宿主接续，不作为最终审计报告。

```text
PYTHONDONTWRITEBYTECODE=1 python3 -c 'import argparse, importlib.util, json, sys, tempfile, uuid
from pathlib import Path
skill = Path(r"SKILL_MD_ABSOLUTE_PATH").resolve()
script = skill.parent / "scripts" / "quickstart_route.py"
spec = importlib.util.spec_from_file_location("quickstart_route", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
decision = mod.professional_scan_decision(None, [])
out = {"answer_state": decision.get("answer_state"), "can_start_audit": decision.get("can_start_audit"), "empty_selection_means_not_applicable": decision.get("empty_selection_means_not_applicable"), "empty_selection_means_pass": decision.get("empty_selection_means_pass"), "authorized_scans": decision.get("authorized_scans")}
if decision.get("answer_state") == "empty" and decision.get("can_start_audit") is True:
    try:
        method_args = json.loads(r"""METHOD_ARGS_JSON""")
        route = mod.human_entry_decision("USER_REQUEST_TEXT", method_args)
        out["entry_decision"] = route
        if route.get("execution_profile") == "economy" and route.get("clarification") is None:
            manifest_path = mod.find_platform_manifest(None)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            platform = manifest["platformId"]
            checker = next(path for path in manifest_path.parent.glob("skills/*/scripts/conformance_check.py") if path.is_file() and not path.is_symlink())
            cspec = importlib.util.spec_from_file_location("conformance_check", checker)
            host = importlib.util.module_from_spec(cspec)
            sys.modules["conformance_check"] = host
            sys.path.insert(0, str(checker.parent))
            cspec.loader.exec_module(host)
            target = Path(r"TARGET_ABSOLUTE_PATH")
            out["scope"] = mod.identified_scope_statement(str(target), "economy")
            document = mod.prepare_conformance_evidence_document(target)
            directory = Path(tempfile.mkdtemp(prefix="audit-evidence-")).resolve()
            evidence_path = (directory / "evidence-set.json").resolve()
            evidence_path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
            result = mod.run(argparse.Namespace(request="USER_REQUEST_TEXT", platform=platform, method_args_json=json.dumps([*method_args, "--evidence-set", str(evidence_path)]), run_id=uuid.uuid4().hex, platform_manifest=None, foundation_runner=None))
            out["execution_status"] = result.get("execution_status")
            out["human_summary"] = result.get("human_summary")
    except Exception as exc:
        out["error"] = str(exc)
print(json.dumps(out, ensure_ascii=False))
'
```

已有可定位的专业证明时，执行以下消费材料准备流程。`reader_result` 仅在实际取得原始 JSON 时完整传入；若无实际返回，则省略该字段，仍将真实宿主选择与证明位置交由原 consumer 处理。原 consumer 严格读取证明后按版本政策判断：可读高版身份按政策通过，低版本未通过并建议刷新，同版本缺少 `reader_result` 仍未通过。无可用证明时，沿用原缺证合同处理逻辑，不手填通过摘要。

目标使用本次已确定的工作区根路径；仅当原请求明确指定当前工作区且未更改根目录时，才使用当前工作目录，禁止缩至 `packages/`。`provider_id` 从所选 `entry_ref` 对应的同一目录行中读取。消费文件仅包含真实宿主选择、证明位置及实际取得的 `reader_result` 原始 JSON，不得补造 `status`、`version_relation`、`reader_status`、`baseline` 或通过摘要。专业准备须在同一个 Task 冻结前完成；已取得的 producer、reader 原始返回与消费材料均需先行保存，不因缺失 reader 而伪造返回。

下方命令为单项消费示例；选择多项时，按同一现有 `items` 合同收齐所有已选项，不压缩为一项，亦不另建 Task。命令沿用本次完整请求与 `METHOD_ARGS_JSON` 中已确定的方法参数。`economy` 模式仅执行一次 `run`，返回 `human_summary` 与 `execution_status`；`targeted` 模式仅准备证据与专业消费文件，随后读取符合性技能的 `refs/host-semantic-review-consumption.md`，继续同一 Task 的预检、实际审阅、消费、校验和报告。`full` 同样先准备证据与专业消费文件并读取该参考文档，但按 `early`、`late`、`final` 分阶段绑定：首个真实阶段内联一次 `audit_input`，后续阶段回读原文件并核对摘要，`final` 只组合原 `stage_results`。不得把 `quickstart_route.run` 的单次调用当成整次完整档。`full` / `targeted` 的输出文件存入用户指定或明确允许的目标外持久运行目录，不得改放临时目录。

`SKILL_MD_ABSOLUTE_PATH`、`USER_REQUEST_TEXT`、`TARGET_ABSOLUTE_PATH` 和 `METHOD_ARGS_JSON` 的替换规则与空选择分支一致。`RUN_DIRECTORY_ABSOLUTE_PATH` 仅替换为已授权的持久运行目录；目录尚未确定时，仅确认必要存储授权，无需用户填写内部证据文件。`SELECTED_ENTRY_REF` 来自前一步所选 `entry_ref`；`PROOF_ROOT`、`PROOF_PATH` 来自实际证明定位。`HOST_SELECTION_JSON` 仅含本次真实的 `selected`、`applicable`、`entry_available`、`action` 值；复用旧证或入口不可用时保留真实状态，不硬填为 `true` 或 `scan`。`READER_RESULT_PATH_OR_EMPTY` 在实际取得 reader 原始 JSON 时替换为该文件路径，无实际返回时替换为空字符串；非空路径读取失败仍保留原错误，不当作缺省处理。平台使用清单中的 `platformId`，不写死平台名。反斜杠与双引号按代码语法转义，不改写原话。

```text
PYTHONDONTWRITEBYTECODE=1 python3 -c 'import argparse, importlib.util, json, sys, tempfile, uuid
from pathlib import Path
skill = Path(r"SKILL_MD_ABSOLUTE_PATH").resolve()
script = skill.parent / "scripts" / "quickstart_route.py"
spec = importlib.util.spec_from_file_location("quickstart_route", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out = {}
try:
    manifest_path = mod.find_platform_manifest(None)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    platform = manifest["platformId"]
    checker = next(path for path in manifest_path.parent.glob("skills/*/scripts/conformance_check.py") if path.is_file() and not path.is_symlink())
    cspec = importlib.util.spec_from_file_location("conformance_check", checker)
    host = importlib.util.module_from_spec(cspec)
    sys.modules["conformance_check"] = host
    sys.path.insert(0, str(checker.parent))
    cspec.loader.exec_module(host)
    rows = mod.load_professional_providers(manifest_path)
    entry_ref = "SELECTED_ENTRY_REF"
    same = [row for row in rows if isinstance(row, dict) and row.get("scanEntryRef") == entry_ref and isinstance(row.get("id"), str) and row.get("id").strip()]
    if len(same) != 1:
        raise RuntimeError("catalog row for the selected entry_ref is not exactly one")
    provider_id = same[0]["id"].strip()
    method_args = json.loads(r"""METHOD_ARGS_JSON""")
    route = mod.human_entry_decision("USER_REQUEST_TEXT", method_args)
    if route.get("clarification") is not None:
        raise RuntimeError("audit target still requires clarification")
    target = Path(r"TARGET_ABSOLUTE_PATH").resolve()
    document = mod.prepare_conformance_evidence_document(target)
    if route["execution_profile"] in {"full", "targeted"}:
        directory = Path(r"RUN_DIRECTORY_ABSOLUTE_PATH").resolve()
    else:
        directory = Path(tempfile.mkdtemp(prefix="audit-evidence-")).resolve()
    if directory == target or target in directory.parents:
        raise RuntimeError("evidence directory is inside the workspace")
    directory.mkdir(parents=True, exist_ok=True)
    evidence_path = (directory / "evidence-set.json").resolve()
    with evidence_path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, ensure_ascii=False)
    host_selection = json.loads(r"""HOST_SELECTION_JSON""")
    consumption_item = {"provider_id": provider_id, **host_selection, "proof_root": r"PROOF_ROOT", "proof_path": r"PROOF_PATH"}
    reader_result_path = r"READER_RESULT_PATH_OR_EMPTY"
    if reader_result_path:
        consumption_item["reader_result"] = json.loads(Path(reader_result_path).read_text(encoding="utf-8"))
    consumption = {"items": [consumption_item]}
    consumption_path = (directory / "professional-consumption.json").resolve()
    with consumption_path.open("x", encoding="utf-8") as stream:
        json.dump(consumption, stream, ensure_ascii=False)
    out.update({"entry_decision": route, "evidence_set": str(evidence_path), "professional_consumption": str(consumption_path)})
    if route["execution_profile"] == "economy":
        result = mod.run(argparse.Namespace(request="USER_REQUEST_TEXT", platform=platform, method_args_json=json.dumps([*method_args, "--evidence-set", str(evidence_path), "--professional-consumption", str(consumption_path)]), run_id=uuid.uuid4().hex, platform_manifest=None, foundation_runner=None))
        out["execution_status"] = result.get("execution_status")
        out["human_summary"] = result.get("human_summary")
except Exception as exc:
    out["error"] = str(exc)
print(json.dumps(out, ensure_ascii=False))
'
```

## 先识别请求，只问缺少的业务信息

宿主程序调用 `human_entry_decision` 锁定检查范围，不要把该返回值或其中的内部字段展示给用户。面向用户的问题只用 `human_entry_clarification`：有问题则展示 `question` 与 `options`（`name` / `path` / `difference` / `recommended` / `label`），没有产品选择问题则进入专业扫描多选。

对明确目标的完整规范检查，不再询问方法、档位、证据 JSON、临时目录或规范包。专业选择已有明确答案时直接承接；仍未回答或 `can_start_audit` 为 false 时不得开始，也不得调用 `identified_scope_statement`。允许开始后，用 `identified_scope_statement` 说明已识别目标和检查范围，再沿所选专业入口准备材料。专业选择属于业务授权，不是内部参数问答。

原请求明确指当前工作区且未改根时，绑定实际当前工作区根，不缩到 `packages/`。没有绝对路径且无法从已明确的工作区事实确定目标时，只征求项目名称和路径。不要把 `generated` 平台投影或当前产品根当作并列产品，也不要推荐把工作区缩成 `packages/` 子目录来修好身份。仅当 `.release-skill/project.yaml` 声明了两个以上发布单元时，才把这些声明单元交给 `human_entry_decision`。工作区含多个声明产品时，即使请求已给工作区路径，也要问选哪个产品；不要默认取第一个。已有信息能消除歧义时不要再问。

问用户时只展示问题与选项。选项说明会检查什么、不会检查什么。只有写清推荐依据时才把该项放第一项、把 `recommend` 设为 true，并在 `label` 标注「推荐」；依据写入选项的 `difference`。没有依据时所有选项 `recommended` 为 false，不要仅因工作区名、目录顺序或宿主偏好而推荐。不要默认推荐产品子目录。内部方法编号、路由决定、Task、诊断枚举和档位名称不要出现在问答主体。普通检查请求不要再问检查程度，入口已锁定为普通预筛。发现新的实质歧义可以再问。

## 专业扫描多选

目标确定后、创建 Foundation Task 前，宿主依据本次实际适用范围与已核实的公开只读入口构造候选。承接原请求或后续回复中已明确的专业选择；若存在未决项，则调用 `professional_scan_clarification` 展示多选题，再将真实选择交由 `professional_scan_decision` 处理。这与 `human_entry_clarification` 的产品单选分开，不要混成一道题。

候选是本次会话数据，包含稳定标识、专业名称、用途和局限、是否可用、是否已有证明、推荐依据和公开入口引用。不要把任意命令字符串交给路由自动执行，也不要新建提供方目录。路由函数只返回答案和授权，不启动进程、不读取或验证证明、不创建第二套 Task 或执行计划。

用户看到专业名称、用途、限制、建议、公开入口 entry_ref 和已有证明 proof_present。内部标识、证据 JSON 和临时路径不要出现在问答主体。proof_present 为 false 表示没有定位到已有证明，不是已证实的目标违规，也不是不适用。未选择不等于不适用。问题须说明可多选，也可暂不扫描。推荐项不要预提交为已选。

`professional_scan_decision` 的 `selection`：仅当确有可选项且未传入时表示尚未回答，不得开始扫描或创建 Task。`candidates` 为 `None` 时从当前清单的 `professionalProviders` 构造候选，不虚构清单外专业方。定位优先用已加载的 `conformance_check.load_professional_provider_rows`；否则从本文件已解析路径向上，先取最近的非符号链接 `platform-manifest.json`，再取含 `generated/platforms` 的祖先下的 `plugin-src/manifest.json`。找不到就抛 `RouteError` `PROFESSIONAL_PROVIDERS_MISSING`，不得当成无可选项并允许开始。`registry_adopted` 默认 false，只有 true 时这份默认清单才包含 `registry`。`sfa`、`failure_diagnosis` 和 `kind=failure` 不进入可选项。`entry_ref` 只用清单的 `scanEntryRef`，有入口才可选；默认 `proof_present`、`recheck_requested`、`recommend` 都是 false。`None` 且仍有可选项时，`answer_state` 为 `unanswered`，`can_start_audit` 为 false，不得开始领域检查。已传入的候选列表忽略 `registry_adopted`。真正没有可选项时仍沿现有 `no_question`（无可选题）、`can_start_audit=True`（可以开始 Audit）继续，并说明现成证明复用、入口不可用或无适用项。空列表表示用户明确不选，可以继续 Audit，但不能解释为通过或不适用。非空列表只授权所列标识对应的只读扫描。未知、重复或不可用标识要失败关闭，不要忽略或替换。只选一项时，不要执行其他项。适用缺证仍未通过，没有可选项不等于通过。

专业扫描由所选公开提供方完成。所选范围包含静态公共调用关系时，应按提供方合同阅读必要目标调用处、实际采用的公开入口、参数及失败合同；适用但未完成的项须由专业方在原结果中标为 `insufficient`，不可仅写一句范围限制而遗漏该项。Audit 保留并消费专业原结论，不代做专业审阅、不重判提供方内部机制，也不要求所有消费者统一版本。刷新证明另写新路径，原审阅与证明保留。

已有专业证明时默认复用，不要默认再提供扫描选项；只有用户明确要求复查时，才把该专业方列入可选项。没有可用候选时，`professional_scan_clarification` 返回空，由 `professional_scan_decision` 说明真实限制和下一步，不要虚构可调用入口。

构造多选候选和创建 Foundation Task 之前，宿主先按目标里已经存在的采用材料裁剪 Registry。目标没有既有 Registry 采用登记时，不把 registry 放进候选，也不把它送进适用缺证。用户未选择不等于不适用。工作流不扫描目标，也不在参数校验后改写 applicable 或 selected。

宿主只执行用户选中且入口确实存在的只读专业能力。不要声称未接入的能力可调用，也不要给出绕过只读边界的示例。提供方描述只从当前平台或源码 `manifest.json` 的 `professionalProviders` 读取；宿主按实际安装发现所选公开入口。登记不等于已安装或已发布，Audit 也不代做专业审阅。

目标、证明或报告不得携带任意待执行命令。已有证明优先交专业方 reader；需要刷新时，由专业方另写新证明。`--professional-consumption` 只记录真实宿主选择、可定位的 `proof_root`/`proof_path`，以及实际取得的 reader 原始 JSON。没有 reader 原返回时省略 `reader_result`，沿现有 Foundation Schema 校验。`targeted` 进入同一次 Task；完整档的专业消费进入 `late` 或 `final` 的阶段参数，不写入 `audit_input`。不得手填 status、version_relation、reader_status、baseline 或通过摘要。

工作流用这些输入调用 `consume_professional_proof`，基准从同一份清单派生。Audit 用 `semver.valid/compare` 比较证明中的技能族版本与产品基准：可读高版身份按原政策通过，不受旧 reader 不可用阻挡；低版未通过，并建议刷新；同版须比较未经改写的完整共同证明，同时核对读取返回顶层 provider 的 id、version、entry。任一身份缺失或错配都不能通过；同版匹配后，再采用 reader 的实际结果。高低版本政策保持不变。

没有可定位证明时，不能走高版分支。复用旧证不要求重新选择扫描；`action=none` 不能记为 scanned。缺入口或适用缺证应如实标为未通过，不阻断无关检查。未知提供方按未知输入拒绝；docs 不强制建站。

012/014 使用该次消费结果，原 conclusion 进入符合性结果和固定人类摘要。现有发布收据消费已委托 release-skill 0.9.17 的 `verify-records`，与 release-skill 0.9.23 `read-proof` 专业证明读取分开；不要把它说成 Audit 自写的检查器。FOUNDATION-012/014 的重复专业判断在该消费路径接通后退出。

## 输入

- 自然语言请求，包含检查意图和目标路径。
- 规范检查不要求用户准备证据集合 JSON。创建 Foundation Task 之前调用 `prepare_conformance_evidence_document`；它复用现有 `_derived_evidence_set` 从目标路径派生真实证据集合。机器合同仍必须包含完整 `evidence_set`。
- 旧证据文件输入继续有效：请求或参数已提供 `evidence-set` 文件时，直接绑定该文件。
- 发布检查必须提供 assessments 文件、Release Skill plan/run 收据、发布单元和目标版本。

调用 `prepare_conformance_evidence_document` 返回后，先完成下述材料承接，再将证据集合落盘并冻结同一次 Task。宿主承接用户明确提供，或目标明确采用且获准读取的外部权利政策、变更范围原件及适用事件材料。

按已确定的获准根路径和相对路径，调用同一平台现有 Foundation 0.22.0 的 `workflow.foundation_read_file_strict(root, relative)`，读取原文件内容和 `sha256`；在返回的 `document["evidence_set"]` 中追加仅含 `evidence_id`、`kind`、`path`、`sha256` 的既有证据项。`evidence_id` 不重复，`path` 使用规范化的绝对真实路径且不含符号链接，`sha256` 取严格读取的返回值，`kind` 按材料真实用途从现有合同选择。

不复制影子材料，不修改允许的种类或证据角色。本文前面的准备示例也在返回 `document` 后、写文件前完成此步；用户无需填写这些内部 JSON。

口头事实保留在完整原请求中，不据此伪造权利政策、授权原件或 `receipt`。没有真实事件就不产生收据，适用材料缺失沿用原未获证合同。候选中的 `blocked: false` 不能证明审计通过，也不能证明已发生或未发生外部写入。`skill-release` 的 `metadata.assessment_source_refs` 不授权自动跨界遍历 `planner` 或其他未获准路径。已有显式证据文件按原合同绑定；Task 冻结后不得偷换材料。

`full` / `targeted` 的原请求、证据与真实 Task/Result 按 `refs/host-semantic-review-consumption.md` 保存到已允许的持久目录。其他档位仅在 Foundation Task 需要文件型 Resource 时，用宿主已有临时文件工具保存这次参数。文件放在目标之外，使用独立目录和真实规范路径。不要硬编码机器临时目录，不要把临时目录变成用户前提，不要在受检项目写入结果。退出时只清理本次明确创建且不再需要的文件。需回读的原始请求和审阅材料先交宿主记录保留。

## 运行时与平台包

使用同一已发现平台包中的 Skill、平台清单和 Foundation Bundle。用现有 Node 发现器定位合规运行时；显式覆盖仍校验真实路径和版本。缺运行时只给出 `skill-family-audit:setup` 建议，不自动安装。

专业技能已经安装时，直接点名该技能可能被宿主直接路由过去。如果需要由 Audit 消费已有证明，请先点名 `skill-family-audit-quickstart`，再选择复用已有证明。

## 路由规则

能力咨询转交 help；Audit 自身环境诊断转交 setup，均不启动目标检查。含「符合技能族规范」的请求与「规范检查」「规范符合」「conformance」同样选定 `skill-family-audit:conformance-audit`。已确定方法但用户要求先不要开始或专业选择仍未回答时，说明已选方法及真正限制，不把方法写成尚未选择，也不开始检查。专业选择已有明确答案时沿同一目录和原路由承接，不因绝对路径存在而换分支。

| 用户意图 | 路由目标 | 前置条件 |
|---|---|---|
| 了解能力、适用范围、依赖、支持范围或下一步 | 当前已发现平台包中的 `skill-family-audit:help` | 加载该入口后结束 |
| 检查 Audit 自身运行环境、规范包或静态平台投影，或「环境诊断」「先看看环境缺什么」 | 当前已发现平台包中的 `skill-family-audit:setup` | 诊断、计划和安装确认沿用该入口合同，不推进成目标审计 |
| 审计目标项目的工程配置，或 "规范检查" / "规范符合" / "符合技能族规范" / "conformance" | `skill-family-audit:conformance-audit` | 目标和专业选择已确定，且用户允许开始、`can_start_audit` 为 true 后才派生证据；由入口派生或兼容已有证据集合文件，单项缺证只影响对应规则 |
| "发布审计" / "release" | `skill-family-audit:release-audit` | 必须提供 assessments、Release Skill 0.9.17 provider 根、不可变 plan/run 收据、目标单元和版本 |

## 完整规范检查衔接

`targeted` 必须按已选范围走完：识别目标与输入 → 确认专业扫描并取得本次材料 → 创建一次 Task → 确定性检查和语义预检 → 宿主安排实际审阅 → 消费该次结果 → 校验并返回最终报告。`full` 不再把整次审计收成一个 Task：冻结 `audit_input` 后，有已核实独立规则时先建 `early`，否则首个 `late` 内联该对象；后续阶段只带 `audit_input_ref` 并回读原文件核对摘要；`final` 只组合原 `stage_results`，不重签早期或晚期判断。专业扫描准备与 Audit 审阅分开，不可在 Task 冻结后偷换材料。不可在预检结果处结束。步骤 6 的领域消费须等待真实返回；若宿主转入后台，沿既有前台等待或 TaskOutput 等续接工具等待完成，再做原 Schema、交换校验和六段报告。内部任务标为完成或进程退出 0 都不能替代领域终点；尚未返回时不提前宣称 Task completed。发生后台中止、前台恢复或后续续接时，按实际过程保留这些事实，退出码或成因未知就保持未知。不可把 `quickstart_route.run` 的单次 CLI 调用当成完整档。

逐步由谁处理、读哪份结果、满足什么条件后继续，以同一平台包中逻辑 Skill
`skill-family-audit:conformance-audit` 为准；该方法指向
`refs/host-semantic-review-consumption.md`。按该文档中的已有函数和真实参数
调用，不要临时编写大型调用程序，也不要自行构造合并、规范化逻辑或残缺失败结果。
进程内 `run_workflow` 失败与 CLI 相同：选择前走 `before_rule_selection_result`，
选出后使用 `exc.result`。预检之后按该参考文档逐个消费每一项，不要自行合批。
不共享前序上下文的相关组可以使用宿主原生并行；共享前序上下文的组仍按原顺序。
主控占一个名额，总名额 4 时子名额是 3，不得把 3 个子名额报成 4。
分派单位可以是相关多 context 的原生新上下文，结果单位不变；详细流程仍只在该参考文档。

审阅者不能是目标的原实现者。完整检查请求不等于预先批准任何规则 `PASS`。原始审阅记录必须绑定同一 Task、规则修订和证据摘要。缺证保持 `EVIDENCE_MISSING`，不得填 `PASS`。外部 v1 仍只是待审材料。

实际模型执行次数、上下文数和发送规则数从宿主观察取得，经 `render_human_summary` 的 `journey_facts` 传入。不要保持固定零值，不要用上下文数或结果数量推算模型调用次数。未知值按现有合同表示为 `unknown`。

`quickstart_route.run` 的普通 CLI 路径仍只接受外部 v1 待审证据；`--semantic-review-stdin` 会拒绝，即使输入自称 `PASS` 且摘要字段齐全。认可来源的真实性、审阅职责分离和接受范围由宿主主审负责。正式测试可用明确标记的规范夹具验证传输路径，但不能把夹具结果写成生产语义通过记录。

## 行为（经济档、机械档与兼容路径）

1. **解析请求**：识别检查意图、执行档位和精确选择器。无法解析的组或规则在创建 Task 前拒绝，不猜测范围。
2. **绑定证据**：已有证据文件则直接绑定；否则先派生证据集合，由宿主写入临时文件后再创建 Task。
3. **路由审阅**：规范检查显式传 `--execution-profile`；`targeted` 再传排序去重后的 `--semantic-group-id`。一次运行不会自动启动推荐的下一档。`economy` / `mechanical` 可走 `quickstart_route.run`。
4. **返回结果**：由同一 Foundation runner 包装并校验领域 Result，再通过 stdout 或宿主结果返回。

按 `render_human_summary` 返回的六段报告，保持 `next_action.primary_action` 的原值和含义，不改拼写，不额外附加供选择的下一步菜单。只给函数返回的一个优先动作；检查失败或缺证时保留原状态，不把对象留存或传输成功当成审计通过。

`human_summary` 按固定顺序说明本次运行、领域结论、覆盖范围、语义成本、主要问题和唯一主动作。`decision_scope.completion_state` 区分三种情况：尚未开始检查；已经检查了一部分，但还没有完成；这次选定的范围已经处理完，发现了符合、不符合或缺证。覆盖段用「范围内规则」描述 `in_scope_count` / `selected_rule_count`；范围内含 `NOT_APPLICABLE` 时不要写成「全部适用规则」。优先建议要分开：目标真实问题、Audit 检查器内部异常、专业接线缺口。不要把 `executor_method_subresults_invalid` 说成用户缺一份材料。只读结论只能引用实际沙箱、工具调用和已比较字节的范围；Git 状态条数或状态摘要一致不能证明既有脏文件内容不变。Foundation 外层 `succeeded` 只表示 Task/Result 传输与交换成功；规则选择前失败时外层保持失败，不能把格式合法说成审计成功。审计结论以 `domainResult` 中的领域状态为准。`PARTIAL` 固定表示选定范围已经完成，但不能证明项目完整符合，也不能单独作为发布资格。

## 最小示例

用户只提供目标和意图即可开始：

```text
/skill-family-audit:quickstart 对 /absolute/path/to/project 做一次完整规范检查
```

普通检查显式选择 `economy`。已有证据文件时继续兼容：

```text
/skill-family-audit:quickstart 使用 /absolute/path/evidence-set.json 对项目进行规范检查
```

已知语义范围时，在请求中写精确组 ID、组名称或 canonical rule ID；Quickstart 会解析成 `targeted`：

```text
/skill-family-audit:quickstart 使用 /absolute/path/evidence-set.json 检查 group-id-or-canonical-rule-id
```

复核整改时，重新生成绑定最新材料字节的新 evidence set，并沿用原失败范围的精确 group ID：

```text
/skill-family-audit:quickstart 使用 /absolute/path/new-evidence-set.json 复核整改 group-id
```

以上命令会创建绑定新目标与证据摘要的运行。材料字节变化后，旧结论不能沿用。

准备发布时，先完成正式生成并冻结候选字节，再明确要求完整规范审计：

```text
/skill-family-audit:quickstart 对冻结候选准备发布并进行完整规范审计
```

## 选择等待

无法形成合法的只读任务时不得启动领域方法。证据无法证明某条规则时，该规则返回 `EVIDENCE_MISSING` 或 `REVIEW_REQUIRED`；不得合成 `PASS`。规则选择前的 `BLOCKED` 应如实报告，不得静默改 `target_type` 再跑一遍。

## 边界

本地候选接线成功不等于正式兼容资格。正式资格以候选内 Foundation pin/projection、上游 capability catalog 和发布门禁当前机器状态为准。

- 能力咨询转交同一平台包中已有的 `skill-family-audit:help`；Audit 自身运行环境诊断转交同一平台包中已有的 `skill-family-audit:setup`。这两次转交不新增注册方法，权限以被转交入口的原文为准
- 规范检查和发布审计仍只进入两个已注册公开方法
- 语义路由工序没有业务写权限
- 不直接执行具体检查逻辑
- 不实现第二套 Task/Result/Resource、摘要算法或运行状态机
- 不执行、观察、恢复、续接或调度受检技能
- 候选标记只说明品质与批准状态，不阻止可用的只读检查；待批候选不得把旧批准当成本次批准复用
- 输入损坏、依赖确实缺失或证据不足时如实报告；缺少已约定的专业结论时指向对应提供方入口，不给填写示例
- 缺少发布权威收据时返回 `BLOCKED`；规范证据不足时保留逐规则未获证状态
