---
name: "skill-family-audit-quickstart"
description: 把自然语言审计请求路由到两个只读公开方法，并用 Foundation Quickstart Profile 绑定调用方证据与领域结果。
user-invocable: true
internal: false
argument-hint: "<自然语言请求，如：对 /path/to/project 进行规范检查>"
---
<!-- platform-projection: platform=claude-code; logical=skill-family-audit:quickstart; source=skills/skill-family-audit/quickstart -->

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

下面的审计分诊只处理规范检查和发布审计。在此之前：

1. 用户要了解能力、适用范围、依赖、支持范围或下一步：加载当前已发现平台包中的 `skill-family-audit:help`，到此结束，不调用 `human_entry_decision`。
2. 用户要检查 Audit 自身的运行环境、规范包或静态平台投影，或原话含「环境诊断」「先看看环境缺什么」：加载当前已发现平台包中的 `skill-family-audit:setup`。回复写明路由目标是该 setup 入口，不得把这句话推进成经济档规范审计，不得开始检查。同一条回复接着按第 3 条写出固定四行，再列出适用专业方的 name、purpose、entry_ref、proof_present、recommended，写明可多选或暂不扫描，并逐字写出「proof_present 为 false 表示没有定位到已有证明，不是已证实的目标违规，也不是不适用。」和「未选择不等于不适用。」两句，然后停止。不得只用 setup 的诊断结论替换这四行和专业方清单。不调用 `human_entry_decision`。诊断、计划和安装确认沿用 setup 原文。
3. 用户要审计目标项目，包括该项目的工程配置。对已经给出绝对路径的普通「做一次规范检查」，第一条工具调用是一条 `python3 -c`。它按文件路径加载本文件旁边的 `scripts/quickstart_route.py`，用用户原话和空的 method args 调用 `human_entry_decision`，并调用 `professional_scan_clarification(None)`。同一条命令再调用 `professional_scan_decision(None)`，以便读取 `can_start_audit` 与 `answer_state`。不要打开或阅读该脚本，不要列出目录，不要检索。这条命令返回前不阅读脚本，stdout 回到上下文之前不要发出第二条工具调用。stdout 只保留澄清函数的 `question` 与 `options`，以及决策函数的 `can_start_audit` 与 `answer_state`。不要把 `human_entry_decision` 的内部字段展示给用户。若 `answer_state` 为 unanswered，或 `can_start_audit` 为 false，本轮用户回复的第一行必须写出插件清单里的 version，以及本 SKILL.md 的绝对路径，该路径就是本次实际遵循的技能文件。然后再按固定四行逐字引用用户原话，顺序不得调换，四行之间不插入解释。第一行以「工作区绝对路径：」开头，只引用用户要审计的仓库绝对路径；技能安装目录不是工作区。第二行以「产品身份：」开头，只引用「产品身份是」或「产品身份：」之后、到下一个逗号或句号为止的原文，并去掉这段原文的首尾空白；冒号后直接连接身份，不再保留空白；没有这几个字才写未说明。第三行以「例外：」开头，只引用限制审计范围的原句：含「例外」的原句，以及含「不要做」「不要做成」或「不要把」的业务限制；这些句子存在时必须按原话逐字引用，禁止写成未说明。含「不要读取」「不要安装」「不要发布」「不要改文件」「不要修改」「不要替我选择」「不要自动安装」的句子不写入例外。没有任何审计范围限制时，例外才写未说明。第四行以「运行目录：」开头，只引用含「运行目录」的那一句里从「运行目录」起直到句号（含句号）的原文，不把逗号之前的文字写入这一行；没有才写未说明。不编造；不从 `intent`、`execution_profile`、`selection_reason` 取值。这四项不在 stdout 里。然后再展示问题原文，以及每个选项的 `name`、`purpose`、`limitation`、`recommended`、`label`、`entry_ref`、`proof_present`。展示之后必须逐字写出「proof_present 为 false 表示没有定位到已有证明，不是已证实的目标违规，也不是不适用。」和「未选择不等于不适用。」两句，然后停止。这条命令返回之后不得再发出任何工具调用，不得调用 ask_user_question，不得把非交互会话、提问失败或用户尚未回复当成「暂不扫描」或空选择。空选择只来自用户明确说出的不选。除宿主为加载本技能而读取本文件之外，不要先读取 conformance、help、release 或 `quickstart_route.py`。不要加载 conformance 的 `SKILL.md`、refs 或 scripts，不要创建 Task，不要开始领域检查，不要先打开符合性技能。原话没有绝对路径、运行目录是当前工作区根、并且已经用选项上的名称点了一个专业方时，不要继续下一节，改走下面「已经点名专业方」分支。其余尚未给出绝对路径、或不是这句普通规范检查的目标项目审计，继续下一节，并且不要先打开符合性技能。`SKILL_MD_ABSOLUTE_PATH` 只换成加载本技能时已经得到的本文件绝对路径，`USER_REQUEST_TEXT` 只换成用户原话；反斜杠和双引号要转义，不改写内容，不要为此搜索。

```text
python3 -c 'import importlib.util, json; from pathlib import Path; skill = Path(r"SKILL_MD_ABSOLUTE_PATH").resolve(); script = skill.parent / "scripts" / "quickstart_route.py"; spec = importlib.util.spec_from_file_location("quickstart_route", script); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); mod.human_entry_decision("USER_REQUEST_TEXT", []); clarification = mod.professional_scan_clarification(None); decision = mod.professional_scan_decision(None); print(json.dumps({"question": None if clarification is None else clarification.get("question"), "options": None if clarification is None else clarification.get("options"), "can_start_audit": decision.get("can_start_audit"), "answer_state": decision.get("answer_state")}, ensure_ascii=False))'
```
用户后来的回复正好是「暂不扫描」，或明确表示空选择时，下一条工具调用只能是下面这一条命令。不要读脚本，不要打开符合性技能，不要检索。先调用 `professional_scan_decision(None, [])`。只有 `answer_state` 为 `empty` 且 `can_start_audit` 为 true 时，同一条命令才继续：把同平台的 `conformance_check` 放进 `sys.modules`，调用 `identified_scope_statement(target, "economy")`，调用 `prepare_conformance_evidence_document`，把返回文档写到目标仓库之外、`tempfile.mkdtemp` 之后 `resolve` 的普通文件，再调用 `run`。`request` 用上一条审计原话，不用「暂不扫描」。`platform` 用清单里的 `platformId`，不要写死平台名。失败也要打印决策字段后停止。`answer_state` 不是 `empty` 时只打印决策字段并停止。空选择不是不适用，也不是通过。stdout 保留 `answer_state`、`can_start_audit`、`empty_selection_means_not_applicable`、`empty_selection_means_pass`、`authorized_scans`、范围句和 `human_summary`。`SKILL_MD_ABSOLUTE_PATH` 只换成本 Quickstart 技能文件的绝对路径，`USER_REQUEST_TEXT` 只换成上一条审计原话，`TARGET_ABSOLUTE_PATH` 只换成原话里的工作区绝对路径。反斜杠和双引号要转义，不改写原话。
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
        manifest_path = mod.find_platform_manifest(None)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        platform = manifest["platformId"]
        checker = next(path for path in manifest_path.parent.glob("skills/*/scripts/conformance_check.py") if path.is_file() and not path.is_symlink())
        cspec = importlib.util.spec_from_file_location("conformance_check", checker)
        host = importlib.util.module_from_spec(cspec)
        sys.modules["conformance_check"] = host
        cspec.loader.exec_module(host)
        target = Path(r"TARGET_ABSOLUTE_PATH")
        out["scope"] = mod.identified_scope_statement(str(target), "economy")
        document = mod.prepare_conformance_evidence_document(target)
        directory = Path(tempfile.mkdtemp(prefix="audit-evidence-")).resolve()
        evidence_path = (directory / "evidence-set.json").resolve()
        evidence_path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        result = mod.run(argparse.Namespace(request="USER_REQUEST_TEXT", platform=platform, method_args_json=json.dumps(["--evidence-set", str(evidence_path)]), run_id=uuid.uuid4().hex, platform_manifest=None, foundation_runner=None))
        out["execution_status"] = result.get("execution_status")
        out["human_summary"] = result.get("human_summary")
    except Exception as exc:
        out["error"] = str(exc)
print(json.dumps(out, ensure_ascii=False))
'
```
已经点名专业方：原话没有绝对路径，运行目录是当前工作区根，并且用户原文已经用选项上的名称点了一个专业方。这条分支的第一条工具调用是下面这一条 `python3 -c`。它按文件路径加载本文件旁边的 `scripts/quickstart_route.py`，调用 `professional_scan_clarification(None)`，把 `USER_NAMED_TEXT` 对齐到恰好一个选项的 `name` 或 `label`。再从 `find_platform_manifest` 读到的同一份 `professionalProviders` 里，取 `name` 等于该选项 `name`、且 `scanEntryRef` 等于该选项 `entry_ref` 的那一行的 `id`，调用 `professional_scan_decision(None, [id])`。这个 `id` 只从该目录行读取，正文不写死。不要打开或阅读该脚本，不要列出目录，不要检索。这条命令返回前不阅读脚本，stdout 回到上下文之前不要发出第二条工具调用。对不齐恰好一个选项，或同一目录行不是恰好一行时，只打印计数字段和 `can_start_audit` 为 false，然后停止。`answer_state` 为 unanswered，或 `can_start_audit` 为 false 时，只打印决策字段并停止。不得把未回答写成「暂不扫描」或空选择。不得再发出任何工具调用。`can_start_audit` 为 true 且 `authorized_scans` 恰好给出一个 `entry_ref` 时，这条命令只打印 `answer_state`、`can_start_audit` 和所选 `entry_ref`，不要在这条命令里调用 `prepare_conformance_evidence_document` 或 `run`。`SKILL_MD_ABSOLUTE_PATH` 只换成本 Quickstart 技能文件的绝对路径，`USER_NAMED_TEXT` 只换成用户点名专业方的原话。反斜杠和双引号要转义，不改写原话。

```text
PYTHONDONTWRITEBYTECODE=1 python3 -c 'import importlib.util, json
from pathlib import Path
skill = Path(r"SKILL_MD_ABSOLUTE_PATH").resolve()
script = skill.parent / "scripts" / "quickstart_route.py"
spec = importlib.util.spec_from_file_location("quickstart_route", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
named = "USER_NAMED_TEXT"
out = {"can_start_audit": False}
try:
    clarification = mod.professional_scan_clarification(None)
    options = [] if clarification is None else clarification.get("options") or []
    matched = []
    for opt in options:
        if not isinstance(opt, dict):
            continue
        name = opt.get("name") if isinstance(opt.get("name"), str) else ""
        label = opt.get("label") if isinstance(opt.get("label"), str) else ""
        if (name and (named == name or name in named)) or (label and (named == label or label in named)):
            matched.append(opt)
    manifest_path = mod.find_platform_manifest(None)
    rows = mod.load_professional_providers(manifest_path)
    same = []
    if len(matched) == 1:
        opt = matched[0]
        for row in rows:
            if isinstance(row, dict) and row.get("name") == opt.get("name") and row.get("scanEntryRef") == opt.get("entry_ref") and isinstance(row.get("id"), str) and row.get("id").strip():
                same.append(row)
    out["aligned_option_count"] = len(matched)
    out["catalog_row_count"] = len(same)
    if len(matched) == 1 and len(same) == 1:
        id = same[0]["id"].strip()
        decision = mod.professional_scan_decision(None, [id])
        authorized = decision.get("authorized_scans") or []
        refs = []
        for item in authorized:
            if isinstance(item, dict) and isinstance(item.get("entry_ref"), str) and item.get("entry_ref"):
                refs.append(item.get("entry_ref"))
        if decision.get("answer_state") == "unanswered" or decision.get("can_start_audit") is False or len(refs) != 1:
            out = {"answer_state": decision.get("answer_state"), "can_start_audit": decision.get("can_start_audit"), "authorized_scans": authorized, "empty_selection_means_not_applicable": decision.get("empty_selection_means_not_applicable"), "empty_selection_means_pass": decision.get("empty_selection_means_pass")}
        elif decision.get("can_start_audit") is True and authorized:
            out = {"answer_state": decision.get("answer_state"), "can_start_audit": decision.get("can_start_audit"), "entry_ref": refs[0]}
except Exception as exc:
    out["error"] = str(exc)
print(json.dumps(out, ensure_ascii=False))
'
```

下一条工具调用才加载上一条 stdout 里的所选 `entry_ref` 已经存在的专业技能，并按那个技能自己的公开步骤做只读检查和 reader。不要先打开符合性技能，不要先读 Audit 的 refs 或 scripts，不要新写扫描器，也不要发明入口。该 `entry_ref` 没有已经存在的专业技能时停止。登记不等于已安装。

专业技能返回之后，下一条工具调用只能是下面这一条命令。没有可定位证明或没有 reader 原始 JSON 时停止，不要手填通过摘要，也不要调用 `run`。工作区根是进程当前工作目录的解析结果，不要缩到 `packages/`。对该根调用 `prepare_conformance_evidence_document`。证据文件和消费文件都写到目标之外、`tempfile.mkdtemp` 之后 `resolve` 的普通文件。消费文件只含宿主选择、证明路径和 reader 原始 JSON：`provider_id` 仍从 `scanEntryRef` 等于所选 `entry_ref` 的同一目录行读取，不写死；`selected`、`applicable`、`entry_available` 均为 true；`action` 为 `scan`。不得手填 status、version_relation、reader_status、baseline 或通过摘要。然后调用带 `--professional-consumption` 的 `run`。`request` 用上一条审计原话。`platform` 用清单里的 `platformId`，不要写死平台名。stdout 保留 `human_summary` 与 `execution_status`。这一条才加载同平台的 `conformance_check.py`，仍然不要打开符合性技能的 SKILL.md 或 refs。`SKILL_MD_ABSOLUTE_PATH` 只换成本 Quickstart 技能文件的绝对路径，`USER_REQUEST_TEXT` 只换成上一条审计原话，`SELECTED_ENTRY_REF` 只换成上一条打印的 `entry_ref`，`PROOF_ROOT` 与 `PROOF_PATH` 只换成该专业技能返回的可定位证明，`READER_RESULT_PATH` 只换成保存 reader 原始 JSON 的普通文件。反斜杠和双引号要转义，不改写原话。

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
    cspec.loader.exec_module(host)
    rows = mod.load_professional_providers(manifest_path)
    entry_ref = "SELECTED_ENTRY_REF"
    same = [row for row in rows if isinstance(row, dict) and row.get("scanEntryRef") == entry_ref and isinstance(row.get("id"), str) and row.get("id").strip()]
    if len(same) != 1:
        raise RuntimeError("catalog row for the selected entry_ref is not exactly one")
    provider_id = same[0]["id"].strip()
    target = Path.cwd().resolve()
    document = mod.prepare_conformance_evidence_document(target)
    directory = Path(tempfile.mkdtemp(prefix="audit-evidence-")).resolve()
    if directory == target or target in directory.parents:
        raise RuntimeError("evidence directory is inside the workspace")
    evidence_path = (directory / "evidence-set.json").resolve()
    evidence_path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    reader_result = json.loads(Path(r"READER_RESULT_PATH").read_text(encoding="utf-8"))
    consumption = {"items": [{"provider_id": provider_id, "selected": True, "applicable": True, "entry_available": True, "action": "scan", "proof_root": r"PROOF_ROOT", "proof_path": r"PROOF_PATH", "reader_result": reader_result}]}
    consumption_path = (directory / "professional-consumption.json").resolve()
    consumption_path.write_text(json.dumps(consumption, ensure_ascii=False), encoding="utf-8")
    result = mod.run(argparse.Namespace(request="USER_REQUEST_TEXT", platform=platform, method_args_json=json.dumps(["--evidence-set", str(evidence_path), "--professional-consumption", str(consumption_path)]), run_id=uuid.uuid4().hex, platform_manifest=None, foundation_runner=None))
    out["execution_status"] = result.get("execution_status")
    out["human_summary"] = result.get("human_summary")
except Exception as exc:
    out["error"] = str(exc)
print(json.dumps(out, ensure_ascii=False))
'
```
4. 用户要审计已有发布材料：继续下一节，进入 `skill-family-audit:release-audit`。

help 与 setup 是同一平台包里已有的入口。这里只转交，不新注册方法。

## 先识别请求，只问缺少的业务信息

宿主程序调用 `human_entry_decision` 锁定检查范围，不要把该返回值或其中的内部字段展示给用户。面向用户的问题只用 `human_entry_clarification`：有问题则展示 `question` 与 `options`（`name` / `path` / `difference` / `recommended` / `label`），没有产品选择问题则进入专业扫描多选。

对「对这个明确路径做一次完整规范检查」这类请求：不要询问方法、档位、证据 JSON、临时目录或规范包。专业扫描尚未回答或 `can_start_audit` 为 false 时不得开始，也不得调用 `identified_scope_statement`。用户已经回答并且 `can_start_audit` 为 true 之后，先调用 `identified_scope_statement` 说明已识别的目标和检查范围，再按「专业扫描多选」确认尚未决定的专业扫描，然后开始。专业扫描授权是业务选择，不是内部参数问答。

无绝对路径时只征求项目名称和路径。不要把 `generated` 平台投影或当前产品根当作并列产品，也不要推荐把工作区缩成 `packages/` 子目录来修好身份。仅当 `.release-skill/project.yaml` 声明了两个以上发布单元时，才把这些声明单元交给 `human_entry_decision`。工作区含多个声明产品时，即使请求已给工作区路径，也要问选哪个产品；不要默认取第一个。已有信息能消除歧义时不要再问。

问用户时只展示问题与选项。选项说明会检查什么、不会检查什么。只有写清推荐依据时才把该项放第一项、把 `recommend` 设为 true，并在 `label` 标注「推荐」；依据写入选项的 `difference`。没有依据时所有选项 `recommended` 为 false，不要仅因工作区名、目录顺序或宿主偏好而推荐。不要默认推荐产品子目录。内部方法编号、路由决定、Task、诊断枚举和档位名称不要出现在问答主体。普通检查请求不要再问检查程度，入口已锁定为普通预筛。发现新的实质歧义可以再问。

## 专业扫描多选

目标确定之后、创建 Foundation Task 之前，宿主按本次实际适用范围和已核实的公开只读入口构造候选，调用 `professional_scan_clarification` 向用户展示多选题，再把用户选择交给 `professional_scan_decision`。这与 `human_entry_clarification` 的产品单选分开，不要混成一道题。

候选是本次会话数据，包含稳定标识、专业名称、用途和局限、是否可用、是否已有证明、推荐依据和公开入口引用。不要把任意命令字符串交给路由自动执行，也不要新建提供方目录。路由函数只返回答案和授权，不启动进程、不读取或验证证明、不创建第二套 Task 或执行计划。

用户看到专业名称、用途、限制、建议、公开入口 entry_ref 和已有证明 proof_present。内部标识、证据 JSON 和临时路径不要出现在问答主体。proof_present 为 false 表示没有定位到已有证明，不是已证实的目标违规，也不是不适用。未选择不等于不适用。问题须说明可多选，也可暂不扫描。推荐项不要预提交为已选。

`professional_scan_decision` 的 `selection`：仅当确有可选项且未传入时表示尚未回答，不得开始扫描或创建 Task。`candidates` 为 `None` 时从当前清单的 `professionalProviders` 构造候选，不虚构清单外专业方。定位优先用已加载的 `conformance_check.load_professional_provider_rows`；否则从本文件已解析路径向上，先取最近的非符号链接 `platform-manifest.json`，再取含 `generated/platforms` 的祖先下的 `plugin-src/manifest.json`。找不到就抛 `RouteError` `PROFESSIONAL_PROVIDERS_MISSING`，不得当成无可选项并允许开始。`registry_adopted` 默认 false，只有 true 时这份默认清单才包含 `registry`。`sfa`、`failure_diagnosis` 和 `kind=failure` 不进入可选项。`entry_ref` 只用清单的 `scanEntryRef`，有入口才可选；默认 `proof_present`、`recheck_requested`、`recommend` 都是 false。`None` 且仍有可选项时，`answer_state` 为 `unanswered`，`can_start_audit` 为 false，不得开始领域检查。已传入的候选列表忽略 `registry_adopted`。真正没有可选项时仍沿现有 `no_question`（无可选题）、`can_start_audit=True`（可以开始 Audit）继续，并说明现成证明复用、入口不可用或无适用项。空列表表示用户明确不选，可以继续 Audit，但不能解释为通过或不适用。非空列表只授权所列标识对应的只读扫描。未知、重复或不可用标识要失败关闭，不要忽略或替换。只选一项时，不要执行其他项。适用缺证仍未通过，没有可选项不等于通过。

已有专业证明时默认复用，不要默认再提供扫描选项；只有用户明确要求复查时，才把该专业方列入可选项。没有可用候选时，`professional_scan_clarification` 返回空，由 `professional_scan_decision` 说明真实限制和下一步，不要虚构可调用入口。

构造多选候选和创建 Foundation Task 之前，宿主先按目标里已经存在的采用材料裁剪 Registry。目标没有既有 Registry 采用登记时，不把 registry 放进候选，也不把它送进适用缺证。用户未选择不等于不适用。工作流不扫描目标，也不在参数校验后改写 applicable 或 selected。

宿主只执行用户选中且入口确实存在的只读专业能力。不要声称未接入的能力可调用，不要给出绕过只读边界的示例。提供方描述只从当前平台或源码 `manifest.json` 的 `professionalProviders` 读取；宿主按实际安装发现所选公开入口，登记不等于已安装或已发布。目标、证明或报告不得携带任意待执行命令。已有证明优先交专业方 reader；刷新由专业方另写新证明。`--professional-consumption` 只写宿主选择、可定位 `proof_root`/`proof_path` 和 reader 原始 JSON，进入现有 Foundation Schema 校验与同一次 Task；不得手填 status、version_relation、reader_status、baseline 或通过摘要。工作流从这些输入调用 `consume_professional_proof`，基准由同一份清单派生。Audit 用 `semver.valid/compare` 比较证明文件中的技能族版本与产品基准：可读高版身份先按政策通过，不受旧 reader 不可用挡住；低版未通过并建议刷新；同版须比较未经改写的完整共同证明，并核读取返回顶层 provider 的 id、version、entry；任一缺失或错配都不能通过。高低版本政策不变，同版匹配后再采用 reader 实际结果。没有可定位证明不能走高版分支。旧证复用不要求选择扫描；`action=none` 不能记为 scanned。缺入口或适用缺证如实未通过，不阻断无关检查。未知提供方按未知输入拒绝，docs 不强制建站。012/014 使用该次消费结果；原 conclusion 进入符合性结果和固定人类摘要。现有发布收据消费已经委托 release-skill 0.9.17 的 `verify-records`，与 0.9.22 `read-proof` 专业证明读取分开，不要把它说成 Audit 自写的检查器。FOUNDATION-012/014 的重复专业判断在该消费路径接通后退出。

## 输入

- 自然语言请求，包含检查意图和目标路径。
- 规范检查不要求用户准备证据集合 JSON。创建 Foundation Task 之前调用 `prepare_conformance_evidence_document`；它复用现有 `_derived_evidence_set` 从目标路径派生真实证据集合。机器合同仍必须包含完整 `evidence_set`。
- 旧证据文件输入继续有效：请求或参数已提供 `evidence-set` 文件时，直接绑定该文件。
- 发布检查必须提供 assessments 文件、Release Skill plan/run 收据、发布单元和目标版本。

仅在 Foundation Task 需要文件型 Resource 时，用宿主已有临时文件工具保存这次参数。文件放在目标之外，使用独立目录和真实规范路径。不要硬编码机器临时目录，不要把临时目录变成用户前提，不要在受检项目写入结果。退出时只清理本次明确创建且不再需要的文件。需回读的原始请求和审阅材料先交宿主记录保留。

## 运行时与平台包

使用同一已发现平台包中的 Skill、平台清单和 Foundation Bundle。用现有 Node 发现器定位合规运行时；显式覆盖仍校验真实路径和版本。缺运行时只给出 `skill-family-audit:setup` 建议，不自动安装。

## 路由规则

能力咨询先转交 help 并结束。环境诊断（含「环境诊断」和「先看看环境缺什么」）转交 setup，不得推进成经济档规范审计，不得开始检查；同一条回复仍按第 3 条写出固定四行和专业方清单，然后停止。含「符合技能族规范」的请求与「规范检查」「规范符合」「conformance」同样选定 `skill-family-audit:conformance-audit`。用户写明先不要开始检查，或专业扫描尚未回答时，回复必须写出该选定方法，不得写成「尚未选择」或「路由结果是尚未选择」，不得打开符合性技能，不得开始检查；固定四行和专业方清单仍按第 3 条写出，然后停止。规范检查和发布审计才进入 `human_entry_decision` 和已注册业务方法。

| 用户意图 | 路由目标 | 前置条件 |
|---|---|---|
| 了解能力、适用范围、依赖、支持范围或下一步 | 当前已发现平台包中的 `skill-family-audit:help` | 加载该入口后结束 |
| 检查 Audit 自身运行环境、规范包或静态平台投影，或「环境诊断」「先看看环境缺什么」 | 当前已发现平台包中的 `skill-family-audit:setup` | 转交 setup，不进入经济档规范审计。同一条回复按第 3 条写出固定四行和专业方清单后停止 |
| 审计目标项目的工程配置，或 "规范检查" / "规范符合" / "符合技能族规范" / "conformance" | `skill-family-audit:conformance-audit` | 已经给出绝对路径的普通「做一次规范检查」，第一条工具调用是第 3 条的那一条 `python3 -c`，服从第 3 条的同一停止，不要先打开符合性技能。派生证据只发生在用户已经回答并且 `can_start_audit` 为 true 之后；未作答时本轮结束，不派生证据。由入口派生或兼容已有证据集合文件；单项证据不足只影响对应规则，不拒绝整个审阅请求 |
| "发布审计" / "release" | `skill-family-audit:release-audit` | 必须提供 assessments、Release Skill 0.9.17 provider 根、不可变 plan/run 收据、目标单元和版本 |

## 完整规范检查衔接

`full` 必须走完：识别目标与输入 → 确认专业扫描并取得本次材料 → 创建一次 Task → 确定性检查和语义预检 → 宿主安排实际审阅 → 消费该次结果 → 校验并返回最终报告。专业扫描准备与 Audit 审阅分开，不能在 Task 冻结后偷换材料。不能在预检结果处结束。不要把 `quickstart_route.run` 的单次 CLI 调用当成完整档。

逐步由谁处理、读哪份结果、满足什么条件后继续，以同一平台包中逻辑 Skill
`skill-family-audit:conformance-audit` 为准；该方法指向
`refs/host-semantic-review-consumption.md`。按该文档中的已有函数和真实参数
调用，不要临时编写大型调用程序，也不要自行构造合并、规范化逻辑或残缺失败结果。
进程内 `run_workflow` 失败与 CLI 相同：选择前走 `before_rule_selection_result`，
选出后使用 `exc.result`。预检之后按该参考文档逐个消费每一项，不要自行合批，
不要在同一助手消息里后台并行多个 Agent。

审阅者不能是目标的原实现者。完整检查请求不等于预先批准任何规则 `PASS`。原始审阅记录必须绑定同一 Task、规则修订和证据摘要。缺证保持 `EVIDENCE_MISSING`，不得填 `PASS`。外部 v1 仍只是待审材料。

实际模型执行次数、上下文数和发送规则数从宿主观察取得，经 `render_human_summary` 的 `journey_facts` 传入。不要保持固定零值，不要用上下文数或结果数量推算模型调用次数。未知值按现有合同表示为 `unknown`。

`quickstart_route.run` 的普通 CLI 路径仍只接受外部 v1 待审证据；`--semantic-review-stdin` 会拒绝，即使输入自称 `PASS` 且摘要字段齐全。认可来源的真实性、审阅职责分离和接受范围由宿主主审负责。正式测试可用明确标记的规范夹具验证传输路径，但不能把夹具结果写成生产语义通过记录。

## 行为（经济档、机械档与兼容路径）

1. **解析请求**：识别检查意图、执行档位和精确选择器。无法解析的组或规则在创建 Task 前拒绝，不猜测范围。
2. **绑定证据**：已有证据文件则直接绑定；否则先派生证据集合，由宿主写入临时文件后再创建 Task。
3. **路由审阅**：规范检查显式传 `--execution-profile`；`targeted` 再传排序去重后的 `--semantic-group-id`。一次运行不会自动启动推荐的下一档。`economy` / `mechanical` 可走 `quickstart_route.run`。
4. **返回结果**：由同一 Foundation runner 包装并校验领域 Result，再通过 stdout 或宿主结果返回。

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
