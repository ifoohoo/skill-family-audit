"""conformance_profiles —— A2 领域内核：执行分支 profile 规范化、规则选择、覆盖统计与领域状态聚合。

权威输入：
- docs/handoffs/2026-08-27-sfa-foundation-independent-continuous-implementation.md
  （5.2 精确行为、6.2 写集、7.2 验证命令）；
- docs/specs/2026-08-27-conformance-cost-aware-workflow/05-execution-profiles.md；
- docs/specs/2026-08-27-conformance-cost-aware-workflow/06-coverage-and-status.md
  （§2 coverage 字段、§4 状态优先级、§5 逐规则状态）；
- docs/specs/2026-08-27-conformance-cost-aware-workflow/contract-delta.json
  （parameter_delta、profile_selection、status_algorithm、derived_invariants、rule_result_scope）；
- docs/specs/2026-08-27-conformance-cost-aware-workflow/journey-contract.json
  （direct_method.absent_execution_profile = "full"）；
- docs/specs/2026-08-27-conformance-cost-aware-workflow/14-foundation-014-phasing.md
  （§3.2：A2 返回排序后的 ID 集合、计数和状态，不计算集合摘要，不含 *_digest）。

边界（handoff 5.2 与 14 §2）：
- 本模块只接受/返回普通 Python 值（bool/int/str/list/dict）；不读文件、不计算摘要、
  不创建 Task、不调用模型、无全局可变状态、纯函数、无副作用；
- 输出一律排序（sorted）保证确定性；不返回集合对象，只返回列表和普通字典；
- 模块由 importlib.util.spec_from_file_location 独立加载（无包上下文），因此不使用
  任何相对导入；本文件零 import（只用内建能力），顶层无执行副作用；
- 参数/结构校验失败一律抛 ValueError（冻结测试 docstring 结构假设 1）；而
  derive_conformance_status 的合同错误（execution_contract_ok=False、状态表缺行/未知行/
  重复行/非法容器）返回 "BLOCKED" 字符串而不是抛异常（结构假设 2/7），已证明的 FAIL 仍优先
  （handoff 5.2）。
"""

# 合法执行分支（contract-delta.json parameter_delta.execution_profile.enum）
VALID_PROFILES = ("mechanical", "economy", "targeted", "full")

# 底层方法没有 execution_profile 时按 full 处理（journey-contract.json
# direct_method.absent_execution_profile = "full"；handoff 5.2 明文）
DEFAULT_PROFILE = "full"

NOT_RUN = "NOT_RUN"

# 终态（06 §5 逐规则状态）：conclusion_complete 与 full 的 SUCCEEDED 只认这三个状态
TERMINAL_STATUSES = ("PASS", "FAIL", "NOT_APPLICABLE")

# 非 full profile 判定「所选规则全部完成」的状态集合（06 §4 优先级 4；05 §3/§4/§5）
COMPLETED_SELECTED_STATUSES = ("PASS", "NOT_APPLICABLE")


def _as_unique_string_list(value, name):
    """ID 数组最小结构校验：必须是 list/tuple（排除 str/bytes）、元素为字符串且唯一。

    失败一律抛 ValueError（结构假设 1）。ID 是字符串是产品数据模型的固定事实；
    元素类型检查把「数组元素类型错误」从静默忽略转成结构失败。
    """
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            "{name} must be a list or tuple of unique string ids, "
            "got {kind}".format(name=name, kind=type(value).__name__)
        )
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(
                "{name} must contain only string ids, got {kind}".format(
                    name=name, kind=type(item).__name__
                )
            )
        if item in seen:
            raise ValueError(
                "{name} contains duplicate id: {item!r}".format(name=name, item=item)
            )
        seen.add(item)
        result.append(item)
    return result


def _normalize_status_table(rule_status_by_id):
    """把状态表规范化为 {rule_id: status} 普通字典。

    接受普通字典或键值对序列（list/tuple of (rule_id, status) 2 元素序列；
    只有序列形式能表达「重复行」，06 §2 与测试结构假设 7）。

    返回 (ok, statuses)：ok=False 表示结构失败（容器非法、行不是 2 元素序列、
    键不是字符串、重复行），由调用方决定处置（derive_coverage → ValueError；
    derive_conformance_status → "BLOCKED"）。
    """
    if isinstance(rule_status_by_id, dict):
        rows = list(rule_status_by_id.items())
    elif isinstance(rule_status_by_id, (list, tuple)):
        rows = []
        for item in rule_status_by_id:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                return False, None
            rows.append((item[0], item[1]))
    else:
        return False, None
    statuses = {}
    for key, value in rows:
        if not isinstance(key, str):
            return False, None
        if key in statuses:
            return False, None
        statuses[key] = value
    return True, statuses


def normalize_profile_request(execution_profile, semantic_group_ids,
                              registered_group_ids):
    """规范化执行分支请求，返回 (规范化 profile, 排序后唯一的 group ids 数组)。

    输入契约：
    - execution_profile：None → "full"；必须是 {mechanical, economy, targeted, full}
      之一（非字符串或未知值 → ValueError）（05 §1、contract-delta parameter_delta、
      journey-contract direct_method）。
    - semantic_group_ids：只有 None 表示字段缺席。targeted 时必须是 非空、元素唯一、且全部 ∈
      registered_group_ids 的字符串数组，否则 ValueError（05 §1：targeted 缺少
      group ID 时参数校验失败）。非 targeted 时：None → 返回 (profile, [])；显式
      空数组或非空数组都 → ValueError（05 §1「其他 profile 传入 group ID 也失败，
      不能静默忽略」；同批整改架构复核 R5）。
    - registered_group_ids：最小结构校验（字符串数组、唯一），不合法 → ValueError。

    输出契约：(profile, sorted(unique group ids))。例：
    ("targeted", ["group-y", "group-x"]) → ("targeted", ["group-x", "group-y"])。
    """
    if execution_profile is None:
        profile = DEFAULT_PROFILE
    elif isinstance(execution_profile, str) and execution_profile in VALID_PROFILES:
        profile = execution_profile
    else:
        raise ValueError(
            "execution_profile must be one of {valid} (or None for default full), "
            "got {value!r}".format(valid=VALID_PROFILES, value=execution_profile)
        )
    _as_unique_string_list(registered_group_ids, "registered_group_ids")
    if profile == "targeted":
        if not isinstance(semantic_group_ids, (list, tuple)):
            raise ValueError(
                "targeted requires a non-empty, unique, registered "
                "semantic_group_ids array; got {value!r}".format(value=semantic_group_ids)
            )
        groups = _as_unique_string_list(semantic_group_ids, "semantic_group_ids")
        if not groups:
            raise ValueError("targeted requires a non-empty semantic_group_ids array")
        registered_set = set(registered_group_ids)
        for group_id in groups:
            if group_id not in registered_set:
                raise ValueError(
                    "semantic_group_ids contains unregistered group id: {id!r}".format(
                        id=group_id
                    )
                )
        return (profile, sorted(groups))
    # 非 targeted：只有 None 表示字段缺席；显式数组无论是否为空都失败（R5）。
    if semantic_group_ids is None:
        return (profile, [])
    raise ValueError(
        "semantic_group_ids is forbidden for execution_profile {profile!r}".format(
            profile=profile
        )
    )


def select_rule_ids(profile, in_scope_rule_ids, deterministic_rule_ids,
                    first_tier_semantic_rule_ids, group_members,
                    requested_group_ids):
    """按执行分支选择规则，返回排序去重的 ID 数组。

    输入契约：
    - profile：None → "full"；未知值 → ValueError。
    - in_scope_rule_ids / deterministic_rule_ids / first_tier_semantic_rule_ids /
      requested_group_ids：字符串数组，各自不得有重复元素，否则 ValueError
      （handoff 5.2、测试结构假设 11）；requested_group_ids 必须全部存在于
      group_members 中，否则 ValueError（空数组合法，组段为空）。
    - 数组元素类型错误（非字符串）→ ValueError；requested 非空时 group_members
      必须是字典、其成员值必须是 list/tuple（结构最小校验，防字符串被逐字符迭代）。

    选择语义（handoff 5.2、05 §3/§4/§5、contract-delta profile_selection）：
    - mechanical / economy：sorted(in_scope ∩ deterministic)。语义规则
      （first-tier 与组内）即使 in-scope 也不选；economy 的语义预筛由 A3 表达，
      不把语义规则算作已选择。
    - targeted：sorted((in_scope ∩ deterministic) ∪ (in_scope ∩
      请求各组成员的并集))。已启用的 first-tier semantic 规则已经进入同一
      group registry；不在请求组内时不得自动加入。
    - full：sorted(in_scope)（调用方传入的 in_scope 已视为完成 executable 过滤，
      handoff 5.2）。
    - deterministic_rule_ids / first_tier_semantic_rule_ids 中不在 in-scope 的
      ID 自然忽略（交集语义，不失败，测试结构假设 11）。

    输出契约：排序去重的字符串数组。
    """
    if profile is None:
        profile = DEFAULT_PROFILE
    elif not (isinstance(profile, str) and profile in VALID_PROFILES):
        raise ValueError(
            "profile must be one of {valid} (or None for default full), "
            "got {value!r}".format(valid=VALID_PROFILES, value=profile)
        )
    in_scope = _as_unique_string_list(in_scope_rule_ids, "in_scope_rule_ids")
    deterministic = _as_unique_string_list(
        deterministic_rule_ids, "deterministic_rule_ids"
    )
    first_tier = _as_unique_string_list(
        first_tier_semantic_rule_ids, "first_tier_semantic_rule_ids"
    )
    requested = _as_unique_string_list(requested_group_ids, "requested_group_ids")
    if requested:
        if not isinstance(group_members, dict):
            raise ValueError(
                "group_members must be a dict when requested_group_ids is non-empty"
            )
        for group_id in requested:
            if group_id not in group_members:
                raise ValueError(
                    "requested_group_ids contains unknown group id: {id!r}".format(
                        id=group_id
                    )
                )
            members = group_members[group_id]
            if not isinstance(members, (list, tuple)):
                raise ValueError(
                    "group_members[{id!r}] must be a list or tuple of rule ids".format(
                        id=group_id
                    )
                )
    if profile == "full":
        return sorted(in_scope)
    deterministic_set = set(deterministic)
    if profile in ("mechanical", "economy"):
        return sorted(rule for rule in in_scope if rule in deterministic_set)
    # targeted
    member_set = set()
    for group_id in requested:
        member_set.update(group_members[group_id])
    return sorted(
        rule
        for rule in in_scope
        if rule in deterministic_set or rule in member_set
    )


def project_in_scope_rule_results(in_scope_rule_ids, result_rows):
    """把内部检查结果投影为精确的 canonical ``rule_results``。

    没有 ``canonical_lineage`` 的辅助检查只保留在诊断发现中，不得进入公开
    ``rule_results``，也不得参与 profile 状态聚合。带 lineage 的结果必须恰好
    覆盖每条 in-scope canonical rule 一次；缺行、重复行或 scope 外行均失败。
    """
    in_scope = _as_unique_string_list(in_scope_rule_ids, "in_scope_rule_ids")
    if not isinstance(result_rows, (list, tuple)):
        raise ValueError("result_rows must be a list or tuple")
    in_scope_set = set(in_scope)
    by_canonical = {}
    for row in result_rows:
        if not isinstance(row, dict):
            raise ValueError("result_rows must contain only objects")
        lineage = row.get("canonical_lineage")
        if lineage is None:
            continue
        if not isinstance(lineage, dict):
            raise ValueError("canonical_lineage must be an object when present")
        canonical_id = lineage.get("canonical_id")
        if not isinstance(canonical_id, str) or canonical_id not in in_scope_set:
            raise ValueError(
                "canonical result row must identify one in-scope rule"
            )
        if canonical_id in by_canonical:
            raise ValueError(
                "canonical result rows must cover each in-scope rule exactly once"
            )
        by_canonical[canonical_id] = row
    if set(by_canonical) != in_scope_set:
        raise ValueError(
            "canonical result rows must cover each in-scope rule exactly once"
        )
    return [by_canonical[canonical_id] for canonical_id in sorted(in_scope)]


def derive_coverage(in_scope_rule_ids, selected_rule_ids, rule_status_by_id):
    """从逐规则状态计算覆盖统计，返回普通字典（不含任何 *_digest，14 §3.2）。

    输入契约（结构校验失败 → ValueError，结构假设 3/7/8）：
    - in_scope_rule_ids：字符串数组，不得有重复元素。
    - selected_rule_ids：字符串数组，不得有重复元素，且必须是 in-scope 的子集
      （含不在 in-scope 的 ID → ValueError，结构假设 8）。
    - rule_status_by_id：字典或键值对序列（list of pairs，可表达重复行）；必须恰好
      覆盖全部 in-scope 规则——缺行、未知行、重复行都 → ValueError（06 §2
      「rule_results 必须恰好包含每条 in-scope 规则一次」、contract-delta
      rule_result_scope）。任何未选择规则的状态必须为 NOT_RUN，否则 → ValueError；
      不得自动改写调用方状态（同批整改架构复核 R4）。

    计算（handoff 5.2、06 §2、contract-delta derived_invariants）：
    - in_scope_count = len(in_scope)；selected_count = len(selected)；
    - attempted = sorted(id for id in in_scope if status != "NOT_RUN")；
      attempted_count = len(attempted)；
    - not_run = sorted(其余 in-scope ID)；not_run_count = len(not_run)；
    - coverage_complete = set(attempted) == set(in_scope)；
    - conclusion_complete = 每条 in-scope 规则状态 ∈ {PASS, FAIL, NOT_APPLICABLE}。

    输出契约：普通字典，键为 in_scope_count、selected_count、attempted_count、
    not_run_count、coverage_complete、conclusion_complete、attempted（排序数组）、
    not_run（排序数组）。
    """
    in_scope = _as_unique_string_list(in_scope_rule_ids, "in_scope_rule_ids")
    selected = _as_unique_string_list(selected_rule_ids, "selected_rule_ids")
    in_scope_set = set(in_scope)
    for rule_id in selected:
        if rule_id not in in_scope_set:
            raise ValueError(
                "selected_rule_ids contains rule id outside in-scope: {id!r}".format(
                    id=rule_id
                )
            )
    ok, statuses = _normalize_status_table(rule_status_by_id)
    if not ok:
        raise ValueError(
            "rule_status_by_id must be a dict or a list of (rule_id, status) pairs "
            "with string keys and no duplicate rows"
        )
    if set(statuses) != in_scope_set:
        raise ValueError(
            "rule_status_by_id must cover every in-scope rule exactly once "
            "(missing or unknown rows are not allowed)"
        )
    selected_set = set(selected)
    for rule_id in in_scope_set - selected_set:
        if statuses[rule_id] != NOT_RUN:
            raise ValueError(
                "unselected in-scope rules must have NOT_RUN status: "
                "{id!r}".format(id=rule_id)
            )
    attempted = sorted(rule for rule in in_scope if statuses[rule] != NOT_RUN)
    not_run = sorted(rule for rule in in_scope if statuses[rule] == NOT_RUN)
    attempted_set = set(attempted)
    coverage_complete = attempted_set == in_scope_set
    conclusion_complete = all(
        statuses[rule] in TERMINAL_STATUSES for rule in in_scope
    )
    return {
        "in_scope_count": len(in_scope),
        "selected_count": len(selected),
        "attempted_count": len(attempted),
        "not_run_count": len(not_run),
        "coverage_complete": coverage_complete,
        "conclusion_complete": conclusion_complete,
        "attempted": attempted,
        "not_run": not_run,
    }


def derive_conformance_status(profile, selected_rule_ids, in_scope_rule_ids,
                              rule_status_by_id, execution_contract_ok=True):
    """按 06 §4 / contract-delta status_algorithm 计算领域状态，返回单个字符串
    FAILED / BLOCKED / SUCCEEDED / PARTIAL。

    输入契约：
    - profile：None → "full"（handoff 5.2「底层方法没有 execution_profile 时按
      full 处理」在状态函数层同样成立的解读；这是冻结测试 docstring 结构假设 12
      标注的待 Codex 最终复审裁决点，实现按此执行）；未知值 → ValueError（结构失败）。
    - selected_rule_ids / in_scope_rule_ids：字符串数组、无重复、selected 必须是
      in-scope 的子集，违反 → ValueError（结构失败；与 derive_coverage 的
      结构假设 8 保持一致）。
    - rule_status_by_id：字典或键值对序列；合同错误（缺行/未知行/重复行/非法容器）
      返回 "BLOCKED" 而不抛异常（结构假设 2/7）；重复行在 FAIL 扫描之前判定
      （矩阵 11 纯重复用例：重复行中的 FAIL 不构成已证明 FAIL）。
    - execution_contract_ok：合同执行标志，False → BLOCKED（除非已证明 FAIL）。

    状态优先级（06 §4 精确顺序、contract-delta status_algorithm、handoff 5.2）：
    1. 任一所选规则状态为 FAIL → "FAILED"（优先于合同错误与 execution_contract_ok=False；
       矩阵 15 证明缺行 + FAIL 也返回 FAILED，因此 FAIL 检测不要求状态表完整）。
    2. 否则：execution_contract_ok 为 False，或状态表未恰好覆盖 in-scope
       （缺行/未知行/重复行），或任一未选择 in-scope 规则状态 != "NOT_RUN"
       （结构假设 9 合同不变量，contract-delta rule_result_scope），→ "BLOCKED"。
    3. 否则 full：coverage_complete（in-scope 无 NOT_RUN）且 conclusion_complete
       （全部 PASS/FAIL/NOT_APPLICABLE）→ "SUCCEEDED"；不满足 → "BLOCKED"
       （full 绝不返回 PARTIAL，contract-delta derived_invariants）。
    4. 否则（mechanical/economy/targeted）：全部所选规则状态 ∈ {PASS,
       NOT_APPLICABLE} → "PARTIAL"（即使覆盖与结论都完整也绝不 SUCCEEDED，
       矩阵 16）；任一所选规则为 EVIDENCE_MISSING / REVIEW_REQUIRED / NOT_RUN /
       其他非终态 → "BLOCKED"。

    输出契约：单个状态字符串。
    """
    if profile is None:
        profile = DEFAULT_PROFILE
    elif not (isinstance(profile, str) and profile in VALID_PROFILES):
        raise ValueError(
            "profile must be one of {valid} (or None for default full), "
            "got {value!r}".format(valid=VALID_PROFILES, value=profile)
        )
    selected = _as_unique_string_list(selected_rule_ids, "selected_rule_ids")
    in_scope = _as_unique_string_list(in_scope_rule_ids, "in_scope_rule_ids")
    in_scope_set = set(in_scope)
    selected_set = set(selected)
    for rule_id in selected:
        if rule_id not in in_scope_set:
            raise ValueError(
                "selected_rule_ids contains rule id outside in-scope: {id!r}".format(
                    id=rule_id
                )
            )
    ok, statuses = _normalize_status_table(rule_status_by_id)
    if not ok:
        # 结构合同错误（重复行/非法容器/键非字符串）→ BLOCKED（结构假设 2/7）。
        # 重复行必须先于 FAIL 扫描判定：纯重复用例中重复行里的 FAIL 是非法表内容，
        # 不是「已证明的 FAIL」（矩阵 11 *_pure 用例期望 BLOCKED）。
        return "BLOCKED"
    # 优先级 1：任一所选规则 FAIL → FAILED。该扫描不要求状态表完整（矩阵 15：
    # 缺行 + FAIL 仍 FAILED），因此放在缺行/未知行判定之前。
    for rule_id, status in statuses.items():
        if rule_id in selected_set and status == "FAIL":
            return "FAILED"
    # 优先级 2 合同错误：execution_contract_ok=False
    if not execution_contract_ok:
        return "BLOCKED"
    # 优先级 2 合同错误：状态表未恰好覆盖 in-scope（缺行/未知行）
    if set(statuses) != in_scope_set:
        return "BLOCKED"
    # 优先级 2 合同错误：未选择规则必须保持 NOT_RUN（结构假设 9，
    # contract-delta rule_result_scope「unselected rules use NOT_RUN」）
    for rule_id in in_scope_set - selected_set:
        if statuses[rule_id] != NOT_RUN:
            return "BLOCKED"
    if profile == "full":
        # 优先级 3：覆盖与结论都完整且无 FAIL → SUCCEEDED；否则 BLOCKED
        # （full 绝不返回 PARTIAL，contract-delta derived_invariants）。
        # FAIL 已在优先级 1 拦截，此处只需检查 NOT_RUN 与终态。
        coverage_complete = all(status != NOT_RUN for status in statuses.values())
        conclusion_complete = all(
            status in TERMINAL_STATUSES for status in statuses.values()
        )
        if coverage_complete and conclusion_complete:
            return "SUCCEEDED"
        return "BLOCKED"
    # 优先级 4：mechanical / economy / targeted —— 全部所选规则完成 → PARTIAL；
    # 其余（EVIDENCE_MISSING / REVIEW_REQUIRED / NOT_RUN / 未知状态）→ BLOCKED
    if all(
        statuses[rule_id] in COMPLETED_SELECTED_STATUSES for rule_id in selected
    ):
        return "PARTIAL"
    return "BLOCKED"
