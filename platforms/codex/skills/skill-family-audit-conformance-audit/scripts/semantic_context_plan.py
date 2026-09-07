"""语义上下文计划：证据角色预筛、按 review family 装箱与子结果集合校验。

对应交接单 5.3 与规格 03 §5、04 §2.2/§2.4/§2.5/§2.6/§4、06 §3、14 §3.3，
并落实整改交接单 2026-08-27 第六节：6.1 scope_disposition 结构化适用性
门禁、6.2 rule/binding 的 revision_digest 绑定、6.3 证据行六字段（无
fixture_name）、6.4 装箱前预筛记录 canonical_id 去重。本模块只处理已经
通过上游结构校验的 Audit 领域描述，只提供普通 Python 值上的纯函数：不
读取路径、不读取证据文件、不重算摘要、不估算词元、不调用模型、不调用
semantic_review.finalize_review，也不导入或模拟 Foundation。返回值是
普通列表与字典，不含 token 估算、不含 PASS/FAIL。

对外函数固定为：
- build_semantic_preflight(rule_rows, binding_rows, evidence_role_rows)
- pack_semantic_candidates(preflight_rows, group_registry)
- validate_child_result_rows(parent_rows, child_result_rows)

行结构合同与判定语义以冻结测试
tests/first-tier/test_semantic_context_plan.py 为准：结构违约一律
ValueError 失败关闭（先校验后计算）。
"""

_PACKING_COSTS = ("compact", "standard", "heavy")
_BOX_CAPACITY = {"compact": 12, "standard": 6, "heavy": 2}
_APPLICABILITY_VALUES = ("APPLICABLE", "NOT_APPLICABLE", "UNDETERMINED")
_ROLE_STATUS_VALUES = ("READY", "MISSING", "NOT_REQUIRED")
_SCOPE_DISPOSITION_VALUES = ("APPLICABLE", "NOT_APPLICABLE", "UNDETERMINED")

_RULE_FIELDS = (
    "canonical_id", "group_id", "revision_digest",
    "semantic_review_required", "scope_disposition", "citable_scope_facts",
)
_BINDING_FIELDS = (
    "canonical_id", "binding_id", "revision_digest", "required_evidence_roles",
)
_EVIDENCE_FIELDS = (
    "canonical_id", "role", "evidence_kind", "evidence_id", "sha256", "locator",
)
_PREFLIGHT_FIELDS = (
    "canonical_id", "group_id", "applicability_preflight",
    "evidence_role_status", "missing_evidence_roles",
    "semantic_review_required",
)
_RESULT_FIELDS = (
    "canonical_id", "revision_digest", "binding_id", "evidence_refs",
)


def build_semantic_preflight(rule_rows, binding_rows, evidence_role_rows):
    """对每条分组规则恰好生成一条预筛记录。

    - 只有 scope_disposition == "NOT_APPLICABLE" 且 citable_scope_facts
      非空时 → NOT_APPLICABLE + NOT_REQUIRED，missing_evidence_roles 为空
      （与证据观测无关）；显式 NOT_APPLICABLE 但没有引用事实 → ValueError；
    - 其余 disposition（APPLICABLE/UNDETERMINED）即使携带范围事实也不得
      提升为不适用，一律按证据判定：必需角色只从 binding 行读取，任一缺失
      → UNDETERMINED + MISSING，缺失角色按排序列出；全部就绪且
      semantic_review_required 为真 → UNDETERMINED + READY；全部就绪且为假
      → APPLICABLE + READY；
    - 同一 canonical_id 的 rule 行与 binding 行 revision_digest 必须完全
      一致，不一致 → ValueError（先于证据角色映射与 READY 生成）；
    - 角色判定只认 evidence_role_rows 的 role 值，不依据 evidence_kind、
      evidence_id、sha256 或 locator 反推；任何字段值不得出现 PASS/FAIL。
    """
    _validate_rule_rows(rule_rows)
    _validate_binding_rows(binding_rows, rule_rows)
    _validate_evidence_role_rows(evidence_role_rows, rule_rows)

    binding_by_id = {row["canonical_id"]: row for row in binding_rows}
    observed_roles = {}
    for row in evidence_role_rows:
        observed_roles.setdefault(row["canonical_id"], set()).add(row["role"])

    records = []
    for rule in rule_rows:
        canonical_id = rule["canonical_id"]
        if (rule["scope_disposition"] == "NOT_APPLICABLE"
                and rule["citable_scope_facts"]):
            records.append({
                "canonical_id": canonical_id,
                "group_id": rule["group_id"],
                "applicability_preflight": "NOT_APPLICABLE",
                "evidence_role_status": "NOT_REQUIRED",
                "missing_evidence_roles": [],
                "semantic_review_required": rule["semantic_review_required"],
            })
            continue
        required = set(binding_by_id[canonical_id]["required_evidence_roles"])
        missing = sorted(required - observed_roles.get(canonical_id, set()))
        if missing:
            applicability, role_status = "UNDETERMINED", "MISSING"
        elif rule["semantic_review_required"]:
            applicability, role_status = "UNDETERMINED", "READY"
        else:
            applicability, role_status = "APPLICABLE", "READY"
        records.append({
            "canonical_id": canonical_id,
            "group_id": rule["group_id"],
            "applicability_preflight": applicability,
            "evidence_role_status": role_status,
            "missing_evidence_roles": missing,
            "semantic_review_required": rule["semantic_review_required"],
        })
    return records


def pack_semantic_candidates(preflight_rows, group_registry):
    """过滤、稳定排序并贪心装箱语义审阅候选，返回普通装箱单。

    - 候选 = evidence_role_status == READY 且 semantic_review_required 为真
      且 applicability_preflight != NOT_APPLICABLE；
    - 直接校验 A1 Registry 的 groups[]/rules[] 嵌套形状，以及全部预筛行
      canonical_id 与 group_id 的登记归属；装箱前校验 preflight_rows 的
      canonical_id 唯一，重复 → ValueError（不静默去重）；review_family
      来自 group 行，packing_cost 来自 rule 行，packing_cost_ceiling 不参与
      装箱；违约一律 ValueError；排序在过滤之后，键为
      (review_family, packing_cost 成本序, group_id, canonical_id)；
    - 同一箱只含一个 review family 与一个 packing cost；容量上限
      compact=12、standard=6、heavy=2，满箱或 family/cost 变化时开新箱，
      同一 family/cost 的相邻小组可共箱，同组可跨箱拆分（group_id 不变）；
    - 返回普通列表：每个元素是一个箱（稳定顺序的 canonical_id 字符串
      列表）；空候选返回 []，不含 token 估算与 PASS/FAIL。
    """
    registry_by_rule = _index_group_registry(group_registry)
    if not isinstance(preflight_rows, list):
        raise ValueError("preflight_rows 必须是列表")
    for row in preflight_rows:
        _validate_preflight_row(row)
    seen_ids = set()
    for row in preflight_rows:
        if row["canonical_id"] in seen_ids:
            raise ValueError("preflight_rows 的 canonical_id 重复：%s"
                             % row["canonical_id"])
        seen_ids.add(row["canonical_id"])
    for row in preflight_rows:
        registry_rule = registry_by_rule.get(row["canonical_id"])
        if registry_rule is None:
            raise ValueError("canonical_id 未在 group registry 登记：%s"
                             % row["canonical_id"])
        if row["group_id"] != registry_rule["group_id"]:
            raise ValueError("canonical_id 的 group_id 与 registry 不一致：%s"
                             % row["canonical_id"])

    candidates = [
        row for row in preflight_rows
        if row["evidence_role_status"] == "READY"
        and row["semantic_review_required"] is True
        and row["applicability_preflight"] != "NOT_APPLICABLE"
    ]
    cost_order = {cost: index for index, cost in enumerate(_PACKING_COSTS)}
    candidates.sort(key=lambda row: (
        registry_by_rule[row["canonical_id"]]["review_family"],
        cost_order[registry_by_rule[row["canonical_id"]]["packing_cost"]],
        row["group_id"],
        row["canonical_id"],
    ))
    boxes = []
    current_box = []
    current_family = None
    current_cost = None
    current_capacity = None
    for row in candidates:
        registry_rule = registry_by_rule[row["canonical_id"]]
        family = registry_rule["review_family"]
        cost = registry_rule["packing_cost"]
        capacity = _BOX_CAPACITY[cost]
        if current_box and (
            family != current_family or cost != current_cost
            or len(current_box) >= current_capacity
        ):
            boxes.append(current_box)
            current_box = []
        if not current_box:
            current_family = family
            current_cost = cost
            current_capacity = capacity
        current_box.append(row["canonical_id"])
    if current_box:
        boxes.append(current_box)
    return boxes


def validate_child_result_rows(parent_rows, child_result_rows):
    """校验子结果集合精确覆盖 parent 请求，返回排序后的子结果列表本身。

    - child 的 canonical_id 集合必须与 parent 完全相等、每条恰好一次；
      遗漏、重复、越界/未知 → ValueError；
    - 每条 child 行的 revision_digest、binding_id、evidence_refs 必须与
      parent 对应行一致（evidence_refs 按完全相等比较，顺序敏感）；
    - 成功后只返回按 canonical_id 排序的 child 行本身，不附加字段、不
      构建 internalReviewV2、不计算任何摘要；结构违约一律 ValueError。
    """
    _validate_result_rows(parent_rows, "parent 行")
    _validate_result_rows(child_result_rows, "child 行")
    parent_ids = [row["canonical_id"] for row in parent_rows]
    if len(parent_ids) != len(set(parent_ids)):
        raise ValueError("parent canonical_id 重复")
    parent_by_id = {row["canonical_id"]: row for row in parent_rows}
    child_ids = [row["canonical_id"] for row in child_result_rows]
    if set(child_ids) != set(parent_by_id):
        raise ValueError("child 与 parent 的 canonical_id 集合不一致")
    if len(child_ids) != len(parent_ids):
        raise ValueError("child 行数与 parent 不一致（存在重复或遗漏）")
    for child in child_result_rows:
        parent = parent_by_id[child["canonical_id"]]
        if child["revision_digest"] != parent["revision_digest"]:
            raise ValueError("revision_digest 不一致：%s"
                             % child["canonical_id"])
        if child["binding_id"] != parent["binding_id"]:
            raise ValueError("binding_id 不一致：%s" % child["canonical_id"])
        if child["evidence_refs"] != parent["evidence_refs"]:
            raise ValueError("evidence_refs 不一致：%s" % child["canonical_id"])
    return sorted(child_result_rows, key=lambda row: row["canonical_id"])


# --------------------------------------------------------------------------
# 私有校验辅助：结构违约一律 ValueError 失败关闭（先校验后计算）
# --------------------------------------------------------------------------

def _require_dict(value, what):
    if not isinstance(value, dict):
        raise ValueError("%s必须是 dict" % what)


def _require_non_empty_string(value, field):
    if not isinstance(value, str) or not value:
        raise ValueError("%s 必须是非空字符串" % field)


def _require_string_list(value, field):
    if not isinstance(value, list):
        raise ValueError("%s 必须是字符串列表" % field)
    if not all(isinstance(item, str) and item for item in value):
        raise ValueError("%s 的元素必须是非空字符串" % field)


def _index_group_registry(group_registry):
    """校验并索引 A1 Registry 的 groups[]/rules[] 真实嵌套形状。"""
    _require_dict(group_registry, "group_registry")
    groups = group_registry.get("groups")
    if not isinstance(groups, list):
        raise ValueError("group_registry.groups 必须是列表")
    seen_groups = set()
    registry_by_rule = {}
    for group in groups:
        _require_dict(group, "group registry group 行")
        group_id = group.get("group_id")
        review_family = group.get("review_family")
        rules = group.get("rules")
        _require_non_empty_string(group_id, "group_id")
        _require_non_empty_string(review_family, "review_family")
        if group_id in seen_groups:
            raise ValueError("group_id 重复：%s" % group_id)
        seen_groups.add(group_id)
        if not isinstance(rules, list) or not rules:
            raise ValueError("group rules 必须是非空列表")
        for rule in rules:
            _require_dict(rule, "group registry rule 行")
            canonical_id = rule.get("canonical_id")
            packing_cost = rule.get("packing_cost")
            _require_non_empty_string(canonical_id, "canonical_id")
            if packing_cost not in _PACKING_COSTS:
                raise ValueError("packing_cost 必须是 compact/standard/heavy")
            if canonical_id in registry_by_rule:
                raise ValueError("canonical_id 在 registry 中重复：%s"
                                 % canonical_id)
            registry_by_rule[canonical_id] = {
                "group_id": group_id,
                "review_family": review_family,
                "packing_cost": packing_cost,
            }
    return registry_by_rule


def _validate_rule_rows(rule_rows):
    if not isinstance(rule_rows, list):
        raise ValueError("rule_rows 必须是列表")
    seen = set()
    for row in rule_rows:
        _require_dict(row, "rule 行")
        for field in _RULE_FIELDS:
            if field not in row:
                raise ValueError("rule 行缺少字段：%s" % field)
        _require_non_empty_string(row["canonical_id"], "canonical_id")
        _require_non_empty_string(row["group_id"], "group_id")
        _require_non_empty_string(row["revision_digest"], "revision_digest")
        if not isinstance(row["semantic_review_required"], bool):
            raise ValueError("semantic_review_required 必须是 bool")
        if row["scope_disposition"] not in _SCOPE_DISPOSITION_VALUES:
            raise ValueError(
                "scope_disposition 必须是 APPLICABLE/NOT_APPLICABLE/"
                "UNDETERMINED"
            )
        _require_string_list(row["citable_scope_facts"], "citable_scope_facts")
        if (row["scope_disposition"] == "NOT_APPLICABLE"
                and not row["citable_scope_facts"]):
            raise ValueError(
                "scope_disposition 为 NOT_APPLICABLE 时必须提供非空 "
                "citable_scope_facts：%s" % row["canonical_id"])
        if row["canonical_id"] in seen:
            raise ValueError("canonical_id 重复：%s" % row["canonical_id"])
        seen.add(row["canonical_id"])


def _validate_binding_rows(binding_rows, rule_rows):
    if not isinstance(binding_rows, list):
        raise ValueError("binding_rows 必须是列表")
    rule_by_id = {row["canonical_id"]: row for row in rule_rows}
    seen = set()
    for row in binding_rows:
        _require_dict(row, "binding 行")
        for field in _BINDING_FIELDS:
            if field not in row:
                raise ValueError("binding 行缺少字段：%s" % field)
        _require_non_empty_string(row["canonical_id"], "canonical_id")
        _require_non_empty_string(row["binding_id"], "binding_id")
        _require_non_empty_string(row["revision_digest"], "revision_digest")
        _require_string_list(row["required_evidence_roles"],
                             "required_evidence_roles")
        if row["canonical_id"] not in rule_by_id:
            raise ValueError("binding 目标规则不存在：%s"
                             % row["canonical_id"])
        if row["revision_digest"] != (
                rule_by_id[row["canonical_id"]]["revision_digest"]):
            raise ValueError("rule 与 binding 的 revision_digest 不一致：%s"
                             % row["canonical_id"])
        if row["canonical_id"] in seen:
            raise ValueError("同一规则重复绑定：%s" % row["canonical_id"])
        seen.add(row["canonical_id"])
    missing_binding = sorted(set(rule_by_id) - seen)
    if missing_binding:
        raise ValueError("规则缺少绑定行：%s" % ", ".join(missing_binding))


def _validate_evidence_role_rows(evidence_role_rows, rule_rows):
    if not isinstance(evidence_role_rows, list):
        raise ValueError("evidence_role_rows 必须是列表")
    rule_ids = {row["canonical_id"] for row in rule_rows}
    for row in evidence_role_rows:
        _require_dict(row, "evidence 行")
        for field in _EVIDENCE_FIELDS:
            if field not in row:
                raise ValueError("evidence 行缺少字段：%s" % field)
        _require_non_empty_string(row["canonical_id"], "canonical_id")
        _require_non_empty_string(row["role"], "role")
        _require_non_empty_string(row["evidence_kind"], "evidence_kind")
        _require_non_empty_string(row["evidence_id"], "evidence_id")
        _require_non_empty_string(row["sha256"], "sha256")
        _require_non_empty_string(row["locator"], "locator")
        if row["canonical_id"] not in rule_ids:
            raise ValueError("证据观测目标规则不存在：%s"
                             % row["canonical_id"])


def _validate_preflight_row(row):
    _require_dict(row, "preflight 行")
    for field in _PREFLIGHT_FIELDS:
        if field not in row:
            raise ValueError("preflight 行缺少字段：%s" % field)
    _require_non_empty_string(row["canonical_id"], "canonical_id")
    _require_non_empty_string(row["group_id"], "group_id")
    if row["applicability_preflight"] not in _APPLICABILITY_VALUES:
        raise ValueError("applicability_preflight 枚举非法")
    if row["evidence_role_status"] not in _ROLE_STATUS_VALUES:
        raise ValueError("evidence_role_status 枚举非法")
    if not isinstance(row["semantic_review_required"], bool):
        raise ValueError("semantic_review_required 必须是 bool")
    _require_string_list(row["missing_evidence_roles"],
                         "missing_evidence_roles")


def _validate_result_rows(rows, what):
    if not isinstance(rows, list):
        raise ValueError("%s必须是列表" % what)
    for row in rows:
        _require_dict(row, what)
        missing_fields = set(_RESULT_FIELDS) - set(row)
        if missing_fields:
            raise ValueError("%s缺少必填字段：%s" % (
                what, ", ".join(sorted(missing_fields))))
        _require_non_empty_string(row["canonical_id"], "canonical_id")
        _require_non_empty_string(row["revision_digest"], "revision_digest")
        _require_non_empty_string(row["binding_id"], "binding_id")
        _require_string_list(row["evidence_refs"], "evidence_refs")
