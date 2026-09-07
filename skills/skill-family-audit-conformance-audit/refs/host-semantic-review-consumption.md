# 宿主程序内消费已接受的审阅结果（按需参考）

本文档是 `SKILL.md`「语义审阅结果接入」的按需参考资料（SFA-CONTEXT-003
授权手段：把长流程资料迁入按需参考）。授权规则、失败语义与四项接受条件
以 `SKILL.md` 为权威入口文本；本文只展开调用顺序，不建立第二真源。

宿主已经有认可的审阅来源和接受记录时，可以分阶段调用现有函数并保留同一实际 Task。下面的顺序已经由现有测试用真实 Foundation Bundle 跑过；测试使用的规范包带有 `test_fixture: true`，只能证明传输和绑定，不代表生产审计已获语义通过。

1. 用 Quickstart 的 `extract_business_parameters("conformance", method_args)` 解析 `--evidence-set`、`--target-type` 等业务参数。再用 `resolve_method_contract(platform_root, "conformance")` 取得参数与结果 Schema 引用，用 `validate_by_schema_id(runner, parameter_schema, parameters)` 校验参数。`runner` 必须来自已校验的受管 Foundation Bundle（权威版本以项目 `profile.json` 的 `adoption.foundation_pin` 与 foundation-pin 收据为准）；不要改用 sibling import、临时环境变量或 fallback 入口。
2. 用同一证据文件调用 `create_foundation_task(runner, resource, operation_id=run_id, method="conformance-audit", parameters=parameters)`。Task 创建后，调用 `call_foundation(runner, "digest-document", {"document": task})["digest"]` 派生 `foundation_task_digest`。后续预检和消费都复用这个摘要，不能手填或从任务 ID 推导。
3. 调用 `run_workflow` 时保留同一 `evidence_set`、`target_type`、规范包和 `run_id`，并传入派生的 `foundation_task_digest` 与 `semantic_review_preflight=True`。读取返回的 `semantic_review_request`，把其中的 `review_request_digest`、`evidence_set_digest`、`reviewed_rule_set_digest`、规则描述和证据摘要交给认可的审阅职责。
4. 宿主接受该次结果后，忠实消费原始审阅记录构造 v2 `internal_semantic_review`，再用同一组 Task 参数调用 `run_workflow`，将 `semantic_review_preflight` 设为 `False`。`reviews` 必须覆盖且只覆盖请求中的规则；每个 `binding_id`、规则修订摘要、证据角色、定位符和证据摘要都从该次请求与原始材料取得。已有非结构化记录只能忠实转录，不能为使绑定成功而重填旧摘要；缺少角色、理由或证据时保留 `EVIDENCE_MISSING`，不得补造或提升为 `PASS`。
5. 用前一步取得的结果 Schema，再调用 `validate_by_schema_id(runner, result_schema, workflow_result)`。最后用 `wrap_foundation_result` 和 `assert_foundation_exchange` 包装并校验同一 Task 的 Result。领域结果仍为 `FAILED`、`EVIDENCE_MISSING` 或 `REVIEW_REQUIRED` 时，Result 也保留该失败事实；交换校验通过只说明 Task/Result 绑定有效，不说明语义结论正确。

这条程序内路径不改变 CLI 边界：`--semantic-review-stdin` 仍以退出码 2、顶层 `BLOCKED` 和 `SEMANTIC_REVIEW_PRODUCER_UNTRUSTED` 失败关闭。
