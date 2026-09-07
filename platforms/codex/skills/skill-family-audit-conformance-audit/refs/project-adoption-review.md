# project_adoption 审阅细则（按需参考）

本文档是 `SKILL.md`「受检对象」`project_adoption` 条目的按需参考资料（SFA-CONTEXT-003 授权手段：把资料迁入按需参考）。进入条件与失败语义以 `SKILL.md` 与 canonical 规则投影为权威文本；本文只展开细则，不建立第二真源。

- **SPI 闭包**：通过平台包自带的离线 Profile SPI 运行，在受控 Node 22 进程中调用 Foundation Engineering Kit 公开入口 `verifyProjectProfile()`；权威 Bundle 版本以项目 `profile.json` 的 `adoption.foundation_pin` 与 foundation-pin 收据为准。SPI 通过结论码为 `SPE0000`；非 `SPE0000` 结果作为审计事实进入规则 finding。
- **证据集进入**：仅豁免载体（exemption-only）或仅 JSONL 冻结证据的证据集仍可进入审阅；适用规则证据缺失时诚实形成 `EVIDENCE_MISSING`。
- **不等于自身 Bundle**：Audit 接受项目真实声明且通过 SPI 的 Foundation profile，不要求它等于 Audit 自身 Bundle 使用的 `quickstart-profile`；Profile 规则本身不加宽。
- **历史裁决**：旧采用锁合同已按 D-8（2026-08-18）废弃，其现役消费、产出路径和 Schema 文件均已退出活跃合同树；历史裁决记录仍保留原始引用。
