# SBI Fuzz 项目缺陷检查与多场景 BUG 报告实施计划（2026-03-20）

> 目标：给出面向 **SBI 固件（OpenSBI / RustSBI）** 的实战缺陷清单、场景化 fuzz 路径、以及可落地的 BUG report 产线方案。

## 1. 当前能力基线（已具备）

结合仓库现状，当前项目已经具备：

- 主机侧 fuzz 入口（ecall / sequence / diff）与语料生成脚本。
- triage / replay / summarize / report 的结果处理流水线。
- campaign 脚本（可按 profile 驱动 fuzz + replay + bug-report）。
- 覆盖 OpenSBI 与 RustSBI 两条目标路径，并支持复杂多 hart 场景。

因此，后续重点不是“从 0 到 1”，而是“补齐工程闭环和质量门禁”。

## 2. 针对 SBI fuzz 工具的关键缺陷（Gap）

### G1. 文档与仓库现实存在漂移

- `Readme.md` 仍指向 `TODO.md`，但仓库中不存在该文件，容易误导新用户。  
- 部分命令说明很丰富，但缺少“最小可复现路径”的统一入口（新用户不清楚先跑哪条链路）。

### G2. 缺少统一 CI 编排入口

- 仓库未看到 `.github/workflows/*` 这类公开 CI 配置，当前验证主要依赖本地 `make test-*`。  
- 缺少“PR 必跑最小集合”（例如：格式检查 + 单测 + 脚本冒烟 + 报告 schema 校验）。

### G3. 差分 fuzz 默认入口偏单一

- `host-fuzz-diff` 目前默认只跑 `fuzz_diff_ecall`，而序列差分（`fuzz_diff_sequence`）更多依赖其他流程触发。  
- 这会导致跨实现差异更容易聚焦在单调用，而不是状态序列差异。

### G4. BUG report 规范化字段仍可加强

当前已有 JSON/Markdown 输出，但从运营角度仍建议补充：

- 统一 `bug_id`（跨层 dedup 后稳定不变）。
- `repro_stability`（复现稳定度）提升为一级字段。
- `impact`（如 crash/hang/spec_violation）与 `affected_target`（opensbi/rustsbi/both）的固定枚举。
- `fix_hint`（自动给出可能修复方向，如参数校验/状态机/并发同步）。

### G5. 质量门禁可更偏“发布可用”

- 目前质量门禁偏“统计聚合”，建议额外增加“阻断项”：
  - 新增高危 bug（sanitizer/crash）数量上升时阻断。
  - 已回归关闭的 bug 再出现时阻断。
  - replay 不稳定比例高于阈值时阻断。

## 3. 多场景 fuzz 与 BUG report 的目标产线

## 3.1 场景分层

1. **S0 - 快速回归（开发机 / PR 前）**
   - 目标：10~30 分钟确认无明显回退。
   - 路径：host fuzz smoke + triage + metrics。

2. **S1 - 单实现深挖（RustSBI/OpenSBI）**
   - 目标：单目标高吞吐挖掘 crash/hang/spec 违规。
   - 路径：`host-fuzz-rustsbi` / OpenSBI 对应 campaign。

3. **S2 - 序列状态机场景（多 hart）**
   - 目标：挖掘 HSM 状态迁移、并发竞态、时序问题。
   - 路径：`host-fuzz-sequence` + complex profile + hang-stability。

4. **S3 - 差分一致性场景（OpenSBI vs RustSBI）**
   - 目标：发现实现不一致并自动分桶（可接受差异 vs 可疑差异）。
   - 路径：`host-fuzz-diff` + cross-layer-dedup。

5. **S4 - 系统级确认（QEMU/L3）**
   - 目标：将 host 发现提升到系统级复现，降低“仅 harness 可见”的风险。
   - 路径：`campaign-opensbi` / `campaign-rustsbi` + replay。

## 3.2 统一 BUG report 结构（建议）

每个缺陷至少包含：

- `bug_id`: 稳定主键（由 semantic_signature + target + class 哈希得到）
- `title`: 一句话缺陷摘要
- `target`: `opensbi` / `rustsbi` / `both`
- `layer`: `host_single` / `host_sequence` / `host_diff` / `qemu`
- `classification`: `sanitizer` / `crash` / `hang` / `spec_violation` / `mismatch`
- `reproducer`: 最小输入路径（.host/.seq/.exec）
- `replay`: 最近 N 次复现结果（通过/失败、稳定度）
- `first_seen` / `last_seen`
- `eid` / `fid` / `hart_topology`
- `oracle`: 命中的 oracle 规则（可多值）
- `dedup_key`: 用于跨层合并
- `fix_hint`: 自动建议（参数检查、状态机保护、锁/并发修复等）

## 4. 详细实施计划（四阶段）

### Phase A（第 1~2 周）：建立“可重复跑通”的标准路径

**交付物**

- `docs/` 下新增《Runbook（场景 -> 命令 -> 产物路径）》。
- `make` 新增聚合目标：`preflight`, `smoke-all`, `report-all`。
- README 增加“10 分钟最小闭环”。

**任务分解**

1. 固化标准目录约定：
   - 原始结果：`output/<scenario>/result`
   - triage：`output/<scenario>/triage.*`
   - report：`output/<scenario>/bugs.*`
2. 给每个场景定义“输入、命令、退出码、产物”四元组。
3. 增加脚本健壮性：当依赖缺失时返回可行动错误（而不是 silent skip）。

**验收**

- 任意新成员按 runbook 能在新机器 30 分钟内完成 S0。

### Phase B（第 3~4 周）：报告标准化与去重稳定化

**交付物**

- `scripts/report-*.py` 输出统一 schema v1。
- 增加 `bug_id` 与 `repro_stability`。
- cross-layer dedup 将同根因问题合并为单 bug 卡片。

**任务分解**

1. 在报告阶段引入字段标准化映射。
2. 对 hang/stability/minimize 结果进行关联回填。
3. Markdown 报告按“严重度 -> 稳定度 -> 影响范围”排序。

**验收**

- 同一问题在 host 与 qemu 两层发现时，最终只出现 1 条主 bug，且保留多 repro 引用。

### Phase C（第 5~6 周）：多场景自动化 campaign

**交付物**

- 新增“日跑/周跑”profile（短跑与长跑）。
- 自动产出 `latest.json` + `latest.md` + `delta.md`（与上一周期对比）。

**任务分解**

1. 为 S0~S4 建 profile（duration、smp、replay 次数、门禁阈值）。
2. 统一 campaign 元数据（机器信息、commit、toolchain、profile）。
3. 自动生成趋势图输入（CSV/JSON），供 dashboard 使用。

**验收**

- 可一键执行“周跑”，输出新增 bug、已修复 bug、回归 bug 三类清单。

### Phase D（第 7~8 周）：质量门禁与回归防线

**交付物**

- 质量门禁策略 v1：发布阻断项 + 警告项。
- `tests/regression/` 新增来自真实 fuzz finding 的回归样例。

**任务分解**

1. 门禁规则：
   - Blocker: 新增 sanitizer/crash 高危 bug。
   - Blocker: 已关闭 bug 复发。
   - Warning: hang 稳定度下降。
2. 每个已修复 bug 至少有一个最小化回归输入。
3. 回归测试接入默认 test 套件。

**验收**

- 连续两周周跑，报告结构稳定且门禁能正确阻断回归。

## 5. 你现在可以直接执行的实操流程

1. **环境与基础检查**
   - `make check-env`
   - `make host-fuzz-corpus`
   - `make host-fuzz-smoke`

2. **按场景 fuzz**
   - S1（单实现）：`make host-fuzz-rustsbi`
   - S2（序列）：`make host-fuzz-sequence`
   - S3（差分）：`make host-fuzz-diff`
   - S4（系统级）：`make campaign-opensbi` / `make campaign-rustsbi`

3. **产出报告**
   - `make triage-host-fuzz`
   - `make collect-metrics`
   - `make quality-gate`
   - （系统级）`make -C playground/<target> bug-report`

4. **做跨层去重与结论汇总**
   - `make cross-layer-dedup`
   - 汇总 JSON + Markdown，按 bug_id 追踪生命周期。

5. **进入修复与回归闭环**
   - 对稳定 bug 做最小化 reproducer。
   - 将 reproducer 写入 `tests/regression/`。
   - 修复后执行 regression + smoke + quality gate。

## 6. 风险与缓解建议

- **风险 R1：环境依赖复杂导致跑不通**  
  缓解：优先使用 host 路径做主验证，QEMU 路径作为升级确认。

- **风险 R2：差分噪声过高**  
  缓解：维护 diff 白名单与分类策略，把“实现允许差异”降噪。

- **风险 R3：hang 太多且不稳定**  
  缓解：启用稳定性重放 + 自动最小化，先看 stable_hang。

- **风险 R4：报告太多但不可执行**  
  缓解：强制每个高优先级 bug 附带最小 repro + 修复建议 + 影响层级。

## 7. 建议优先级（从今天开始）

- **P0（本周）**：修 README 漂移（TODO.md 链接）、补 runbook、固定 S0 一键流程。  
- **P1（两周）**：统一报告 schema（bug_id / stability / dedup_key）。  
- **P2（三到四周）**：完善差分 + 序列场景并纳入固定周跑。  
- **P3（长期）**：host -> qemu 跨层证据自动串联，形成持续质量平台。

---