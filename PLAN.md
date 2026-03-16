# SBI-Fuzz 分层实施计划

## 现状评估

本项目已建成的基础设施：

| 层级 | 组件 | 状态 |
|------|------|------|
| L3 系统级 | LibAFL + QEMU 全系统 fuzzer | ✅ 可用，edge coverage + SBI shared coverage |
| L1 宿主侧 | host_harness (OpenSBI C shim + RustSBI Rust adapter) | ✅ 单次执行可用，未接入 fuzzing loop |
| 输入格式 | TOML / ExecProgram / SequenceProgram | ✅ 三种格式完备 |
| 语义变异 | AddressValue / SizeValue / FlagsValue / HartIdValue | ✅ 基础池已有 |
| Schema | config/schemas/ 覆盖 HSM/IPI/RFENCE/Console/PMU | ✅ 可用 |
| Oracle | HSM hart0 status / pure call mismatch / crash / timeout | ⚠️ 仅两个语义 oracle |
| 平台故障注入 | host_harness 支持 ReturnSbiError/RawError/OverrideValue | ✅ 宿主侧可用 |
| 差分 | diff-sequence 命令 (OpenSBI vs RustSBI) | ⚠️ 仅单次比较，未入 loop |
| Campaign | run-sbi-fuzz-campaign.py / run-sequence-campaign.py | ✅ 自动化流水线 |
| Triage | triage / replay / bug-report / hang-stability / minimize | ✅ 完整 |

核心差距：host_harness 有完整的 ecall dispatch + 内存模型 + 故障注入，但没有接入 coverage-guided fuzzing loop；oracle 只覆盖了 HSM hart0 和 pure call 两个点；序列级变异是静态生成而非 fuzzer 驱动。

---

## 威胁模型

### 攻击面

S-mode supervisor 通过 ECALL 调用 M-mode SBI 固件。攻击者完全控制：
- EID / FID / a0–a5 寄存器
- S-mode 可见的物理内存内容和布局
- 调用时序和顺序
- 多 hart 并发调用模式

### 高价值 bug 分类

| 类别 | 典型模式 | 检测方式 |
|------|----------|----------|
| M1 内存安全 | OOB read/write, base+len 溢出, 未对齐访问 | sanitizer / host 内存模型断言 |
| M2 地址校验缺陷 | 只检查起始不检查区间, 跨页遗漏, hi:lo 拼接错 | spec oracle + 内存模型 |
| M3 状态机违例 | HSM 非法转换, 重复 start, stop→stop | 状态机 oracle |
| M4 后端回滚失败 | 平台回调失败后状态未恢复, 锁未释放 | 故障注入 + 状态断言 |
| M5 返回码违规 | 不支持的 EID 未返回 NOT_SUPPORTED, 错误码混淆 | spec oracle |
| M6 Hart-mask 解码错误 | base 偏移错, 高位截断, 空 mask 行为异常 | 差分 + spec oracle |
| M7 部分 I/O 语义错误 | DBCN partial write 返回值与实际写入不一致 | spec oracle |
| M8 多 hart 竞态 | TOCTOU, 并发状态污染 | 多 hart 序列 + 状态断言 |

---

## 阶段划分

```
Phase 0  基础补全        ← 让 host_harness 能被 coverage-guided fuzzer 驱动
Phase 1  Oracle 扩展     ← 从 2 个语义 oracle 扩展到覆盖 M1–M7
Phase 2  序列级 Fuzz     ← 把静态序列生成升级为 fuzzer 驱动的序列变异
Phase 3  差分闭环        ← OpenSBI vs RustSBI 自动差分 + 归类
Phase 4  系统级增强      ← 把 L1/L2 成果回灌到 L3 QEMU 路径
Phase 5  数据收割        ← triage / minimize / regression / 报告
```

---

## Phase 0：Host Harness Coverage-Guided Fuzzing Loop

### 目标

让 `host_harness` 的 ecall dispatch 路径能在 LibAFL (或 cargo-fuzz) 下以 >10k exec/s 的吞吐跑 coverage-guided fuzzing。

### 0.1 为 host_harness 添加 libFuzzer 兼容入口

**文件**: `host_harness/fuzz/` (新建 cargo-fuzz target)

```
host_harness/
├── fuzz/
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── fuzz_ecall_opensbi.rs      # OpenSBI ecall dispatch
│       ├── fuzz_ecall_rustsbi.rs      # RustSBI ecall dispatch
│       └── fuzz_sequence_both.rs      # 序列级，双目标
```

每个 target 的核心逻辑：
1. 从 fuzzer 字节流解码为 `HostHarnessInput`（结构化）
2. 调用 `host_harness::run(&input)`
3. 对返回的 `HostHarnessReport` 执行 oracle 检查
4. oracle 失败时 panic（让 fuzzer 捕获为 crash）

### 0.2 结构化输入解码器

**文件**: `common/src/host.rs` 扩展

从 fuzzer 的原始字节流中解码出 `HostHarnessInput`，而不是随机灌字节。策略：

```
字节布局 (变长，fuzzer 可自由变异):
[0]      target_kind: 0=OpenSBI, 1=RustSBI
[1]      mode: 0=Ecall, 1=PlatformFault
[2..10]  eid (u64 LE)
[10..18] fid (u64 LE)
[18..66] args[6] (6 × u64 LE)
[66]     hart_id (u8, 截断到 smp 范围)
[67]     hart_state (u8 mod 4)
[68]     privilege (u8 mod 3)
[69]     fault_mode (u8 mod 4)
[70..78] fault_error (i64 LE)
[78..86] fault_value (u64 LE)
[86]     fault_duplicate (u8 mod 2)
[87]     region_count (u8, 上限 4)
[88..]   regions: 每个 region = guest_addr(8) + perm(1) + len(2) + bytes(len)
```

关键设计：
- 地址字段用 `AddressValue::random` 的池做字典，但也允许 fuzzer 自由变异
- region 的 guest_addr 可以引用 args 中的地址值（建立关联）
- 当字节不足时用默认值填充，保证任何长度的输入都能解码

### 0.3 编译配置

OpenSBI C shim 需要用 `-fsanitize=address,undefined` 编译：

**文件**: `host_harness/build.rs` 修改

为 `opensbi_host_shim.c` 添加 ASan/UBSan 编译标志（仅在 `cfg(fuzzing)` 或环境变量控制下启用）。

### 0.4 字典文件

**文件**: `host_harness/fuzz/dict/sbi.dict`

包含所有已知 EID、FID、常见错误码、边界地址值的字典条目，供 libFuzzer 使用。

### 0.5 初始语料

**文件**: `host_harness/fuzz/corpus/` (自动生成)

复用 `helper generate-host-seeds` 的输出，转换为二进制格式作为初始语料。同时从 `config/schemas/` 中每个 (eid, fid) 组合生成至少一个合法调用种子。

### 0.6 验收标准

- [ ] `cd host_harness && cargo fuzz run fuzz_ecall_opensbi -- -max_len=512 -dict=fuzz/dict/sbi.dict` 能稳定运行
- [ ] 吞吐 > 5000 exec/s（单核，无 QEMU 开销）
- [ ] ASan 能捕获 OpenSBI shim 中的 OOB
- [ ] RustSBI target 能捕获 panic

### 涉及文件变更

| 文件 | 操作 |
|------|------|
| `host_harness/fuzz/Cargo.toml` | 新建 |
| `host_harness/fuzz/fuzz_targets/fuzz_ecall_opensbi.rs` | 新建 |
| `host_harness/fuzz/fuzz_targets/fuzz_ecall_rustsbi.rs` | 新建 |
| `host_harness/fuzz/dict/sbi.dict` | 新建 |
| `host_harness/build.rs` | 修改：添加 sanitizer 编译标志 |
| `common/src/host.rs` | 修改：添加 `HostHarnessInput::from_fuzz_bytes()` |
| `helper/src/seed_generator.rs` | 修改：添加 `export-fuzz-corpus` 子命令 |

---

## Phase 1：Oracle 扩展

### 目标

从当前 2 个 oracle（HSM hart0 status、pure call mismatch）扩展到覆盖 M1–M7 全部 bug 类别。

### 1.1 Spec Oracle 框架

**文件**: `common/src/spec_oracle.rs` (新建)

```rust
pub struct SpecOracleVerdict {
    pub passed: bool,
    pub violation: Option<SpecViolation>,
}

pub enum SpecViolation {
    UnsupportedExtensionWrongError { eid: u64, got: i64 },
    InvalidAddressNotRejected { eid: u64, fid: u64, addr: u64, len: u64 },
    HsmIllegalTransition { from: HartState, to: HartState, op: &'static str },
    PartialIoInconsistent { reported: u64, actual: u64 },
    WrongErrorCode { expected: i64, got: i64, context: String },
    HartMaskInvalidNotRejected { hart_id: u64 },
}

pub fn check_ecall_result(
    input: &HostHarnessInput,
    report: &HostEcallReport,
    memory_model: &MemoryModel,
) -> Vec<SpecViolation>;
```

### 1.2 各扩展的 Oracle 规则

#### Base Extension (EID 0x10)

| 规则 | 检查 |
|------|------|
| B1 | 所有 Base 函数必须返回 `SBI_SUCCESS` |
| B2 | `probe_extension` 对已知扩展返回非零 value |
| B3 | `get_spec_version` 返回值 ≥ 2（SBI v2.0+）|
| B4 | 不存在的 FID 返回 `NOT_SUPPORTED` |

#### HSM Extension (EID 0x48534D)

| 规则 | 检查 |
|------|------|
| H1 | `hart_start` 对已 STARTED 的 hart 返回 `ALREADY_AVAILABLE` |
| H2 | `hart_stop` 只能由 hart 自身调用 |
| H3 | `hart_get_status` 对无效 hartid 返回 `INVALID_PARAM` |
| H4 | 状态转换必须符合 spec 状态机图 |
| H5 | `hart_suspend` 的 suspend_type 高位保留位非零时返回 `INVALID_PARAM` |

#### Debug Console (EID 0x4442434E)

| 规则 | 检查 |
|------|------|
| D1 | 非法地址范围 → `INVALID_PARAM` |
| D2 | partial write 时 `value` ≤ 请求的 `num_bytes` |
| D3 | `write_byte` 不接受地址参数 |
| D4 | 后端拒绝 → `DENIED`，后端失败 → `FAILED` |

#### IPI / RFENCE

| 规则 | 检查 |
|------|------|
| R1 | 无效 hartid 在 mask 中 → `INVALID_PARAM` |
| R2 | hart_mask_base = -1 时表示所有 hart |
| R3 | 不可用 hart → 跳过但不报错（或 `INVALID_PARAM`，取决于实现）|

#### PMU

| 规则 | 检查 |
|------|------|
| P1 | `num_counters` 返回 `SBI_SUCCESS` |
| P2 | counter_idx 超出范围 → `INVALID_PARAM` |
| P3 | `snapshot_set_shmem` 地址不合法 → `INVALID_PARAM` |

### 1.3 内存模型 Oracle

**文件**: `common/src/memory_oracle.rs` (新建)

在 host_harness 执行前后对比 memory region 内容：

```rust
pub struct MemoryOracle {
    pre_snapshot: Vec<RegionSnapshot>,
}

impl MemoryOracle {
    /// 调用前快照
    pub fn snapshot_before(regions: &[HostMemoryRegion]) -> Self;

    /// 调用后检查
    pub fn check_after(
        &self,
        regions: &[HostMemoryRegion],
        report: &HostEcallReport,
    ) -> Vec<MemoryViolation>;
}

pub enum MemoryViolation {
    /// 只读 region 被修改
    ReadOnlyRegionModified { region_index: usize },
    /// 不相关 region 被修改（调用不应触及的区域）
    UnrelatedRegionModified { region_index: usize },
    /// 写入超出 region 边界
    WriteExceedsBounds { region_index: usize, written: usize, capacity: usize },
}
```

### 1.4 Oracle 集成到 fuzz target

在每个 fuzz target 的 harness 函数中：

```rust
fn harness(input: &HostHarnessInput) {
    let mem_oracle = MemoryOracle::snapshot_before(&input.memory_regions);
    let report = host_harness::run(input).expect("harness run");

    // Spec oracle
    if let HostHarnessResult::Ecall(ref ecall) = report.result {
        let violations = check_ecall_result(input, ecall, &memory_model);
        if !violations.is_empty() {
            panic!("spec violation: {:?}", violations[0]);
        }
    }

    // Memory oracle
    let mem_violations = mem_oracle.check_after(&input.memory_regions, &report);
    if !mem_violations.is_empty() {
        panic!("memory violation: {:?}", mem_violations[0]);
    }
}
```

### 1.5 验收标准

- [ ] 每个扩展至少 3 条 spec oracle 规则实现并有单元测试
- [ ] 内存 oracle 能检测只读区域被修改
- [ ] 在已知 bug 样本上 oracle 能正确触发

### 涉及文件变更

| 文件 | 操作 |
|------|------|
| `common/src/spec_oracle.rs` | 新建 |
| `common/src/memory_oracle.rs` | 新建 |
| `common/src/lib.rs` | 修改：pub mod spec_oracle / memory_oracle |
| `host_harness/fuzz/fuzz_targets/*.rs` | 修改：集成 oracle |
| `common/tests/spec_oracle.rs` | 新建：oracle 单元测试 |

---

## Phase 2：序列级 Fuzzer 驱动变异

### 目标

把当前静态生成的 `SequenceProgram` 升级为 fuzzer 可在线变异的序列，实现 stateful coverage-guided fuzzing。

### 2.1 序列变异器

**文件**: `common/src/sequence_mutation.rs` (新建)

变异操作集：

| 变异 | 描述 |
|------|------|
| InsertStep | 在随机位置插入一个新 Call/SetHartState/SetPlatformFault step |
| RemoveStep | 删除一个随机 step |
| SwapSteps | 交换两个 step 的顺序 |
| MutateStepArgs | 对某个 Call step 的参数做语义变异 |
| MutateStepEidFid | 替换某个 Call step 的 eid/fid |
| MutateCallerHart | 改变某个 step 的 caller hart |
| MutateMemoryObject | 修改某个 memory object 的地址/权限/内容 |
| InjectFault | 在某个 step 前插入 SetPlatformFault |
| DuplicateStep | 复制某个 step（测试重复调用） |
| SpliceSequence | 从语料库中取另一个序列的片段拼接 |

### 2.2 序列级 fuzz target

**文件**: `host_harness/fuzz/fuzz_targets/fuzz_sequence_opensbi.rs` (新建)

```rust
fn harness(bytes: &[u8]) {
    let program = SequenceProgram::from_fuzz_bytes(bytes, smp=4);
    let mut state_tracker = HsmStateTracker::new(smp=4);

    for step in &program.steps {
        let input = step.to_host_harness_input(&program.memory, &state_tracker);
        let mem_oracle = MemoryOracle::snapshot_before(&input.memory_regions);
        let report = host_harness::run(&input).expect("run");

        // 更新状态追踪
        state_tracker.update(&step, &report);

        // Spec oracle（含状态机检查）
        let violations = check_sequence_step(&step, &report, &state_tracker);
        if !violations.is_empty() {
            panic!("sequence violation at step {}: {:?}", step_idx, violations[0]);
        }

        // Memory oracle
        let mem_v = mem_oracle.check_after(&input.memory_regions, &report);
        if !mem_v.is_empty() {
            panic!("memory violation at step {}: {:?}", step_idx, mem_v[0]);
        }
    }
}
```

### 2.3 HSM 状态机追踪器

**文件**: `common/src/hsm_tracker.rs` (新建)

```rust
pub struct HsmStateTracker {
    hart_states: Vec<HsmHartState>,
}

pub enum HsmHartState {
    Started,
    Stopped,
    StartPending,
    StopPending,
    Suspended,
    SuspendPending,
    ResumePending,
}

impl HsmStateTracker {
    pub fn new(smp: u16) -> Self;

    /// 根据 step 和 report 更新状态
    pub fn update(&mut self, step: &SequenceStep, report: &HostHarnessReport);

    /// 检查当前状态是否合法
    pub fn check_invariants(&self) -> Vec<HsmViolation>;

    /// 给定操作，预测合法的返回码集合
    pub fn expected_outcomes(&self, op: HsmOp, target_hart: u64) -> Vec<i64>;
}
```

### 2.4 序列解码器

**文件**: `common/src/sequence.rs` 扩展

添加 `SequenceProgram::from_fuzz_bytes(bytes: &[u8], smp: u16) -> Self`：

```
字节布局:
[0..2]   step_count (u16 LE, 上限 32)
[2]      memory_object_count (u8, 上限 8)
[3..]    memory objects: 每个 = guest_addr(8) + perm(1) + len(2) + bytes(len)
[..]     steps: 每个 step = kind(1) + payload(变长)
         kind=0: Call { eid(8) + fid(8) + args[6](48) + caller_hart(1) }
         kind=1: SetTargetHart { hart_id(1) }
         kind=2: SetHartState { hart_id(1) + state(1) }
         kind=3: SetPlatformFault { mode(1) + error(8) + value(8) }
         kind=4: BusyWait { iterations(2) }
```

### 2.5 验收标准

- [ ] 序列 fuzzer 能在 host_harness 上以 >1000 exec/s 运行
- [ ] 能发现至少一个需要 ≥2 步才能触发的 bug
- [ ] HSM 状态机追踪器有完整单元测试
- [ ] 变异器能产生有效的多 hart 交错序列

### 涉及文件变更

| 文件 | 操作 |
|------|------|
| `common/src/sequence_mutation.rs` | 新建 |
| `common/src/hsm_tracker.rs` | 新建 |
| `common/src/sequence.rs` | 修改：添加 from_fuzz_bytes |
| `common/src/lib.rs` | 修改：pub mod |
| `host_harness/fuzz/fuzz_targets/fuzz_sequence_opensbi.rs` | 新建 |
| `host_harness/fuzz/fuzz_targets/fuzz_sequence_rustsbi.rs` | 新建 |

---

## Phase 3：差分闭环

### 目标

将现有的 `diff-sequence` 单次比较能力升级为 fuzzer 驱动的自动差分发现，系统化地找出 OpenSBI 与 RustSBI 之间的行为不一致。

### 3.1 差分 fuzz target

**文件**: `host_harness/fuzz/fuzz_targets/fuzz_diff_ecall.rs` (新建)

```rust
fn harness(bytes: &[u8]) {
    let input_template = HostHarnessInput::from_fuzz_bytes(bytes);

    // 同一输入分别跑两个目标
    let mut input_opensbi = input_template.clone();
    input_opensbi.target_kind = HostTargetKind::OpenSbi;
    let mut input_rustsbi = input_template.clone();
    input_rustsbi.target_kind = HostTargetKind::RustSbi;

    let report_a = host_harness::run(&input_opensbi);
    let report_b = host_harness::run(&input_rustsbi);

    match (report_a, report_b) {
        (Ok(a), Ok(b)) => {
            let diffs = diff_reports(&a, &b, &DIFF_POLICY);
            if !diffs.is_empty() {
                panic!("differential: {:?}", diffs[0]);
            }
        }
        // 一方 crash 另一方正常 → 也是差异
        (Err(_), Ok(_)) | (Ok(_), Err(_)) => {
            panic!("one target crashed, the other didn't");
        }
        _ => {} // 都失败则跳过
    }
}
```

### 3.2 差分策略配置

**文件**: `common/src/diff_policy.rs` (新建)

不是所有差异都是 bug。需要一个策略层来过滤已知的合法差异：

```rust
pub struct DiffPolicy {
    /// 忽略 implementation-defined 的返回值差异
    pub ignore_impl_defined_value: bool,
    /// 忽略 NOT_SUPPORTED vs 具体错误码（扩展支持范围不同）
    pub ignore_unsupported_extension_diff: bool,
    /// 只比较错误码，不比较 value（对 info 类调用）
    pub error_code_only_eids: HashSet<u64>,
    /// 已知差异白名单
    pub known_diffs: Vec<KnownDiff>,
}

pub struct DiffResult {
    pub field: &'static str,  // "sbi_error" / "value" / "memory" / "side_effects"
    pub opensbi: String,
    pub rustsbi: String,
    pub severity: DiffSeverity,
}

pub enum DiffSeverity {
    /// 至少一方违反 spec
    SpecViolation,
    /// 行为不同但 spec 允许
    ImplementationDefined,
    /// 已知差异，已白名单
    KnownAccepted,
}
```

### 3.3 差分序列 fuzz target

**文件**: `host_harness/fuzz/fuzz_targets/fuzz_diff_sequence.rs` (新建)

对序列级输入做差分：同一 `SequenceProgram` 分别在 OpenSBI 和 RustSBI 后端执行，逐步比较每一步的返回值和状态变化。

### 3.4 差分结果归类

差分发现的不一致自动归类为：

| 类别 | 处理 |
|------|------|
| 一方 crash | 高优先级 bug |
| 错误码不同 | 检查 spec，判定谁错 |
| value 不同 | 检查是否 implementation-defined |
| 内存写入不同 | 检查 spec 对该调用的内存语义 |
| 状态转换不同 | 检查 HSM 状态机 spec |

### 3.5 验收标准

- [ ] 差分 fuzzer 能稳定运行，不因已知差异误报
- [ ] 能发现至少一个"一方符合 spec 另一方不符合"的差异
- [ ] 差分结果自动归类并输出 JSON 报告
- [ ] 白名单机制能有效过滤 implementation-defined 差异

### 涉及文件变更

| 文件 | 操作 |
|------|------|
| `common/src/diff_policy.rs` | 新建 |
| `common/src/lib.rs` | 修改：pub mod diff_policy |
| `host_harness/fuzz/fuzz_targets/fuzz_diff_ecall.rs` | 新建 |
| `host_harness/fuzz/fuzz_targets/fuzz_diff_sequence.rs` | 新建 |

---

## Phase 4：系统级增强（L3 回灌）

### 目标

将 L1/L2 在 host_harness 上发现的 bug pattern 回灌到 L3 QEMU 全系统路径，验证真实 trap/fault 环境下的行为，并增强 L3 自身的 oracle 能力。

### 4.1 Oracle 回灌到 injector

当前 injector 只有 HSM hart0 status 和 pure call mismatch 两个 oracle。将 Phase 1 的 spec oracle 规则移植到 injector 的 exec 解释器中。

**文件**: `injector/src/injector.c` 修改

新增 oracle 检查点：

```c
// 在 exec_call 返回后
if (call_id == CALL_CONSOLE_WRITE) {
    // D2: partial write 时 value <= num_bytes
    if (ret.error == SBI_SUCCESS && ret.value > args[0]) {
        oracle_fail(ORACLE_DBCN_PARTIAL_OVERFLOW, instr_idx, ...);
    }
}

if (call_id == CALL_HSM_HART_START) {
    // H1: 对已 STARTED 的 hart 返回 ALREADY_AVAILABLE
    // (需要在 injector 中维护简单的 hart 状态表)
}
```

### 4.2 Spec Oracle Buffer 扩展

当前 `SBI_ORACLE_FAILURE_BUFFER` 只有 9 个 word。扩展 oracle kind 枚举：

```c
#define ORACLE_HSM_HART0_STATUS      1  // 已有
#define ORACLE_PURE_CALL_MISMATCH    2  // 已有
#define ORACLE_DBCN_PARTIAL_OVERFLOW 3  // 新增
#define ORACLE_DBCN_INVALID_NOT_REJECTED 4
#define ORACLE_HSM_ILLEGAL_TRANSITION 5
#define ORACLE_UNSUPPORTED_WRONG_ERROR 6
#define ORACLE_HARTMASK_INVALID_ACCEPTED 7
```

### 4.3 Host-found bug 转换为 L3 回归种子

**文件**: `helper/src/seed_generator.rs` 扩展

添加命令：`helper convert-host-crash-to-exec <crash-input>`

将 host_harness 发现的 crash 输入转换为 `.exec` 格式，可直接在 L3 QEMU 路径回放验证。

### 4.4 Coverage 增强

当前 L3 使用 QEMU edge coverage + SBI shared coverage buffer。增强：

1. 在 injector 中为每个 oracle 检查点添加独立的 coverage 标记，让 fuzzer 能区分"到达了 oracle 检查"和"没到达"
2. 为 exec 程序的不同调用序列模式添加 coverage 标记

**文件**: `injector/src/injector.c` 修改

```c
// 在 oracle 检查前后插入 coverage marker
static volatile uint8_t oracle_coverage[32];
#define ORACLE_COVER(id) do { oracle_coverage[id] = 1; } while(0)
```

### 4.5 验收标准

- [ ] injector 中至少新增 3 个 oracle 检查点
- [ ] host_harness 发现的 crash 能转换为 L3 可回放的 .exec 文件
- [ ] L3 路径能独立发现至少一个 spec violation（不依赖 host_harness）

### 涉及文件变更

| 文件 | 操作 |
|------|------|
| `injector/src/injector.c` | 修改：新增 oracle + coverage marker |
| `common/src/exec.rs` | 修改：新增 oracle kind 常量 |
| `helper/src/seed_generator.rs` | 修改：添加 convert 命令 |
| `fuzzer/src/fuzz.rs` | 修改：读取扩展的 oracle buffer |

---

## Phase 5：数据收割与报告

### 目标

将所有层级的发现汇总、去重、最小化，形成可用于论文/报告的数据集。

### 5.1 统一 Triage 流水线

扩展现有的 `triage-sbi-results.py` 和 `triage-sequence-results.py`，增加对 host_harness fuzz 结果的支持：

**文件**: `scripts/triage-host-fuzz-results.py` (新建)

- 读取 `host_harness/fuzz/artifacts/` 下的 crash 文件
- 对每个 crash 重放并提取：触发的 oracle 类型、EID/FID、参数摘要、crash 签名
- 按 (oracle_type, eid, fid, error_pattern) 去重
- 输出 JSON + Markdown 报告

### 5.2 跨层去重

**文件**: `scripts/cross-layer-dedup.py` (新建)

同一个 bug 可能在 L1 (host_harness)、L2 (sequence)、L3 (QEMU) 三个层级都被发现。需要跨层去重：

1. 提取每个 crash 的规范化签名：`(target, eid, fid, oracle_type, error_pattern)`
2. 合并同签名的 crash，保留每层的最小复现样本
3. 标记"仅 L3 可复现"的 bug（真实 trap 路径依赖）

### 5.3 最小化增强

扩展现有的 `minimize-hang` 能力到所有 oracle 类型：

**文件**: `helper/src/sequence_runner.rs` 修改

添加 `minimize-spec-violation` 子命令：对触发 spec violation 的序列做步骤级最小化（逐步删除 step，保留能触发同一 violation 的最短序列）。

### 5.4 回归测试集

**文件**: `tests/regression/` (新建目录)

每个确认的 bug 生成一个回归测试：
- `.toml` / `.seq` / `.exec` 格式的最小复现输入
- 预期的 oracle violation 类型
- 可在 CI 中自动回放验证

### 5.5 统计指标收集

**文件**: `scripts/collect-metrics.py` (新建)

自动收集并输出：

| 指标 | 来源 |
|------|------|
| 各层级吞吐 (exec/s) | fuzzer 日志 / libFuzzer 输出 |
| 覆盖率增长曲线 | edge coverage 时间序列 |
| unique crash 数 | triage 去重后 |
| unique spec violation 数 | oracle 分类 |
| time-to-first-crash | fuzzer 日志 |
| time-to-first-spec-violation | fuzzer 日志 |
| 各 oracle 类型命中分布 | triage 统计 |
| 差分发现数 | diff triage |
| 跨层确认率 | cross-layer dedup |

### 5.6 验收标准

- [ ] 所有 crash 有去重后的最小复现样本
- [ ] 回归测试集可在 `make test-regression` 下自动运行
- [ ] 统计指标能自动生成 JSON 报告
- [ ] 跨层去重能正确合并同一 bug 的多层发现

### 涉及文件变更

| 文件 | 操作 |
|------|------|
| `scripts/triage-host-fuzz-results.py` | 新建 |
| `scripts/cross-layer-dedup.py` | 新建 |
| `scripts/collect-metrics.py` | 新建 |
| `helper/src/sequence_runner.rs` | 修改：添加 minimize-spec-violation |
| `tests/regression/` | 新建目录 |
| `Makefile` | 修改：添加 test-regression target |

---

## 各扩展专项 Fuzz 策略

### Debug Console (DBCN) — 最高优先级

DBCN 是地址 + 长度 + 部分 I/O 语义的典型代表，bug 密度最高。

#### 输入空间

| 参数 | 语义 | 高价值变异 |
|------|------|-----------|
| a0 | num_bytes / byte | 0, 1, 0xFFF, 0x1000, 0x1001, u32::MAX, u64::MAX |
| a1 | base_addr_lo | 合法 region 起始, 跨页, 未对齐, 未映射, 0, u64::MAX |
| a2 | base_addr_hi | 0 (RV64), 非零 (应被拒绝) |

#### 必须覆盖的场景矩阵

```
write(合法地址, 合法长度)                    → SUCCESS, value=num_bytes
write(合法地址, 0)                           → SUCCESS, value=0
write(合法起始, 长度越过 region 末尾)         → INVALID_PARAM
write(未映射地址, 任意长度)                   → INVALID_PARAM
write(只读 region, 任意长度)                  → INVALID_PARAM (或 SUCCESS 取决于方向)
write(合法地址, 合法长度, 后端 partial)       → SUCCESS, 0 < value < num_bytes
write(合法地址, 合法长度, 后端 deny)          → DENIED
write(合法地址, 合法长度, 后端 fail)          → FAILED
write_byte(任意 byte)                        → SUCCESS
read(合法可写地址, 合法长度)                  → SUCCESS, value ≤ num_bytes
read(只读地址, 合法长度)                      → INVALID_PARAM (需要写权限)
```

#### 种子

从 `config/schemas/console.toml` 的 3 个 FID 各生成 10+ 变体，覆盖上述矩阵。

### HSM — 第二优先级

#### 状态机

```
STOPPED ──hart_start──→ START_PENDING ──→ STARTED
STARTED ──hart_stop───→ STOP_PENDING ──→ STOPPED
STARTED ──hart_suspend─→ SUSPEND_PENDING ──→ SUSPENDED
SUSPENDED ──resume────→ RESUME_PENDING ──→ STARTED
```

#### 必须覆盖的序列

```
[start(hart1), start(hart1)]           → 第二次 ALREADY_AVAILABLE
[start(hart1), stop(hart1), stop(hart1)] → 第二次应失败
[start(hart1), suspend(hart1), start(hart1)] → 应失败（suspended≠stopped）
[status(hart_invalid)]                  → INVALID_PARAM
[start(hart0)]                          → ALREADY_AVAILABLE（boot hart）
[stop(hart0)]                           → 只能自身调用
多 hart 交错: hart0 start hart1, hart1 start hart2, hart2 stop hart1
```

#### 种子

从 `helper generate-sequence-seeds` 已有的 HSM 序列扩展，添加上述非法序列。

### IPI / RFENCE — 第三优先级

#### Hart-mask 变异重点

| 场景 | hart_mask | hart_mask_base |
|------|-----------|----------------|
| 空 mask | 0x0 | 0 |
| 全 1 | 0xFFFFFFFFFFFFFFFF | 0 |
| 单 hart | 0x1 | target_hart |
| 高位 hart | 0x1 | 63 |
| 无效 base | 0x1 | smp_count + 1 |
| base = -1 | 任意 | 0xFFFFFFFFFFFFFFFF (所有 hart) |
| 稀疏 | 0x5 | 0 (hart 0 和 2) |

#### RFENCE 额外参数

`sfence_vma` 的 start_addr 和 size 也是地址 + 长度语义，复用 DBCN 的地址变异策略。

### PMU — 第四优先级

#### 重点

- counter_idx 边界：0, num_counters-1, num_counters, u64::MAX
- config_matching 的 flags 组合
- snapshot_set_shmem 的地址校验（复用地址变异）
- counter start/stop 的状态依赖（需要序列）

---

## 实施时间线

### 第 1 周：Phase 0 (host_harness fuzzing loop)

| 天 | 任务 |
|----|------|
| D1 | 创建 `host_harness/fuzz/` cargo-fuzz 项目骨架 |
| D2 | 实现 `HostHarnessInput::from_fuzz_bytes()` 结构化解码 |
| D3 | 实现 `fuzz_ecall_opensbi` target，验证能跑 |
| D4 | 添加 ASan 编译标志到 build.rs，创建字典文件 |
| D5 | 实现 `fuzz_ecall_rustsbi` target，生成初始语料 |
| D6 | 基准测试：吞吐、初始覆盖率、首次运行 24h |
| D7 | 修复首轮发现的 harness 稳定性问题 |

### 第 2 周：Phase 1 前半 (spec oracle 框架 + Base/DBCN oracle)

| 天 | 任务 |
|----|------|
| D1 | 设计并实现 `spec_oracle.rs` 框架 |
| D2 | 实现 Base extension oracle 规则 B1–B4 |
| D3 | 实现 DBCN oracle 规则 D1–D4 |
| D4 | 实现 `memory_oracle.rs` |
| D5 | 集成 oracle 到 fuzz target，单元测试 |
| D6 | 带 oracle 运行 24h，收集首批 spec violation |
| D7 | Triage 首批结果，调整 oracle 阈值 |

### 第 3 周：Phase 1 后半 (HSM/IPI/PMU oracle) + Phase 2 启动

| 天 | 任务 |
|----|------|
| D1 | 实现 HSM oracle 规则 H1–H5 |
| D2 | 实现 IPI/RFENCE oracle 规则 R1–R3 |
| D3 | 实现 PMU oracle 规则 P1–P3 |
| D4 | 设计 `sequence_mutation.rs` 变异器 |
| D5 | 实现 `SequenceProgram::from_fuzz_bytes()` |
| D6 | 实现 `hsm_tracker.rs` |
| D7 | 实现 `fuzz_sequence_opensbi` target |

### 第 4 周：Phase 2 完成 + Phase 3 启动

| 天 | 任务 |
|----|------|
| D1 | 序列 fuzzer 稳定化，修复解码边界问题 |
| D2 | 添加序列级 oracle（状态机检查） |
| D3 | 序列 fuzzer 运行 48h，收集结果 |
| D4 | 实现 `diff_policy.rs` |
| D5 | 实现 `fuzz_diff_ecall` target |
| D6 | 实现 `fuzz_diff_sequence` target |
| D7 | 差分 fuzzer 运行 24h，收集首批差异 |

### 第 5 周：Phase 3 完成 + Phase 4

| 天 | 任务 |
|----|------|
| D1 | 差分结果 triage，建立白名单 |
| D2 | 将 spec oracle 移植到 injector (L3) |
| D3 | 扩展 oracle buffer，添加新 oracle kind |
| D4 | 实现 host crash → exec 转换 |
| D5 | L3 带新 oracle 运行 campaign |
| D6 | 对比 L1/L3 发现，验证跨层一致性 |
| D7 | 修复 L3 独有的 oracle 误报 |

### 第 6 周：Phase 5 (数据收割)

| 天 | 任务 |
|----|------|
| D1 | 实现 `triage-host-fuzz-results.py` |
| D2 | 实现 `cross-layer-dedup.py` |
| D3 | 全量 triage + 去重 |
| D4 | 最小化所有 crash / spec violation |
| D5 | 建立回归测试集 |
| D6 | 实现 `collect-metrics.py`，生成统计报告 |
| D7 | 最终数据整理，输出完整报告 |

---

## 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| OpenSBI C shim 在 ASan 下不稳定 | Phase 0 阻塞 | 先不开 ASan，用 UBSan only；或只 fuzz RustSBI |
| 结构化输入解码器产生大量无效输入 | 吞吐浪费 | 添加 `is_valid()` 快速拒绝，配合字典提高有效率 |
| Spec oracle 误报率高 | 人工 triage 成本 | 先只启用高置信度规则，逐步放开 |
| 序列变异器产生的序列太长 | 吞吐下降 | 限制最大步数 (32)，添加长度惩罚 |
| 差分白名单不完整 | 大量已知差异淹没真实 bug | 先跑一轮收集所有差异，人工分类后建白名单 |
| L3 oracle 移植引入 injector bug | 假阳性 | 先在 host_harness 验证 oracle 正确性，再移植 |

---

## 文件总览

### 新建文件

```
common/src/spec_oracle.rs          # Spec oracle 框架
common/src/memory_oracle.rs        # 内存模型 oracle
common/src/diff_policy.rs          # 差分策略
common/src/hsm_tracker.rs          # HSM 状态机追踪
common/src/sequence_mutation.rs    # 序列变异器
common/tests/spec_oracle.rs        # Oracle 单元测试
host_harness/fuzz/Cargo.toml       # cargo-fuzz 配置
host_harness/fuzz/fuzz_targets/fuzz_ecall_opensbi.rs
host_harness/fuzz/fuzz_targets/fuzz_ecall_rustsbi.rs
host_harness/fuzz/fuzz_targets/fuzz_sequence_opensbi.rs
host_harness/fuzz/fuzz_targets/fuzz_sequence_rustsbi.rs
host_harness/fuzz/fuzz_targets/fuzz_diff_ecall.rs
host_harness/fuzz/fuzz_targets/fuzz_diff_sequence.rs
host_harness/fuzz/dict/sbi.dict
scripts/triage-host-fuzz-results.py
scripts/cross-layer-dedup.py
scripts/collect-metrics.py
tests/regression/
```

### 修改文件

```
common/src/lib.rs                  # 新 mod 声明
common/src/host.rs                 # from_fuzz_bytes()
common/src/sequence.rs             # from_fuzz_bytes()
common/src/exec.rs                 # 新 oracle kind 常量
host_harness/build.rs              # sanitizer 编译标志
injector/src/injector.c            # 新 oracle + coverage marker
helper/src/seed_generator.rs       # export-fuzz-corpus / convert 命令
helper/src/sequence_runner.rs      # minimize-spec-violation
fuzzer/src/fuzz.rs                 # 扩展 oracle buffer 读取
Makefile                           # test-regression target
```
