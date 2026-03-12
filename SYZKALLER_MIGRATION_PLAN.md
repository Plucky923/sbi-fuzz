# Syzkaller Migration Plan for `sbifuzz`

这份文档定义 `sbifuzz` 下一阶段把 syzkaller 架构逐步迁移到 `S-Mode payload -> M-Mode SBI/OpenSBI` 场景中的详细实施计划。

和 `TODO.md` 的区别是：

- `TODO.md` 负责威胁建模与高层路线图；
- 本文档负责“下一步怎么做”，并且要求每一步都有明确、可执行、可验收的测试方案。

## 1. 当前状态总结

截至当前版本，仓库已经完成以下“第一阶段骨架迁移”：

- 引入了 syzkaller 风格的 exec 输入流骨架：`common/src/exec.rs`
- 引入了最小 call descriptor 表和 `raw_ecall` 兼容入口：`common/src/exec.rs`
- 将 injector 从“单次固定 64-byte SBI 调用”扩展为“可解释多条指令的执行器”原型：`injector/src/injector.c`
- 让 `helper run/debug` 与 `fuzzer` 默认优先走 exec wire format，同时保留 legacy raw input 兼容：`helper/src/runner.rs`、`fuzzer/src/fuzz.rs`

这意味着下一阶段的目标，不再是“证明可以执行一条 SBI 调用”，而是要把以下几个关键能力补齐：

1. 输入格式稳定化；
2. ABI/调用描述外部化；
3. 真实的覆盖率回传；
4. triage / report / repro 闭环；
5. 多 Hart 并发与状态机测试；
6. 最终朝着 syzkaller 风格 host/guest 分层继续靠拢。

## 1.5 当前进度（2026-03-06）

- [x] `Step 0` 已完成最小落地：新增环境探测脚本 `scripts/check-env.sh`，并接入 `make check-env` / `make check-env-smoke`。
- [x] `Step 0` 已完成自动验证：运行过 `bash -n scripts/check-env.sh`、`./scripts/check-env.sh --help`、`./scripts/check-env.sh --verbose`、`make check-env`。
- [x] `Step 0` 已补充 QEMU bridge 依赖探测：`check-env` 现在会检查 `glib-2.0` 与 `pixman-1` 开发包，避免环境被误判为完整。
- [x] `Step 0` 已补充 LLVM/Clang 依赖探测：`check-env` 现在也会检查 `llvm-config` 与 `clang`，覆盖 bindgen/QEMU bridge 的关键前置条件。
- [x] `Step 1` 已完成最小落地：新增 `common/tests/exec_format.rs`，覆盖 registry 完整性、单调用 round-trip、多调用 round-trip、malformed 输入拒绝、参数归一化幂等性。
- [x] `Step 1` 已完成自动验证：`cargo test -p common` 通过，当前共有 5 个 exec-format 相关测试。
- [~] `Step 2` 已完成代码落地：新增 `validate_exec_call_table` / `format_exec_call_table` / `exec_call_table`，并在 `helper` 中加入 `list-calls` 命令。
- [x] `Step 2` 已完成端到端验证：在 `llvm-18` / `clang-18` 环境下，`cargo check -p helper -p fuzzer` 和 `helper list-calls` / `helper import-linux-corpus` 已可正常运行。
- [x] 已确认稳定运行路径：当前仓库默认通过 Makefile 导出 `llvm-18` / `clang-18` 优先级，规避了 `clang-20` 路径下的 bindgen/QEMU bridge 兼容问题。
- [x] 已将稳定工具链写入 `.cargo/config.toml` 默认环境，减少直接使用 `cargo helper` / `cargo fuzzer` 时的环境噪音。
- [x] `Step 3` 已完成基础落地：新增 `scripts/import-linux-sbi-corpus.py`，可把 Linux 风格 `sbi_ecall(...)` 调用提取为 TOML seeds。
- [x] `Step 3` 已完成基础自动验证：新增 `scripts/test-import-linux-sbi-corpus.sh` 与 fixture `tests/fixtures/linux-corpus/sample_sbi_calls.c`，并通过 `make test-linux-corpus-import` 验证。
- [x] `Step 4` 已完成 common 层基础落地：新增 `SbiError` / `SbiRet` / `is_standard_sbi_error_code`，为 host 侧错误分类提供统一语义。
- [x] `Step 4` 已完成基础自动验证：`cargo test -p common` 现覆盖 6 个测试，其中包含 SBI 错误码映射稳定性测试。
- [x] 已完成首轮真实 OpenSBI fuzz：`playground/opensbi-fuzz` 成功完成 `prepare`，并实际运行短时 fuzz，观察到 corpus/objective/edges 持续增长。
- [x] 已完成首轮 smoke fuzz 稳定化：修复 `capacity overflow` 后再次运行短时 fuzz，退出时不再因 `Error::ShuttingDown` 触发 panic。
- [x] 已完成 OpenSBI 结果 triage 与 replay 基础设施：新增 `scripts/triage-opensbi-results.py`、`scripts/replay-opensbi-results.py`，并验证 `.exec` 回放优先于 `.toml` 更保真。
- [x] 已完成 OpenSBI sanitizer-demo 样本验证：固定 `test-heap-overflow.toml` 可稳定观察到 `KASAN` 输出，`test-integer-overflow.toml` 可稳定观察到 `UBSAN` 输出。
- [x] 首轮真实 fuzz 暴露并修复了一个实际缺陷：`exec_program_from_bytes` 对异常 `nargs` 缺少边界检查，已补上并新增回归测试。
- [~] `Step 5` 已完成 shared-memory 覆盖率基础设施：新增 `common/src/coverage.rs`、固定 buffer 地址 `0x809fc000`、injector `SBI_COVERAGE_BUFFER`、`helper coverage-info` / `collect-coverage`，并在 `helper` / `fuzzer` 中接入 reset/collect + fallback signal 桥接；`instrument-kasan` 现会为 OpenSBI 注入 `trace-pc` shared-coverage hook，`helper run` 可做基础 PC 符号化，且新增 `scripts/check-opensbi-coverage.py` 与 `make test-opensbi-coverage` 用于 `cover.raw` / `cover.json` 导出和稳定性 smoke。
- [~] `Step 6` 已完成第一版 bug-report 闭环：`replay-opensbi-results.py` 现输出 `classification/signals/signature`，新增 `report-opensbi-bugs.py` 与 `make -C playground/opensbi-fuzz bug-report`，可把 replay 结果按 sanitizer/crash/hang bucket 聚合。

## 2. 计划使用原则

### 2.1 实施原则

- 每一步必须先完成“最小闭环”，再做增强。
- 每一步都必须同时定义：实现范围、测试范围、通过标准、失败回滚点。
- 优先保证 `OpenSBI + QEMU virt` 可重复，`RustSBI` 作为第二目标并行验证。
- 任何新能力都需要保留至少一个最小 repro 样本，避免只靠 fuzz 偶发命中。

### 2.2 测试原则

每个步骤至少覆盖五类测试：

- **静态检查**：格式化、编译、lint 或结构检查。
- **单元测试**：针对新增编码器、解析器、schema、分类器的确定性测试。
- **集成测试**：通过 `helper run` / `helper debug` / QEMU 运行真实固件。
- **回归测试**：验证旧输入、旧目标、旧示例没有被破坏。
- **验收测试**：站在使用者视角，验证这一阶段是否真的可用。

### 2.3 测试产物约定

每一步的测试都要尽量保存如下产物：

- 输入样本：`.toml` / `.exec`
- 运行日志：`qemu.log` / `serial.log`
- 崩溃样本：`crash.toml` / `crash.exec`
- 覆盖率样本：`cover.raw` / `cover.json`
- 分类结果：`triage.json`

建议统一保存到类似目录：

```text
artifacts/
  step-01/
  step-02/
  ...
```

## 3. 阶段化实施计划

---

## Step 0：环境基线与可重复构建

### 目标

把开发环境和验证环境固定下来，解决“能写代码但无法稳定构建/运行”的问题。

### 预期改动

- 补充环境依赖文档：交叉工具链、`ninja`、QEMU、GDB、RISC-V 编译工具等。
- 增加环境检查脚本，快速报告缺失依赖。
- 为 `injector`、`helper`、`fuzzer` 提供分层检查命令。

### 建议落点

- `Readme.md`
- 新增 `scripts/check-env.sh` 或 `helper` 子命令
- 可能新增 `docs/` 或根目录环境说明

### 详细测试

#### Test 0.1：环境探测脚本正确识别依赖

**目的**
- 确保常见缺失项能被提前发现，而不是在 fuzz 过程中才失败。

**操作**
- 在具备完整依赖的机器上运行环境检查脚本。
- 在故意缺少 `ninja`、`riscv64-unknown-elf-gcc`、`qemu-system-riscv64` 的机器上分别运行。

**检查点**
- 能分别报告每个缺失依赖。
- 错误消息包含可操作建议。
- 返回码非 0。

**通过标准**
- 对每种缺失情况都能输出明确、单独的错误项。

#### Test 0.2：最小构建链检查

**目的**
- 确保三个关键部分可独立验证：`common`、`injector`、`helper/fuzzer`。

**操作**
- 运行：
  - `cargo check -p common`
  - `make -C injector compile`
  - `cargo check -p helper -p fuzzer`

**检查点**
- 每个命令都能独立成功或在缺依赖时给出明确错误。

**通过标准**
- 在完整环境下全部成功。
- 在缺依赖环境下能定位失败原因。

#### Test 0.3：示例目标基线运行

**目的**
- 确保 OpenSBI / RustSBI playground 没有在迁移中静默失效。

**操作**
- 运行：
  - `make -C playground/opensbi-fuzz prepare`
  - `make -C playground/rustsbi-fuzz prepare`

**检查点**
- 两个目标都能构建到可运行镜像。

**通过标准**
- 至少 OpenSBI 路径成功；RustSBI 失败时必须有明确 issue 记录。

### Done 标准

- 环境依赖被文档化；
- 能一条命令检查环境；
- 能稳定构建至少 OpenSBI 基线。

---

## Step 1：exec wire format 稳定化与兼容性封版

### 目标

把当前 `common/src/exec.rs` 的原型格式固化成“可长期兼容”的 wire format v1，并补齐测试。

### 预期改动

- 为 exec format 写清楚版本、magic、指令集、参数类型、限制值。
- 补充 encode/decode round-trip 测试。
- 明确 legacy raw input 的兼容策略。
- 明确 `copyin/copyout/result/data` 当前已支持与未支持的边界。

### 建议落点

- `common/src/exec.rs`
- 新增 `common/tests/exec_format.rs`
- 文档说明 `docs/exec-wire-format.md` 或合并入本文件

### 详细测试

#### Test 1.1：单调用 round-trip

**目的**
- 验证 `InputData -> ExecProgram -> bytes -> ExecProgram -> InputData` 可逆。

**操作**
- 使用 Base、Timer、IPI、HSM、Reset、Console、PMU 各选一个样本。
- 对每个样本执行：
  - `exec_program_from_input`
  - `exec_program_to_bytes`
  - `exec_program_from_bytes`
  - `exec_program_primary_input`

**检查点**
- `eid/fid/a0-a5` 一致。
- schema 元数据不丢失。

**通过标准**
- 所有样本 round-trip 一致。

#### Test 1.2：多调用流解析

**目的**
- 验证新的多调用执行器不会只在单调用场景下工作。

**操作**
- 手工构造至少 3 条调用的 exec 程序：
  - 一个普通 call
  - 一个 `copyin`
  - 一个 `copyout`
  - 一个引用前序 `result`
- 编码再解码。

**检查点**
- 指令顺序保持不变。
- `copyout index` 和 `result index` 正确关联。

**通过标准**
- 程序结构完全一致。

#### Test 1.3：错误输入鲁棒性

**目的**
- 防止 malformed fuzz input 在 host 侧直接 panic。

**操作**
- 构造错误样本：
  - magic 错误
  - varint 截断
  - 未知 arg type
  - 未知 instruction
  - data 长度越界

**检查点**
- `exec_program_from_bytes` 返回结构化错误，而不是 panic。

**通过标准**
- 所有错误样本都能被安全拒绝。

#### Test 1.4：legacy raw input 回归

**目的**
- 保证历史 `.toml` 和 64-byte binary 输入还能复现旧样本。

**操作**
- 选取已有 crash 样本和 playground 样本。
- 通过 `helper run` 分别喂 `.toml`、legacy binary、`.exec`。

**检查点**
- 三者都能执行。
- `.toml` 自动转 exec 后的行为与 legacy 模式保持等价。

**通过标准**
- 旧样本不失效。

### Done 标准

- exec format 有明确定义；
- `common` 层有完整 round-trip 测试；
- legacy 兼容策略被验证。

---

## Step 2：调用描述层外部化（descriptor/schema registry）

### 目标

把现在写死在 `common/src/exec.rs` 里的 `EXEC_CALL_TABLE` 和 `common/src/lib.rs` 里的参数 schema 进一步结构化，避免后续维护靠手工双写。

### 预期改动

- 定义统一的 call registry 数据模型。
- 将 `call_id <-> eid/fid <-> schema <-> name` 集中管理。
- 清理重复信息，避免 descriptor 与 schema 不一致。

### 建议落点

- `common/src/lib.rs`
- `common/src/exec.rs`
- 可新增 `common/src/registry.rs`

### 详细测试

#### Test 2.1：registry 完整性检查

**目的**
- 保证 registry 内部没有重复 ID、重复 `(eid, fid)`、空名字或缺 schema。

**操作**
- 新增完整性测试，对所有表项做唯一性验证。

**检查点**
- `call_id` 唯一。
- `(eid, fid)` 唯一。
- 所有固定调用都有 schema。

**通过标准**
- 任何冲突都让测试失败。

#### Test 2.2：schema 与 exec descriptor 一致性测试

**目的**
- 防止某个调用在 exec 层是 6 参数、在 schema 层被误标成地址/flags 等不匹配语义。

**操作**
- 对每个固定调用生成一份样本，做 normalize，再回查 registry。

**检查点**
- `exec_program_primary_input` 还原出的调用元数据和 registry 一致。

**通过标准**
- 所有固定调用一致。

#### Test 2.3：helper CLI 枚举测试

**目的**
- 让维护者能直接看到当前支持哪些调用，而不是读源码。

**操作**
- 新增 `cargo helper list-calls` 或等价命令。

**检查点**
- 输出至少包含：`call_id`、`name`、`eid`、`fid`、参数语义。

**通过标准**
- 输出可读，能覆盖全部当前支持调用。

### Done 标准

- registry 成为单一事实源；
- descriptor/schema 不再分散维护；
- 调用清单可通过命令直接查看。

---

## Step 3：真实语料接入与结构化种子增强

### 目标

不再只依赖规范生成的“全零参数” seed，而是引入真实、可执行、带语义的初始语料。

### 预期改动

- 从 Linux `arch/riscv/kernel/sbi.c` 提取常见调用模式。
- 从 OpenSBI / RustSBI 示例和测试中提取有效参数组合。
- 为地址参数生成“合法地址 / 边界地址 / 敏感地址 / 未对齐地址”候选池。
- 让种子既有“合法调用”也有“故障导向调用”。

### 建议落点

- `helper/src/seed_generator.rs`
- 新增 `helper/src/seed_importer.rs`
- 新增 `seeds/` 或 `corpus/` 目录

### 详细测试

#### Test 3.1：规范 seed 回归

**目的**
- 保证新增语料导入后，原有规范生成能力不退化。

**操作**
- 运行 `cargo helper generate-seed output/seed-doc`

**检查点**
- 仍然能生成完整 seed 集合。
- 输出包含 schema 元数据。

**通过标准**
- 文档 seed 数量不下降，格式正确。

#### Test 3.2：真实语料导入测试

**目的**
- 验证 Linux/OpenSBI/RustSBI 语料能成功转换为内部 seed。

**操作**
- 针对每类来源各准备至少 5 个样本。
- 导入后运行 `helper parse-binary-input` / `encode-exec-input` 双向验证。

**检查点**
- 导入的 `(eid, fid)` 正确。
- 转出的 `.exec` 可被当前 injector 接受。

**通过标准**
- 每类来源至少成功导入 5 个样本。

#### Test 3.3：地址类种子分布测试

**目的**
- 确认新地址候选池真的覆盖“合法 / 边界 / 故障导向”三类值，而不是全部被 normalize 成中庸值。

**操作**
- 对每个地址型调用生成 100 个样本，统计地址分布。

**检查点**
- 至少出现以下类别：
  - 合法范围地址
  - 边界地址
  - 未对齐地址
  - 范围外地址

**通过标准**
- 每个地址型调用都能出现至少 3 类不同地址风格。

#### Test 3.4：最小可运行语料测试

**目的**
- 让导入语料至少不是“全部一跑就秒崩”的无效种子。

**操作**
- 对新种子随机抽样 20 个，使用 `helper run` 跑 OpenSBI。

**检查点**
- 至少有一部分样本正常返回或返回合法 SBI 错误码。

**通过标准**
- 抽样中正常/合法错误返回率高于 30%。

### Done 标准

- 仓库拥有规范种子 + 真实语料种子；
- 地址类种子有明显分层；
- 至少一部分种子能稳定到达固件逻辑深处。

---

## Step 4：host/target 结果协议与 fallback signal 完整化

### 目标

建立类似 syzkaller 的“调用结果 + 错误映射 + fallback signal”闭环，让没有真实覆盖率时也能稳定运行 fuzz。

### 预期改动

- 定义更明确的 `sbiret.error/value -> host signal` 映射。
- 记录每次执行的调用索引、返回值、错误码、超时状态。
- 在目标侧执行器和 host 侧之间形成稳定的结果协议。

### 建议落点

- `injector/src/injector.c`
- `helper/src/runner.rs`
- `fuzzer/src/fuzz.rs`
- 可能新增 `common/src/result.rs`

### 详细测试

#### Test 4.1：SBI 返回码映射测试

**目的**
- 验证不同 SBI 错误码不会在 host 侧被误判成 crash。

**操作**
- 准备能稳定返回不同 SBI 错误码的样本：
  - `SBI_SUCCESS`
  - `SBI_ERR_NOT_SUPPORTED`
  - `SBI_ERR_INVALID_PARAM`
  - `SBI_ERR_INVALID_ADDRESS`
  - `SBI_ERR_ALREADY_AVAILABLE`

**检查点**
- host 侧能区分“正常返回 / 目标错误 / crash / timeout”。

**通过标准**
- 各返回码分类正确。

#### Test 4.2：fallback signal 稳定性测试

**目的**
- 确保在没有真实覆盖率时，变异器仍然能从结果中区分不同输入。

**操作**
- 用一组语义不同但不 crash 的输入运行短时 fuzz。
- 记录 objective/corpus 的增长。

**检查点**
- 相同输入多次运行 signal 一致。
- 不同输入 signal 有可见差异。

**通过标准**
- signal 具有稳定性和最小区分度。

#### Test 4.3：失败分类回归

**目的**
- 避免 timeout、unexpected exit、invalid a0 被混成一种结果。

**操作**
- 分别构造：
  - 正常断点返回
  - timeout
  - 提前退出
  - 非法 `a0`

**检查点**
- `helper run` 和 `fuzzer` 记录的分类一致。

**通过标准**
- 四类结果能稳定区分。

### Done 标准

- 没有真实覆盖率也能稳定运行 fuzz；
- 错误码分类清楚；
- 结果协议能被 triage 使用。

---

## Step 5：M-Mode shared-memory 覆盖率 MVP

### 目标

用共享内存 `count + pcs[]` 缓冲区，提供一个最小可用、可回传、可符号化的真实覆盖率实现。

### 预期改动

- 在 OpenSBI 目标中接入 `trace-pc` 或 sanitizer coverage 风格回调。
- 定义 M-mode 覆盖率缓冲区格式。
- 定义 reset / collect 机制。
- host 侧接收 raw PCs 并做基本符号化。

### 建议落点

- `playground/opensbi-fuzz` 或 OpenSBI patch
- `helper/src/instrumenter.rs`
- `fuzzer/src/fuzz.rs`
- 新增 `helper/src/coverage.rs` 或 `common/src/coverage.rs`

### 详细测试

#### Test 5.1：覆盖率缓冲区格式测试

**目的**
- 保证 `word0=count, word1..=pcs` 协议稳定。

**操作**
- 在受控的小样本上启用 coverage 回调。
- 读取共享缓冲区并导出原始数据。

**检查点**
- `count` 正确。
- `pcs` 不越界。
- 多次 reset 后缓冲区正确清零。

**通过标准**
- 连续运行 100 次无格式损坏。

#### Test 5.2：覆盖率去重/稳定性测试

**目的**
- 防止同一输入每次得到完全不同 PC 集，影响 triage。

**操作**
- 对同一输入重复运行 30 次。

**检查点**
- PC 集合高度一致。
- 少量噪声在可接受范围内。

**通过标准**
- 稳定 PC 占比高于 90%。

#### Test 5.3：不同输入的覆盖率区分测试

**目的**
- 确认真实覆盖率能区分不同路径，而不是只返回固定少量点。

**操作**
- 准备至少 10 个不同 `(eid, fid)` 输入。

**检查点**
- 不同输入的覆盖率集合存在差异。
- corpus 能因新覆盖率增长。

**通过标准**
- 至少 50% 的输入能产生不同覆盖率集合。

#### Test 5.4：异常链与覆盖率链分离测试

**目的**
- 防止 trap handler 中的 crash telemetry 污染正常覆盖率缓冲区。

**操作**
- 分别运行正常样本和故障样本。

**检查点**
- 正常样本只更新覆盖率缓冲区。
- crash 样本同时留下异常寄存器信息，但不破坏覆盖率格式。

**通过标准**
- 两条链路互不污染。

### Done 标准

- OpenSBI 至少有一条真实覆盖率路径；
- host 能消费并做基本去重；
- fallback signal 可以作为 coverage 不可用时的降级路径保留。

---

## Step 6：Crash Triage 与 Reporter 管线

### 目标

把 crash、timeout、hang、trap 分类标准化，形成可自动归并和复现的 triage 管线。

### 预期改动

- 新增 triage 脚本，按 `mepc/mcause/mtval/Hart ID/hash` 去重。
- 为 OpenSBI 新增 reporter 或最小版日志解析器。
- 输出结构化 triage 结果。

### 建议落点

- 新增 `helper/src/triage.rs` 或独立脚本
- 新增 `scripts/triage-crashes.py` / `scripts/triage-crashes.sh`
- 可能新增 `pkg/report` 等价逻辑的本地实现

### 详细测试

#### Test 6.1：去重一致性测试

**目的**
- 确保同一 crash 的不同样本会归到同一桶。

**操作**
- 对同一 crash 变体收集至少 10 个样本。

**检查点**
- triage 结果归并到同一个 bucket。

**通过标准**
- 桶数量显著小于样本数量。

#### Test 6.2：跨类型区分测试

**目的**
- 防止不同异常因只看 `mepc` 被错误合并。

**操作**
- 准备以下样本：
  - access fault
  - illegal instruction
  - timeout
  - early exit

**检查点**
- 不同类型不会被错误归并。

**通过标准**
- 四类结果独立成桶。

#### Test 6.3：repro 回放测试

**目的**
- 确认 triage 输出能直接驱动复现。

**操作**
- 从 triage 结果中抽样 5 个 bucket，自动调用 `helper run` 或 `helper debug` 复现。

**检查点**
- repro 输入能再次触发原结果。

**通过标准**
- 抽样复现成功率高于 80%。

### Done 标准

- 有自动 triage；
- 能按 bucket 管理 crash；
- repro 可从 triage 结果直接触发。

---

## Step 7：多 Hart 并发模型与 HSM/IPI/RFENCE 专项测试

### 目标

把执行器从单 Hart 单流扩展到最小可用的并发模型，以覆盖 HSM、IPI、RFENCE 的竞态问题。

### 预期改动

- 支持多 Hart 配置的 QEMU 运行模式。
- 为 exec program 增加最小并发语义：例如 Hart 亲和、同步屏障、并发调用组。
- 提供 HSM/IPI/RFENCE 的专项种子与专项调度逻辑。

### 建议落点

- `common/src/exec.rs`
- `injector/src/injector.c`
- `fuzzer/src/fuzz.rs`
- `playground/opensbi-fuzz/Makefile`

### 详细测试

#### Test 7.1：双 Hart 启动冒烟测试

**目的**
- 确保多 Hart 配置下执行器还能稳定运行。

**操作**
- 使用 `-smp 2` 启动 QEMU。
- 运行单调用和多调用样本。

**检查点**
- 单 Hart 样本在双 Hart 配置下仍可执行。
- 不出现额外死锁或无响应。

**通过标准**
- 双 Hart 冒烟通过。

#### Test 7.2：HSM 状态机专项测试

**目的**
- 验证启动/停止/状态查询/挂起路径在并发条件下能被覆盖。

**操作**
- 构造一组程序：
  - Hart0 发起 `hart_start`
  - Hart1 并发查询 `hart_status`
  - Hart0/1 交替 `hart_suspend`

**检查点**
- 能稳定观察到不同状态转换返回。
- crash/hang 能被记录。

**通过标准**
- 至少能稳定触发 2 类以上状态转换路径。

#### Test 7.3：IPI/RFENCE 风暴测试

**目的**
- 探测资源耗尽、锁竞争和 timeout 分类。

**操作**
- 在多个 Hart 间高频发送 IPI / RFENCE。
- 设置多个不同持续时间与调用批次。

**检查点**
- timeout 被正确识别。
- 不同负载下有可比较的统计结果。

**通过标准**
- 能复现至少一类高负载异常或性能退化路径。

### Done 标准

- 支持最小并发模型；
- HSM/IPI/RFENCE 有专项语料与专项测试；
- 能稳定记录 hang/死锁类结果。

---

## Step 8：向真正 syzkaller 风格描述链迁移

### 目标

开始把现在的手工 registry 迁移到真正类似 syzkaller 的“描述文件 -> 生成 call table / metadata”的流程。

### 预期改动

- 设计 `SBI 描述文件格式`，至少能表达：
  - `name`
  - `eid`
  - `fid`
  - 参数类型
  - 地址语义
  - 资源依赖
- 写最小生成器，把描述文件转换成 Rust 侧 registry 和 C 侧 dispatcher table。
- 为后续接 syzlang 或兼容 syzkaller `sys/*.txt` 做准备。

### 建议落点

- 新增 `descriptors/`
- 新增 `helper` 生成子命令
- 生成 `common/src/generated_*.rs`
- 生成 `injector/src/generated_*.h`

### 详细测试

#### Test 8.1：描述文件语法测试

**目的**
- 保证描述文件出错时能尽早发现。

**操作**
- 准备合法和非法描述文件各一组。

**检查点**
- 非法文件能给出精确报错行。
- 合法文件能稳定生成代码。

**通过标准**
- 错误定位清晰；合法文件全部通过。

#### Test 8.2：生成物一致性测试

**目的**
- 确保 Rust registry 与 C dispatcher 来自同一份输入。

**操作**
- 生成后对比条目数量、名字、`eid/fid`、参数数量。

**检查点**
- 两侧表项完全一致。

**通过标准**
- 一致性检查无差异。

#### Test 8.3：手工表与生成表对比回归

**目的**
- 避免迁移时破坏当前已支持调用。

**操作**
- 用当前手工表生成一组样本。
- 再用新生成表生成同一组样本。

**检查点**
- 编码结果、执行结果、分类结果一致。

**通过标准**
- 当前支持的调用行为不变。

### Done 标准

- call table 不再靠手写维护；
- 为后续真正对接 syzkaller 描述链打下基础。

---

## 4. 推荐执行顺序

建议严格按以下顺序推进：

1. `Step 0` 环境基线
2. `Step 1` exec format 稳定化
3. `Step 2` registry 外部化
4. `Step 3` 真实语料接入
5. `Step 4` fallback signal / 结果协议
6. `Step 5` coverage MVP
7. `Step 6` crash triage / reporter
8. `Step 7` 多 Hart 并发
9. `Step 8` 描述链生成

原因是：

- 没有 `Step 0`，后续测试不可重复；
- 没有 `Step 1/2`，输入层和 ABI 层会持续漂移；
- 没有 `Step 4`，在接入真实覆盖率前很难稳定跑起来；
- 没有 `Step 5/6`，即使找到 crash 也无法规模化处理；
- 没有 `Step 7`，HSM/IPI/RFENCE 风险面无法真正覆盖；
- `Step 8` 适合在前述路径稳定后再做，不然会把问题混在一起。

## 5. 每周交付建议

如果按“一周一个可验收里程碑”推进，建议如下：

- Week 1：完成 `Step 0`
- Week 2：完成 `Step 1`
- Week 3：完成 `Step 2`
- Week 4：完成 `Step 3`
- Week 5：完成 `Step 4`
- Week 6-7：完成 `Step 5`
- Week 8：完成 `Step 6`
- Week 9-10：完成 `Step 7`
- Week 11+：完成 `Step 8`

## 6. 立即下一步

如果按当前仓库状态继续推进，最合适的下一个实际开发任务是：

### 优先任务 A：完成 `Step 0`

原因：当前环境里已经暴露出两个明确阻塞项：

- `ninja` 缺失，导致 `libafl_qemu_sys` 无法完整构建；
- `riscv64-unknown-elf-gcc` 缺失，导致 `injector` 无法编译。

如果不先解决这些问题，后面每一步的测试都会被环境噪音打断。

### 优先任务 B：并行完成 `Step 1`

原因：当前 exec format 已经有实现，但还缺少：

- round-trip 单元测试；
- malformed 输入测试；
- 多调用程序测试；
- legacy 回归测试。

这一步可以在不依赖完整 QEMU/覆盖率链的前提下先做起来。
