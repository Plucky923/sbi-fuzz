# SBI Fuzzing TODO

这份文档用于跟踪 `sbifuzz` 的威胁建模、阶段性目标与近期待办项，面向的主要目标包括 OpenSBI、RustSBI 以及厂商基于 SBI 规范实现或扩展的 M-mode 固件。

## 威胁建模

### P0：参数校验与内存越界（Memory Access & Pointer Validation）

- 攻击面：S-mode 通过 `a0-a7` 传递参数，部分 SBI 扩展会把物理地址、共享缓冲区地址或结果写回地址交给 M-mode 处理。
- 关键风险：如果 M-mode 没有校验地址是否属于 S-mode 合法共享区域，S-mode 可能诱导固件覆盖 M-mode 自身代码、`scratch`、状态机或跳板数据。
- 失败模式：未对齐地址、越界地址、不可访问地址、跨页边界地址、只读/执行区写入等都可能触发 `Load/Store access fault`、异常陷阱或状态损坏。
- Fuzz 重点：需要把“地址类参数”与普通整数参数区分开，优先变异到未对齐地址、保留区地址、边界地址、共享内存边界和已知关键结构地址附近。

### P0：Hart 状态机与并发竞争（State Machine & Race Conditions）

- 攻击面：HSM、IPI、RFENCE 以及其他会修改跨 Hart 共享状态的 SBI 扩展。
- 关键风险：并发 `sbi_hart_start`/`stop`/`suspend`/`resume` 可能暴露 TOCTOU、锁粒度不足、状态回滚不完整等问题。
- 失败模式：非法状态转换、重复唤醒、挂起期间中断注入、共享状态不一致、固件断言或整个系统卡死。
- Fuzz 重点：Harness 需要支持多 Hart 场景下的时序编排，而不只是单次 `ecall` 的参数变异。

### P1：拒绝服务与资源耗尽（DoS & Resource Exhaustion）

- 攻击面：高频 IPI、RFENCE、定时器、中断转发、任务队列与共享事件处理逻辑。
- 关键风险：有界队列溢出、无界分配导致内存耗尽、错误的锁顺序导致死锁、超长临界区导致系统不可用。
- 失败模式：QEMU 长时间无响应、单个 Hart 卡死、所有 Hart 无进展、固件 watchdog/timeout 或异常退出。
- Fuzz 重点：需要超时检测、hang 分类以及高负载重复调用模型，而不是只盯 crash。

### P1：厂商自定义扩展（Vendor-specific Extensions）

- 攻击面：EID 范围 `0x09000000 - 0x09FFFFFF` 内的私有接口，以及厂商移植时新增的非标准扩展。
- 关键风险：这类代码通常缺少社区审查，容易出现参数校验缺失、状态机漏洞、DMA/共享内存处理错误。
- Fuzz 重点：为厂商扩展建立独立描述文件，记录 EID/FID、参数类型、共享内存语义和依赖前置状态。

## 已完成进展

- [x] 已新增 syzkaller 风格 exec wire format 骨架：`common/src/exec.rs`
- [x] 已新增环境探测入口：`scripts/check-env.sh`、`make check-env`
- [x] 已完成 `Step 1` 的 `common` 层自动化测试：`cargo test -p common`
- [x] 已实现并验证 `Step 2` 的 registry 基础接口与 `helper list-calls`
- [x] 已确认 `llvm-18` / `clang-18` 为当前稳定构建路径，并已固化到 Makefile 默认导出
- [x] 已将稳定工具链默认值写入 `.cargo/config.toml`，直接运行 `cargo helper` / `cargo fuzzer` 更顺畅
- [x] 已完成 `Step 3` 的 Linux 语料导入基础脚本：`scripts/import-linux-sbi-corpus.py`
- [x] 已完成 `Step 3` 的自动化脚本测试：`make test-linux-corpus-import`
- [x] 已完成 `Step 4` 的 common 层 SBI 返回值建模与测试：`SbiError` / `SbiRet` / `cargo test -p common`
- [x] 已完成首轮真实 OpenSBI fuzz smoke：`playground/opensbi-fuzz/output/result-smoke` 与 `output/result-recheck` 已生成真实样本
- [x] 已修复 fuzz 收尾 panic：timeout 结束时 `Error::ShuttingDown` 现被正常处理
- [x] 已完成 OpenSBI 结果 triage / replay 工具，并验证 `.exec` 回放可用于结果复查
- [x] 已完成 OpenSBI sanitizer-demo 两个固定样本的验证：KASAN / UBSAN 信号均可观测
- [x] 已修复真实 fuzz 暴露的 `capacity overflow`：为 exec 解码增加 `EXEC_MAX_ARGS` 边界检查，并补充回归测试

## 现有仓库基线

### 已具备能力

- `fuzzer` 已使用 `LibAFL + libafl_qemu(systemmode)` 执行系统级 fuzzing，输入格式固定为 `eid/fid/a0-a5` 八个 `u64`。
- `helper generate-seed` 已能根据 SBI 规范仓库自动生成基础 seed。
- `helper instrument-kasan` 与 `playground/opensbi-sanitizer-demo` 已覆盖 OpenSBI 的 sanitizer 演示路径。
- `playground/opensbi-fuzz` 与 `playground/rustsbi-fuzz` 已提供两个基线目标与一键运行入口。
- `helper run` / `helper debug` 已提供复现与 GDB 辅助入口。

### 当前缺口

- 缺少对“参数类型”的建模，无法区分地址参数、Hart mask、flags、size、timeout 等不同语义。
- 缺少多 Hart 并发 harness，暂时难以稳定触发 HSM/IPI/RFENCE 竞态问题。
- 缺少基于 `mepc`、`mcause`、`mtval`、Hart ID 的自动化 crash 去重与分类脚本。
- 缺少厂商扩展的清单、描述格式与针对性语料。
- 当前 seed 主要来自规范，尚未吸收 Linux `arch/riscv/kernel/sbi.c`、OpenSBI/RustSBI 自测样例等“真实调用语料”。

## 分阶段路线图

### 阶段一：目标分析与威胁建模（Target Analysis & Threat Modeling）

- [ ] 研读最新 RISC-V SBI 规范，并在仓库中固定使用的规范版本或 commit。
- [ ] 明确首批目标：优先以 `playground/opensbi-fuzz` 与 `playground/rustsbi-fuzz` 为公开基线，后续再接入厂商固件。
- [ ] 梳理各目标支持的 EID/FID，形成“攻击面清单”。
- [ ] 标记所有接受指针、物理地址、共享内存或长度参数的接口。
- [ ] 标记所有涉及多 Hart 协作、共享状态或异步事件的接口。
- [ ] 在 QEMU 中建立稳定的基线启动流，确保能保留 M-mode crash log、寄存器状态与退出原因。
- [ ] 记录各目标的关键地址空间布局，包括固件镜像、scratch、共享页、保留区与潜在敏感区域。

### 阶段二：Fuzzer 架构设计与 Harness 开发（Harness Development）

- [ ] 以现有 `LibAFL + QEMU systemmode` 路线为主线，保留 Syzkaller 作为后续对照方案。
- [ ] 明确输入格式版本：保留现有 `64-byte` 基础布局，同时增加“参数语义描述层”。
- [ ] 为每个 EID/FID 建立参数 schema，标识哪些参数是地址、长度、Hart mask、flags、timeout 或枚举值。
- [ ] 为地址类参数定义可选地址池：合法共享区、未映射区、未对齐区、M-mode 敏感区、边界页和只读页。
- [ ] 扩展 harness 的状态重置机制，优先考虑 QEMU snapshot / 快速重启 / 轻量级固件复位。
- [ ] 在目标为开源固件时继续复用 sanitizer、QEMU 覆盖率与已有 debug 能力。
- [ ] 为 hang、trap、unexpected exit 建立统一的退出分类接口。

### 阶段三：测试用例生成与语料库准备（Corpus Generation）

- [ ] 在规范生成 seed 之外，引入 Linux `arch/riscv/kernel/sbi.c` 的真实调用参数作为补充种子。
- [ ] 补充 OpenSBI、RustSBI 测试代码与示例中的有效参数组合。
- [ ] 实现结构化变异，让 fuzzer 知道哪些字段更适合做地址替换、边界扩展、bit flip 或状态枚举。
- [ ] 针对地址参数优先生成以下值：未对齐地址、空洞地址、边界地址、固件关键结构地址附近、跨页地址。
- [ ] 引入多步时序语料，而不是只保留单个 `ecall`；重点覆盖 HSM、IPI、RFENCE 和挂起/恢复路径。
- [ ] 为每条输入记录目标、Hart 拓扑、扩展名与来源，便于后续 triage。

### 阶段四：执行、监控与分类（Execution & Triage）

- [ ] 在多核机器上并行部署多个 fuzzer 实例，按目标固件和配置分目录保存输出。
- [ ] 监控 QEMU 退出、M-mode 异常陷阱、超时与无进展状态。
- [ ] 对 hang / 死锁设置明确 timeout，并记录触发前最后一条 SBI 调用与 Hart 上下文。
- [ ] 编写 triage 脚本，基于 `mepc`、`mcause`、`mtval`、退出类型、Hart ID 和输入 hash 做去重。
- [ ] 使用 `helper run` / `helper debug` 做复现与缩减，沉淀稳定 repro。
- [ ] 为高价值 crash 产出 C / 汇编级 PoC，并记录根因、触发条件和影响范围。

## 近期优先级（建议按顺序推进）

- [ ] 为 `common::InputData` 补充参数语义元数据，支持指针感知变异。
- [ ] 新增目标攻击面枚举工具，自动列出目标固件支持的 EID/FID 与参数类型。
- [ ] 为 QEMU / 固件输出实现 crash triage 脚本，先解决去重与分类问题。
- [ ] 设计多 Hart 并发输入模型，优先覆盖 HSM、IPI、RFENCE 的竞态路径。
- [ ] 将 Linux / OpenSBI / RustSBI 的真实调用样例并入种子语料。
- [ ] 为厂商扩展设计描述文件格式，便于后续接入闭源或私有实现。

## 详细实施计划

- 详细的 syzkaller 迁移执行计划与逐步测试矩阵见 `SYZKALLER_MIGRATION_PLAN.md`。

## 完成标准（Definition of Done）

- 能稳定启动并 fuzz OpenSBI 与 RustSBI 基线目标。
- 能自动区分 crash、hang、halt、正常返回，并生成可复现样本。
- 能对地址类参数执行有意识的结构化变异，而不是纯随机整数变异。
- 能在多 Hart 场景下执行并发 SBI 序列并观察状态机异常。
- 能输出最小化后的 repro 输入，并支持 `helper debug` 直接复现。
