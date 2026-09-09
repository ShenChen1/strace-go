# upstream 测试失败分析与击破路线

基线日期：2026-09-08；语义复现日期：2026-09-09。

本文把 upstream exact diff、纯 eBPF 架构边界、测试 runner 缺陷和真实实现缺口分开记录。2026-09-08 的 `--suite all` 基线来自目录扫描，其失败数量只用于保留历史现场，不能直接等同于实现 bug 数量或 upstream 全量通过率。阶段 1 已让 runner 改用 configure 后的官方 `TESTS` 集合；阶段 3 已完成一次配置一致的完整 `all`，当前失败仍需按下文分类，不能直接当作实现 bug 总数。

## Problem 1-Pager

### Context

`strace-go` 使用纯 eBPF probe-site bounded snapshot 和 Go 单消费者状态机，不使用 ptrace、`process_vm_readv` 或 procfs 补读 tracee。upstream 测试仍以经典 `strace` 的 ptrace 输出和测试辅助程序为基准。

### Problem

2026-09-08 的 runner 文件系统扫测结果为 1500 项中 374 通过、954 失败、172 跳过。`get_tests("all")` 会枚举目录中几乎所有 `.test`，没有遵循 upstream Makefile 根据 configure 结果展开的 `TESTS`，因此直接查看这个数字既无法判断失败类型，也不能确认分母是否属于当前配置。

### Goal

先建立配置一致、构建失败可观测的测试清单，再形成可重复的失败分类和修复顺序，使每次只击破一个明确问题，并用 focused upstream test、eBPF semantic test 和 Go 门禁验证。

### Non-Goals

- 不通过 ptrace、`/proc/<pid>/mem`、`process_vm_readv` 或无限制 tracee 内存读取消除 bounded snapshot 差异。
- 不为了让 `all` 变绿而把真实失败静默标为 XFAIL。
- 不在本轮一次性修改所有 syscall handler。

### Constraints

- 生成文件必须由生成器输入产生，不能直接手改 `pkg/meta/xlat_auto.go`。
- 生命周期、FD state 和 Ringbuf 对账错误必须保留为可观测失败。
- upstream runner 需要 root；纯 eBPF 运行时只在当前 x86_64/BTF 环境验证。

### Assumptions

- configure 后生成的 `strace-upstream/tests/Makefile` 是当前平台和 feature 配置下测试清单的权威来源。
- pinned upstream 提供的 `check-prerequisites-local` 是 helper 构建边界；它构建 `check_LIBRARIES` 和 `check_PROGRAMS`，但不执行测试。
- 374 PASS / 954 FAIL / 172 SKIP 和 199 PASS / 63 FAIL / 3 XFAIL 是修复 runner 前的历史基线；在重新取得配置一致的清单前，不把它们表述为当前 upstream 全量结果。
- 主仓库提交必须能在干净 submodule 上重新生成全部 xlat，不能依赖 submodule 内的未跟踪输入。

## 当前证据

使用的 upstream 子模块提交为 `0681e211cf64aaeb8284e2ec19c6ba62983a8455`。

| 命令 | 结果 | 解释 |
| --- | --- | --- |
| `sudo -n python3 test/run_tests.py --suite all` | 374 PASS / 954 FAIL / 172 SKIP | runner 对生成目录进行文件系统扫测；混合了非配置测试、helper 缺失、exact output 差异和纯 eBPF 非契约差异，不能作为 upstream 官方全量结果或实现 bug 总数 |
| `sudo -n python3 test/run_tests.py --suite more --skip-build` | 199 PASS / 63 FAIL / 3 XFAIL / 0 XPASS | `more` 只登记了 3 个已知非契约差异，其余失败仍需分类 |
| `sudo -n python3 test/run_tests.py --suite ebpf-semantic --skip-build` | 3 FAIL | `orphan_exit` 2 个，以及两个 signalfd 同事件路径输出失败 |
| `sudo -n python3 test/run_tests.py --suite ebpf-no-ptrace --skip-build` | PASS | 未观察到 ptrace 运行时介入 |
| `GOCACHE=/tmp/strace-go-gocache go test ./... -count=1` | PASS | Go 单测和生成结果可编译、可运行 |
| `GOCACHE=/tmp/strace-go-gocache go vet ./...` | PASS | 静态检查通过 |
| `python3 -m unittest -v run_tests_unit.py run_tests_upstream_setup_unit.py` | 55 PASS | runner 原有门禁和新增配置清单、prerequisite、失败传播测试全部通过 |
| 配置后的 upstream `TESTS` 查询 | 1494 项 | 相比旧目录扫描的 1500 项，排除了当前 `--enable-stacktrace=no` 配置下的 6 个 stacktrace 测试 |
| `sudo -n python3 test/run_tests.py --suite all --skip-build` | 466 PASS / 851 FAIL / 177 SKIP；0 XFAIL / 0 XPASS | 阶段 3 的配置一致全量基线；runner 已完成汇总，退出码 1 由 851 个失败用例导致，不是清单或 helper 构建失败 |
| `sudo -n python3 test/run_tests.py --suite small --skip-build` | 23 PASS / 0 FAIL | 阶段 1 已消除 helper/environment false negative；阶段 2 补齐 `O_EMPTYPATH` 后 small 全绿 |
| `dup3.gen.test`、`dup3-P.gen.test` | 2 PASS / 0 FAIL | `dup3_flags` 派生表的基础和 path-filter flag 输出通过 |
| `dup3-y.gen.test`、`dup3-yy.gen.test` | 2 FAIL | flag 输出已经匹配；剩余 diff 仅为成功覆盖目标 FD 后，同一 exit 事件仍显示调用前的目标路径 |

语义 suite 的复现统计更具体：`records_decoded=185`、`records_invalid=0`、`pending_mismatch=0`、`pending_update_fail=0`、`lifecycle_map_update_fail=0`、`orphan_exit=2`。attach fixture 另报告 1 个 attach orphan，但 non-leader attach 的 orphan 为 0。

### 2026-09-09 外部 semantic 结果的二进制复核

用户在宿主机执行了 `sudo -n python3 test/run_tests.py --suite ebpf-semantic --skip-build`，输出为正常 semantic fixture `orphan_exit=2`，并报告两个 signalfd 返回路径断言失败。复核本工作区时发现：该命令使用的 `./strace-go` 二进制时间戳为 `2026-09-09 03:32:42 UTC`，而包含 signalfd event-time 修复的 `5e058ff` 提交时间为 `2026-09-09 05:12:51 UTC`。因此这次 `--skip-build` 运行没有执行当前提交中的 Go 代码，两个 signalfd 失败不能作为 HEAD 的有效回归证据。

当前源码已用以下命令重新构建，并通过 `cmd/strace-go` 单测、`go test ./... -count=1` 和 `go vet ./...`；仍需在具备 root/eBPF 能力的宿主机用这个新二进制重新执行 semantic suite：

```sh
GOCACHE=/tmp/strace-go-gocache go build -o strace-go ./cmd/strace-go
sudo -n python3 test/run_tests.py --suite ebpf-semantic --skip-build
```

重新运行前若 BPF object 被清理，则先执行 `GOCACHE=/tmp/strace-go-gocache ./build.sh`。在 fresh binary 结果出来前，阶段 4 只算“实现和本地回归已完成、真实 semantic 验收待确认”；`orphan_exit=2` 仍作为独立生命周期关联问题保留，不能和旧二进制的 signalfd 失败合并。

### 阶段 3 全量基线的首轮归因

本次执行命令为 `sudo -n python3 test/run_tests.py --suite all --skip-build`。配置后的 1494 项全部进入 runner，最终计数为 466 PASS、851 FAIL、177 SKIP；`all` 当前没有复用 `more` 的 XFAIL 映射，因此 `XFailed=0` 和 `XPassed=0`。这次结果证明 runner inventory、共享 helper 和 prerequisite 边界已经工作，但不代表 851 个失败都是同一类实现问题。

日志中有 224 个失败测试块明确报出 `pure eBPF tracing cannot modify tracee state`，集中在 `-e inject`、`-e fault`、延迟和 poke 场景，例如 `arch_prctl-success*.gen.test`、`clone3-success*.gen.test`、`qual_inject*.test`、`qual_fault*.test`、`delay.test` 和 `poke*.test`。这些测试要求 ptrace 修改返回值、错误、时序或 tracee 内存，和当前纯 eBPF 边界冲突，不能通过补 decoder 变绿；后续应把它们作为有证据的契约例外登记，而不是逐个修改 syscall handler。

剩余失败不是一个单一簇，当前按修复价值分为以下几类：

1. **FD event-time path（真实实现缺口）**：`dup2-y/yy.gen.test`、`dup3-y/yy.gen.test` 等在成功覆盖目标 FD 的同一 exit 事件中仍看到调用前 path。`dup3` 的 flag 文本已经通过，剩余 diff 与持久 FD state 更新晚于 handler 格式化一致，优先处理 event-time overlay；signalfd 的同类问题仍由 `ebpf-semantic` 回归负责。
2. **PID namespace translation（能力簇）**：多个 `--pidns-translation` 用例（例如 `xet_robust_list--pidns-translation.gen.test`、`xetpgid--pidns-translation.gen.test`、`xetpriority--pidns-translation.gen.test`）缺少经典 strace 的 `/* PID in strace's PID NS */` 注释。它们不能和普通参数解码混修，先确认项目是否承诺 PID namespace 映射，再决定实现或登记契约差异。
3. **bounded snapshot / decoder / xlat（实现簇）**：`xetitimer.gen.test` 把应解码的 `itimerval` 留成裸地址，`clone3*.gen.test` 对尾部结构字段只输出地址或截断，`bpf*.gen.test`、`io_uring*.gen.test`、`file_setattr*.gen.test` 和大量 `ioctl*` 变体存在结构字段、unknown bits 或新常量差异。这些必须按 syscall family 取最小 diff，先确认是 eBPF snapshot 没采到、decoder 没消费，还是 generator/xlat 输入缺失。
4. **ptrace/lifecycle 和环境条件**：`attach-p-eperm-yama.test`、`bexecve.test`、`detach-vfork.test`、`filter_seccomp-*`、`get_regs.test`、`ptrace*.gen.test` 依赖 ptrace stop、`ptrace_scope`、`PTRACE_O_EXITKILL` 或 tracee 调度；`getpid--pidns-translation.gen.test` 等还受 user namespace/内核策略影响。这些不应作为普通 syscall 格式化回归处理。
5. **大面积协议/结构族差异**：`prctl`、`ioctl`、netlink、socket option、scheduler 和 signal 相关失败数量较大，且同一 family 同时包含普通 decode、`-y/-yy`、PID namespace 和 inject 变体。先用不含 inject、ptrace 和 pidns 的最小测试确定一个可修复样本，避免被变体数量误导。

阶段 3 的结论是：先清理契约分类，再击破已经有 focused evidence 的 FD event-time path；其后每次只选择一个具体 decoder/xlat family。不能根据 851 这个总数批量添加 XFAIL，也不能把 PID namespace、ptrace 和纯 eBPF bounded snapshot 差异混为“解码失败”。

## 分类结论

### A. runner 的测试清单和 helper 构建边界不可信（P0，阶段 1 已关闭）

当前有三个相互独立、但必须在同一阶段关闭的 runner 问题：

1. `get_tests("all")` 枚举目录中的 `.test`，仅排除一个固定名称；upstream 的 `TESTS` 则由 configure 条件、`GEN_TESTS`、`DECODER_TESTS`、`MISC_TESTS` 和可选 feature 共同决定。例如 `--enable-stacktrace=no` 时，`STACKTRACE_TESTS` 不属于当前配置的官方集合。
2. `test/run_tests.py:183-213` 的 `build_upstream_test_helper` 从当前 `.test` 文件名推导一个同名 binary，再调用一次 `make`。upstream shell test 还会调用跨测试共享的程序，例如：

- `netlink_netlink_diag`；
- `sleep`、`sleep-timing`；
- `status-none-f`；
- `strace-p1-Y-p`。

3. `build_upstream` 和 `build_upstream_test_helper` 都丢弃 stdout/stderr，且不检查 `subprocess.run` 返回码。任何编译失败都会被忽略，随后表现为 helper 缺失或普通 exact diff。

这些失败不应修改 syscall 实现。runner 必须先得到配置一致的测试清单，使用 upstream 已有的 helper 构建边界，并在构建失败时终止 suite，而不是把环境错误计入兼容性结果。

方案比较：

| 方案 | 优点 | 风险 |
| --- | --- | --- |
| 通过只读 make 目标展开配置后的 `TESTS`，并先运行 `make -C tests check-prerequisites-local` | 测试选择和 helper 依赖都由 pinned upstream Makefile 决定；保留当前逐项 timeout、filter 和 XFAIL 分类 | 首次构建全部 helper 时间更长；需要为 make 输出建立严格解析和错误处理 |
| 直接把执行完全交给 upstream `make check` | 最接近 upstream 官方入口 | 难以保留当前逐项超时、root wrapper、JSON 诊断和具名 XFAIL 语义 |
| 继续扫描 `.test` 并解析 shell 中的 helper 引用 | 单项启动看似最小 | 无法覆盖 configure 条件和 shell 间接依赖，维护成本高且仍会漏项 |

选择并已实现第一种。实现边界如下：

1. configure 完成后，通过 GNU make 展开 `tests/Makefile` 中最终的 `TESTS`；不直接解析 Makefile 文本。
2. `all`、`--filter` 和 `--limit` 都作用于该配置清单；不存在于清单的测试不能进入 `all`。
3. upstream 主构建和 `check-prerequisites-local` 都必须检查返回码；成功时保持安静，失败时报告命令、阶段和完整 stderr，然后终止 suite。
4. `check-prerequisites-local` 每个 suite 只执行一次，删除逐测试的同名 helper 猜测和 `sleep-timing` 特例。
5. 单测至少覆盖配置禁用测试不进入 `all`、make 失败会中止、helper 目标只调用一次、filter/limit 不越过配置清单。

阶段 1 的实际结果：配置清单为 1494 项，旧扫描多出的 6 项为 `strace-k-demangle.test`、`strace-k-p.test`、`strace-k-with-depth-limit.test`、`strace-k-z.test`、`strace-kk-p.test` 和 `strace-kk.test`；此前缺失的五个代表性共享 helper 均已生成。完整 `all` 留到阶段 3 重跑，届时新结果才命名为“当前配置的 upstream 全量基线”；旧的 1500 项结果继续保留为 runner 修复前的历史证据。

### B. `all` 没有应用已知 XFAIL 分类（P0，先修门禁解释）

`expected_failures_for_suite` 只为 `more` 和 `upstream-reference` 提供 expected failures，`all` 返回空映射。因此下面这些已经被架构文档和 `more` 登记的差异，在 `all` 中会被计为普通 FAIL：

- `read-write.gen.test`：经典 strace 可在冻结点继续读取任意长度，纯 eBPF 只承诺 bounded snapshot；
- `attach-p-cmd.test`：跨任务生命周期退出顺序受调度影响，不是纯 eBPF 的 exact contract；
- `strace-k-with-depth-limit.test`：当前只提供 probe 点地址栈，不解析 tracee ELF 符号，也不提供 ptrace signal-stop 栈。

此外，inject、delay、fault、poke 等测试要求修改 syscall 结果、时序、signal 或 tracee 内存，属于 CLI 契约中的架构冲突，不应通过实现伪造出来。

方案比较：

| 方案 | 优点 | 风险 |
| --- | --- | --- |
| 给 `all` 复用已登记 XFAIL，并保持 unexpected XPASS 失败 | 结果可解释，仍能发现契约之外的新回归 | 需要维护 expected-failure 的证据和原因 |
| 继续把所有 exact diff 计为 FAIL | 数字看起来严格 | 已知非契约噪声淹没真正回归 |

选择第一种，但只允许有明确理由、focused evidence 和文档记录的 XFAIL；不能把未知失败批量加入列表。

### C. FD creator 同一 exit 事件的新 path 没进入格式化上下文（P0，明确实现缺口）

当前 signalfd 流程已经在 eBPF 端捕获了：

1. enter 的 `sigset_t` IN struct TLV；
2. exit 的 `FD_STATE` snapshot；
3. Go 的 `signalfdPolicy.state` 可以据此生成 `signalfd:[USR2]` 或 `signalfd:[USR2 CHLD]`。

但 `SyscallHandlerRunner.Handle` 的顺序是先 `r.handleWith(...)` 格式化，再 `r.update(...)` 更新 FD state。与此同时，当前 `fdPathOverlayFromSections` 只识别 `FD_PATH` TLV，不会把该 exit 事件里的 signalfd mask 和返回 fd 组合成 event-time path。因此同一条 `signalfd4`/`signalfd` exit 的 `return_text` 看不到刚创建或刚更新的 mask，正好对应：

- `signalfd4 return path missing initial mask`；
- `signalfd update return path missing new mask`。

这不是缺少 eBPF 快照，而是“事件内状态 overlay”没有覆盖 signalfd 特殊 FD creator。

阶段 2 还确认了同类的 dup3 缺口：成功的 `dup3(oldfd, newfd, flags)` 会把 `newfd` 指向 `oldfd` 的对象，但 handler 格式化发生在持久 FD state 更新之前，因此 `dup3-y.gen.test` 和 `dup3-yy.gen.test` 的返回值仍显示调用前的 `newfd` 路径。两项测试的 flag 文本已经完全匹配，剩余 diff 只涉及 event-time path。

方案比较：

| 方案 | 优点 | 风险 |
| --- | --- | --- |
| 在 event-time view 中根据当前 exit payload 和 syscall 构造临时 path；signalfd 使用 mask/ret，dup3 使用 oldfd/newfd/ret | 不改变持久 FD state 更新顺序，符合事件时间语义 | 需要为不同 FD creator 增加窄的 overlay 解码入口和回归测试 |
| 先把 FD state 写入持久 store，再执行 handler | 改动表面较小 | 改变副作用顺序，可能让 handler 观察到不应提前可见的状态 |

选择第一种。signalfd 和 dup3 分成两个窄提交：各自先写失败回归，验证同一 exit event 的 `return_text`，再复用 event-time overlay 边界；不把持久 store 的副作用提前。

### D. `orphan_exit` 是真实的生命周期/关联缺口，尚未定位到具体 syscall（P0）

`bpf/pending_state.h` 只在以下条件同时成立时递增 `orphan_exit`：

- 当前 TID 仍被 lifecycle filter 标记为 tracked；
- `attach_exited_map` 没有把它标成 teardown；
- syscall 被 trace 或 FD-state 跟踪；
- syscall 不属于已知的 terminating、fork child 或 exec restart unmatched 情况；
- task-local pending state 查不到。

因此当前的 `orphan_exit=2` 不能直接归因于 Ringbuf 丢失：本次统计同时显示 `ringbuf_reserve_fail=0`、`ringbuf_copy_fail=0`、`pending_update_fail=0`。更可能的候选是某个 raw `sys_exit` 与 task storage/lifecycle cleanup 的竞态，或某个 route 没有建立对应 pending state；但现有 counter 只记录总数，没有 syscall ID/TID/reason，不能安全猜修。

下一步不是放宽 counter，而是增加仅用于 debug/semantic fixture 的原因分类：至少记录 `sys_id`、`tid`、pending lookup 结果、tracked/filter 状态和 lifecycle teardown 状态，然后用最小 fixture 重现。确认具体路径后再补 BPF 回归测试。

### E. `dup3_flags` 生成输入位于 submodule 未跟踪区（P0，阶段 2 已关闭）

阶段 2 前，`strace-upstream/src/xlat/dup3_flags.in` 是 submodule 内的未跟踪文件。父仓库只能提交 submodule gitlink，无法携带这个文件；干净检出后，生成器仍会写出 `dup3 -> dup3_flags` 映射，却不会生成对应表。

upstream 的 `src/dup.c` 使用 `open_mode_flags` 打印 dup3 flags，但本项目的通用 decoder 会对名称包含 `open_mode_flags` 的表额外解释 `O_RDONLY`、`O_WRONLY` 和 `O_RDWR`。因此不能简单把 dup3 映射改成 `open_mode_flags`：dup3 的 `0` 必须输出 `0`，访问模式位必须按未知 `O_???` 处理。

方案比较：

| 方案 | 优点 | 风险 |
| --- | --- | --- |
| 生成器从 upstream `open_mode_flags.in` 派生 `dup3_flags`，但不启用 access-mode 特例 | 单一 upstream 输入来源；不会污染 submodule；自动跟随新增 open flags | 生成器需要显式记录派生表关系，并确保稳定 fallback 同步写入 |
| 在主仓库维护一份静态 `dup3_flags` 表 | 实现直接 | 与 upstream `open_mode_flags.in` 重复，后续新增 flag 容易漂移 |
| 在 submodule 创建并提交该输入 | 文件可追踪 | 需要维护非 upstream patch 和新 gitlink，不符合参考 submodule 的所有权边界 |

选择并已实现第一种。生成器先收集 upstream xlat，再从已经解析、求值后的 `open_mode_flags` 数据生成第二个表名，最后按表名排序输出；显式 upstream 表存在时优先使用显式输入，派生 source 缺失时立即失败。两个表共享稳定 fallback，只有 `open_mode_flags` 触发 access-mode 解码。

阶段 2 验证结果：

- 生成结果同时包含 `open_mode_flags` 和 `dup3_flags`；
- dup3 的 `0` 输出 `0`，`O_TRUNC|O_CLOEXEC` 正常解码，访问模式位保留 `O_???` 语义；
- `O_EMPTYPATH` 使用稳定值 `67108864` 补入 open/dup3 表，`openat.gen.test` 和完整 `small` 通过；
- `dup3.gen.test`、`dup3-P.gen.test` 通过；`dup3-y.gen.test`、`dup3-yy.gen.test` 仅剩 C 节记录的 FD event-time path diff；
- 完整生成后 submodule 保持 clean。

### F. 生成的 xlat/格式差异（P1，逐项聚焦）

已观察到的代表性差异包括：

- `openat2` 输出缺少 upstream 新增的 `OPENAT2_REGULAR`，并把 `0x100000000` 留作未知位；该常量来自 `strace-upstream/src/xlat/openat2_flags.in` 和 bundled `linux/openat2.h`，而当前生成器只把 `open_mode_flags` 用于 openat2 handler，没有纳入该 flag；
- `file_setattr` 的 `at_flags`/未知位输出与 upstream 不一致，需要用 `file_setattr*.gen.test` 的精确 diff 确认是 supplemental xlat 表还是 decoder 的 unknown-bit 规则；
- 时间类失败中有一部分来自 `sleep`/`sleep-timing` helper 缺失，不能和格式化 bug 混修。

方案比较：

| 方案 | 优点 | 风险 |
| --- | --- | --- |
| 先修 generator input、xlat mapping 和 focused handler test | 生成边界清晰，后续不会被 build 覆盖 | 需要补生成器/生成结果两层验证 |
| 直接编辑 `pkg/meta/xlat_auto.go` | 见效快 | 下次 `build.sh` 丢失，违反生成文件约束 |

选择第一种。`OPENAT2_REGULAR` 是最适合的第一个兼容性小修：输入来源明确、值明确、upstream 用例集中。

## 分阶段修复计划

| 阶段 | 改动边界 | 验收 | 建议提交 |
| --- | --- | --- | --- |
| 1. 修 runner inventory 和 prerequisite（已完成） | `test/run_tests.py`、`test/run_tests_upstream_setup_unit.py`；读取配置后的 `TESTS`，调用 `check-prerequisites-local`，传播构建错误 | 55 项 Python 单测通过；干净 upstream 可自行配置并构建 helper；清单为 1494 项且排除 6 个禁用 stacktrace 测试；`small` 为 22 PASS / 1 个明确 xlat FAIL | `test: honor configured upstream test inventory` |
| 2. 关闭 dup3 生成输入所有权（已完成） | `cmd/generate-xlats/`、生成结果及测试；删除 submodule 未跟踪输入 | generator/meta 单测和 `go test ./...` 通过；`small` 23/23；dup3 基础用例 2/2，y/yy 仅剩具名 FD path diff；submodule clean | `f51471f fix(generator): derive dup3 flags from open flags` |
| 3. 重建可信基线（已完成） | 不改 syscall 实现，只重跑配置后的 `all` 并按 environment / contract / implementation 分类 | 配置清单 1494 项；466 PASS / 851 FAIL / 177 SKIP；保留纯 eBPF、PID namespace、FD path、decoder 和环境类代表性 diff | `docs: refresh upstream failure inventory` |
| 4. 验证 signalfd event-time FD path | handler event-time overlay 和回归测试已提交；用 fresh binary 做 root semantic 验收 | 两个 signalfd semantic 断言归零；相关 Go 测试和 fresh `ebpf-semantic` | `fix(handler): render signalfd path from exit event` |
| 5. 修 dup3 event-time FD path | 复用 overlay 边界，但只处理 dup3 成功覆盖目标 FD | `dup3-y.gen.test`、`dup3-yy.gen.test` 通过；失败返回不改变 path；cloexec 状态保持正确 | `fix(handler): render dup3 return path from exit event` |
| 6. 定位 orphan exit | 仅增加原因级诊断，再按证据修 pending/lifecycle 路径 | 最小 fixture 定位 sys_id/TID/reason；正常 semantic fixture `orphan_exit=0`；attach 诊断契约不被破坏 | 分成 `test:` 诊断提交和一个窄 `fix(bpf):` 提交 |
| 7. 逐 syscall 修兼容性 | 先 `OPENAT2_REGULAR`，再 `file_setattr`，每次一个 family | focused upstream tests、相关 Go 测试、`small` 和受影响 `more` | 每个 family 一个 `fix(decoder):` 或 `fix(handler):` 提交 |
| 8. 整理契约分类 | 只登记有架构证据和 focused evidence 的 XFAIL | unexpected XPASS 仍失败；无批量未知 XFAIL；无 ptrace/procfs/process-vm fallback | `test: document upstream compatibility exceptions` |

阶段 1 和阶段 2 是可信测试基线的前置条件，现已分别提交，runner 变化和生成器变化没有混在一个 diff。阶段 3 只刷新证据，不夹带实现修复。阶段 4 的实现提交和本地回归已完成，但由于此前 root 命令使用了早于该提交的二进制，真实 semantic 验收仍未闭环。从阶段 4 开始，每一步的共同完成条件是：失败回归先失败、实现后 focused test 通过、`go test ./...` 通过，并且没有引入 ptrace/procfs/process-vm fallback。

## 重跑注意事项

`--skip-build` 只跳过 upstream build，不会替仓库生成 `/opt/strace-go/strace-go` 或 BPF object，也不会自动重编 Go 二进制。源码提交后必须先执行 `GOCACHE=/tmp/strace-go-gocache go build -o strace-go ./cmd/strace-go`；若 BPF object 被清理，则改为先执行 `GOCACHE=/tmp/strace-go-gocache ./build.sh`，再运行 semantic suite。否则即使二进制存在，也可能得到旧代码的测试结论。2026-09-08 的 `--suite all` 历史结果统一称为“文件系统扫测”；阶段 1 之后的新 `all` 才使用配置后的 upstream `TESTS`。
