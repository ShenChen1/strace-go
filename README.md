# strace-go

`strace-go` 是一个基于 **Go 语言** 和 **eBPF (Extended Berkeley Packet Filter)** 技术实现的系统调用追踪工具。产品路径只有一条：纯 eBPF syscall tracing。

> [!NOTE]
> 纯 eBPF 路线不承诺与经典 `strace` 完全等价。它不在运行期 ptrace/reaper 目标进程，因此不提供 ptrace 冻结点内存快照、严格 stdout/stderr 交错顺序或完整信号 restart 语义。上游 `strace` 测试只作为参考，不对应 ptrace 兼容模式。

---

## 🛠️ 项目结构

```text
strace-go/
├── bpf/                   # eBPF C 源码及内核头文件 (strace.c, vmlinux.h, direct event helpers)
├── cmd/
│   ├── generate-syscalls/ # 系统调用字典生成器 (从内核动态提取 ID 与参数信息)
│   ├── generate-xlats/    # 标志位常量翻译生成器 (从 strace-upstream 提取 flags 字典)
│   └── strace-go/         # 主程序入口及 eBPF 加载器与事件循环
├── pkg/
│   ├── cli/               # 命令行参数解析
│   ├── event/             # eBPF 事件解析、缓存同步与路径过滤
│   ├── format/            # 常用系统调用数据结构（如 stat, timespec 等）的格式化解析器
│   ├── handler/           # 基于注册表的特定系统调用解码器 (如 ioctl, epoll, network 等)
│   ├── meta/              # 自动生成的系统调用元数据与标志翻译表 (syscall_table.go, xlat_auto.go)
│   └── stacktrace/        # BPF 用户栈地址格式化（--stack-trace）
├── test/                  # 测试框架与批量集成测试脚本
├── strace-upstream/       # 官方 strace 源代码仓库 (Submodule, 用作测试对照和数据源)
├── build.sh               # 一键生成与构建脚本
└── strace-go              # 编译后生成的可执行文件
```

---

## 🏗️ 架构设计与工作流

`strace-go` 采用“**内核态探针快照 + 用户态单消费者状态机**”的解耦架构。其主要工作流程如下：

```mermaid
graph TD
    subgraph 内核态 (eBPF Kernel Probe)
        tp_enter[sys_enter tracepoint] --> |1. 触发系统调用| filter{PID 过滤}
        filter -->|匹配| direct_enter[direct event v2 helper<br/>按 syscall 现场拷贝 IN payload]
        direct_enter -->|2. 保存 exit 所需元数据| pending_map[(pending_syscalls HASH MAP<br/>Key: TID, compact metadata)]
        direct_enter -->|可选 JSON/debug enter| ring_buf[events BPF RING BUFFER]
        
        tp_exit[sys_exit tracepoint] -->|4. 系统调用返回| lookup[从 pending_syscalls 查找对应 TID 缓存]
        lookup -->|找到| direct_exit[direct event v2 helper<br/>按 syscall 现场拷贝 OUT payload]
        direct_exit -->|5. 发送 exit event v2| ring_buf
        direct_exit -->|6. 清理缓存| delete_hash[从 pending_syscalls 物理删除 TID]
    end

    subgraph 用户态 (Go User Space Controller)
        done_chan{目标进程状态}
        ring_reader[单 goroutine ReadInto Ring Buffer] -->|7. 读取/解码/派发| handler_loop[handleEvent 核心处理逻辑]
        done_chan -->|进程退出| wait_close[处理剩余缓存并优雅关闭]
        
        handler_loop -->|9. 解析嵌套指针/大参数| snapshot_check{BPF snapshot 是否完整?}
        snapshot_check -->|完整| format_step[format/handler 参数解码]
        snapshot_check -->|不完整/未读取| pointer_output[保留原始指针或已知 fd/file 缓存]
        pointer_output --> format_step
        
        format_step -->|10. 智能常量还原| xlat[meta/xlat_auto.go 常量翻译字典]
        xlat -->|11. 格式化输出| stderr[标准错误输出 stderr / 输出文件]
    end

    style 内核态 fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    style 用户态 fill:#efebe9,stroke:#5d4037,stroke-width:2px;
```

### 💡 底层设计要点

1. **线程级安全的上下文跟踪 (pending_syscalls)**
   为了避免多线程程序在内核中并发执行系统调用时产生交错与数据覆盖，`strace-go` 在内核中引入了以线程 ID (`TID`) 为 Key 的 `pending_syscalls` (HASH MAP)。在 `sys_enter` 时只保存 exit 阶段需要的紧凑元数据，在 `sys_exit` 时补齐返回值和 OUT 参数后删除。

2. **Direct event v2 + Ring Buffer**
   eBPF 探针不再维护固定 `str_arg` 大窗口，也不再通过 per-CPU `heap` 重建旧事件。需要 payload 的 syscall 由专项 direct helper 预留 Ring Buffer 记录空间，在探针现场写入 event v2 header/body 和 TLV sections；未知或未专项 syscall 走 no-payload event v2，仍保留 args/ret/duration。

3. **纯 eBPF snapshot 边界**
   由于 eBPF 运行在高度受限的安全沙箱中，内核态无法安全解引用任意深度的嵌套指针，也无法复制无限长度字符串。`strace-go` 的产品路径只消费探针现场已经复制进事件的 bytes：
   - **内核态拷贝**：在 `sys_enter`/`sys_exit` 阶段复制高价值 IN/OUT 参数快照。
   - **用户态解码**：Go handler 只解析 BPF snapshot、返回值、fd/path 状态和已知文件缓存。
   - **缺失数据策略**：若 snapshot 或 event-sourced FD state 不完整，输出原始指针/FD，不在运行期通过 `ptrace`、`process_vm_readv`、`/proc/<pid>/mem` 或 `/proc/<pid>/fd*` 补读 tracee 状态。
   - **栈回溯策略**：`-k` 只输出 BPF 在 probe 点捕获的原始用户指令地址；不读取 tracee 的 mapping 或 ELF 符号，避免用查询时快照解释已经变化的地址空间。

---

## 🚀 构建与编译指南

我们提供了一键自动化构建脚本 `build.sh`，可完成 eBPF 代码生成和 Go 二进制文件的编译：

```bash
./build.sh
```

### 📋 分步与手动构建流程

#### 1. 系统依赖
在编译前，请确保您的系统安装了以下组件：
- Go 1.24 或更高版本（go.mod 声明 `go 1.24.2`）
- `clang` & `llvm`（用于编译 eBPF C 源码）
- Linux 内核头文件：`linux-headers-$(uname -r)`
- 较新的 Linux 内核版本（建议 >= 5.8，需完整支持 BPF Ring Buffer 和 BTF 机制）

#### 2. 生成系统调用元数据与 BPF 字节码
因代码生成器需要动态读取受内核保护的 `/sys/kernel/tracing` 调试目录并提取当前系统的所有 tracepoints 参数，必须以 `sudo` 权限运行：
```bash
cd cmd/strace-go
sudo go generate ./...
```
> [!TIP]
> 运行成功后，会在 `pkg/meta/` 下自动生成 `syscall_table.go`，并在当前目录生成 `bpf_bpfel.go` / `bpf_bpfeb.go`（bpf2go 把编译后的 ELF 字节码内嵌进 Go 源文件；`.o` 只是中间产物，不进入版本库）。

#### 3. 编译与运行
回到项目根目录并编译：
```bash
cd ../..
go build -o strace-go ./cmd/strace-go
```
运行追踪目标：
```bash
sudo ./strace-go <待追踪的命令或进程>
```

### 机器可测输出

- `--event-format=json` 或 `--debug-events`：逐行输出结构化 syscall 事件，供 eBPF 语义测试和工具集成使用。
- JSON syscall 事件包含稳定的 `event_version`、`event_type` 和 `event_flags`。其中通用 syscall enter 事件只在 JSON/debug 通道打开时由 BPF 发出，普通文本输出继续消费 exit/full 事件，避免重复打印。
- JSON exit 事件会在 Go 侧按 TID 与 enter 事件配对；配对成功时输出 `paired_enter=true`。
- JSON/debug 通道禁止用户态 tracee memory fallback；未被 BPF 快照捕获的指针参数保留为地址，避免把 TOCTOU 读到的后态当成测试 oracle。
- 当前 v2 垂直切片已经覆盖 `enter`/`exit` 双相事件；后续状态机和 OUT 参数重构应继续以这些字段作为测试 oracle，而不是解析人类文本。

#### 4. 运行测试
测试采用纯 eBPF 语义门禁；upstream 测试只作为参考集。
```bash
python3 test/run_tests.py --suite small --skip-build
python3 test/run_tests.py --suite more --skip-build
python3 test/run_tests.py --suite upstream-reference --skip-build
python3 test/run_tests.py --suite ebpf-semantic --skip-build
python3 test/run_tests.py --suite ebpf-perf --skip-build
```
可用的 suite 有 `small`、`more`、`all`、`upstream-reference`、`ebpf-semantic`、`ebpf-perf`，也支持 `--filter <test>` 只跑单个用例。
`upstream-reference` 仍使用 `strace-upstream/tests` 作为参考；`ebpf-semantic` 使用本仓库 fixture 和 JSON 事件做语义断言，不做字节级输出 diff。
`upstream-reference` 与 `more` 中已知不属于纯 eBPF 契约的 upstream exact diff 会显示为 `XFAIL`，例如 `read-write.gen.test` 的大 payload hexdump（bounded snapshot 与 ptrace 大块 fetch 的语义差异）和 `strace-C.test`（上游 `-c` 汇总按 per-syscall CPU 时间计，eBPF 只能观测 wall-clock 时长）；稳定边界意外通过会显示 `XPASS` 并使 runner 失败，提醒维护者更新契约。`attach-p-cmd.test` 额外属于调度敏感的跨任务生命周期 exact diff：成功时显示 `XPASS-ALLOWED`，失败时仍显示 `XFAIL`，两种结果都不使 suite 失败，但不会改变 semantic lifecycle suite 的严格断言。

---

## ⚖️ 与传统 strace (基于 ptrace) 的优劣势对比

| 对比维度 | 传统 `strace` (基于 `ptrace`) | `strace-go` (基于 `eBPF` + `Go`) |
| :--- | :--- | :--- |
| **性能损耗 (Overhead)** | **极高** (每次系统调用导致多次内核态/用户态切换，目标进程可能显著变慢) | 低侵入异步观测；运行期不使用 ptrace reaper |
| **对应用运行的影响** | **高侵入** (强制停止/拦截应用执行，影响信号传递，多调试器间互斥) | 不使用运行期 ptrace reaper，不提供 ptrace 冻结语义 |
| **部署与执行权限** | **低权限** (普通用户可直接追踪自己所拥有的进程) | **高权限** (强制需要 Root 权限，或 `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_PTRACE`) |
| **复杂/嵌套结构解析** | **极其强大** (历经几十年演进，可深入解析 netlink、ioctl、套接字多层结构) | **较弱** (受限于 BPF Verifier 安全沙箱，只解析 BPF snapshot 覆盖到的数据) |
| **系统兼容性** | **极强** (几乎兼容所有 Linux 内核版本、各种类 Unix 系统以及多种硬件架构) | **受限** (仅支持较新 Linux 内核，且需要开启 BTF 功能以实现 BPF 模块正常加载) |

### 🌟 详细优势 (Pros)

1. **低侵入的 eBPF syscall 观测**
   核心追踪点放在内核态并通过 Ring Buffer 异步发送，适合低侵入 syscall observability。
2. **现代化的解耦架构**
   Go 语言编写的用户态处理循环可以非常轻松地被剥离出 CLI 界面，直接融入到 Kubernetes 等容器编排平台的 DaemonSet 或 Sidecar 监控组件中。
3. **完全兼容官方常量翻译**
   结合了 `cmd/generate-xlats` 工具，从官方 strace 精准提炼并支持了按位与标志位转换。能够输出符合 `O_RDONLY|O_CREAT|O_CLOEXEC` 的精细化逻辑表达。

### ⚠️ 缺点与局限性 (Cons)

1. **安全权限瓶颈**
   高特权级别的安全要求阻碍了非特权用户日常的开发调试。在一些有严格安全策略限制的生产容器云中，下发 `CAP_BPF` 或 `CAP_SYS_ADMIN` 会面临审计风险。
2. **snapshot 覆盖有限**
   为避免运行期补读 tracee 内存，未被 BPF 快照覆盖的深层结构、长字符串或大 payload 会退化为原始指针或截断数据。
3. **纯 eBPF 语义边界**
   不保证传统 `strace` 的冻结点内存读取、严格输出交错和完整信号 restart 语义；这是纯 eBPF 低侵入路线的明确取舍。
