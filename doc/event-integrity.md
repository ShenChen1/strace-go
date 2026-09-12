# ADR：事件损失后的可信度

## Problem 1-Pager

- Context：单 Ringbuf、单 Go 消费者维护 event-sourced FD/path/correlation；现有异常只有最终统计。
- Problem：漏掉 close/dup/chdir/fork 后，后续输出可能复用已经失真的历史；零值 seq 无法定位连续性中断。
- Goal：检测连续性中断，在消费当前记录前设置分域 taint，公开检测边界，停止不可信历史推断，并覆盖没有后续事件的尾部损失。
- Non-Goals：全局事件排序、丢失事件重放、procfs 补读、完整共享资源图、自动恢复整张 FD 表。
- Constraints：纯 eBPF；单消费者；所有 BPF collections 共享同一完整性状态；正常路径无跨 CPU atomic 写；诊断不能把检测位置冒充实际损失位置。

## 方案比较

| 方案 | 优点 | 缺点及风险 | gap 的安全 taint 范围 |
| --- | --- | --- | --- |
| global seq | 单一编号空间 | 每条事件争用；atomic 与 reserve 不是一个事务，编号仍可能重排 | 缺失记录身份未知，整个 session |
| per-CPU seq | CPU 本地写，跨 task 仍可发现缺口 | task 迁移；CPU 空闲时延迟发现；嵌套探针编号与 reserve 次序可能不同 | 不能只 taint 该 CPU；缺失任务及共享关系未知，整个 session |
| per-task seq | gap 可归属发射 task，迁移不影响 | 需要稳定 task lifetime identity；首条/最后一条及整个 task 消失无法靠后继发现；fork/free 的发射者不等于事件主体 | 该 task 的配对，加上共享 files/fs、继承后代；共享图不完整时仍须整个 session |
| hybrid（选择） | per-CPU 连续性检查，加异常路径全局 epoch，其他 CPU 也能报告故障 | 多读取一个共享状态；仍不提供精确损失位置或全局排序 | 当前实现整个 session，后续任务继承 taint |

假设与选择：当前没有完整的 CLONE_FILES/CLONE_FS 共享资源图，因此不承诺 PID 级隔离。选择保守 session taint；一次 exec 不足以证明 cwd、继承 FD 和共享关系重新可信。

## 协议与边界

沿用 event-v2 的 version、类型和正文。通过 header_len 将 header 从 56 扩展到 80 字节，增加 CPU、loss epoch 和首次异常 monotonic 时间。56 字节旧 header 仍可解码，但没有 sequence 验证能力；不将旧 seq=0 误报为丢失。保留 u32 CPU 和 u64 sequence，避免 packed 16/48 方案的 CPU 上限和计数回绕缩短。CPU hotplug 不重建 map，map 生命周期就是 session 基线。

每 CPU seq 从 1 开始，在每次 reserve 前为 record emission attempt 分配一个序号。之后 reserve/copy/discard 失败都不退回或重复分配。copy failure 有时仅丢失 record 内一个 section，故分类统计不等于丢失记录数。过滤、enter elision 不分配序号。所有 enter/exit/fragment/lifecycle/signal 使用相同编号源。先 reserve 后发现无可选 payload 的路径提交无 payload 的完整 exit，避免取消后 fallback 产生无意义缺口。

reserve/copy/pending/mismatch/lifecycle update failure 以及非预期 orphan 增加全局 loss epoch；payload probe fault/truncation 不增加。附加首次异常时间，尾部异常同时保存在 per-CPU stats，最终 drain 后对账。

seq 用于连续性检查，不用于排序。每 CPU 首次记录建立基线，允许 attach mid-stream；重复、倒退与前向缺口分别统计。uint64 自然回绕按模加法处理。CPU 编号不复用为 task 身份。嵌套 producer 可使编号与 reservation 重排，不能把倒退当作巨大丢失数量；缺口估计与最终 producer counters 分别报告。

所有记录在用户态 scope/output filter 之前检查；invalid record 立即形成完整性屏障。输出记录消费位置、CPU、expected/observed seq、loss epoch、首次异常时间。检测之前已经输出的行不能撤销，也不能宣称是已认证的完整前缀；时间和消费位置只界定观测证据。CPU 没有后继事件的损失通过其他 CPU 的 epoch 或最终统计发现。

## 降级与恢复

- 清除当前所有 pending enter/exit、fragment、exec 参数、suspended/unfinished 数据及待解析 fork 继承；释放持有的 payload。
- 历史 FD/path/cwd/offset/identity/cloexec 不再用于解释；后续事件和 fork/exec 都不能恢复旧历史。
- 当前记录内的 args/ret、bounded payload、FD/path snapshot 仍是直接观测事实。correlation 每个 TID 单独恢复：缺口后清理所有 pending；新的 generic enter 可建立候选，只有 sys_id、enter_time、args 匹配的 exit 才完成恢复。fragment 不能单独恢复，也不能跨 syscall 身份合并。新的缺口再次清除候选。
- task 的历史 executable/parent 推断失效；已明确观测的退出事实仍可用于控制面清理，不能把清空任务表当作“全部 task 已退出”。
- 文本输出立即报告 session taint；JSON 提供 integrity 诊断和后续事件的 degraded 标记；summary 仅统计已观察事件，完整性状态同时报告。
- FD/path 与 topology 历史不自动恢复；exec 保留非 CLOEXEC FD，也不能证明共享 files/fs 图完整。close_range 只能证明范围内描述符的关闭，不能恢复 cwd、范围外 FD 或未知共享关系。当前快照仅重建当前事件的局部事实，不授权未来复用。task exit/free 结束该 task 的 correlation 污染；exec 清理旧/新 TID，后续完整 pair 恢复。累计输出/summary 缺失保持到 session 结束。

## 实施与验收阶段

1. 协议：reserve 前为每次 record emission attempt 分配编号；copy/discard 不重复编号；过滤、未发送的 tail-call 分支不编号。独立 fragment 各占一次。
2. concrete TraceIntegrity owner：reader admission 前检查；未知 gap 对全部潜在共享者失效，按 TID 维护 correlation 恢复，分别公开 fd_state/lifecycle/output_state。
3. 重复 gap、迁移、wrap、旧 ABI、exec TID 变更和 FD 不复活的回归测试。
4. 文本转换警告，JSON 增量字段，最终输出 gaps/estimated loss/transitions/active tainted tasks/processes/recoveries 与 BPF counters。
5. 仅测试 fixture 提供每 N 条、类型和下一条故障；覆盖 enter/exit/fragment/close/dup/fork/exec/exit/free。
6. Go test/vet/build，root producer fixture、small 与相关 more；保留已有 XFAIL/XPASS。
7. baseline/global/per-CPU producer 与 Go detector/state benchmarks；微基准不冒充 tracing throughput 或全机 BPF CPU 成本。

## 影响说明

完整性 owner 位于 reader 与 router 之间，必须先失效领域状态再解释本记录。ABI generator、BPF 公共 header 初始化及异常统计是生产者入口；FDStateStore 的读取边界和 TraceState 的配对边界负责 fail-closed。输出编码复用既有编码器，不输出 tracee 数据到诊断日志。

## 验证

需覆盖正常跨 CPU/迁移、首条 gap、间隔 gap、重复/倒退/回绕、其他 CPU 传播 epoch、invalid record、尾部损失、旧 FD/cwd 不复活、当前快照保留、fragment/deferred/unfinished 释放、fork/exec 不恢复。运行结果在实现验证后补充。

参考：[Linux Ringbuf 文档](https://docs.kernel.org/bpf/ringbuf.html)明确消费者按 reservation 顺序观察，commit 独立；seq 不替代该顺序。
