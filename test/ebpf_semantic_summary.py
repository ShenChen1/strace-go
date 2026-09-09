def print_semantic_summary(context, filter_event_count):
    main = context.main
    stats = main.stats_events[0] if main.stats_events else {}
    print(f"=> eBPF thread semantic events: {len(context.thread.events)}")
    print(f"=> eBPF thread lifecycle events: {len(context.thread.lifecycle_events)}")
    print(f"=> eBPF mount-query semantic events: {len(context.mount_query.events)}")
    print(f"=> eBPF mount-path semantic events: {len(context.mount_path.events)}")
    print(f"=> eBPF dirent semantic events: {len(context.dirent.events)}")
    print(f"=> eBPF mmsg semantic events: {len(context.mmsg.events)}")
    unfinished = sum(
        1
        for line in context.thread_text.stderr.splitlines()
        if "<unfinished ...>" in line
    )
    print(f"=> eBPF thread unfinished text lines: {unfinished}")
    attach_stats = context.attach.stats_events
    orphan = attach_stats[0].get("orphan_exit") if attach_stats else "unavailable"
    print(f"=> eBPF attach orphan exits: {orphan}")
    attach_thread = context.attach_thread
    print(
        f"=> eBPF non-leader attach enter/exit: "
        f"{sum(event.get('event_type') == 'enter' for event in attach_thread.events)}/"
        f"{sum(event.get('event_type') == 'exit' for event in attach_thread.events)}"
    )
    thread_stats = attach_thread.stats_events
    thread_orphan = thread_stats[0].get("orphan_exit") if thread_stats else "unavailable"
    print(f"=> eBPF non-leader attach orphan exits: {thread_orphan}")
    print(f"=> eBPF semantic events: {len(main.events)}")
    print(f"=> eBPF fcntl semantic events: {len(context.fcntl.events)}")
    print(f"=> eBPF semantic enter/exit: {len(main.enter_events)}/{len(main.exit_events)}")
    print(f"=> eBPF lifecycle events: {len(main.lifecycle_events)}")
    print(f"=> eBPF ringbuf reserve failures: {stats.get('ringbuf_reserve_fail')}")
    print(f"=> eBPF ringbuf copy failures: {stats.get('ringbuf_copy_fail')}")
    print(f"=> eBPF payload truncated events: {stats.get('payload_truncated_events')}")
    print(f"=> eBPF pending update failures: {stats.get('pending_update_fail')}")
    print(f"=> eBPF orphan exits: {stats.get('orphan_exit')}")
    print(
        f"=> eBPF orphan first: pid={stats.get('orphan_first_pid')} "
        f"tid={stats.get('orphan_first_tid')} sys_id={stats.get('orphan_first_sys_id')} "
        f"ret={stats.get('orphan_first_ret')} reason={stats.get('orphan_first_reason')}"
    )
    print(
        f"=> eBPF orphan last: pid={stats.get('orphan_last_pid')} "
        f"tid={stats.get('orphan_last_tid')} sys_id={stats.get('orphan_last_sys_id')} "
        f"ret={stats.get('orphan_last_ret')} reason={stats.get('orphan_last_reason')}"
    )
    print(f"=> eBPF pending mismatches: {stats.get('pending_mismatch')}")
    print(
        f"=> eBPF lifecycle map update failures: "
        f"{stats.get('lifecycle_map_update_fail')}"
    )
    print(f"=> eBPF write-only events: {filter_event_count}")
