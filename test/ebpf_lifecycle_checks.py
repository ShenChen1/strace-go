import os

from ebpf_check_support import require, valid_stats_event


def check_lifecycle(context, failures):
    events = context.main.lifecycle_events
    actions = {event.get("action") for event in events}
    process_ids = {event.get("pid") for event in context.main.events}
    require(len(process_ids) >= 2, failures, "forked child pid events missing")
    for action in ("fork", "exec"):
        require(action in actions, failures, f"{action} lifecycle event missing")
    require(
        "exit" in actions or "free" in actions,
        failures,
        "exit/free lifecycle event missing",
    )
    require(
        any(_is_live_fork_state(event) for event in events),
        failures,
        "fork lifecycle task state missing",
    )
    require(
        any(_is_live_exec_state(event) for event in events),
        failures,
        "exec lifecycle task state missing",
    )
    require(
        any(_is_true_exec_filename(event) for event in events),
        failures,
        "exec lifecycle filename missing",
    )
    exec_tasks = {
        event.get("task_tid"): event.get("task_executable")
        for event in events
        if _is_true_task_executable(event)
    }
    require(exec_tasks, failures, "exec lifecycle task executable state missing")
    require(
        any(_retains_executable(event, exec_tasks) for event in events),
        failures,
        "exit/free lifecycle lost task executable state",
    )
    require(
        any(
            event.get("action") in ("exit", "free")
            and event.get("alive") is False
            for event in events
        ),
        failures,
        "exit/free task state stayed alive",
    )


def _is_live_fork_state(event):
    return (
        event.get("action") == "fork"
        and event.get("task_tid") == event.get("arg1")
        and event.get("parent_tid") == event.get("arg0")
        and event.get("alive")
    )


def _is_live_exec_state(event):
    return event.get("action") == "exec" and event.get("execed") and event.get("alive")


def _is_true_exec_filename(event):
    return (
        event.get("action") == "exec"
        and os.path.basename(event.get("filename") or "") == "true"
    )


def _is_true_task_executable(event):
    return (
        event.get("action") == "exec"
        and os.path.basename(event.get("task_executable") or "") == "true"
    )


def _retains_executable(event, exec_tasks):
    task_tid = event.get("task_tid")
    return (
        event.get("action") in ("exit", "free")
        and task_tid in exec_tasks
        and event.get("task_executable") == exec_tasks[task_tid]
    )


def check_thread(context, failures):
    capture = context.thread
    syscalls = [
        event
        for event in capture.events
        if event.get("syscall") == "getpid" and event.get("tid") != event.get("pid")
    ]
    forks = [
        event for event in capture.lifecycle_events if event.get("action") == "fork"
    ]
    exec_events = [
        event
        for event in capture.events
        if event.get("syscall") == "execve" and event.get("tid") != event.get("pid")
    ]
    exec_tids = {event.get("tid") for event in exec_events}
    exec_lifecycle = [
        event
        for event in capture.lifecycle_events
        if event.get("action") == "exec"
        and event.get("arg0") in exec_tids
        and event.get("arg0") != event.get("task_tid")
    ]
    migrated_exec_tasks = {
        event.get("task_tid"): event.get("task_executable")
        for event in exec_lifecycle
        if _is_true_task_executable(event)
    }
    require(
        capture.result.returncode == 0,
        failures,
        f"thread fixture rc={capture.result.returncode}",
    )
    require(
        "thread-fixture-ok" in capture.result.stdout,
        failures,
        "thread fixture stdout marker missing",
    )
    require(
        len(capture.stats_events) == 1
        and valid_stats_event(capture.stats_events[0]),
        failures,
        "thread stats event missing",
    )
    require(syscalls, failures, "non-leader thread getpid events missing")
    require(
        any(
            event.get("event_type") == "exit" and event.get("paired_enter")
            for event in syscalls
        ),
        failures,
        "thread getpid exit not paired",
    )
    require(exec_events, failures, "non-leader thread execve events missing")
    require(
        any(
            event.get("event_type") == "exit" and event.get("paired_enter")
            for event in exec_events
        ),
        failures,
        "non-leader thread execve exit not paired",
    )
    require(
        any(_is_true_task_executable(event) for event in exec_lifecycle),
        failures,
        "non-leader exec lifecycle task migration missing",
    )
    require(
        any(
            _retains_executable(event, migrated_exec_tasks)
            and event.get("task_tgid") == event.get("pid")
            and event.get("alive") is False
            for event in capture.lifecycle_events
        ),
        failures,
        "non-leader exec exit/free lost migrated executable state",
    )
    require(
        any(
            event.get("task_tid") == event.get("arg1")
            and not event.get("task_tgid")
            for event in forks
        ),
        failures,
        "thread fork guessed child TGID",
    )
    text = context.thread_text.stderr
    require(
        context.thread_text.returncode == 0,
        failures,
        f"thread text rc={context.thread_text.returncode}",
    )
    require(
        "thread-fixture-ok" in context.thread_text.stdout,
        failures,
        "thread text stdout marker missing",
    )
    require(
        "read(" in text and "<unfinished ...>" in text,
        failures,
        "thread unfinished output missing",
    )
    require("<... read resumed>)" in text, failures, "thread resumed output missing")
    require(
        "superseded by execve" in text and "<... execve resumed>) = 0" in text,
        failures,
        "non-leader exec superseded output missing",
    )
