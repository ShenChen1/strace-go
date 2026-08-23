#!/usr/bin/env python3

from ebpf_aio_suite import run_aio_semantic
from ebpf_bpf_iter_suite import run_bpf_iter_semantic
from ebpf_bpf_rare_suite import run_bpf_rare_semantic
from ebpf_bpf_stream_suite import run_bpf_stream_semantic
from ebpf_bpf_struct_ops_suite import run_bpf_struct_ops_semantic
from ebpf_bpf_suite import run_bpf_semantic
from ebpf_cloexec_suite import run_cloexec_semantic
from ebpf_epoll_suite import run_epoll_semantic
from ebpf_ioctl_suite import run_ioctl_semantic
from ebpf_key_suite import run_key_semantic
from ebpf_keyctl_suite import run_keyctl_semantic
from ebpf_network_suite import run_network_semantic
from ebpf_no_ptrace_suite import run_no_ptrace_semantic
from ebpf_poll_select_suite import run_poll_select_semantic
from ebpf_recvmsg_suite import run_recvmsg_semantic
from ebpf_signalfd_suite import run_signalfd_semantic
from ebpf_sockopt_suite import run_sockopt_semantic
from ebpf_xattr_suite import run_xattr_semantic


def run_extended_semantic_suites(wrapper, root):
    failures = []
    failures.extend(run_no_ptrace_semantic(wrapper, root))
    failures.extend(run_epoll_semantic(wrapper))
    failures.extend(run_cloexec_semantic())
    failures.extend(run_ioctl_semantic(wrapper, root))
    failures.extend(run_key_semantic(wrapper, root))
    failures.extend(run_keyctl_semantic(wrapper, root))
    failures.extend(run_signalfd_semantic(wrapper, root))
    failures.extend(run_network_semantic(wrapper, root))
    failures.extend(run_poll_select_semantic(wrapper, root))
    failures.extend(run_recvmsg_semantic(wrapper, root))
    failures.extend(run_sockopt_semantic(wrapper, root))
    failures.extend(run_xattr_semantic(wrapper, root))
    failures.extend(run_aio_semantic(wrapper, root))
    failures.extend(run_bpf_semantic(wrapper, root))
    failures.extend(run_bpf_iter_semantic(wrapper, root))
    failures.extend(run_bpf_rare_semantic(wrapper, root))
    failures.extend(run_bpf_stream_semantic(wrapper, root))
    failures.extend(run_bpf_struct_ops_semantic(wrapper, root))
    return failures
