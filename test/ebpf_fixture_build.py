#!/usr/bin/env python3
import os
import subprocess
import tempfile


def build_fixture(sources, output, extra_args=None):
    if isinstance(sources, (str, bytes, os.PathLike)):
        raise TypeError("fixture sources must be a source sequence")
    source_paths = tuple(os.fspath(source) for source in sources)
    if not source_paths:
        raise ValueError("fixture requires at least one source")
    if isinstance(extra_args, (str, bytes, os.PathLike)):
        raise TypeError("fixture extra args must be an argument sequence")

    command = ["gcc", "-O2", "-Wall", "-Wextra"]
    if extra_args:
        command.extend(extra_args)
    command.extend(["-o", os.fspath(output), *source_paths])
    subprocess.run(command, check=True)
    os.chmod(output, 0o755)


def build_named_fixture(name, sources, extra_args=None):
    output = os.path.join(tempfile.gettempdir(), name)
    build_fixture(sources, output, extra_args)
    return output


def build_bpf_object(name, source, extra_args=None):
    if isinstance(source, (bytes, os.PathLike)):
        source = os.fspath(source)
    if not isinstance(source, str) or not source:
        raise ValueError("BPF object requires one source path")
    if isinstance(extra_args, (str, bytes, os.PathLike)):
        raise TypeError("BPF object extra args must be an argument sequence")
    output = os.path.join(tempfile.gettempdir(), name)
    command = [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
    ]
    if extra_args:
        command.extend(extra_args)
    command.extend(["-c", source, "-o", output])
    subprocess.run(command, check=True)
    os.chmod(output, 0o644)
    return output
