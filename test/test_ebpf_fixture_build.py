#!/usr/bin/env python3
import os
import tempfile
import unittest
from unittest import mock

import ebpf_fixture_build
import ebpf_suites


class SemanticFixtureSourcePolicyTests(unittest.TestCase):
    def test_semantic_fixture_uses_bounded_procfs_free_source_set(self):
        sources = ebpf_suites.FIXTURE_SOURCES

        self.assertEqual(
            tuple(os.path.basename(source) for source in sources),
            (
                "ebpf_semantic_fixture.c",
                "ebpf_semantic_fs_workloads.c",
                "ebpf_semantic_runtime_workloads.c",
            ),
        )
        header = os.path.join(os.path.dirname(sources[0]), "ebpf_semantic_fixture.h")
        for source in (*sources, header):
            with open(source, "r", encoding="utf-8") as fixture_file:
                text = fixture_file.read()
            self.assertLessEqual(len(text.splitlines()), 500, source)
            self.assertNotIn("/proc/", text, source)
            self.assertNotIn("TracerPid", text, source)

    def test_runtime_test_support_does_not_read_procfs_or_rebuild_fds(self):
        test_dir = os.path.dirname(__file__)
        paths = (
            os.path.join(test_dir, "fixtures", "ebpf_dirent_fixture.c"),
            os.path.join(test_dir, "strace-sudo.sh"),
        )

        for path in paths:
            with open(path, "r", encoding="utf-8") as support_file:
                text = support_file.read()
            self.assertNotIn("/proc/", text, path)
        with open(paths[1], "r", encoding="utf-8") as wrapper_file:
            wrapper = wrapper_file.read()
        self.assertNotRegex(wrapper, r"\beval\b")
        self.assertNotIn("exec sudo", wrapper)
        self.assertNotIn("sudo env", wrapper)

    def test_no_ptrace_fixture_is_the_explicit_procfs_probe(self):
        path = os.path.join(
            os.path.dirname(__file__), "fixtures", "ebpf_no_ptrace_fixture.c"
        )
        with open(path, "r", encoding="utf-8") as fixture_file:
            text = fixture_file.read()
        self.assertIn('"/proc/self/status"', text)
        self.assertIn("TracerPid:", text)
        self.assertNotIn("/proc/", text.replace('"/proc/self/status"', ""))


class FixtureBuildTests(unittest.TestCase):
    def test_bpf_prog_load_fixture_uses_header_compatible_fd_array_abi(self):
        path = os.path.join(
            os.path.dirname(__file__), "fixtures", "ebpf_bpf_fixture.c"
        )
        with open(path, "r", encoding="utf-8") as fixture_file:
            text = fixture_file.read()

        self.assertIn("BPF_PROG_LOAD_FD_ARRAY_OFFSET = 120", text)
        self.assertIn("BPF_PROG_LOAD_FD_ARRAY_CNT_OFFSET = 148", text)
        self.assertIn("unsigned char bytes[BPF_PROG_LOAD_ATTR_SIZE]", text)
        self.assertIn("set_bpf_prog_load_fd_array(", text)
        self.assertNotIn("attr.fd_array_cnt", text)

    def test_bpf_percpu_fixture_defines_newer_uapi_flags(self):
        path = os.path.join(
            os.path.dirname(__file__), "fixtures", "ebpf_bpf_percpu_fixture.c"
        )
        with open(path, "r", encoding="utf-8") as fixture_file:
            text = fixture_file.read()

        self.assertIn("#ifndef BPF_F_CPU", text)
        self.assertIn("#define BPF_F_CPU 8U", text)
        self.assertIn("#ifndef BPF_F_ALL_CPUS", text)
        self.assertIn("#define BPF_F_ALL_CPUS 16U", text)

    @mock.patch.object(ebpf_fixture_build.os, "chmod")
    @mock.patch.object(ebpf_fixture_build.subprocess, "run")
    def test_build_fixture_compiles_all_sources(self, run, chmod):
        sources = ["entry.c", "workload.c"]

        ebpf_fixture_build.build_fixture(sources, "/tmp/fixture", ["-pthread"])

        run.assert_called_once_with(
            [
                "gcc",
                "-O2",
                "-Wall",
                "-Wextra",
                "-pthread",
                "-o",
                "/tmp/fixture",
                *sources,
            ],
            check=True,
        )
        chmod.assert_called_once_with("/tmp/fixture", 0o755)

    def test_build_fixture_rejects_empty_source_set(self):
        with self.assertRaisesRegex(ValueError, "at least one source"):
            ebpf_fixture_build.build_fixture([], "/tmp/fixture")

    def test_build_fixture_rejects_scalar_source(self):
        with self.assertRaisesRegex(TypeError, "source sequence"):
            ebpf_fixture_build.build_fixture("fixture.c", "/tmp/fixture")

    def test_build_fixture_rejects_scalar_extra_args(self):
        with self.assertRaisesRegex(TypeError, "argument sequence"):
            ebpf_fixture_build.build_fixture(
                ["fixture.c"], "/tmp/fixture", "-pthread"
            )

    @mock.patch.object(ebpf_fixture_build.os, "chmod")
    @mock.patch.object(ebpf_fixture_build.subprocess, "run")
    def test_build_bpf_object_compiles_one_source(self, run, chmod):
        ebpf_fixture_build.build_bpf_object("stream.o", "stream.bpf.c", ["-DTEST=1"])

        run.assert_called_once_with(
            [
                "clang",
                "-target",
                "bpf",
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DTEST=1",
                "-c",
                "stream.bpf.c",
                "-o",
                os.path.join(tempfile.gettempdir(), "stream.o"),
            ],
            check=True,
        )
        chmod.assert_called_once_with(
            os.path.join(tempfile.gettempdir(), "stream.o"), 0o644
        )

    def test_build_bpf_object_rejects_invalid_source(self):
        with self.assertRaisesRegex(ValueError, "one source path"):
            ebpf_fixture_build.build_bpf_object("stream.o", "")

    def test_build_bpf_object_rejects_scalar_extra_args(self):
        with self.assertRaisesRegex(TypeError, "argument sequence"):
            ebpf_fixture_build.build_bpf_object("stream.o", "stream.bpf.c", "-g")


if __name__ == "__main__":
    unittest.main()
