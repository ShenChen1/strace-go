#!/usr/bin/env python3
import os
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


class FixtureBuildTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
