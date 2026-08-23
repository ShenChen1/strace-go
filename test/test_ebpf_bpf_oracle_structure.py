import ast
import unittest
from pathlib import Path

import ebpf_bpf_semantic_checks
import ebpf_bpf_suite


class BpfOracleStructureTests(unittest.TestCase):
    def test_suite_keeps_public_facade(self):
        self.assertIs(
            ebpf_bpf_suite.check_bpf_semantic,
            ebpf_bpf_semantic_checks.check_bpf_semantic,
        )
        self.assertTrue(callable(ebpf_bpf_suite.run_bpf_semantic))

    def test_oracle_modules_respect_source_limits(self):
        root = Path(__file__).parent
        for name in ("ebpf_bpf_event_queries.py", "ebpf_bpf_semantic_checks.py"):
            path = root / name
            source = path.read_text(encoding="utf-8")
            self.assertLessEqual(len(source.splitlines()), 500, name)
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                line_count = node.end_lineno - node.lineno + 1
                self.assertLessEqual(line_count, 80, f"{name}:{node.name}")


if __name__ == "__main__":
    unittest.main()
