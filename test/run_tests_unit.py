import unittest

import run_tests
import upstream_suites


class ClassifyTestResultTest(unittest.TestCase):
    def test_plain_pass(self):
        result = {"test": "getpid.gen.test", "success": True, "rc": 0}

        self.assertEqual(run_tests.classify_test_result(result, {}), ("pass", ""))

    def test_plain_fail(self):
        result = {"test": "getpid.gen.test", "success": False, "rc": 1}

        self.assertEqual(run_tests.classify_test_result(result, {}), ("fail", ""))

    def test_skip_wins_over_expected_failure(self):
        result = {"test": "read-write.gen.test", "success": False, "rc": 77}

        self.assertEqual(
            run_tests.classify_test_result(result, {"read-write.gen.test": "known"}),
            ("skip", ""),
        )

    def test_expected_failure(self):
        result = {"test": "read-write.gen.test", "success": False, "rc": 1}

        self.assertEqual(
            run_tests.classify_test_result(result, {"read-write.gen.test": "known"}),
            ("xfail", "known"),
        )

    def test_unexpected_pass(self):
        result = {"test": "read-write.gen.test", "success": True, "rc": 0}

        self.assertEqual(
            run_tests.classify_test_result(result, {"read-write.gen.test": "known"}),
            ("xpass", "known"),
        )

    def test_tolerated_unexpected_pass(self):
        result = {"test": "attach-p-cmd.test", "success": True, "rc": 0}

        self.assertEqual(
            run_tests.classify_test_result(
                result,
                {"attach-p-cmd.test": "scheduler-sensitive"},
                {"attach-p-cmd.test"},
            ),
            ("xpass_allowed", "scheduler-sensitive"),
        )


class UpstreamReferenceSuiteTest(unittest.TestCase):
    def test_stable_more_snapshot_is_explicit_and_unique(self):
        stable = upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS
        reference = upstream_suites.UPSTREAM_REFERENCE_TESTS

        self.assertEqual(len(stable), len(set(stable)))
        self.assertEqual(len(reference), len(set(reference)))
        self.assertTrue(set(stable).issubset(reference))

    def test_reference_does_not_promote_more_expected_failures(self):
        promoted = set(upstream_suites.UPSTREAM_REFERENCE_STABLE_MORE_TESTS)
        expected = set(upstream_suites.MORE_EXPECTED_FAILURES)

        self.assertTrue(promoted.isdisjoint(expected))
        self.assertNotIn("strace-C.test", promoted)
        self.assertNotIn("attach-p-cmd.test", promoted)


if __name__ == "__main__":
    unittest.main()
