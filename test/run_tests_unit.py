import unittest

import run_tests


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


if __name__ == "__main__":
    unittest.main()
