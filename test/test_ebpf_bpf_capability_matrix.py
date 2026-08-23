import json
import unittest

from ebpf_bpf_capability_matrix import (
    CAPABILITY_PROBES,
    check_capability_matrix,
    parse_capability_records,
)


def _record(command, probe, status="invalid_input", error=22):
    return {
        "type": "bpf_capability",
        "command": command,
        "name": CAPABILITY_PROBES[(command, probe)],
        "status": status,
        "errno": error,
        "probe": probe,
    }


def _stdout(records):
    return "\n".join(json.dumps(record, sort_keys=True) for record in records)


class CapabilityMatrixTests(unittest.TestCase):
    def complete_records(self):
        return [
            _record(32, "valid", "supported", 0),
            _record(33, "invalid-object"),
            _record(36, "valid", "environment_blocked", 95),
            _record(36, "invalid-object"),
            _record(37, "invalid-object"),
            _record(38, "invalid-object"),
        ]

    def test_accepts_complete_matrix(self):
        stdout = _stdout(self.complete_records())
        self.assertEqual(len(parse_capability_records(stdout)), 6)
        self.assertEqual(check_capability_matrix(stdout), [])

    def test_rejects_missing_probe(self):
        records = self.complete_records()
        records.pop()
        failures = check_capability_matrix(_stdout(records))
        self.assertTrue(any("missing BPF capability probes" in failure for failure in failures))

    def test_rejects_duplicate_probe(self):
        records = self.complete_records()
        records.append(_record(37, "invalid-object"))
        failures = check_capability_matrix(_stdout(records))
        self.assertIn(
            "duplicate BPF capability probe (37, 'invalid-object')",
            failures,
        )

    def test_rejects_supported_probe_with_errno(self):
        records = self.complete_records()
        records[0]["errno"] = 1
        failures = check_capability_matrix(_stdout(records))
        self.assertIn("supported with errno=1", " ".join(failures))

    def test_rejects_unsupported_probe_with_wrong_errno(self):
        records = self.complete_records()
        records[1]["status"] = "unsupported"
        failures = check_capability_matrix(_stdout(records))
        self.assertIn("want ENOSYS", " ".join(failures))


if __name__ == "__main__":
    unittest.main()
