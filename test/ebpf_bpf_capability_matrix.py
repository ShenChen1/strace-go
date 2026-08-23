import errno
import json


CAPABILITY_PROBES = {
    (32, "valid"): "BPF_ENABLE_STATS",
    (33, "invalid-object"): "BPF_ITER_CREATE",
    (36, "valid"): "BPF_TOKEN_CREATE",
    (36, "invalid-object"): "BPF_TOKEN_CREATE",
    (37, "invalid-object"): "BPF_PROG_STREAM_READ_BY_FD",
    (38, "invalid-object"): "BPF_PROG_ASSOC_STRUCT_OPS",
}
VALID_STATUSES = frozenset(
    ("supported", "unsupported", "environment_blocked", "invalid_input")
)
VALID_PROBES = frozenset(("valid", "invalid-object"))


def parse_capability_records(stdout):
    records = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("type") == "bpf_capability":
            records.append(record)
    return records


def _is_integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_record(key, record, failures):
    command, probe = key
    expected_name = CAPABILITY_PROBES[key]
    if record.get("name") != expected_name:
        failures.append(
            f"BPF capability {command}/{probe} name={record.get('name')!r}, "
            f"want {expected_name!r}"
        )
    status = record.get("status")
    if status not in VALID_STATUSES:
        failures.append(f"BPF capability {command}/{probe} has invalid status {status!r}")
    error = record.get("errno")
    if not _is_integer(error) or error < 0:
        failures.append(f"BPF capability {command}/{probe} has invalid errno {error!r}")
    if status == "supported" and error != 0:
        failures.append(f"BPF capability {command}/{probe} supported with errno={error}")
    if status != "supported" and _is_integer(error) and error == 0:
        failures.append(f"BPF capability {command}/{probe} failed with errno=0")
    if probe not in VALID_PROBES:
        failures.append(f"BPF capability {command} has invalid probe {probe!r}")
    if status == "unsupported" and error != errno.ENOSYS:
        failures.append(
            f"BPF capability {command}/{probe} unsupported with errno={error}, "
            f"want ENOSYS={errno.ENOSYS}"
        )


def check_capability_matrix(stdout):
    failures = []
    records = parse_capability_records(stdout)
    observed = {}
    for record in records:
        key = (record.get("command"), record.get("probe"))
        if key in observed:
            failures.append(f"duplicate BPF capability probe {key!r}")
            continue
        observed[key] = record
    if set(observed) != set(CAPABILITY_PROBES):
        missing = sorted(set(CAPABILITY_PROBES) - set(observed))
        unexpected = sorted(set(observed) - set(CAPABILITY_PROBES))
        if missing:
            failures.append(f"missing BPF capability probes: {missing}")
        if unexpected:
            failures.append(f"unexpected BPF capability probes: {unexpected}")
    for key, record in observed.items():
        if key in CAPABILITY_PROBES:
            _check_record(key, record, failures)
    return failures
