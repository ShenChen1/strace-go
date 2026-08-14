#!/bin/bash
set -euo pipefail

if (( EUID != 0 )); then
  printf 'strace-go test wrapper requires root; run the suite with sudo -n\n' >&2
  exit 126
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
STRACE_BIN="$(dirname -- "$SCRIPT_DIR")/strace-go"
if [[ ! -x "$STRACE_BIN" ]]; then
  printf 'strace-go test binary is missing or not executable: %s\n' "$STRACE_BIN" >&2
  exit 127
fi

exec -a "$0" "$STRACE_BIN" "$@"
