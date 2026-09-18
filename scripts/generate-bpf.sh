#!/usr/bin/env bash
set -euo pipefail
if (( $# > 1 )); then
  echo 'usage: generate-bpf.sh [amd64|arm64]' >&2
  exit 2
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
requested="${1:-${ARCH:-}}"
environment_arch="${GOARCH:-}"
exec env GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" \
  go run ./cmd/generate-bpf -arch "$requested" -goarch "$environment_arch" -cc "${BPF_CLANG:-clang}"
