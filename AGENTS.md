# Repository Guidelines

## Project Structure & Module Organization

`cmd/strace-go/` contains the CLI entry point, eBPF loader, session lifecycle, and event loop. Reusable code lives under `pkg/`: argument parsing in `cli`, event decoding in `event`, output rendering in `format` and `handler`, generated syscall metadata in `meta`, process-memory access in `procmem`, and stack resolution in `stacktrace`. Kernel-side eBPF code is in `bpf/`. Generators live in `cmd/generate-syscalls/` and `cmd/generate-xlats/`.

Unit tests sit beside Go packages as `*_test.go`. `test/run_tests.py` drives compatibility tests from the `strace-upstream/` submodule through `test/strace-sudo.sh`.

## Build, Test, and Development Commands

- `go test ./...` runs the fast Go unit suite.
- `go build -o strace-go ./cmd/strace-go` builds from existing generated artifacts.
- `./build.sh` removes and regenerates syscall tables, xlat tables, and BPF objects before building. It requires `sudo`, `clang`, kernel tracing data, and a Linux host with eBPF/BTF support.
- `python3 test/run_tests.py --suite small --skip-build` runs smoke compatibility tests after the upstream test binaries exist.
- `python3 test/run_tests.py --suite more --filter dup2.gen.test --skip-build` isolates one regression. Use `--parallel N` cautiously because tests and tracing require elevated privileges.

Initialize dependencies with `git submodule update --init --recursive`.

## Coding Style & Naming Conventions

Use standard Go formatting: tabs, `gofmt`, idiomatic package names, exported identifiers in `CamelCase`, and unexported identifiers in `camelCase`. Run `gofmt -w` on changed Go files. Keep syscall handlers grouped by domain under `pkg/handler/`, and name tests `TestFeature` with table cases where practical. Treat `pkg/meta/syscall_table.go`, `pkg/meta/xlat_auto.go`, `bpf/syscall_capture.h`, and `cmd/strace-go/bpf_*` as generated outputs; edit their generator inputs instead.

## Testing Guidelines

Every formatting or decoding change should include a focused unit test or an upstream regression test. Compatibility is exact: stdout/stderr text, escaping, flags, return values, and ordering must match classic `strace`. Start with a filtered test, then run the `small` suite and relevant `more` tests.

## Commit & Pull Request Guidelines

History primarily uses Conventional Commit prefixes such as `feat:`, `fix:`, `test:`, and scoped forms like `fix(decoder):`. Keep commits focused and describe the observable behavior. Pull requests should explain the syscall or CLI behavior changed, list exact test commands and results, note generated-file updates, and link the relevant issue. Include output diffs for compatibility fixes; screenshots are generally unnecessary.

## Privilege & Safety Notes

Tracing and generation may run as root. Review commands and target PIDs carefully, and never commit local binaries, logs, scratch programs, or captured trace output.
