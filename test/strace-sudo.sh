#!/bin/bash

# Collect non-standard open file descriptors and their target paths
redirects=""
for fd_path in /proc/self/fd/*; do
  fd=$(basename "$fd_path")
  if [[ "$fd" =~ ^[0-9]+$ ]] && [ "$fd" -gt 2 ]; then
    # Exclude bash-internal or temporary fds
    if [ "$fd" -eq 255 ] || [ "$fd" -eq 10 ] || [ "$fd" -eq 11 ]; then
      continue
    fi
    target=$(readlink "$fd_path" 2>/dev/null)
    # Only redirect files, devices, etc. (must start with / and not be socket/pipe)
    if [[ "$target" == /* ]] && [[ "$target" != *:* ]] && [[ "$target" != /proc/* ]] && [[ "$target" != /sys/* ]]; then
      redirects="$redirects exec $fd<>$target;"
    fi
  fi
done

STRACE_BIN="$(dirname "$(dirname "$(readlink -f "$0")")")/strace-go"

if [ "$(id -u)" -eq 0 ]; then
  if [ -n "$redirects" ]; then
    eval "$redirects exec -a \"\$0\" \"\$STRACE_BIN\" \"\$@\""
  else
    exec -a "$0" "$STRACE_BIN" "$@"
  fi
else
  # Pass caller's environment explicitly since sudo -E is ignored
  ENV_VARS=()
  while IFS='=' read -r -d '' name value; do
    if [[ "$name" != "PATH" && "$name" != "TERM" && "$name" != "PWD" && "$name" != "SHLVL" && "$name" != "_" ]]; then
      ENV_VARS+=("$name=$value")
    fi
  done < <(env -0)

  if [ -n "$redirects" ]; then
    exec sudo env "${ENV_VARS[@]}" bash -c "umask 022; $redirects exec -a \"\$1\" \"\$2\" \"\${@:3}\"" -- "$0" "$STRACE_BIN" "$@"
  else
    exec sudo env "${ENV_VARS[@]}" bash -c "umask 022; exec -a \"\$1\" \"\$2\" \"\${@:3}\"" -- "$0" "$STRACE_BIN" "$@"
  fi
fi
