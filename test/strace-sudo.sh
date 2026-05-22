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
    eval "$redirects exec \"$STRACE_BIN\" \"\$@\""
  else
    exec "$STRACE_BIN" "$@"
  fi
else
  if [ -n "$redirects" ]; then
    # Use sudo bash -c to re-open fds before exec-ing the actual binary
    exec sudo bash -c "$redirects exec \"$STRACE_BIN\" \"\$@\"" -- "$@"
  fi
  exec sudo "$STRACE_BIN" "$@"
fi
