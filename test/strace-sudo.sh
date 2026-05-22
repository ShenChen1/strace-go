#!/bin/bash
for arg in "$@"; do
  if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
    exec strace "$@"
  fi
done

if [ "$(id -u)" -eq 0 ]; then
  "$(dirname "$(dirname "$(readlink -f "$0")")")/strace-go" "$@"
else
  sudo "$(dirname "$(dirname "$(readlink -f "$0")")")/strace-go" "$@"
fi
