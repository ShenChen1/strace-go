#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
  "$(dirname "$(dirname "$(readlink -f "$0")")")/strace-go" "$@"
else
  sudo "$(dirname "$(dirname "$(readlink -f "$0")")")/strace-go" "$@"
fi
