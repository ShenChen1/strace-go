#!/bin/bash
echo '123456' | sudo -S /opt/strace-go/strace-go "$@"
