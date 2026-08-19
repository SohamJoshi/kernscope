#!/usr/bin/env bash
# Simple runner to execute benchmarks and collect results
set -euo pipefail

HERE=$(dirname "$0")
PYTHON=${PYTHON:-python3}

echo "Run syscall saturation (10 runs)"
${PYTHON} ${HERE}/syscall_saturation.py

echo "Run mixed CPU+syscall workload"
${PYTHON} ${HERE}/mixed_cpu_syscall.py

echo "PID-filtered workload: start the script in a separate shell and note the PID, then run kernscope -p <PID> to profile."
