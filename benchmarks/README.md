Benchmark suite for KernScope V1

This folder contains microbenchmarks and a runner to measure KernScope overhead.

Benchmarks included:
- syscall_saturation.py: tight loop calling `os.stat()` to saturate syscalls (worst-case stress)
- pid_filtered.py: runs same workload inside a process and prints PID for filtered runs
- mixed_cpu_syscall.py: synthetic mixed workload combining CPU work and occasional syscalls
- run_benchmarks.sh: orchestrates multiple runs, collects timings and computes mean/median/stdev

Methodology
- Warm-up phase before measurements
- At least 10 runs per configuration where applicable
- Report mean, median, stddev, ops/sec
- Compare runs with KernScope OFF vs ON to compute elapsed-time overhead and throughput reduction
