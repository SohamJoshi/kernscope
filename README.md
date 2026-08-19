# KernScope

KernScope is a small, low-overhead syscall latency profiler for Linux built with eBPF, libbpf and CO-RE.

**Highlights**
- System-wide or per-PID syscall tracing
- Per-CPU aggregation in BPF maps (no per-event streaming)
- Interval reporting (default 10s) with COUNT, AVG_US, approximate P50/P95/P99
- Log2 histogram-based percentile approximation

Acknowledgment: KernScope was bootstrapped from the libbpf-bootstrap examples; original SPDX/license notices are preserved where applicable.

**Motivation**
KernScope provides a lightweight way to measure syscall latencies across the system or for a single PID. It aggregates per-CPU statistics in BPF maps and emits periodic summaries to userspace, keeping the eBPF hot path minimal.

**Architecture (ASCII diagram)**

User-space (kernscope) <-- libbpf skeleton ---> BPF programs
	   ^                                       ^
	   |                                       |
   periodic pull                        raw_tracepoint enter/exit
	   |                                       |
   compute deltas, percentiles         per-CPU hashmap aggregation

Kernel-side flow
- raw_tracepoint/sys_enter: record start timestamp per thread in a hash map
- raw_tracepoint/sys_exit: compute latency, update per-CPU hash map of syscall statistics

Per-CPU aggregation rationale
- Aggregating per-CPU in BPF reduces contention and minimizes map update overhead.
- Userspace reads all per-CPU values and sums them to produce interval deltas.

Histogram / percentile approximation
- Uses log2 buckets of latency in microseconds. Each bucket's upper bound is used as the percentile value.
- This provides a cheap P50/P95/P99 approximation without streaming all events.

Build dependencies
- clang, llvm (for BPF compilation)
- bpftool (for skeleton generation)
- libbpf (or use vendored libbpf-bootstrap)
- libseccomp (for syscall name resolution)

vmlinux.h
You need a matching `vmlinux.h` for your kernel. Generate with:

1. Install pahole and bpftool
2. `sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`

Build
1. `make clean && make`
2. The `kernscope` binary will be produced.

Run examples
- System-wide: `sudo ./kernscope`
- PID filtered: `sudo ./kernscope -p 12345`
- Verbose libbpf: `sudo ./kernscope -v`

Sample output (intervals of ~10s):

SYSCALL              COUNT      AVG_US      P50_US      P95_US      P99_US
open                 1234       12.34       8           64          255

Benchmarks
- See `benchmarks/` for reproducible microbenchmarks and runner scripts.

Benchmark methodology (what I ran)
- Warm-up before measurements as implemented in each script
- `syscall_saturation.py`: tight `os.stat()` loop (worst-case stress), 10 runs
- `mixed_cpu_syscall.py`: mixed CPU + occasional syscall, 10 runs
- `pid_filtered.py`: PID-filtered test (5 runs)
- Each benchmark was run twice: with KernScope OFF and with KernScope ON (system-wide or PID-filtered as appropriate).  Mean, median, stddev and ops/sec were recorded.

Measured V1 results (this environment)

1) Syscall saturation (worst-case stress)
- OFF (no kernscope): mean elapsed = 1.238510 s, mean throughput = 1,614,843 ops/sec
- ON (kernscope system-wide): mean elapsed = 1.583109 s, mean throughput = 1,263,337 ops/sec
- Elapsed-time overhead: +27.8%  (measured)
- Throughput reduction: -21.8%  (measured)
- Sustained instrumented ops/sec (ON): ~1.26M ops/sec

Note: this is a stressful worst-case syscall-saturation workload; higher overheads are expected here. The workload is intentionally synthetic and intended to exercise the profiler hot path.

2) Mixed CPU + syscall workload (representative mixed work)
- OFF: mean elapsed = 0.127932 s (≈1.56M ops/sec)
- ON: mean elapsed = 0.131267 s (≈1.52M ops/sec)
- Elapsed-time overhead: +2.6%  (measured)
- Throughput reduction: ~2.6%  (measured)

3) PID-filtered syscall workload
- OFF: avg ops/sec = 1,540,789
- ON (kernscope -p <PID>): avg ops/sec = 1,558,683
- Observed change: +1.1% (measurement noise; no detectable overhead in this run)

## V1 Benchmark Results

| Workload | Mode | Mean Elapsed | Throughput | Overhead |
|---|---|---:|---:|---:|
| Syscall saturation | OFF | 1.238510 s | 1,614,843 ops/s | — |
| Syscall saturation | ON, system-wide | 1.583109 s | 1,263,337 ops/s | +27.8% |
| Mixed CPU + syscall | OFF | 0.127932 s | 1,563,997 ops/s | — |
| Mixed CPU + syscall | ON | 0.131267 s | 1,523,537 ops/s | +2.6% |
| PID-filtered syscall | OFF | — | 1,540,789 ops/s | — |
| PID-filtered syscall | ON, `-p <PID>` | — | 1,558,683 ops/s | ~0% detectable* |

\*The PID-filtered result showed a +1.1% throughput difference, which is within measurement noise and should not be interpreted as a speedup.

Interpretation
- The worst-case syscall-saturation workload shows significant overhead when instrumented system-wide — this is expected for adversarial saturation tests.
- For a mixed CPU+syscall representative workload, measured overhead is modest (~2–3%).
- PID-filtering can materially reduce overhead; in this small test the measured difference is within noise and did not show significant overhead.

Reproducibility
- See `benchmarks/run_benchmarks.sh` and `benchmarks/*` scripts. To reproduce:

```bash
make clean && make
# baseline
python3 benchmarks/syscall_saturation.py > off.txt
# enable kernscope in another terminal: sudo ./kernscope
python3 benchmarks/syscall_saturation.py > on.txt
```

Limitations
- V1 focuses on syscall latency only. Scheduler, I/O, memory tracing are planned for future releases.
- Percentiles are approximations (log2 histogram); not exact.
