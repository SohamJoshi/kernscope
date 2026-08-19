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

Limitations
- V1 focuses on syscall latency only. Scheduler, I/O, memory tracing are planned for future releases.
- Percentiles are approximations (log2 histogram); not exact.

Roadmap
- Scheduler / runqueue latency
- Page faults / memory events
- Block I/O tracing
- CPU profiling and further hot-path optimizations

