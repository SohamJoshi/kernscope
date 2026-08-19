import os
import time
import statistics

N = 2_000_000
RUNS = 10

# warmup
for _ in range(200_000):
    os.stat("/etc/hostname")

times = []

for run in range(RUNS):
    start = time.perf_counter()

    for _ in range(N):
        os.stat("/etc/hostname")

    elapsed = time.perf_counter() - start
    times.append(elapsed)

    print(
        f"run={run+1} elapsed={elapsed:.6f}s ops_per_sec={N / elapsed:.2f}"
    )

print()
print(f"mean_elapsed={statistics.mean(times):.6f}s")
print(f"median_elapsed={statistics.median(times):.6f}s")
print(f"stdev={statistics.stdev(times):.6f}s")
print(f"mean_ops_per_sec={N / statistics.mean(times):.2f}")
