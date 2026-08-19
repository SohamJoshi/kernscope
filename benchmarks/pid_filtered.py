import os
import time
import statistics

N = 200_000
RUNS = 5

print(f"PID={os.getpid()}")
print("Starting benchmark in 5 seconds...")
time.sleep(5)

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

avg = statistics.mean(times)

print()
print(f"avg_elapsed={avg:.6f}s")
print(f"avg_ops_per_sec={N / avg:.2f}")
