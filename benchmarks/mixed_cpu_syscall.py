import time
import statistics
import math

# Mixed workload: do CPU work and occasional syscalls
RUNS = 10
ITER = 200_000

def cpu_work(n):
    s = 0.0
    for i in range(n):
        s += math.sin(i) * math.cos(i)
    return s

times = []

# warmup
for _ in range(1000):
    cpu_work(1000)

for run in range(RUNS):
    start = time.perf_counter()
    for i in range(ITER):
        if (i % 100) == 0:
            # occasional syscall
            open('/etc/hostname').close()
        cpu_work(10)
    elapsed = time.perf_counter() - start
    times.append(elapsed)
    print(f"run={run+1} elapsed={elapsed:.6f}s ops_per_sec={ITER / elapsed:.2f}")

print()
print(f"mean_elapsed={statistics.mean(times):.6f}s")
print(f"median_elapsed={statistics.median(times):.6f}s")
print(f"stdev={statistics.stdev(times):.6f}s")
