// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <seccomp.h>
#include <unistd.h>
#include "kernscope.h"
#include "kernscope.skel.h"

#define MAX_SYSCALLS 4096

static struct env {
    bool verbose;
    int target_pid;
} env;

struct previous_syscall_stats {
    unsigned long long count;
    unsigned long long total_latency_ns;
    unsigned long long latency_buckets[NUM_LATENCY_BUCKETS];
};

static struct previous_syscall_stats prev_stats[MAX_SYSCALLS];

const char *argp_program_version = "kernscope 1.0";
const char *argp_program_bug_address = "<kernscope@local>";
const char argp_program_doc[] = "KernScope syscall latency profiler.\n"
                "\n"
                "USAGE: sudo ./kernscope [-p PID] [-v]\n";

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Trace only this PID" },
    { "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        env.target_pid = atoi(arg);
        break;
    case 'v':
        env.verbose = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static double histogram_percentile(unsigned long long *buckets, unsigned long long total, double percentile){
    if (total == 0){
        return 0.0;
    }

    unsigned long long threshold = (unsigned long long) (total * percentile);
    if (threshold == 0){
        threshold = 1;
    }

    unsigned long long cumulative = 0;
    for (int i = 0; i < NUM_LATENCY_BUCKETS; i++){
        cumulative += buckets[i];
        if (cumulative >= threshold){
            return (double) ((1ULL << (i+1)) - 1);
        }
    }

    return (double) (1ULL << (NUM_LATENCY_BUCKETS-1));
}

static void print_stats(struct kernscope_bpf *skel){
    int map_fd;
    int ncpus;
    int err;

    uint32_t key, next_key;
    struct syscall_stats *values;

    map_fd = bpf_map__fd(skel->maps.syscall_stats_map);
    ncpus = libbpf_num_possible_cpus();
    if (ncpus < 0) {
        fprintf(stderr, "Failed to get number of possible CPUs: %d\n", ncpus);
        return;
    }

    values = calloc(ncpus, sizeof(*values));
    if (!values) {
        fprintf(stderr, "Failed to allocate memory for values\n");
        return;
    }

    printf("%-18s     %-10s %-12s %-12s %-12s %-12s\n",
        "SYSCALL",
        "COUNT",
        "AVG_US",
        "P50_US",
        "P95_US",
        "P99_US");

    /* get first key */
    if (bpf_map_get_next_key(map_fd, NULL, &key) != 0) {
        /* empty map */
        free(values);
        printf("(no syscall data)\n");
        return;
    }

    for (;;) {
        unsigned long long total_count = 0;
        unsigned long long total_latency_ns = 0;
        unsigned long long max_latency_ns = 0;
        unsigned long long total_buckets[NUM_LATENCY_BUCKETS] = {0};
        unsigned long long interval_buckets[NUM_LATENCY_BUCKETS] = {0};

        err = bpf_map_lookup_elem(map_fd, &key, values);
        if (err == 0){
            for (int cpu = 0; cpu < ncpus; cpu++) {
                total_count += values[cpu].count;
                total_latency_ns += values[cpu].total_latency_ns;
                if (values[cpu].max_latency_ns > max_latency_ns) {
                    max_latency_ns = values[cpu].max_latency_ns;
                }

                for (int bucket = 0; bucket < NUM_LATENCY_BUCKETS; bucket++){
                    total_buckets[bucket] += values[cpu].latency_buckets[bucket];
                }
            }

            unsigned long long prev_count = 0;
            unsigned long long prev_total_latency = 0;

            if (key < MAX_SYSCALLS) {
                unsigned long long interval_count = total_count - prev_stats[key].count;
                unsigned long long interval_latency_ns = total_latency_ns - prev_stats[key].total_latency_ns;
                for (int bucket = 0; bucket < NUM_LATENCY_BUCKETS; bucket++){
                    interval_buckets[bucket] = total_buckets[bucket] - prev_stats[key].latency_buckets[bucket];
                }

                for (int bucket = 0; bucket < NUM_LATENCY_BUCKETS; bucket++){
                    prev_stats[key].latency_buckets[bucket] = total_buckets[bucket];
                }
                prev_stats[key].count = total_count;
                prev_stats[key].total_latency_ns = total_latency_ns;

                prev_count = prev_stats[key].count;
                prev_total_latency = prev_stats[key].total_latency_ns;

                if (interval_count > 0) {
                    double avg_latency_us = (double)interval_latency_ns / (double)interval_count / 1000.0;
                    char *syscall_name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, key);
                    double p50 = histogram_percentile(interval_buckets, interval_count, 0.5);
                    double p90 = histogram_percentile(interval_buckets, interval_count, 0.9);
                    double p99 = histogram_percentile(interval_buckets, interval_count, 0.99);

                    printf("%-18s %-10llu %-12.2f %-12.2f %-12.2f %-12.2f\n",
                        syscall_name ? syscall_name : "unknown",
                        interval_count,
                        avg_latency_us,
                        p50,
                        p90,
                        p99);

                    free(syscall_name);
                }
            } else {
                /* syscall id out of tracked range; print cumulative stats */
                if (total_count > 0) {
                    double avg_latency_us = (double)total_latency_ns / (double)total_count / 1000.0;
                    char *syscall_name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, key);
                    double p50 = histogram_percentile(total_buckets, total_count, 0.5);
                    double p90 = histogram_percentile(total_buckets, total_count, 0.9);
                    double p99 = histogram_percentile(total_buckets, total_count, 0.99);

                    printf("%-18s %-10llu %-12.2f %-12.2f %-12.2f %-12.2f\n",
                        syscall_name ? syscall_name : "unknown",
                        total_count,
                        avg_latency_us,
                        p50,
                        p90,
                        p99);

                    free(syscall_name);
                }
            }

            if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
                break;
            }

            key = next_key;
        } else {
            /* key disappeared, try to get next */
            if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
                break;
            }
            key = next_key;
        }
    }

    free(values);
}

int main(int argc, char **argv)
{
    struct kernscope_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (env.target_pid == 0) {
        printf("KernScope: tracing system-wide syscalls\n");
    } else {
        printf("KernScope: tracing PID %d only\n", env.target_pid);
    }

    /* Load and verify BPF application */
    skel = kernscope_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    /* Load & verify BPF programs */
    skel->rodata->target_pid = env.target_pid;
    err = kernscope_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = kernscope_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Process events */
    while (!exiting) {
        sleep(10);

        if (exiting)
            break;

        printf("\n--- Last 10 seconds ---\n");
        print_stats(skel);
    }

cleanup:
    /* Clean up */
    kernscope_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
