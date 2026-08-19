// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernscope.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 target_pid = 0;

struct syscall_event_info {
    unsigned long long start_ns;
    int syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, struct syscall_event_info);
} syscall_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct syscall_stats);
} syscall_stats_map SEC(".maps");

static __always_inline bool should_trace(u64 pid_tgid)
{
    u32 tgid = (pid_tgid >> 32);
    if (target_pid == 0) {
        return true;
    }

    return tgid == target_pid;
}

static __always_inline __u32 latency_bucket(__u64 latency_ns){
    __u64 latency_us = latency_ns / 1000;
    __u32 bucket = 0;
    if (latency_us == 0){
        return 0;
    }

    while (latency_us > 1 && bucket < NUM_LATENCY_BUCKETS - 1){
        latency_us >>= 1;
        bucket++;
    }

    return bucket;
}


SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx){
    u64 pid_tgid;
    u32 tid;
    struct syscall_event_info info = {};

    pid_tgid = bpf_get_current_pid_tgid();

    if (!should_trace(pid_tgid)) {
        return 0;
    }

    tid = (u32)pid_tgid;

    info.start_ns = bpf_ktime_get_ns();
    info.syscall_id = (int)ctx->args[1];

    bpf_map_update_elem(&syscall_start, &tid, &info, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx){
    u64 pid_tgid;
    u32 tid;
    u32 pid;
    u32 syscall_id;
    u32 bucket;

    struct syscall_event_info *info;
    struct syscall_stats *stats;
    struct syscall_stats zero_stats = {};

    u64 latency_ns;

    pid_tgid = bpf_get_current_pid_tgid();
    if (!should_trace(pid_tgid)) {
        return 0;
    }

    tid = (u32)pid_tgid;
    pid = (pid_tgid >> 32);

    info = bpf_map_lookup_elem(&syscall_start, &tid);
    if(!info) {
        return 0;
    }

    latency_ns = bpf_ktime_get_ns() - info->start_ns;

    syscall_id = info->syscall_id;
    stats = bpf_map_lookup_elem(&syscall_stats_map, &syscall_id);

    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &syscall_id, &zero_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &syscall_id);
        if (!stats) {
            return 0;
        }
    }

    stats->count++;
    stats->total_latency_ns += latency_ns;
    if (latency_ns > stats->max_latency_ns) {
        stats->max_latency_ns = latency_ns;
    }

    bucket = latency_bucket(latency_ns);
    if (bucket < NUM_LATENCY_BUCKETS) {
        stats->latency_buckets[bucket]++;
    }

    bpf_map_delete_elem(&syscall_start, &tid);
    return 0;
}
