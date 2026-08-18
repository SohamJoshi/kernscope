// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx){
	u64 pid_tgid;
	u32 tid;
	struct syscall_event_info info = {};

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;

	info.start_ns = bpf_ktime_get_ns();
	info.syscall_id = (int)ctx->args[1];

	// store the start timestamp and syscall ID in the BPF hash map
	bpf_map_update_elem(&syscall_start, &tid, &info, BPF_ANY);

	return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx){
	u64 pid_tgid;
	u32 tid;
	u32 pid;
	struct syscall_event_info *info;
	struct event *e;
	u64 latency_ns;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	pid = (pid_tgid >> 32);

	info = bpf_map_lookup_elem(&syscall_start, &tid);
	if(!info) {
		return 0;
	}

	latency_ns = bpf_ktime_get_ns() - info->start_ns;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&syscall_start, &tid);
		return 0;
	}

	e->pid = pid;
	e->syscall_id = info->syscall_id;
	e->latency_ns = latency_ns;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&syscall_start, &tid);
	return 0;
}
