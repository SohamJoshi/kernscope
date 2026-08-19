/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int syscall_id;
    unsigned long long latency_ns;
    char comm[TASK_COMM_LEN];
};

struct syscall_stats {
    unsigned long long count;
    unsigned long long total_latency_ns;
    unsigned long long max_latency_ns;
};

#endif /* __BOOTSTRAP_H */