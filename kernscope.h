/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */

#ifndef __KERNSCOPE_H
#define __KERNSCOPE_H

#define TASK_COMM_LEN 16
#define NUM_LATENCY_BUCKETS 32

struct syscall_stats {
    unsigned long long count;
    unsigned long long total_latency_ns;
    unsigned long long max_latency_ns;
    unsigned long long latency_buckets[NUM_LATENCY_BUCKETS];
};

#endif /* __KERNSCOPE_H */
