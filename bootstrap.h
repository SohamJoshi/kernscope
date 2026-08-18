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

#endif /* __BOOTSTRAP_H */