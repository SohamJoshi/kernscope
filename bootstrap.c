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
#include "bootstrap.h"
#include "bootstrap.skel.h"

#define MAX_SYSCALLS 1024

static struct env {
    bool verbose;
} env;



const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF bootstrap demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
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

static void print_stats(struct bootstrap_bpf *skel){
	int map_fd;
	int ncpus;
	int err;

	uint32_t key;
	uint32_t next_key;
	struct syscall_stats *values;
	char *syscall_name;

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

	printf("\n%-12s       %-12s  %-15s %-15s\n",
		"SYSCALL_NAME",
		"COUNT",
		"AVG_US",
		"MAX_US");

	while (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        break;
    }

	key = next_key;
	while(1){
		unsigned long long total_count = 0;
		unsigned long long total_latency_ns = 0;
		unsigned long long max_latency_ns = 0;

		err = bpf_map_lookup_elem(map_fd, &key, values);
		if (err == 0){
			for (int cpu = 0; cpu < ncpus; cpu++) {
				total_count += values[cpu].count;
				total_latency_ns += values[cpu].total_latency_ns;
				if (values[cpu].max_latency_ns > max_latency_ns) {
					max_latency_ns = values[cpu].max_latency_ns;
				}
			}

			if (total_count > 0) {
				double avg_latency_us = total_latency_ns / total_count / 1000;
				double max_latency_us = max_latency_ns / 1000;
				syscall_name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, key);

				printf("%-20s %-12llu %-15.2f %-15.2f\n",
				syscall_name ? syscall_name : "unknown",
				total_count,
				avg_latency_us,
				max_latency_us);
			}

			if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
				bpf_map_delete_elem(map_fd, &key);
				break;
			}

			bpf_map_delete_elem(map_fd, &key);
			key = next_key;
		}
	}

	free(values);
	free(syscall_name);
}

int main(int argc, char **argv)
{
	struct bootstrap_bpf *skel;
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

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Process events */
	while (!exiting) {
		print_stats(skel);
		sleep(10);
	}

cleanup:
	/* Clean up */
	bootstrap_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
