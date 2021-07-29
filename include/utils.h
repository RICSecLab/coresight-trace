/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_UTILS_H
#define PROC_TRACE_UTILS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/sysinfo.h>

struct addr_range {
  unsigned long start;
  unsigned long end;
  char path[PATH_MAX];
};

void dump_maps(FILE *stream, pid_t pid);
void dump_mem_range(FILE *stream, struct addr_range *range, int count);
int setup_mem_range(pid_t pid, struct addr_range *range, int count_max);
int export_decoder_args(int trace_id, const char *trace_path,
    const char *args_path, struct addr_range *range, int count);
int get_preferred_cpu(pid_t pid);
int set_cpu_affinity(int cpu, pid_t pid);
void read_pid_fd_path(pid_t pid, int fd, char *buf, size_t size);

#endif /* PROC_TRACE_UTILS_H */
