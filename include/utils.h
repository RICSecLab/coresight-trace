/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_UTILS_H
#define PROC_TRACE_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

struct addr_range {
  unsigned long start;
  unsigned long end;
  char path[PATH_MAX];
};

void dump_mem_range(struct addr_range *range, int count);
int get_mem_range(pid_t pid, struct addr_range *range, int count_max);
int export_decoder_args(const char *hardware, int cpu,
        const char *trace_path, const char *args_path,
            struct addr_range *range, int count);

#endif /* PROC_TRACE_UTILS_H */
