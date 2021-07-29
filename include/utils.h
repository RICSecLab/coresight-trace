/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_UTILS_H
#define PROC_TRACE_UTILS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/sysinfo.h>

#include <linux/elf.h>

#include <asm/ptrace.h>
#include <asm/unistd.h>

#define PAGE_SIZE 0x1000
#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))

#define RANGE_MAX (32)

struct addr_range {
  unsigned long start;
  unsigned long end;
  char path[PATH_MAX];
};

struct mmap_params {
  void *addr;
  size_t length;
  int prot;
  int flags;
  int fd;
  off_t offset;
};

void dump_maps(FILE *stream, pid_t pid);
void dump_mem_range(FILE *stream, struct addr_range *range, int count);
int setup_mem_range(pid_t pid, struct addr_range *range, int count_max);
int export_decoder_args(int trace_id, const char *trace_path,
    const char *args_path, struct addr_range *range, int count);
int get_preferred_cpu(pid_t pid);
int set_cpu_affinity(int cpu, pid_t pid);
void read_pid_fd_path(pid_t pid, int fd, char *buf, size_t size);
int get_mmap_params(pid_t pid, struct mmap_params *params);
bool is_syscall_exit_group(pid_t pid);
struct addr_range *append_mmap_exec_region(pid_t pid,
    struct mmap_params *params, struct addr_range *range, size_t range_count);

#endif /* PROC_TRACE_UTILS_H */
