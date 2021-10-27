/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef CS_TRACE_UTILS_H
#define CS_TRACE_UTILS_H

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

#include <sys/types.h>

#include <linux/limits.h>

#include "libcsdec.h"

#define PAGE_SIZE 0x1000
#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))

#define RANGE_MAX (1)

struct map_info {
  unsigned long start;
  unsigned long end;
  off_t offset;
  void *buf;
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

void dump_buf(void *buf, size_t buf_size, const char *buf_path);
void dump_maps(FILE *stream, pid_t pid);
void dump_map_info(FILE *stream, struct map_info *map_info, int count);
int setup_map_info(pid_t pid, struct map_info *map_info, int info_count_max);
int export_decoder_args(int trace_id, const char *trace_path,
    const char *args_path, struct map_info *map_info, int count);
int get_preferred_cpu(pid_t pid);
int find_free_cpu(void);
int set_cpu_affinity(int cpu, pid_t pid);
int set_pthread_cpu_affinity(int cpu, pthread_t thread);
void read_pid_fd_path(pid_t pid, int fd, char *buf, size_t size);
int get_mmap_params(pid_t pid, struct mmap_params *params);
bool is_syscall_exit_group(pid_t pid);
int get_udmabuf_info(int udmabuf_num, unsigned long *phys_addr, size_t *size);

#endif /* CS_TRACE_UTILS_H */
