/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <sched.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <linux/elf.h>
#include <linux/limits.h>

#include <asm/ptrace.h>
#include <asm/unistd.h>

#define MAX_LINE 8192
#define MAX_CPUS 4096

void dump_buf(void *buf, size_t buf_size, const char *buf_path)
{
  FILE *fp;
  size_t fwrite_size;

  fp = fopen(buf_path, "wb");
  if (fp == NULL) {
    perror("fopen");
    return;
  }

  if ((fwrite_size = fwrite(buf, 1, buf_size, fp)) != buf_size) {
    fprintf(stderr, "fwrite() failed: %ld (expected: %ld)\n", fwrite_size,
            buf_size);
  }

  fclose(fp);
}

void dump_map_info(FILE *stream, struct map_info *map_info, int count)
{
  int i;

  for (i = 0; i < count; i++) {
    fprintf(stream, "[0x%lx-0x%lx]@0x%lx: %s\n", map_info[i].start,
            map_info[i].end, map_info[i].offset, map_info[i].path);
  }
}

void dump_maps(FILE *stream, pid_t pid)
{
  FILE *fp;
  char maps_path[PATH_MAX];
  char *line;
  size_t n;

  memset(maps_path, 0, sizeof(maps_path));
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  fp = fopen(maps_path, "r");
  if (fp == NULL) {
    perror("fopen");
    return;
  }

  line = NULL;
  n = 0;
  while (getline(&line, &n, fp) != -1) {
    fprintf(stream, "%s", line);
  }

  if (line != NULL) {
    free(line);
  }

  fclose(fp);

  return;
}

int setup_map_info(pid_t pid, struct map_info **map_info, int info_count_max)
{
  FILE *fp;
  char maps_path[PATH_MAX];
  char *line;
  size_t n;
  ssize_t readn;
  int count;
  char *path;
  int fd;
  size_t buf_size;
  void *buf;
  int i;

  unsigned long start;
  unsigned long end;
  off_t offset;
  char x;
  char c;

  memset(maps_path, 0, sizeof(maps_path));
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  fp = fopen(maps_path, "r");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  line = NULL;
  n = 0;
  count = 0;
  while ((readn = getline(&line, &n, fp)) != -1) {
    if (readn > 0 && line[readn - 1] == '\n') {
      line[readn - 1] = '\0';
      readn--;
    }
    sscanf(line, "%lx-%lx %c%c%c%c %lx", &start, &end, &c, &c, &x, &c, &offset);
    if (x != 'x') {
      /* Not an executable region */
      continue;
    }
    while (count >= info_count_max) {
      info_count_max *= 2;
      assert (info_count_max > 0);
      *map_info = realloc(*map_info, sizeof(struct map_info)*info_count_max);
    }
    /* Search absolute path */
    path = strchr(line, '/');
    if (!path) {
      continue;
    }
    (*map_info)[count].start = start;
    (*map_info)[count].end = end;
    (*map_info)[count].offset = offset;
    (*map_info)[count].buf = NULL;
    strncpy((*map_info)[count].path, path, PATH_MAX - 1);
    count++;
  }

  if (line != NULL) {
    free(line);
  }
  fclose(fp);

  for (i = 0; i < count; i++) {
    if ((fd = open((*map_info)[i].path, O_RDONLY | O_SYNC)) < -1) {
      perror("open");
      return -1;
    }
    buf_size = (size_t)ALIGN_UP((*map_info)[i].end - (*map_info)[i].start, PAGE_SIZE);
    buf = mmap(NULL, buf_size, PROT_READ, MAP_PRIVATE, fd, (*map_info)[i].offset);
    if (!buf) {
      perror("mmap");
      close(fd);
      return -1;
    }
    (*map_info)[i].buf = buf;
    close(fd);
  }

  return count;
}

int export_decoder_args(int trace_id, const char *trace_path,
                        const char *args_path, struct map_info *map_info,
                        int count)
{
  FILE *fp;
  int i;
  int ret;

  if (trace_id < 0 || !trace_path || !args_path || !map_info) {
    return -1;
  }

  fp = fopen(args_path, "w");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  if ((ret = fprintf(fp, " %s", trace_path)) < 0) {
    goto exit;
  }

  if ((ret = fprintf(fp, " 0x%x", trace_id)) < 0) {
    goto exit;
  }

  if ((ret = fprintf(fp, " %d", count)) < 0) {
    goto exit;
  }

  for (i = 0; i < count; i++) {
    ret = fprintf(fp, " %s 0x%lx 0x%lx", map_info[i].path, map_info[i].start,
                  map_info[i].end);
    if (ret < 0) {
      goto exit;
    }
  }

  ret = 0;

exit:

  fclose(fp);

  if (ret < 0) {
    fprintf(stderr, "Failed to write decoder arguments\n");
  }

  return ret;
}

static cpu_set_t *alloc_cpu_set(cpu_set_t **cpu_set, size_t *setsize)
{
  int nprocs;

  if (!cpu_set || !setsize) {
    return NULL;
  }

  nprocs = get_nprocs();
  *cpu_set = CPU_ALLOC(nprocs);
  if (!(*cpu_set)) {
    perror("CPU_ALLOC");
    return NULL;
  }

  *setsize = CPU_ALLOC_SIZE(nprocs);
  CPU_ZERO_S(*setsize, *cpu_set);

  return *cpu_set;
}

/* Set given cpu_set bits represent related CPU cores with cpu */
/* NOTE: This is not supported by the Jetson family. */
static int set_core_cpus(int cpu, cpu_set_t *cpu_set, size_t setsize)
{
  int ret;
  FILE *fp;
  char core_cpus_list_path[PATH_MAX];
  char *token;
  size_t n;
  ssize_t readn;
  long int core_cpu;

  ret = -1;
  fp = NULL;
  token = NULL;

  if (!cpu_set || !setsize) {
    goto exit;
  }

  memset(core_cpus_list_path, 0, sizeof(core_cpus_list_path));
  snprintf(core_cpus_list_path, sizeof(core_cpus_list_path),
           "/sys/devices/system/cpu/cpu%d/topology/core_cpus_list", cpu);

  fp = fopen(core_cpus_list_path, "r");
  if (!fp) {
    perror("fopen");
    goto exit;
  }

  token = NULL;
  n = 0;
  while ((readn = getdelim(&token, &n, ',', fp)) != -1) {
    if (readn > 1 && token[readn - 1] != '\0') {
      token[readn - 1] = '\0';
    }
    core_cpu = strtol(token, NULL, 0);
    if (core_cpu == LONG_MIN || core_cpu == LONG_MAX) {
      perror("strtol");
      goto exit;
    }
    CPU_SET_S((int)core_cpu, setsize, cpu_set);
  }

  ret = 0;

exit:
  if (token) {
    free(token);
  }

  if (fp) {
    fclose(fp);
  }

  return ret;
}

/* Find CPU core in the same group of CPU binded to the PID process. */
/* NOTE: This is not supported by the Jetson family. */
int get_preferred_cpu(pid_t pid)
{
  int ret;
  int i;
  cpu_set_t *cpu_set;
  cpu_set_t *core_cpu_set;
  size_t setsize;
  size_t core_setsize;
  int nprocs;
  int preferred_cpu;

  ret = -1;
  cpu_set = NULL;
  core_cpu_set = NULL;
  preferred_cpu = -1;

  if (!alloc_cpu_set(&cpu_set, &setsize)) {
    goto exit;
  }
  if (sched_getaffinity(pid, setsize, cpu_set) < 0) {
    perror("sched_getaffinity");
    goto exit;
  }

  nprocs = get_nprocs();
  if (!alloc_cpu_set(&core_cpu_set, &core_setsize)) {
    goto exit;
  }
  for (i = 0; i < nprocs; i++) {
    if (CPU_ISSET_S(i, setsize, cpu_set)) {
      if (set_core_cpus(i, core_cpu_set, core_setsize) < 0) {
        goto exit;
      }
    }
  }

  for (i = 0; i < nprocs; i++) {
    if (!CPU_ISSET_S(i, core_setsize, core_cpu_set)) {
      preferred_cpu = i;
      break;
    }
  }

  ret = preferred_cpu;

exit:
  if (core_cpu_set) {
    CPU_FREE(core_cpu_set);
  }

  if (cpu_set) {
    CPU_FREE(cpu_set);
  }

  return ret;
}

/* ref:
 * https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-fuzz-init.c */
/* Finds a free CPU core by reading procfs. */
int find_free_cpu(void)
{
  int nprocs;
  DIR *proc_dir;
  struct dirent *proc_entry;
  char task_path[PATH_MAX];
  DIR *task_dir;
  struct dirent *task_entry;
  char status_path[PATH_MAX];
  FILE *status_fp;
  char tmp[MAX_LINE];
  bool has_vmsize;
  unsigned int hval;
  bool cpu_used[MAX_CPUS];
  int i;

  nprocs = sysconf(_SC_NPROCESSORS_ONLN);
  if (nprocs < 2) {
    return 0;
  }

  memset(cpu_used, (int)false, sizeof(cpu_used));

  if (!(proc_dir = opendir("/proc"))) {
    perror("opendir");
    return -1;
  }

  while ((proc_entry = readdir(proc_dir))) {
    if (!isdigit(proc_entry->d_name[0])) {
      continue;
    }

    memset(task_path, 0, PATH_MAX);
    snprintf(task_path, PATH_MAX, "/proc/%s/task", proc_entry->d_name);
    if (!(task_dir = opendir((const char *)task_path))) {
      perror("opendir");
      continue;
    }

    while ((task_entry = readdir(task_dir))) {
      if (!isdigit(task_entry->d_name[0])) {
        continue;
      }

      memset(status_path, 0, PATH_MAX);
      snprintf(status_path, PATH_MAX, "/proc/%s/task/%s/status",
               proc_entry->d_name, task_entry->d_name);
      if (!(status_fp = fopen(status_path, "r"))) {
        continue;
      }

      has_vmsize = false;
      while (fgets(tmp, MAX_LINE, status_fp)) {
        hval = 0;
        if (!strncmp(tmp, "VmSize:\t", 8)) {
          has_vmsize = true;
        }
        if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
            !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
            hval < MAX_CPUS && has_vmsize) {
          cpu_used[hval] = true;
          break;
        }
      }
      fclose(status_fp);
    }
    closedir(task_dir);
  }
  closedir(proc_dir);

  for (i = 0; i < nprocs; i++) {
    if (!cpu_used[i]) {
      /* Free CPU found. */
      return i;
    }
  }

  /* Free CPU not found. */
  return -1;
}

int set_cpu_affinity(int cpu, pid_t pid)
{
  int ret;
  cpu_set_t *cpu_set;
  size_t setsize;

  ret = -1;

  if (!alloc_cpu_set(&cpu_set, &setsize)) {
    goto exit;
  }
  CPU_SET_S(cpu, setsize, cpu_set);
  if (sched_setaffinity(pid, setsize, cpu_set) < 0) {
    perror("sched_setaffinity");
    goto exit;
  }

  ret = 0;

exit:
  if (cpu_set) {
    CPU_FREE(cpu_set);
  }

  return ret;
}

int set_pthread_cpu_affinity(int cpu, pthread_t thread)
{
  int ret;
  cpu_set_t *cpu_set;
  size_t setsize;

  ret = -1;

  if (!alloc_cpu_set(&cpu_set, &setsize)) {
    goto exit;
  }
  CPU_SET_S(cpu, setsize, cpu_set);
  if (pthread_setaffinity_np(thread, setsize, cpu_set) < 0) {
    perror("pthread_setaffinity_np");
    goto exit;
  }

  ret = 0;

exit:
  if (cpu_set) {
    CPU_FREE(cpu_set);
  }

  return ret;
}

void read_pid_fd_path(pid_t pid, int fd, char *buf, size_t size)
{
  char fd_path[PATH_MAX];

  memset(fd_path, 0, sizeof(fd_path));
  snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
  if (readlink(fd_path, buf, size) < 0) {
    perror("readlink");
  }
}

static long get_pid_syscall_regs(pid_t pid, struct user_pt_regs *regs)
{
  struct iovec iov;
  long syscall;

  if (!regs) {
    return -1;
  }

  iov.iov_base = regs;
  iov.iov_len = sizeof(regs);
  if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
    return -1;
  }

  syscall = regs->regs[8];

  return syscall;
}

int get_mmap_params(pid_t pid, struct mmap_params *params)
{
  struct user_pt_regs regs;

  if (!params) {
    return -1;
  }

  if (get_pid_syscall_regs(pid, &regs) != __NR_mmap) {
    return -1;
  }

  params->addr = (void *)regs.regs[0];
  params->length = (size_t)regs.regs[1];
  params->prot = (int)regs.regs[2];
  params->flags = (int)regs.regs[3];
  params->fd = (int)regs.regs[4];
  params->offset = (off_t)regs.regs[5];

  return 0;
}

bool is_syscall_exit_group(pid_t pid)
{
  struct user_pt_regs regs;

  if (get_pid_syscall_regs(pid, &regs) == __NR_exit_group) {
    return true;
  }

  return false;
}

int get_udmabuf_info(int udmabuf_num, unsigned long *phys_addr, size_t *size)
{
  const char *udmabuf_root = "/sys/class/u-dma-buf";

  int ret;
  char udmabuf_path[PATH_MAX];
  char tmp_path[PATH_MAX];
  char attr[1024];
  int fd;
  struct stat sb;

  ret = -1;

  memset(udmabuf_path, '\0', sizeof(udmabuf_path));
  snprintf(udmabuf_path, sizeof(udmabuf_path), "%s/udmabuf%d", udmabuf_root,
           udmabuf_num);
  if (stat(udmabuf_path, &sb) != 0 || (!S_ISDIR(sb.st_mode))) {
    fprintf(stderr, "u-dma-buf device 'udmabuf%d' not found\n", udmabuf_num);
    return ret;
  }

  memset(tmp_path, '\0', sizeof(tmp_path));
  snprintf(tmp_path, sizeof(tmp_path), "%s/udmabuf%d/phys_addr", udmabuf_root,
           udmabuf_num);
  if ((fd = open(tmp_path, O_RDONLY)) < 0) {
    perror("open");
    return -1;
  }

  memset(attr, 0, sizeof(attr));
  if (read(fd, attr, sizeof(attr)) < 0) {
    perror("read");
    close(fd);
    return -1;
  }
  sscanf(attr, "%lx", phys_addr);
  close(fd);

  memset(tmp_path, '\0', sizeof(tmp_path));
  snprintf(tmp_path, sizeof(tmp_path), "%s/udmabuf%d/size", udmabuf_root,
           udmabuf_num);
  if ((fd = open(tmp_path, O_RDONLY)) < 0) {
    perror("open");
    return -1;
  }

  memset(attr, 0, sizeof(attr));
  if (read(fd, attr, sizeof(attr)) < 0) {
    perror("read");
    close(fd);
    return -1;
  }
  sscanf(attr, "%ld", size);
  close(fd);

  return 0;
}
