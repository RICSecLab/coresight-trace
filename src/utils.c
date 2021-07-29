/* SPDX-License-Identifier: Apache-2.0 */

#include "utils.h"

void dump_mem_range(FILE *stream, struct addr_range *range, int count)
{
  int i;

  for (i = 0; i < count; i++) {
    fprintf(stream, "[0x%lx-0x%lx]: %s\n", range[i].start, range[i].end, range[i].path);
  }
}

void dump_maps(FILE *stream, pid_t pid)
{
  FILE *fp;
  char maps_path[PATH_MAX];
  char *line;
  size_t n;
  ssize_t readn;

  memset(maps_path, 0, sizeof(maps_path));
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  fp = fopen(maps_path, "r");
  if (fp == NULL) {
    perror("fopen");
    return;
  }

  line = NULL;
  n = 0;
  while ((readn = getline(&line, &n, fp)) != -1) {
    fprintf(stream, "%s", line);
  }

  if (line != NULL) {
    free(line);
  }

  fclose(fp);

  return;
}

int setup_mem_range(pid_t pid, struct addr_range *range, int count_max)
{
  FILE *fp;
  char maps_path[PATH_MAX];
  char *line;
  size_t n;
  ssize_t readn;
  unsigned long start;
  unsigned long end;
  int count;
  int i;
  char c;
  char x;
  char *p;

  memset(maps_path, 0, sizeof(maps_path));
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  fp = fopen(maps_path, "r");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  i = 0;
  line = NULL;
  n = 0;
  readn = 0;
  count = 0;
  while ((readn = getline(&line, &n, fp)) != -1) {
    if (readn > 0 && line[readn - 1] == '\n') {
      line[readn - 1] = '\0';
      readn--;
    }
    sscanf(line, "%lx-%lx %c%c%c", &start, &end, &c, &c, &x);
    if (x != 'x') {
      continue;
    }
    if (i >= count_max) {
      fprintf(stderr, "WARNING: [0x%lx-0x%lx] will not trace\n", start, end);
      continue;
    }
    // FIXME: The below registers an exec region with absolute path only
    // It means vDSO is not traced.
    for (p = line; *p != '\0' && *p != '/'; p++) {
    }
    if (*p == '/') {
      strncpy(range[i].path, p, PATH_MAX - 1);
      range[i].path[PATH_MAX - 1] = '\0';
      range[i].start = start;
      range[i].end = end;
      i++;
    }
  }

  if (line != NULL) {
    free(line);
  }

  count = i;

  return count;
}

int export_decoder_args(int trace_id, const char *trace_path,
    const char *args_path, struct addr_range *range, int count)
{
  FILE *fp;
  int i;
  int ret;

  ret = 0;

  if (trace_id < 0 || !trace_path || !args_path || !range) {
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
    ret = fprintf(fp, " %s 0x%lx 0x%lx",
        range[i].path, range[i].start, range[i].end);
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
static int set_core_cpus(int cpu, cpu_set_t *cpu_set, size_t setsize)
{
  int ret;
  FILE *fp;
  char core_cpus_list_path[PATH_MAX];
  char *token;
  size_t n;
  ssize_t readn;
  int core_cpu;

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
    core_cpu = (int)strtol(token, NULL, 0);
    if (core_cpu == LONG_MIN || core_cpu == LONG_MAX) {
      perror("strtol");
      goto exit;
    }
    CPU_SET_S(core_cpu, setsize, cpu_set);
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

/* Find CPU core not in the same group of CPU binded to the PID process. */
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
        fprintf(stderr, "Failed to set related core CPU\n");
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

int set_cpu_affinity(int cpu, pid_t pid)
{
  int ret;
  cpu_set_t *cpu_set;
  size_t setsize;

  ret = -1;

  if (!alloc_cpu_set(&cpu_set, &setsize)) {
    goto exit;
  }
  CPU_SET_S(cpu, setsize,  cpu_set);
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

void read_pid_fd_path(pid_t pid, int fd, char *buf, size_t size)
{
  char fd_path[PATH_MAX];

  memset(fd_path, 0, sizeof(fd_path));
  snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
  if (readlink(fd_path, buf, size) < 0) {
    perror("readlink");
  }
}
