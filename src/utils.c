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
