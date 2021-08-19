/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"

#include "libcsdec.h"

#include "afl/common.h"

#include "common.h"
#include "known-boards.h"
#include "config.h"
#include "utils.h"

#define DEFAULT_BOARD_NAME "Marvell ThunderX2"
#define DEFAULT_TRACE_CPU 0
#define DEFAULT_UDMABUF_NAME "udmabuf0"
#define DEFAULT_ETF_SIZE 0x1000
#define DEFAULT_TRACE_SIZE 0x80000
#define DEFAULT_TRACE_NAME "cstrace.bin"
#define DEFAULT_TRACE_ARGS_NAME "decoderargs.txt"

enum cov_type {
  edge_cov,
  path_cov,
};

char *board_name = DEFAULT_BOARD_NAME;
struct cs_devices_t devices;
bool tracing_on = true;
bool decoding_on = false;
int trace_cpu = -1;
bool export_config = false;
unsigned long etr_ram_addr = 0;
size_t etr_ram_size = 0;
int range_count = 0;
struct addr_range range[RANGE_MAX];
bool trace_started = false;
bool etr_mode = true;

static unsigned char dummy[MAP_SIZE];
unsigned char *afl_area_ptr = dummy;
unsigned int afl_map_size = MAP_SIZE;

static const struct board *board;
static char *udmabuf_name = DEFAULT_UDMABUF_NAME;
static int trace_id = -1;
static bool is_first_trace = true;
static libcsdec_t decoder = NULL;
static void *trace_buf = NULL;
static size_t trace_buf_size = 0;
static void *trace_buf_ptr = NULL;
static enum cov_type cov_type = path_cov;

extern int registration_verbose;

static libcsdec_t init_decoder(void)
{
  const char **paths;
  libcsdec_t decoder;
  int i;

  paths = malloc(sizeof(char *) * range_count);
  if (!paths) {
    decoder = (libcsdec_t)NULL;
    goto exit;
  }
  for (i = 0; i < range_count; i++) {
    paths[i] = range[i].path;
  }

  if (!afl_area_ptr || afl_map_size == 0) {
    decoder = (libcsdec_t)NULL;
    goto exit;
  }

  switch (cov_type) {
    case edge_cov:
      decoder = libcsdec_init_edge(range_count, paths, afl_area_ptr, afl_map_size);
      break;
    case path_cov:
      decoder = libcsdec_init_path(afl_area_ptr, afl_map_size);
      break;
  }

exit:
  if (paths) {
    free(paths);
  }

  return decoder;
}

static int alloc_trace_buf(void)
{
  trace_buf = mmap(NULL, DEFAULT_TRACE_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (!trace_buf) {
    perror("mmap");
    return -1;
  }
  trace_buf_size = DEFAULT_TRACE_SIZE;
  trace_buf_ptr = trace_buf;

  return 0;
}

static void free_trace_buf(void)
{
  if (devices.etb) {
    cs_empty_trace_buffer(devices.etb);
  }

  if (trace_buf) {
    munmap(trace_buf, trace_buf_size);
    trace_buf_ptr = NULL;
  }
}

static int export_trace(const char *trace_name)
{
  int ret;
  char *cwd;
  char trace_path[PATH_MAX];
  char decoder_args_path[PATH_MAX];
  FILE *fp;

  ret = -1;

  cwd = getcwd(NULL, 0);
  if (!cwd) {
    perror("getcwd");
    goto exit;
  }

  memset(trace_path, 0, sizeof(trace_path));
  memset(decoder_args_path, 0, sizeof(decoder_args_path));
  snprintf(trace_path, sizeof(trace_path), "%s/%s", cwd, trace_name);
  snprintf(decoder_args_path, sizeof(decoder_args_path),
      "%s/%s", cwd, DEFAULT_TRACE_ARGS_NAME);

  if (export_decoder_args(trace_id, trace_path, decoder_args_path,
        range, range_count) < 0) {
    goto exit;
  }

  fp = fopen(trace_path, "wb");
  if (!fp) {
    perror("fopen");
    goto exit;
  }

  fwrite(trace_buf, (size_t)((char *)trace_buf_ptr - (char *)trace_buf), 1, fp);
  fclose(fp);

  ret = 0;

exit:
  if (cwd) {
    free(cwd);
  }

  return ret;
}

static int setup_trace_config(pid_t pid)
{
  int ret;

  ret = -1;

  if (etr_mode
      && get_udmabuf_info(udmabuf_name, &etr_ram_addr, &etr_ram_size) < 0) {
    fprintf(stderr, "Failed to get u-dma-buf info\n");
    goto exit;
  }

  if ((range_count = setup_mem_range(pid, range, RANGE_MAX)) < 0) {
    fprintf(stderr, "setup_mem_range() failed\n");
    goto exit;
  }

  if (tracing_on) {
    if (setup_named_board(board_name, &board, &devices, known_boards) < 0) {
      fprintf(stderr, "setup_named_board() failed\n");
      goto exit;
    }
  }

  if ((trace_id = get_trace_id(board_name, trace_cpu)) < 0) {
    goto exit;
  }

  if (decoding_on) {
    decoder = init_decoder();
    if (!decoder) {
      goto exit;
    }
  }

  ret = 0;

exit:
  if (tracing_on && ret < 0) {
    cs_shutdown();
  }

  return ret;
}

static int enable_cs_trace(pid_t pid)
{
  int ret;

  ret = -1;

  if (is_first_trace) {
    /* Do not specify traced PID in forkserver mode */
    if (configure_trace(board, &devices, range, range_count, pid) < 0) {
      fprintf(stderr, "configure_trace() failed\n");
      goto exit;
    }
    is_first_trace = false;
  }

  if (enable_trace(board, &devices) < 0) {
    fprintf(stderr, "enable_trace() failed\n");
    goto exit;
  }

  if (export_config) {
    do_dump_config(board, &devices, 0);
  }

  trace_started = true;
  ret = 0;

exit:
  if (ret < 0) {
    cs_shutdown();
  }

  return ret;
}

static void disable_cs_trace(void)
{
  if (disable_trace(board, &devices) < 0) {
    fprintf(stderr, "disable_trace() failed\n");
    return;
  }

  trace_started = false;
}

static void fetch_trace(void)
{
  cs_device_t etb;
  int len;
  size_t buf_remain;
  void *new_trace_buf;
  size_t new_trace_buf_size;
  int n;

  etb = devices.etb;
  len = cs_get_buffer_unread_bytes(etb);

  trace_buf_ptr = (void *)ALIGN_UP((unsigned long)trace_buf_ptr, 0x8);

  buf_remain = trace_buf_size - (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  if ((size_t)len > buf_remain) {
    new_trace_buf_size = trace_buf_size * 2;
    new_trace_buf = mremap(trace_buf, trace_buf_size, new_trace_buf_size, 0);

    if (!new_trace_buf) {
      perror("mremap");
      return;
    }
    trace_buf_ptr = (void *)((char *)new_trace_buf
        + ((char *)trace_buf_ptr - (char *)trace_buf));
    trace_buf = new_trace_buf;
    trace_buf_size = new_trace_buf_size;
    buf_remain = (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  }

  n = cs_get_trace_data(etb, trace_buf_ptr, buf_remain);
  if (n <= 0) {
    fprintf(stderr, "Failed to get trace\n");
    return;
  } else if (n < len) {
    fprintf(stderr, "Got incomplete trace\n");
  }
  cs_empty_trace_buffer(etb);
  trace_buf_ptr = (void *)((char *)trace_buf_ptr + n);
}

static int decode_trace(void)
{
  libcsdec_result_t ret;
  size_t trace_size;

  if (trace_id < 0) {
    return -1;
  }

  if (!afl_area_ptr || afl_map_size == 0) {
    return -1;
  }

  ret = LIBCSDEC_ERROR;

  if (!decoder) {
    return -1;
  }

  trace_size = (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  switch (cov_type) {
    case edge_cov:
      ret = libcsdec_run_edge(decoder, trace_buf, trace_size);
      libcsdec_finish_edge(decoder);
      break;
    case path_cov:
      ret = libcsdec_run_path(decoder, trace_buf, trace_size);
      libcsdec_finish_path(decoder);
      break;
  }

  return (ret == LIBCEDEC_SUCCESS) ? 0 : -1;
}

void init_trace(pid_t parent_pid, pid_t pid)
{
  int preferred_cpu;

  if (trace_cpu < 0) {
    preferred_cpu = get_preferred_cpu(parent_pid);
    trace_cpu = preferred_cpu >= 0 ? preferred_cpu : DEFAULT_TRACE_CPU;
  }
  setup_trace_config(pid);
}

void fini_trace(void)
{
  export_trace(DEFAULT_TRACE_NAME);

  if (registration_verbose > 0) {
    dump_mem_range(stderr, range, range_count);
  }

  free_trace_buf();
  cs_shutdown();
}

void start_trace(pid_t pid, bool use_pid_trace)
{
  set_cpu_affinity(trace_cpu, pid);
  alloc_trace_buf();
  if (decoding_on) {
    switch (cov_type) {
      case edge_cov:
        libcsdec_reset_edge(decoder, trace_id, range_count,
            (struct libcsdec_memory_map *)range);
        break;
      case path_cov:
        libcsdec_reset_path(decoder, trace_id, range_count,
            (struct libcsdec_memory_map *)range);
        break;
    }
  }
  if (tracing_on) {
    enable_cs_trace(use_pid_trace ? pid : 0);
  }
}

int stop_trace(bool needs_decode, bool needs_free_trace_buf)
{
  int ret;
  disable_cs_trace();
  fetch_trace();
  if (decoding_on && needs_decode) {
    ret = decode_trace();
    if (ret < 0) {
      return ret;
    }
  }
  if (needs_free_trace_buf) {
    free_trace_buf();
  }
  return 0;
}
