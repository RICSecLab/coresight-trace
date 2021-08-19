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

#include "proc-trace.h"
#include "known-boards.h"
#include "config.h"
#include "utils.h"
#include "afl.h"

#include "afl/common.h"

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

unsigned long etr_ram_addr = 0;
size_t etr_ram_size = 0;
bool needs_rerun = false;
bool etr_mode = true;

static char *board_name = DEFAULT_BOARD_NAME;
static const struct board *board;
static struct cs_devices_t devices;
static char *udmabuf_name = DEFAULT_UDMABUF_NAME;
static bool forkserver_mode = false;
static bool tracing_on = true;
static bool polling_on = true;
static int trace_cpu = -1;
static int trace_id = -1;
static bool trace_started = false;
static bool is_first_trace = true;
static float etf_ram_usage_threshold = 0.8;
static bool export_config = false;
static int range_count = 0;
static struct addr_range range[RANGE_MAX];
static libcsdec_t decoder = NULL;
static void *trace_buf = NULL;
static size_t trace_buf_size = 0;
static void *trace_buf_ptr = NULL;
static bool decoding_on = false;
static enum cov_type cov_type = edge_cov;

static pthread_cond_t trace_cond;
static pthread_mutex_t trace_mutex;

extern int registration_verbose;
extern unsigned char *afl_area_ptr;
extern unsigned int afl_map_size;

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
  }
}

static int export_trace(void)
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
  snprintf(trace_path, sizeof(trace_path), "%s/%s", cwd, DEFAULT_TRACE_NAME);
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

  decoder = init_decoder();
  if (!decoder) {
    goto exit;
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
    if (configure_trace(board, &devices, range, range_count,
          forkserver_mode ? 0 : pid) < 0) {
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

  switch (cov_type) {
    case edge_cov:
      ret = libcsdec_run_edge(decoder, trace_buf, trace_buf_size);
      libcsdec_finish_edge(decoder);
      break;
    case path_cov:
      ret = libcsdec_run_path(decoder, trace_buf, trace_buf_size);
      libcsdec_finish_path(decoder);
      break;
  }
  if (ret != LIBCEDEC_SUCCESS) {
    needs_rerun = true;
  }

  return 0;
}

static void fini_trace(void)
{
  export_trace();

  if (registration_verbose > 0) {
    dump_mem_range(stderr, range, range_count);
  }

  free_trace_buf();
  cs_shutdown();
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

void start_trace(pid_t pid)
{
  set_cpu_affinity(trace_cpu, pid);
  alloc_trace_buf();
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
  if (tracing_on) {
    enable_cs_trace(pid);
  }
}

void stop_trace(bool needs_decode, bool needs_free_trace_buf)
{
  disable_cs_trace();
  fetch_trace();
  if (needs_decode) {
    decode_trace();
  }
  if (needs_free_trace_buf) {
    free_trace_buf();
  }
}

static void *etb_polling(void *arg)
{
  pid_t pid = *(pid_t *)arg;
  size_t etf_ram_depth;
  size_t etf_ram_remain;
  unsigned int rwp;
  int ret;

  etf_ram_depth = DEFAULT_ETF_SIZE;

  if (tracing_on) {
    etf_ram_depth = cs_get_buffer_size_bytes(devices.etb);
  }

  while (kill(pid, 0) == 0) {
    if (tracing_on && trace_started == true) {
      rwp = cs_get_buffer_rwp(devices.etb);
      etf_ram_remain = etr_ram_addr + etf_ram_depth - rwp;
      if (etf_ram_remain < (etf_ram_depth * (1.0 - etf_ram_usage_threshold))) {
        pthread_mutex_lock(&trace_mutex);
        ret = kill(pid, SIGSTOP);
        if (ret < 0) {
          fprintf(stderr, "kill() failed\n");
        }
        pthread_cond_wait(&trace_cond, &trace_mutex);
        pthread_mutex_unlock(&trace_mutex);
      }
    }
  }
  return NULL;
}

void child(char *argv[])
{
  long ret;

  ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  if (ret < 0) {
    perror("ptrace");
  }
  execvp(argv[0], argv);
}

void parent(pid_t pid, int *child_status)
{
  int wstatus;
  struct mmap_params mmap_params;
  bool is_entered_mmap;

  pthread_t polling_thread;
  int ret;

  trace_started = false;
  is_entered_mmap = false;

  pthread_mutex_init(&trace_mutex, NULL);
  pthread_cond_init(&trace_cond, NULL);;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    pthread_mutex_lock(&trace_mutex);
    init_trace(getpid(), pid);
    start_trace(pid);
    pthread_mutex_unlock(&trace_mutex);
  }

  if (polling_on) {
    ret = pthread_create(&polling_thread, NULL, etb_polling, &pid);
    if (ret != 0) {
      return;
    }
  }

  while (1) {
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
      if (tracing_on && trace_started == true) {
        pthread_mutex_lock(&trace_mutex);
        stop_trace(decoding_on, false);
        fini_trace();
        pthread_mutex_unlock(&trace_mutex);
      }
      break;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
      // TODO: It should support mprotect
      if (get_mmap_params(pid, &mmap_params) < 0) {
        // Not mmap syscall. Do nothing
        if (is_syscall_exit_group(pid)) {
          // exit_group syscall.
          if (registration_verbose > 0) {
            dump_maps(stderr, pid);
          }
        }
      } else {
        if (is_entered_mmap) {
          append_mmap_exec_region(pid, &mmap_params, range, range_count);
        }
        is_entered_mmap = !is_entered_mmap;
      }
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
      if (tracing_on) {
        if (cs_buffer_has_wrapped(devices.etb)) {
          int bytes = cs_get_buffer_unread_bytes(devices.etb);
          fprintf(stderr, "WARNING: ETB full bit is set: %d bytes\n", bytes);
        }
        pthread_mutex_lock(&trace_mutex);
        stop_trace(false, false);
        start_trace(pid);
        pthread_cond_signal(&trace_cond);
        pthread_mutex_unlock(&trace_mutex);
      }
    }
  }

  pthread_cond_destroy(&trace_cond);
  pthread_mutex_destroy(&trace_mutex);

  if (child_status) {
    *child_status = wstatus;
  }
}

static void usage(char *argv0)
{
  fprintf(stderr, "Usage: %s [OPTIONS] -- EXE [ARGS]\n", argv0);
  fprintf(stderr, "CoreSight process tracer\n");
  fprintf(stderr, "[OPTIONS]\n");
  fprintf(stderr, "  --forkserver={0,1}\t\tenable AFL fork server mode (default: %d)\n", forkserver_mode);
  fprintf(stderr, "  --cpu=INT\t\t\tbind traced process to CPU (default: %d)\n", trace_cpu);
  fprintf(stderr, "  --tracing={0,1}\t\tenable tracing (default: %d)\n", tracing_on);
  fprintf(stderr, "  --polling={0,1}\t\tenable ETF polling (default: %d)\n", polling_on);
  fprintf(stderr, "  --decoding={0,1}\t\tenable trace decoding (default: %d)\n", decoding_on);
  fprintf(stderr, "  --export-config={0,1}\t\tenable exporting config (default: %d)\n", export_config);
  fprintf(stderr, "  --etf-threshold=FLOAT\t\tETF full threshold (default: %.1f)\n", etf_ram_usage_threshold);
  fprintf(stderr, "  --verbose=INT\t\t\tverbose output level (default: %d)\n", registration_verbose);
  fprintf(stderr, "  --help\t\t\tshow this help\n");
}

int main(int argc, char *argv[])
{
  char **argvp;
  pid_t pid;
  int i;
  float f;
  int n;
  char junk;

  i = 1;
  argvp = NULL;
  registration_verbose = 0;

  if (argc < 3) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  for (i = 1; i < argc; i++) {
    if (sscanf(argv[i], "--forkserver=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      forkserver_mode = n ? true : false;
    } else if (strcmp(argv[i], "--board") == 0 && i + 1 < argc) {
      board_name = argv[++i];
    } else if (sscanf(argv[i], "--cpu=%d%c", &n, &junk) == 1) {
      trace_cpu = n;
    } else if (sscanf(argv[i], "--tracing=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      tracing_on = n ? true : false;
    } else if (sscanf(argv[i], "--polling=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      polling_on = n ? true : false;
    } else if (sscanf(argv[i], "--etr=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      etr_mode = n ? true : false;
    } else if (sscanf(argv[i], "--etf-threshold=%f%c", &f, &junk) == 1
        && (0 < f && f < 1)) {
      etf_ram_usage_threshold = f;
    } else if (sscanf(argv[i], "--export-config=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      export_config = n ? true : false;
    } else if (sscanf(argv[i], "--decoding=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      decoding_on = n ? true : false;
    } else if (sscanf(argv[i], "--verbose=%d%c", &n, &junk) == 1
        && (n >= 0)) {
      registration_verbose = n;
    } else if (!strcmp(argv[i], "--help")) {
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    } else if (!strcmp(argv[i], "--") && i + 1 < argc) {
      argvp = &argv[++i];
      break;
    } else if (argc > 2 && i + 1 >= argc) {
      fprintf(stderr, "Invalid option '%s'\n", argv[i]);
      exit(EXIT_FAILURE);
    }
  }

  if (!argvp) {
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  if (forkserver_mode) {
    afl_setup();
    afl_forkserver(argvp);
    exit(EXIT_SUCCESS);
  }

  pid = fork();
  switch (pid) {
    case 0:
      child(argvp);
      break;
    case -1:
      perror("fork");
      exit(EXIT_FAILURE);
      break;
    default:
      parent(pid, NULL);
      wait(NULL);
      break;
  }

  return 0;
}
