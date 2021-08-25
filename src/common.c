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

#define CSDBG() do { \
    fprintf(stderr, "%s:%d\n", __func__, __LINE__); \
  } while (0);

typedef enum {
  edge_cov,
  path_cov,
} cov_type_t;

typedef enum {
  init_state,
  fini_state,
  ready_state,
  running_state,
  suspended_state,
} trace_state_t;

typedef enum {
  init_event,
  fini_event,
  ready_event,
  start_event,
  stop_event,
  suspend_event,
  resume_event,
} trace_event_t;

typedef enum {
  decoder_init_event,
  decoder_fini_event,
  decoder_reset_event,
  decoder_decode_event,
} decoder_event_t;

char *board_name = DEFAULT_BOARD_NAME;
const struct board *board;
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

static char *udmabuf_name = DEFAULT_UDMABUF_NAME;
static int trace_id = -1;
static pid_t child_pid = -1;
static bool is_first_trace = true;
static libcsdec_t decoder = NULL;
static void *trace_buf = NULL;
static size_t trace_buf_size = 0;
static void *trace_buf_ptr = NULL;
static void *decoded_trace_buf = NULL;
static cov_type_t cov_type = path_cov;
static sigset_t sig_set;

static pthread_t decoder_thread;
static pthread_t signal_handler_thread;

static pthread_mutex_t trace_mutex;
static pthread_mutex_t trace_state_mutex;
static pthread_mutex_t trace_event_mutex;
static pthread_cond_t trace_event_cond;
static trace_state_t trace_state = init_state;
static trace_event_t trace_event = init_event;

static pthread_mutex_t trace_decoder_mutex;
static pthread_cond_t trace_decoder_cond;
static decoder_event_t decoder_event = decoder_init_event;

extern int registration_verbose;

static int enable_cs_trace(pid_t pid);
static int disable_cs_trace(void);

static void signal_trace_event(trace_event_t event)
{
  pthread_mutex_lock(&trace_event_mutex);
  trace_event = event;
  pthread_cond_broadcast(&trace_event_cond);
  pthread_mutex_unlock(&trace_event_mutex);
}

static void wait_trace_event(trace_event_t event)
{
  pthread_mutex_lock(&trace_event_mutex);
  while (trace_event != event) {
    pthread_cond_wait(&trace_event_cond, &trace_event_mutex);
  }
  pthread_mutex_unlock(&trace_event_mutex);
}

static void signal_decoder_event(decoder_event_t event)
{
  pthread_mutex_lock(&trace_decoder_mutex);
  decoder_event = event;
  pthread_cond_broadcast(&trace_decoder_cond);
  pthread_mutex_unlock(&trace_decoder_mutex);
}

static void wait_decoder_event(decoder_event_t event)
{
  pthread_mutex_lock(&trace_decoder_mutex);
  while (decoder_event != event) {
    pthread_cond_wait(&trace_decoder_cond, &trace_decoder_mutex);
  }
  pthread_mutex_unlock(&trace_decoder_mutex);
}

static void set_trace_state(trace_state_t new_state)
{
  trace_state_t old_state;

  pthread_mutex_lock(&trace_state_mutex);
  old_state = trace_state;
  trace_state = new_state;
  if (old_state == init_state) {
    signal_trace_event(init_event);
  } else if (new_state == fini_state) {
    signal_trace_event(fini_event);
  } else if (new_state == ready_state) {
    signal_trace_event(stop_event);
  } else if (old_state == ready_state && new_state == running_state) {
    signal_trace_event(start_event);
  } else if (old_state == running_state && new_state == suspended_state) {
    signal_trace_event(suspend_event);
  } else if (old_state == suspended_state && new_state == running_state) {
    signal_trace_event(resume_event);
  } else {
    fprintf(stderr, "Unexpected trace state transition: %d -> %d\n",
        old_state, new_state);
  }
  pthread_mutex_unlock(&trace_state_mutex);
}

static int trace_sink_polling(void)
{
  int ret;
  unsigned long init_pos;
  unsigned long curr_offset;
  unsigned long decoding_threshold = 0x200;

  ret = 0;
  init_pos = cs_get_buffer_rwp(devices.etb);

  while (!kill(child_pid, 0)) {
    curr_offset = cs_get_buffer_rwp(devices.etb) - init_pos;
    if (curr_offset > decoding_threshold) {
      /* Suspend child_pid process. */
      ret = kill(child_pid, SIGSTOP);
      if (ret < 0) {
        perror("kill");
        goto exit;
      }

      /* Wait for suspending trace. */
      wait_trace_event(suspend_event);
      ret = disable_cs_trace();
      if (ret < 0) {
        fprintf(stderr, "disable_cs_trace() failed\n");
        goto exit;
      }
      fetch_trace();

      enable_cs_trace(child_pid);
      /* Continue child_pid process. */
      ret = kill(child_pid, SIGCONT);
      if (ret < 0) {
        perror("kill");
        goto exit;
      }

      /* Decode trace during the process is running. */
      if ((ret = decode_trace()) < 0) {
        fprintf(stderr, "decode_trace() failed\n");
        goto exit;
      }
    }
  }

  pthread_mutex_lock(&trace_event_mutex);
  while (trace_event != stop_event && trace_event != fini_event) {
    pthread_cond_wait(&trace_event_cond, &trace_event_mutex);
  }
  pthread_mutex_unlock(&trace_event_mutex);

  fetch_trace();
  if ((ret = decode_trace()) < 0) {
    fprintf(stderr, "decode_trace() failed\n");
    goto exit;
  }

exit:
  return ret;
}

static void *decoder_worker(void *arg)
{
  trace_event_t event;

  /* TODO: Set CPU affinity of this thread */

  while (1) {
    pthread_mutex_lock(&trace_event_mutex);
    while (trace_event != start_event && trace_event != fini_event) {
      pthread_cond_wait(&trace_event_cond, &trace_event_mutex);
    }
    event = trace_event; /* TODO: trace_event can be changed in if cond. */
    pthread_mutex_unlock(&trace_event_mutex);
    if (event == start_event) {
      trace_sink_polling();
    } else if (event == fini_event) {
      break;
    }
  }

  return NULL;
}

static void *signal_handler(void *arg)
{
  int signal;

  /* TODO: Set CPU affinity of this thread */

  while (1) {
    /* Wait SIGTERM */
    sigwait(&sig_set, &signal);

    if (signal == SIGTERM) {
      /* Wait trace_stop */
      wait_trace_event(stop_event);
      fini_trace();
      exit(0);
    }
  }

  return NULL;
}

/* TODO: Take cov_type as a argument. */
static int reset_decoder(void)
{
  libcsdec_result_t ret;

  if (!decoder) {
    return -1;
  }

  switch (cov_type) {
    case edge_cov:
      ret = libcsdec_reset_edge(decoder, trace_id, range_count,
          (struct libcsdec_memory_map *)range);
      break;
    case path_cov:
      ret = libcsdec_reset_path(decoder, trace_id, range_count,
          (struct libcsdec_memory_map *)range);
      break;
  }

  signal_decoder_event(decoder_reset_event);

  return (ret == LIBCEDEC_SUCCESS) ? 0 : -1;
}

/* TODO: Take cov_type as a argument. */
static int run_decoder(void *buf, size_t buf_size)
{
  libcsdec_result_t ret;

  if (!decoder) {
    return -1;
  }

  switch (cov_type) {
    case edge_cov:
      ret = libcsdec_run_edge(decoder, buf, buf_size);
      break;
    case path_cov:
      ret = libcsdec_run_path(decoder, buf, buf_size);
      break;
  }

  signal_decoder_event(decoder_decode_event);

  return (ret == LIBCEDEC_SUCCESS) ? 0 : -1;
}

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

  /* FIXME: Do not use AFL specific variables inside common function */
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

  signal_decoder_event(decoder_init_event);

exit:
  if (paths) {
    free(paths);
  }

  return decoder;
}

/* TODO: Take cov_type as a argument. */
static int fini_decoder(void)
{
  if (!decoder) {
    return -1;
  }

  switch (cov_type) {
    case edge_cov:
      libcsdec_finish_edge(decoder);
      break;
    case path_cov:
      libcsdec_finish_path(decoder);
      break;
  }

  signal_decoder_event(decoder_fini_event);

  return 0;
}

/* FIXME: Do not initialize global variables in the function */
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
  decoded_trace_buf = trace_buf_ptr;

  return 0;
}

/* FIXME: Make it better */
static void free_trace_buf(void)
{
  if (devices.etb) {
    cs_empty_trace_buffer(devices.etb);
  }

  if (trace_buf) {
    munmap(trace_buf, trace_buf_size);
    trace_buf_ptr = NULL;
    decoded_trace_buf = NULL;
  }
}

static int export_trace(const char *trace_name, const char *trace_args_name)
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
  snprintf(decoder_args_path, sizeof(decoder_args_path), "%s/%s", cwd,
      trace_args_name);

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

static int enable_cs_trace(pid_t pid)
{
  int ret;

  ret = -1;

  pthread_mutex_lock(&trace_mutex);

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
  pthread_mutex_unlock(&trace_mutex);

  return ret;
}

static int disable_cs_trace(void)
{
  int ret;

  pthread_mutex_lock(&trace_mutex);

  if ((ret = disable_trace(board, &devices)) < 0) {
    fprintf(stderr, "disable_trace() failed\n");
    goto exit;
  }

  trace_started = false;

exit:
  pthread_mutex_unlock(&trace_mutex);

  return ret;
}

int fetch_trace(void)
{
  int ret;
  cs_device_t etb;
  int len;
  size_t buf_remain;
  void *new_trace_buf;
  size_t new_trace_buf_size;
  int n;

  ret = -1;

  pthread_mutex_lock(&trace_mutex);

  etb = devices.etb;
  len = cs_get_buffer_unread_bytes(etb);

  trace_buf_ptr = (void *)ALIGN_UP((unsigned long)trace_buf_ptr, 0x8);

  buf_remain = trace_buf_size - (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  /* No space left in trace_buf. */
  if ((size_t)len > buf_remain) {
    new_trace_buf_size = trace_buf_size * 2;
    new_trace_buf = mremap(trace_buf, trace_buf_size, new_trace_buf_size, 0);

    if (!new_trace_buf) {
      perror("mremap");
      goto exit;
    }
    decoded_trace_buf = (void *)((char *)new_trace_buf
        + ((char *)decoded_trace_buf - (char *)trace_buf));
    trace_buf_ptr = (void *)((char *)new_trace_buf
        + ((char *)trace_buf_ptr - (char *)trace_buf));
    trace_buf = new_trace_buf;
    trace_buf_size = new_trace_buf_size;
    buf_remain = (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  }

  n = cs_get_trace_data(etb, trace_buf_ptr, buf_remain);
  if (n <= 0) {
    fprintf(stderr, "Failed to get trace\n");
  } else if (n < len) {
    fprintf(stderr, "Got incomplete trace\n");
  }
  cs_empty_trace_buffer(etb);
  trace_buf_ptr = (void *)((char *)trace_buf_ptr + n);

  ret = 0;

exit:
  pthread_mutex_unlock(&trace_mutex);
  return ret;
}

int decode_trace(void)
{
  int ret;
  void *buf;
  size_t buf_size;

  buf = decoded_trace_buf;
  buf_size = (size_t)((char *)trace_buf_ptr - (char *)buf);
  
  ret = run_decoder(buf, buf_size);
  if (ret < 0) {
    return ret;
  }

  decoded_trace_buf = (void *)((char *)buf + buf_size);

  return ret;
}

void trace_suspend_resume_callback(void)
{
  set_trace_state(suspended_state);
}

/* Start trace session. CoreSight and decoder must be initialized. */
int start_trace(pid_t pid, bool use_pid_trace)
{
  int ret;

  if ((ret = set_cpu_affinity(trace_cpu, pid)) < 0) {
    fprintf(stderr, "set_cpu_affinity() failed\n");
    goto exit;
  }

  if (!tracing_on) {
    goto exit;
  }

  alloc_trace_buf();

  if (decoding_on && ((ret = reset_decoder()) < 0)) {
    fprintf(stderr, "reset_decoder() failed\n");
    goto exit;
  }

  child_pid = pid;
  if ((ret = enable_cs_trace(use_pid_trace ? pid : 0)) < 0) {
    fprintf(stderr, "enable_cs_trace() failed\n");
  }

  if (ret < 0) {
    goto exit;
  }

  set_trace_state(running_state);

exit:
  return ret;
}

/* Stop trace session. CoreSight and decoder are still available. */
int stop_trace(void)
{
  int ret;

  if ((ret = disable_cs_trace()) < 0) {
    fprintf(stderr, "disable_cs_trace() failed\n");
  }

  if (ret < 0) {
    goto exit;
  }

  set_trace_state(ready_state);
  wait_decoder_event(decoder_decode_event);

exit:
  return ret;
}

/* Initialize trace. Called on the first time and only once. */
int init_trace(pid_t parent_pid, pid_t pid)
{
  int ret;
  int preferred_cpu;

  ret = -1;

  pthread_mutex_init(&trace_mutex, NULL);
  pthread_mutex_init(&trace_state_mutex, NULL);
  pthread_mutex_init(&trace_event_mutex, NULL);
  pthread_cond_init(&trace_event_cond, NULL);

  pthread_mutex_init(&trace_decoder_mutex, NULL);
  pthread_cond_init(&trace_decoder_cond, NULL);

  if (trace_cpu < 0) {
    preferred_cpu = get_preferred_cpu(parent_pid);
    trace_cpu = preferred_cpu >= 0 ? preferred_cpu : DEFAULT_TRACE_CPU;
  }

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

  sigemptyset(&sig_set);
  sigaddset(&sig_set, SIGTERM);
  pthread_sigmask(SIG_BLOCK, &sig_set, NULL);
  ret = pthread_create(&signal_handler_thread, NULL, signal_handler, NULL);
  if (ret != 0) {
    fprintf(stderr, "pthread_create: %d\n", ret);
    goto exit;
  }

  if (decoding_on) {
    decoder = init_decoder();
    if (!decoder) {
      goto exit;
    }
    ret = pthread_create(&decoder_thread, NULL, decoder_worker, NULL);
    if (ret != 0) {
      fprintf(stderr, "pthread_create: %d\n", ret);
      goto exit;
    }
  }

  set_trace_state(ready_state);
  ret = 0;

exit:
  if (tracing_on && ret != 0) {
    cs_shutdown();
  }

  return ret;
}

/* Finalize trace. Called after all trace sessions finished. */
void fini_trace(void)
{
  if (decoding_on) {
    /* Cancel decoder_thread. Assuming stop singal is sent prior to it. */
    set_trace_state(fini_state);
    pthread_join(decoder_thread, NULL);
  } else {
    fetch_trace();
  }

  export_trace(DEFAULT_TRACE_NAME, DEFAULT_TRACE_ARGS_NAME);

  if (registration_verbose > 0) {
    dump_mem_range(stderr, range, range_count);
  }

  fini_decoder();

  free_trace_buf();

  cs_shutdown();

  pthread_cond_destroy(&trace_decoder_cond);
  pthread_mutex_destroy(&trace_decoder_mutex);

  pthread_cond_destroy(&trace_event_cond);
  pthread_mutex_destroy(&trace_event_mutex);
  pthread_mutex_destroy(&trace_state_mutex);
  pthread_mutex_destroy(&trace_mutex);
}