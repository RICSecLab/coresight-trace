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
#include <sched.h>
#include <limits.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/sysinfo.h>

#include <linux/elf.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"

#include "config.h"

#define RANGE_MAX (ETMv4_NUM_ADDR_COMP_MAX / 2)

#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))
#define PAGE_SIZE 0x1000

#define DEFAULT_TRACE_CPU 0

const char *trace_name = "cstrace.bin";
const char *decoder_args_path = "decoderargs.txt";
const char *board_name = "Marvell ThunderX2";

int etb_stop_on_flush = 1;

static const struct board *board;
static struct cs_devices_t devices;
static int trace_cpu = DEFAULT_TRACE_CPU;
static bool trace_started = false;
static float etf_ram_usage_threshold = 0.8;
static useconds_t polling_sleep_us = 10;
static int export_config = 0;
static int range_count = 0;
static struct addr_range range[RANGE_MAX];

extern const struct board known_boards[];
extern int registration_verbose;

struct mmap_params {
  void *addr;
  size_t length;
  int prot;
  int flags;
  int fd;
  off_t offset;
};

static int init_trace(pid_t pid)
{
  int ret;
  int nprocs;
  cpu_set_t *cpu_set;
  size_t setsize;

  ret = -1;

  if ((range_count = setup_mem_range(pid, range, RANGE_MAX)) < 0) {
    fprintf(stderr, "setup_mem_range() failed\n");
    goto exit;
  }

  if (setup_named_board(board_name, &board, &devices, known_boards) < 0) {
    fprintf(stderr, "setup_named_board() failed\n");
    goto exit;
  }

  nprocs = get_nprocs();
  cpu_set = CPU_ALLOC(nprocs);
  if (!cpu_set) {
    perror("CPU_ALLOC");
    goto exit;
  }
  setsize = CPU_ALLOC_SIZE(nprocs);
  CPU_ZERO_S(setsize, cpu_set);
  CPU_SET_S(trace_cpu, setsize,  cpu_set);
  if (sched_setaffinity(pid, setsize, cpu_set) < 0) {
    perror("sched_setaffinity");
    goto exit;
  }

  ret = 0;

exit:
  if (cpu_set) {
    CPU_FREE(cpu_set);
  }

  if (ret < 0) {
    cs_shutdown();
  }

  return ret;
}

static void fini_trace(void)
{
  char *cwd;
  char trace_path[PATH_MAX];

  cs_shutdown();

  cwd = getcwd(NULL, 0);
  if (!cwd) {
    perror("getcwd");
    return;
  }
  memset(trace_path, 0, sizeof(trace_path));
  snprintf(trace_path, sizeof(trace_path), "%s/%s", cwd, trace_name);
  export_decoder_args(board_name, trace_cpu, trace_path, decoder_args_path,
      range, range_count);

  if (registration_verbose > 0) {
    dump_mem_range(stderr, range, range_count);
  }

  if (cwd) {
    free(cwd);
  }
}

static int start_trace(void)
{
  int ret;

  ret = -1;

  if (configure_trace(board, &devices, range, range_count) < 0) {
    fprintf(stderr, "configure_trace() failed\n");
    goto exit;
  }

  if (enable_trace(board, &devices) < 0) {
    fprintf(stderr, "enable_trace() failed\n");
    goto exit;
  }

  if (export_config > 0) {
    do_dump_config(board, &devices, 0);
  }

  cs_checkpoint();

  trace_started = true;
  ret = 0;

exit:
  if (ret < 0) {
    cs_shutdown();
  }

  return ret;
}

static void stop_trace(void)
{
  int i;

  if (etb_stop_on_flush > 0) {
    cs_etb_flush_and_wait_stop(&devices);
  }

  for (i = 0; i < board->n_cpu; ++i) {
    cs_trace_disable(devices.ptm[i]);
  }
  cs_sink_disable(devices.etb);

  if (registration_verbose > 1) {
    for (i = 0; i < board->n_cpu; ++i) {
      show_etm_config(devices.ptm[i]);
    }
  }

  trace_started = false;
}

static void fetch_trace(void)
{
  do_fetch_trace(&devices, 0);
}

static void read_pid_fd_path(pid_t pid, int fd, char *buf, size_t size)
{
  char fd_path[PATH_MAX];

  memset(fd_path, 0, sizeof(fd_path));
  snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
  readlink(fd_path, buf, size);
}

static int get_mmap_params(pid_t pid, struct mmap_params *params)
{
  struct user_pt_regs regs;
  struct iovec iov;
  long syscall;

  if (!params) {
    return -1;
  }

  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
    return -1;
  }

  syscall = regs.regs[8];
  if (syscall != __NR_mmap) {
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

static struct addr_range *append_mmap_exec_region(pid_t pid,
    struct mmap_params *params)
{
  struct addr_range *r;

  if (!params) {
    return NULL;
  }

  if (!(params->prot & PROT_EXEC) || params->fd < 3) {
    return NULL;
  }

  if (range_count >= RANGE_MAX) {
    return NULL;
  }

  r = &range[range_count];

  r->start = (unsigned long)params->addr;
  r->end = ALIGN_UP(r->start + params->length, PAGE_SIZE);
  read_pid_fd_path(pid, params->fd, r->path, PATH_MAX);
  range_count++;

  return r;
}

static void *etb_polling(void *arg)
{
  pid_t pid = *(pid_t *)arg;
  size_t etf_ram_depth;
  int rwp;
  int ret;

  etf_ram_depth = cs_get_buffer_size_bytes(devices.etb);

  while (kill(pid, 0) == 0) {
    if (trace_started == true) {
      rwp = cs_get_buffer_rwp(devices.etb);
      if (rwp > (etf_ram_depth * etf_ram_usage_threshold)) {
        ret = kill(pid, SIGSTOP);
        if (ret < 0) {
          fprintf(stderr, "kill() failed\n");
        }
      }
    }
    usleep(polling_sleep_us);
  }
  return NULL;
}

void child(char *argv[])
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execvp(argv[0], argv);
}

void parent(pid_t pid)
{
  int wstatus;
  struct mmap_params mmap_params;
  bool is_entered_mmap;

  pthread_t polling_thread;
  int ret;

  trace_started = false;
  is_entered_mmap = false;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    init_trace(pid);
    start_trace();
  }

  ret = pthread_create(&polling_thread, NULL, etb_polling, &pid);
  if (ret != 0) {
    return;
  }

  while (1) {
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus) && trace_started == true) {
      stop_trace();
      fetch_trace();
      fini_trace();
      return;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
      // TODO: It should support mprotect
      if (get_mmap_params(pid, &mmap_params) < 0) {
        // Not mmap syscall. Do nothing
      } else {
        if (is_entered_mmap && append_mmap_exec_region(pid, &mmap_params)) {
          stop_trace();
          fetch_trace();
          start_trace();
        }
        is_entered_mmap = !is_entered_mmap;
      }
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
      if (cs_buffer_has_wrapped(devices.etb)) {
        fprintf(stderr, "WARNING: ETB full bit is set\n");
      }
      stop_trace();
      fetch_trace();
      start_trace();
    }
  }
}

static void usage(char *argv0)
{
  fprintf(stderr, "Usage: %s [FLAGS] [--] EXE [ARGS]\n", argv0);
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

  if (argc < 2) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  } else if (argc == 2) {
    argvp = &argv[1];
    i++;
  }

  for (i = 1; i < argc; i++) {
    if (sscanf(argv[i], "--cpu=%d%c", &n, &junk) == 1) {
      trace_cpu = n;
    } else if (sscanf(argv[i], "--etf-stop-on-flush=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      etb_stop_on_flush = n;
    } else if (sscanf(argv[i], "--etf-threshold=%f%c", &f, &junk) == 1
        && (0 < f && f < 1)) {
      etf_ram_usage_threshold = f;
    } else if (sscanf(argv[i], "--sleep-us=%d%c", &n, &junk) == 1) {
      polling_sleep_us = n;
    } else if (sscanf(argv[i], "--export-config=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      export_config = n;
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
      parent(pid);
      wait(NULL);
      break;
  }

  return 0;
}
