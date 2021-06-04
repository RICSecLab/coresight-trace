#define _GNU_SOURCE
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

#define DUMP_CONFIG 1
#define SHOW_ETM_CONFIG 0
#define TRACE_CPU 0

const char *trace_name = "cstrace.bin";
const char *decoder_args_path = "decoderargs.txt";
const char *board_name = "Marvell ThunderX2";
const float etf_ram_usage_threshold = 0.8;
const useconds_t polling_sleep_us = 10;

static struct cs_devices_t devices;
const struct board *board;

static int cpu = TRACE_CPU;
static cpu_set_t affinity_mask;

extern int registration_verbose;

extern const struct board known_boards[];

struct addr_range range[RANGE_MAX];
int range_count = 0;

bool trace_started = false;

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

  ret = -1;

  if ((range_count = setup_mem_range(pid, range, RANGE_MAX)) < 0) {
    fprintf(stderr, "setup_mem_range() failed\n");
    goto exit;
  }

  dump_mem_range(range, range_count);

  if (setup_named_board(board_name, &board, &devices, known_boards) < 0) {
    fprintf(stderr, "setup_named_board() failed\n");
    goto exit;
  }

  if (cpu >= 0) {
    // TODO: Support CPU hotplug
    CPU_ZERO(&affinity_mask);
    CPU_SET(cpu, &affinity_mask);
    if (sched_setaffinity(pid, sizeof(affinity_mask), &affinity_mask) < 0) {
      perror("sched_setaffinity");
      goto exit;
    }
  }

  ret = 0;

exit:
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
  export_decoder_args(board_name, cpu, trace_path, decoder_args_path,
      range, range_count);

  dump_mem_range(range, range_count);

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

#if DUMP_CONFIG
  do_dump_config(board, &devices, 0);
#endif

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

  for (i = 0; i < board->n_cpu; ++i) {
    cs_trace_disable(devices.ptm[i]);
  }
  cs_sink_disable(devices.etb);

#if SHOW_ETM_CONFIG
  for (i = 0; i < board->n_cpu; ++i) {
    show_etm_config(i);
  }
#endif

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
          fprintf(stderr, "** kill failed\n");
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
        fprintf(stderr, "** WARNING: ETB full bit is set\n");
      }
      stop_trace();
      fetch_trace();
      start_trace();
    }
  }
}

int main(int argc, char *argv[])
{
  pid_t pid;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s EXE\n", argv[0]);
    exit(EXIT_SUCCESS);
  }

  registration_verbose = 0;

  pid = fork();
  switch (pid) {
    case 0:
      child(&argv[1]);
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
