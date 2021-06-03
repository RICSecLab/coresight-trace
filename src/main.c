#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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

static struct cs_devices_t devices;
const struct board *board;

static int cpu = TRACE_CPU;
static cpu_set_t affinity_mask;

extern int registration_verbose;

extern const struct board known_boards[];

struct addr_range range[RANGE_MAX];
int range_count = 0;

static void start_trace(pid_t pid)
{
  if ((range_count = get_mem_range(pid, range, RANGE_MAX)) < 0) {
    fprintf(stderr, "get_mem_range() failed\n");
    return;
  }

  printf("Trace range:\n");
  dump_mem_range(range, range_count);

  if (setup_named_board(board_name, &board, &devices, known_boards) < 0) {
    fprintf(stderr, "setup_named_board() failed\n");
    return;
  }

  if (cpu >= 0) {
    printf("Set CPU affinity: CPU #%d\n", cpu);
    CPU_ZERO(&affinity_mask);
    CPU_SET(cpu, &affinity_mask);
    if (sched_setaffinity(pid, sizeof(affinity_mask), &affinity_mask) < 0) {
      perror("sched_setaffinity");
      cs_shutdown();
      return;
    }
  }

  if (configure_trace(board, &devices, range, range_count) < 0) {
    fprintf(stderr, "** configure_trace() failed\n");
    return;
  }

  if (enable_trace(board, &devices) < 0) {
    fprintf(stderr, "** enable_trace() failed\n");
    return;
  }

#if DUMP_CONFIG
  do_dump_config(board, &devices, 0);
#endif
  cs_checkpoint();

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

  printf("Start tracing PID: %d\n", pid);
}

static void exit_trace(pid_t pid)
{
  int i;
  char *cwd;
  char trace_path[PATH_MAX];

  printf("Exit tracing PID: %d\n", pid);

  if (registration_verbose)
    printf("CSDEMO: Disable trace...\n");
  for (i = 0; i < board->n_cpu; ++i) {
    cs_trace_disable(devices.ptm[i]);
  }
  cs_sink_disable(devices.etb);
  if (devices.itm_etb != NULL) {
    cs_sink_disable(devices.itm_etb);
  }

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

#if SHOW_ETM_CONFIG
  for (i = 0; i < board->n_cpu; ++i) {
    show_etm_config(i);
  }
#endif

  do_fetch_trace(&devices, 0);

  if (registration_verbose)
    printf("CSDEMO: shutdown...\n");
  cs_shutdown();

  cwd = getcwd(NULL, 0);
  if (!cwd) {
    perror("getcwd");
    return;
  }
  memset(trace_path, 0, sizeof(trace_path));
  snprintf(trace_path, sizeof(trace_path), "%s/%s", cwd, trace_name);
  export_decoder_args(trace_path, decoder_args_path, range, range_count);

  printf("Trace range:\n");
  dump_mem_range(range, range_count);

  if (cwd) {
    free(cwd);
  }
}

static void suspend_trace(void)
{
  int i;

  if (registration_verbose)
    printf("CSDEMO: Disable trace...\n");
  for (i = 0; i < board->n_cpu; ++i) {
    cs_trace_disable(devices.ptm[i]);
  }
  cs_sink_disable(devices.etb);
  if (devices.itm_etb != NULL) {
    cs_sink_disable(devices.itm_etb);
  }

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

  do_fetch_trace(&devices, 0);

  if (registration_verbose)
    printf("CSDEMO: shutdown...\n");
  cs_shutdown();
}

static void resume_trace(pid_t pid)
{
  start_trace(pid);
}

void child(char *argv[])
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execvp(argv[0], argv);
}

void parent(pid_t pid)
{
  int wstatus;
  bool is_first_exec;
  bool trace_started;
  struct user_pt_regs regs;
  struct iovec iov;
  long syscall_num;
  bool is_entered_mmap;
  const long mmap_syscall = 222;

  void *addr;
  size_t length;
  int prot;
  int fd;
  char fd_path[PATH_MAX];

  is_first_exec = true;
  trace_started = false;
  is_entered_mmap = false;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    if (is_first_exec == true) {
      is_first_exec = false;
      start_trace(pid);
      trace_started = true;
    }
  }
  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  ptrace(PTRACE_CONT, pid, 0, 0);

  while (1) {
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus) && trace_started == true) {
      exit_trace(pid);
      trace_started = false;
      return;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);
      ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
      syscall_num = regs.regs[8];
      // TODO: It should support mprotect
      if (syscall_num == mmap_syscall) {
        if (is_entered_mmap == true) {
          addr = (void *)regs.regs[0];
          length = regs.regs[1];
          prot = regs.regs[2];
          fd = regs.regs[4];
          if ((prot & PROT_EXEC) && fd > 2) {
            if (range_count < RANGE_MAX) {
              suspend_trace();
              trace_started = false;

              memset(fd_path, 0, sizeof(fd_path));
              snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
              readlink(fd_path, range[range_count].path, PATH_MAX);

              range[range_count].start = (unsigned long)addr;
              range[range_count].end = ALIGN_UP((unsigned long)addr + length, PAGE_SIZE);
              printf("Added [0x%lx-0x%lx]: %s\n",
                  range[range_count].start,
                  range[range_count].end,
                  range[range_count].path);
              range_count += 1;

              resume_trace(pid);
              trace_started = true;
            } else {
              fprintf(stderr, "** addr_range_count: %d\n", range_count);
            }
          }
          is_entered_mmap = false;
        } else {
          is_entered_mmap = true;
        }
      }
    }
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  }
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s EXE\n", argv[0]);
    exit(EXIT_SUCCESS);
  }

  pid_t pid;

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
}
