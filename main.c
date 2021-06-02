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

#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))
#define PAGE_SIZE 0x1000

#define DUMP_CONFIG 1
#define SHOW_ETM_CONFIG 0
#define TRACE_CPU 0

const char *decoder_args_path = "decoderargs.txt";
const char *board_name = "Marvell ThunderX2";

static struct cs_devices_t devices;
const struct board *board;

static int cpu = TRACE_CPU;
static cpu_set_t affinity_mask;

extern int registration_verbose;

extern const struct board known_boards[];

struct addr_range {
    unsigned long start;
    unsigned long end;
    char path[PATH_MAX];
} addr_range_cmps[ETMv4_NUM_ADDR_COMP_MAX / 2];
int addr_range_count = 0;

static void dump_mem_range(void)
{
  int i;

  for (i = 0; i < addr_range_count; i++) {
    printf("[0x%lx-0x%lx]: %s\n",
        addr_range_cmps[i].start,
        addr_range_cmps[i].end,
        addr_range_cmps[i].path);
  }
}

static int get_mem_range(pid_t pid)
{
  FILE *fp;
  char maps_path[PATH_MAX];
  char *line;
  size_t n;
  ssize_t readn;
  unsigned long start_addr;
  unsigned long end_addr;
  char c;
  char x;
  int count;
  char *p;

  memset(maps_path, 0, sizeof(maps_path));
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  fp = fopen(maps_path, "r");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  line = NULL;
  n = 0;
  readn = 0;
  count = 0;
  while ((readn = getline(&line, &n, fp)) != -1) {
    if (readn > 0 && line[readn - 1] == '\n') {
      line[readn - 1] = '\0';
      readn--;
    }
    sscanf(line, "%lx-%lx %c%c%c", &start_addr, &end_addr, &c, &c, &x);
    if (x == 'x') {
      if (count < ETMv4_NUM_ADDR_COMP_MAX / 2) {
        // FIXME: The below registers an exec region with absolute path only
        // It means vDSO is not traced.
        for (p = line; *p != '\0' && *p != '/'; p++) {
        }
        if (*p == '/') {
          strncpy(addr_range_cmps[count].path, p, PATH_MAX - 1);
          addr_range_cmps[count].path[PATH_MAX - 1] = '\0';
          addr_range_cmps[count].start = start_addr;
          addr_range_cmps[count].end = end_addr;
          count += 1;
        }
      } else {
        fprintf(stderr, "** WARNING: address range [0x%lx-0x%lx] will not trace\n", start_addr, end_addr);
      }
    }
  }

  if (line != NULL) {
    free(line);
  }
  addr_range_count = count;
  return count;
}

static int export_decoder_args(const char *args_path)
{
  const char *trace_name = "cstrace.bin"; // TODO: It depends on CSAL
  char trace_path[PATH_MAX];
  char *cwd;
  //const int trace_id = 0x10; // TODO: Use CPU ID to trace ID table
  // addr_range_count
  FILE *fp;
  int i;
  int ret;

  if (args_path == NULL) {
    return -1;
  }

  fp = fopen(args_path, "w");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  cwd = getcwd(NULL, 0);
  if (cwd == NULL) {
    perror("getcwd");
    ret = -1;
    goto exit;
  }
  memset(trace_path, 0, sizeof(trace_path));
  snprintf(trace_path, sizeof(trace_path), "%s/%s", cwd, trace_name);
  if ((ret = fprintf(fp, " %s", trace_path)) < 0) {
    goto exit;
  }
  if ((ret = fprintf(fp, " %d", addr_range_count)) < 0) {
    goto exit;
  }
  for (i = 0; i < addr_range_count; i++) {
    ret = fprintf(fp, " %s 0x%lx 0x%lx",
        addr_range_cmps[i].path,
        addr_range_cmps[i].start,
        addr_range_cmps[i].end);
    if (ret < 0) {
      goto exit;
    }
  }

  ret = 0;

exit:
  if (cwd != NULL) {
    free(cwd);
  }

  fclose(fp);

  if (ret < 0) {
    fprintf(stderr, "** WARNING: Failed to write decoder arguments\n");
  }

  return ret;
}

static void start_trace(pid_t pid)
{
  if (get_mem_range(pid) < 0) {
    fprintf(stderr, "get_mem_range() failed\n");
    return;
  }

  printf("Trace range:\n");
  dump_mem_range();

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

  if (configure_trace(board, &devices) < 0) {
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

  export_decoder_args(decoder_args_path);

  printf("Trace range:\n");
  dump_mem_range();
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
#if 0
  printf("resume trace\n");
  //
  // TODO: Use our own board setup
  if (setup_known_board_by_name(board_name, &board, &devices) < 0) {
    fprintf(stderr, "setup_known_board_by_name() failed\n");
    return;
  }

  if (do_configure_trace(board) < 0) {
    fprintf(stderr, "do_configure_trace() failed\n");
    return;
  }

#if DUMP_CONFIG
  printf("dumping config with %s\n", itm ? "ITM enabled" : "No ITM");
  do_dump_config(board, &devices, itm);
#endif
  cs_checkpoint();

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));
#endif
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
  struct addr_range *range;
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
            if (addr_range_count < ETMv4_NUM_ADDR_COMP_MAX / 2) {
              range = &addr_range_cmps[addr_range_count];

              suspend_trace();
              trace_started = false;

              memset(fd_path, 0, sizeof(fd_path));
              snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd);
              readlink(fd_path, range->path, PATH_MAX);

              range->start = (unsigned long)addr;
              range->end = ALIGN_UP((unsigned long)addr + length, PAGE_SIZE);
              addr_range_count += 1;
              printf("Added [0x%lx-0x%lx]: %s\n",
                  range->start,
                  range->end,
                  range->path);

              resume_trace(pid);
              trace_started = true;
            } else {
              fprintf(stderr, "** addr_range_count: %d\n", addr_range_count);
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
