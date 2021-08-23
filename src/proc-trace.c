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

#include "common.h"
#include "config.h"
#include "utils.h"

extern int registration_verbose;

extern char *board_name;
extern struct cs_devices_t devices;
extern bool tracing_on;
extern bool decoding_on;
extern int trace_cpu;
extern bool export_config;
extern int range_count;
extern struct addr_range range[RANGE_MAX];
extern bool trace_started;

extern unsigned long etr_ram_addr;
extern size_t etr_ram_size;
extern bool etr_mode;

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

  trace_started = false;
  is_entered_mmap = false;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    init_trace(getpid(), pid);
    start_trace(pid, true);
  }

  while (1) {
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
      if (tracing_on && trace_started == true) {
        stop_trace();
        fini_trace();
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
      trace_suspend_resume_callback();
    }
  }

  if (child_status) {
    *child_status = wstatus;
  }
}

static void usage(char *argv0)
{
  fprintf(stderr, "Usage: %s [OPTIONS] -- EXE [ARGS]\n", argv0);
  fprintf(stderr, "CoreSight process tracer\n");
  fprintf(stderr, "[OPTIONS]\n");
  fprintf(stderr, "  --cpu=INT\t\t\tbind traced process to CPU (default: %d)\n", trace_cpu);
  fprintf(stderr, "  --tracing={0,1}\t\tenable tracing (default: %d)\n", tracing_on);
  fprintf(stderr, "  --decoding={0,1}\t\tenable trace decoding (default: %d)\n", decoding_on);
  fprintf(stderr, "  --export-config={0,1}\t\tenable exporting config (default: %d)\n", export_config);
  fprintf(stderr, "  --verbose=INT\t\t\tverbose output level (default: %d)\n", registration_verbose);
  fprintf(stderr, "  --help\t\t\tshow this help\n");
}

int main(int argc, char *argv[])
{
  char **argvp;
  pid_t pid;
  int i;
  int n;
  char junk;

  argvp = NULL;
  registration_verbose = 0;

  if (argc < 3) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--board") == 0 && i + 1 < argc) {
      board_name = argv[++i];
    } else if (sscanf(argv[i], "--cpu=%d%c", &n, &junk) == 1) {
      trace_cpu = n;
    } else if (sscanf(argv[i], "--tracing=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      tracing_on = n ? true : false;
    } else if (sscanf(argv[i], "--etr=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      etr_mode = n ? true : false;
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
