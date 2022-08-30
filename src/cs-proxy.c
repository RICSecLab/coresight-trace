/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2019-2020 AFLplusplus Project. All rights reserved. */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef __ANDROID__
#include "afl/android-ashmem.h"
#endif
#include "afl/config.h"
#include "afl/types.h"
#include "afl/debug.h"

#include "config.h"
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <fcntl.h>

#define AFLCS_PROXY_NAME "afl-cs-proxy"
#define AFLCS_FORKSRV_FD (FORKSRV_FD - 3)
#define AFLCS_DEFAULT_CYCLE_CNT (1000)
#define AFLCS_CUSTOM_STATUS (-1)

char *__afl_proxy_name = AFLCS_PROXY_NAME;
u32 default_cycle_count = AFLCS_DEFAULT_CYCLE_CNT;

s32 fsrv_pid = -1;
s32 proxy_ctl_fd = -1;
s32 proxy_st_fd = -1;
u8 first_run = 1;
u8 no_forksrv = 0;
bool disable_all = false;

#ifdef EXEC_COUNT
u32 exec_count = 0;
#endif

/* TODO: Remove extern variables. */
extern int trace_cpu;
extern int decoder_cpu;
extern int udmabuf_num;
extern bool decoding_on;
extern unsigned char *trace_bitmap;
extern unsigned int trace_bitmap_size;
extern cov_type_t cov_type;

/* Error reporting to forkserver controller */

void send_forkserver_error(int error)
{
  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;
}

/* SHM setup. */

static void __afl_map_shm(void)
{
  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {
    u32 val = atoi(ptr);
    if (val > 0) trace_bitmap_size = val;
  }

  if (trace_bitmap_size > MAP_SIZE) {
    if (trace_bitmap_size > FS_OPT_MAX_MAPSIZE) {
      fprintf(stderr,
              "Error: %s *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_proxy_name, trace_bitmap_size);
      if (id_str) {
        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);
      }

    } else {
      fprintf(stderr,
              "Warning: %s will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_proxy_name, trace_bitmap_size);
    }
  }

  if (id_str) {
#ifdef USEMMAP
    const char *shm_file_path = id_str;
    int shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {
      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);
    }

    /* map the shared memory segment to the address space of the process */
    shm_base = mmap(0, trace_bitmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    shm_fd, 0);

    if (shm_base == MAP_FAILED) {
      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);
    }

    trace_bitmap = shm_base;
#else
    u32 shm_id = atoi(id_str);

    trace_bitmap = shmat(shm_id, 0, 0);

#endif

    if (trace_bitmap == (void *)-1) {
      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);
    }

    /* Write something into the bitmap so that the parent doesn't give up */

    trace_bitmap[0] = 1;
  }
}

/* Fork server logic. */

static void __afl_start_forkserver(char *argv[])
{
  u8 tmp[4] = {0, 0, 0, 0};
  u32 status = 0;
  int st_pipe[2], ctl_pipe[2];

  if (pipe(st_pipe) || pipe(ctl_pipe)) {
    PFATAL("pipe() failed");
  }

  fsrv_pid = fork();
  if (fsrv_pid < 0) {
    PFATAL("fork() failed");
  }

  if (!fsrv_pid) {
    /* Child Process */

    if (dup2(ctl_pipe[0], AFLCS_FORKSRV_FD) < 0) {
      PFATAL("dup2() failed");
    }
    if (dup2(st_pipe[1], AFLCS_FORKSRV_FD + 1) < 0) {
      PFATAL("dup2() failed");
    }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);

    execvp(argv[0], argv);

    FATAL("Error: execv to target failed\n");
  }

  /* Parent Process */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  proxy_ctl_fd = ctl_pipe[1];
  proxy_st_fd = st_pipe[0];

  if (read(proxy_st_fd, &tmp, 4) != 4) {
    PFATAL("read() failed");
  }
  memcpy(&status, tmp, 4);

  if (!status) {
    if (trace_bitmap_size <= FS_OPT_MAX_MAPSIZE)
      status |= (FS_OPT_SET_MAPSIZE(trace_bitmap_size) | FS_OPT_MAPSIZE);
    if (status) status |= (FS_OPT_ENABLED);
    memcpy(tmp, &status, 4);
  }

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    PFATAL("write() failed");
  }
}

static u32 __afl_next_testcase(u32 cycle_count)
{
  s32 was_killed, child_pid;

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &was_killed, 4) != 4) return 1;
  if (write(proxy_ctl_fd, &was_killed, 4) != 4) return -1;

  /* Wait for child by reading from the pipe. Abort if read fails. */
  if (read(proxy_st_fd, &child_pid, 4) != 4) return -1;

  if (unlikely(first_run)) {
    if (init_trace(fsrv_pid, child_pid) < 0) return -1;
    first_run = 0;
  }

  start_trace(child_pid, false, cycle_count == default_cycle_count);

  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) return -1;

  /* Resume child process. */
  kill(child_pid, SIGCONT);

  return child_pid;
}

static s32 __afl_end_testcase(s32 status)
{
  if (write(FORKSRV_FD + 1, &status, 4) != 4) return -1;

  return 0;
}

static s32 __afl_fauxsrv_execv(char *argv[])
{
  u8 tmp[4] = {0, 0, 0, 0};
  int status = 0;
  s32 was_killed, child_pid;
  u32 cycle_count;

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return -1;

  cycle_count = default_cycle_count;

  while (1) {
    /* Wait for parent by reading from the pipe. Abort if read fails. */
    if (read(FORKSRV_FD, &was_killed, 4) != 4) return -1;

    /* Create a clone of our process. */

    child_pid = fork();

    if (child_pid < 0) {
      PFATAL("Fork failed");
    }

    /* In child process: close fds, resume execution. */

    if (!child_pid) {
      /* TODO: Add SIGPIPE handling */

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        PFATAL("ptrace failed");
      }

      execvp(argv[0], argv);

      WARNF("Error: execv to target failed\n");
      break;
    }

    waitpid(child_pid, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == PTRACE_EVENT_VFORK_DONE) {
      init_trace(getpid(), child_pid);
      start_trace(child_pid, true, cycle_count == default_cycle_count);
      ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    }

    /* In parent process: write PID to AFL. */
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) return -1;

    /* Handle child process suspend/resume */
    while (1) {
      waitpid(child_pid, &status, 0);
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        trace_suspend_resume_callback();
      } else {
        /* Child process has exited. */
        break;
      }
    }

    if (--cycle_count) {
      if (stop_trace(disable_all) < 0) return -1;
    } else {
      /* cycle_count is 0. */
      if (stop_trace(true) < 0) return -1;
      cycle_count = default_cycle_count;
    }

    /* Relay wait status to AFL pipe, then loop back. */
    if (write(FORKSRV_FD + 1, &status, 4) != 4) return -1;

#ifdef EXEC_COUNT
    if (++exec_count > EXEC_COUNT) return 0;
#endif
  }

  return 0;
}

/* you just need to modify the while() loop in this main() */

int main(int argc, char *argv[])
{
  s32 status;
  int i;
  char **argvp;
  char *ptr;
  u32 cycle_count;

  if (argc < 3) {
    return -1;
  }

  argvp = NULL;
  registration_verbose = 0;
  decoding_on = true;

  /* here you specify the map size you need that you are reporting to
     afl-fuzz.  Any value is fine as long as it can be divided by 32. */
  trace_bitmap_size = MAP_SIZE;  // default is 65536
  __afl_proxy_name = argv[0];

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--") && i + 1 < argc) {
      argvp = &argv[++i];
      break;
    } else if (argc > 2 && i + 1 >= argc) {
      FATAL("Invalid option '%s'", argv[i]);
    }
  }

  /* Mark as AFL++ CoreSight mode is enabled. */
  setenv("__AFLCS_ENABLE", "1", 0);

  if (getenv("AFLCS_NO_FORKSRV")) {
    no_forksrv = 1;
  }

  if (getenv("AFLCS_STOP_ALL_DEV")) {
    disable_all = true;
  }

  if ((ptr = getenv("AFLCS_CYCLE_CNT")) != NULL) {
    default_cycle_count = atoi(ptr);
  }

  if ((ptr = getenv("AFLCS_COV")) != NULL) {
    if (!strcmp(ptr, "edge")) {
      cov_type = edge_cov;
    } else if (!strcmp(ptr, "path")) {
      cov_type = path_cov;
    } else {
      FATAL("Error: unknown coverage type '%s'", ptr);
    }
  }

  if ((ptr = getenv("AFLCS_UDMABUF")) != NULL) {
    udmabuf_num = atoi(ptr);
  }

  if ((ptr = getenv("AFLCS_TRACE_CPU")) != NULL) {
    trace_cpu = atoi(ptr);
  }

  if ((ptr = getenv("AFLCS_DECODER_CPU")) != NULL) {
    decoder_cpu = atoi(ptr);
  }

  /* then we initialize the shared memory map and start the forkserver */
  __afl_map_shm();

  if (no_forksrv) {
    return __afl_fauxsrv_execv(argvp);
  }

  __afl_start_forkserver(argvp);

  cycle_count = default_cycle_count;

  while (__afl_next_testcase(cycle_count) > 0) {
    /* Handle child process suspend/resume */
    while (1) {
      if (read(proxy_st_fd, &status, 4) != 4) return -1;
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        trace_suspend_resume_callback();
      } else {
        /* Child process has exited. */
        break;
      }
    }

    if (--cycle_count) {
      if (stop_trace(disable_all) < 0) {
        status = AFLCS_CUSTOM_STATUS;
      }
    } else {
      /* cycle_count is 0. */
      if (stop_trace(true) < 0) {
        status = AFLCS_CUSTOM_STATUS;
      }
      cycle_count = default_cycle_count;
    }

    /* report the test case is done and wait for the next */
    if (__afl_end_testcase(status) < 0) return -1;

#ifdef EXEC_COUNT
    if (++exec_count > EXEC_COUNT) return 0;
#endif
  }

  return 0;
}
