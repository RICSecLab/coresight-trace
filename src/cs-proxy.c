/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "afl/common.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"

#include "config.h"
#include "common.h"

#define AFLCS_FORKSRV_FD (FORKSRV_FD - 3)

static bool forkserver_mode = true;
static int forkserver_installed = 0;

unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned char is_persistent;
pid_t child_pid = 0;

unsigned int afl_inst_rms = MAP_SIZE;

extern int registration_verbose;

extern bool decoding_on;
extern unsigned char *afl_area_ptr;
extern unsigned int afl_map_size;

static void afl_exit(int status)
{
  if (afl_forksrv_pid) {
    kill(afl_forksrv_pid, SIGKILL);
  }
  exit(status);
}

void afl_setup(void)
{
  char *id_str;
  char *inst_r;
  int shm_id;

  setenv("__AFLCS_ENABLE", "1", 0);

  inst_r = getenv("AFL_INST_RATIO");
  if (inst_r) {
    unsigned int r;

    r = atoi(inst_r);

    if (r  > 100) {
      r = 100;
    }
    if (!r) {
      r = 1;
    }

    afl_inst_rms = MAP_SIZE * r / 100;
  }

  id_str = getenv(SHM_ENV_VAR);
  if (id_str) {
    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void *)-1) {
      exit(1);
    }

    /* With AFL_INST_RATIO set to low value, we want to touch the bitmap
     * so that the parent doesn't give up on us. */
    if (inst_r) {
      afl_area_ptr[0] = 1;
    }
  }

  /* TODO: Support persistent mode */
}

void afl_forkserver(char *argv[])
{
  unsigned char tmp[4] = {0};
  int first_run;
  int proxy_st_pipe[2];
  int proxy_ctl_pipe[2];
  int proxy_st_fd;
  int proxy_ctl_fd;
  u8 child_stopped = 0;
  u32 was_killed;
  int status;

  if (forkserver_installed == 1) {
    return;
  }
  forkserver_installed = 1;

  if (pipe(proxy_st_pipe) || pipe(proxy_ctl_pipe)) {
    fprintf(stderr, "[AFL] ERROR: pipe() failed\n");
    exit(1);
  }

  afl_forksrv_pid = fork();
  if (afl_forksrv_pid < 0) {
    fprintf(stderr, "[AFL] ERROR: fork() failed\n");
    exit(2);
  }

  if (!afl_forksrv_pid) {
    /* Child process. Close descriptors and run free. */
    if (dup2(proxy_ctl_pipe[0], AFLCS_FORKSRV_FD) < 0) {
      fprintf(stderr, "[AFL] ERROR: dup2() failed\n");
      exit(3);
    }
    if (dup2(proxy_st_pipe[1], AFLCS_FORKSRV_FD + 1) < 0) {
      fprintf(stderr, "[AFL] ERROR: dup2() failed\n");
      exit(4);
    }
    afl_fork_child = 1;
    close(proxy_ctl_pipe[0]);
    close(proxy_ctl_pipe[1]);
    close(proxy_st_pipe[0]);
    close(proxy_st_pipe[1]);
    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);

    execvp(argv[0], argv);

    return;
  }

  /* Parent. */
  close(proxy_ctl_pipe[0]);
  close(proxy_st_pipe[1]);
  proxy_ctl_fd = proxy_ctl_pipe[1];
  proxy_st_fd = proxy_st_pipe[0];

  if (read(proxy_st_fd, tmp, 4) != 4) {
    afl_exit(5);
  }

  memcpy(&status, tmp, 4);
  if (getenv("AFL_DEBUG")) {
    fprintf(stderr, "Debug: Sending status %08x\n", status);
  }

  /* Tell the parent that we're alive. If the parent doesn't want
   * to talk, assume that we're not running in forkserver mode. */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    afl_exit(6);
  }

  first_run = 1;

  /* All right, let's await orders... */
  while (1) {
    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, &was_killed, 4) != 4) {
      afl_exit(7);
    }

    if (write(proxy_ctl_fd, &was_killed, 4) != 4) {
      afl_exit(8);
    }

    /* If we stopped the child in persistent mode, but there was a race
     * condition and afl-fuzz already issued SIGKILL, wriite off the old
     * process. */
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) {
        afl_exit(9);
      }
    }

    if (!child_stopped) {
      /* Wait for target by reading from the pipe. */
      if (read(proxy_st_fd, &child_pid, 4) != 4) {
        afl_exit(10);
      }
    } else {
      /* Special handling for persistent mode: if the child is alive but
       * currently stopped, simple restart it with SIGCONT. */
      kill(child_pid, SIGCONT);
      child_stopped = 0;
    }

    /* Parent. */
    if (first_run) {
      init_trace(afl_forksrv_pid, child_pid);
      first_run = 0;
    }
    start_trace(child_pid, false);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      afl_exit(11);
    }

    /* Resume child process. */
    kill(child_pid, SIGCONT);

    while (1) {
      if (read(proxy_st_fd, &status, 4) != 4) {
        afl_exit(12);
      }
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        trace_suspend_resume_callback();
      } else {
        /* The child process exited. */
        break;
      }
    }

    if (stop_trace() < 0) {
      afl_exit(13);
    }

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
     * a successfull run. In this case, we want to wake it up without forking
     * again. */
    if (WIFSTOPPED(status)) {
      child_stopped = 1;
    } else if (first_run && is_persistent) {
      fprintf(stderr, "[AFL] ERROR: no persistent iteration executed\n");
      afl_exit(14);
    }

    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
      afl_exit(15);
    }
  }
}

int main(int argc, char *argv[])
{
  char **argvp;
  int i;
  int n;
  char junk;

  argvp = NULL;
  registration_verbose = 0;
  decoding_on = true;

  if (argc < 3) {
    exit(EXIT_FAILURE);
  }

  for (i = 1; i < argc; i++) {
    if (sscanf(argv[i], "--forkserver=%d%c", &n, &junk) == 1
        && (n == 0 || n == 1)) {
      forkserver_mode = n ? true : false;
    } else if (!strcmp(argv[i], "--") && i + 1 < argc) {
      argvp = &argv[++i];
      break;
    } else if (argc > 2 && i + 1 >= argc) {
      fprintf(stderr, "Invalid option '%s'\n", argv[i]);
      exit(EXIT_FAILURE);
    }
  }

  if (!forkserver_mode || !argvp) {
    exit(EXIT_FAILURE);
  }

  afl_setup();
  afl_forkserver(argvp);

  return 0;
}
