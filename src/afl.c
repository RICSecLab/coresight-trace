
#include "afl/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "proc-trace.h"
#include "afl.h"

#define TSL_FD (FORKSRV_FD - 1)

static unsigned char dummy[MAP_SIZE];
unsigned char *afl_area_ptr = dummy;

static int forkserver_installed = 0;
static int disable_caching = 1; /* FIXME: Caching is not available. */

unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned char is_persistent;

u8 *shared_buf;
u32 *shared_buf_len;
u8 sharedmem_fuzzing;

unsigned int afl_inst_rms = MAP_SIZE;

char *dec_path;
unsigned int afl_map_size = MAP_SIZE;

extern char **dec_args;
extern bool needs_rerun;

/* This is the other size of the same channel. Since timeouts are handled by
 * afl-fuzz simple killing the child, we can just wait until the pipe breaks. */
static void afl_wait_tsl(int fd) {
  if (disable_caching) {
    return;
  }
}

static void afl_map_shm_fuzz(void)
{
  char *id_str;

  id_str = getenv(SHM_FUZZ_ENV_VAR);
  if (id_str) {
    u32 shm_id = atoi(id_str);
    u8 *map = (u8 *)shmat(shm_id, NULL, 0);
    if (!map || map == (void *)-1) {
      perror("[AFL] ERROR: could not access fuzzing shared memory");
      exit(1);
    }
    shared_buf_len = (u32 *)map;
    shared_buf = map + sizeof(u32);

    if (getenv("AFL_DEBUG")) {
      fprintf(stderr, "[AFL] DEBUG: successfully got fuzzing shared memory\n");
    } else {
      fprintf(stderr, "[AFL] ERROR: variable for fuzzing shared memory is not set\n");
      exit(1);
    }
  }
}

void afl_setup(void)
{
  char *id_str;
  char *inst_r;
  int shm_id;

  /* XXX: proc-trace uses its own CPU affinity settings */
  if (!getenv("AFL_NO_AFFINITY")) {
    fprintf(stderr, "[AFL] ERROR: AFL_NO_AFFINITY must be set to use CoreSight mode\n");
    exit(1);
  }

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
  pid_t child_pid;
  int t_fd[2];
  u8 child_stopped = 0;
  u32 was_killed;
  int status;

  if (forkserver_installed == 1) {
    return;
  }
  forkserver_installed = 1;

  status = 0;
  if (MAP_SIZE <= FS_OPT_MAX_MAPSIZE) {
    status |= (FS_OPT_SET_MAPSIZE(MAP_SIZE) | FS_OPT_MAPSIZE);
  }
  if (sharedmem_fuzzing != 0) {
    status |= FS_OPT_SHDMEM_FUZZ;
  }
  if (status) {
    status |= (FS_OPT_ENABLED);
  }
  if (getenv("AFL_DEBUG")) {
    fprintf(stderr, "Debug: Sending status %08x\n", status);
  }
  memcpy(tmp, &status, 4);

  /* Tell the parent that we're alive. If the parent doesn't want
   * to talk, assume that we're not running in forkserver mode. */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    return;
  }

  afl_forksrv_pid = getpid();

  first_run = 1;

  if (sharedmem_fuzzing) {
    if (read(FORKSRV_FD, &was_killed, 4) != 4) {
      exit(2);
    }

    if ((was_killed & (0xffffffff & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ))) ==
        (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) {
      afl_map_shm_fuzz();
    } else {
      fprintf(stderr,
          "[AFL] ERROR: afl-fuzz is old and does not support"
          " shmem input");
      exit(1);
    }
  }

  /* All right, let's await orders... */
  while (1) {
    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, &was_killed, 4) != 4) {
      exit(2);
    }

    /* If we stopped the child in persistent mode, but there was a race
     * condition and afl-fuzz already issued SIGKILL, wriite off the old
     * process. */
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) {
        exit(8);
      }
    }

    if (!child_stopped) {
      /* Establish a channel with child to grab translation commands. We'll
       * read from t_fd[0], child will write to TSL_FD. */
      if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) {
        exit(3);
      }
      close(t_fd[1]);

      child_pid = fork();
      if (child_pid < 0) {
        exit(4);
      }

      if (!child_pid) {
        /* Child process. Close descriptors and run free. */
        afl_fork_child = 1;
        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        close(t_fd[0]);
        child(argv);
        return;
      }

      /* Parent. */
      close(TSL_FD);
    } else {
      /* Special handling for persistent mode: if the child is alive but
       * currently stopped, simple restart it with SIGCONT. */
      kill(child_pid, SIGCONT);
      child_stopped = 0;
    }

    /* Parent. */
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      exit(5);
    }

    /* Collect translation requests until child dies and closes the pipe. */
    afl_wait_tsl(t_fd[0]);

    parent(child_pid, &status);

    if (needs_rerun) {
      fprintf(stderr, "[AFL] ERROR: failed to retrieve bitmap\n");
      needs_rerun = false;
      status = -1;
      exit(11);
    }

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
     * a successfull run. In this case, we want to wake it up without forking
     * again. */
    if (WIFSTOPPED(status)) {
      child_stopped = 1;
    } else if (first_run && is_persistent) {
      fprintf(stderr, "[AFL] ERROR: no persistent iteration executed\n");
      exit(12);
    }

    first_run = 0;

    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
      exit(7);
    }
  }
}
