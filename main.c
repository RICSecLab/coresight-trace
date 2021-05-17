#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

static void start_trace(pid_t pid)
{
  // TODO:
  printf("TODO: Start tracing PID: %d\n", pid);
}

static void exit_trace(pid_t pid)
{
  // TODO:
  printf("TODO: Exit tracing PID: %d\n", pid);
}

void child(char *argv[])
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execv(argv[0], argv);
}

void parent(pid_t pid)
{
  int wstatus;
  struct user_regs_struct regs;
  bool is_first_exec;

  is_first_exec = true;

  while (1) {
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
      exit_trace(pid);
      break;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#if defined(__x86_64__)
      if (regs.orig_rax == SYS_execve && is_first_exec == true) {
        is_first_exec = false;
        start_trace(pid);
      }
#endif
    }
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  }
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s EXE\n", argv[0]);
  }

  pid_t pid;

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
