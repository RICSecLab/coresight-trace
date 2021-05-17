#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

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
  bool is_first_exec;

  is_first_exec = true;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    if (is_first_exec == true) {
      is_first_exec = false;
      start_trace(pid);
    }
  }
  ptrace(PTRACE_CONT, pid, 0, 0);

  waitpid(pid, &wstatus, 0);
  if (WIFEXITED(wstatus)) {
    exit_trace(pid);
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
