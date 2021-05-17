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
#include <sys/uio.h>

#include <linux/elf.h>
#include <asm/ptrace.h>

extern char **environ;

#if defined(__aarch64__)
static void dump_regs(struct user_pt_regs *regs)
{
#if 0
  printf("regs[8]: %lld\n", regs->regs[8]);
  for (int i = 0; i < 31; i++) {
    if (regs->regs[i] == 221) {
      printf("regs[%d]: 0x%llx\n", i, regs->regs[i]);
    }
  }
#endif
}
#endif

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
#if defined(__x86_64__)
  struct user_regs_struct regs;
#elif defined(__aarch64__)
  struct user_pt_regs regs;
  struct iovec io;
#endif
  unsigned long syscall;
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
    return;
  }
#if 0
  ptrace(PTRACE_SETOPTIONS, pid, NULL,
        PTRACE_O_EXITKILL
      | PTRACE_O_TRACECLONE
      | PTRACE_O_TRACEEXEC
      | PTRACE_O_TRACEEXIT
      | PTRACE_O_TRACEFORK
      | PTRACE_O_TRACESYSGOOD
      | PTRACE_O_TRACEVFORK
      | PTRACE_O_TRACEVFORKDONE
      | PTRACE_O_TRACESECCOMP
      | PTRACE_O_SUSPEND_SECCOMP);
  while (1) {
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
      exit_trace(pid);
      return;
    } else if (WIFSTOPPED(wstatus)) {
      printf("stop reason: %d\n", WSTOPSIG(wstatus));
      if (WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
        if (is_first_exec == true) {
          is_first_exec = false;
          start_trace(pid);
        }
        ptrace(PTRACE_CONT, pid, 0, 0);
      }
    }
  }
#endif

#if 0
  while (1) {
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
      exit_trace(pid);
      break;
    } else if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
#if defined(__x86_64__)
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      syscall = regs.orig_rax;
#elif defined(__aarch64__)
      io.iov_base = &regs;
      io.iov_len = sizeof(regs);
      ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io);
      dump_regs(&regs);
      syscall = regs.regs[8];
#endif
      if (is_first_exec == true) {
        switch (syscall) {
          case SYS_execve:
          //case SYS_vfork:
            is_first_exec = false;
            start_trace(pid);
            break;
          default:
            break;
        }
      }
    }
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  }
#endif
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
