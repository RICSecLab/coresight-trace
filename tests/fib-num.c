#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main(int argc, char *argv[])
{
  long num;
  unsigned long prev, curr, next;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s NUM\n", argv[0]);
    return -1;
  }

  num = strtol(argv[1], NULL, 0);
  if (num == LONG_MIN || num == LONG_MAX) {
    perror("strtol");
    return -1;
  } else if (num <= 0) {
    fprintf(stderr, "NUM must be positive number\n");
    return -1;
  }

  prev = 0;
  curr = 1;

  for (unsigned long i = 0; i < (unsigned long)num; i++) {
    next = prev + curr;
    prev = curr;
    curr = next;
  }

  printf("%lu: %lu\n", num, next);

  return 0;
}
