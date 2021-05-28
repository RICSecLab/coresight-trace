#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_SIZE 30000

char data[DATA_SIZE];

void run(char *code)
{
  char *code_ptr = code;
  char *data_ptr = data;
  char *code_end = code + strlen(code);

  while (code_ptr < code_end) {
    switch (*code_ptr) {
      case '>':
        data_ptr++;
        break;
      case '<':
        data_ptr--;
        break;
      case '+':
        (*data_ptr)++;
        break;
      case '-':
        (*data_ptr)--;
        break;
      case '.':
        putchar(*data_ptr);
        break;
      case ',':
        *data_ptr = (char)getchar();
        break;
      case '[':
        if (!(*data_ptr)) {
          int count = 1;
          while (count > 0) {
            code_ptr++;
            if (*code_ptr == '[') {
              count++;
            } else if (*code_ptr == ']') {
              count--;
            }
          }
        }
        break;
      case ']':
        if (*data_ptr) {
          int count = 1;
          while (count > 0) {
            code_ptr--;
            if (*code_ptr == ']') {
              count++;
            } else if (*code_ptr == '[') {
              count--;
            }
          }
        }
        break;
      default:
        puts("Invalid code");
    }
    code_ptr++;
  }
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    return -1;
  }

  char *code = argv[1];

  run(code);

  return 0;
}
