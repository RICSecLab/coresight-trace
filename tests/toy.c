#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 190
unsigned char buf[MAX_BUF];
typedef struct{
  unsigned char raw[128];
  unsigned int checksum;
  unsigned int checksum2;
}simple_format;

void crash(int id) {
  printf("Congratulation!\nYou got a crash (id: %d)\n", id);  
  *((unsigned int *)1) = 1;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage ./toy <input-file>\n");
    exit(EXIT_FAILURE);
  }

  FILE *fp;
  if ((fp = fopen(argv[1], "r")) == NULL) {
    fprintf(stderr, "Failed to open %s\n", argv[1]);
    exit(EXIT_FAILURE);
  }

  fread(buf, sizeof(char), MAX_BUF, fp);
  fclose(fp);

  printf("Read %s\n", buf);

  /* Check magic number (short) */
  if (buf[0] == 0xde) {
    if (buf[1] == 0xad) {
      if (buf[2] == 0xbe) {
        if (buf[3] == 0xef) {
          crash(0);
        }
      }
    }
  }
  if (buf[0] == 0xca) {
    if (buf[1] == 0xfe) {
      if (buf[2] > 0x10) {
        crash(1);
      }
    }
  }

  return 0;
}
