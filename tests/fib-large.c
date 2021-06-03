#define N 0x10000

unsigned long a[N];

int main()
{
  a[0] = 1;
  a[1] = 1;

  for (int i = 2; i < N; i++) {
    a[i] = a[i - 2] + a[i - 1];
  }

  return 0;
}
