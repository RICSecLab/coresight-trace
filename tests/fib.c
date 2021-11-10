/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

int main()
{
  int a[11];

  a[0] = 1;
  a[1] = 1;

  for (int i = 2; i < 11; i++) {
    a[i] = a[i - 2] + a[i - 1];
  }

  return 0;
}
