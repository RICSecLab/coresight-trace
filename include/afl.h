/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_AFL_H
#define PROC_TRACE_AFL_H

void afl_setup(void);
void afl_forkserver(char *argv[]);

#endif /* PROC_TRACE_AFL_H */
