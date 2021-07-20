/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_PROC_TRACE_H
#define PROC_TRACE_PROC_TRACE_H

#include <sys/types.h>

void afl_init_trace(pid_t afl_forksrv_pid, pid_t pid);
void afl_start_trace(pid_t pid);
void afl_stop_trace(void);

void child(char *argv[]);
void parent(pid_t pid, int *child_status);

#endif /* PROC_TRACE_PROC_TRACE_H */
