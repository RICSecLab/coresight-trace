/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_PROC_TRACE_H
#define PROC_TRACE_PROC_TRACE_H

#include <stdbool.h>
#include <sys/types.h>

void init_trace(pid_t parent_pid, pid_t pid);
void start_trace(pid_t pid);
void stop_trace(bool needs_decode, bool needs_free_trace_buf);

void child(char *argv[]);
void parent(pid_t pid, int *child_status);

#endif /* PROC_TRACE_PROC_TRACE_H */
