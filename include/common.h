/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_COMMON_H
#define PROC_TRACE_COMMON_H

#include <stdbool.h>
#include <sys/types.h>

void init_trace(pid_t parent_pid, pid_t pid);
void fini_trace(void);
void start_trace(pid_t pid, bool use_pid_trace);
int stop_trace(bool needs_decode, bool needs_free_trace_buf);

#endif /* PROC_TRACE_COMMON_H */
