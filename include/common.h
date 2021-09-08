/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef CS_TRACE_COMMON_H
#define CS_TRACE_COMMON_H

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
  edge_cov,
  path_cov,
} cov_type_t;

int fetch_trace(void);
int decode_trace(void);
int init_trace(pid_t parent_pid, pid_t pid);
void fini_trace(void);
int start_trace(pid_t pid, bool use_pid_trace);
int stop_trace();
void trace_suspend_resume_callback(void);

#endif /* CS_TRACE_COMMON_H */
