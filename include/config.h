/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_CONFIG_H
#define PROC_TRACE_CONFIG_H

#include <sys/types.h>

#include "csregistration.h"

#include "utils.h"

void cs_etb_flush_and_wait_stop(struct cs_devices_t *devices);
int init_etm(cs_device_t dev);
void show_etm_config(cs_device_t etm);
int configure_trace(const struct board *board, struct cs_devices_t *devices,
    struct addr_range *range, int range_count, pid_t pid);
int enable_trace(const struct board *board, struct cs_devices_t *devices);
int disable_trace(const struct board *board, struct cs_devices_t *devices);
int enable_trace_sinks(const struct board *board, struct cs_devices_t *devices);
int disable_trace_sinks(const struct board *board, struct cs_devices_t *devices);

#endif /* PROC_TRACE_CONFIG_H */
