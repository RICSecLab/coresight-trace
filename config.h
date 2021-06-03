/* SPDX-License-Identifier: Apache-2.0 */

#ifndef PROC_TRACE_CONFIG_H
#define PROC_TRACE_CONFIG_H

#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"

#include "utils.h"

#define SHOW_ETM_CONFIG 0

int init_etm(cs_device_t dev);
int configure_trace(const struct board *board, struct cs_devices_t *devices,
    struct addr_range *range, int range_count);
int enable_trace(const struct board *board, struct cs_devices_t *devices);

#endif /* PROC_TRACE_CONFIG_H */
