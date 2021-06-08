/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"

const bool return_stack = true;

extern pid_t trace_pid;
extern int etb_stop_on_flush;
extern int registration_verbose;

void cs_etb_flush_and_wait_stop(struct cs_devices_t *devices)
{
  unsigned int ffcr_val, ffsr_val;
  ffcr_val = cs_device_read(devices->etb, CS_ETB_FLFMT_CTRL);
  ffcr_val |= CS_ETB_FLFMT_CTRL_FOnMan;
  cs_device_write(devices->etb, CS_ETB_FLFMT_CTRL, ffcr_val);
  if (cs_device_wait(devices->etb, CS_ETB_FLFMT_STATUS,
        CS_ETB_FLFMT_STATUS_FtStopped, CS_REG_WAITBITS_ALL_1, 0, &ffsr_val)
      == 0) {
  } else {
    fprintf(stderr, "ETB collection not stopped on flush on trigger. FFSR: 0x%08x\n", ffsr_val);
  }
}

void show_etm_config(cs_device_t etm)
{
    cs_etmv4_config_t t4config;	/* ETMv4 config */
    void *p_config = 0;

    if (CS_ETMVERSION_MAJOR(cs_etm_get_version(etm)) >= CS_ETMVERSION_ETMv4)
        p_config = &t4config;
    else
      return;

    cs_etm_config_init_ex(etm, p_config);
    t4config.flags = CS_ETMC_ALL;
    cs_etm_config_get_ex(etm, p_config);
    cs_etm_config_print_ex(etm, p_config);
}

static void set_etmv4_addr_range(struct addr_range *range,
    struct _adrcmp *addr_comp, unsigned int acc_type_ex)
{
    const unsigned int acc_type
      = CS_ETMV4_ACATR_ExEL0_S
      | CS_ETMV4_ACATR_ExEL1_S
      | CS_ETMV4_ACATR_ExEL2_S
      | CS_ETMV4_ACATR_ExEL1_NS
      | CS_ETMV4_ACATR_ExEL2_NS
      | acc_type_ex;

    if (!range || !addr_comp) {
        return;
    }


    addr_comp[0].acvr_l = range->start & 0xFFFFFFFF;
    addr_comp[0].acvr_h = (range->start >> 32) & 0xFFFFFFFF;
    addr_comp[0].acatr_l = acc_type;
    addr_comp[1].acvr_l = range->end & 0xFFFFFFFF;
    addr_comp[1].acvr_h = (range->end >> 32) & 0xFFFFFFFF;
    addr_comp[1].acatr_l = acc_type;
}

static int configure_etmv4_addr_range(cs_device_t etm,
    struct addr_range *range, int range_count)
{
    cs_etmv4_config_t tconfig;
    int i, error_count;

    /* default settings are trace everything - already set. */
    cs_etm_config_init_ex(etm, &tconfig);
    tconfig.flags =
        CS_ETMC_TRACE_ENABLE | CS_ETMC_CONFIG | CS_ETMC_EVENTSELECT;
    cs_etm_config_get_ex(etm, &tconfig);

    if (tconfig.scv4->idr2.bits.vmidsize > 0)
        tconfig.configr.bits.vmid = 1;	/* VMID trace enable */
    if (tconfig.scv4->idr2.bits.cidsize > 0)
        tconfig.configr.bits.cid = 1;	/* context ID trace enable. */

    if (return_stack)
        tconfig.configr.bits.rs = 1; /* set the return stack */

    for (i = 0; i < range_count; i++) {
        set_etmv4_addr_range(&range[i], &tconfig.addr_comps[i * 2], 0);
        tconfig.addr_comps_acc_mask |= 0x3 << (i * 2);
        /* program the address comp pair i for include */
        tconfig.viiectlr |= 1 << i;
    }

    /* mark the config structure to program the above registers on 'put' */
    tconfig.flags |= CS_ETMC_ADDR_COMP;
    tconfig.syncpr = 0xc;	/* 4096 bytes per sync */

    cs_etm_config_put_ex(etm, &tconfig);

    if (registration_verbose > 0) {
        /* Show the resulting configuration */
        show_etm_config(etm);
    }

    error_count = cs_error_count();
    if (error_count > 0) {
        fprintf(stderr, "%u errors reported when configuring ETM\n", error_count);
        return -1;
    }

    return 0;
}

static int configure_etmv4_addr_range_cid(cs_device_t etm,
    struct addr_range *range, int range_count, unsigned long cid)
{
    cs_etmv4_config_t tconfig;
    struct addr_range sys_range;
    int error_count;
    size_t cididx;
    size_t addridx;

    /* default settings are trace everything - already set. */
    cs_etm_config_init_ex(etm, &tconfig);
    tconfig.flags =
        CS_ETMC_TRACE_ENABLE | CS_ETMC_CONFIG | CS_ETMC_EVENTSELECT;
    cs_etm_config_get_ex(etm, &tconfig);

    if (tconfig.scv4->idr2.bits.vmidsize > 0)
        /* XXX: VMID trace must be disabled to use context ID trace only. */
        tconfig.configr.bits.vmid = 0;
    if (tconfig.scv4->idr2.bits.cidsize > 0)
        tconfig.configr.bits.cid = 1;	/* context ID trace enable. */

    if (return_stack)
        tconfig.configr.bits.rs = 1; /* set the return stack */

    cididx = 0;
    tconfig.cxid_comps[cididx].cidcvr_l = cid & 0xFFFFFFFF;
    tconfig.cxid_comps[cididx].cidcvr_h = (cid >> 32) & 0xFFFFFFFF;
    tconfig.cidcctlr0 &= ~(1 << cididx);
    tconfig.cxid_comps_acc_mask |= (1 << cididx);
    tconfig.flags |= CS_ETMC_CXID_COMP;

    addridx = 0;
    /* XXX: Assuming range[0] is the tracee itself. */
    set_etmv4_addr_range(&range[0], &tconfig.addr_comps[addridx],
        (cididx << 4) | (0x1 << 2)); /* Add and enable Context ID filtering */
    tconfig.addr_comps_acc_mask |= 0x3 << addridx;
    tconfig.viiectlr |= 1 << (addridx / 2);

    addridx = 2;
    /* Add [ffff00000000-ffffffffffff] */
    sys_range.start = 0xffff00000000;
    sys_range.end = 0xffffffffffff;
    set_etmv4_addr_range(&sys_range, &tconfig.addr_comps[addridx],
        (cididx << 4) | (0x1 << 2)); /* Add and enable Context ID filtering */
    tconfig.addr_comps_acc_mask |= 0x3 << addridx;
    tconfig.viiectlr |= 1 << (addridx / 2);

    tconfig.flags |= CS_ETMC_ADDR_COMP;

    /* mark the config structure to program the above registers on 'put' */
    tconfig.syncpr = 0xc;	/* 4096 bytes per sync */

    cs_etm_config_put_ex(etm, &tconfig);

    if (registration_verbose > 0) {
        /* Show the resulting configuration */
        show_etm_config(etm);
    }

    error_count = cs_error_count();
    if (error_count > 0) {
        fprintf(stderr, "%u errors reported when configuring ETM\n", error_count);
        return -1;
    }

    return 0;
}

int init_etm(cs_device_t dev)
{
    int rc;
    cs_etmv4_config_t v4config;
    int etm_version = cs_etm_get_version(dev);

    /* ASSERT that this is an etm etc */
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));

    /* set to a 'clean' state - clears events & values, retains ctrl and ID, ensure programmable */
    if ((rc = cs_etm_clean(dev)) != 0) {
        fprintf(stderr, "Failed to set ETM/PTM into clean state\n");
        return rc;
    }

    /* program up some basic trace control.
       Set up to trace all instructions.
    */
    /* ETMv4 support only */
    assert(CS_ETMVERSION_IS_ETMV4(etm_version));
    /* ETMv4 initialisation */

    cs_etm_config_init_ex(dev, &v4config);
    v4config.flags = CS_ETMC_CONFIG;
    cs_etm_config_get_ex(dev, &v4config);
    v4config.flags |= CS_ETMC_TRACE_ENABLE | CS_ETMC_EVENTSELECT;
    /* trace enable */
    v4config.victlr = 0x201;	/* Viewinst - trace all, ss started. */
    v4config.viiectlr = 0;	/* no address range */
    v4config.vissctlr = 0;	/* no start stop points */
    /* event select */
    v4config.eventctlr0r = 0;	/* disable all event tracing */
    v4config.eventctlr1r = 0;
    /* config */
    v4config.stallcrlr = 0;	/* no stall */
    v4config.syncpr = 0xC;	/* sync 4096 bytes */
    cs_etm_config_put_ex(dev, &v4config);

    return 0;
}

int configure_trace(const struct board *board, struct cs_devices_t *devices,
    struct addr_range *range, int range_count)
{
    int i, r, error_count;

    if (!board || !devices) {
      return -1;
    }

    /* Ensure TPIU isn't generating back-pressure */
    cs_disable_tpiu();
    /* While programming, ensure we are not collecting trace */
    cs_sink_disable(devices->etb);
    for (i = 0; i < board->n_cpu; ++i) {
        devices->ptm[i] = cs_cpu_get_device(i, CS_DEVCLASS_SOURCE);
        if (devices->ptm[i] == CS_ERRDESC) {
            fprintf(stderr, "Failed to get trace source for CPU #%d\n", i);
            return -1;
        }
        if (cs_set_trace_source_id(devices->ptm[i], 0x10 + i) < 0) {
            return -1;
        }
        if (init_etm(devices->ptm[i]) < 0) {
            return -1;
        }
    }
    cs_checkpoint();

    for (i = 0; i < board->n_cpu; ++i) {
        if (CS_ETMVERSION_MAJOR(cs_etm_get_version(devices->ptm[i])) >=
            CS_ETMVERSION_ETMv4) {
            r = configure_etmv4_addr_range_cid(devices->ptm[i], range, range_count, (unsigned long)trace_pid);
        } else {
            fprintf(stderr, "Unsupported ETM for CPU #%d\n", i);
            continue;
        }
        if (r != 0)
            return r;
    }

    unsigned int ffcr_val;
    if (etb_stop_on_flush) {
        ffcr_val = cs_device_read(devices->etb, CS_ETB_FLFMT_CTRL);
        ffcr_val |= CS_ETB_FLFMT_CTRL_StopFl;
        if (cs_device_write(devices->etb, CS_ETB_FLFMT_CTRL, ffcr_val) != 0) {
            fprintf(stderr, "Failed to set stop on flush\n");
        }
    }

    error_count = cs_error_count();
    if (error_count > 0) {
        fprintf(stderr, "%u errors reported when configuring trace\n", error_count);
        return -1;
    }

    return 0;
}

int enable_trace(const struct board *board, struct cs_devices_t *devices)
{
  int i, error_count;

  if (!board || !devices) {
    return -1;
  }

  if (cs_sink_enable(devices->etb) != 0) {
    fprintf(stderr, "Failed to enable ETB\n");
    return -1;
  }

  for (i = 0; i < board->n_cpu; ++i) {
    cs_trace_enable(devices->ptm[i]);
  }

  cs_checkpoint();

  cs_cti_diag();

  error_count = cs_error_count();
  if (error_count > 0) {
      fprintf(stderr, "%u errors reported when enabling trace\n", error_count);
      return -1;
  }

  return 0;
}
