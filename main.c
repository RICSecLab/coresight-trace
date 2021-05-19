#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"
#include "cs_demo_known_boards.h"

#define TRACE_CPU 1

const char *board_name = "Jetson TX2";
const bool full = true;
const bool itm_only = false;
const bool itm = false;
const bool trace_timestamps = false;
const bool trace_cycle_accurate = false;
const bool etb_stop_on_flush = false;
const bool return_stack = false;

static struct cs_devices_t devices;
const struct board *board;

static int cpu = TRACE_CPU;
static cpu_set_t affinity_mask;

static void show_etm_config(unsigned int n)
{
    cs_etm_config_t tconfig;	/* PTM/ETMv3 config */
    cs_etmv4_config_t t4config;	/* ETMv4 config */
    void *p_config = 0;

    if (CS_ETMVERSION_MAJOR(cs_etm_get_version(devices.ptm[n])) >=
        CS_ETMVERSION_ETMv4)
        p_config = &t4config;
    else
        p_config = &tconfig;

    cs_etm_config_init_ex(devices.ptm[n], p_config);
    tconfig.flags = CS_ETMC_ALL;
    t4config.flags = CS_ETMC_ALL;
    cs_etm_config_get_ex(devices.ptm[n], p_config);
    cs_etm_config_print_ex(devices.ptm[n], p_config);
}

static int do_config_etmv3_ptm(int n_core)
{
    cs_etm_config_t tconfig;

    cs_etm_config_init(&tconfig);
    tconfig.flags = CS_ETMC_TRACE_ENABLE;
    cs_etm_config_get(devices.ptm[n_core], &tconfig);
    //   cs_etm_config_print(&tconfig);
    tconfig.flags = CS_ETMC_TRACE_ENABLE;

#if 0
    if (!full) {
        /* Select address comparator #0 as a start address */
        /* Select address comparator #1 as a stop address */
        /* n.b. ETM numbers the comparators from 1. */
        tconfig.flags |= CS_ETMC_ADDR_COMP;
        tconfig.trace_enable_cr1 = 0x1;	/* address range comparator 0 */
        tconfig.trace_start_comparators = 0x0000;	/* Select comparator #0 as a start address */
        tconfig.trace_stop_comparators = 0x0000;	/* Select comparator #1 as a stop address  */
        tconfig.addr_comp_mask = 0x3;	/* Set address comparators 0 and 1 for programming */
        tconfig.addr_comp[0].address = o_trace_start_address & 0xFFFFFFFE;
//      tconfig.addr_comp[0].access_type = CS_ETMACT_EX|CS_ETMACT_ARMTHUMB|CS_ETMACT_USER;
        //tconfig.addr_comp[0].access_type = 0x1;
        tconfig.addr_comp[0].access_type = 0x1 | CS_ETMACT_ARMTHUMB;
        tconfig.addr_comp[1].address = o_trace_end_address & 0xFFFFFFFE;
//      tconfig.addr_comp[1].access_type = CS_ETMACT_EX|CS_ETMACT_ARMTHUMB|CS_ETMACT_USER;
        tconfig.addr_comp[1].access_type = 0x1 | CS_ETMACT_ARMTHUMB;
    }
#endif
    tconfig.flags |= CS_ETMC_COUNTER;
    tconfig.counter_mask = 0x03;	/* set first 2 bits in mask to ensure first 2 counters are programmed */
    tconfig.counter[0].value = 0x1000;
    tconfig.counter[0].enable_event = CS_ETMER_ALWAYS;	/*CS_ETMER_SAC(0); */
    tconfig.counter[0].reload_value = 0x2000;
    tconfig.counter[0].reload_event = CS_ETMER_CZERO(0);
    tconfig.counter[1].value = 0x1000;
    tconfig.counter[1].enable_event = CS_ETMER_SEQSTATE(2);
    tconfig.counter[1].reload_value = 0x2000;
    tconfig.counter[1].reload_event = CS_ETMER_CZERO(1);

    tconfig.flags |= CS_ETMC_SEQUENCER;
    tconfig.sequencer.state = 1;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(1, 2)] =
        CS_ETMER_SAC(0);
    tconfig.sequencer.transition_event[CS_ETMSQOFF(2, 3)] =
        CS_ETMER_SAC(1);
    tconfig.sequencer.transition_event[CS_ETMSQOFF(1, 3)] = CS_ETME_NEVER;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(2, 1)] = CS_ETME_NEVER;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(3, 1)] = CS_ETME_NEVER;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(3, 2)] = CS_ETME_NEVER;
    
    if (trace_timestamps) {
        tconfig.flags |= CS_ETMC_TS_EVENT;
        tconfig.timestamp_event = CS_ETMER_CZERO(0);
    }

    if (return_stack) {
        tconfig.cr.raw.c.ret_stack = 1;
    }

    cs_etm_config_print(&tconfig);
    cs_etm_config_put(devices.ptm[n_core], &tconfig);

    /* Show the resulting configuration */
    printf("CSDEMO: Reading back configuration after programming...\n");
    show_etm_config(n_core);

    if (cs_error_count() > 0) {
        printf
            ("CSDEMO: %u errors reported in configuration - not running demo\n",
             cs_error_count());
        return -1;
    }
    return 0;
}

static int do_config_etmv4(int n_core)
{
    cs_etmv4_config_t tconfig;
    cs_device_t etm = devices.ptm[n_core];

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
    
#if 0
    if (!full) {
        /*  set up an address range filter - use comparator pair and the view-inst registers */

        tconfig.addr_comps[0].acvr_l = o_trace_start_address & 0xFFFFFFFF;
        tconfig.addr_comps[0].acvr_h =
            (o_trace_start_address >> 32) & 0xFFFFFFFF;
        tconfig.addr_comps[0].acatr_l = 0x0;	/* instuction address compare, all ELs, no ctxt, vmid, data, etc */
        tconfig.addr_comps[1].acvr_l = o_trace_end_address & 0xFFFFFFFF;
        tconfig.addr_comps[1].acvr_h =
            (o_trace_end_address >> 32) & 0xFFFFFFFF;
        tconfig.addr_comps[1].acatr_l = 0x0;	/* instuction address compare, all ELs, no ctxt, vmid, data, etc */

        /* mark the config structure to program the above registers on 'put' */
        tconfig.addr_comps_acc_mask = 0x3;
        tconfig.flags |= CS_ETMC_ADDR_COMP;

        /* finally, set up ViewInst to trace according to the resources we have set up */
        tconfig.viiectlr = 0x1;	/* program the address comp pair 0 for include */
        tconfig.syncpr = 0x0;	/* no extra sync */

    }
#endif
    cs_etm_config_print_ex(etm, &tconfig);
    cs_etm_config_put_ex(etm, &tconfig);

    /* Show the resulting configuration */
    printf("CSDEMO: Reading back configuration after programming...\n");
    show_etm_config(n_core);

    if (cs_error_count() > 0) {
        printf
            ("CSDEMO: %u errors reported in configuration - not running demo\n",
             cs_error_count());
        return -1;
    }
    return 0;
}

static int do_init_etm(cs_device_t dev)
{
    int rc;
    struct cs_etm_config config;
    int etm_version = cs_etm_get_version(dev);

    printf("CSDEMO: Initialising ETM/PTM\n");

    /* ASSERT that this is an etm etc */
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));

    /* set to a 'clean' state - clears events & values, retains ctrl and ID, ensure programmable */
    if ((rc = cs_etm_clean(dev)) != 0) {
        printf("CSDEMO: Failed to set ETM/PTM into clean state\n");
        return rc;
    }

    /* program up some basic trace control.
       Set up to trace all instructions.
    */
    if (!CS_ETMVERSION_IS_ETMV4(etm_version)) {

        cs_etm_config_init(&config);
        config.flags = CS_ETMC_CONFIG;
        cs_etm_config_get(dev, &config);
        config.trace_enable_event = CS_ETMER_ALWAYS;
        config.flags |= CS_ETMC_TRACE_ENABLE;
        /* "To trace all memory:
           - set bit [24] in the ETMTECR1 to 1
           - set all other bits in the ETMTECR1 to 0
           - set the ETMEEVER to 0x6F (TRUE)
           This has the effect of excluding nothing, that is, tracing everything." */
        config.trace_enable_event = CS_ETMER_ALWAYS;
        config.trace_enable_cr1 = CS_ETMTECR1_EXCLUDE;
        config.trace_enable_cr2 = 0x00000000;
        cs_etm_config_put(dev, &config);
    } else {
        /* ETMv4 initialisation */
        cs_etmv4_config_t v4config;

        cs_etm_config_init_ex(dev, &v4config);
        v4config.flags = CS_ETMC_CONFIG;
        cs_etm_config_get_ex(dev, &v4config);
        v4config.flags |= CS_ETMC_TRACE_ENABLE | CS_ETMC_EVENTSELECT;
        /* trace enable */
        if (itm_only) {
            printf("No Viewinst, ITM only\n");
            v4config.victlr = 0x0;	/* Viewinst - trace nothing. */
        } else {
            printf("Viewinst trace everything\n");
            v4config.victlr = 0x201;	/* Viewinst - trace all, ss started. */
        }
        v4config.viiectlr = 0;	/* no address range */
        v4config.vissctlr = 0;	/* no start stop points */
        /* event select */
        v4config.eventctlr0r = 0;	/* disable all event tracing */
        v4config.eventctlr1r = 0;
        /* config */
        v4config.stallcrlr = 0;	/* no stall */
        v4config.syncpr = 0xC;	/* sync 4096 bytes */
        cs_etm_config_put_ex(dev, &v4config);

    }
    return 0;
}

static int do_configure_trace(const struct board *board)
{
    int i, r;

    printf("CSDEMO: Configuring trace...\n");
    /* Ensure TPIU isn't generating back-pressure */
    cs_disable_tpiu();
    /* While programming, ensure we are not collecting trace */
    cs_sink_disable(devices.etb);
    if (devices.itm_etb != NULL) {
        cs_sink_disable(devices.itm_etb);
    }
    for (i = 0; i < board->n_cpu; ++i) {
        printf
            ("CSDEMO: Configuring trace source id for CPU #%d ETM/PTM...\n",
             i);
        devices.ptm[i] = cs_cpu_get_device(i, CS_DEVCLASS_SOURCE);
        if (devices.ptm[i] == CS_ERRDESC) {
            fprintf(stderr, "** Failed to get trace source for CPU #%d\n",
                    i);
            return -1;
        }
        if (cs_set_trace_source_id(devices.ptm[i], 0x10 + i) < 0) {
            return -1;
        }
        if (do_init_etm(devices.ptm[i]) < 0) {
            return -1;
        }
    }
    if (itm) {
        cs_set_trace_source_id(devices.itm, 0x20);
    }
    cs_checkpoint();

    for (i = 0; i < board->n_cpu; ++i) {
        if (CS_ETMVERSION_MAJOR(cs_etm_get_version(devices.ptm[i])) >=
            CS_ETMVERSION_ETMv4)
            r = do_config_etmv4(i);
        else
            r = do_config_etmv3_ptm(i);
        if (r != 0)
            return r;
    }

    printf("CSDEMO: Enabling trace...\n");
    if (cs_sink_enable(devices.etb) != 0) {
        printf
            ("CSDEMO: Could not enable trace buffer - not running demo\n");
        return -1;
    }
    if (devices.itm_etb != NULL) {
        if (cs_sink_enable(devices.itm_etb) != 0) {
            printf("CSDEMO: Could not enable ITM trace buffer\n");
        }
    }

    for (i = 0; i < board->n_cpu; ++i) {
        if (cpu >= 0 && i != cpu) {
          printf("Skipping Trace enabling for CPU #%d\n", i);
          continue;
        }
        if (trace_timestamps)
            cs_trace_enable_timestamps(devices.ptm[i], 1);
        if (trace_cycle_accurate)
            cs_trace_enable_cycle_accurate(devices.ptm[i], 1);
        cs_trace_enable(devices.ptm[i]);
    }

    if (itm) {
        cs_trace_swstim_enable_all_ports(devices.itm);
        cs_trace_swstim_set_sync_repeat(devices.itm, 32);
        if (trace_timestamps)
            cs_trace_enable_timestamps(devices.itm, 1);
        cs_trace_enable(devices.itm);
    }

    unsigned int ffcr_val;
    /* for this demo we may set stop on flush and stop capture by maunal flushing later */
    if (etb_stop_on_flush) {
        /* set up some bits in the FFCR - enabling the  ETB later will retain these bits */
        ffcr_val = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
        ffcr_val |= CS_ETB_FLFMT_CTRL_StopFl;
        if (cs_device_write(devices.etb, CS_ETB_FLFMT_CTRL, ffcr_val) == 0) {
            printf("CSDEMO: setting stop on flush, ETB FFCR = 0x%08X",
                   ffcr_val);
        } else {
            printf
                ("CSDEMO: Failed to set stop on flush, ETB FFCR to 0x%08X",
                 ffcr_val);
        }
    }

    cs_checkpoint();
    if (cs_error_count() > 0) {
        printf
            ("CSDEMO: %u errors reported when enabling trace - not running demo\n",
             cs_error_count());
        return -1;
    }

    printf("CSDEMO: CTI settings....\n");
    cs_cti_diag();

    printf("CSDEMO: Configured and enabled trace.\n");
    return 0;
}

static void start_trace(pid_t pid)
{
  // TODO: Use our own board setup
  if (setup_known_board_by_name(board_name, &board, &devices) < 0) {
    fprintf(stderr, "setup_known_board_by_name() failed\n");
    return;
  }

  if (0) {
    cs_shutdown();
    return;
  }

  if (cpu >= 0) {
    printf("Set CPU affinity: CPU #%d\n", cpu);
    CPU_ZERO(&affinity_mask);
    CPU_SET(cpu, &affinity_mask);
    if (sched_setaffinity(pid, sizeof(affinity_mask), &affinity_mask) < 0) {
      perror("sched_setaffinity");
      cs_shutdown();
      return;
    }
  }

  if (do_configure_trace(board) < 0) {
    fprintf(stderr, "do_configure_trace() failed\n");
    return;
  }

  printf("Trace configured\n");

  printf("dumping config with %s\n", itm ? "ITM enabled" : "No ITM");
  do_dump_config(board, &devices, itm);
  cs_checkpoint();

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

  // TODO:
  printf("TODO: Start tracing PID: %d\n", pid);
}

static void exit_trace(pid_t pid)
{
  int i;
  // TODO:
  printf("TODO: Exit tracing PID: %d\n", pid);

  printf("CSDEMO: Disable trace...\n");
  for (i = 0; i < board->n_cpu; ++i) {
    if (cpu >= 0 && i != cpu) {
      printf("Skipping Trace disabling for CPU #%d\n", i);
      continue;
    }
    cs_trace_disable(devices.ptm[i]);
  }
  cs_sink_disable(devices.etb);
  if (devices.itm_etb != NULL) {
    cs_sink_disable(devices.itm_etb);
  }

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

  for (i = 0; i < board->n_cpu; ++i) {
    show_etm_config(i);
  }

  do_fetch_trace(&devices, itm);

  printf("CSDEMO: shutdown...\n");
  cs_shutdown();
}

void child(char *argv[])
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execv(argv[0], argv);
}

void parent(pid_t pid)
{
  int wstatus;
  bool is_first_exec;
  bool trace_started;

  is_first_exec = true;
  trace_started = false;

  waitpid(pid, &wstatus, 0);
  if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == PTRACE_EVENT_VFORK_DONE) {
    if (is_first_exec == true) {
      is_first_exec = false;
      start_trace(pid);
      trace_started = true;
    }
  }
  ptrace(PTRACE_CONT, pid, 0, 0);

  waitpid(pid, &wstatus, 0);
  if (WIFEXITED(wstatus) && trace_started == true) {
    exit_trace(pid);
    trace_started = false;
  }
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s EXE\n", argv[0]);
    exit(EXIT_SUCCESS);
  }

  pid_t pid;

  pid = fork();
  switch (pid) {
    case 0:
      child(&argv[1]);
      break;
    case -1:
      perror("fork");
      exit(EXIT_FAILURE);
      break;
    default:
      parent(pid);
      wait(NULL);
      break;
  }
}
