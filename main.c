#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"
#include "cs_demo_known_boards.h"

#define ENABLE_DUMP_CONFIG 1
#define ENABLE_SHOW_ETM_CONFIG 0
#define TRACE_CPU 1

const char *board_name = "Marvell ThunderX2";
const bool itm_only = false;
const bool itm = false;
const bool trace_timestamps = false;
const bool trace_cycle_accurate = false;
const bool etb_stop_on_flush = true;
const bool return_stack = true;

static bool full = true;

static struct cs_devices_t devices;
const struct board *board;

static int cpu = TRACE_CPU;
static cpu_set_t affinity_mask;

extern int registration_verbose;

struct addr_range {
    unsigned long start;
    unsigned long end;
} addr_range_cmps[ETMv4_NUM_ADDR_COMP_MAX / 2];
static int addr_range_count = 0;

#if ENABLE_SHOW_ETM_CONFIG
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
#endif

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
    
    if (!full) {
        for (int i = 0; i < addr_range_count; i++) {
            /*  set up an address range filter - use comparator pair and the view-inst registers */
            tconfig.addr_comps[i * 2].acvr_l = addr_range_cmps[i].start & 0xFFFFFFFF;
            tconfig.addr_comps[i * 2].acvr_h =
                (addr_range_cmps[i].start >> 32) & 0xFFFFFFFF;
            tconfig.addr_comps[i * 2].acatr_l = 0x0;	/* instuction address compare, all ELs, no ctxt, vmid, data, etc */
            tconfig.addr_comps[i * 2 + 1].acvr_l = addr_range_cmps[i].end & 0xFFFFFFFF;
            tconfig.addr_comps[i * 2 + 1].acvr_h =
                (addr_range_cmps[i].end >> 32) & 0xFFFFFFFF;
            tconfig.addr_comps[i * 2 + 1].acatr_l = 0x0;	/* instuction address compare, all ELs, no ctxt, vmid, data, etc */
            tconfig.addr_comps_acc_mask |= (1 << (i * 2 + 1)) | (1 << (i * 2));
            /* finally, set up ViewInst to trace according to the resources we have set up */
            tconfig.viiectlr |= 1 << i;	/* program the address comp pair 0 for include */
        }

        /* mark the config structure to program the above registers on 'put' */
        tconfig.flags |= CS_ETMC_ADDR_COMP;
        tconfig.syncpr = 0x14;	/* 4096 bytes per sync */
    }
#if ENABLE_SHOW_ETM_CONFIG
    cs_etm_config_print_ex(etm, &tconfig);
#endif
    cs_etm_config_put_ex(etm, &tconfig);

#if ENABLE_SHOW_ETM_CONFIG
    /* Show the resulting configuration */
    if (registration_verbose)
        printf("CSDEMO: Reading back configuration after programming...\n");
    show_etm_config(n_core);
#endif

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
    int etm_version = cs_etm_get_version(dev);

    if (registration_verbose)
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
    /* ETMv4 support only */
    assert(CS_ETMVERSION_IS_ETMV4(etm_version));
    /* ETMv4 initialisation */
    cs_etmv4_config_t v4config;

    cs_etm_config_init_ex(dev, &v4config);
    v4config.flags = CS_ETMC_CONFIG;
    cs_etm_config_get_ex(dev, &v4config);
    v4config.flags |= CS_ETMC_TRACE_ENABLE | CS_ETMC_EVENTSELECT;
    /* trace enable */
    if (itm_only) {
        if (registration_verbose)
            printf("No Viewinst, ITM only\n");
        v4config.victlr = 0x0;	/* Viewinst - trace nothing. */
    } else {
        if (registration_verbose)
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

    return 0;
}

static int do_configure_trace(const struct board *board)
{
    int i, r;

    if (registration_verbose)
        printf("CSDEMO: Configuring trace...\n");
    /* Ensure TPIU isn't generating back-pressure */
    cs_disable_tpiu();
    /* While programming, ensure we are not collecting trace */
    cs_sink_disable(devices.etb);
    if (devices.itm_etb != NULL) {
        cs_sink_disable(devices.itm_etb);
    }
    for (i = 0; i < board->n_cpu; ++i) {
        if (registration_verbose)
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
            CS_ETMVERSION_ETMv4) {
            r = do_config_etmv4(i);
        } else {
            fprintf(stderr, "** Unsupported ETM for CPU #%d\n", i);
            continue;
        }
        if (r != 0)
            return r;
    }

    if (registration_verbose)
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
            if (registration_verbose)
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

    if (registration_verbose)
        printf("CSDEMO: CTI settings....\n");
    cs_cti_diag();

    if (registration_verbose)
        printf("CSDEMO: Configured and enabled trace.\n");
    return 0;
}

static int get_mem_range(pid_t pid)
{
  FILE *fp;
  char maps_path[PATH_MAX];
  char *line;
  size_t n;
  ssize_t readn;
  unsigned long start_addr;
  unsigned long end_addr;
  char c;
  char x;
  int count;

  memset(maps_path, 0, sizeof(maps_path));
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  fp = fopen(maps_path, "r");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }

  line = NULL;
  n = 0;
  readn = 0;
  count = 0;
  while ((readn = getline(&line, &n, fp)) != -1) {
    sscanf(line, "%lx-%lx %c%c%c", &start_addr, &end_addr, &c, &c, &x);
    if (x == 'x') {
      if (count < ETMv4_NUM_ADDR_COMP_MAX / 2) {
        addr_range_cmps[count].start = start_addr;
        addr_range_cmps[count].end = end_addr;
      } else {
        fprintf(stderr, "** WARNING: address range [0x%lx-0x%lx] will not trace\n", start_addr, end_addr);
      }
      count += 1;
    }
  }

  if (line != NULL) {
    free(line);
  }
  addr_range_count = count;
  return count;
}

static void start_trace(pid_t pid)
{
  if (get_mem_range(pid) < 0) {
    fprintf(stderr, "get_mem_range() failed\n");
    return;
  }

  // Use address range filter
  full = false;

  for (int i = 0; i < addr_range_count; i++) {
    printf("Trace [0x%lx-0x%lx]\n", addr_range_cmps[i].start, addr_range_cmps[i].end);
  }

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

#if ENABLE_DUMP_CONFIG
  printf("dumping config with %s\n", itm ? "ITM enabled" : "No ITM");
  do_dump_config(board, &devices, itm);
#endif
  cs_checkpoint();

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

  printf("Start tracing PID: %d\n", pid);
}

static void exit_trace(pid_t pid)
{
  int i;

  printf("Exit tracing PID: %d\n", pid);

  if (registration_verbose)
    printf("CSDEMO: Disable trace...\n");
  for (i = 0; i < board->n_cpu; ++i) {
    cs_trace_disable(devices.ptm[i]);
  }
  cs_sink_disable(devices.etb);
  if (devices.itm_etb != NULL) {
    cs_sink_disable(devices.itm_etb);
  }

  printf("CSDEMO: trace buffer contents: %u bytes\n",
      cs_get_buffer_unread_bytes(devices.etb));

#if ENABLE_SHOW_ETM_CONFIG
  for (i = 0; i < board->n_cpu; ++i) {
    show_etm_config(i);
  }
#endif

  do_fetch_trace(&devices, itm);

  if (registration_verbose)
    printf("CSDEMO: shutdown...\n");
  cs_shutdown();

  for (int i = 0; i < addr_range_count; i++) {
    printf("Traced [0x%lx-0x%lx]\n", addr_range_cmps[i].start, addr_range_cmps[i].end);
  }
}

void child(char *argv[])
{
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execvp(argv[0], argv);
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

  registration_verbose = 0;

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
