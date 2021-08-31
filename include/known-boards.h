/* SPDX-License-Identifier: Apache-2.0 */

#ifndef CS_TRACE_KNOWN_BOARDS_H
#define CS_TRACE_KNOWN_BOARDS_H

#include "csregistration.h"

#include <stdbool.h>

extern bool etr_mode;

int get_trace_id(const char *hardware, int cpu);

static int do_registration_thunderx2(struct cs_devices_t *devices)
{
    /* please refer to CSAL/demos/thunderx2_materials/output.txt */

    int num_cs_cpu = 112;
    uintptr_t cti_base = 0x410420000;
    uintptr_t etm_base = 0x410440000;

    cs_device_t rep, tpiu, etr, etf, funnel;

    cs_register_romtable(0x410000000);

    for (int i = 0; i < num_cs_cpu; i++) {
        /* CTI affinities */
        cs_device_set_affinity(cs_device_register(cti_base + (0x100000 * i)), i);
        /* ETM affinities */
        cs_device_set_affinity(cs_device_register(etm_base + (0x100000 * i)), i);
    }

    funnel = cs_device_get(0x410001000);
    /* FIXME: funnel has 3 in ports. Hardcode to connect CPU #0 to #2 */
    cs_atb_register(cs_cpu_get_device(0, CS_DEVCLASS_SOURCE), 0,
		    funnel, 0);
    cs_atb_register(cs_cpu_get_device(1, CS_DEVCLASS_SOURCE), 0,
		    funnel, 1);
    cs_atb_register(cs_cpu_get_device(2, CS_DEVCLASS_SOURCE), 0,
		    funnel, 2);

    etf = cs_device_get(0x410002000);
    cs_atb_register(funnel, 0, etf, 0);

    rep = cs_atb_add_replicator(2);
    cs_atb_register(etf, 0, rep, 0);

    etr = cs_device_get(0x410004000);
    tpiu = cs_device_get(0x410005000);

    cs_atb_register(rep, 0, etr, 0);
    cs_atb_register(rep, 1, tpiu, 0);

    devices->etb = etr_mode ? etr : etf;
    devices->trace_sinks[0] = etr_mode ? etf : NULL;

    for (int i = 0; i < num_cs_cpu; i++ ) {
        devices->cpu_id[i] = cpu_id[i];
    }

    return 0;
}

static int do_registration_jetson_nano(struct cs_devices_t *devices)
{
  enum { A57_0, A57_1, A57_2, A57_3 };

  int i;
  cs_device_t funnel_a57, funnel_major, etf, rep, etr, tpiu, stm, sys_cti;

  cs_register_romtable(0x72000000);

  /* CTI affinities */
  cs_device_set_affinity(cs_device_register(0x73420000), A57_0);
  cs_device_set_affinity(cs_device_register(0x73520000), A57_1);
  cs_device_set_affinity(cs_device_register(0x73620000), A57_2);
  cs_device_set_affinity(cs_device_register(0x73720000), A57_3);

  /* PMU affinities */
  cs_device_set_affinity(cs_device_register(0x73430000), A57_0);
  cs_device_set_affinity(cs_device_register(0x73530000), A57_1);
  cs_device_set_affinity(cs_device_register(0x73630000), A57_2);
  cs_device_set_affinity(cs_device_register(0x73730000), A57_3);

  /* ETM affinities */
  cs_device_set_affinity(cs_device_register(0x73440000), A57_0);
  cs_device_set_affinity(cs_device_register(0x73540000), A57_1);
  cs_device_set_affinity(cs_device_register(0x73640000), A57_2);
  cs_device_set_affinity(cs_device_register(0x73740000), A57_3);

  funnel_a57 = cs_device_get(0x73010000);
  cs_atb_register(cs_cpu_get_device(A57_0, CS_DEVCLASS_SOURCE), 0,
                  funnel_a57, 0);
  cs_atb_register(cs_cpu_get_device(A57_1, CS_DEVCLASS_SOURCE), 0,
                  funnel_a57, 1);
  cs_atb_register(cs_cpu_get_device(A57_2, CS_DEVCLASS_SOURCE), 0,
                  funnel_a57, 2);
  cs_atb_register(cs_cpu_get_device(A57_3, CS_DEVCLASS_SOURCE), 0,
                  funnel_a57, 3);

  funnel_major = cs_device_get(0x72010000);
  etf = cs_device_get(0x72030000);
  rep = cs_device_get(0x72040000);
  etr = cs_device_get(0x72050000);
  tpiu = cs_device_get(0x72060000);
  stm = cs_device_get(0x72070000);

  cs_atb_register(funnel_a57, 0, funnel_major, 0);
  cs_atb_register(stm, 0, funnel_major, 3);

  cs_atb_register(funnel_major, 0, etf, 0);
  cs_atb_register(etf, 0, rep, 0);
  cs_atb_register(rep, 0, etr, 0);
  cs_atb_register(rep, 1, tpiu, 0);

  devices->itm = stm;
  devices->etb = etr_mode ? etr : etf;
  devices->trace_sinks[0] = etr_mode ? etf : NULL;

  cs_stm_config_master(stm, 0, 0x71000000);
  cs_stm_select_master(stm, 0);

  /* etf */
  sys_cti = cs_device_register(0x72020000);
  cs_cti_connect_trigsrc(etf, CS_TRIGOUT_ETB_FULL,
      cs_cti_trigsrc(sys_cti, 0));
  cs_cti_connect_trigsrc(etf, CS_TRIGOUT_ETB_ACQCOMP,
      cs_cti_trigsrc(sys_cti, 1));
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 0),
      etf, CS_TRIGIN_ETB_TRIGIN);
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 1),
      etf, CS_TRIGIN_ETB_FLUSHIN);

  /* etr */
  cs_cti_connect_trigsrc(etr, CS_TRIGOUT_ETB_FULL,
      cs_cti_trigsrc(sys_cti, 2));
  cs_cti_connect_trigsrc(etr, CS_TRIGOUT_ETB_ACQCOMP,
      cs_cti_trigsrc(sys_cti, 3));
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 2),
      etr, CS_TRIGIN_ETB_TRIGIN);
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 3),
      etr, CS_TRIGIN_ETB_FLUSHIN);

  /* stm */
  cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_ASYNCOUT,
      cs_cti_trigsrc(sys_cti, 4));
  cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTSPTE,
      cs_cti_trigsrc(sys_cti, 5));
  cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTSW,
      cs_cti_trigsrc(sys_cti, 6));

  for (i = 0; i < 4; i++) {
    devices->cpu_id[i] = cpu_id[i];
  }

  return 0;
}

static int do_registration_jetsontx2(struct cs_devices_t *devices)
{
	// CoreSight configurations for Jetson TX2
	// Currently only supports CoreSight Major and A57 Cluster

	enum { A57_0, A57_3, A57_4, A57_5, Denver_0, Denver_1};

	cs_device_t rep, etr, etf, funnel_major, funnel_a57, stm, tpiu, sys_cti;

	cs_register_romtable(0x8000000);

	/* CTI affinities */
	cs_device_set_affinity(cs_device_register(0x9820000), A57_0);
	cs_device_set_affinity(cs_device_register(0x9920000), A57_3);
	cs_device_set_affinity(cs_device_register(0x9A20000), A57_4);
	cs_device_set_affinity(cs_device_register(0x9B20000), A57_5);

	// cs_device_set_affinity(cs_device_register(0x9420000), Denver_0);
	// cs_device_set_affinity(cs_device_register(0x9520000), Denver_1);

	/* PMU affinities */
	cs_device_set_affinity(cs_device_register(0x9830000), A57_0);
	cs_device_set_affinity(cs_device_register(0x9930000), A57_3);
	cs_device_set_affinity(cs_device_register(0x9A30000), A57_4);
	cs_device_set_affinity(cs_device_register(0x9B30000), A57_5);

	// cs_device_set_affinity(cs_device_register(0x9430000), Denver_0);
	// cs_device_set_affinity(cs_device_register(0x9530000), Denver_1);

	/* PTM affinities(ETM) */
	cs_device_set_affinity(cs_device_register(0x9840000), A57_0);
	cs_device_set_affinity(cs_device_register(0x9940000), A57_3);
	cs_device_set_affinity(cs_device_register(0x9A40000), A57_4);
	cs_device_set_affinity(cs_device_register(0x9B40000), A57_5);

	// cs_device_set_affinity(cs_device_register(0x9440000), Denver_0);
	// cs_device_set_affinity(cs_device_register(0x9540000), Denver_1);

	/* funnels in A57 clusters */
	funnel_a57 = cs_device_get(0x9010000);
	cs_atb_register(cs_cpu_get_device(A57_0, CS_DEVCLASS_SOURCE), 0,
			funnel_a57, 0);
	cs_atb_register(cs_cpu_get_device(A57_3, CS_DEVCLASS_SOURCE), 0,
			funnel_a57, 1);
	cs_atb_register(cs_cpu_get_device(A57_4, CS_DEVCLASS_SOURCE), 0,
			funnel_a57, 2);
	cs_atb_register(cs_cpu_get_device(A57_5, CS_DEVCLASS_SOURCE), 0,
			funnel_a57, 3);

	/* setup for coresight major */
	funnel_major = cs_device_get(0x8010000);
	stm = cs_device_get(0x8070000);
	etf = cs_device_get(0x8030000);
	rep = cs_device_get(0x8040000);
	etr = cs_device_get(0x8050000);
	tpiu = cs_device_get(0x8060000);

  cs_atb_register(funnel_a57, 0, funnel_major, 0);
  cs_atb_register(stm, 0, funnel_major, 3);

	/* implementing trace-bus connections according to coresight-tools/top_rom_table.txt */
  cs_atb_register(funnel_major, 0, etf, 0);
  cs_atb_register(etf, 0, rep, 0);
  cs_atb_register(rep, 1, etr, 0);
  cs_atb_register(rep, 0, tpiu, 0);

  devices->itm = stm;
  devices->etb = etr_mode ? etr : etf;
  devices->trace_sinks[0] = etr_mode ? etf : NULL;

  /* stm registration */
  cs_stm_config_master(stm, 0, 0x0a000000);
  cs_stm_select_master(stm, 0);

  /* Connect system CTI to devices according to Table 136 in Parker TRM */
  sys_cti = cs_device_register(0x8020000);
  /* etf */
  cs_cti_connect_trigsrc(etf, CS_TRIGOUT_ETB_FULL,
                cs_cti_trigsrc(sys_cti, 0));
  cs_cti_connect_trigsrc(etf, CS_TRIGOUT_ETB_ACQCOMP,
                cs_cti_trigsrc(sys_cti, 1));
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 0), etf,
                CS_TRIGIN_ETB_TRIGIN);
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 1), etf,
                CS_TRIGIN_ETB_FLUSHIN);
  /* etr */
  cs_cti_connect_trigsrc(etr, CS_TRIGOUT_ETB_FULL,
                cs_cti_trigsrc(sys_cti, 2));
  cs_cti_connect_trigsrc(etr, CS_TRIGOUT_ETB_ACQCOMP,
                cs_cti_trigsrc(sys_cti, 3));
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 2), etr,
                CS_TRIGIN_ETB_TRIGIN);
  cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 3), etr,
                CS_TRIGIN_ETB_FLUSHIN);
  /* stm */
  cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_ASYNCOUT,
                cs_cti_trigsrc(sys_cti, 4));
  cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTSPTE,
                cs_cti_trigsrc(sys_cti, 5));
  cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTSW,
                cs_cti_trigsrc(sys_cti, 6));
  /* TPIU (should be here but the document says TPIU not supported) */

  /* There are A57x4 and denver cluster inside Parker SoC -
    so hardcode here (are we really need this?) */

  for (int i = 0; i < 4; i++) {
      devices->cpu_id[i] = 0xD07;
  }
  return 0;
}

const struct board known_boards[] = {
  {
    .do_registration = do_registration_thunderx2,
    .n_cpu = 32, /* XXX: To limit initialized CPU ETMs */
    .hardware = "Marvell ThunderX2",
  }, {
    .do_registration = do_registration_jetson_nano,
    .n_cpu = 4,
    .hardware = "Jetson Nano",
  }, {
    .do_registration = do_registration_jetsontx2,
    .n_cpu = 4,
    .hardware = "Jetson TX2",
  },
  {},
};

int get_trace_id(const char *hardware, int cpu)
{
  if (strcmp(hardware, "Marvell ThunderX2") == 0) {
    return 0x10 + (cpu % 28) * 4 + cpu / 28; 
  } else if (strcmp(hardware, "Jetson TX2") == 0) {
    if (cpu == 0) {
      return 0x10 + cpu;
    } else if (3 <= cpu && cpu <= 5) {
      return 0x10 + cpu - 2;
    }   
  } else if (strcmp(hardware, "Jetson Nano") == 0) {
    return 0x10 + cpu;
  }

  // Unknown hardware name
  return -1; 
}

#endif /* CS_TRACE_KNOWN_BOARDS_H */
