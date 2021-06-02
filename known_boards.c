/* SPDX-License-Identifier: Apache-2.0 */

#include "csregistration.h"

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

    devices->etb = etf;

    for (int i = 0; i < num_cs_cpu; i++ ) {
        devices->cpu_id[i] = cpu_id[i];
    }

    return 0;
}

const struct board known_boards[] = {
  {
    .do_registration = do_registration_thunderx2,
    .n_cpu = 32, /* XXX: To limit initialized CPU ETMs */
    .hardware = "Marvell ThunderX2",
  },
  {},
};
