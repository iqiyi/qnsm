/*
 * QNSM is a Network Security Monitor based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_timer.h>

#include "qnsm_inspect_main.h"
#include "util.h"
#include "qnsm_cfg.h"
#include "app.h"
#include "qnsm_dbg.h"
#include "qnsm_msg_ex.h"
#include "qnsm_port_ex.h"
#include "qnsm_session_ex.h"
#include "qnsm_ip_agg.h"
#include "qnsm_edge_ex.h"
#include "qnsm_master_ex.h"
#include "qnsm_ips_shell.h"
#include "qnsm_dump_ex.h"
#include "qnsm_dummy.h"

int
app_lcore_main_loop(void *arg)
{
    unsigned lcore = rte_lcore_id();
    struct app_params *app = qnsm_service_get_cfg_para();
    EN_QNSM_APP app_type = app->app_type[lcore];
    uint16_t lcore_id = 0;
    uint32_t p_id;
    struct app_pipeline_params *params = NULL;
    static QNSM_APP_INIT init_fun[EN_QNSM_APP_MAX] = {
        qnsm_sess_service_init,
        qnsm_service_cus_ip_agg_init,
        qnsm_service_svr_host_init,
        qnsm_edge_service_init,
        qnsm_master_init,
#ifdef QNSM_LIBQNSM_IDPS
        qnsm_detect_service_init,
#else
        NULL,
#endif
        qnsm_service_dump_init,
        NULL,
        qnsm_dummy_init,
    };

    for (p_id = 0; p_id < app->n_pipelines; p_id++) {
        params = &app->pipeline_params[p_id];

        lcore_id = cpu_core_map_get_lcore_id(app->core_map,
                                             params->socket_id,
                                             params->core_id,
                                             params->hyper_th_id);
        if (lcore_id == lcore) {
            break;
        }
    }

    if (params && init_fun[app_type]) {

        printf("Logical core %u (%s) main loop.\n", lcore, params->name);
        qnsm_servcie_app_launch(params,
                                init_fun[app_type]);
    }
    return 0;
}
