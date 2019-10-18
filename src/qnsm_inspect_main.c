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
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>


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

#include "app.h"
#include "qnsm_inspect_main.h"

#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_dbg.h"
#include "qnsm_msg_ex.h"

int qnsm_inspect_init(void)
{
    int ret = 0;

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_CFG, 0xFF);

    time_init();

    /*
     *conf parse
     */
    ret = qnsm_conf_parse();
    if(ret != 0) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "ret = %d\n", ret);
        return ret;
    }

    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);
    return ret;
}

void qnsm_signal_proc(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    (void)pthread_sigmask(SIG_BLOCK, &set, NULL);
    return;
}

void qnsm_corefile_init(void)
{
    struct rlimit rlim;
    struct rlimit rlim_new;

    if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
        rlim_new.rlim_cur = RLIM_INFINITY;
        rlim_new.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &rlim_new) != 0) {
            rlim_new.rlim_cur = rlim.rlim_max;
            rlim_new.rlim_max = rlim.rlim_max;
            (void) setrlimit(RLIMIT_CORE, &rlim_new);
        }
    }
    return;
}

int
MAIN(int argc, char **argv)
{
    int ret;

    /*init signal*/
    qnsm_signal_proc();

    /*init coredump file size*/
    qnsm_corefile_init();

    rte_openlog_stream(stderr);

    /*common config */
    struct app_params *app_paras = NULL;
    app_paras = qnsm_service_get_cfg_para();
    app_config_init(app_paras);
    app_config_args(app_paras, argc, argv);
    app_config_preproc(app_paras);
    app_config_parse(app_paras, app_paras->parser_file);
    app_config_check(app_paras);

    /*eal , link Init */
    app_init(app_paras);

    /*qnsm inspect init*/
    ret = qnsm_inspect_init();
    if(ret != 0) {
        rte_exit(EXIT_FAILURE, "qnsm inspect init failed\n");
    }

    /*qnsm service init*/
    ret = qnsm_service_lib_init(app_paras);
    if(ret != 0) {
        rte_exit(EXIT_FAILURE, "qnsm service lib init failed\n");
    }

    /* Launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(app_lcore_main_loop, NULL, CALL_MASTER);

    return 0;
}

