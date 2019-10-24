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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/time.h>
#include <sched.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_alarm.h>
#include <cmdline.h>
#include <cmdline_socket.h>

#include "util.h"
#include "app.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_crm.h"
#include "qnsm_msg.h"
#include "qnsm_port_ex.h"
#include "qnsm_port.h"
#include "qnsm_tbl_conf.h"
#include "qnsm_kafka_ex.h"
#include "qnsm_kafka.h"
#include "qnsm_dpi_ex.h"
#include "qnsm_dpi.h"
#include "qnsm_acl.h"
#include "qnsm_idps_lib_ex.h"

#include "qnsm_service_ex.h"
#include "qnsm_service.h"

#define QNSM_BURST_TX_DRAIN_US 100
#define QNSM_INIT_MBUF_PRI_DATA(pkt_info)                          \
    do{                                                            \
        ((QNSM_PACKET_INFO *)(pkt_info))->need_dump = 0;           \
        ((QNSM_PACKET_INFO *)(pkt_info))->dpi_policy = 0;          \
        ((QNSM_PACKET_INFO *)(pkt_info))->pf = 0;                  \
    }while(0);


RTE_DEFINE_PER_LCORE(void *, qnsm_data);
struct app_params app;

#ifdef QNSM_LIBQNSM_IDPS
#define QNSM_IDPS_CONF_DIR      "/usr/local/etc/"
const char* idps_argument[] = {"suricata", "-c", QNSM_IDPS_CONF_DIR, "--dpdkintel", "--runmode", "workers", NULL};

static void qnsm_idps_args_preproc(int argc, char **argv)
{
    int index = 0;
    int custom_conf_dir = 0;
    char *ips_inst_conf = NULL;
    struct app_params *app_paras = NULL;

    app_paras = qnsm_service_get_cfg_para();
    custom_conf_dir = (app_paras->xml_conf_dir != NULL) ? 1 : 0;

    if (0 == custom_conf_dir) {
        rte_exit(EXIT_FAILURE, "qnsm_ips_args_preproc failed\n");
        return;
    }
    ips_inst_conf = malloc(128);
    if (NULL == ips_inst_conf) {
        rte_exit(EXIT_FAILURE, "qnsm_ips_args_preproc failed\n");
        return;
    }
    for (index = 0; index < argc; index++) {
        if (!strncmp(argv[index], QNSM_IDPS_CONF_DIR, strlen(QNSM_IDPS_CONF_DIR))) {
            snprintf(ips_inst_conf, 128, "%s/%s", app_paras->xml_conf_dir, app_paras->idps_conf_file);
            argv[index] = ips_inst_conf;
            break;
        }
    }

    return;
}
#endif

#if QNSM_PART("cmd")

inline void* qnsm_cmd_app_data(void *para, EN_QNSM_APP type)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *entry = params->app_data;

    QNSM_ASSERT(entry->app_type == type);
    return entry->app_handle;
}

inline void* qnsm_cmd_service_handle(void *para, EN_QNSM_SERVICE handle_type)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *entry = params->app_data;

    return entry->service_lib_handle[handle_type];
}

inline uint8_t qnsm_cmd_lib_load(void *para, EN_QNSM_SERVICE handle_type)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *entry = params->app_data;

    return (en_lib_state_load == (*(enum en_service_lib_state *)entry->service_lib_handle[handle_type]));
}
#endif

inline void* qnsm_service_handle(EN_QNSM_SERVICE handle_type)
{
    QNSM_DATA *entry = QNSM_GET_DATA();
    return entry->service_lib_handle[handle_type];
}

/*init app inst*/
inline void* qnsm_app_inst_init(uint32_t size,
                                QNSM_APP_PKT_PROC pkt_proc,
                                QNSM_APP_ACTION action,
                                QNSM_APP_RUN run)
{
    void *app_data = NULL;
    QNSM_DATA *entry = QNSM_GET_DATA();

    app_data= rte_zmalloc_socket("QNSM_APP", size, QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == app_data) {
        QNSM_ASSERT(0);
        return NULL;
    }

    entry->app_handle = app_data;
    entry->pkt_proc = pkt_proc;
    entry->action = action;
    entry->run = run;

    return app_data;
}

inline void* qnsm_app_data(EN_QNSM_APP type)
{
    QNSM_DATA *entry = QNSM_GET_DATA();

    QNSM_ASSERT(entry->app_type == type);
    return entry->app_handle;
}

inline void* qnsm_service_get_cfg_para(void)
{
    return &app;
}

int32_t qnsm_service_lib_init(void *app_params)
{
    int32_t ret = 0;
    struct app_params *app_paras = app_params;

    /*crm run on intr thread*/
    void *crm = NULL;
    ret = qnsm_crm_init(app_paras, &crm);
    if(ret != 0) {
        rte_exit(EXIT_FAILURE, "qnsm crm service init failed\n");
    }

    static const uint64_t us = 100 * 1000;
    rte_eal_alarm_set(us, qnsm_crm_msg_req_handle, crm);

    /*msg pre init*/
    ret = qnsm_msg_pre_init();
    if(ret != 0) {
        printf("qnsm msg init failed\n");
        return ret;
    }

    /*qnsm tbl pre init*/
    ret = qnsm_tbl_pre_init();
    if(ret != 0) {
        printf("qnsm tbl init failed\n");
        return ret;
    }

    /*port pre init*/
    ret = qnsm_port_pre_init();
    if(ret != 0) {
        printf("qnsm swq init failed\n");
        return ret;
    }

#ifdef QNSM_LIBQNSM_IDPS
    if (app_type_find(app_paras, EN_QNSM_DETECT)) {
        qnsm_idps_args_preproc(sizeof(idps_argument) / sizeof(char *) - 1,
                               (char **)idps_argument);
        qnsm_idps_init(sizeof(idps_argument) / sizeof(char *) - 1, idps_argument);
    }
#endif

    return ret;
}

static void qnsm_service_run(QNSM_DATA *data, struct app_pipeline_params *pipeline_params)
{
    uint32_t lcore = rte_lcore_id();
    const uint64_t msg_dispatch_tsc = ((rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S) * pipeline_params->timer_period;
    const uint64_t cr_drain_tsc = ((rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S) * 100;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
                               US_PER_S * QNSM_BURST_TX_DRAIN_US;
    uint64_t                        time;
    uint64_t                        deadline;
    uint64_t                        crm_deadline;
    uint64_t                        msg_dispatch_deadline;
    uint64_t i = 0;
    QNSM_PORT_HANDLE *port_handle = qnsm_service_handle(EN_QNSM_SERVICE_PORT);
    QNSM_ACL_HANDLE *acl_hdl = qnsm_service_handle(EN_QNSM_SERVICE_ACL);

    struct rte_mbuf **mbuf = NULL;
    uint16_t port_id = 0;
    uint16_t index = 0;
    int32_t nb_pkts = 0;
    QNSM_APP_PKT_PROC pkt_proc = NULL;
    QNSM_APP_ACTION   action = NULL;
    QNSM_APP_RUN run = NULL;
    uint8_t load_acl = (en_lib_state_load == GET_LIB_COMMON_STATE(acl_hdl));
    uint8_t load_port = (en_lib_state_load == GET_LIB_COMMON_STATE(port_handle));

    QNSM_CRM_AGENT *crm_agent = qnsm_service_handle(EN_QNSM_SERVICE_CRM);
    QNSM_MSG_DATA *msg_hdl = qnsm_service_handle(EN_QNSM_SERVICE_MSG);

    time = rte_get_tsc_cycles();
    deadline = time + drain_tsc;
    crm_deadline = time + cr_drain_tsc;
    msg_dispatch_deadline = time + msg_dispatch_tsc;

    /*mbuf proc*/
    pkt_proc = data->pkt_proc;
    action = data->action;
    run = data->run;
    while (1) {
        for (port_id = 0; port_id < port_handle->rx_port_cnt; port_id++) {
            mbuf =  port_handle->pkts;
            nb_pkts = qnsm_port_rx(port_handle, port_id, mbuf);
            if (0 >= nb_pkts) {
                continue;
            }

            /* Prefetch packets */
            for (index = 0; index < PREFETCH_OFFSET && index < nb_pkts; index++) {
                rte_prefetch0(mbuf[index] + 1);
                rte_prefetch0(rte_pktmbuf_mtod(
                                  mbuf[index], void *));
            }
            for (index = 0; index < (nb_pkts - PREFETCH_OFFSET); index++) {
                rte_prefetch0(mbuf[index] + 1);
                rte_prefetch0(rte_pktmbuf_mtod(mbuf[index + PREFETCH_OFFSET],
                                               void *));
            }

            if (load_acl) {
                /*acl run*/
                qnsm_acl_run(acl_hdl, mbuf, nb_pkts);
            }

            for (index = 0; index < nb_pkts; index++) {
                if (pkt_proc) {
                    pkt_proc(data->app_handle, lcore, mbuf[index]);
                }

                if (action) {
                    action(mbuf[index]);
                }
            }
        }

        if (run) {
            run(data->app_handle);
        }
        if (0 == (i & 0x7)) {
            /*msg*/
            if (0 == msg_dispatch_tsc) {
                (void)qnsm_msg_dispatch(msg_hdl);
            }

            /*timer*/
                rte_timer_manage();
        }

        if(0 == (i & 0xF)) {
            time = rte_get_tsc_cycles();

            if (msg_dispatch_tsc) {
                if (QNSM_TIME_AFTER(time, msg_dispatch_deadline)) {
                    (void)qnsm_msg_dispatch(msg_hdl);
                    msg_dispatch_deadline += msg_dispatch_tsc;
                }
            }

            /*
            *pkt flush
            */
            if (load_port) {
                if (QNSM_TIME_AFTER(time, deadline)) {
                    QNSM_PORT_TX_FLUSH(port_handle);
                    deadline += drain_tsc;
                }
            }

            if (QNSM_TIME_AFTER(time, crm_deadline)) {
                /*crm*/
                qnsm_crm_agent_msg_handle(crm_agent, qnsm_msg_cr_rsp, msg_hdl);

                crm_deadline += cr_drain_tsc;
            }
        }
        i++;
    }

    return;
}

int32_t qnsm_service_run_reg(QNSM_APP_RUN run)
{
    QNSM_DATA *data = QNSM_GET_DATA();
    int32_t ret = -1;

    if (data) {
        data->service_run = run;
        ret = 0;
    }

    return ret;
}

/*called by per lcore*/
int32_t qnsm_servcie_app_launch(void *para,
                                QNSM_APP_INIT init_fun)
{
    QNSM_DATA *data = NULL;
    int32_t ret = 0;
    struct app_pipeline_params *params = para;
    EN_QNSM_APP type = params->app_type;

    QNSM_ASSERT(NULL == data);

    data = rte_zmalloc_socket("QNSM_SERVCIE", sizeof(QNSM_DATA), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == data) {
        QNSM_ASSERT(0);
        return -1;
    }
    QNSM_GET_DATA() = data;

    ret = qnsm_crm_agent_init(&app,
                              params,
                              &data->service_lib_handle[EN_QNSM_SERVICE_CRM]);
    if (ret != 0) {
        printf("qnsm crm init failed\n");
        return ret;
    }

    ret = qnsm_msg_init(type, &data->service_lib_handle[EN_QNSM_SERVICE_MSG]);
    if (ret != 0) {
        printf("qnsm msg init failed\n");
        return ret;
    }

    /*tbl init*/
    //if (params->load_tbl)
    {
        ret = qnsm_tbl_init(&data->service_lib_handle[EN_QNSM_SERVICE_TBL]);
        if (ret != 0) {
            printf("qnsm tbl init failed\n");
            return ret;
        }
    }

    /*dpi init*/
    //if (params->load_dpi)
    {
        ret = qnsm_dpi_init(&data->service_lib_handle[EN_QNSM_SERVICE_DPI]);
        if (ret != 0) {
            printf("qnsm dpi init failed\n");
            return ret;
        }
    }

    /*port init*/
    ret = qnsm_port_service_init(&app,
                                 params,
                                 &data->service_lib_handle[EN_QNSM_SERVICE_PORT]);
    if (ret != 0) {
        printf("qnsm port init failed\n");
        return ret;
    }

    /*kafka init*/
    //if (params->load_kafka)
    {
        ret = qnsm_kafka_init(&data->service_lib_handle[EN_QNSM_SERVICE_KAFKA]);
        if (ret != 0) {
            printf("qnsm kafka init failed\n");
            return ret;
        }
    }

    /*acl init*/
    //if (params->load_acl)
    {
        ret = qnsm_acl_init(&data->service_lib_handle[EN_QNSM_SERVICE_ACL]);
        if (ret != 0) {
            return ret;
        }
    }

    /*init app*/
    data->app_type = type;
    data->run = NULL;
    data->service_run = NULL;
    data->init_fun = init_fun;
    data->pkt_proc = NULL;
    data->action = NULL;

    /*!!!only for cmd!!!*/
    params->app_data = data;

    /*app init*/
    if (init_fun) {
        data->init_fun();
    }

    /*app run*/
    if (NULL == data->service_run) {
        if (EN_QNSM_MASTER != type) {
            char name[16];
            snprintf(name, sizeof(name), "%s#%u", params->type, rte_lcore_id());
            QnsmSetThreadName(name);
        }
        qnsm_service_run(data, params);
    } else {
        data->service_run(data->app_handle);
    }

    return 0;
}


