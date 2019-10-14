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

#include <rte_common.h>
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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_alarm.h>


#include "app.h"
#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_service.h"
#include "qnsm_crm.h"

static inline struct rte_ring *
qnsm_crm_msgq_in_get(struct app_params *app,
                     uint32_t pipeline_id)
{
    struct app_msgq_params *p;

    APP_PARAM_FIND_BY_ID(app->msgq_params,
                         "MSGQ-REQ-PIPELINE",
                         pipeline_id,
                         p);
    if (p == NULL)
        return NULL;

    return app->msgq[p - app->msgq_params];
}

static inline struct rte_ring *
qnsm_crm_msgq_out_get(struct app_params *app,
                      uint32_t pipeline_id)
{
    struct app_msgq_params *p;

    APP_PARAM_FIND_BY_ID(app->msgq_params,
                         "MSGQ-RSP-PIPELINE",
                         pipeline_id,
                         p);
    if (p == NULL)
        return NULL;

    return app->msgq[p - app->msgq_params];
}

#if QNSM_PART("crm agent")

static inline void *
__qnsm_crm_agent_msg_send_recv(QNSM_CRM_AGENT *crm_agent,
                               void *msg,
                               uint32_t timeout_ms)
{
    struct rte_ring *r_req = crm_agent->msgq_out;
    struct rte_ring *r_rsp = crm_agent->msgq_in;
    uint64_t hz = rte_get_tsc_hz();
    void *msg_recv;
    uint64_t deadline;
    int status;

    /* send */
    do {
        status = rte_ring_sp_enqueue(r_req, (void *) msg);
    } while (status == -ENOBUFS);

    /* recv */
    deadline = (timeout_ms) ?
               (rte_rdtsc() + ((hz * timeout_ms) / 1000)) :
               UINT64_MAX;

    do {
        if (rte_rdtsc() > deadline)
            return NULL;

        status = rte_ring_sc_dequeue(r_rsp, &msg_recv);
    } while (status != 0);

    return msg_recv;
}


static inline int
__qnsm_crm_agent_msg_send(QNSM_CRM_AGENT *crm_agent,
                          void *msg)
{
    struct rte_ring *r_req = crm_agent->msgq_out;
    int status;

    /* send */
    do {
        status = rte_ring_sp_enqueue(r_req, (void *) msg);
    } while (status == -ENOBUFS);

    return status;
}

static inline void *
__qnsm_crm_agent_msg_recv(QNSM_CRM_AGENT *crm_agent)
{
    struct rte_ring *r = crm_agent->msgq_in;
    void *msg;
    int status = rte_ring_sc_dequeue(r, &msg);

    if (status != 0)
        return NULL;

    return msg;
}

/*msg alloc/free by app*/
void qnsm_crm_agent_msg_send(void *req_msg)
{
    QNSM_CRM_AGENT *crm_agent = qnsm_service_handle(EN_QNSM_SERVICE_CRM);

    (void)__qnsm_crm_agent_msg_send(crm_agent, req_msg);

    return;
}

void qnsm_crm_agent_msg_handle(QNSM_CRM_AGENT *crm_agent, QNSM_CRM_RESP_HANDLER rsp_cb, void *arg)
{
#if 0
    void *msg = NULL;
    msg = __qnsm_crm_agent_msg_recv(crm_agent);
    if (msg) {
        rsp_cb(arg, msg);
        qnsm_crm_free(msg);
    }
#else
    void *msg[16];
    uint16_t nb_rx = 0;
    uint16_t index = 0;

    nb_rx = rte_ring_sc_dequeue_burst(crm_agent->msgq_in, (void **)msg, 8);
    for (index = 0; index < nb_rx; index++) {
        rsp_cb(arg, msg[index]);
        qnsm_crm_free(msg[index]);
    }
#endif

    return;
}

/*all app init*/
int32_t qnsm_crm_agent_init(struct app_params *app, struct app_pipeline_params *pipeline_params, void **tbl_handle)
{
    QNSM_CRM_AGENT *crm_agent = NULL;

    crm_agent = rte_zmalloc_socket(NULL,
                                   sizeof(QNSM_CRM_AGENT),
                                   QNSM_DDOS_MEM_ALIGN,
                                   rte_socket_id());
    QNSM_ASSERT(crm_agent);
    QNSM_ASSERT(1 == pipeline_params->n_msgq_in);

    crm_agent->msgq_out = app->msgq[pipeline_params->msgq_in[0]];
    crm_agent->msgq_in = app->msgq[pipeline_params->msgq_out[0]];
    printf("crm agent lcore %d msgq_out %p msgq_in %p\n",
           rte_lcore_id(),
           crm_agent->msgq_out,
           crm_agent->msgq_in);
    *tbl_handle = crm_agent;

    return 0;
}


#endif


#if QNSM_PART("crm")

static inline void *
qnsm_crm_msg_recv(QNSM_CRM *crm_handle,
                  uint32_t msgq_id)
{
    struct rte_ring *r = crm_handle->msgq_in[msgq_id];
    void *msg;
    int status = rte_ring_sc_dequeue(r, &msg);

    if (status != 0)
        return NULL;

    return msg;
}

static inline void
qnsm_crm_msg_send(QNSM_CRM *crm_handle,
                  uint32_t msgq_id,
                  void *msg)
{
    struct rte_ring *r = crm_handle->msgq_out[msgq_id];
    int status;

    do {
        status = rte_ring_sp_enqueue(r, msg);
    } while (status == -ENOBUFS);
}

static void
qnsm_crm_msg_req_invalid_handler(QNSM_CRM *h_crm, void *msg)
{
    QNSM_CRM_MSG *rsp = msg;

    h_crm = h_crm;
    rsp->resp_status = -1; /* Error */

    return;
}

static void qnsm_crm_msg_req_handler(QNSM_CRM *h_crm, void *msg)
{
    QNSM_CRM_MSG *crm_msg = msg;
    uint16_t lcore_id = 0;
    QNSM_CR_SUB_NODE *pos = NULL;
    QNSM_CR_SUB_NODE *next = NULL;
    QNSM_CR_SUB_NODE *sub_node = NULL;
    struct rte_ring *ring = NULL;
    char ring_name[128];
    QNSM_CR_VALUE *cr_value = NULL;
    QNSM_CRM_MSG *snd_msg = NULL;

    switch(crm_msg->type) {
        case EN_QNSM_CRM_MSG_ONLINE: {
            crm_msg->value_len = 0;
            if (EN_QNSM_CRM_ACT_PUBLISH == crm_msg->act_head.act) {
                h_crm->cr_map[crm_msg->act_head.pub_lcore].act |= EN_QNSM_CRM_ACT_PUBLISH;
                for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++) {
                    qnsm_list_for_each_entry_safe(pos,
                                                  next,
                                                  &h_crm->cr_map[lcore_id].subscribe_list.subscribe_head, node) {
                        if (pos->target_lcore_id == crm_msg->act_head.pub_lcore) {
                            snprintf(ring_name, sizeof(ring_name), "ring_lcore%u--lcore%u", pos->target_lcore_id, lcore_id);
                            ring = rte_ring_create(
                                       ring_name,
                                       (1024UL << 4),
                                       rte_lcore_to_socket_id(lcore_id),
                                       (RING_F_SP_ENQ | RING_F_SC_DEQ));
                            QNSM_ASSERT(ring);
                            h_crm->cr_map[pos->target_lcore_id].ring[lcore_id] = ring;

                            printf("ring %s\n", ring_name);
                            /*alloc msg & fill*/
                            snd_msg = qnsm_crm_alloc();
                            QNSM_ASSERT(snd_msg);
                            rte_memcpy(snd_msg, crm_msg, sizeof(QNSM_CRM_MSG));
                            cr_value = snd_msg->cr_value;
                            cr_value->tx_lcore = lcore_id;
                            cr_value->rx_lcore = pos->target_lcore_id;
                            cr_value->ring = ring;
                            snd_msg->value_len = sizeof(QNSM_CR_VALUE);
                            qnsm_crm_msg_send(h_crm, h_crm->msgq_id[cr_value->tx_lcore], snd_msg);

                            snd_msg = qnsm_crm_alloc();
                            QNSM_ASSERT(snd_msg);
                            rte_memcpy(snd_msg, crm_msg, sizeof(QNSM_CRM_MSG));
                            cr_value = snd_msg->cr_value;
                            cr_value->tx_lcore = lcore_id;
                            cr_value->rx_lcore = pos->target_lcore_id;
                            cr_value->ring = ring;
                            snd_msg->value_len = sizeof(QNSM_CR_VALUE);
                            qnsm_crm_msg_send(h_crm, h_crm->msgq_id[cr_value->rx_lcore], snd_msg);
                        }
                    }
                }
            }

            if (EN_QNSM_CRM_ACT_SUBCRIBE == crm_msg->act_head.act) {
                uint32_t sub_lcore = crm_msg->act_head.sub_lcore;
                uint32_t pub_lcore = crm_msg->act_head.pub_lcore;
                h_crm->cr_map[sub_lcore].act |= EN_QNSM_CRM_ACT_SUBCRIBE;
                if (h_crm->cr_map[pub_lcore].act | EN_QNSM_CRM_ACT_PUBLISH) {
                    if (NULL == h_crm->cr_map[pub_lcore].ring[sub_lcore]) {
                        snprintf(ring_name, sizeof(ring_name), "ring_lcore%u--lcore%u", pub_lcore, sub_lcore);
                        ring = rte_ring_create(
                                   ring_name,
                                   (1024UL << 4),
                                   rte_lcore_to_socket_id(sub_lcore),
                                   (RING_F_SP_ENQ | RING_F_SC_DEQ));
                        QNSM_ASSERT(ring);
                        h_crm->cr_map[pub_lcore].ring[sub_lcore] = ring;
                        printf("ring %s\n", ring_name);

                        /*fill cr*/
                        snd_msg = qnsm_crm_alloc();
                        QNSM_ASSERT(snd_msg);
                        rte_memcpy(snd_msg, crm_msg, sizeof(QNSM_CRM_MSG));
                        cr_value = snd_msg->cr_value;
                        cr_value->tx_lcore = sub_lcore;
                        cr_value->rx_lcore = pub_lcore;
                        cr_value->ring = ring;
                        snd_msg->value_len = sizeof(QNSM_CR_VALUE);
                        qnsm_crm_msg_send(h_crm, h_crm->msgq_id[sub_lcore], snd_msg);

                        snd_msg = qnsm_crm_alloc();
                        QNSM_ASSERT(snd_msg);
                        rte_memcpy(snd_msg, crm_msg, sizeof(QNSM_CRM_MSG));
                        cr_value = snd_msg->cr_value;
                        cr_value->tx_lcore = sub_lcore;
                        cr_value->rx_lcore = pub_lcore;
                        cr_value->ring = ring;
                        snd_msg->value_len = sizeof(QNSM_CR_VALUE);
                        qnsm_crm_msg_send(h_crm, h_crm->msgq_id[pub_lcore], snd_msg);
                    }
                } else {
                    sub_node = (QNSM_CR_SUB_NODE *)rte_zmalloc_socket("QNSM_CRM_SUB_NODE",
                               sizeof(QNSM_CR_SUB_NODE),
                               QNSM_DDOS_MEM_ALIGN,
                               rte_lcore_to_socket_id(sub_lcore));
                    if (NULL == sub_node) {
                        QNSM_ASSERT(0);
                        return;
                    }

                    QNSM_INIT_LIST_HEAD(&sub_node->node);
                    sub_node->target_lcore_id = pub_lcore;
                    qnsm_list_add(&sub_node->node, &h_crm->cr_map[sub_lcore].subscribe_list.subscribe_head);
                }
            }
            break;
        }
        case EN_QNSM_CRM_MSG_OFFLINE: {
            /*now not support*/
            QNSM_ASSERT(0);
            break;
        }
        default: {
            break;
        }
    }
    return;
}

void qnsm_crm_msg_req_handle(void *crm)
{
    uint32_t msgq_id;
    QNSM_CRM *h_crm = crm;
    static const uint64_t us = 100 * 1000;

    for (msgq_id = 0; msgq_id < h_crm->n_msgq; msgq_id++) {
        for ( ; ; ) {
            QNSM_CRM_MSG *req;
            QMSM_CRM_REQ_HANDLER f_handle;

            req = qnsm_crm_msg_recv(h_crm, msgq_id);
            if (req == NULL)
                break;

            f_handle = (req->type < EN_QNSM_CRM_MSG_MAX) ?
                       qnsm_crm_msg_req_handler :
                       qnsm_crm_msg_req_invalid_handler;

            if (f_handle == NULL)
                f_handle = qnsm_crm_msg_req_invalid_handler;

            f_handle(h_crm, (void *) req);

            qnsm_crm_free(req);
        }
    }

    rte_eal_alarm_set(us, qnsm_crm_msg_req_handle, crm);
    return;
}

int32_t qnsm_crm_init(struct app_params *app, void **crm)
{
    uint16_t index = 0;
    uint16_t pos = 0;
    char msgq_name[64];
    QNSM_CRM *crm_hdl = NULL;
    uint16_t lcore_id = 0;

    crm_hdl = rte_zmalloc_socket(NULL,
                                 sizeof(QNSM_CRM),
                                 QNSM_DDOS_MEM_ALIGN,
                                 rte_socket_id());
    QNSM_ASSERT(crm_hdl);

    for (index = 0; index < app->n_pipelines; index++) {
        snprintf(msgq_name, sizeof(msgq_name), "MSGQ-REQ-%s", app->pipeline_params[index].name);
        pos = APP_PARAM_FIND(app->msgq_params, msgq_name);
        crm_hdl->msgq_in[index] = app->msgq[pos];

        snprintf(msgq_name, sizeof(msgq_name), "MSGQ-RSP-%s", app->pipeline_params[index].name);
        pos = APP_PARAM_FIND(app->msgq_params, msgq_name);
        crm_hdl->msgq_out[index] = app->msgq[pos];

        lcore_id = cpu_core_map_get_lcore_id(app->core_map,
                                             app->pipeline_params[index].socket_id,
                                             app->pipeline_params[index].core_id,
                                             app->pipeline_params[index].hyper_th_id);
        crm_hdl->msgq_id[lcore_id] = index;

        crm_hdl->n_msgq = app->n_pipelines;
    }

    memset(crm_hdl->cr_map, 0, sizeof(QNSM_CR) * APP_MAX_LCORES);
    for (index = 0; index < APP_MAX_LCORES; index++) {

        QNSM_INIT_LIST_HEAD(&crm_hdl->cr_map[index].subscribe_list.subscribe_head);
    }
    *crm = crm_hdl;

    return 0;
}
#endif


