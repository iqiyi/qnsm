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
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include "rte_alarm.h"

#include "util.h"
#include "qnsm_crm.h"
#include "qnsm_service.h"
#include "qnsm_msg.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_MSG_HASH_CRC 1
#endif

static struct rte_mempool *qnsm_msg_pool[APP_MAX_SOCKETS];

inline int32_t qnsm_msg_get_pipe_statis(uint16_t rx_lcore, uint16_t tx_lcore, QNSM_MSG_PIPE_STATIS *statis)
{
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;
    uint32_t p_id;
    uint32_t lcore_id = 0;
    QNSM_DATA *app_data = NULL;
    QNSM_MSG_DATA *msg_data = NULL;
    int32_t ret = -1;

    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        pipeline_para = &app_paras->pipeline_params[p_id];
        lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                             pipeline_para->socket_id,
                                             pipeline_para->core_id,
                                             pipeline_para->hyper_th_id);

        if (lcore_id == rx_lcore) {
            app_data = pipeline_para->app_data;
            msg_data = app_data->service_lib_handle[EN_QNSM_SERVICE_MSG];
            statis->rx_statistics = msg_data->rx_pipe[tx_lcore].statis.rx_statistics;
            ret = 0;
        }

        if (lcore_id == tx_lcore) {
            app_data = pipeline_para->app_data;
            msg_data = app_data->service_lib_handle[EN_QNSM_SERVICE_MSG];

            statis->tx_statistics = msg_data->tx_pipe[rx_lcore].statis.tx_statistics;
            statis->tx_drop_statistics = msg_data->tx_pipe[rx_lcore].statis.tx_drop_statistics;
            ret = 0;
        }
    }
    return ret;
}

static int32_t qnsm_msg_app_init(QNSM_MSG_DATA *msg_data, EN_QNSM_APP app_type)
{
    QNSM_MSG_LCORE_PARA  *lcore_para = NULL;
    uint16_t lcore_id = rte_lcore_id();
    uint16_t socket_id = rte_lcore_to_socket_id(lcore_id);

    QNSM_ASSERT(EN_QNSM_APP_MAX != app_type);

    lcore_para = &msg_data->lcore_para;

    lcore_para->app_type = app_type;
    lcore_para->lcore_id = lcore_id;
    lcore_para->socket_id = socket_id;
    lcore_para->service_status = EN_QNSM_MSG_SERVICE_INVALID;

    QNSM_INIT_LIST_HEAD(&lcore_para->msg_proc_head);
    memset(lcore_para->sub_lcore_num, 0, sizeof(lcore_para->sub_lcore_num));

    lcore_para->rx_burst_sz = QNSM_MSG_RX_BURST_SIZE_MAX;
    memset(lcore_para->rcv_lcore, 0xFF, sizeof(lcore_para->rcv_lcore));
    lcore_para->rcv_lcore_num = 0;
    QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_INFO, "msg lcore %u\n", lcore_id);

    return 0;
}

void qnsm_msg_cr_rsp(void *arg, void *msg)
{
    QNSM_MSG_DATA *msg_data = arg;
    QNSM_CRM_MSG *rsp_msg = msg;
    struct app_params *app = qnsm_service_get_cfg_para();
    enum qnsm_crm_act act = EN_QNSM_CRM_ACT_MAX;
    uint32_t pub_lcore = 0xFF;
    uint32_t sub_lcore = 0xFF;
    uint32_t local_lcore = msg_data->lcore_para.lcore_id;

    QNSM_ASSERT(rsp_msg);
    QNSM_ASSERT(sizeof(QNSM_CR_VALUE) == rsp_msg->value_len);

    act = rsp_msg->act_head.act;
    sub_lcore = rsp_msg->cr_value[0].tx_lcore;
    pub_lcore = rsp_msg->cr_value[0].rx_lcore;

    switch (act) {
        case EN_QNSM_CRM_ACT_PUBLISH:
        case EN_QNSM_CRM_ACT_SUBCRIBE: {
            if (local_lcore == sub_lcore) {
                EN_QNSM_APP pub_lcore_type = app->app_type[pub_lcore];
                uint8_t sub_lcore_num = msg_data->lcore_para.sub_lcore_num[pub_lcore_type];

                msg_data->lcore_para.sub_target_lcore[pub_lcore_type][sub_lcore_num] = pub_lcore;
                msg_data->lcore_para.sub_lcore_num[pub_lcore_type]++;
                msg_data->tx_pipe[pub_lcore].ring = rsp_msg->cr_value[0].ring;

                printf("lcore %d sub %d, sub_lcore_num %d\n", sub_lcore, pub_lcore, msg_data->lcore_para.sub_lcore_num[pub_lcore_type]);
            }

            if (local_lcore == pub_lcore) {
                msg_data->lcore_para.rcv_lcore[msg_data->lcore_para.rcv_lcore_num] = sub_lcore;
                msg_data->lcore_para.rcv_lcore_num++;
                msg_data->rx_pipe[sub_lcore].ring = rsp_msg->cr_value[0].ring;
            }
            break;

        }
        default: {
            QNSM_ASSERT(0);
        }
    }

    return;
}


static void qnsm_msg_obj_init(struct rte_mempool *mp,
                              __attribute__((unused)) void *opaque_arg,
                              void *_m,
                              __attribute__((unused)) unsigned i)
{
    QNSM_MSG_HEADER *m = _m;
    static const char *magic = "qnsmmsg";

    strncpy(m->magic_num.str, magic, strlen(magic));
    memset(m + 1, 0, (mp->elt_size - sizeof(QNSM_MSG_HEADER)));
    return;
}


int32_t qnsm_msg_pre_init(void)
{
    int32_t socket_id;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    char pool_name[128];

    /*pool init*/
    for (socket_id = 0; socket_id < APP_MAX_SOCKETS; socket_id++) {

        if (app_is_socket_used(app_paras, socket_id) == 0) {
            continue;
        }

        /*msg pool*/
        snprintf(pool_name, sizeof(pool_name), "QNSM_MSG_POOL_SOCKET%u", socket_id);
        qnsm_msg_pool[socket_id] = rte_mempool_create(pool_name,
                                   QNSM_MSG_POOL_SIZE,
                                   sizeof(QNSM_MSG_HEADER) + QNSM_MSG_MAX_DATA_LEN,
                                   64,
                                   0,
                                   NULL, NULL,
                                   qnsm_msg_obj_init, NULL,
                                   socket_id, 0);
        if (NULL == qnsm_msg_pool[socket_id]) {
            QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_ERR, "failed\n");
            QNSM_ASSERT(0);
        }
    }
    return 0;
}

int32_t qnsm_msg_init(EN_QNSM_APP app_type, void **handle)
{
    int32_t socket_id;
    int32_t lcore_id;
    QNSM_MSG_DATA *msg_data = NULL;

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_MSG, QNSM_DBG_ALL);
    msg_data = rte_zmalloc_socket("QNSM_MSG", sizeof(QNSM_MSG_DATA), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == msg_data) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_ERR, "msg init failed\n");
        return -1;
    }

    for (socket_id = 0; socket_id < APP_MAX_SOCKETS; socket_id++) {
        msg_data->msg_pool[socket_id] = qnsm_msg_pool[socket_id];
    }

    /*init lcore para*/
    (void)qnsm_msg_app_init(msg_data, app_type);

    for (lcore_id = 0; lcore_id < QNSM_MSG_LCORE_MAX; lcore_id++) {
        /*init tx pipe*/
        msg_data->tx_pipe[lcore_id].ring = NULL;
        msg_data->tx_pipe[lcore_id].pipe_status = EN_QNSM_MSG_PIPE_INIT;
        msg_data->tx_pipe[lcore_id].tx_buf_count = 0;
        msg_data->tx_pipe[lcore_id].tx_burst_sz = QNSM_MSG_TX_BURST_SIZE_MAX;
        memset(&msg_data->tx_pipe[lcore_id].statis, 0, sizeof(QNSM_MSG_PIPE_STATIS));

        /*init rx pipe*/
        msg_data->rx_pipe[lcore_id].ring = NULL;
        msg_data->rx_pipe[lcore_id].pipe_status = EN_QNSM_MSG_PIPE_INIT;
        memset(&msg_data->rx_pipe[lcore_id].statis, 0, sizeof(QNSM_MSG_PIPE_STATIS));
    }

    SET_LIB_COMMON_STATE(msg_data, en_lib_state_init);
    *handle = msg_data;
    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);
    return 0;
}

int32_t qnsm_msg_publish(void)
{
    uint32_t              lcore_id = rte_lcore_id();
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *lcore_para = NULL;
    QNSM_CRM_MSG *msg = NULL;

    lcore_para = &msg_data->lcore_para;
    lcore_para->service_status |= EN_QNSM_MSG_SERVICE_PUB;

    /*send msg to crm*/
    msg = qnsm_crm_alloc();
    QNSM_ASSERT(msg);

    msg->type = EN_QNSM_CRM_MSG_ONLINE;
    msg->act_head.act = EN_QNSM_CRM_ACT_PUBLISH;
    msg->act_head.pub_lcore = lcore_id;
    msg->value_len = 0;

    QNSM_LOG(INFO, "lcore %d send pub msg to crm\n", lcore_id);
    qnsm_crm_agent_msg_send(msg);
    return 0;
}

int32_t qnsm_msg_subscribe(uint32_t target_lcore_id)
{
    uint32_t              lcore_id = rte_lcore_id();
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *lcore_para = NULL;

    /*discard self*/
    if (lcore_id == target_lcore_id) {
        return 0;
    }

    lcore_para = &msg_data->lcore_para;
    lcore_para->service_status |= EN_QNSM_MSG_SERVICE_ONLINE;

    QNSM_CRM_MSG *msg = NULL;

    msg = qnsm_crm_alloc();
    QNSM_ASSERT(msg);
    msg->type = EN_QNSM_CRM_MSG_ONLINE;
    msg->act_head.act = EN_QNSM_CRM_ACT_SUBCRIBE;
    msg->act_head.sub_lcore = lcore_id;
    msg->act_head.pub_lcore = target_lcore_id;
    msg->value_len = 0;

    QNSM_LOG(INFO, "lcore %d send sub lcore %d msg to crm\n", lcore_id, target_lcore_id);
    qnsm_crm_agent_msg_send(msg);

    return 0;
}


/*reg msg proc func*/
int32_t qnsm_msg_reg(EN_QNSM_MSG_ID msg_id, QNSM_MSG_PROC msg_proc, QNSM_MSG_ENCAP msg_encap)
{
    uint32_t socket_id;
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *lcore_para = NULL;
    QNSM_MSG_CB          *msg_cb = NULL;
    uint32_t              lcore_id = rte_lcore_id();

    socket_id = rte_lcore_to_socket_id(lcore_id);
    lcore_para = &msg_data->lcore_para;
    msg_cb = (QNSM_MSG_CB *)rte_zmalloc_socket("QNSM_MSG_CB", sizeof(QNSM_MSG_CB), QNSM_DDOS_MEM_ALIGN, socket_id);
    if (NULL == msg_cb) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_ERR, "failed\n");
        return -1;
    }

    msg_cb->msg_id = msg_id;
    msg_cb->msg_proc = msg_proc;
    msg_cb->msg_encap = msg_encap;
    QNSM_INIT_LIST_HEAD(&msg_cb->node);
    qnsm_list_add(&msg_cb->node, &lcore_para->msg_proc_head);

    SET_LIB_COMMON_STATE(msg_data, en_lib_state_load);
    return 0;
}

/*async send flush*/
static int32_t qnsm_msg_send_flush(QNSM_MSG_DATA *msg_data, uint32_t dest_lcore_id)
{
    uint32_t socket_id;
    QNSM_MSG_PIPE *pipe = NULL;
    uint16_t nb_tx = 0;
    uint16_t drop_cnt;

    pipe = &msg_data->tx_pipe[dest_lcore_id];
    if (NULL == pipe->ring) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_ERR, "failed\n");
        return -1;
    }

    socket_id = msg_data->lcore_para.socket_id;
    if (pipe->tx_buf_count > 0) {
        nb_tx = rte_ring_sp_enqueue_burst(pipe->ring, (void **)pipe->tx_buf, pipe->tx_buf_count);
        if (nb_tx < pipe->tx_buf_count) {
            drop_cnt = pipe->tx_buf_count - nb_tx;
            QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_EVT, "act sent %u drop %u\n", nb_tx, drop_cnt);
            rte_mempool_put_bulk(msg_data->msg_pool[socket_id], (void **)&pipe->tx_buf[nb_tx], drop_cnt);
            QNSM_PIPE_TX_STATS_DROP_ADD(pipe, drop_cnt);
        }
        QNSM_PIPE_TX_STATS_IN_ADD(pipe, nb_tx);
        pipe->tx_buf_count = 0;
    }

    return 0;
}

static int32_t qnsm_msg_send(uint32_t dest_lcore_id, EN_QNSM_MSG_ID msg_id, void *data, uint16_t sync)
{
    uint32_t socket_id;
    QNSM_MSG_HEADER *msg_header = NULL;
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    struct rte_ring *ring = NULL;
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;
    QNSM_MSG_CB          *msg_cb = NULL;
    QNSM_MSG_PIPE *pipe = NULL;
    uint32_t nb_tx = 0;
    int32_t ret = 0;

    local_lcore_para = &msg_data->lcore_para;
    socket_id = local_lcore_para->socket_id;
    pipe = &msg_data->tx_pipe[dest_lcore_id];

    /*according dest_lcore_id & local_core_id,
     *find ring
     */
    ring = pipe->ring;
    if (NULL == ring) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_ERR, "failed\n");
        ret = -1;
        goto EXIT;
    }
    if (0 >= rte_ring_free_count(ring)) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_WARN, "local_core %u que full\n", local_lcore_para->lcore_id);
        ret = -1;
        goto EXIT;
    }

    if (rte_mempool_get(msg_data->msg_pool[socket_id], (void **)&msg_header)) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_EVT, "lcore %u get msg failed\n", local_lcore_para->lcore_id);
        ret = -1;
        goto EXIT;
    }
    msg_header->pool = msg_data->msg_pool[socket_id];
    msg_header->msg_id = msg_id;

    qnsm_list_for_each_entry(msg_cb, &local_lcore_para->msg_proc_head, node) {
        if (msg_cb->msg_id == msg_header->msg_id) {
            msg_cb->msg_encap(msg_header + 1, &msg_header->msg_len, data);
            break;
        }
    }
    if (msg_header->pool != msg_data->msg_pool[socket_id]) {
        QNSM_ASSERT(0);
    }

    if (sync) {
        /*enque*/
        if (-ENOBUFS == rte_ring_sp_enqueue(ring, msg_header)) {
            /*
            *now just recycle resource
            */
            rte_mempool_put(msg_data->msg_pool[socket_id], (void *)msg_header);
            QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_EVT, "msg que full\n");
            ret = -1;
            goto EXIT;
        }
        QNSM_PIPE_TX_STATS_IN_ADD(pipe, 1);
    } else {
        pipe->tx_buf[pipe->tx_buf_count]  = (char *)msg_header;
        pipe->tx_buf_count++;
        if (pipe->tx_buf_count >= pipe->tx_burst_sz) {
            nb_tx = rte_ring_sp_enqueue_burst(ring, (void **)pipe->tx_buf, pipe->tx_buf_count);
            if (nb_tx < pipe->tx_buf_count) {
                QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_EVT, "act sent %u drop %u\n", nb_tx, pipe->tx_buf_count - nb_tx);
                for ( ; nb_tx < pipe->tx_buf_count; nb_tx++) {
                    rte_mempool_put(msg_data->msg_pool[socket_id], (void *)pipe->tx_buf[nb_tx]);
                }
                QNSM_PIPE_TX_STATS_DROP_ADD(pipe, pipe->tx_buf_count - nb_tx);
            }
            QNSM_PIPE_TX_STATS_IN_ADD(pipe, nb_tx);
            pipe->tx_buf_count = 0;
        }
    }

EXIT:
    if (ret) {
        QNSM_PIPE_TX_STATS_DROP_ADD(pipe, 1);
    }
    return ret;
}

int32_t qnsm_msg_send_multi(EN_QNSM_APP app_type, EN_QNSM_MSG_ID msg_id, void *data, uint16_t sync)
{
    int32_t ret = 0;
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;
    uint32_t pos = 0;

    local_lcore_para = &msg_data->lcore_para;
    for (pos = 0; pos < local_lcore_para->sub_lcore_num[app_type]; pos++) {
        ret |= qnsm_msg_send(local_lcore_para->sub_target_lcore[app_type][pos], msg_id, data, sync);
    }
    return ret;
}

int32_t qnsm_msg_send_lb(EN_QNSM_APP app_type, EN_QNSM_MSG_ID msg_id, void *data, uint32_t seed, uint16_t sync)
{
    int32_t ret = 0;
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;
    uint32_t pos = 0;
    uint32_t sub_lcore_num = 0;

    local_lcore_para = &msg_data->lcore_para;
    sub_lcore_num = local_lcore_para->sub_lcore_num[app_type];
    if (0 == sub_lcore_num) {
        return ret;
    }

#ifdef QNSM_MSG_HASH_CRC
    pos = rte_hash_crc_4byte(seed, 0);
#else
    pos = rte_jhash_1word(seed, pos);
#endif
    if (likely(rte_is_power_of_2(sub_lcore_num))) {
        pos = pos & (sub_lcore_num - 1);
    } else {
        pos = pos % (sub_lcore_num);
    }
    ret = qnsm_msg_send(local_lcore_para->sub_target_lcore[app_type][pos], msg_id, data, sync);
    return ret;
}



/*multicast send not care core type*/
int32_t qnsm_msg_send_all(EN_QNSM_MSG_ID msg_id, void *data)
{
    int32_t ret = 0;
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;
    EN_QNSM_APP app_id = 0;
    uint32_t pos = 0;

    local_lcore_para = &msg_data->lcore_para;

    for (app_id = 0; app_id < EN_QNSM_APP_MAX; app_id++) {
        for (pos = 0; pos < local_lcore_para->sub_lcore_num[app_id]; pos++) {
            ret |= qnsm_msg_send(local_lcore_para->sub_target_lcore[app_id][pos], msg_id, data, 1);
        }
    }
    return ret;
}

/*
*msg dispatch
*timer proc
*loop all rings
*decode msg type, call msg proc
*free resources
*/
int32_t qnsm_msg_dispatch(void *hdl)
{
    uint32_t lcore_id;
    QNSM_MSG_DATA *msg_data = hdl;
    QNSM_MSG_PIPE *pipe = NULL;
    QNSM_MSG_HEADER *msg_header = NULL;
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;
    QNSM_MSG_CB          *msg_cb = NULL;
    struct rte_mempool *tmp_pool = NULL;
    uint16_t nb_rx = 0;
    uint16_t index = 0;
    uint16_t rcv_index = 0;

    local_lcore_para = &msg_data->lcore_para;
    for (rcv_index = 0; rcv_index < local_lcore_para->rcv_lcore_num; rcv_index++) {
        lcore_id = local_lcore_para->rcv_lcore[rcv_index];

        pipe = &msg_data->rx_pipe[lcore_id];
        if (NULL == pipe->ring) {
            continue;
        }
        if (rte_ring_empty(pipe->ring)) {
            continue;
        }

        nb_rx = rte_ring_sc_dequeue_burst(pipe->ring, (void **)local_lcore_para->rx_buf, local_lcore_para->rx_burst_sz);
        for (index = 0; index < nb_rx; index++) {
            msg_header = (QNSM_MSG_HEADER *)local_lcore_para->rx_buf[index];
            tmp_pool = msg_header->pool;
            QNSM_ASSERT(0x6d736e71 == msg_header->magic_num.num[0]);  //0x6d736e71 == "qnsm"
            QNSM_ASSERT(tmp_pool);

            /*need opt*/
            qnsm_list_for_each_entry(msg_cb, &local_lcore_para->msg_proc_head, node) {
                if (msg_cb->msg_id == msg_header->msg_id) {
                    QNSM_ASSERT(msg_cb->msg_proc);
                    msg_cb->msg_proc(msg_header + 1, msg_header->msg_len);
                    break;
                }
            }

            /*recycle resource*/
            QNSM_ASSERT(tmp_pool == msg_header->pool);
            rte_mempool_put(msg_header->pool, msg_header);
        }

        QNSM_PIPE_RX_STATS_IN_ADD(pipe, nb_rx);
    }

    return 0;
}

static void qnsm_msg_flush_timer_proc(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_MSG_DATA *msg_data = arg;
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;
    EN_QNSM_APP app_id = 0;
    uint32_t pos = 0;

    local_lcore_para = &msg_data->lcore_para;
    for (app_id = 0; app_id < EN_QNSM_APP_MAX; app_id++) {
        for (pos = 0; pos < local_lcore_para->sub_lcore_num[app_id]; pos++) {
            (void)qnsm_msg_send_flush(msg_data, local_lcore_para->sub_target_lcore[app_id][pos]);
        }
    }
    return;
}
void qnsm_msg_flush_timer_init(void)
{
    int32_t ret = 0;
    QNSM_MSG_DATA *msg_data = qnsm_service_handle(EN_QNSM_SERVICE_MSG);
    QNSM_MSG_LCORE_PARA  *local_lcore_para = NULL;

    local_lcore_para = &msg_data->lcore_para;

    rte_timer_init(&local_lcore_para->msg_flush_timer);
    ret = rte_timer_reset(&local_lcore_para->msg_flush_timer,
                          rte_get_timer_hz() * 3, PERIODICAL,
                          local_lcore_para->lcore_id, qnsm_msg_flush_timer_proc, msg_data);
    if (ret < 0) {
        QNSM_DEBUG(QNSM_DBG_M_MSG, QNSM_DBG_ERR,"Cannot set lcore %d timer\n", local_lcore_para->lcore_id);
        return;
    }
    return;
}
