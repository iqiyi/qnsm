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

#ifndef __QNSM_MSG__
#define __QNSM_MSG__

#include "rte_ring.h"
#include "rte_spinlock.h"
#include "rte_timer.h"

#include "list.h"
#include "qnsm_dbg.h"
#include "qnsm_service.h"
#include "qnsm_msg_ex.h"
#include "app.h"

#ifdef __cplusplus
extern "C" {
#endif


#define QNSM_MSG_LCORE_MAX          (RTE_MAX_LCORE)

#define QNSM_MSG_TIMEOUT_MS         (100)
#define QNSM_MSG_POOL_SIZE          (1024UL << 9)

#define QNSM_MSG_TX_BURST_SIZE_MAX     (64)
#define QNSM_MSG_RX_BURST_SIZE_MAX     (128)

typedef enum {
    EN_QNSM_MSG_SERVICE_INVALID = 0x00,
    EN_QNSM_MSG_SERVICE_OFFLINE = 0x01,
    EN_QNSM_MSG_SERVICE_ONLINE  = 0x02,
    EN_QNSM_MSG_SERVICE_PUB     = 0x04,
} EN_QNSM_MSG_SERVICE_STATUS;

typedef enum {
    EN_QNSM_MSG_PIPE_INVALID     = 0x00,
    EN_QNSM_MSG_PIPE_INIT        = 0x01,
    EN_QNSM_MSG_PIPE_PUBLISHED   = 0x02,
    EN_QNSM_MSG_PIPE_SUBSCRIBED  = 0x04,
    EN_QNSM_MSG_PIPE_ESTABLISHED = 0x08,
    EN_QNSM_MSG_PIPE_MAX,
} EN_QNSM_MSG_PIPE_STATUS;

#define QNSM_PIPE_TX_STATS_IN_ADD(pipe, val) \
    pipe->statis.tx_statistics += val
#define QNSM_PIPE_TX_STATS_DROP_ADD(pipe, val) \
    pipe->statis.tx_drop_statistics += val
#define QNSM_PIPE_RX_STATS_IN_ADD(pipe, val) \
        pipe->statis.rx_statistics += val


typedef struct {
    struct qnsm_list_head node;
    EN_QNSM_MSG_ID msg_id;
    QNSM_MSG_PROC  msg_proc;
    QNSM_MSG_ENCAP msg_encap;
} QNSM_MSG_CB;

typedef struct qnsm_msg_lcore_para {
    EN_QNSM_APP app_type;
    uint32_t lcore_id;
    uint32_t socket_id;
    struct qnsm_list_head msg_proc_head;
    struct rte_timer      msg_flush_timer;
    EN_QNSM_MSG_SERVICE_STATUS service_status;

    /*sub lcore array*/
    uint8_t sub_target_lcore[EN_QNSM_APP_MAX][QNSM_MSG_LCORE_MAX];
    uint8_t sub_lcore_num[EN_QNSM_APP_MAX];

    /*rcv msg from lcore 0-QNSM_MSG_LCORE_MAX*/
    uint8_t rcv_lcore[QNSM_MSG_LCORE_MAX];
    uint16_t rcv_lcore_num;

    /*support burst rx*/
    uint16_t rx_burst_sz;
    char *rx_buf[2 * QNSM_MSG_RX_BURST_SIZE_MAX];
} __rte_cache_aligned QNSM_MSG_LCORE_PARA;

typedef struct qnsm_msg_pipe {
    struct rte_ring *ring;
    EN_QNSM_MSG_PIPE_STATUS pipe_status;

    /*support burst tx*/
    char *tx_buf[2 * QNSM_MSG_TX_BURST_SIZE_MAX];
    uint16_t tx_buf_count;
    uint16_t tx_burst_sz;

    /*pipe statistics*/
    QNSM_MSG_PIPE_STATIS statis;
} QNSM_MSG_PIPE;

typedef struct

{
    SERVICE_LIB_COMMON
    QNSM_MSG_LCORE_PARA lcore_para;
    QNSM_MSG_PIPE       tx_pipe[QNSM_MSG_LCORE_MAX];
    QNSM_MSG_PIPE       rx_pipe[QNSM_MSG_LCORE_MAX];
    struct rte_mempool  *msg_pool[APP_MAX_SOCKETS];
} QNSM_MSG_DATA;

typedef struct qnsm_msg_header {
    union {
        char str[8];
        uint32_t num[2];
    } magic_num;
    struct rte_mempool *pool;
    EN_QNSM_MSG_ID msg_id;
    uint32_t msg_len;
    uint32_t rsvd;
} __rte_cache_aligned QNSM_MSG_HEADER;

void qnsm_msg_cr_rsp(void *arg, void *msg);
int32_t qnsm_msg_pre_init(void);
int32_t qnsm_msg_init(EN_QNSM_APP app_type, void **handle);
int32_t qnsm_msg_dispatch(void *hdl);


#ifdef __cplusplus
}
#endif

#endif

