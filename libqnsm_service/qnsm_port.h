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

#ifndef __QNSM_PORT__
#define __QNSM_PORT__

#include "rte_port.h"
#include "qnsm_service.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_PORT_MAX             (48)
#define QNSM_PORT_RETA_SIZE       (64)

typedef struct {
    struct rte_port_in_ops  *in_ops[APP_PKTQ_IN_MAX];
    struct rte_port_out_ops *out_ops[APP_PKTQ_OUT_MAX];
} QNSM_PORT_OPS;

typedef struct {
    struct rte_port_in_ops ops;
    void *h_port;
    uint32_t burst_size;
} __rte_cache_aligned QNSM_PORT_IN;

typedef struct {
    struct rte_port_out_ops ops;
    void *h_port;

    /*
    *pkt cross socket
    *now do pkt cpy
    */
    struct rte_mempool *pool;
} __rte_cache_aligned QNSM_PORT_OUT;

typedef struct {
    SERVICE_LIB_COMMON
    QNSM_PORT_IN port_in[QNSM_PORT_MAX];
    QNSM_PORT_OUT port_out[QNSM_PORT_MAX];
    struct rte_mbuf *pkts[RTE_PORT_IN_BURST_SIZE_MAX];
    uint8_t  reta[QNSM_PORT_RETA_SIZE];  /*tx redirect tbl*/
    uint16_t rx_port_cnt;
    uint16_t tx_port_cnt;      /*not include dump ports, nor dup ports*/
    uint16_t n_tx_port_pow2;

    uint16_t  n_dump_port;
    QNSM_PORT_OUT port_dump;

    uint16_t  n_dup_port;
    uint16_t  n_dup_port_pow2;
    QNSM_PORT_OUT port_dup_tx[QNSM_PORT_MAX];

#ifdef RTE_LIBRTE_KNI
    uint16_t  n_kni_port;
    uint16_t  n_kni_port_pow2;
    QNSM_PORT_OUT port_kni_tx[QNSM_PORT_MAX];
#endif

    uint16_t  n_tap_port;
    uint16_t  n_tap_port_pow2;
    QNSM_PORT_OUT port_tap_tx[QNSM_PORT_MAX];

    QNSM_PORT_TX_POLICY policy_fun;
} __rte_cache_aligned QNSM_PORT_HANDLE;

int32_t qnsm_port_pre_init(void);
int32_t qnsm_port_service_init(struct app_params *app, struct app_pipeline_params *pipeline_params, void **tbl_handle);
int32_t qnsm_port_tx_flush(void *hdl);

#define QNSM_PORT_TX_FLUSH(hdl)   \
    qnsm_port_tx_flush(hdl)


#ifdef __cplusplus
}
#endif

#endif
