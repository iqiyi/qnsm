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
#ifndef __QNSM_PORT_EX__
#define __QNSM_PORT_EX__

#include "app.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*QNSM_PORT_TX_POLICY)(void *pkt_info);

inline int32_t qnsm_port_rx(void *hdl, uint16_t port_id, struct rte_mbuf **mbuf);
inline uint16_t qnsm_rx_port_num(void *hdl);
inline struct rte_mbuf **qnsm_port_mbuf_array(void *hdl);
void* qnsm_port_hdl(void);

int32_t qnsm_port_in_num(void *para);
int32_t qnsm_port_out_num(void *para);

/*struct rte_port_out_stats *out_stats*/
int32_t qnsm_port_out_statis(void *para, void *out_stats, uint32_t port_index);
int32_t qnsm_port_dup_num(void *para);
int32_t qnsm_port_dup_statis(void *para, void *out_stats, uint32_t port_index);
int32_t qnsm_port_tap_num(void *para);
int32_t qnsm_port_tap_statis(void *para, void *out_stats, uint32_t port_index);
int32_t qnsm_port_dump_statis(void *para, void *out_stats);

/**
 * tx pkt load balance
 *
 * @param pos
 *   hash seed
 * @param mbuf
 *   pkt mbuf
 * @return
 *   0 success, other failed
 */
int32_t qnsm_port_tx_lb(uint32_t pos, struct rte_mbuf *mbuf);

/**
 * tx pkt to kernel net-stack
 *
 * @param pos
 *   hash seed
 * @param mbuf
 *   pkt mbuf
 * @return
 *   0 success, other failed
 */
int32_t qnsm_port_tap_tx_lb(uint32_t pos, struct rte_mbuf *mbuf);

/**
 * send pkt load balance to duplicate ports
 *
 * @param pos
 *   hash seed
 * @param mbuf
 *   pkt mbuf
 * @return
 *   0 success, other failed
 */
int32_t qnsm_port_dup_tx_lb(uint32_t pos, struct rte_mbuf *mbuf);

/**
 * send pkt load balance to dump ports
 *
 * @param mbuf
 *   pkt mbuf
 * @return
 *   0 success, other failed
 */
int32_t qnsm_port_dump_tx(struct rte_mbuf *mbuf);

#ifdef __cplusplus
}
#endif

#endif
