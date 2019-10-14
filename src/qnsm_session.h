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

#ifndef __QNSM_SESSION__
#define __QNSM_SESSION__

#include <rte_timer.h>

#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_dpi_ex.h"
#include "qnsm_session_ex.h"
#include "qnsm_ip.h"
#include "tcp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define     QNSM_SESS_MAX   ((65536UL) << 3)

#define QNSM_SESS_STATIS_AGG_INTERVAL_SEC (INTVAL)
#define QNSM_SESS_AGING_TIME              (60)

typedef enum {
    EN_QNSM_SESS_DIR_SAME = 0,
    EN_QNSM_SESS_DIR_DIFF = 1,
    EN_QNSM_SESS_DIR_MAX
} EN_QNSM_SES_DIR;

typedef void (*ITER_SESS_FUNC)(void *cl, uint32_t lcore_id, void *iter_data, void *arg);
typedef enum {
    EN_ITER_SESS_STATIS = 0,
    EN_ITER_SESS_CONN,
    EN_ITER_SESS_DATA_QUE,
    EN_ITER_SESS_ADDR,
    EN_ITER_SESS_PROTO,
} EN_ITER_SESS_TYPE;

typedef struct {
    QNSM_SESS_ADDR key;
    uint8_t af:4;
    uint8_t vip_is_src:4;
    uint8_t vip_agg_pkt_type;
    uint8_t tcp_flags[DIRECTION_MAX];
    uint8_t icmp_type[DIRECTION_MAX];
    void *vip_item;

    /*statis data*/
    QNSM_FLOW_STATISTICS            sess_statis[EN_QNSM_SESS_DIR_MAX];
    uint64_t                        last_tick;
#ifdef __FLOW_LIFE_STATTIS
    uint64_t                        begin_time;
#endif

    /*tcp conn stat proc*/
    TCP_STREAM *tcp_stream;

    /*tcp stream reassemble*/
#ifdef __QNSM_STREAM_REASSEMBLE
    QNSM_TCP_DATA_QUE data_que;
#endif

    /*parse app info*/
    EN_QNSM_DPI_PROTO app_proto;
    void *app_parse_info;

    /*timer*/
#ifdef __DDOS
    struct rte_timer agg_timer;
#endif
    struct rte_timer aging_timer;
} __rte_cache_aligned QNSM_SESS;

typedef struct {
    TCP_CACHE tcp_data;

    /*biz vip tbl*/
    struct rte_lpm *biz_vip_tbl;
    struct rte_timer vip_timer;
    QNSM_SESS_VIP_DATA *vip_data;
    uint32_t remote_vip_num;
    uint32_t local_vip_data;

    /*vip ops tbl*/
    QNSM_SESS_VIP_OPS inet_ops_list[EN_QNSM_AF_MAX];

    /*sample conf*/
    uint16_t pkt_sample_rate;
    uint16_t flow_sample_rate;
    uint16_t pkt_pass;
    uint16_t rsvd;

#ifdef  DEBUG_QNSM
    /*counter*/
    uint64_t inner_pkt_counter;
    uint64_t outer_pkt_counter;
    uint64_t filter_pkt_counter;
    uint64_t bits;
    uint64_t pps;
    uint64_t bps;
    struct rte_timer statis_timer;
#endif

    /*port+app map*/
    EN_QNSM_DPI_PROTO port_map[65536];
} __rte_cache_aligned QNSM_SESS_DATA;

inline int32_t qnsm_sess_cmp(void *key, void *item_key);
inline uint32_t qnsm_sess_hash(void *key);


#ifdef __cplusplus
}
#endif

#endif

