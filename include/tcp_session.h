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
#ifndef _TCP_SESS_H
#define _TCP_SESS_H

#include <sys/time.h>
#include <rte_malloc.h>

#include "util.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_session_ex.h"


#ifdef __cplusplus
extern "C" {
#endif

#define TH_FIN         0x01
#define TH_SYN         0x02
#define TH_SYNFIN      0x03
#define TH_RST         0x04
#define TH_PSH         0x08
#define TH_ACK         0x10
#define TH_SYNACK      0x12
#define TH_PUSHACK     0x18
#define TH_URG         0x20

typedef struct half_stream {
    char state;
    u_int seq;
    u_int list_count;
    struct skbuff *list;
} HALF_STRAEM;

typedef struct tcp_stream {
    uint8_t af;
    QNSM_SESS_ADDR addr;
    HALF_STRAEM active;
    HALF_STRAEM passive;

    /*state cbk data*/
    uint8_t established;
#ifdef  DEBUG_QNSM
    uint8_t dump_enable;
#endif
} __rte_cache_aligned TCP_STREAM;

typedef struct {
    struct qnsm_list_head node;

    QNSM_PACKET_INFO *pkt_info;
    uint32_t        seq;
    uint32_t        ack;
    uint16_t        len;
    uint16_t        dir;
} TCP_DATA;


struct psuedo_hdr {
    u_int saddr;
    u_int daddr;
    u_char zero;
    u_char protocol;
    u_short len;
};

#define FIN_SENT 120
#define FIN_CONFIRMED 121

struct skbuff {
    struct skbuff *next;
    struct skbuff *prev;

    char *data;  /* 保存包含ip tcp + data */
    u_int len;   /* 报文的长度 */
    u_int truesize; /* 保存数据长度去掉ip头 tcp头后的 */
    u_int seq;
};

typedef void (*on_established)(TCP_STREAM *conn, void *sess);
typedef void (*on_rst)(TCP_STREAM *conn, void *sess);
typedef void (*on_fin_ack)(TCP_STREAM *conn, void *sess);

typedef struct {
    on_established f_on_established;
    on_rst f_on_rst;
    on_fin_ack f_on_fin_ack;
} TCP_STATE_CBK;

typedef struct tcp_cache {
    struct rte_mempool *tcp_conn_cache;

    /*tcp stream reassemble cache*/
    struct rte_mempool *pkt_info_cache;
    uint64_t max_pkt_num;               /*sessm per lcore max reassemble mbuf num*/
    uint64_t cur_pkt_num;

    /*cb*/
    TCP_STATE_CBK cb;
} TCP_CACHE;

typedef struct {
    struct qnsm_list_head tcp_que;
    uint32_t data_cnt;
    uint32_t tcp_seq[2];
} QNSM_TCP_DATA_QUE;


inline int32_t tcp_proc_check(QNSM_PACKET_INFO* pkt_info, uint32_t *data_len);
int32_t tcp_conn_proc(QNSM_PACKET_INFO* pkt_info, void *sess, uint32_t *tcp_seq);
int32_t tcp_data_proc(QNSM_PACKET_INFO* pkt_info, QNSM_TCP_DATA_QUE *que, uint32_t dir, uint32_t payload_len);
void tcp_check_timeouts(void **item);
inline void tcp_free_data(TCP_DATA *data);
int32_t tcp_lcore_init(int32_t lcore_id, TCP_CACHE *cache);

#ifdef __cplusplus
}
#endif

#endif

