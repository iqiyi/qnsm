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
#ifndef __QNSM_SESSION_EX__
#define __QNSM_SESSION_EX__

#include "list.h"
#include "qnsm_dpi_ex.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XMM_NUM_IN_IPV6_5TUPLE 3

#define QNSM_SESS_MAX_DPI_POLICY (4)            /*max dpi policy num*/
#define QNSM_SESS_VIP_MAX  (2048)               /*vip num per lcore*/

#define QNSM_TCP_STATE_MAP(XX)                   \
    XX(1,  ESTABLISHED,      ESTABLISHED)        \
    XX(2,  SYN_SENT,         SYN_SENT)           \
    XX(3,  SYN_RECV,         SYN_RECV)           \
    XX(4,  FIN_WAIT1,        FIN_WAIT1)          \
    XX(5,  FIN_WAIT2,        FIN_WAIT2)          \
    XX(6,  TIME_WAIT,        TIME_WAIT)          \
    XX(7,  CLOSE,            CLOSE)              \
    XX(8,  CLOSE_WAIT,       CLOSE_WAIT)         \
    XX(9,  LAST_ACK,         LAST_ACK)           \
    XX(10, LISTEN,           LISTEN)             \
    XX(11, CLOSING,          CLOSING)            \
    /*port from libnids*/                        \
    XX(12, FIN_SENT,         FIN_SENT)           \
    XX(13, FIN_CONFIRMED,    FIN_CONFIRMED)      \

enum en_qnsm_tcp_state {
#define XX(num, name, string) QNSM_TCP_##name = num,
    QNSM_TCP_STATE_MAP(XX)
#undef XX
    QNSM_TCP_STATE_MAX,
};

typedef enum en_qnsm_tcp_state EN_QNSM_TCP_STATE;

enum {
    PROTO_FIELD_IPV4,
    SRC_FIELD_IPV4,
    DST_FIELD_IPV4,
    SRCP_FIELD_IPV4,
    DSTP_FIELD_IPV4,
    NUM_FIELDS_IPV4
};

enum {
    PROTO_FIELD_IPV6,
    SRC1_FIELD_IPV6,
    SRC2_FIELD_IPV6,
    SRC3_FIELD_IPV6,
    SRC4_FIELD_IPV6,
    DST1_FIELD_IPV6,
    DST2_FIELD_IPV6,
    DST3_FIELD_IPV6,
    DST4_FIELD_IPV6,
    SRCP_FIELD_IPV6,
    DSTP_FIELD_IPV6,
    NUM_FIELDS_IPV6
};


union ipv4_5tuple_host {
    struct {
        uint8_t  pad0;
        uint8_t  proto;
        uint16_t pad1;
        uint32_t ip_src;
        uint32_t ip_dst;
        uint16_t port_src;
        uint16_t port_dst;
    };
    xmm_t xmm;
};

union ipv6_5tuple_host {
    struct {
        uint16_t pad0;
        uint8_t  proto;
        uint8_t  pad1;
        uint8_t  ip_src[IPV6_ADDR_LEN];
        uint8_t  ip_dst[IPV6_ADDR_LEN];
        uint16_t port_src;
        uint16_t port_dst;
        uint64_t reserve;
    };
    xmm_t xmm[XMM_NUM_IN_IPV6_5TUPLE];
};

typedef union qnsm_sess_addr {
    union ipv4_5tuple_host v4_5tuple;
    union ipv6_5tuple_host v6_5tuple;
} QNSM_SESS_ADDR;

typedef struct {
    uint8_t protocol;
    uint8_t vip_is_src;
    uint8_t af;
    uint8_t tcp_flags[DIRECTION_MAX];
    uint8_t icmp_type[DIRECTION_MAX];
    QNSM_IN_ADDR cus_ip;
    QNSM_SESS_ADDR sess_addr;
    uint64_t time_old;
    uint64_t time_new;
    uint64_t in_pps;
    uint64_t in_bps;
    uint64_t out_pps;
    uint64_t out_bps;

} QNSM_SESS_AGG_MSG;

typedef struct {
    uint8_t protocol;
    uint8_t af;
    QNSM_SESS_ADDR sess_addr;
    uint64_t time_begin;
    uint64_t time_end;
    uint64_t in_pkts;
    uint64_t in_bits;
    uint64_t out_pkts;
    uint64_t out_bits;

    /*sess state*/
    EN_QNSM_TCP_STATE active_state;
    EN_QNSM_TCP_STATE passive_state;

    /*tcp active side*/
    QNSM_IN_ADDR active_ip;
    uint32_t uint_rsvd[3];
} QNSM_SESS_LIFE_STATIS_MSG;

typedef struct {
    void *sess;
    uint64_t time_old;
    uint64_t time_new;

    QNSM_IN_ADDR cus_ip;
} QNSM_SESS_MSG_DATA;

typedef struct {
    uint64_t pkts;
    uint64_t bits;
} QNSM_SESS_DPI_PROTO_STATIS;

typedef struct {
    QNSM_IN_ADDR    vip_key;
    uint16_t dpi_sport;
    uint8_t af;
    uint8_t rsvd;
    uint32_t seq_id;
    QNSM_SESS_DPI_PROTO_STATIS statis[EN_QNSM_DPI_PROTO_MAX + 1];
} QNSM_SESS_DPI_STATIS_MSG;

int32_t qnsm_sess_service_init(void);
int32_t qnsm_sess_agg_msg_proc(void *data, uint32_t data_len);
void qnsm_rx_proc(void *this_app_data, uint32_t lcore_id, struct rte_mbuf *mbuf);

#ifdef __cplusplus
}
#endif

#endif
