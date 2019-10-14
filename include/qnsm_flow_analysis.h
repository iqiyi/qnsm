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

#ifndef _QNSM_FLOW_ANALYSIS_H_
#define _QNSM_FLOW_ANALYSIS_H_

#include "list.h"
#include "qnsm_inspect_main.h"

#ifdef __cplusplus
extern "C" {
#endif

#if QNSM_PART("macro")

#define QNSM_HASH_EMPLOY_TIME           (60)

#define QNSM_PKT_TYPES_MAP(XX)       \
    XX(0,  total,      TOTAL)        \
    XX(1,  tcp,        TCP)          \
    /*classsify by tcp flag*/        \
    XX(2,  syn,        SYN)          \
    XX(3,  ack,        ACK)          \
    XX(4,  fin,        FIN)          \
    XX(5,  rst,        RST)          \
    XX(6,  synack,     SYNACK)       \
    XX(7,  pushack,    PSHACK)       \
    XX(8,  other_flag, OTHER_FLAG)   \
    /*classify by tcp dport*/        \
    XX(9,  http_get,   HTTP_GET)     \
    XX(10, http_post,  HTTP_POST)    \
    /*udp classify by udp dport*/    \
    XX(11, udp,        UDP)          \
    XX(12, dns_reply,  DNS_REPLY)    \
    XX(13, dns_query,  DNS_QUERY)    \
    XX(14, ntp,        NTP)          \
    XX(15, ssdp_req,   SSDP_REQ)     \
    XX(16, ssdp_rep,   SSDP_REP)     \
    /*others*/                       \
    XX(17, icmp,       ICMP)         \
    XX(18, frag,       FRAG)         \
    XX(19, esp,        ESP)          \
    XX(20, other,      OTHER)        \
    XX(21, type_max,   TYPE_MAX)

enum en_qnsm_detect {
#define XX(num, name, string) e_##name = num,
    QNSM_PKT_TYPES_MAP(XX)
#undef XX
};
#endif

typedef struct flow_statistics {
    uint64_t pkt_curr;
    uint64_t pkt_prev;
    uint64_t bit_curr;
    uint64_t bit_prev;

    uint64_t pps;
    uint64_t bps;
} QNSM_FLOW_STATISTICS;

#ifdef __cplusplus
}
#endif

#endif
