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


#ifndef _INSPECT_MAIN_H_
#define _INSPECT_MAIN_H_

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPV6_ADDR_LEN 16

enum en_qnsm_ip_af {
    EN_QNSM_AF_IPv4 = 0,
    EN_QNSM_AF_IPv6,
    EN_QNSM_AF_MAX
};

struct qnsm_in_addr {
    uint32_t s_addr;
};

struct qnsm_in6_addr {
    union {
        uint8_t __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __in6_u;
#define s6_addr                 __in6_u.__u6_addr8
#define s6_addr16              __in6_u.__u6_addr16
#define s6_addr32              __in6_u.__u6_addr32
};

typedef union {
    struct qnsm_in_addr  in4_addr;
    struct qnsm_in6_addr in6_addr;
} QNSM_IN_ADDR;


#if QNSM_PART("pkt info")

typedef union l4_header {
    struct tcphdr   *th;
    struct udphdr   *uh;
    struct icmphdr  *icmph;
    unsigned char   *raw;
    struct ip_auth_hdr *ah;
} L4_HEAD;

typedef struct packet_info {
    QNSM_IN_ADDR src_addr;
    QNSM_IN_ADDR dst_addr;
    uint16_t     af;            /*enum en_qnsm_ip_af*/
    uint16_t     l3_offset;
    uint16_t     l3_len;
    uint8_t      proto;
    char*        payload;
#define v4_src_ip src_addr.in4_addr.s_addr
#define v4_dst_ip dst_addr.in4_addr.s_addr
#define v6_src_ip src_addr.in6_addr.s6_addr
#define v6_dst_ip dst_addr.in6_addr.s6_addr

    uint16_t sport;
    uint16_t dport;
    uint16_t pkt_len;
    uint8_t  lcore_id;       /*rss lcore*/
    uint8_t  direction : 2;
    uint8_t  sess_dir :  4;
    uint8_t  is_frag  :  2;

    uint8_t pf:1;            /*passive fingerprint*/
    uint8_t need_dump:1;     /*dump flag*/
    uint8_t dpi_policy:1;    /*dpi flag*/
    uint8_t dpi_app_prot:5;  /*dpi proto type*/
    uint8_t rsvd[2];
} __rte_cache_aligned QNSM_PACKET_INFO;

#endif

#ifdef RTE_EXEC_ENV_BAREMETAL
#define MAIN _main
#else
#define MAIN main
#endif

int app_lcore_main_loop(void *arg);

int MAIN(int argc, char **argv);

#ifdef __cplusplus
}
#endif


#endif /* _MAIN_H_ */

