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

#ifndef __QNSM_IP_AGG_H__
#define __QNSM_IP_AGG_H__

#include <rte_timer.h>

#include "util.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"


#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_IPV4_MAX_MASK_LEN    (32)

/*vip port statis type*/
enum qnsm_port_type {
    EN_QNSM_SRC_PORT = 0,
    EN_QNSM_DST_PORT = 1,
    EN_QNSM_PORT_TYPE_MAX,
};

/*cus ip l4 protocol index*/
typedef enum {
    EN_CUS_IP_PROT_TCP = 0,
    EN_CUS_IP_PROT_UDP,
    EN_CUS_IP_PROT_TOTAL,
    EN_CUS_IP_PROT_MAX
} EN_QNSM_CUS_IP_PROT;

typedef struct {
    QNSM_IN_ADDR key;       /*ip addr, v4/v6*/
    uint8_t  af;            /*addr family*/
    uint8_t  rsvd[7];
    uint64_t time;          /*agg msg tmestamp*/
    uint8_t msg_body[0];
} QNSM_CUS_IP_AGG_MSG;

typedef struct {
    uint64_t pps;
    uint64_t bps;
} QNSM_CUS_VIP_STATISTICS;

typedef struct {
    uint16_t port_id;
    uint16_t rsvd;
    uint32_t intval_pkts;
    uint64_t intval_bits;
    uint64_t tick;
    struct qnsm_list_head node;
} QNSM_PORT_STATIS;


int32_t qnsm_service_cus_ip_agg_init(void);
int32_t qnsm_service_svr_host_init(void);

#ifdef __cplusplus
}
#endif

#endif

