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

#ifndef __QNSM_IP__
#define __QNSM_IP__

#include <rte_table_acl.h>
#include "qnsm_acl_ex.h"
#include "qnsm_dpi_ex.h"
#include "qnsm_session_ex.h"

#ifdef __cplusplus
extern "C" {
#endif

enum en_vip_loc {
    EN_QNSM_VIP_OUTSIDE = 0,
    EN_QNSM_VIP_REMOTE  = 1,
    EN_QNSM_VIP_LOCAL   = 2,
    EN_QNSM_VIP_LOC_MAX,
};

enum en_pkt_act {
    EN_QNSM_PKT_DROP = 0,
    EN_QNSM_PKT_FWD  = 1,
    EN_QNSM_ACT_MAX,
};

struct qnsm_pkt_rslt {
    enum DIRECTION dir;
    enum en_pkt_act act;
    uint32_t id;
};

typedef struct qnsm_sess_vip_data QNSM_SESS_VIP_DATA;

typedef QNSM_SESS_VIP_DATA* (*find_ip)(void *host);
typedef QNSM_SESS_VIP_DATA* (*add_ip)(void *host, uint8_t mask);
typedef int32_t (*del_ip)(void *host, uint8_t mask);
typedef void (*fill_policy_para)(struct rte_table_acl_rule_add_params *acl_rule_para,
                                 QNSM_SESS_VIP_DATA *vip_data);
typedef void (*add_policy)(enum qnsm_acl_action act, fill_policy_para f_fill_policy_para, QNSM_SESS_VIP_DATA *vip_data);
typedef void (*del_policy)(enum qnsm_acl_action act, fill_policy_para f_fill_policy_para, QNSM_SESS_VIP_DATA *vip_data);

typedef struct {
    find_ip f_find_ip;
    add_ip  f_add_ip;
    del_ip f_del_ip;

    /*policies*/
    fill_policy_para f_fill_policy_para[EN_QNSM_ACL_ACT_MAX];
    add_policy f_add_policy;
    del_policy f_del_policy;
    qnsm_acl_act f_acl_act;
} __rte_cache_aligned QNSM_SESS_VIP_OPS;

typedef struct {
    /*
    *dpi policy data
    */
    uint8_t dpi_enable;
    uint8_t rsvd;
    uint16_t dpi_sport;
    uint64_t dpi_tick;
    uint32_t seq_id;

    /*statis*/
    QNSM_SESS_DPI_PROTO_STATIS statis[EN_QNSM_DPI_PROTO_MAX + 1];
} QNSM_SESS_VIP_SPORT_POLICY;

struct qnsm_sess_vip_data {
    QNSM_IN_ADDR    vip_key;
#define vip                 vip_key.in4_addr.s_addr
#define vip6                vip_key.in6_addr.s6_addr

    uint8_t af;

    /*tx port pos*/
    uint8_t tx_pos;

    uint8_t valid : 1;
    uint8_t location : 2;

    /*cus ip agg enable*/
    uint8_t cus_ip_agg_enable : 1;
    uint8_t is_block_ip : 1;
    uint8_t rsvd : 3;

    /*session enable*/
    uint8_t session_enable;

    /*dump policy data*/
    uint8_t dump_enable;
    uint8_t proto;
    uint16_t port;
    uint64_t tick;

    /*dpi policy*/
    QNSM_SESS_VIP_SPORT_POLICY *cur_dpi_policy;
    QNSM_SESS_VIP_SPORT_POLICY dpi_policy[QNSM_SESS_MAX_DPI_POLICY];

    /*vip ops*/
    void *ops;
};

void qnsm_inet_vip_init(void *this);
struct qnsm_pkt_rslt* qnsm_inet_get_pkt_dire(void *this, QNSM_PACKET_INFO *pkt_info, QNSM_SESS_VIP_DATA **item);

/*vip+sport pkts dpi statis*/
void qnsm_inet_update_vip_sport_statis(void *vip_item, QNSM_PACKET_INFO *pkt_info);

#ifdef __cplusplus
}
#endif

#endif
