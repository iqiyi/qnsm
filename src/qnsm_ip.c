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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_icmp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_ip_frag.h>
#include <rte_lpm.h>
#include <rte_table_acl.h>
#include <rte_hash_crc.h>

#include "app.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_service_ex.h"
#include "qnsm_tbl_ex.h"
#include "qnsm_acl_ex.h"
#include "qnsm_msg_ex.h"
#include "qnsm_master_ex.h"
#include "qnsm_ip.h"
#include "qnsm_session.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_HASH_CRC 1
#endif


#if QNSM_PART("ipv4")
static void qnsm_ip_fill_dump_acl_para(struct rte_table_acl_rule_add_params *acl_rule_para,
                                       QNSM_SESS_VIP_DATA *vip_data)
{
    QNSM_ASSERT(acl_rule_para);

    if (vip_data->vip) {
        acl_rule_para[0].field_value[SRC_FIELD_IPV4].value.u32 = vip_data->vip;
        acl_rule_para[0].field_value[SRC_FIELD_IPV4].mask_range.u32 = 32;

        acl_rule_para[1].field_value[DST_FIELD_IPV4].value.u32 = vip_data->vip;
        acl_rule_para[1].field_value[DST_FIELD_IPV4].mask_range.u32 = 32;
    }
    if (vip_data->port) {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].value.u16 = vip_data->port;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].mask_range.u16 = vip_data->port;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].value.u16 = vip_data->port;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].mask_range.u16 = vip_data->port;
    } else {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
    }

    if (vip_data->proto) {
        acl_rule_para[0].field_value[PROTO_FIELD_IPV4].value.u8 = vip_data->proto;
        acl_rule_para[0].field_value[PROTO_FIELD_IPV4].mask_range.u8 = 0xFF;

        acl_rule_para[1].field_value[PROTO_FIELD_IPV4].value.u8 = vip_data->proto;
        acl_rule_para[1].field_value[PROTO_FIELD_IPV4].mask_range.u8 = 0xFF;
    }

    acl_rule_para[0].priority = RTE_ACL_MAX_PRIORITY;
    acl_rule_para[1].priority = RTE_ACL_MAX_PRIORITY;
    return;
}

static void qnsm_ip_fill_dpi_acl_para(struct rte_table_acl_rule_add_params *acl_rule_para,
                                      QNSM_SESS_VIP_DATA *vip_data)
{

    QNSM_ASSERT(acl_rule_para);

    if (vip_data->vip) {
        acl_rule_para[0].field_value[SRC_FIELD_IPV4].value.u32 = vip_data->vip;
        acl_rule_para[0].field_value[SRC_FIELD_IPV4].mask_range.u32 = 32;

        acl_rule_para[1].field_value[DST_FIELD_IPV4].value.u32 = vip_data->vip;
        acl_rule_para[1].field_value[DST_FIELD_IPV4].mask_range.u32 = 32;
    }

    if (vip_data->cur_dpi_policy->dpi_sport) {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].value.u16 =  vip_data->cur_dpi_policy->dpi_sport;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].mask_range.u16 =  vip_data->cur_dpi_policy->dpi_sport;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].value.u16 =  vip_data->cur_dpi_policy->dpi_sport;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].mask_range.u16 = vip_data->cur_dpi_policy->dpi_sport;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
    } else {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].value.u16 = 0;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
    }

    acl_rule_para[0].priority = RTE_ACL_MAX_PRIORITY - 1;
    acl_rule_para[1].priority = RTE_ACL_MAX_PRIORITY - 1;
    return;
}


static void qnsm_ip_add_policy(enum qnsm_acl_action act, fill_policy_para f_fill_policy_para, QNSM_SESS_VIP_DATA *vip_data)
{
    struct rte_table_acl_rule_add_params acl_rule_para[DIRECTION_MAX] = {{0}};
    QNSM_ACL_ENTRY acl_entry[DIRECTION_MAX];
    QNSM_ACL_ENTRY ret_entry[DIRECTION_MAX];
    int32_t key_found[DIRECTION_MAX] = {0};
    int32_t ret = 0;
    struct in_addr          addr;
    char                    ip_str[20];

    f_fill_policy_para(acl_rule_para, vip_data);

    acl_entry[0].act = act;
    acl_entry[1].act = act;

    /*
    *When adding new rules into an ACL context, all fields must be in host byte order (LSB).
    *When the search is performed for an input tuple, all fields in that tuple must be in network byte
    *order (MSB)
    */
    ret = qnsm_acl_tbl_add_bulk(EN_QSNM_ACL_TBL_5TUPLE,
                                acl_rule_para,
                                acl_entry,
                                DIRECTION_MAX,
                                key_found,
                                ret_entry);

    addr.s_addr = rte_cpu_to_be_32(vip_data->vip);
    inet_ntop(AF_INET, (const void *)&addr.s_addr, ip_str, sizeof(ip_str));
    QNSM_LOG(CRIT, "add v4 acl rule (act %u vip %s ret %d)\n",
            act,
            ip_str,
            ret);

    return;
}

static void qnsm_ip_del_policy(enum qnsm_acl_action act, fill_policy_para f_fill_policy_para, QNSM_SESS_VIP_DATA *vip_data)
{
    struct rte_table_acl_rule_add_params acl_rule_para[DIRECTION_MAX] = {{0}};
    struct rte_table_acl_rule_delete_params del_rule_para[DIRECTION_MAX];
    QNSM_ACL_ENTRY acl_entry[DIRECTION_MAX];
    int32_t key_found[DIRECTION_MAX] = {0};
    int32_t ret = 0;
    struct in_addr          addr;
    char                    ip_str[20];

    addr.s_addr = rte_cpu_to_be_32(vip_data->vip);
    f_fill_policy_para(acl_rule_para, vip_data);

    acl_entry[0].act = act;
    acl_entry[1].act = act;

    memcpy(del_rule_para[0].field_value, acl_rule_para[0].field_value, sizeof(struct rte_acl_field) * RTE_ACL_MAX_FIELDS);
    memcpy(del_rule_para[1].field_value, acl_rule_para[1].field_value, sizeof(struct rte_acl_field) * RTE_ACL_MAX_FIELDS);
    ret = qnsm_acl_tbl_delete_bulk(EN_QSNM_ACL_TBL_5TUPLE,
                                   del_rule_para,
                                   DIRECTION_MAX,
                                   key_found,
                                   acl_entry);
    inet_ntop(AF_INET, (const void *)&addr.s_addr, ip_str, sizeof(ip_str));
    QNSM_LOG(CRIT, "del v4 acl rule (act %u vip %s ret %d)\n",
            act,
            ip_str,
            ret);

    return;
}

static inline void qnsm_ip_acl_act(struct rte_mbuf *mbuf, QNSM_ACL_ENTRY *entry)
{
    QNSM_PACKET_INFO *pkt_info = NULL;

    pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);
    switch (entry->act) {
        case EN_QNSM_ACL_ACT_DUMP: {
            pkt_info->need_dump = 1;
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_EVT, "acl match dump sip 0x%x dip 0x%x pkt_info %p pf %d\n",
                       pkt_info->v4_src_ip,
                       pkt_info->v4_dst_ip,
                       pkt_info,
                       pkt_info->pf);
            break;
        }
        case EN_QNSM_ACL_ACT_DPI: {
            pkt_info->dpi_policy = 1;
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_EVT, "acl match dpi sip 0x%x dip 0x%x\n",
                       pkt_info->v4_src_ip,
                       pkt_info->v4_dst_ip);
            break;
        }
        default: {
            pkt_info->need_dump = 0;
            pkt_info->dpi_policy = 0;
            break;
        }
    }

    return;
}

/*
*@param key, host order
*return: find, return item,
*        other null
*/
QNSM_SESS_VIP_DATA* qnsm_ip_find_biz_ip(void *key)
{
    struct rte_lpm *lpm_tbl = NULL;
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    int32_t host_id = 0;
    int32_t ret = 0;
    QNSM_SESS_VIP_DATA *vip_data = NULL;
    struct qnsm_in_addr *addr = key;

    QNSM_ASSERT(NULL != key);
    lpm_tbl = sess_data->biz_vip_tbl;

    ret = rte_lpm_lookup(lpm_tbl, addr->s_addr, &host_id);
    if (0 == ret) {
        vip_data = sess_data->vip_data + host_id;
    }
    return vip_data;
}

static QNSM_SESS_VIP_DATA* qnsm_ip_add_block_ip_seg(void *key, uint8_t mask_len)
{
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    struct rte_lpm *lpm_tbl = sess_data->biz_vip_tbl;
    int32_t ret = -1;
    int32_t host_id = 0;
    QNSM_SESS_VIP_DATA *vip_data = NULL;
    QNSM_SESS_VIP_DATA *tmp_data = NULL;
    struct qnsm_in_addr *addr = key;
    uint32_t pos = 0;

    QNSM_ASSERT(32 >= mask_len);

    if (lpm_tbl) {
        /*get free host*/
        for (host_id = 0; host_id < QNSM_IPV4_LPM_MAX_RULES; host_id++) {
            tmp_data = (QNSM_SESS_VIP_DATA *)sess_data->vip_data + host_id;
            if (0 == tmp_data->valid) {
                vip_data = tmp_data;
                break;
            }
        }
        if (QNSM_IPV4_LPM_MAX_RULES <= host_id) {
            return NULL;
        }

        /*vip data pos as nhp id*/
        ret = rte_lpm_add(lpm_tbl, addr->s_addr, mask_len, host_id);
    }

    if (vip_data) {
        if (0 == ret) {
            vip_data->valid = 1;
            vip_data->vip = addr->s_addr;

            /*set ops*/
            vip_data->ops = &sess_data->inet_ops_list[EN_QNSM_AF_IPv4];
            vip_data->af = EN_QNSM_AF_IPv4;

            /*set nhp*/
#ifdef QNSM_HASH_CRC
            pos = rte_hash_crc_4byte(vip_data->vip, 0);
#else
            pos = rte_jhash_1word(vip_data->vip, 0);
#endif
            vip_data->tx_pos = (uint8_t)pos;
        }
    }
    return vip_data;
}


/**
 * add a vip with biz group.
 *
 * @param host
 *   in para, vip is host order
 * @return
 *   return item, null if failure
 */
QNSM_SESS_VIP_DATA* qnsm_ip_add_biz_ip(void *key, uint8_t mask)
{
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    struct rte_lpm *lpm_tbl = sess_data->biz_vip_tbl;
    int32_t ret = -1;
    int32_t host_id = 0;
    QNSM_SESS_VIP_DATA *vip_data = NULL;
    QNSM_SESS_VIP_DATA *tmp_data = NULL;
    struct qnsm_in_addr *addr = key;
    uint32_t pos = 0;

    if (lpm_tbl) {
        /*get free host*/
        for (host_id = 0; host_id < QNSM_IPV4_LPM_MAX_RULES; host_id++) {
            tmp_data = (QNSM_SESS_VIP_DATA *)sess_data->vip_data + host_id;
            if (0 == tmp_data->valid) {
                vip_data = tmp_data;
                break;
            }
        }
        if (QNSM_IPV4_LPM_MAX_RULES <= host_id) {
            return NULL;
        }

        /*vip data pos as nhp id*/
        ret = rte_lpm_add(lpm_tbl, addr->s_addr, mask, host_id);
    }

    if (vip_data) {
        if (0 == ret) {
            vip_data->valid = 1;
            vip_data->vip = addr->s_addr & qnsm_ipv4_depth_to_mask(mask);

            /*set ops*/
            vip_data->ops = &sess_data->inet_ops_list[EN_QNSM_AF_IPv4];
            vip_data->af = EN_QNSM_AF_IPv4;

            /*set nhp*/
#ifdef QNSM_HASH_CRC
            pos = rte_hash_crc_4byte(vip_data->vip, 0);
#else
            pos = rte_jhash_1word(vip_data->vip, 0);
#endif
            vip_data->tx_pos = (uint8_t)pos;
        }
    }
    return vip_data;
}

/**
 * del a vip.
 *
 * @param key
 *   qnsm_in_addr host order
 * @return
 *   0 on success, negative value otherwise
 */
int32_t qnsm_ip_del_biz_ip(void *key, uint8_t mask)
{
    struct rte_lpm *lpm_tbl = NULL;
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    struct qnsm_in_addr *addr = key;
    int32_t ret = -1;

    lpm_tbl = sess_data->biz_vip_tbl;
    if (lpm_tbl) {
        /*group id as nhp id*/
        ret = rte_lpm_delete(lpm_tbl, addr->s_addr, mask);
    }
    return ret;
}

static int32_t qnsm_ip_vip_ops_reg(void *ops_tbl)
{
    static QNSM_SESS_VIP_OPS ops = {
        .f_find_ip = qnsm_ip_find_biz_ip,
        .f_add_ip  = qnsm_ip_add_biz_ip,
        .f_del_ip  = qnsm_ip_del_biz_ip,
        .f_fill_policy_para[EN_QNSM_ACL_ACT_DUMP] = qnsm_ip_fill_dump_acl_para,
        .f_fill_policy_para[EN_QNSM_ACL_ACT_DPI] = qnsm_ip_fill_dpi_acl_para,
        .f_add_policy = qnsm_ip_add_policy,
        .f_del_policy = qnsm_ip_del_policy,
        .f_acl_act = qnsm_ip_acl_act,
    };

    rte_memcpy(ops_tbl, &ops, sizeof(QNSM_SESS_VIP_OPS));

    /*reg acl act*/
    qnsm_acl_act_reg(EN_QSNM_ACL_TBL_5TUPLE, ops.f_acl_act);
    return 0;
}
#endif

#if QNSM_PART("ipv6")

static void qnsm_ip6_fill_dump_acl_para(struct rte_table_acl_rule_add_params *acl_rule_para,
                                        QNSM_SESS_VIP_DATA *vip_data)
{
    QNSM_ASSERT(acl_rule_para);

    /*IP6 CHECK in add, must not zero*/
    acl_rule_para[0].field_value[SRC1_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[0]);
    acl_rule_para[0].field_value[SRC1_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[0].field_value[SRC2_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[1]);
    acl_rule_para[0].field_value[SRC2_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[0].field_value[SRC3_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[2]);
    acl_rule_para[0].field_value[SRC3_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[0].field_value[SRC4_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[3]);
    acl_rule_para[0].field_value[SRC4_FIELD_IPV6].mask_range.u32 = 32;

    acl_rule_para[1].field_value[DST1_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[0]);
    acl_rule_para[1].field_value[DST1_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[1].field_value[DST2_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[1]);
    acl_rule_para[1].field_value[DST2_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[1].field_value[DST3_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[2]);
    acl_rule_para[1].field_value[DST3_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[1].field_value[DST4_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[3]);
    acl_rule_para[1].field_value[DST4_FIELD_IPV6].mask_range.u32 = 32;

    if (vip_data->port) {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].value.u16 = vip_data->port;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].mask_range.u16 = vip_data->port;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].value.u16 = vip_data->port;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].mask_range.u16 = vip_data->port;
    } else {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
    }

    if (vip_data->proto) {
        acl_rule_para[0].field_value[PROTO_FIELD_IPV6].value.u8 = vip_data->proto;
        acl_rule_para[0].field_value[PROTO_FIELD_IPV6].mask_range.u8 = 0xFF;

        acl_rule_para[1].field_value[PROTO_FIELD_IPV6].value.u8 = vip_data->proto;
        acl_rule_para[1].field_value[PROTO_FIELD_IPV6].mask_range.u8 = 0xFF;
    }

    acl_rule_para[0].priority = RTE_ACL_MAX_PRIORITY;
    acl_rule_para[1].priority = RTE_ACL_MAX_PRIORITY;
    return;
}

static void qnsm_ip6_fill_dpi_acl_para(struct rte_table_acl_rule_add_params *acl_rule_para,
                                       QNSM_SESS_VIP_DATA *vip_data)
{

    QNSM_ASSERT(acl_rule_para);

    /*IP6 CHECK in add, must not zero*/
    acl_rule_para[0].field_value[SRC1_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[0]);
    acl_rule_para[0].field_value[SRC1_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[0].field_value[SRC2_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[1]);
    acl_rule_para[0].field_value[SRC2_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[0].field_value[SRC3_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[2]);
    acl_rule_para[0].field_value[SRC3_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[0].field_value[SRC4_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[3]);
    acl_rule_para[0].field_value[SRC4_FIELD_IPV6].mask_range.u32 = 32;

    acl_rule_para[1].field_value[DST1_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[0]);
    acl_rule_para[1].field_value[DST1_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[1].field_value[DST2_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[1]);
    acl_rule_para[1].field_value[DST2_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[1].field_value[DST3_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[2]);
    acl_rule_para[1].field_value[DST3_FIELD_IPV6].mask_range.u32 = 32;
    acl_rule_para[1].field_value[DST4_FIELD_IPV6].value.u32 = rte_be_to_cpu_32(vip_data->vip_key.in6_addr.s6_addr32[3]);
    acl_rule_para[1].field_value[DST4_FIELD_IPV6].mask_range.u32 = 32;

    if (vip_data->cur_dpi_policy->dpi_sport) {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].value.u16 =  vip_data->cur_dpi_policy->dpi_sport;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].mask_range.u16 =  vip_data->cur_dpi_policy->dpi_sport;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].value.u16 =  vip_data->cur_dpi_policy->dpi_sport;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].mask_range.u16 = vip_data->cur_dpi_policy->dpi_sport;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
    } else {
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[0].field_value[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[0].field_value[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;

        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[1].field_value[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].value.u16 = 0;
        acl_rule_para[1].field_value[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
    }

    acl_rule_para[0].priority = RTE_ACL_MAX_PRIORITY - 1;
    acl_rule_para[1].priority = RTE_ACL_MAX_PRIORITY - 1;
    return;
}

static void qnsm_ip6_add_policy(enum qnsm_acl_action act, fill_policy_para f_fill_policy_para, QNSM_SESS_VIP_DATA *vip_data)
{
    struct rte_table_acl_rule_add_params acl_rule_para[DIRECTION_MAX] = {{0}};
    QNSM_ACL_ENTRY acl_entry[DIRECTION_MAX];
    QNSM_ACL_ENTRY ret_entry[DIRECTION_MAX];
    int32_t key_found[DIRECTION_MAX] = {0};
    int32_t ret = 0;
    char                    ip_str[64];

    f_fill_policy_para(acl_rule_para, vip_data);
    acl_entry[0].act = act;
    acl_entry[1].act = act;

    /*
    *When adding new rules into an ACL context, all fields must be in host byte order (LSB).
    *When the search is performed for an input tuple, all fields in that tuple must be in network byte
    *order (MSB)
    */
    ret = qnsm_acl_tbl_add_bulk(EN_QSNM_ACL_TBL_IPv6_5TUPLE,
                                acl_rule_para,
                                acl_entry,
                                DIRECTION_MAX,
                                key_found,
                                ret_entry);
    inet_ntop(AF_INET6, (const void *)vip_data->vip6, ip_str, sizeof(ip_str));
    QNSM_LOG(CRIT, "add v6 acl rule (act %u vip %s ret %d)\n",
            act,
            ip_str,
            ret);

    return;
}

static void qnsm_ip6_del_policy(enum qnsm_acl_action act, fill_policy_para f_fill_policy_para, QNSM_SESS_VIP_DATA *vip_data)
{
    struct rte_table_acl_rule_add_params acl_rule_para[DIRECTION_MAX] = {{0}};
    struct rte_table_acl_rule_delete_params del_rule_para[DIRECTION_MAX];
    QNSM_ACL_ENTRY acl_entry[DIRECTION_MAX];
    int32_t key_found[DIRECTION_MAX] = {0};
    int32_t ret = 0;
    char                    ip_str[64];

    f_fill_policy_para(acl_rule_para, vip_data);

    acl_entry[0].act = act;
    acl_entry[1].act = act;

    memcpy(del_rule_para[0].field_value, acl_rule_para[0].field_value, sizeof(struct rte_acl_field) * RTE_ACL_MAX_FIELDS);
    memcpy(del_rule_para[1].field_value, acl_rule_para[1].field_value, sizeof(struct rte_acl_field) * RTE_ACL_MAX_FIELDS);
    ret = qnsm_acl_tbl_delete_bulk(EN_QSNM_ACL_TBL_IPv6_5TUPLE,
                                   del_rule_para,
                                   DIRECTION_MAX,
                                   key_found,
                                   acl_entry);
    inet_ntop(AF_INET6, (const void *)vip_data->vip6, ip_str, sizeof(ip_str));
    QNSM_LOG(CRIT, "del v6 acl rule (act %u, vip %s, ret %d)\n",
            act,
            ip_str,
            ret);

    return;
}

static inline void qnsm_ip6_acl_act(struct rte_mbuf *mbuf, QNSM_ACL_ENTRY *entry)
{
    QNSM_PACKET_INFO *pkt_info = NULL;

    pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);
    switch (entry->act) {
        case EN_QNSM_ACL_ACT_DUMP: {
            pkt_info->need_dump = 1;
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_EVT, "acl match dump sip 0x%x dip 0x%x\n",
                       pkt_info->v4_src_ip,
                       pkt_info->v4_dst_ip);
            break;
        }
        case EN_QNSM_ACL_ACT_DPI: {
            pkt_info->dpi_policy = 1;
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_EVT, "acl match dpi sip 0x%x dip 0x%x\n",
                       pkt_info->v4_src_ip,
                       pkt_info->v4_dst_ip);
            break;
        }
        default: {
            pkt_info->need_dump = 0;
            pkt_info->dpi_policy = 0;
            break;
        }
    }

    return;
}

/*
*@param host
*return: find, return item,
*        other null
*/
QNSM_SESS_VIP_DATA* qnsm_ip6_find_biz_ip(void *key)
{
    QNSM_SESS_VIP_DATA *vip_data = NULL;
    vip_data = qnsm_find_tbl_item(EN_QNSM_SESS_IPV6_VIP, (void *)key);

    return vip_data;
}

/**
 * add a vip with biz group.
 *
 * @param key
 *   in para, vip is Big Endian/net order
 * @return
 *   return item, null if failure
 */
QNSM_SESS_VIP_DATA* qnsm_ip6_add_biz_ip6(void *key, uint8_t mask)
{
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    QNSM_SESS_VIP_DATA *vip_data = NULL;
    uint8_t normal_mode = 0;
    uint32_t pos = 0;

    mask = mask;
    vip_data = qnsm_add_tbl_item(EN_QNSM_SESS_IPV6_VIP, key, &normal_mode);
    if (vip_data) {
        vip_data->valid = 1;

        vip_data->af = EN_QNSM_AF_IPv6;

        /*set ops*/
        vip_data->ops = &sess_data->inet_ops_list[EN_QNSM_AF_IPv6];

        /*set ip*/
        rte_memcpy(vip_data->vip6, key, IPV6_ADDR_LEN);
        QNSM_ASSERT(vip_data->vip_key.in6_addr.s6_addr32[0]
                    || vip_data->vip_key.in6_addr.s6_addr32[1]
                    || vip_data->vip_key.in6_addr.s6_addr32[2]
                    || vip_data->vip_key.in6_addr.s6_addr32[3]);

#ifdef QNSM_HASH_CRC
        pos = rte_hash_crc_4byte(vip_data->vip_key.in6_addr.s6_addr32[3], 0);
#else
        pos = rte_jhash_1word(vip_data->vip_key.in6_addr.s6_addr32[3], 0);
#endif
        vip_data->tx_pos = (uint8_t)pos;
    }

    return vip_data;
}

/**
 * del a vip.
 *
 * @param key
 *   vip is Big Endian/net order
 * @return
 *   0 on success, negative value otherwise
 */
static inline int32_t qnsm_ip6_del_biz_ip6(void *key, uint8_t mask)
{
    int32_t ret = 0;
    void *item = qnsm_ip6_find_biz_ip(key);

    mask = mask;
    if (NULL == item) {
        return -1;
    }
    ret = qnsm_del_tbl_item(EN_QNSM_SESS_IPV6_VIP, item);
    return ret;
}

static inline uint32_t
qnsm_ip6_hash_crc(const void *data, __rte_unused uint32_t data_len,
                  uint32_t init_val)
{
    const struct qnsm_in6_addr *k;
    k = data;

#ifdef QNSM_HASH_CRC
    init_val = rte_hash_crc_4byte(k->s6_addr32[0], init_val);
    init_val = rte_hash_crc_4byte(k->s6_addr32[1], init_val);
    init_val = rte_hash_crc_4byte(k->s6_addr32[2], init_val);
    init_val = rte_hash_crc_4byte(k->s6_addr32[3], init_val);
#else
    init_val = rte_jhash(k->s6_addr,
                         sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
#endif
    return init_val;
}

static void qnsm_ip6_vip_tbl_reg(EN_QNSM_APP lcore_type)
{
    uint32_t pool_size = 0;

    pool_size = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_SESSM) * QNSM_SESS_VIP_MAX;
    pool_size = (pool_size << 2) / 5;
    QNSM_TBL_PARA  ipv6_para = {
        "inet_ip6",
        QNSM_SESS_VIP_MAX,
        pool_size,
        sizeof(QNSM_SESS_VIP_DATA),
        offsetof(QNSM_SESS_VIP_DATA, vip_key),
        sizeof(QNSM_IN_ADDR),
        qnsm_ip6_hash_crc,
        NULL,
        EN_QNSM_SESSM,
        30,
    };

    qnsm_tbl_para_reg(lcore_type, EN_QNSM_SESS_IPV6_VIP, (void *)&ipv6_para);
    return;
}

static int32_t qnsm_ip6_vip_ops_reg(void *ops_tbl)
{
    static QNSM_SESS_VIP_OPS ops = {
        .f_find_ip = qnsm_ip6_find_biz_ip,
        .f_add_ip  = qnsm_ip6_add_biz_ip6,
        .f_del_ip  = qnsm_ip6_del_biz_ip6,
        .f_fill_policy_para[EN_QNSM_ACL_ACT_DUMP] = qnsm_ip6_fill_dump_acl_para,
        .f_fill_policy_para[EN_QNSM_ACL_ACT_DPI] = qnsm_ip6_fill_dpi_acl_para,
        .f_add_policy = qnsm_ip6_add_policy,
        .f_del_policy = qnsm_ip6_del_policy,
        .f_acl_act = qnsm_ip6_acl_act,
    };

    rte_memcpy(ops_tbl, &ops, sizeof(QNSM_SESS_VIP_OPS));

    /*reg acl act*/
    qnsm_acl_act_reg(EN_QSNM_ACL_TBL_IPv6_5TUPLE, ops.f_acl_act);
    return 0;
}

#endif

static void qnsm_inet_policy_aging(QNSM_SESS_VIP_DATA *vip_item, uint64_t cur_tick, uint64_t *intvals)
{
    QNSM_SESS_VIP_OPS *ops = NULL;
    uint16_t dpi_policy_id = 0;

    ops = vip_item->ops;
    if (vip_item->dump_enable
        && (get_diff_time(cur_tick, vip_item->tick) >= intvals[0])) {
        /*del acl tuple*/
        ops->f_del_policy(EN_QNSM_ACL_ACT_DUMP, ops->f_fill_policy_para[EN_QNSM_ACL_ACT_DUMP], vip_item);

        /*update dump polciy data*/
        vip_item->dump_enable = 0;
    }

    if (vip_item->cur_dpi_policy) {
        if (vip_item->cur_dpi_policy->dpi_enable
            && (get_diff_time(cur_tick, vip_item->cur_dpi_policy->dpi_tick) >= intvals[1])) {
            /*send dpi statis msg*/
            qnsm_msg_send_lb(EN_QNSM_MASTER,
                             QNSM_MSG_SESS_DPI_STATIS,
                             vip_item,
                             vip_item->vip_key.in6_addr.s6_addr32[0],
                             1);

            /*del acl tuple*/
            ops->f_del_policy(EN_QNSM_ACL_ACT_DPI, ops->f_fill_policy_para[EN_QNSM_ACL_ACT_DPI], vip_item);

            /*clear dump polciy data*/
            memset(vip_item->cur_dpi_policy->statis,
                   0,
                   sizeof(QNSM_SESS_DPI_PROTO_STATIS) * (EN_QNSM_DPI_PROTO_MAX +1));
            vip_item->cur_dpi_policy->dpi_enable = 0;
            vip_item->cur_dpi_policy = NULL;
        }
    }

    if (NULL == vip_item->cur_dpi_policy) {
        /*get dpi policy*/
        for (dpi_policy_id = 0; dpi_policy_id < QNSM_SESS_MAX_DPI_POLICY; dpi_policy_id++) {
            if (vip_item->dpi_policy[dpi_policy_id].dpi_enable) {
                vip_item->cur_dpi_policy = &vip_item->dpi_policy[dpi_policy_id];
                vip_item->cur_dpi_policy->dpi_tick = cur_tick;
                ops->f_add_policy(EN_QNSM_ACL_ACT_DPI, ops->f_fill_policy_para[EN_QNSM_ACL_ACT_DPI], vip_item);
                break;
            }
        }
    }

    return;
}

static void qnsm_inet_policy_timer(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    uint64_t cur_tick = 0;
    QNSM_SESS_VIP_DATA *vip_data = arg;
    QNSM_SESS_VIP_DATA *vip_item = NULL;
    uint64_t hz = rte_get_timer_hz();
    uint64_t intvals[EN_QNSM_ACL_ACT_MAX] = {60 * hz, 10 * hz};
    uint16_t index = 0;
    uint32_t iter = 0;

    cur_tick = rte_rdtsc();

    /*ipv4 policies*/
    for (index = 0; index < QNSM_IPV4_LPM_MAX_RULES; index++) {
        vip_item = &vip_data[index];
        if (0 == vip_item->valid) {
            continue;
        }
        if (EN_QNSM_VIP_LOCAL != vip_item->location) {
            continue;
        }
        qnsm_inet_policy_aging(vip_item, cur_tick, intvals);
    }

    /*ipv6 policies*/
    while(0 <= qnsm_iterate_tbl(EN_QNSM_SESS_IPV6_VIP, (void **)&vip_item, &iter)) {
        if (EN_QNSM_VIP_LOCAL != vip_item->location) {
            continue;
        }
        qnsm_inet_policy_aging(vip_item, cur_tick, intvals);
    }
    return;
}

static inline QNSM_SESS_VIP_OPS* qnsm_inet_get_vip_ops(void *this, uint16_t af)
{
    QNSM_SESS_DATA *data = this;
    return &data->inet_ops_list[af];
}


#if QNSM_PART("msg")

static int32_t qnsm_inet_dpi_policy_statis_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    QNSM_SESS_VIP_DATA *vip_data = send_data;
    QNSM_SESS_DPI_STATIS_MSG *dpi_statis = NULL;

    dpi_statis = msg;
    dpi_statis->af = vip_data->af;
    if (EN_QNSM_AF_IPv4 == vip_data->af) {
        dpi_statis->vip_key.in4_addr.s_addr = vip_data->vip;
    } else {
        QNSM_ASSERT(EN_QNSM_AF_IPv6 == vip_data->af);
        rte_memcpy(dpi_statis->vip_key.in6_addr.s6_addr, vip_data->vip6, IPV6_ADDR_LEN);
    }
    dpi_statis->dpi_sport = vip_data->cur_dpi_policy->dpi_sport;
    dpi_statis->seq_id = vip_data->cur_dpi_policy->seq_id;
    rte_memcpy(dpi_statis->statis, vip_data->cur_dpi_policy->statis, sizeof(QNSM_SESS_DPI_PROTO_STATIS) * (EN_QNSM_DPI_PROTO_MAX + 1));
    *msg_len = sizeof(QNSM_SESS_DPI_STATIS_MSG);
    return 0;
}

static int32_t qnsm_inet_biz_vip_msg_proc(void *data, uint32_t data_len)
{
    int32_t ret = 0;
    uint32_t exist = 0;
    QNSM_BIZ_VIP_MSG *vip_msg = data;
    QNSM_IN_ADDR host;
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    QNSM_SESS_VIP_DATA *vip_data = NULL;
    QNSM_POLICY_MSG_DATA *policy_msg_data = NULL;
    QNSM_SESS_VIP_OPS *ops = NULL;
    char tmp[128];
    uint8_t  is_local_vip = vip_msg->cmd_data[0];

    QNSM_ASSERT(EN_QNSM_AF_MAX > vip_msg->af);

    /*
    *check whether add remote vip
    */
    if ((0 == is_local_vip)
        && (sess_data->remote_vip_num >= (QNSM_IPV4_LPM_MAX_RULES >> 1))) {
        return ret;
    }

    host = vip_msg->key;
    if (EN_QNSM_AF_IPv4 == vip_msg->af) {
        host.in4_addr.s_addr = rte_be_to_cpu_32(vip_msg->key.in4_addr.s_addr);
        inet_ntop(AF_INET, &vip_msg->key, tmp, sizeof(tmp));
    } else {
        inet_ntop(AF_INET6, &vip_msg->key, tmp, sizeof(tmp));
    }
    ops = &sess_data->inet_ops_list[vip_msg->af];
    vip_data = ops->f_find_ip(&host);
    if (NULL != vip_data) {
        exist = 1;
    }

    if (QNSM_BIZ_VIP_ADD == vip_msg->op) {
        if (!exist) {
            vip_data = ops->f_add_ip(&host, vip_msg->mask);
            QNSM_LOG(CRIT, "add %s vip %s/%d %s\n",
                    is_local_vip ? "local" : "remote",
                    tmp,
                    vip_msg->mask,
                    (NULL == vip_data) ? "failed" : "success");
            if (NULL == vip_data) {
                return -1;
            }

            /*set whether local idc vip*/
            vip_data->location = is_local_vip ? EN_QNSM_VIP_LOCAL : EN_QNSM_VIP_REMOTE;

            /*init*/
            vip_data->cus_ip_agg_enable = 0;
        }

        if ((EN_QNSM_CMD_VIP_ENABLE_CUS_IP_AGG == vip_msg->cmd)
            || (EN_QNSM_CMD_VIP_DISABLE_CUS_IP_AGG == vip_msg->cmd)) {
            /*set cus ip agg enable*/
            vip_data->cus_ip_agg_enable = (EN_QNSM_CMD_VIP_ENABLE_CUS_IP_AGG == vip_msg->cmd) ? 1 : 0;
            QNSM_LOG(CRIT, "vip cus ip statis %s (vip:%s, cmd:%u)\n",
                    (vip_data->cus_ip_agg_enable ? "enable" : "disable"),
                    tmp, vip_msg->cmd);
        }

        if ((EN_QNSM_CMD_DUMP_PKT == vip_msg->cmd)
            || (EN_QNSM_CMD_DISABLE_DUMP_PKT == vip_msg->cmd)) {
            /*update vip dump policy data*/
            policy_msg_data = (QNSM_POLICY_MSG_DATA *)(vip_msg->cmd_data + 8);
            vip_data->dump_enable = (EN_QNSM_CMD_DUMP_PKT == vip_msg->cmd) ? 1 : 0;
            vip_data->tick = rte_rdtsc();
            vip_data->port = policy_msg_data->vport;
            vip_data->proto = policy_msg_data->proto;
            //vip_data->vip = rte_be_to_cpu_32(vip_msg->key.ip);
            if (vip_data->dump_enable) {
                ops->f_add_policy(EN_QNSM_ACL_ACT_DUMP, ops->f_fill_policy_para[EN_QNSM_ACL_ACT_DUMP], vip_data);
            } else {
                ops->f_del_policy(EN_QNSM_ACL_ACT_DUMP, ops->f_fill_policy_para[EN_QNSM_ACL_ACT_DUMP], vip_data);
            }
        }

        if (EN_QNSM_CMD_DPI_CHECK== vip_msg->cmd) {
            uint16_t index = 0;

            /*update vip dpi policy data*/
            policy_msg_data = (QNSM_POLICY_MSG_DATA *)(vip_msg->cmd_data + 8);

            for (index = 0; index < QNSM_SESS_MAX_DPI_POLICY; index++) {
                if (0 == vip_data->dpi_policy[index].dpi_enable) {
                    vip_data->dpi_policy[index].dpi_enable = 1;
                    vip_data->dpi_policy[index].dpi_sport = policy_msg_data->sport;
                    vip_data->dpi_policy[index].seq_id = *(uint32_t *)(policy_msg_data + 1);
                    if (NULL == vip_data->cur_dpi_policy) {
                        vip_data->cur_dpi_policy = &vip_data->dpi_policy[index];
                        vip_data->cur_dpi_policy->dpi_tick = rte_rdtsc();
                        memset(vip_data->cur_dpi_policy->statis,
                               0,
                               sizeof(QNSM_SESS_DPI_PROTO_STATIS) * (EN_QNSM_DPI_PROTO_MAX +1));
                        ops->f_add_policy(EN_QNSM_ACL_ACT_DPI, ops->f_fill_policy_para[EN_QNSM_ACL_ACT_DPI], vip_data);
                    }
                    break;
                }
            }
        }

        if ((EN_QNSM_CMD_VIP_ENABLE_SESSION == vip_msg->cmd)
            || (EN_QNSM_CMD_VIP_DISABLE_SESSION == vip_msg->cmd)) {
            /*vip session enable*/
            vip_data->session_enable = (EN_QNSM_CMD_VIP_ENABLE_SESSION == vip_msg->cmd) ? 1 : 0;
            QNSM_LOG(CRIT, "vip session %s cmd (vip:%s, cmd:%u)\n",
                    (vip_data->session_enable ? "enable" : "disable"),
                    tmp, vip_msg->cmd);
        }
    } else {
        QNSM_ASSERT(QNSM_BIZ_VIP_DEL == vip_msg->op);

        if (!exist) {
            return 0;
        } else {
            memset(vip_data, 0,sizeof(QNSM_SESS_VIP_DATA));
            ret = ops->f_del_ip(&host, vip_msg->mask);
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_EVT, "del vip %s/%d\n",
                       tmp, vip_msg->mask);
        }
    }
    return ret;
}
#endif

void qnsm_inet_update_vip_sport_statis(void *vip_item, QNSM_PACKET_INFO *pkt_info)
{
    QNSM_SESS_VIP_DATA *vip_data = vip_item;
    uint8_t dpi_prot = 0;

    if ((0 == pkt_info->dpi_policy)
        || (NULL == vip_data->cur_dpi_policy)) {
        return;
    }
    if ((vip_data->cur_dpi_policy->dpi_sport != pkt_info->sport)
        && (vip_data->cur_dpi_policy->dpi_sport != pkt_info->dport)) {
        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_ERR, "pkt not match policy!!!\n");
        return;
    }

    dpi_prot = pkt_info->dpi_app_prot;
    vip_data->cur_dpi_policy->statis[dpi_prot].pkts++;
    vip_data->cur_dpi_policy->statis[dpi_prot].bits += (pkt_info->pkt_len << 3);

    /*clear dpi flag*/
    pkt_info->dpi_policy = 0;
    return;
}

void qnsm_inet_vip_init(void *this)
{
    QNSM_SESS_DATA *data = this;
    QNSM_VIP_CFG *groups = NULL;
    QNSM_SVR_IP_GROUP *ip_group = NULL;
    uint32_t group_id;
    uint32_t host_id;
    struct rte_lpm_config config_ipv4;
    QNSM_SESS_VIP_DATA *tmp_data = NULL;
    uint8_t name[32];
    QNSM_IN_ADDR conf_addr;
    int32_t ret = 0;

    /*msg reg*/
    (void)qnsm_msg_reg(QNSM_MSG_SESS_DPI_STATIS, NULL, qnsm_inet_dpi_policy_statis_msg);
    (void)qnsm_msg_reg(QNSM_MSG_SYN_BIZ_VIP, qnsm_inet_biz_vip_msg_proc, NULL);

    /*v4 vip init*/
    config_ipv4.max_rules = QNSM_IPV4_LPM_MAX_RULES * 2;
    config_ipv4.number_tbl8s = QNSM_IPV4_LPM_NUMBER_TBL8S * 8;
    config_ipv4.flags = 0;
    snprintf(name, sizeof(name), "biz_vip%d", rte_lcore_id());
    data->biz_vip_tbl = rte_lpm_create(name, rte_socket_id(), &config_ipv4);
    if (NULL == data->biz_vip_tbl) {
        QNSM_ASSERT(0);
    }
    data->vip_data = rte_zmalloc_socket(NULL,
                                        sizeof(QNSM_SESS_VIP_DATA) * QNSM_IPV4_LPM_MAX_RULES,
                                        QNSM_DDOS_MEM_ALIGN,
                                        rte_socket_id());
    if (NULL == data->vip_data) {
        QNSM_ASSERT(0);
    }

    /*v6 vip init*/
    qnsm_ip6_vip_tbl_reg(EN_QNSM_SESSM);

    groups = qnsm_get_groups();
    if (NULL == groups) {
        QNSM_ASSERT(0);
    }
    for (group_id = 0; group_id < groups->group_num; group_id++) {
        ip_group = groups->group[group_id];
        if (0 == ip_group->valid) {
            continue;
        }
        for (host_id = 0; host_id < ip_group->host_num; host_id++) {
            conf_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip_group->hosts[host_id].addr.in4_addr.s_addr);
            if (0 == strcmp(ip_group->name, "disable_ip")) {
                tmp_data = qnsm_ip_add_block_ip_seg(&conf_addr, ip_group->hosts[host_id].mask);
                tmp_data->is_block_ip = 1;
                printf("add block ip seg 0x%x success\n", conf_addr.in4_addr.s_addr);
            }
        }
        for (host_id = 0; host_id < ip_group->host6_num; host_id++) {
            if (0 == strcmp(ip_group->name, "disable_ip")) {
                //TODO
                ;
            }
        }

    }

    /*inet ops list init*/
    qnsm_ip_vip_ops_reg(&data->inet_ops_list[EN_QNSM_AF_IPv4]);
    qnsm_ip6_vip_ops_reg(&data->inet_ops_list[EN_QNSM_AF_IPv6]);

    /*policy timer*/
    rte_timer_init(&data->vip_timer);
    ret = rte_timer_reset(&data->vip_timer,
                          INTVAL * rte_get_timer_hz(), PERIODICAL,
                          rte_lcore_id(), qnsm_inet_policy_timer, data->vip_data);
    QNSM_LOG(CRIT, "sess policy timer init %d\n", ret);

    return;
}

struct qnsm_pkt_rslt* qnsm_inet_get_pkt_dire(void *this, QNSM_PACKET_INFO *pkt_info, QNSM_SESS_VIP_DATA **item)
{
    QNSM_SESS_VIP_DATA *vip_item[DIRECTION_MAX] = {NULL};
    QNSM_SESS_VIP_OPS *ops = NULL;
    uint8_t dst_vip_location;
    uint8_t src_vip_location;
    struct qnsm_pkt_rslt *result = NULL;

    /*src ip ============= dst ip*/
    static struct qnsm_pkt_rslt rslt[EN_QNSM_VIP_LOC_MAX][EN_QNSM_VIP_LOC_MAX] = {
        {
            {DIRECTION_MAX, EN_QNSM_PKT_FWD,  2},
            {DIRECTION_MAX, EN_QNSM_PKT_FWD,  2},
            {DIRECTION_IN,  EN_QNSM_PKT_FWD,  0},
        },
        {
            {DIRECTION_MAX, EN_QNSM_PKT_FWD,  2},
            {DIRECTION_MAX, EN_QNSM_PKT_FWD,  2},
            {DIRECTION_IN,  EN_QNSM_PKT_DROP, 0},
        },
        {
            {DIRECTION_OUT, EN_QNSM_PKT_FWD,  1},
            {DIRECTION_OUT, EN_QNSM_PKT_DROP, 1},
            {DIRECTION_IN,  EN_QNSM_PKT_DROP, 0},
        }
    };

    ops = qnsm_inet_get_vip_ops(this, pkt_info->af);
    //QNSM_ASSERT(ops);

    if ((vip_item[0] = ops->f_find_ip(&pkt_info->dst_addr))) {
        dst_vip_location = vip_item[0]->location;
    } else {
        dst_vip_location = EN_QNSM_VIP_OUTSIDE;
    }

    if ((vip_item[1] = ops->f_find_ip(&pkt_info->src_addr))) {
        src_vip_location = vip_item[1]->location;
    } else {
        src_vip_location = EN_QNSM_VIP_OUTSIDE;
    }

    result = &rslt[src_vip_location][dst_vip_location];
    pkt_info->direction = result->dir;
    if (DIRECTION_MAX > pkt_info->direction) {
        *item = vip_item[result->id];
    }
    return result;
}


