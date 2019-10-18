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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/time.h>
#include <sched.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>


/* RTE HEAD FILE*/
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_hash_crc.h>

/*cmd*/
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_socket.h>


#include "app.h"
#include "util.h"
#include "bsb.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_msg_ex.h"
#include "qnsm_tbl_ex.h"
#include "qnsm_session_ex.h"
#include "qnsm_cfg.h"
#include "qnsm_service_ex.h"
#include "qnsm_master_ex.h"
#include "qnsm_ip_agg.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_HASH_CRC 1
#endif

#define QNSM_DEFAULT_CUSTOM_IP_SIZE  (0x80000)
#define QNSM_CUSTOM_IP_POOL_SIZE     (0x80000)
#define QNSM_CUS_RUN_INTVAL_USEC   (1000 * 50)

typedef struct qnsm_cus_ip_data QNSM_CUS_IP_DATA;
typedef QNSM_CUS_IP_DATA* (*add_cus)(QNSM_IN_ADDR *key);
typedef QNSM_CUS_IP_DATA* (*find_cus)(QNSM_IN_ADDR *key);
typedef int32_t (*del_cus)(void *item);

struct qnsm_cus_ip_ops {
    add_cus f_add_cus;
    find_cus f_find_cus;
    del_cus f_del_cus;
};

typedef struct {
    struct qnsm_list_head  node;
    QNSM_IN_ADDR vip_key;
    uint64_t vip_tick;
    QNSM_CUS_VIP_STATISTICS          statistics_info[EN_CUS_IP_PROT_MAX][DIRECTION_MAX];
} __rte_cache_aligned QNSM_CUS_IP_VIP_STATIS;

typedef struct {
    struct qnsm_list_head head;
} QNSM_CUS_IP_STATIS;

struct qnsm_cus_ip_data {
    QNSM_IN_ADDR                  key;
    uint8_t                       af;                        /*enum en_qnsm_ip_af*/
    uint8_t                       rsvd[7];
    uint64_t                      tick;                      /*latest pkt time*/
    uint64_t                      agg_time;
    QNSM_CUS_IP_STATIS            statis_data;

    /*timer*/
    struct rte_timer              agg_timer;
    struct rte_timer              aging_timer;
};

typedef struct {

    struct rte_mempool *stais_cache;

    uint32_t prev_sleep_time;

    /*cus agg enable/disable*/
    uint32_t vip_enable_cus_agg_num;

    /*ops*/
    struct qnsm_cus_ip_ops ops[EN_QNSM_AF_MAX];
} QNSM_CUS_IP_APP_DATA;

static int32_t qnsm_cus_ip_encap_agg_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    QNSM_CUS_IP_AGG_MSG *cus_agg_msg = NULL;
    QNSM_CUS_IP_DATA *cus_ip_data = send_data;
    QNSM_CUS_IP_VIP_STATIS *vip_statis = NULL;
    BSB cus_bsb;
    uint8_t *ptr = NULL;
    static uint32_t statis_len = sizeof(QNSM_IN_ADDR) +
                                 sizeof(QNSM_CUS_VIP_STATISTICS) * EN_CUS_IP_PROT_MAX * DIRECTION_MAX;

    QNSM_ASSERT(msg);
    cus_agg_msg = msg;
    cus_agg_msg->key = cus_ip_data->key;
    cus_agg_msg->af = cus_ip_data->af;
    cus_agg_msg->time = cus_ip_data->agg_time;

    BSB_INIT(cus_bsb, (cus_agg_msg + 1), (QNSM_MSG_MAX_DATA_LEN - sizeof(QNSM_CUS_IP_AGG_MSG)));
    qnsm_list_for_each_entry(vip_statis, &cus_ip_data->statis_data.head, node) {
        if ((0 < vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][DIRECTION_IN].bps)
            || (0 < vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][DIRECTION_OUT].bps)) {
            ptr = BSB_WORK_PTR(cus_bsb);
            BSB_EXPORT_skip(cus_bsb, statis_len);
            if (BSB_IS_ERROR(cus_bsb)) {
                BSB_EXPORT_rewind(cus_bsb, statis_len);
                break;
            }
            BSB_EXPORT_rewind(cus_bsb, statis_len);
            QNSM_ASSERT(ptr == BSB_WORK_PTR(cus_bsb));

            BSB_EXPORT_ptr(cus_bsb, &vip_statis->vip_key, sizeof(QNSM_IN_ADDR));
            BSB_EXPORT_ptr(cus_bsb,
                           vip_statis->statistics_info,
                           (statis_len - sizeof(QNSM_IN_ADDR)));

            /*clear statis*/
            memset(vip_statis->statistics_info, 0, (statis_len - sizeof(QNSM_IN_ADDR)));
        }
    }

    *msg_len = BSB_LENGTH(cus_bsb) + sizeof(QNSM_CUS_IP_AGG_MSG);
    return 0;
}

static void qnsm_cus_ip_agg(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_CUS_IP_DATA *cus_ip_data = arg;
    QNSM_CUS_IP_VIP_STATIS *vip_statis = NULL;
    uint32_t send_agg_info = 0;

    /*send filter*/
    if (qnsm_list_empty(&cus_ip_data->statis_data.head)) {
        return;
    }
    qnsm_list_for_each_entry(vip_statis, &cus_ip_data->statis_data.head, node) {
        if ((0 < vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][DIRECTION_IN].bps)
            || (0 < vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][DIRECTION_OUT].bps)) {
            send_agg_info = 1;
            break;
        }
    }
    if (0 == send_agg_info) {
        return;
    }

    /*
    *send cus ip statis to edge
    */
    cus_ip_data->agg_time += INTVAL;
    (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                           QNSM_MSG_CUSTOM_IP_AGG,
                           cus_ip_data,
                           cus_ip_data->key.in4_addr.s_addr,
                           1);

    QNSM_ASSERT(cus_ip_data->agg_time);
    return;
}

static void qnsm_cus_ip_aging(struct rte_timer *timer, void *arg)
{
    QNSM_CUS_IP_APP_DATA *custom_data = qnsm_app_data(EN_QNSM_SIP_AGG);
    QNSM_CUS_IP_DATA *cus_ip_data = arg;
    QNSM_CUS_IP_VIP_STATIS *vip_statis = NULL;
    QNSM_CUS_IP_VIP_STATIS *tmp = NULL;
    uint64_t curr_time = rte_get_tsc_cycles();
    uint64_t hz = rte_get_timer_hz();
    struct qnsm_cus_ip_ops *ops = NULL;
    int32_t ret = 0;
    uint8_t af = cus_ip_data->af;
    QNSM_IN_ADDR addr = cus_ip_data->key;

    /*get af*/
    ops = custom_data->ops + af;

    /*aging cus ip access vip statis*/
    qnsm_list_for_each_entry_safe(vip_statis, tmp, &cus_ip_data->statis_data.head, node) {
        if (QNSM_TIME_AFTER(curr_time, (vip_statis->vip_tick + timer->period - hz))) {
            qnsm_list_del_init(&vip_statis->node);
            rte_mempool_put(custom_data->stais_cache, vip_statis);
        }
    }

    /*aging cus ip*/
    if (QNSM_TIME_AFTER(curr_time, (cus_ip_data->tick + timer->period - hz))) {
        if (qnsm_list_empty(&cus_ip_data->statis_data.head)) {
            ret = ops->f_del_cus(cus_ip_data);
            if (EN_QNSM_AF_IPv4 == af) {
                QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_EVT, "lcore %u del custom ip 0x%x ret %d\n",
                           rte_lcore_id(),
                           addr.in4_addr.s_addr,
                           ret);
                if (ret) {
                    QNSM_LOG(ERR, "del sip 0x%x failed\n", addr.in4_addr.s_addr);
                }
            } else {
                //TODO
                ;
            }
        } else {
            QNSM_ASSERT(0);
        }
    }
    return;
}

#if QNSM_PART("ipv4")
static inline QNSM_CUS_IP_DATA* qnsm_cus_ip_find(QNSM_IN_ADDR *key)
{
    QNSM_CUS_IP_DATA *ip_data = qnsm_find_tbl_item(EN_QNSM_IPV4_CUSTOM, key);
    return ip_data;
}

static inline int32_t qnsm_cus_ip_del(void *cus_item)
{
    int32_t ret = 0;
    QNSM_CUS_IP_DATA *item = cus_item;

    (void)rte_timer_stop(&item->agg_timer);
    (void)rte_timer_stop(&item->aging_timer);

    ret = qnsm_del_tbl_item(EN_QNSM_IPV4_CUSTOM, item);
    return ret;
}

static QNSM_CUS_IP_DATA* qnsm_cus_ip_add(QNSM_IN_ADDR *key)
{
    QNSM_CUS_IP_DATA *data = NULL;
    uint8_t normal_mode = 0;
    uint64_t aging_time = QNSM_HASH_EMPLOY_TIME * rte_get_timer_hz();
    int32_t ret = 0;
    uint32_t lcore_id = rte_lcore_id();

    QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_EVT, "lcore %u add cus ip 0x%x\n",
               lcore_id, key->in4_addr.s_addr);
    data = qnsm_add_tbl_item(EN_QNSM_IPV4_CUSTOM, key, &normal_mode);
    if (data) {
        QNSM_INIT_LIST_HEAD(&data->statis_data.head);
        rte_timer_init(&data->agg_timer);
        ret = rte_timer_reset(&data->agg_timer,
                              INTVAL * rte_get_timer_hz(), PERIODICAL,
                              lcore_id, qnsm_cus_ip_agg, data);
        if (ret < 0) {
            QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_ERR, "Cannot set lcore %d timer\n", lcore_id);
            goto FAILURE;
        }
        data->agg_time = jiffies();

        /*sess aging timer init*/
        if (0 == normal_mode) {
            aging_time = aging_time >> 1;
        }
        rte_timer_init(&data->aging_timer);
        ret = rte_timer_reset(&data->aging_timer,
                              aging_time, PERIODICAL,
                              lcore_id, qnsm_cus_ip_aging, data);
        if (ret < 0) {
            QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_ERR,"Cannot set lcore %d timer\n", lcore_id);
            (void)rte_timer_stop(&data->agg_timer);
            goto FAILURE;
        }

        /*set af*/
        data->af = EN_QNSM_AF_IPv4;
        QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_EVT, "add custom ip 0x%x normal_mode %u\n", key->in4_addr.s_addr, normal_mode);
    } else {
        QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_ERR, "add custom ip 0x%x failed\n", key->in4_addr.s_addr);
    }

    return data;

FAILURE:
    (void)qnsm_del_tbl_item(EN_QNSM_IPV4_CUSTOM, data);
    return NULL;
}

static inline uint32_t
qnsm_cus_ipv4_hash(const void *data, __rte_unused uint32_t data_len,
                   uint32_t init_val)
{
    const struct qnsm_in_addr *in4_addr = data;

    init_val = rte_hash_crc_4byte(in4_addr->s_addr, init_val);

    return init_val;
}

static int32_t qnsm_cus_ip_tbl_reg(EN_QNSM_APP lcore_type)
{
    uint8_t deploy_num = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_SIP_AGG);
    uint32_t entry_num = QNSM_CUSTOM_IP_POOL_SIZE / deploy_num;

    QNSM_TBL_PARA  in_ip_para = {
        "IN_IP",
        entry_num,
        QNSM_CUSTOM_IP_POOL_SIZE,
        sizeof(QNSM_CUS_IP_DATA),
        offsetof(QNSM_CUS_IP_DATA, key),
        sizeof(QNSM_IN_ADDR),
        qnsm_cus_ipv4_hash,
        NULL,
        EN_QNSM_SIP_AGG,
        30,
    };

    /*tbl reg*/
    qnsm_tbl_para_reg(lcore_type, EN_QNSM_IPV4_CUSTOM, (void *)&in_ip_para);
    return 0;
}

static void qnsm_cus_ip_init(void *this)
{
    QNSM_CUS_IP_APP_DATA *custom_data = this;
    struct qnsm_cus_ip_ops ops = {
        .f_add_cus = qnsm_cus_ip_add,
        .f_find_cus = qnsm_cus_ip_find,
        .f_del_cus = qnsm_cus_ip_del,
    };

    /*init ops*/
    custom_data->ops[EN_QNSM_AF_IPv4] = ops;

    /*reg tbl*/
    qnsm_cus_ip_tbl_reg(EN_QNSM_SIP_AGG);

    return;
}

#endif

#if QNSM_PART("ipv6")

static inline QNSM_CUS_IP_DATA* qnsm_cus_ip6_find(QNSM_IN_ADDR *key)
{
    QNSM_CUS_IP_DATA *ip_data = qnsm_find_tbl_item(EN_QNSM_IPV6_CUSTOM, key);
    return ip_data;
}

static inline int32_t qnsm_cus_ip6_del(void *cus_item)
{
    int32_t ret = 0;
    QNSM_CUS_IP_DATA *item = cus_item;

    QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_EVT, "del lcore %u ipv6 custom ip \n", rte_lcore_id());
    (void)rte_timer_stop(&item->agg_timer);
    (void)rte_timer_stop(&item->aging_timer);

    ret = qnsm_del_tbl_item(EN_QNSM_IPV6_CUSTOM, item);
    return ret;
}

static QNSM_CUS_IP_DATA* qnsm_cus_ip6_add(QNSM_IN_ADDR *key)
{
    QNSM_CUS_IP_DATA *data = NULL;
    uint8_t normal_mode = 0;
    uint64_t aging_time = QNSM_HASH_EMPLOY_TIME * rte_get_timer_hz();
    int32_t ret = 0;
    uint32_t lcore_id = rte_lcore_id();

    data = qnsm_add_tbl_item(EN_QNSM_IPV6_CUSTOM, key, &normal_mode);
    if (data) {
        QNSM_INIT_LIST_HEAD(&data->statis_data.head);
        rte_timer_init(&data->agg_timer);
        ret = rte_timer_reset(&data->agg_timer,
                              INTVAL * rte_get_timer_hz(), PERIODICAL,
                              lcore_id, qnsm_cus_ip_agg, data);
        if (ret < 0) {
            QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_ERR, "Cannot set lcore %d timer\n", lcore_id);
            goto FAILURE;
        }
        data->agg_time = jiffies();

        /*sess aging timer init*/
        if (0 == normal_mode) {
            aging_time = aging_time >> 1;
        }
        rte_timer_init(&data->aging_timer);
        ret = rte_timer_reset(&data->aging_timer,
                              aging_time, PERIODICAL,
                              lcore_id, qnsm_cus_ip_aging, data);
        if (ret < 0) {
            QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_ERR,"Cannot set lcore %d timer\n", lcore_id);
            (void)rte_timer_stop(&data->agg_timer);
            goto FAILURE;
        }

        /*set af*/
        data->af = EN_QNSM_AF_IPv6;
        QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_EVT, "add custom ip6 normal_mode %u\n", normal_mode);
    } else {
        QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_ERR, "add custom ip6 failed\n");
    }

    return data;

FAILURE:
    (void)qnsm_del_tbl_item(EN_QNSM_IPV6_CUSTOM, data);
    return NULL;
}


static inline uint32_t
qnsm_cus_ipv6_hash(const void *data, __rte_unused uint32_t data_len,
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

static int32_t qnsm_cus_ip6_tbl_reg(EN_QNSM_APP lcore_type)
{
    uint8_t deploy_num = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_SIP_AGG);
    uint32_t entry_num = QNSM_CUSTOM_IP_POOL_SIZE / deploy_num;

    QNSM_TBL_PARA  in_ip_para = {
        "IN_IP6",
        entry_num,
        QNSM_CUSTOM_IP_POOL_SIZE,
        sizeof(QNSM_CUS_IP_DATA),
        offsetof(QNSM_CUS_IP_DATA, key),
        sizeof(QNSM_IN_ADDR),
        qnsm_cus_ipv6_hash,
        NULL,
        EN_QNSM_SIP_AGG,
        30,
    };

    /*tbl reg*/
    qnsm_tbl_para_reg(lcore_type, EN_QNSM_IPV6_CUSTOM, (void *)&in_ip_para);
    return 0;
}

static void qnsm_cus_ip6_init(void *this)
{
    QNSM_CUS_IP_APP_DATA *custom_data = this;
    struct qnsm_cus_ip_ops ops = {
        .f_add_cus = qnsm_cus_ip6_add,
        .f_find_cus = qnsm_cus_ip6_find,
        .f_del_cus = qnsm_cus_ip6_del,
    };

    /*init ops*/
    custom_data->ops[EN_QNSM_AF_IPv6] = ops;

    /*reg tbl*/
    qnsm_cus_ip6_tbl_reg(EN_QNSM_SIP_AGG);

    return;
}

#endif

static void qnsm_cus_ip_vip_statis_init(struct rte_mempool *mp,
                                        __attribute__((unused)) void *opaque_arg,
                                        void *_m,
                                        __attribute__((unused)) unsigned i)
{
    char *m = _m;

    memset(m, 0, mp->elt_size);
    return;
}

#ifdef __DDOS
static int32_t qnsm_cus_5tuple_msg_proc(void *data, uint32_t data_len)
{
    QNSM_CUS_IP_APP_DATA *app_data = qnsm_app_data(EN_QNSM_SIP_AGG);
    QNSM_CUS_IP_DATA *cus_ip_data = NULL;
    QNSM_SESS_AGG_MSG *sess_msg = data;
    QNSM_IN_ADDR ip_key;
    QNSM_IN_ADDR vip;
    uint32_t dir_diff = 0;
    uint32_t cmp_len = 0;
    EN_QNSM_CUS_IP_PROT cus_proto = 0xFF;
    struct qnsm_cus_ip_ops *ops = NULL;

    QNSM_ASSERT(NULL != sess_msg);
    QNSM_ASSERT(EN_QNSM_AF_MAX > sess_msg->af);

    /*get ops*/
    ops = app_data->ops + sess_msg->af;
    cmp_len = (EN_QNSM_AF_IPv4 == sess_msg->af) ? 4 : 16;

    /*fill key*/
    ip_key = sess_msg->cus_ip;
    cus_ip_data = ops->f_find_cus(&ip_key);
    if (NULL == cus_ip_data) {
        cus_ip_data = ops->f_add_cus(&ip_key);
        if (NULL == cus_ip_data) {
            return 0;
        }
    }

    //if (sess_msg->cus_ip == sess_msg->sess_addr.addr.v4_5tuple.ip_src)
    if (0 == sess_msg->vip_is_src) {
        if (EN_QNSM_AF_IPv4 == sess_msg->af) {
            vip.in4_addr.s_addr = sess_msg->sess_addr.v4_5tuple.ip_dst;
        } else {
            rte_memcpy(vip.in6_addr.s6_addr, sess_msg->sess_addr.v6_5tuple.ip_dst, IPV6_ADDR_LEN);
        }
        dir_diff = 0;
    } else {
        if (EN_QNSM_AF_IPv4 == sess_msg->af) {
            vip.in4_addr.s_addr = sess_msg->sess_addr.v4_5tuple.ip_src;
        } else {
            rte_memcpy(vip.in6_addr.s6_addr, sess_msg->sess_addr.v6_5tuple.ip_src, IPV6_ADDR_LEN);
        }
        dir_diff = 1;
    }

    cus_proto = (TCP_PROTOCOL == sess_msg->protocol)
                ? (EN_CUS_IP_PROT_TCP) : (EN_CUS_IP_PROT_UDP);

    if (cus_ip_data) {
        /*lookup vip statis is exist*/
        QNSM_CUS_IP_VIP_STATIS *vip_statis = NULL;
        uint32_t find_vip = 0;
        cus_ip_data->tick = rte_get_tsc_cycles();

        /*not empty & search*/
        if (0 == qnsm_list_empty(&cus_ip_data->statis_data.head)) {
            qnsm_list_for_each_entry(vip_statis, &cus_ip_data->statis_data.head, node) {
                if (0 == memcmp(&vip_statis->vip_key, &vip, cmp_len)) {
                    find_vip = 1;
                    break;
                }
            }
        }

        if (0 == find_vip) {
            /*
            *get vip statis
            */
            if (0 == rte_mempool_get(app_data->stais_cache, (void **)&vip_statis)) {
                /*must init node!!!*/
                QNSM_INIT_LIST_HEAD(&vip_statis->node);
                qnsm_list_add(&vip_statis->node, &cus_ip_data->statis_data.head);
                vip_statis->vip_key = vip;
            } else {
                vip_statis = NULL;
                QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_WARN, "lcore %u get vip stattis failed\n",
                           rte_lcore_id());
            }
        }

        /*update*/
        if (vip_statis) {
            /*update statis*/
            vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][dir_diff].pps += sess_msg->in_pps;
            vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][dir_diff].bps += sess_msg->in_bps;
            vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][!dir_diff].pps += sess_msg->out_pps;
            vip_statis->statistics_info[EN_CUS_IP_PROT_TOTAL][!dir_diff].bps += sess_msg->out_bps;

            vip_statis->statistics_info[cus_proto][dir_diff].pps += sess_msg->in_pps;
            vip_statis->statistics_info[cus_proto][dir_diff].bps += sess_msg->in_bps;
            vip_statis->statistics_info[cus_proto][!dir_diff].pps += sess_msg->out_pps;
            vip_statis->statistics_info[cus_proto][!dir_diff].bps += sess_msg->out_bps;
            vip_statis->vip_tick = cus_ip_data->tick;
        }
    }

    QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_INFO,
               "custom ip update statis leave\n");
    return 0;
}
#endif

static int32_t qnsm_cus_cmd_msg_proc(void *data, uint32_t data_len)
{
    QNSM_CUS_IP_APP_DATA *app_data = qnsm_app_data(EN_QNSM_SIP_AGG);
    QNSM_BIZ_VIP_MSG *vip_msg = data;

    if (QNSM_BIZ_VIP_ADD == vip_msg->op) {
        if (EN_QNSM_CMD_VIP_ENABLE_CUS_IP_AGG == vip_msg->cmd) {
            app_data->vip_enable_cus_agg_num++;
            QNSM_LOG(CRIT, "cus ip (vip_enable_cus_agg_num:%u)\n", app_data->vip_enable_cus_agg_num);
        }

        if (EN_QNSM_CMD_VIP_DISABLE_CUS_IP_AGG == vip_msg->cmd) {
            if (0 < app_data->vip_enable_cus_agg_num) {
                app_data->vip_enable_cus_agg_num--;
            }
            QNSM_LOG(CRIT, "cus ip (vip_enable_cus_agg_num:%u)\n", app_data->vip_enable_cus_agg_num);
        }
    }

    return 0;
}

static void qnsm_cus_run(void *para)
{
    QNSM_CUS_IP_APP_DATA *custom_data = para;
    uint32_t cus_ip_num = 0;
    uint32_t sleep_time = QNSM_CUS_RUN_INTVAL_USEC;

    if (0 < custom_data->vip_enable_cus_agg_num) {
        cus_ip_num = qnsm_get_tbl_item_no(EN_QNSM_IPV4_CUSTOM) + qnsm_get_tbl_item_no(EN_QNSM_IPV6_CUSTOM);
        if (0 >= cus_ip_num) {
            custom_data->vip_enable_cus_agg_num = 0;
            QNSM_LOG(CRIT, "cus ip run, set vip_enable_cus_agg_num zero\n");
        } else if (10 >= cus_ip_num) {
            sleep_time = sleep_time >> 1;
        } else {
            sleep_time = 0;
            goto EXIT;
        }
    }
    usleep(sleep_time);

EXIT:
    if (sleep_time != custom_data->prev_sleep_time) {
        QNSM_LOG(CRIT, "cus ip run, %" PRIu64 "sleep time prev %u now %u\n",
                jiffies(), custom_data->prev_sleep_time, sleep_time);
        custom_data->prev_sleep_time = sleep_time;
    }
    return;
}

int32_t qnsm_service_cus_ip_agg_init(void)
{
    QNSM_CUS_IP_APP_DATA *custom_data = NULL;
    char name[64];
    uint32_t lcore_id = rte_lcore_id();
    uint32_t socket_id = rte_socket_id();
    EN_QNSM_APP *app_type = app_get_lcore_app_type(qnsm_service_get_cfg_para());
    uint32_t index = 0;

    /*msg reg*/
    for (index= 0; index < APP_MAX_LCORES; index ++) {
        if (app_type[index] == EN_QNSM_EDGE) {
            (void)qnsm_msg_subscribe(index);
        }
    }
    (void)qnsm_msg_publish();
    (void)qnsm_msg_reg(QNSM_MSG_CUSTOM_IP_AGG, NULL, qnsm_cus_ip_encap_agg_msg);
#ifdef __DDOS
    (void)qnsm_msg_reg(QNSM_MSG_SESS_AGG, qnsm_cus_5tuple_msg_proc, NULL);
#endif
    (void)qnsm_msg_reg(QNSM_MSG_SYN_BIZ_VIP, qnsm_cus_cmd_msg_proc, NULL);
    qnsm_msg_flush_timer_init();

    /*app init*/
    custom_data = qnsm_app_inst_init(sizeof(QNSM_CUS_IP_APP_DATA),
                                     NULL,
                                     NULL,
                                     qnsm_cus_run);

    /*v4 init*/
    qnsm_cus_ip_init(custom_data);

    /*v6 init*/
    qnsm_cus_ip6_init(custom_data);

    /*statis pool init*/
    snprintf(name, sizeof(name), "cus_ip_%d", lcore_id);
    custom_data->stais_cache = rte_mempool_create(name,
                               QNSM_DEFAULT_CUSTOM_IP_SIZE * 2,
                               sizeof(QNSM_CUS_IP_VIP_STATIS),
                               APP_DEFAULT_MEMPOOL_CACHE_SIZE,
                               0,
                               NULL, NULL,
                               qnsm_cus_ip_vip_statis_init, NULL,
                               socket_id,
                               (MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET));

    if (NULL == custom_data->stais_cache) {
        printf("[ERR]qnsm custom ip agg init failed\n");
        return -1;
    }

    /*reg cus run*/
    custom_data->vip_enable_cus_agg_num = 0;
    custom_data->prev_sleep_time = QNSM_CUS_RUN_INTVAL_USEC;
    return 0;
}

#if QNSM_PART("cmd")

/*cmd show flow*/
struct cmd_show_cus_ip_result {
    cmdline_fixed_string_t show_cus;
};

static void cmd_show_cus_ip_parsed(void *parsed_result,
                                   __attribute__((unused)) struct cmdline *cl,
                                   __attribute__((unused)) void *data)
{
    /*in ip*/
    uint32_t p_id;
    QNSM_CUS_IP_DATA *in_ip_data;
    QNSM_CUS_IP_VIP_STATIS *vip_statis = NULL;
    uint32_t iter = 0;
    uint16_t lcore_id = 0;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;
    uint32_t total_ip_num = 0;
    uint32_t total_statis_num = 0;
    uint64_t total_statis[DIRECTION_MAX][2] = {{0},};
    uint64_t tmp_statis[DIRECTION_MAX][2] = {{0},};

    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (EN_QNSM_SIP_AGG == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                 pipeline_para->socket_id,
                                                 pipeline_para->core_id,
                                                 pipeline_para->hyper_th_id);
            iter = 0;
            while(qnsm_cmd_iter_tbl(pipeline_para, EN_QNSM_IPV4_CUSTOM, (void **)&in_ip_data, &iter) >= 0) {
                total_ip_num++;

                qnsm_list_for_each_entry(vip_statis, &in_ip_data->statis_data.head, node) {
                    total_statis[DIRECTION_IN][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_IN].pps;
                    total_statis[DIRECTION_IN][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_IN].pps;
                    total_statis[DIRECTION_IN][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_IN].bps;
                    total_statis[DIRECTION_IN][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_IN].bps;

                    total_statis[DIRECTION_OUT][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_OUT].pps;
                    total_statis[DIRECTION_OUT][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_OUT].pps;
                    total_statis[DIRECTION_OUT][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_OUT].bps;
                    total_statis[DIRECTION_OUT][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_OUT].bps;
                    total_statis_num++;
                }
            }

            cmdline_printf(cl, "lcore %u sip agg statis ip num %u \n",
                           lcore_id,
                           qnsm_cmd_get_tbl_item_no(pipeline_para, EN_QNSM_IPV4_CUSTOM));
            cmdline_printf(cl, "in  pps %" PRIu64 " bps %" PRIu64 "\n",
                           total_statis[DIRECTION_IN][0] - tmp_statis[DIRECTION_IN][0],
                           total_statis[DIRECTION_IN][1] - tmp_statis[DIRECTION_IN][1]);
            cmdline_printf(cl, "out pps %" PRIu64 " bps %" PRIu64 "\n",
                           total_statis[DIRECTION_OUT][0] - tmp_statis[DIRECTION_OUT][0],
                           total_statis[DIRECTION_OUT][1] - tmp_statis[DIRECTION_OUT][1]);
            tmp_statis[DIRECTION_IN][0] = total_statis[DIRECTION_IN][0];
            tmp_statis[DIRECTION_IN][1] = total_statis[DIRECTION_IN][1];
            tmp_statis[DIRECTION_OUT][0] = total_statis[DIRECTION_OUT][0];
            tmp_statis[DIRECTION_OUT][1] = total_statis[DIRECTION_OUT][1];

            /*iter v6*/
            iter = 0;
            while(qnsm_cmd_iter_tbl(pipeline_para, EN_QNSM_IPV6_CUSTOM, (void **)&in_ip_data, &iter) >= 0) {
                total_ip_num++;

                qnsm_list_for_each_entry(vip_statis, &in_ip_data->statis_data.head, node) {
                    total_statis[DIRECTION_IN][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_IN].pps;
                    total_statis[DIRECTION_IN][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_IN].pps;
                    total_statis[DIRECTION_IN][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_IN].bps;
                    total_statis[DIRECTION_IN][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_IN].bps;

                    total_statis[DIRECTION_OUT][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_OUT].pps;
                    total_statis[DIRECTION_OUT][0] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_OUT].pps;
                    total_statis[DIRECTION_OUT][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_TCP][DIRECTION_OUT].bps;
                    total_statis[DIRECTION_OUT][1] += vip_statis->statistics_info[EN_CUS_IP_PROT_UDP][DIRECTION_OUT].bps;
                    total_statis_num++;
                }
            }

            cmdline_printf(cl, "\nlcore %u sip agg statis ip6 num %u \n",
                           lcore_id,
                           qnsm_cmd_get_tbl_item_no(pipeline_para, EN_QNSM_IPV4_CUSTOM));
            cmdline_printf(cl, "in  pps %" PRIu64 " bps %" PRIu64 "\n",
                           total_statis[DIRECTION_IN][0] - tmp_statis[DIRECTION_IN][0],
                           total_statis[DIRECTION_IN][1] - tmp_statis[DIRECTION_IN][1]);
            cmdline_printf(cl, "out pps %" PRIu64 " bps %" PRIu64 "\n",
                           total_statis[DIRECTION_OUT][0] - tmp_statis[DIRECTION_OUT][0],
                           total_statis[DIRECTION_OUT][1] - tmp_statis[DIRECTION_OUT][1]);
            tmp_statis[DIRECTION_IN][0] = total_statis[DIRECTION_IN][0];
            tmp_statis[DIRECTION_IN][1] = total_statis[DIRECTION_IN][1];
            tmp_statis[DIRECTION_OUT][0] = total_statis[DIRECTION_OUT][0];
            tmp_statis[DIRECTION_OUT][1] = total_statis[DIRECTION_OUT][1];
        }
    }

    cmdline_printf(cl, "\ntotal in  pps %" PRIu64 " bps %" PRIu64 "\n", total_statis[DIRECTION_IN][0], total_statis[DIRECTION_IN][1]);
    cmdline_printf(cl, "total out pps %" PRIu64 " bps %" PRIu64 "\n", total_statis[DIRECTION_OUT][0], total_statis[DIRECTION_OUT][1]);
    cmdline_printf(cl, "total in ip num %u total_statis_num %u\n", total_ip_num, total_statis_num);
    return;
}

cmdline_parse_token_string_t show_cus_ip_string =
    TOKEN_STRING_INITIALIZER(struct cmd_show_cus_ip_result, show_cus,
                             "show_cus_ip");

cmdline_parse_inst_t cmd_show_cus_ip = {
    .f = cmd_show_cus_ip_parsed,
    .data = NULL,
    .help_str = "show_cus_ip",
    .tokens = {
        (void *)&show_cus_ip_string,
        NULL,
    },
};
#endif
