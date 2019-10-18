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
#include <rte_spinlock.h>
#include <rte_mbuf.h>
#include <rte_ip_frag.h>


/* RTE HEAD FILE*/
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_timer.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_ethdev.h>
#include <rte_hash_crc.h>


/*cmd*/
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_socket.h>


#include "cJSON.h"
#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_min_heap.h"
#include "qnsm_inspect_main.h"
#include "qnsm_msg_ex.h"
#include "qnsm_port_ex.h"
#include "qnsm_tbl_ex.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_service_ex.h"
#include "qnsm_master_ex.h"
#include "qnsm_ip_agg.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_HASH_CRC 1
#endif

#define QNSM_VIP_AGING_TIME     (3 * INTVAL * rte_get_timer_hz())
#define QNSM_PORT_MAX_NUM (65536)
#define QNSM_PORT_TOPN    (20)
#define QNSM_SPORT_ENTRIES (1024)
#define QNSM_DPORT_ENTRIES (128)

#define QNSM_CLEAR_PORT_STATIS(ptr) do { \
    (ptr)->intval_bits = 0; (ptr)->intval_pkts = 0; \
} while (0)


typedef struct qnsm_svr_ip_data QNSM_SVR_IP_DATA;
typedef QNSM_SVR_IP_DATA* (*add_host)(QNSM_SRV_HOST *host, uint8_t is_static);
typedef QNSM_SVR_IP_DATA* (*find_host)(QNSM_SRV_HOST *host);
typedef int32_t (*del_host)(void *item);
#ifdef  DEBUG_QNSM
typedef QNSM_SVR_IP_DATA* (*dbg_find_host)(QNSM_SRV_HOST *host, void *arg);
#endif

struct qnsm_svr_port_key {
    QNSM_IN_ADDR addr;
    uint16_t port;
    uint8_t  af;
    uint8_t  rsvd;
};

struct qnsm_svr_ip_ops {
    add_host f_add_host;
    find_host f_find_host;
    del_host f_del_host;
#ifdef  DEBUG_QNSM
    dbg_find_host f_dbg_find_host;
#endif
};

struct qnsm_svr_ip_data {
    QNSM_IN_ADDR                  addr;
    uint8_t                       mask_len;
    uint8_t                       af;                        /*enum en_qnsm_ip_af*/
    uint8_t                       valid:1;
    uint8_t                       enable_sport_statis:1;
    uint8_t                       enable_dport_statis:1;
    uint8_t                       is_static_vip:1;
    uint8_t                       is_local_vip:1;            /*dyn vip default assume as not local*/
    uint8_t                       agg_affinity:1;
    uint8_t                       rcvd_vip_syn_msg:1;        /*init phase, whether rcv dyn vip syn msg*/
    uint8_t                       rsvd_bits:1;
    uint8_t                       retrans_num:4;
    uint8_t                       delay_del:4;

    uint64_t                      tick;                               /*latest pkt time*/
    QNSM_FLOW_STATISTICS          statistics_info[e_type_max][DIRECTION_MAX];

    /*vip+port tbl*/
    uint16_t                      port_statis_num[EN_QNSM_PORT_TYPE_MAX];
    struct qnsm_list_head         list_head[EN_QNSM_PORT_TYPE_MAX];

    /*topn port*/
    QNSM_HEAP topn_port_statis[EN_QNSM_PORT_TYPE_MAX];

    /*timer*/
    struct rte_timer agg_timer;
    struct rte_timer aging_timer;
} __rte_cache_aligned;

typedef struct {
    QNSM_SVR_IP_DATA *data;
    uint64_t time_new;
} QNSM_SVR_IP_AGG_DATA;

typedef struct {
    struct rte_lpm *lpm_tbl;

    uint32_t max_hosts;
    uint32_t not_local_vip_counter;
    void *data;

    uint32_t syn_clock_num;
    uint32_t rsvd1;
    uint64_t clock;

    /*port statis pool*/
    struct rte_mempool *port_statis_pool;

    /*port statis tbl*/
    struct rte_hash *port_statis_tbl[EN_QNSM_PORT_TYPE_MAX];
    uint16_t port_statis_entries[EN_QNSM_PORT_TYPE_MAX];

    /*known ports*/
    uint8_t known_ports[QNSM_PORT_MAX_NUM];

    /*aging intval time*/
    uint64_t aging_time;

    /*af ops*/
    struct qnsm_svr_ip_ops ops[EN_QNSM_AF_MAX];

    /*tcp pkt type according by tcp flag*/
    uint8_t en_tcp_det_type[256];
} QNSM_SVR_TBL;

#if QNSM_PART("port statis")
static void qnsm_svr_port_statis_item_init(struct rte_mempool *mp,
        __attribute__((unused)) void *opaque_arg,
        void *_m,
        __attribute__((unused)) unsigned i)
{

    QNSM_PORT_STATIS *m = _m;

    memset(m, 0, mp->elt_size);
    QNSM_INIT_LIST_HEAD(&m->node);
    return;
}

static int32_t qnsm_port_statis_compare(void *elem1, void *elem2)
{
    QNSM_PORT_STATIS *port_statis1 = (QNSM_PORT_STATIS *)elem1;
    QNSM_PORT_STATIS *port_statis2 = (QNSM_PORT_STATIS *)elem2;

    if (port_statis1->intval_bits < port_statis2->intval_bits) {
        return -1;
    }

    if (port_statis1->intval_bits > port_statis2->intval_bits) {
        return 1;
    }

    return 0;
}

static inline uint32_t
qnsm_host_port_hash(const void *data, __rte_unused uint32_t data_len,
                    uint32_t init_val)
{
    const struct qnsm_svr_port_key *key = data;
    uint32_t addr_32 = (EN_QNSM_AF_IPv4 == key->af) ? key->addr.in4_addr.s_addr : key->addr.in6_addr.s6_addr32[3];
    const uint16_t *p = (const uint16_t *)&key->port;

#ifdef QNSM_HASH_CRC
    init_val = rte_hash_crc_4byte(addr_32, init_val);
    init_val = rte_hash_crc_2byte(*p, init_val);
#else
    init_val = rte_jhash_1word(addr_32, init_val);
    init_val = rte_jhash(p, sizeof(uint16_t), init_val);
#endif

    return init_val;
}

static inline int32_t qnsm_port_statis_tbl_init(enum qnsm_port_type type, uint32_t entries)
{
    struct rte_hash_parameters hash_para = {0};
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    char tbl_name[64];
    int32_t ret = 0;

    snprintf(tbl_name, sizeof(tbl_name), "%s_%u", ((EN_QNSM_SRC_PORT == type) ? "vip_sport" : "vip_dport"), rte_lcore_id());
    hash_para.name = tbl_name;
    hash_para.entries = entries;
    hash_para.key_len = sizeof(struct qnsm_svr_port_key);
    hash_para.hash_func = qnsm_host_port_hash;
    hash_para.hash_func_init_val = 0;
    hash_para.socket_id = rte_socket_id();

    svr_tbl->port_statis_tbl[type] = rte_hash_create(&hash_para);
    if (NULL == svr_tbl->port_statis_tbl[type]) {
        QNSM_ASSERT(0);
    }
    QNSM_LOG(CRIT, "[ INFO ] tbl %s create success.\n", tbl_name);

    return ret;
}

static inline void* qnsm_host_port_statis_find(QNSM_SVR_IP_DATA *data, enum qnsm_port_type type, uint16_t port)
{
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    struct qnsm_svr_port_key key;
    void *item = NULL;

    key.addr = data->addr;
    key.af = data->af;
    key.port = port;
    key.rsvd = 0;
    if (0 > rte_hash_lookup_data(svr_tbl->port_statis_tbl[type], &key, &item)) {
        return NULL;
    }
    return item;
}

static inline void* qnsm_host_port_statis_add(QNSM_SVR_IP_DATA *data, enum qnsm_port_type type, uint16_t port)
{
    QNSM_PORT_STATIS *item = NULL;
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    struct qnsm_svr_port_key key;
    int32_t ret = 0;

    if ((data->port_statis_num[type] >= svr_tbl->port_statis_entries[type])
        || (rte_mempool_get(svr_tbl->port_statis_pool, (void **)&item))) {
        return NULL;
    }

    key.af = data->af;
    key.addr = data->addr;
    key.port = port;
    key.rsvd = 0;
    ret = rte_hash_add_key_data(svr_tbl->port_statis_tbl[type], &key, (void *)item);
    if (ret) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_WARN,
                   "add %s port %u statis failed ret %d, cur port_statis_num %u\n",
                   ((EN_QNSM_SRC_PORT == type) ? "src" : "dst"),
                   port,
                   ret,
                   data->port_statis_num[type]);
        rte_mempool_put(svr_tbl->port_statis_pool, (void *)item);
        return NULL;
    }

    /*init port statis port*/
    item->port_id = port;
    QNSM_CLEAR_PORT_STATIS(item);

    /*add vip list tbl*/
    qnsm_list_add_tail(&item->node, &data->list_head[type]);
    data->port_statis_num[type]++;
    return item;
}

static inline int32_t qnsm_host_port_statis_del(QNSM_SVR_IP_DATA *data,
        enum qnsm_port_type type,
        QNSM_PORT_STATIS *port_statis)
{
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    struct qnsm_svr_port_key key;
    int32_t pos = 0;

    key.af = data->af;
    key.addr = data->addr;
    key.port = port_statis->port_id;
    key.rsvd = 0;
    pos = rte_hash_del_key(svr_tbl->port_statis_tbl[type], (void *)&key);
    if (0 > pos) {
        return -1;
    }

    rte_mempool_put(svr_tbl->port_statis_pool, port_statis);
    return 0;
}

static void qnsm_host_port_topn(QNSM_SVR_IP_DATA *data,
                                enum qnsm_port_type type)
{
    QNSM_PORT_STATIS *port_statis = NULL;
    QNSM_PORT_STATIS *topn_port = NULL;
    uint32_t elem_num = 0;

    topn_port = data->topn_port_statis[type].elem;
    if (NULL != topn_port) {
        qnsm_list_for_each_entry(port_statis, &data->list_head[type], node) {
            elem_num++;
            if (elem_num <= QNSM_PORT_TOPN) {
                data->topn_port_statis[type].cur_elem_num = elem_num;
                topn_port[elem_num - 1] = *port_statis;
                if (QNSM_PORT_TOPN == elem_num) {
                    qnsm_min_heap_construct(&data->topn_port_statis[type]);
                }
            } else {
                if (port_statis->intval_bits > topn_port[0].intval_bits) {
                    topn_port[0] = *port_statis;
                    qnsm_min_heap_adjust_down(&data->topn_port_statis[type], 0);
                }
            }
            QNSM_CLEAR_PORT_STATIS(port_statis);
        }

        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT,
                   "vip 0x%x port heap elem 0x%p\n",
                   data->addr.in4_addr.s_addr, data->topn_port_statis[type].elem);
    }
    return;
}
#endif

static int32_t qnsm_vip_encap_src_port_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    uint16_t len = 0;
    QNSM_SVR_IP_AGG_DATA *ip_agg_data = NULL;
    QNSM_SVR_IP_DATA *ip_data = NULL;
    QNSM_HEAP *vip_port_heap = NULL;
    uint8_t *buf = msg;
    QNSM_SRV_HOST *host = NULL;

    if ((NULL == send_data) || (NULL == msg)) {
        return 0;
    }

    buf = msg;
    ip_agg_data = send_data;
    ip_data = ip_agg_data->data;
    vip_port_heap = &ip_data->topn_port_statis[EN_QNSM_SRC_PORT];

    *(uint32_t *)(buf + len) = ip_data->af;
    len += sizeof(uint32_t);

    host = (QNSM_SRV_HOST *)(buf + len);
    host->addr = ip_data->addr;
    host->mask = ip_data->mask_len;
    len += sizeof(QNSM_SRV_HOST);

    *(uint64_t *)(buf + len) = ip_agg_data->time_new;
    len += sizeof(uint64_t);

    *(uint64_t *)(buf + len) = EN_QNSM_SRC_PORT;
    len += sizeof(uint64_t);
    *(uint64_t *)(buf + len) = vip_port_heap->cur_elem_num;
    len += sizeof(uint64_t);
    rte_memcpy(buf + len, vip_port_heap->elem, sizeof(QNSM_PORT_STATIS) * vip_port_heap->cur_elem_num);
    len += sizeof(QNSM_PORT_STATIS) * vip_port_heap->cur_elem_num;

    *msg_len = len;
    return 0;
}

static int32_t qnsm_vip_encap_dst_port_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    uint16_t len = 0;
    QNSM_SVR_IP_AGG_DATA *ip_agg_data = NULL;
    QNSM_SVR_IP_DATA *ip_data = NULL;
    QNSM_HEAP *vip_port_heap = NULL;
    uint8_t *buf = msg;
    QNSM_SRV_HOST *host = NULL;

    if ((NULL == send_data) || (NULL == msg)) {
        return 0;
    }

    buf = msg;
    ip_agg_data = send_data;
    ip_data = ip_agg_data->data;
    vip_port_heap = &ip_data->topn_port_statis[EN_QNSM_DST_PORT];

    *(uint32_t *)(buf + len) = ip_data->af;
    len += sizeof(uint32_t);

    host = (QNSM_SRV_HOST *)(buf + len);
    host->addr = ip_data->addr;
    host->mask = ip_data->mask_len;
    len += sizeof(QNSM_SRV_HOST);

    *(uint64_t *)(buf + len) = ip_agg_data->time_new;
    len += sizeof(uint64_t);

    *(uint64_t *)(buf + len) = EN_QNSM_DST_PORT;
    len += sizeof(uint64_t);
    *(uint64_t *)(buf + len) = vip_port_heap->cur_elem_num;
    len += sizeof(uint64_t);
    rte_memcpy(buf + len, vip_port_heap->elem, sizeof(QNSM_PORT_STATIS) * vip_port_heap->cur_elem_num);
    len += sizeof(QNSM_PORT_STATIS) * vip_port_heap->cur_elem_num;

    *msg_len = len;
    return 0;
}

static int32_t qnsm_svr_host_encap_agg_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    uint8_t *buf = NULL;
    QNSM_SVR_IP_AGG_DATA *ip_agg_data;
    QNSM_SVR_IP_DATA *ip_data = NULL;
    uint16_t len = 0;
    enum en_qnsm_detect pkt_type;
    QNSM_FLOW_STATISTICS            *statis_info[DIRECTION_MAX] = {NULL};
    QNSM_SRV_HOST *host = NULL;

    if ((NULL == send_data) || (NULL == msg)) {
        return 0;
    }

    buf = msg;
    ip_agg_data = send_data;
    ip_data = ip_agg_data->data;

    host = (QNSM_SRV_HOST *)buf;
    host->addr = ip_data->addr;
    host->mask = ip_data->mask_len;
    len += sizeof(QNSM_SRV_HOST);
    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_INFO, "enter vip 0x%x\n", ip_data->addr.in4_addr.s_addr);

    /*used as af*/
    *(uint16_t *)(buf + len) = ip_data->af;
    len += sizeof(uint16_t);

    /*time*/
    *(uint64_t *)(buf + len) = ip_agg_data->time_new;
    len += sizeof(uint64_t);


    for (pkt_type = 0; pkt_type < e_type_max; pkt_type++) {
        if (len + sizeof(uint64_t) * 4 > QNSM_MSG_MAX_DATA_LEN) {
            break;
        }
        statis_info[DIRECTION_IN] = &ip_data->statistics_info[pkt_type][DIRECTION_IN];
        statis_info[DIRECTION_OUT] = &ip_data->statistics_info[pkt_type][DIRECTION_OUT];

        //if ((statis_info[DIRECTION_IN]->bps)
        //    || (statis_info[DIRECTION_OUT]->bps))
        {
            *(uint32_t *)(buf + len) = pkt_type;
            len += sizeof(uint32_t);
            *(uint64_t *)(buf + len) = statis_info[DIRECTION_IN]->pps;
            len += sizeof(uint64_t);
            *(uint64_t *)(buf + len) = statis_info[DIRECTION_IN]->bps;
            len += sizeof(uint64_t);
            *(uint64_t *)(buf + len) = statis_info[DIRECTION_OUT]->pps;
            len += sizeof(uint64_t);
            *(uint64_t *)(buf + len) = statis_info[DIRECTION_OUT]->bps;
            len += sizeof(uint64_t);
        }
    }

    *msg_len = len;
    return 0;
}


static void qnsm_svr_host_aging(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_SVR_IP_DATA *data = arg;
    QNSM_PORT_STATIS *port_statis = NULL;
    QNSM_PORT_STATIS *tmp = NULL;
    uint64_t cur_tick = 0;
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    uint64_t aging_time = svr_tbl->aging_time;
    struct qnsm_svr_ip_ops *ops = NULL;
    int32_t ret = 0;

    cur_tick = rte_rdtsc();
    if (data->enable_sport_statis) {
        qnsm_list_for_each_entry_safe(port_statis, tmp, &data->list_head[EN_QNSM_SRC_PORT], node) {
            if (get_diff_time(cur_tick, port_statis->tick) >= aging_time) {
                /*del port statis*/
                QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "del vip 0x%x sport %u statis\n",
                           data->addr.in4_addr.s_addr,
                           port_statis->port_id);
                if (0 == qnsm_host_port_statis_del(data, EN_QNSM_SRC_PORT, port_statis)) {
                    /*!!!list_del_init must occur with for_each_entry_safe!!!*/
                    qnsm_list_del_init(&port_statis->node);
                    data->port_statis_num[EN_QNSM_SRC_PORT]--;
                }
            }
        }
    }

    /*vip dport aging*/
    if (data->enable_dport_statis) {
        qnsm_list_for_each_entry_safe(port_statis, tmp, &data->list_head[EN_QNSM_DST_PORT], node) {
            if ((0 == svr_tbl->known_ports[port_statis->port_id])
                && (get_diff_time(cur_tick, port_statis->tick) >= aging_time)) {
                /*del port statis*/
                QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "del vip 0x%x dport %u statis\n",
                           data->addr.in4_addr.s_addr,
                           port_statis->port_id);
                if (0 == qnsm_host_port_statis_del(data, EN_QNSM_DST_PORT, port_statis)) {
                    /*!!!list_del_init must occur with for_each_entry_safe!!!*/
                    qnsm_list_del_init(&port_statis->node);
                    data->port_statis_num[EN_QNSM_DST_PORT]--;
                }
            }
        }
    }

    if ((data->delay_del) && (0 == data->is_local_vip)) {
        if (get_diff_time(cur_tick, data->tick) >= (aging_time << 4)) {
            char tmp[128];
            struct qnsm_in_addr in4_addr;

            QNSM_ASSERT(0 == data->port_statis_num[EN_QNSM_SRC_PORT]);
            QNSM_ASSERT(0 == data->port_statis_num[EN_QNSM_DST_PORT]);

            if (data->topn_port_statis[EN_QNSM_SRC_PORT].elem) {
                qnsm_min_heap_destroy(&data->topn_port_statis[EN_QNSM_SRC_PORT]);
            }
            if (data->topn_port_statis[EN_QNSM_DST_PORT].elem) {
                qnsm_min_heap_destroy(&data->topn_port_statis[EN_QNSM_DST_PORT]);
            }

            if (EN_QNSM_AF_IPv4 == data->af) {
                in4_addr.s_addr = rte_cpu_to_be_32(data->addr.in4_addr.s_addr);
                inet_ntop(AF_INET, &in4_addr, tmp, sizeof(tmp));
            } else {
                inet_ntop(AF_INET6, &data->addr, tmp, sizeof(tmp));
            }
            ops = &svr_tbl->ops[data->af];
            ret = ops->f_del_host(data);
            QNSM_LOG(CRIT, "lcore %u del vip %s addr %p ret %d\n", rte_lcore_id(), tmp, data, ret);
        }

    }
    return;
}

static void qnsm_svr_host_send_agg_info(QNSM_SVR_IP_DATA *data, uint64_t time_new)
{
    QNSM_SVR_IP_AGG_DATA svr_ip;

    svr_ip.data = data;
    svr_ip.time_new = time_new;

    (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                           QNSM_MSG_SVR_IP_AGG,
                           &svr_ip,
                           data->af,
                           1);
    if ((data->topn_port_statis[EN_QNSM_SRC_PORT].elem)
        && (0 < data->topn_port_statis[EN_QNSM_SRC_PORT].cur_elem_num)) {
        (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                               QNSM_MSG_VIP_SRC_PORT_AGG,
                               &svr_ip,
                               data->addr.in4_addr.s_addr,
                               1);
    }

    if ((data->topn_port_statis[EN_QNSM_DST_PORT].elem)
        && (0 < data->topn_port_statis[EN_QNSM_DST_PORT].cur_elem_num)) {
        (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                               QNSM_MSG_VIP_DST_PORT_AGG,
                               &svr_ip,
                               data->addr.in4_addr.s_addr,
                               1);
    }
    return;
}

static void qnsm_svr_host_agg(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_SVR_IP_DATA *data = arg;
    enum en_qnsm_detect pkt_type;
    QNSM_FLOW_STATISTICS *statis_info = NULL;
    uint64_t interval = INTVAL;
    uint32_t dire = 0;
    uint8_t agg_affinity = data->agg_affinity;
    QNSM_SVR_TBL *svr_data = qnsm_app_data(EN_QNSM_VIP_AGG);
    struct in_addr ip_addr;
    char  tmp[128];

    if (data->is_local_vip) {
        statis_info = &data->statistics_info[e_total][DIRECTION_IN];
        if (statis_info->pkt_curr <= statis_info->pkt_prev) {
            statis_info->pps = 0;
            statis_info->bps = 0;
            return;
        }

        for (pkt_type = e_total; pkt_type < e_type_max; pkt_type++) {
            for (dire = 0; dire < DIRECTION_MAX; dire++) {
                statis_info = &data->statistics_info[pkt_type][dire];
                if (statis_info->pkt_curr <= statis_info->pkt_prev) {
                    statis_info->pps = 0;
                    statis_info->bps = 0;
                    continue;
                }

                /*pps & bps*/
#if 0
                /*assume div INTVAL(10)*/
                statis_info->pps = ((statis_info->pkt_curr - statis_info->pkt_prev) * 0xCCCCCCCD) >> 35;
                statis_info->bps = ((statis_info->bit_curr - statis_info->bit_prev) * 0xCCCCCCCD) >> 35;
#else
                statis_info->pps = (statis_info->pkt_curr - statis_info->pkt_prev) / interval;
                statis_info->bps = (statis_info->bit_curr - statis_info->bit_prev) / interval;
#endif
                statis_info->pkt_prev = statis_info->pkt_curr;
                statis_info->bit_prev = statis_info->bit_curr;

                if ((0 == agg_affinity) && (0 < statis_info->bps)) {
                    agg_affinity = 1;
                    data->agg_affinity = 1;

                    if (EN_QNSM_AF_IPv4 == data->af) {
                        ip_addr.s_addr = htonl(data->addr.in4_addr.s_addr);
                        (void)inet_ntop(AF_INET, &ip_addr, tmp, sizeof(tmp));
                    } else {
                        (void)inet_ntop(AF_INET6, &data->addr, tmp, sizeof(tmp));
                    }
                    QNSM_LOG(CRIT, "vip %s agg affinity is lcore %u\n", tmp, rte_lcore_id());
                }
            }
        }

        if (agg_affinity) {
            /*port statis*/
            if (data->enable_sport_statis) {
                qnsm_host_port_topn(data, EN_QNSM_SRC_PORT);
            }
            if (data->enable_dport_statis) {
                qnsm_host_port_topn(data, EN_QNSM_DST_PORT);
            }

            /*send local vip agg info*/
            qnsm_svr_host_send_agg_info(data, svr_data->clock);
        }
    } else {
        /*retransmit vip to masetr until rcvd ack or reached max retrans num*/
        if ((0 == data->rcvd_vip_syn_msg)
            && (data->retrans_num < 2)) {
            (void)qnsm_msg_send_multi(EN_QNSM_MASTER,
                                      QNSM_MSG_DYN_VIP_ADD,
                                      data,
                                      1);
            data->retrans_num++;
        }
    }

    return;
}

#if QNSM_PART("ipv4")

#ifdef  DEBUG_QNSM
QNSM_SVR_IP_DATA* qnsm_svr_dbg_find_host(QNSM_SRV_HOST *host, void *arg)

{
    uint32_t host_id;
    int32_t ret = 0;
    QNSM_SVR_IP_DATA *ip_data = NULL;
    QNSM_SVR_TBL *svr_tbl = arg;

    ret = rte_lpm_lookup(svr_tbl->lpm_tbl, host->addr.in4_addr.s_addr, &host_id);
    if (0 == ret) {
        ip_data = (QNSM_SVR_IP_DATA *)svr_tbl->data + host_id;
    }
    return ip_data;
}
#endif

static inline QNSM_SVR_IP_DATA* qnsm_host_lpm_add(uint32_t ip, uint8_t mask_len)
{
    QNSM_SVR_IP_DATA *ip_data = NULL;
    int32_t ret = 0;
    uint32_t host_id;
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);

    /*get free host*/
    for (host_id = 0; host_id < svr_tbl->max_hosts; host_id++) {
        ip_data = (QNSM_SVR_IP_DATA *)svr_tbl->data + host_id;
        if (0 == ip_data->valid) {
            ip_data->valid = 1;
            break;
        }
    }
    if (svr_tbl->max_hosts <= host_id) {
        return NULL;
    }

    ret = rte_lpm_add(svr_tbl->lpm_tbl, ip, mask_len, host_id);
    if (ret) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "!!!add vip 0x%x to lpm failed ret %d!!!\n", ip, ret);
        //RTE_LOG(CRIT, QNSM, "[ ERR ]: %s add vip 0x%x failed ret %d\n", __FUNCTION__, ip, ret);
        ip_data->valid = 0;
        return NULL;
    }
    return ip_data;
}

static inline QNSM_SVR_IP_DATA* qnsm_host_lpm_find(struct qnsm_in_addr *key)
{
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    uint32_t host_id;
    int32_t ret = 0;
    QNSM_SVR_IP_DATA *ip_data = NULL;

    ret = rte_lpm_lookup(svr_tbl->lpm_tbl, key->s_addr, &host_id);
    if (0 == ret) {
        ip_data = (QNSM_SVR_IP_DATA *)svr_tbl->data + host_id;
    }
    return ip_data;
}

static inline int32_t qnsm_host_lpm_del(uint32_t ip, uint8_t mask_len)
{
    QNSM_SVR_TBL *svr_tbl = qnsm_app_data(EN_QNSM_VIP_AGG);
    uint32_t host_id;
    int32_t ret = 0;
    QNSM_SVR_IP_DATA *ip_data = NULL;

    ret = rte_lpm_lookup(svr_tbl->lpm_tbl, ip, &host_id);
    if (0 == ret) {
        ip_data = (QNSM_SVR_IP_DATA *)svr_tbl->data + host_id;
        //memset(ip_data, 0, sizeof(QNSM_SVR_IP_DATA));
        memset(ip_data, 0, offsetof(QNSM_SVR_IP_DATA, tick));
    } else if ((-ENOENT == ret) || (-EINVAL == ret)) {
        QNSM_LOG(CRIT, "dup del vip\n");
        return 0;
    }
    (void)rte_lpm_delete(svr_tbl->lpm_tbl, ip, mask_len);

    return ret;
}

/*ip host may be a subnet or host address
*host order
*/
static QNSM_SVR_IP_DATA* qnsm_svr_add_host(QNSM_SRV_HOST *host, uint8_t is_static)
{
    QNSM_SVR_IP_DATA *ip_data;
    uint32_t lcore_id = rte_lcore_id();
    int32_t ret = 0;
    uint32_t ip = 0;

    if (NULL == host) {
        return NULL;
    }

    /*add host*/
    ip = host->addr.in4_addr.s_addr;
    ip_data = qnsm_host_lpm_add(ip, host->mask);
    if (NULL == ip_data) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "add vip 0x%x failed\n", ip);
        return NULL;

    }
    ip_data->addr.in4_addr.s_addr = ip;
    ip_data->mask_len = host->mask;
    ip_data->valid = 1;

    /*init timer*/
    rte_timer_init(&ip_data->agg_timer);
    ret = rte_timer_reset(&ip_data->agg_timer,
                          INTVAL * rte_get_timer_hz(), PERIODICAL,
                          lcore_id, qnsm_svr_host_agg, ip_data);
    if (ret < 0) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "cannot set lcore %d agg timer\n", lcore_id);
        QNSM_LOG(ERR, "init vip %p lcore %d agg timer failed", ip_data, lcore_id);
        (void)qnsm_host_lpm_del(ip, host->mask);
        return NULL;
    }

    rte_timer_init(&ip_data->aging_timer);
    ret = rte_timer_reset(&ip_data->aging_timer,
                          QNSM_VIP_AGING_TIME, PERIODICAL,
                          lcore_id, qnsm_svr_host_aging, ip_data);
    if (ret < 0) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "cannot set lcore %d aging timer\n", lcore_id);
        QNSM_LOG(ERR, "init vip %p lcore %d aging timer failed", ip_data, lcore_id);
        rte_timer_stop(&ip_data->agg_timer);
        (void)qnsm_host_lpm_del(ip, host->mask);
        return NULL;
    }

    ip_data->retrans_num = 0;
    ip_data->rcvd_vip_syn_msg = is_static;
    ip_data->is_static_vip = is_static;
    ip_data->is_local_vip = is_static;    /*static vip is local*/
    ip_data->agg_affinity = 0;

    /*port statis*/
    ip_data->enable_sport_statis = 0;
    ip_data->enable_dport_statis = is_static;
    ip_data->port_statis_num[EN_QNSM_SRC_PORT] = 0;
    ip_data->port_statis_num[EN_QNSM_DST_PORT] = 0;
    QNSM_INIT_LIST_HEAD(&ip_data->list_head[EN_QNSM_SRC_PORT]);
    QNSM_INIT_LIST_HEAD(&ip_data->list_head[EN_QNSM_DST_PORT]);

    /*set af*/
    ip_data->af = EN_QNSM_AF_IPv4;
    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "add vip 0x%x success\n", ip);
    return ip_data;
}

/*
*params host, host order
*/
static QNSM_SVR_IP_DATA* qnsm_svr_find_host(QNSM_SRV_HOST *host)
{

    return qnsm_host_lpm_find(&host->addr.in4_addr);
}

static int32_t qnsm_svr_del_host(void *item)
{
    int32_t ret = 0;
    uint32_t ip = 0;
    QNSM_SVR_IP_DATA *ip_data = item;

    if (NULL == ip_data) {
        return -1;
    }

    /*del timer*/
    if (rte_timer_stop(&ip_data->agg_timer)) {
        QNSM_LOG(ERR, "stop agg timer failed\n");
        QNSM_ASSERT(0);
    }
    if (rte_timer_stop(&ip_data->aging_timer)) {
        QNSM_LOG(ERR, "stop aging timer failed\n");
        QNSM_ASSERT(0);
    }

    /*del host*/
    ip_data->valid = 0;
    ip = ip_data->addr.in4_addr.s_addr;
    ret = qnsm_host_lpm_del(ip, ip_data->mask_len);

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "del vip 0x%x success\n", ip);
    return ret;
}

static void qnsm_svr_ip4_init(void *this)
{
    char tbl_name[32];
    struct rte_lpm_config config_ipv4;
    uint32_t socket_id = rte_socket_id();
    QNSM_SVR_TBL *svr_tbl = this;
    static struct qnsm_svr_ip_ops ops = {
        .f_add_host = qnsm_svr_add_host,
        .f_find_host = qnsm_svr_find_host,
        .f_del_host = qnsm_svr_del_host,
#ifdef  DEBUG_QNSM
        .f_dbg_find_host = qnsm_svr_dbg_find_host,
#endif
    };

    /*ops reg*/
    svr_tbl->ops[EN_QNSM_AF_IPv4] = ops;

    /*init tbl*/
    svr_tbl->not_local_vip_counter = 0;
    svr_tbl->max_hosts = QNSM_IPV4_LPM_MAX_RULES;
    svr_tbl->data = rte_zmalloc_socket("SVR_TBL",
                                       sizeof(QNSM_SVR_IP_DATA) * svr_tbl->max_hosts,
                                       RTE_CACHE_LINE_SIZE,
                                       socket_id);
    if (NULL == svr_tbl->data) {
        QNSM_ASSERT(0);
    }

    /*create lpm*/
    config_ipv4.max_rules = svr_tbl->max_hosts;
    config_ipv4.number_tbl8s = QNSM_IPV4_LPM_NUMBER_TBL8S;
    config_ipv4.flags = 0;
    snprintf(tbl_name, sizeof(tbl_name), "SVR_TBL%u", rte_lcore_id());
    svr_tbl->lpm_tbl = rte_lpm_create(tbl_name, socket_id, &config_ipv4);
    if (NULL == svr_tbl->lpm_tbl) {
        QNSM_ASSERT(0);
    }

    return;
}
#endif

#if QNSM_PART("ipv6")

#ifdef  DEBUG_QNSM
/*
*arg, pipeline para
*/
QNSM_SVR_IP_DATA* qnsm_ip6_dbg_find_host(QNSM_SRV_HOST *key, void *arg)

{
    QNSM_SVR_IP_DATA *vip_data = NULL;
    vip_data = qnsm_cmd_find_tbl_item(arg, EN_QNSM_IPV6_VIP, (void *)key);

    return vip_data;
}
#endif

/*
*@param key, mask not used, just compatible to v4
*return: find, return item,
*        other null
*/
QNSM_SVR_IP_DATA* qnsm_svr_ip6_find_host(QNSM_SRV_HOST *key)
{
    QNSM_SVR_IP_DATA *vip_data = NULL;
    vip_data = qnsm_find_tbl_item(EN_QNSM_IPV6_VIP, (void *)key);

    return vip_data;
}

static int32_t qnsm_svr_ip6_del_host(void *item)
{
    QNSM_SVR_IP_DATA *ip_data = item;
    int32_t ret = 0;
    char tmp[128];

    if (NULL == ip_data) {
        return -1;
    }

    /*del timer*/
    if (rte_timer_stop(&ip_data->agg_timer)) {
        QNSM_LOG(ERR, "stop v6 agg timer failed\n");
        QNSM_ASSERT(0);
    }
    if (rte_timer_stop(&ip_data->aging_timer)) {
        QNSM_LOG(ERR, "stop v6 aging timer failed\n");
        QNSM_ASSERT(0);
    }

    inet_ntop(AF_INET6, &ip_data->addr, tmp, sizeof(tmp));

    /*del host*/
    memset(&ip_data->af, 0, offsetof(QNSM_SVR_IP_DATA, tick));
    ret = qnsm_del_tbl_item(EN_QNSM_IPV6_VIP, ip_data);

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "del vip %s ret %d\n", tmp, ret);
    return ret;
}

/*ip host may be a subnet or host address*/
static QNSM_SVR_IP_DATA* qnsm_svr_ip6_add_host(QNSM_SRV_HOST *host, uint8_t is_static)
{
    QNSM_SVR_IP_DATA *ip_data;
    uint32_t lcore_id = rte_lcore_id();
    int32_t ret = 0;
    uint8_t normal_mode = 0;
    char tmp[128];

    if (NULL == host) {
        return NULL;
    }

    inet_ntop(AF_INET6, &host->addr, tmp, sizeof(tmp));

    /*add host*/
    ip_data = qnsm_add_tbl_item(EN_QNSM_IPV6_VIP, &host->addr, &normal_mode);
    if (NULL == ip_data) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "add vip %s failed\n", tmp);
        return NULL;

    }
    ip_data->mask_len = host->mask;
    ip_data->valid = 1;

    /*init timer*/
    rte_timer_init(&ip_data->agg_timer);
    ret = rte_timer_reset(&ip_data->agg_timer,
                          INTVAL * rte_get_timer_hz(), PERIODICAL,
                          lcore_id, qnsm_svr_host_agg, ip_data);
    if (ret < 0) {
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "cannot set lcore %d agg timer\n", lcore_id);
        (void)qnsm_del_tbl_item(EN_QNSM_IPV6_VIP, ip_data);
        return NULL;
    }

    rte_timer_init(&ip_data->aging_timer);
    (void)rte_timer_reset(&ip_data->aging_timer,
                          QNSM_VIP_AGING_TIME, PERIODICAL,
                          lcore_id, qnsm_svr_host_aging, ip_data);

    ip_data->retrans_num = 0;
    ip_data->rcvd_vip_syn_msg = is_static;
    ip_data->is_static_vip = is_static;
    ip_data->is_local_vip = is_static;    /*static vip is local*/
    ip_data->agg_affinity = 0;

    /*port statis*/
    ip_data->enable_sport_statis = 0;
    ip_data->enable_dport_statis = is_static;
    ip_data->port_statis_num[EN_QNSM_SRC_PORT] = 0;
    ip_data->port_statis_num[EN_QNSM_DST_PORT] = 0;
    QNSM_INIT_LIST_HEAD(&ip_data->list_head[EN_QNSM_SRC_PORT]);
    QNSM_INIT_LIST_HEAD(&ip_data->list_head[EN_QNSM_DST_PORT]);

    /*set af*/
    ip_data->af = EN_QNSM_AF_IPv6;
    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "add vip %s success\n", tmp);
    return ip_data;
}

static inline uint32_t
qnsm_svr_ip6_hash_crc(const void *data, __rte_unused uint32_t data_len,
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

static void qnsm_svr_ip6_tbl_reg(EN_QNSM_APP lcore_type)
{
    uint32_t pool_size = 0;

    pool_size = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_VIP_AGG) * QNSM_IPV6_VIP_MAX_NUM;
    pool_size = (pool_size << 2) / 5;
    QNSM_TBL_PARA  ipv6_para = {
        "svr_ip6",
        QNSM_IPV6_VIP_MAX_NUM,
        pool_size,
        sizeof(QNSM_SVR_IP_DATA),
        offsetof(QNSM_SVR_IP_DATA, addr),
        sizeof(QNSM_IN_ADDR),
        qnsm_svr_ip6_hash_crc,
        NULL,
        EN_QNSM_VIP_AGG,
        30,
    };

    qnsm_tbl_para_reg(lcore_type, EN_QNSM_IPV6_VIP, (void *)&ipv6_para);
    return;
}

static void qnsm_svr_ip6_init(void *this)
{
    QNSM_SVR_TBL *app_data = this;
    static struct qnsm_svr_ip_ops ops = {
        .f_add_host = qnsm_svr_ip6_add_host,
        .f_find_host = qnsm_svr_ip6_find_host,
        .f_del_host = qnsm_svr_ip6_del_host,
#ifdef  DEBUG_QNSM
        .f_dbg_find_host = qnsm_ip6_dbg_find_host,
#endif
    };

    /*ops reg*/
    app_data->ops[EN_QNSM_AF_IPv6] = ops;

    /*init tbl*/
    qnsm_svr_ip6_tbl_reg(EN_QNSM_VIP_AGG);
    return;
}
#endif

static void qnsm_svr_conf_host_init(void)
{
    /*init tbl*/
    QNSM_VIP_CFG *groups = NULL;
    QNSM_SVR_IP_GROUP *ip_group;
    uint16_t group_id;
    char tmp[128];
    QNSM_SRV_HOST host;

    groups = qnsm_get_groups();
    if (NULL == groups) {
        QNSM_ASSERT(0);
    }
    for (group_id = 0; group_id < groups->group_num; group_id++) {
        ip_group = groups->group[group_id];
        if (0 == ip_group->valid) {
            continue;
        }
        if (0 == strcmp(ip_group->name, "disable_ip")) {
            host.addr.in4_addr.s_addr =
                rte_be_to_cpu_32(ip_group->hosts[0].addr.in4_addr.s_addr);
            host.mask = ip_group->hosts[0].mask;
            inet_ntop(AF_INET, &ip_group->hosts[0].addr.in4_addr, tmp, sizeof(tmp));
            if (qnsm_host_lpm_add(host.addr.in4_addr.s_addr, host.mask)) {
                printf("disable vip %s add success\n", tmp);
            }
        }

    }
    return;
}


inline QNSM_SVR_IP_DATA* qnsm_get_svr_tbl(QNSM_SVR_TBL *tbl)
{
    return tbl->data;
}

#if QNSM_PART("DYN VIP")
int32_t qnsm_svr_ecnap_dyn_vip(void *msg, uint32_t *msg_len, void *send_data)
{
    uint8_t *buf = msg;
    QNSM_SVR_IP_DATA *ip_data = send_data;
    uint32_t len = 0;

    *(uint32_t *)(buf + len) = ip_data->af;
    len += sizeof(uint32_t);
    *(QNSM_IN_ADDR *)(buf + len) = ip_data->addr;
    len += sizeof(QNSM_IN_ADDR);

    *msg_len = len;
    return 0;
}

static int32_t qnsm_svr_biz_vip_msg_proc(void *data, uint32_t data_len)
{
    int32_t ret = 0;
    uint8_t is_local_vip = 0;
    QNSM_BIZ_VIP_MSG *vip_msg = data;
    QNSM_SRV_HOST key;
    QNSM_SVR_IP_DATA *ip_data = NULL;
    QNSM_SVR_TBL *svr_data = qnsm_app_data(EN_QNSM_VIP_AGG);
    struct qnsm_svr_ip_ops *ops = NULL;
    char tmp[128];

    QNSM_ASSERT(QNSM_BIZ_VIP_ADD == vip_msg->op);
    if (EN_QNSM_AF_IPv4 == vip_msg->af) {
        key.addr.in4_addr.s_addr= rte_be_to_cpu_32(vip_msg->key.in4_addr.s_addr);
        key.mask = QNSM_IPV4_MAX_MASK_LEN;
        inet_ntop(AF_INET, &vip_msg->key, tmp, sizeof(tmp));
    } else {
        key.addr.in6_addr = vip_msg->key.in6_addr;
        key.mask = 128;
        inet_ntop(AF_INET6, &vip_msg->key, tmp, sizeof(tmp));
    }

    /*get ops*/
    ops = svr_data->ops + vip_msg->af;

    ip_data = ops->f_find_host(&key);

    /*rcvd ack from master*/
    if (EN_QNSM_CMD_MAX == vip_msg->cmd) {
        if (ip_data) {
            ip_data->rcvd_vip_syn_msg = 1;
        }

        is_local_vip = vip_msg->cmd_data[0];
        if (0 == is_local_vip) {
            if (ip_data
                && (0 == ip_data->is_static_vip)) {
                /*now just stop agg timer & set delay del flag*/
                rte_timer_stop(&ip_data->agg_timer);
                ip_data->delay_del = 1;
                //RTE_LOG(CRIT, QNSM, "[ EVT ]: %s delay del vip %s\n", __FUNCTION__, tmp);
            }
            return ret;
        }
    }

    if (NULL == ip_data) {
        ip_data = ops->f_add_host(&key, 0);
        if (NULL == ip_data) {
            QNSM_LOG(ERR, "add local vip %s failed\n", tmp);
            return ret;
        }
    }

    if (0 == ip_data->is_local_vip) {
        /*set local vip*/
        ip_data->is_local_vip = 1;

        /*enable dport statis*/
        ip_data->enable_dport_statis = 1;

        enum qnsm_port_type type = 0;
        for (type = 0; type < EN_QNSM_PORT_TYPE_MAX; type++) {

            if (NULL == ip_data->topn_port_statis[type].elem) {
                qnsm_min_heap_init(ip_data->topn_port_statis + type,
                                   QNSM_PORT_TOPN,
                                   sizeof(QNSM_PORT_STATIS),
                                   qnsm_port_statis_compare);
                QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT,
                           "vip %s heap elem 0x%p\n",
                           tmp, ip_data->topn_port_statis[type].elem);
            }
        }

        QNSM_LOG(CRIT, "lcore %u set dyn vip %s local\n",
                rte_lcore_id(), tmp);
    }

    /*vip cmd proc*/
    switch(vip_msg->cmd) {
        case EN_QNSM_CMD_MAX: {
            break;
        }
        case EN_QNSM_CMD_ENABLE_SPORT_STATIS: {
            ip_data->enable_sport_statis = 1;
            break;
        }
        case EN_QNSM_CMD_DISABLE_SPORT_STATIS: {
            ip_data->enable_sport_statis = 0;
            qnsm_min_heap_reset(&ip_data->topn_port_statis[EN_QNSM_SRC_PORT]);
            break;
        }
        default: {
            break;
        }
    }

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT,
               "update dyn vip %s local enable_sport_statis %u\n",
               tmp,
               ip_data->enable_sport_statis);
    return ret;
}
#endif

#if QNSM_PART("clock syn")
static int32_t qnsm_svr_syn_clock_msg_proc(void *data, uint32_t data_len)
{
    QNSM_SVR_TBL *svr_data = qnsm_app_data(EN_QNSM_VIP_AGG);

    svr_data->clock = *((uint64_t *)data);
    svr_data->syn_clock_num++;

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_WARN, "cur clock is %" PRIu64 "\n", svr_data->clock);

    return 0;
}
#endif

void qnsm_svr_host_statistics_update(void *this,
                                     QNSM_PACKET_INFO *pkt_info,
                                     int32_t dire,
                                     uint32_t detect_type)
{
    QNSM_SVR_IP_DATA *svr_ip_data = NULL;
    QNSM_PORT_STATIS *port_statis = NULL;
    uint32_t pkt_len = 0;
    uint8_t af = pkt_info->af;
    uint64_t cur_tick = rte_get_tsc_cycles();
    QNSM_SVR_TBL *app_data = this;
    struct qnsm_svr_ip_ops *ops = app_data->ops + af;
    QNSM_SRV_HOST host;
    uint16_t sport = pkt_info->sport;
    uint16_t dport = pkt_info->dport;
    int32_t  ret = 0;

    host.mask = (EN_QNSM_AF_IPv4 == af) ? QNSM_IPV4_MAX_MASK_LEN : 128;

    /*DIRECTION_MAX: add for default biz*/
    if (DIRECTION_MAX == dire) {
        ret = qnsm_match_service(pkt_info, dport);
        if (ret) {
            host.addr = (1 == ret) ? pkt_info->dst_addr : pkt_info->src_addr;
            svr_ip_data = ops->f_find_host(&host);
            if (NULL == svr_ip_data) {
                svr_ip_data = ops->f_add_host(&host, 0);

                /*send msg*/
                if (NULL != svr_ip_data) {
                    (void)qnsm_msg_send_multi(EN_QNSM_MASTER,
                                              QNSM_MSG_DYN_VIP_ADD,
                                              svr_ip_data,
                                              1);
                } else {
                    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "[ ERR ]: 0x%x add vip dport %u failed\n",
                               host.addr.in4_addr.s_addr,
                               dport);
                    goto EXIT;
                }
            }

            if (0 == svr_ip_data->is_local_vip) {
                svr_ip_data->tick = cur_tick;
                goto EXIT;
            }
            dire = DIRECTION_IN;
        } else {
            /*
            *not match service,
            *no update statis
            *
            *todo
            *inform this (sip+dip) to bordermanage
            */
            goto EXIT;
        }
    } else {
        host.addr = (DIRECTION_IN == dire) ? (pkt_info->dst_addr) : (pkt_info->src_addr);

        svr_ip_data = ops->f_find_host(&host);
        if (NULL == svr_ip_data) {
            QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_ERR, "err vip not found\n");
            goto EXIT;
        }
    }

    pkt_len = pkt_info->pkt_len;
    pkt_len += 20;
    pkt_len = pkt_len << 3;

    svr_ip_data->statistics_info[e_total][dire].pkt_curr++;
    svr_ip_data->statistics_info[e_total][dire].bit_curr += pkt_len;

    svr_ip_data->statistics_info[detect_type][dire].pkt_curr++;
    svr_ip_data->statistics_info[detect_type][dire].bit_curr += pkt_len;

    if (TCP_PROTOCOL == pkt_info->proto) {
        svr_ip_data->statistics_info[e_tcp][dire].pkt_curr++;
        svr_ip_data->statistics_info[e_tcp][dire].bit_curr += pkt_len;
    }

    svr_ip_data->tick = cur_tick;

    /*update vip + port in statis*/
    if ((TCP_PROTOCOL != pkt_info->proto)
        && (UDP_PROTOCOL != pkt_info->proto)) {
        goto EXIT;
    }

    if (e_frag == detect_type) {
        if (UDP_PROTOCOL == pkt_info->proto) {
            svr_ip_data->statistics_info[e_udp][dire].pkt_curr++;
            svr_ip_data->statistics_info[e_udp][dire].bit_curr += pkt_len;
        }
        goto EXIT;
    }

    if ((DIRECTION_IN == dire)
        && ((svr_ip_data->is_static_vip) || (svr_ip_data->is_local_vip))) {
        /*update sport*/
        if (0 != svr_ip_data->enable_sport_statis) {
            port_statis = qnsm_host_port_statis_find(svr_ip_data, EN_QNSM_SRC_PORT, sport);
            if (NULL == port_statis) {
                /*add port statis*/
                port_statis = qnsm_host_port_statis_add(svr_ip_data, EN_QNSM_SRC_PORT, sport);
            }
            if (port_statis) {
                port_statis->intval_pkts++;
                port_statis->intval_bits += pkt_len;
                port_statis->tick = svr_ip_data->tick;
            }
        }

        /*update dport*/
        if (svr_ip_data->enable_dport_statis) {
            port_statis = qnsm_host_port_statis_find(svr_ip_data, EN_QNSM_DST_PORT, dport);
            if (NULL == port_statis) {
                /*add port statis*/
                port_statis = qnsm_host_port_statis_add(svr_ip_data, EN_QNSM_DST_PORT, dport);

            }
            if (port_statis) {
                port_statis->intval_pkts++;
                port_statis->intval_bits += pkt_len;
                port_statis->tick = svr_ip_data->tick;
            }
        }
    }

EXIT:
    return;

}

void qnsm_pkt_svr_statis_update(void *this,
                                QNSM_PACKET_INFO* pkt_info,
                                int32_t dire,
                                struct rte_mbuf *mbuf)
{
    enum en_qnsm_detect detect_type;

    if (0 == pkt_info->is_frag) {

        detect_type = qnsm_pkt_type_parse(pkt_info, dire, pkt_info->lcore_id, ((QNSM_SVR_TBL *)this)->en_tcp_det_type);
    } else {
        detect_type = e_frag;
    }

    qnsm_svr_host_statistics_update(this, pkt_info, dire, detect_type);

    return;
}

void qnsm_svr_proc(void *this_app_data, uint32_t lcore_id, struct rte_mbuf *mbuf)
{
    uint8_t          direction;
    QNSM_PACKET_INFO *pkt_info;

    /*get mbuf private data*/
    pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);
    direction = pkt_info->direction;

    /*set lcore id*/
    pkt_info->lcore_id = lcore_id;
    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_PKT, "direction %d\n", direction);

    qnsm_pkt_svr_statis_update(this_app_data, pkt_info, direction, mbuf);

    return;
}

void qnsm_svr_action(struct rte_mbuf *mbuf)
{
    QNSM_PACKET_INFO *pkt_info;
    uint32_t pos = 0;

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_PKT, "enter\n");

    /*get mbuf private data*/
    pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);
    pos = mbuf->hash.rss;

    if (0 != pkt_info->is_frag) {
        pos = pkt_info->v4_dst_ip;
    }
    qnsm_port_tx_lb(pos, mbuf);

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_PKT, "leave\n");
    return;
}


int32_t qnsm_service_svr_host_init(void)
{
    uint32_t socket_id = rte_socket_id();
    QNSM_SVR_TBL *svr_tbl = qnsm_app_inst_init(sizeof(QNSM_SVR_TBL),
                            qnsm_svr_proc,
                            qnsm_svr_action,
                            NULL);
    uint16_t index = 0;
    EN_QNSM_APP *app_type = app_get_lcore_app_type(qnsm_service_get_cfg_para());
    char tbl_name[32];
    QNSM_SERVICES_CFG *known_ports_cfg = qnsm_get_known_ports();

    /*msg reg*/
    (void)qnsm_msg_publish();
    for (index = 0; index < APP_MAX_LCORES; index ++) {
        if ((app_type[index] == EN_QNSM_EDGE)
            || (app_type[index] == EN_QNSM_MASTER)) {
            (void)qnsm_msg_subscribe(index);
        }
    }
    (void)qnsm_msg_reg(QNSM_MSG_SVR_IP_AGG, NULL, qnsm_svr_host_encap_agg_msg);
    (void)qnsm_msg_reg(QNSM_MSG_DYN_VIP_ADD, NULL, qnsm_svr_ecnap_dyn_vip);
    (void)qnsm_msg_reg(QNSM_MSG_VIP_SRC_PORT_AGG, NULL, qnsm_vip_encap_src_port_msg);
    (void)qnsm_msg_reg(QNSM_MSG_VIP_DST_PORT_AGG, NULL, qnsm_vip_encap_dst_port_msg);
    (void)qnsm_msg_reg(QNSM_MSG_SYN_BIZ_VIP, qnsm_svr_biz_vip_msg_proc, NULL);
    (void)qnsm_msg_reg(QNSM_MSG_CLOCK_SYN, qnsm_svr_syn_clock_msg_proc, NULL);
    qnsm_msg_flush_timer_init();

    svr_tbl->clock = jiffies();
    svr_tbl->syn_clock_num = 0;

    /*v4 init*/
    qnsm_svr_ip4_init(svr_tbl);

    /*v6 init*/
    qnsm_svr_ip6_init(svr_tbl);

    /*conf init*/
    qnsm_svr_conf_host_init();

    /*vip port tbl init*/
    svr_tbl->port_statis_entries[EN_QNSM_SRC_PORT] = QNSM_SPORT_ENTRIES;
    svr_tbl->port_statis_entries[EN_QNSM_DST_PORT] = QNSM_DPORT_ENTRIES;
    (void)qnsm_port_statis_tbl_init(EN_QNSM_SRC_PORT, 4096 * QNSM_SPORT_ENTRIES);
    (void)qnsm_port_statis_tbl_init(EN_QNSM_DST_PORT, 4096 * QNSM_DPORT_ENTRIES * 2);

    /*
    *alloc port statis pool
    *QNSM_PORT_MAX_NUM * sizeof(QNSM_PORT_STATIS):1M
    */
    snprintf(tbl_name, sizeof(tbl_name), "VIPPORT_POOL_%u", rte_lcore_id());
    svr_tbl->port_statis_pool = rte_mempool_create(tbl_name,
                                128  * QNSM_PORT_MAX_NUM,
                                sizeof(QNSM_PORT_STATIS),
                                512,
                                0,
                                NULL,
                                NULL,
                                qnsm_svr_port_statis_item_init,
                                NULL,
                                socket_id,
                                0);
    if (NULL == svr_tbl->port_statis_pool) {
        QNSM_ASSERT(0);
    }

    /*init known ports*/
    memset(svr_tbl->known_ports, 0, QNSM_PORT_MAX_NUM * sizeof(uint8_t));
    for (index = 0; index < known_ports_cfg->port_num; index++) {
        svr_tbl->known_ports[known_ports_cfg->port[index]] = 1;
    }

    /*init tcp det type*/
    memset(svr_tbl->en_tcp_det_type, e_other_flag, 256);
    svr_tbl->en_tcp_det_type[TCP_SYN] = e_syn;
    svr_tbl->en_tcp_det_type[TCP_SYN | TCP_PUSH] = e_syn;
    svr_tbl->en_tcp_det_type[TCP_SYN | TCP_PUSH | TCP_URG] = e_syn;
    svr_tbl->en_tcp_det_type[TCP_SYN | TCP_ECN] = e_syn;
    svr_tbl->en_tcp_det_type[TCP_SYNACK] = e_synack;
    svr_tbl->en_tcp_det_type[TCP_ACK] = e_ack;
    svr_tbl->en_tcp_det_type[TCP_PUSHACK] = e_ack;
    svr_tbl->en_tcp_det_type[TCP_FIN] = e_fin;
    svr_tbl->en_tcp_det_type[TCP_FINACK] = e_fin;
    svr_tbl->en_tcp_det_type[TCP_SYNFIN] = e_fin;
    svr_tbl->en_tcp_det_type[TCP_RST] = e_rst;
    svr_tbl->en_tcp_det_type[TCP_FINRST] = e_rst;
    svr_tbl->en_tcp_det_type[TCP_SYNRST] = e_rst;

    svr_tbl->aging_time = QNSM_VIP_AGING_TIME - rte_get_timer_hz();
    return 0;
}

#if QNSM_PART("show cmd")
#define CMD_SHOW_CUTOM_IP (0x01)
#define CMD_SHOW_VIP      (0x02)
#define CMD_SHOW_BRIEF    (0x04)
#define CMD_SHOW_PORT     (0x08)

struct rte_eth_xstat_name show_xgbe_stat_name[256];
struct rte_eth_xstat show_xgbe_stat[256];

/*cmd show flow*/
struct cmd_show_flow_result {
    cmdline_fixed_string_t show_flow;
    cmdline_fixed_string_t show_flow_type;
};

static void cmd_show_flow_parsed(void *parsed_result,
                                 __attribute__((unused)) struct cmdline *cl,
                                 __attribute__((unused)) void *data)
{
    unsigned portid;
    int nb_ports = 0;
    struct rte_eth_stats igb_stats;
    struct rte_eth_link link;
    int index = 0;
    struct in_addr ip_addr;
    char  tmp[128];
    uint8_t show_flag = 0;
    struct cmd_show_flow_result *res = parsed_result;
    QNSM_SVR_IP_DATA *svr_ip_tbl;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;
    uint32_t lcore_id = 0;
    QNSM_SVR_IP_DATA *item = NULL;
    uint32_t iter = 0;

    if (!strcmp(res->show_flow_type, "vip")) {
        show_flag = (CMD_SHOW_VIP);
    }
    if (!strcmp(res->show_flow_type, "brief")) {
        show_flag = (CMD_SHOW_VIP | CMD_SHOW_PORT | CMD_SHOW_BRIEF);
    }

    if (!strcmp(res->show_flow_type, "port")) {
        show_flag = (CMD_SHOW_PORT);
    }


    nb_ports = rte_eth_dev_count();

    /*interface stats*/
    if (show_flag & CMD_SHOW_PORT) {
        uint32_t xgbe_stat_name_num = 0;
        uint32_t xgbe_stat_num = 0;
        for(portid = 0; portid < nb_ports; portid++) {
            rte_eth_stats_get(portid, &igb_stats);

            cmdline_printf(
                cl,
                "\n"
                "Statistics for port %u ------------------------------\n"
                "NIC drop  = %" PRIu64 "\n"
                "ierrors  = %" PRIu64 "\n"
                "Promiscuous mode: %s\n"
                "rbytes M: %" PRIu64 "\n"
                "Packets received: %" PRIu64 "\n\n"
                , portid,  igb_stats.imissed, igb_stats.ierrors,
                rte_eth_promiscuous_get(portid) ? "enabled" : "disabled", (igb_stats.ibytes >> 20), igb_stats.ipackets);

            rte_eth_link_get(portid, &link);
            cmdline_printf(
                cl,
                "duplex %u\n",
                link.link_duplex);
            if (!(show_flag & CMD_SHOW_BRIEF) && (ETH_SPEED_NUM_10G == link.link_speed)) {
                xgbe_stat_name_num = rte_eth_xstats_get_names(portid, show_xgbe_stat_name, sizeof(show_xgbe_stat_name));
                xgbe_stat_num = rte_eth_xstats_get(portid, show_xgbe_stat, sizeof(show_xgbe_stat));
                if (xgbe_stat_num > xgbe_stat_name_num) {
                    xgbe_stat_num = xgbe_stat_name_num;
                }
                for (index = 0; index < xgbe_stat_num; index++) {
                    cmdline_printf(
                        cl,
                        "%s id %" PRIu64 " value %" PRIu64 "\n",
                        show_xgbe_stat_name[index].name,
                        show_xgbe_stat[index].id,
                        show_xgbe_stat[index].value
                    );
                }
            }
        }
    }

    for (index = 0; index < app_paras->n_mempools; index++) {
        struct rte_mempool *pool = app_paras->mempool[index];
        if (pool) {
            cmdline_printf(cl, "socket %u mbuf pool size %u used cnt %u\n\n",
                           app_paras->mempool_params[index].cpu_socket_id,
                           pool->size,
                           rte_mempool_in_use_count(pool));
        }
    }

    /*flow stats*/
    char dir_str[DIRECTION_MAX][16] = {">>>>>>","<<<<<<"};
    uint32_t p_id;

    /*out ip*/
    if (show_flag & CMD_SHOW_VIP) {

        for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
            if (EN_QNSM_VIP_AGG == app_paras->pipeline_params[p_id].app_type) {
                pipeline_para = &app_paras->pipeline_params[p_id];
                lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                     pipeline_para->socket_id,
                                                     pipeline_para->core_id,
                                                     pipeline_para->hyper_th_id);
                svr_ip_tbl = qnsm_get_svr_tbl(qnsm_cmd_app_data(pipeline_para, EN_QNSM_VIP_AGG));
                cmdline_printf(cl,"\n=====lcore %u  vip4 statis=====\n", lcore_id);
                for (index = 0; index < QNSM_IPV4_LPM_MAX_RULES; index++) {
                    if (0 == svr_ip_tbl[index].valid) {
                        continue;
                    }
                    ip_addr.s_addr = htonl(svr_ip_tbl[index].addr.in4_addr.s_addr);
                    (void)inet_ntop(AF_INET, &ip_addr, tmp, sizeof(tmp));
                    cmdline_printf(cl,
                                   "\n"
                                   "VIP %s  mask %u local_vip %d\n",
                                   tmp,
                                   svr_ip_tbl[index].mask_len,
                                   svr_ip_tbl[index].is_local_vip);

                    if (svr_ip_tbl[index].statistics_info[e_total][DIRECTION_IN].bps) {
                        cmdline_printf(cl,"%s cur pkt num %" PRIu64 " pps %" PRIu64 " bps %" PRIu64 " frag_pkt_pps %" PRIu64 "\n",
                                       dir_str[DIRECTION_IN],
                                       svr_ip_tbl[index].statistics_info[e_total][DIRECTION_IN].pkt_curr,
                                       svr_ip_tbl[index].statistics_info[e_total][DIRECTION_IN].pps,
                                       svr_ip_tbl[index].statistics_info[e_total][DIRECTION_IN].bps,
                                       svr_ip_tbl[index].statistics_info[e_frag][DIRECTION_IN].pps);
                    }

                    if (svr_ip_tbl[index].statistics_info[e_total][DIRECTION_OUT].bps) {
                        cmdline_printf(cl,"%s cur pkt num %" PRIu64 " pps %" PRIu64 " bps %" PRIu64 " frag_pkt_pps %" PRIu64 "\n",
                                       dir_str[DIRECTION_OUT],
                                       svr_ip_tbl[index].statistics_info[e_total][DIRECTION_OUT].pkt_curr,
                                       svr_ip_tbl[index].statistics_info[e_total][DIRECTION_OUT].pps,
                                       svr_ip_tbl[index].statistics_info[e_total][DIRECTION_OUT].bps,
                                       svr_ip_tbl[index].statistics_info[e_frag][DIRECTION_OUT].pps);
                    }
                }

                /*iter v6*/
                cmdline_printf(cl,"\n=====lcore %u  vip6 statis=====\n", lcore_id);
                iter = 0;
                while(0 <= qnsm_cmd_iter_tbl(pipeline_para, EN_QNSM_IPV6_VIP, (void **)&item, &iter)) {
                    (void)inet_ntop(AF_INET6, &item->addr.in6_addr, tmp, sizeof(tmp));
                    cmdline_printf(cl,
                                   "\n"
                                   "VIP %s  mask %u local_vip %d\n",
                                   tmp,
                                   item->mask_len,
                                   item->is_local_vip);

                    if (item->statistics_info[e_total][DIRECTION_IN].bps) {
                        cmdline_printf(cl,"%s cur pkt num %" PRIu64 " pps %" PRIu64 " bps %" PRIu64 " frag_pkt_pps %" PRIu64 "\n",
                                       dir_str[DIRECTION_IN],
                                       item->statistics_info[e_total][DIRECTION_IN].pkt_curr,
                                       item->statistics_info[e_total][DIRECTION_IN].pps,
                                       item->statistics_info[e_total][DIRECTION_IN].bps,
                                       item->statistics_info[e_frag][DIRECTION_IN].pps);
                    }

                    if (item->statistics_info[e_total][DIRECTION_OUT].bps) {
                        cmdline_printf(cl,"%s cur pkt num %" PRIu64 " pps %" PRIu64 " bps %" PRIu64 " frag_pkt_pps %" PRIu64 "\n",
                                       dir_str[DIRECTION_OUT],
                                       item->statistics_info[e_total][DIRECTION_OUT].pkt_curr,
                                       item->statistics_info[e_total][DIRECTION_OUT].pps,
                                       item->statistics_info[e_total][DIRECTION_OUT].bps,
                                       item->statistics_info[e_frag][DIRECTION_OUT].pps);
                    }
                }
            }
        }
    }

    return;
}

cmdline_parse_token_string_t cmd_show_flow_string =
    TOKEN_STRING_INITIALIZER(struct cmd_show_flow_result, show_flow,
                             "show_flow");

cmdline_parse_token_string_t cmd_show_flow_type =
    TOKEN_STRING_INITIALIZER(struct cmd_show_flow_result, show_flow_type,
                             "vip#port#brief");

cmdline_parse_inst_t cmd_show_flow = {
    .f = cmd_show_flow_parsed,
    .data = NULL,
    .help_str = "show_flow vip#port#brief",
    .tokens = {
        (void *)&cmd_show_flow_string,
        (void *)&cmd_show_flow_type,
        NULL,
    },
};


struct cmd_show_vip_result {
    cmdline_fixed_string_t show_vip;
    cmdline_ipaddr_t vip;
};

static void cmd_show_vip_parsed(void *parsed_result,
                                __attribute__((unused)) struct cmdline *cl,
                                __attribute__((unused)) void *data)
{
#ifdef  DEBUG_QNSM
    struct cmd_show_vip_result *vip_result = parsed_result;
    QNSM_SVR_TBL *svr_data;
    QNSM_SVR_IP_DATA *ip_data;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;
    uint32_t p_id;
    uint32_t lcore_id = 0;
    uint32_t index = 0;
    QNSM_PORT_STATIS *topn_port = NULL;
    QNSM_PORT_STATIS *port_statis = NULL;
    QNSM_PORT_STATIS *tmp = NULL;
    QNSM_FLOW_STATISTICS *statis = NULL;
    QNSM_SRV_HOST key;
    struct qnsm_svr_ip_ops *ops = NULL;
    void *arg = NULL;

    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (EN_QNSM_VIP_AGG == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                 pipeline_para->socket_id,
                                                 pipeline_para->core_id,
                                                 pipeline_para->hyper_th_id);
            svr_data = qnsm_cmd_app_data(pipeline_para, EN_QNSM_VIP_AGG);
            switch (vip_result->vip.family) {
                case AF_INET:
                    key.addr.in4_addr.s_addr= rte_be_to_cpu_32(vip_result->vip.addr.ipv4.s_addr);
                    key.mask = QNSM_IPV4_MAX_MASK_LEN;
                    ops = svr_data->ops + EN_QNSM_AF_IPv4;
                    arg = svr_data;
                    break;
                case AF_INET6:
                    rte_memcpy(&key.addr.in6_addr, &vip_result->vip.addr.ipv6, IPV6_ADDR_LEN);
                    key.mask = 128;
                    ops = svr_data->ops + EN_QNSM_AF_IPv6;
                    arg = pipeline_para;
                    break;
                default:
                    return;
            }
            ip_data = ops->f_dbg_find_host(&key, arg);
            if (NULL == ip_data) {
                return;
            }

            cmdline_printf(cl,"lcore %d topn port statis\n", lcore_id);
            topn_port = ip_data->topn_port_statis[EN_QNSM_SRC_PORT].elem;
            if (NULL != topn_port) {
                for (index = 0; index < ip_data->topn_port_statis[EN_QNSM_SRC_PORT].cur_elem_num; index++) {
                    cmdline_printf(cl,"src port %u pkts %u bits %" PRIu64 "\n",
                                   topn_port[index].port_id,
                                   topn_port[index].intval_pkts,
                                   topn_port[index].intval_bits);
                }
            }
            cmdline_printf(cl,"\n");

            topn_port = ip_data->topn_port_statis[EN_QNSM_DST_PORT].elem;
            if (NULL != topn_port) {
                for (index = 0; index < ip_data->topn_port_statis[EN_QNSM_DST_PORT].cur_elem_num; index++) {
                    cmdline_printf(cl,"dst port %u pkts %u bits %" PRIu64 "\n",
                                   topn_port[index].port_id,
                                   topn_port[index].intval_pkts,
                                   topn_port[index].intval_bits);
                }
            }
            cmdline_printf(cl,"all dst port statis\n");
            qnsm_list_for_each_entry_safe(port_statis, tmp, &ip_data->list_head[EN_QNSM_DST_PORT], node) {
                cmdline_printf(cl,"dst port %u pkts %u bits %" PRIu64 "\n",
                               port_statis->port_id,
                               port_statis->intval_pkts,
                               port_statis->intval_bits);
            }
            cmdline_printf(cl,"\n");

            statis = &ip_data->statistics_info[e_total][DIRECTION_IN];
            cmdline_printf(cl,"total in pps %" PRIu64 " bps %" PRIu64 "\n",
                           statis->pps,
                           statis->bps);
            statis = &ip_data->statistics_info[e_total][DIRECTION_OUT];
            cmdline_printf(cl,"total out pps %" PRIu64 " bps %" PRIu64 "\n",
                           statis->pps,
                           statis->bps);
            cmdline_printf(cl,"\n\n");
        }
    }
#endif
    return;
}

cmdline_parse_token_string_t cmd_show_vip_string =
    TOKEN_STRING_INITIALIZER(struct cmd_show_vip_result, show_vip,
                             "show_vip");
cmdline_parse_token_ipaddr_t cmd_show_vip_arg =
    TOKEN_IPADDR_INITIALIZER(struct cmd_show_vip_result, vip);

cmdline_parse_inst_t cmd_show_vip = {
    .f = cmd_show_vip_parsed,
    .data = NULL,
    .help_str = "Show vip(x.x.x.x).",
    .tokens = {
        (void *)&cmd_show_vip_string,
        (void *)&cmd_show_vip_arg,
        NULL,
    },
};
#endif



