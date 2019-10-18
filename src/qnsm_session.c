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
#include <rte_udp.h>
#include <rte_sctp.h>
#include <rte_icmp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_ip_frag.h>
#include <rte_lpm.h>
#include <rte_table_acl.h>
#include <rte_net.h>
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
#include "app.h"
#include "qnsm_service_ex.h"
#include "qnsm_tbl_ex.h"
#include "qnsm_dpi_ex.h"
#include "qnsm_msg_ex.h"
#include "qnsm_port_ex.h"
#include "qnsm_master_ex.h"
#include "tcp_session.h"
#include "qnsm_ip_agg.h"
#include "qnsm_acl_ex.h"
#include "qnsm_ip.h"
#include "qnsm_session.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_HASH_CRC 1
#endif

#ifdef  DEBUG_QNSM
#define QNSM_SESS_INC_COUNTER(data, counter)  ((QNSM_SESS_DATA *)(data))->counter++
#define QNSM_SESS_ADD_COUNTER(data, counter, var)  ((QNSM_SESS_DATA *)(data))->counter += (var)

static void qnsm_sess_statis_timer(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_SESS_DATA *data = arg;
#ifndef __DDOS
    data->pps = data->inner_pkt_counter / 10;
    data->bps = data->bits / 10;
    data->bits = 0;
#else
    data->pps = (data->inner_pkt_counter + data->outer_pkt_counter)/ 10;
    data->outer_pkt_counter = 0;
#endif

    data->inner_pkt_counter = 0;
    return;
}
void qnsm_sess_statis_timer_init(void *this)
{
    QNSM_SESS_DATA *data = this;

    rte_timer_init(&data->statis_timer);
    (void)rte_timer_reset(&data->statis_timer,
                          rte_get_timer_hz() * 10, PERIODICAL,
                          rte_lcore_id(), qnsm_sess_statis_timer, data);
    return;
}

#else
#define QNSM_SESS_INC_COUNTER(data, counter)
#define QNSM_SESS_ADD_COUNTER(data, counter, var)
#endif

#if QNSM_PART("parse pkt")

static inline int32_t qnsm_parse_ptype(struct rte_mbuf *m)
{
    struct rte_net_hdr_lens lens = {0};
    QNSM_PACKET_INFO *pkt_info = (QNSM_PACKET_INFO *)(m + 1);
    const struct ipv4_hdr *ip4h;
    struct ipv4_hdr ip4h_copy;
    const struct ipv6_hdr *ip6h;
    struct ipv6_hdr ip6h_copy;
    uint32_t l3_ptypes = 0;
    uint32_t l4_types = 0;

    /*parse pkt*/
    m->packet_type = rte_net_get_ptype(m, &lens, RTE_PTYPE_ALL_MASK);

    pkt_info->payload = NULL;
    if (0 == lens.tunnel_len) {
        /*fill pkt info*/
        pkt_info->l3_offset = lens.l2_len;
        pkt_info->l3_len = lens.l3_len;
        l4_types = m->packet_type & RTE_PTYPE_L4_MASK;
        pkt_info->is_frag = (RTE_PTYPE_L4_FRAG == l4_types) ? 1 : 0;

        l3_ptypes = m->packet_type & RTE_PTYPE_L3_MASK;
        if (l3_ptypes == RTE_PTYPE_L3_IPV4 || l3_ptypes == RTE_PTYPE_L3_IPV4_EXT) {
            ip4h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv4_hdr), &ip4h_copy);

            QNSM_ASSERT(4 == (ip4h->version_ihl >> 4));
            pkt_info->proto = ip4h->next_proto_id;
            pkt_info->src_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->src_addr);
            pkt_info->dst_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->dst_addr);
            pkt_info->payload = (char *)ip4h + lens.l3_len + lens.l4_len;
            pkt_info->af = EN_QNSM_AF_IPv4;
        } else if ((l3_ptypes == RTE_PTYPE_L3_IPV6) || (l3_ptypes == RTE_PTYPE_L3_IPV6_EXT)) {
            ip6h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv6_hdr), &ip6h_copy);

            QNSM_ASSERT(6 == (((uint8_t)ip6h->vtc_flow) >> 4));
            rte_memcpy(pkt_info->src_addr.in6_addr.s6_addr, ip6h->src_addr, IPV6_ADDR_LEN);
            rte_memcpy(pkt_info->dst_addr.in6_addr.s6_addr, ip6h->dst_addr, IPV6_ADDR_LEN);
            pkt_info->payload = (char *)ip6h + lens.l3_len + lens.l4_len;
            pkt_info->af = EN_QNSM_AF_IPv6;
            if (l3_ptypes == RTE_PTYPE_L3_IPV6) {
                pkt_info->proto = ip6h->proto;
            } else {
                /*ext hdr*/
                pkt_info->proto = *(((uint8_t *)ip6h) + pkt_info->l3_len - 2);
            }
        } else {
            return -1;
        }
    } else {
        /*has inner tunnel*/
        pkt_info->l3_offset = lens.l2_len + lens.l3_len + lens.l4_len + lens.tunnel_len + lens.inner_l2_len;
        pkt_info->l3_len = lens.inner_l3_len;
        l4_types = m->packet_type & RTE_PTYPE_INNER_L4_MASK;
        pkt_info->is_frag = (RTE_PTYPE_INNER_L4_FRAG == l4_types) ? 1 : 0;

        l3_ptypes = m->packet_type & RTE_PTYPE_INNER_L3_MASK;

        if ((l3_ptypes == RTE_PTYPE_INNER_L3_IPV4) || (l3_ptypes == RTE_PTYPE_INNER_L3_IPV4_EXT)) {
            ip4h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv4_hdr), &ip4h_copy);

            pkt_info->proto = ip4h->next_proto_id;
            pkt_info->src_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->src_addr);
            pkt_info->dst_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->dst_addr);
            pkt_info->payload = (char *)ip4h + lens.inner_l3_len + lens.inner_l4_len;
            pkt_info->af = EN_QNSM_AF_IPv4;
        } else if ((l3_ptypes == RTE_PTYPE_INNER_L3_IPV6) || (l3_ptypes == RTE_PTYPE_INNER_L3_IPV6_EXT)) {
            ip6h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv6_hdr), &ip6h_copy);

            rte_memcpy(pkt_info->src_addr.in6_addr.s6_addr, ip6h->src_addr, IPV6_ADDR_LEN);
            rte_memcpy(pkt_info->dst_addr.in6_addr.s6_addr, ip6h->dst_addr, IPV6_ADDR_LEN);
            pkt_info->payload = (char *)ip6h + lens.inner_l3_len + lens.inner_l4_len;
            pkt_info->af = EN_QNSM_AF_IPv6;
            if (l3_ptypes == RTE_PTYPE_L3_IPV6) {
                pkt_info->proto = ip6h->proto;
            } else {
                pkt_info->proto = *(((uint8_t *)ip6h) + pkt_info->l3_len - 2);
            }
        } else {
            return -1;
        }
    }

    /*fill port*/
    switch (pkt_info->proto) {
        case TCP_PROTOCOL:
        case UDP_PROTOCOL: {
            uint16_t *ports = rte_pktmbuf_mtod_offset(m, uint16_t *, pkt_info->l3_offset + pkt_info->l3_len);
            pkt_info->sport = rte_be_to_cpu_16(ports[0]);
            pkt_info->dport = rte_be_to_cpu_16(ports[1]);
            break;
        }
        case ICMP_PROTOCOL:
            pkt_info->sport = 0;
            pkt_info->dport = 0;
        default: {
            break;
        }
    }
    return 0;
}

#endif

#if QNSM_PART("acl tbl")

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = PROTO_FIELD_IPV4,
        .input_index = 0,
        .offset = OFF_ETHHEAD +
        offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC_FIELD_IPV4,
        .input_index = 1,
        .offset = OFF_ETHHEAD +
        offsetof(struct ipv4_hdr, src_addr),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST_FIELD_IPV4,
        .input_index = 2,
        .offset = OFF_ETHHEAD +
        offsetof(struct ipv4_hdr, dst_addr),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = SRCP_FIELD_IPV4,
        .input_index = 3,
        .offset = sizeof(struct ether_hdr) +
        sizeof(struct ipv4_hdr) +
        offsetof(struct tcp_hdr, src_port),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = DSTP_FIELD_IPV4,
        .input_index = 3,
        .offset = sizeof(struct ether_hdr) +
        sizeof(struct ipv4_hdr) +
        offsetof(struct tcp_hdr, dst_port),
    },
};

struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = PROTO_FIELD_IPV6,
        .input_index = PROTO_FIELD_IPV6,
        .offset = OFF_ETHHEAD,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC1_FIELD_IPV6,
        .input_index = SRC1_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, src_addr)
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC2_FIELD_IPV6,
        .input_index = SRC2_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, src_addr) + sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC3_FIELD_IPV6,
        .input_index = SRC3_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, src_addr) + 2 * sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC4_FIELD_IPV6,
        .input_index = SRC4_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, src_addr) + 3 * sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST1_FIELD_IPV6,
        .input_index = DST1_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, dst_addr),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST2_FIELD_IPV6,
        .input_index = DST2_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, dst_addr) + sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST3_FIELD_IPV6,
        .input_index = DST3_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, dst_addr) + 2 * sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST4_FIELD_IPV6,
        .input_index = DST4_FIELD_IPV6,
        .offset = OFF_ETHHEAD + offsetof(struct ipv6_hdr, dst_addr) + 3 * sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = SRCP_FIELD_IPV6,
        .input_index = SRCP_FIELD_IPV6,
        .offset = OFF_ETHHEAD + sizeof(struct ipv6_hdr),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = DSTP_FIELD_IPV6,
        .input_index = SRCP_FIELD_IPV6,
        .offset = OFF_ETHHEAD + sizeof(struct ipv6_hdr) + sizeof(uint16_t),
    },
};

static void qnsm_sess_5tuple_acl_init(void)

{
    QNSM_ACL_TBL_PARA tbl_para;
    char name[32];
    void *tbl = NULL;

    /*ipv4 acl*/
    snprintf(name, sizeof(name), "5tuple_%u", rte_lcore_id());
    tbl_para.acl_tbl_para.name = name;
    tbl_para.acl_tbl_para.n_rules = QNSM_ACL_RULE_MAX_NUM;
    tbl_para.acl_tbl_para.n_rule_fields = RTE_DIM(ipv4_defs);
    memcpy(tbl_para.acl_tbl_para.field_format, ipv4_defs, sizeof(ipv4_defs));
    tbl = qnsm_acl_tbl_create(EN_QSNM_ACL_TBL_5TUPLE,
                              &tbl_para,
                              sizeof(QNSM_ACL_ENTRY));
    QNSM_ASSERT(tbl);

    /*ipv6 acl*/
    snprintf(name, sizeof(name), "5tuple_v6_%u", rte_lcore_id());
    tbl_para.acl_tbl_para.name = name;
    tbl_para.acl_tbl_para.n_rules = QNSM_ACL_RULE_MAX_NUM;
    tbl_para.acl_tbl_para.n_rule_fields = RTE_DIM(ipv6_defs);
    memcpy(tbl_para.acl_tbl_para.field_format, ipv6_defs, sizeof(ipv6_defs));
    tbl = qnsm_acl_tbl_create(EN_QSNM_ACL_TBL_IPv6_5TUPLE,
                              &tbl_para,
                              sizeof(QNSM_ACL_ENTRY));
    QNSM_ASSERT(tbl);

    QNSM_LOG(CRIT, "acl tbl init success\n");
    return;
}

#endif

/*__SESS_AGG macro support base sess agg info*/
#ifdef __DDOS

int32_t qnsm_sess_encap_agg_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    QNSM_SESS_AGG_MSG *sess_msg = NULL;
    QNSM_SESS_MSG_DATA *data = NULL;
    QNSM_SESS *sess = NULL;
    //uint32_t socket_id = rte_socket_id();

    if ((NULL == send_data) || (NULL == msg)) {
        return 0;
    }

    sess_msg = msg;
    data = send_data;
    sess = (QNSM_SESS *)data->sess;
    sess_msg->vip_is_src = sess->vip_is_src;
    sess_msg->af = sess->af;
    sess_msg->cus_ip = data->cus_ip;
    sess_msg->protocol = (EN_QNSM_AF_IPv4 == sess->af) ? sess->key.v4_5tuple.proto : sess->key.v6_5tuple.proto;
    rte_memcpy(&sess_msg->sess_addr, &sess->key, sizeof(QNSM_SESS_ADDR));
    rte_memcpy(&sess_msg->tcp_flags, sess->tcp_flags, sizeof(uint8_t) * 4);
    sess_msg->time_old = data->time_old;
    sess_msg->time_new = data->time_new;
    sess_msg->in_pps = sess->sess_statis[DIRECTION_IN].pps;
    sess_msg->in_bps = sess->sess_statis[DIRECTION_IN].bps;
    sess_msg->out_pps = sess->sess_statis[DIRECTION_OUT].pps;
    sess_msg->out_bps = sess->sess_statis[DIRECTION_OUT].bps;
    sess->tcp_flags[DIRECTION_IN] = 0;
    sess->tcp_flags[DIRECTION_OUT] = 0;
    sess->icmp_type[DIRECTION_IN] = 0;
    sess->icmp_type[DIRECTION_OUT] = 0;

    *msg_len = sizeof(QNSM_SESS_AGG_MSG);
    return 0;
}

static void qnsm_sess_send_agg_info(QNSM_SESS *sess, uint64_t time_old, uint64_t time_new, uint8_t cus_ip_agg_enable)
{
    QNSM_SESS_MSG_DATA msg_data;

    msg_data.sess = sess;
    msg_data.time_old = time_old;
    msg_data.time_new = time_new;

    //if (qnsm_get_sessm_conf()->care_biz)
    {
        switch (sess->af) {
            case EN_QNSM_AF_IPv4:
                if (sess->vip_is_src) {
                    msg_data.cus_ip.in4_addr.s_addr = sess->key.v4_5tuple.ip_dst;
                } else {
                    msg_data.cus_ip.in4_addr.s_addr = sess->key.v4_5tuple.ip_src;
                }
                break;
            case EN_QNSM_AF_IPv6:
                if (sess->vip_is_src) {
                    rte_memcpy(&msg_data.cus_ip.in6_addr, sess->key.v6_5tuple.ip_dst, IPV6_ADDR_LEN);
                } else {
                    rte_memcpy(&msg_data.cus_ip.in6_addr, sess->key.v6_5tuple.ip_src, IPV6_ADDR_LEN);
                }
                break;
            default:
                return;
        }

        /*send 5tuple agg data for cus ip statis agg*/
        if (cus_ip_agg_enable) {
            (void)qnsm_msg_send_lb(EN_QNSM_SIP_AGG,
                                   QNSM_MSG_SESS_AGG,
                                   &msg_data,
                                   msg_data.cus_ip.in4_addr.s_addr,
                                   0);
        }

        /*
        *send 5tuple agg data
        *stored sess data for event not detected
        */
        (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                               QNSM_MSG_SESS_AGG,
                               &msg_data,
                               msg_data.cus_ip.in4_addr.s_addr,
                               0);
    }
    return;
}

void qnsm_sess_agg(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_SESS *sess = (QNSM_SESS *)arg;

    uint32_t        send_agg_info = 0;
    uint16_t direction;
    QNSM_FLOW_STATISTICS            *statis_info = NULL;
    uint64_t interval = QNSM_SESS_STATIS_AGG_INTERVAL_SEC;
    uint64_t time_now = jiffies();
    uint8_t cus_ip_agg_enable = 0;

    send_agg_info = 0;

    /*__IDC diff deploy location/pdt type*/
#ifdef __DDOS
    if (NULL == sess->vip_item) {
        return;
    }
    cus_ip_agg_enable = ((QNSM_SESS_VIP_DATA *)sess->vip_item)->cus_ip_agg_enable;
#endif

    if (EN_QNSM_AF_IPv4 == sess->af) {
        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_WARN, "\n\nSESS INFO lcore %u protocol %8d  (%x %u %x %u)\n",
                   rte_lcore_id(),
                   sess->key.v4_5tuple.proto,
                   sess->key.v4_5tuple.ip_src,
                   sess->key.v4_5tuple.port_src,
                   sess->key.v4_5tuple.ip_dst,
                   sess->key.v4_5tuple.port_dst);
    }
    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_WARN, "DIRECTION\t\tPPS\t\t   BPS\n");

    for(direction = 0; direction < EN_QNSM_SESS_DIR_MAX; direction++) {
        statis_info = &(sess->sess_statis[direction]);

        /*
        *pps & bps
        *now actually use pkts * bits
        */
        statis_info->pps = statis_info->pkt_curr - statis_info->pkt_prev;
        statis_info->bps = statis_info->bit_curr - statis_info->bit_prev;
        statis_info->pkt_prev = statis_info->pkt_curr;
        statis_info->bit_prev = statis_info->bit_curr;

        if ((0 == statis_info->pps) && (0 == statis_info->bps)) {
            continue;
        }
        send_agg_info = 1;
        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_WARN, "%-8s \t\t%" PRIu64 "   %" PRIu64 "\n",
                   (direction == EN_QNSM_SESS_DIR_SAME) ? "IN" : "OUT",
                   sess->sess_statis[direction].pps,
                   sess->sess_statis[direction].bps);
    }

    if (send_agg_info) {
        qnsm_sess_send_agg_info(sess, time_now - interval, time_now, cus_ip_agg_enable);
    }

#ifdef __QNSM_STREAM_REASSEMBLE
    TCP_DATA *tmp_tcp_data = NULL;
    TCP_DATA *n = NULL;

    /*
    *free tcp reassemble mbufs
    * if reassemble mbuf num > 8, free
    */
    if (sess->data_que.data_cnt > 8) {
        qnsm_list_for_each_entry_safe(tmp_tcp_data, n, &sess->data_que.tcp_que, node) {
            rte_pktmbuf_free(tmp_tcp_data->pkt_info->mbuf);
            tcp_free_data(tmp_tcp_data);
        }
        sess->data_que.data_cnt = 0;
    }
#endif

    /*qnsm_all_tcp_conn not used now*/
    /*
    if ((TCP_PROTOCOL == proto) && (sess->tcp_stream))
    {
        qnsm_tcp_send_sess(sess->tcp_stream);
    }
    */
    return;
}
#endif

/*__FLOW_LIFE_STATTIS macro support verbose sess statis info*/
#ifdef __FLOW_LIFE_STATTIS
static int32_t qnsm_sess_life_encap_statis(void *msg, uint32_t *msg_len, void *send_data)
{
    QNSM_SESS_LIFE_STATIS_MSG *statis_msg = msg;
    QNSM_SESS *sess = send_data;

    statis_msg->af = sess->af;
    statis_msg->protocol = (EN_QNSM_AF_IPv4 == sess->af) ? sess->key.v4_5tuple.proto : sess->key.v6_5tuple.proto;
    rte_memcpy(&statis_msg->sess_addr, &sess->key, sizeof(QNSM_SESS_ADDR));
    statis_msg->time_begin = sess->begin_time;
    statis_msg->time_end = jiffies();
    statis_msg->in_pkts = sess->sess_statis[DIRECTION_IN].pkt_curr;
    statis_msg->in_bits = sess->sess_statis[DIRECTION_IN].bit_curr;
    statis_msg->out_pkts = sess->sess_statis[DIRECTION_OUT].pkt_curr;
    statis_msg->out_bits = sess->sess_statis[DIRECTION_OUT].bit_curr;

    if (NULL != sess->tcp_stream) {
        statis_msg->active_state = sess->tcp_stream->active.state;
        statis_msg->passive_state = sess->tcp_stream->passive.state;
        if (EN_QNSM_AF_IPv4 == sess->af) {
            /*host order*/
            statis_msg->active_ip.in4_addr.s_addr = sess->tcp_stream->addr.v4_5tuple.ip_src;
        } else {
            rte_memcpy(statis_msg->active_ip.in6_addr.s6_addr,
                       sess->tcp_stream->addr.v6_5tuple.ip_src, IPV6_ADDR_LEN);
        }
    }
    *msg_len = sizeof(QNSM_SESS_LIFE_STATIS_MSG);
    return 0;
}
#endif

void qnsm_sess_aging(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_SESS *sess = (QNSM_SESS*)arg;
    uint64_t cur_tick = 0;
    EN_QNSM_TBL_TYPE tbl_type = EN_QNSM_TBL_MAX;
    uint64_t hz = rte_get_timer_hz();
    uint8_t proto = 0xFF;

    if (EN_QNSM_AF_IPv4 == sess->af) {
        proto = sess->key.v4_5tuple.proto;
    } else {
        proto = sess->key.v6_5tuple.proto;
    }

    cur_tick = rte_rdtsc();
    if (get_diff_time(cur_tick, sess->last_tick) < ((QNSM_SESS_AGING_TIME -1) * hz)) {
        return;
    }

    switch (proto) {
        case TCP_PROTOCOL: {
            if (sess->tcp_stream) {
#ifdef __FLOW_LIFE_STATTIS
                (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                                       QNSM_MSG_SESS_LIFE_STATIS,
                                       sess,
                                       sess->af,
                                       1);
#endif
                tcp_check_timeouts((void **)&sess->tcp_stream);
            }
            break;
        }
        case UDP_PROTOCOL:
#ifdef __FLOW_LIFE_STATTIS
            if (sess->sess_statis[DIRECTION_IN].bit_curr
                && sess->sess_statis[DIRECTION_OUT].bit_curr) {
                (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                                       QNSM_MSG_SESS_LIFE_STATIS,
                                       sess,
                                       sess->af,
                                       0);
            }
#endif
            break;
        case ICMP_PROTOCOL:
            break;
        default:
            QNSM_ASSERT(0);
            return;
    }

#ifdef __QNSM_STREAM_REASSEMBLE
    TCP_DATA *tmp_tcp_data = NULL;
    TCP_DATA *n = NULL;

    /*free tcp data*/
    qnsm_list_for_each_entry_safe(tmp_tcp_data, n, &sess->data_que.tcp_que, node) {
        rte_pktmbuf_free(tmp_tcp_data->pkt_info->mbuf);
        tcp_free_data(tmp_tcp_data);
    }
    sess->data_que.data_cnt = 0;

    if (sess->app_parse_info) {
        qnsm_dpi_proto_free(sess->app_proto, sess->app_parse_info);
        sess->app_parse_info = NULL;
    }
#endif
#ifdef __DDOS
    (void)rte_timer_stop(&sess->agg_timer);
#endif
    (void)rte_timer_stop(&sess->aging_timer);

    if (EN_QNSM_AF_IPv4 == sess->af) {
        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_EVT, "del sess prot %d (%x %d %x %d)\n",
                   proto,
                   sess->key.v4_5tuple.ip_src,
                   sess->key.v4_5tuple.port_src,
                   sess->key.v4_5tuple.ip_dst,
                   sess->key.v4_5tuple.port_dst);
        tbl_type = EN_QNSM_IPV4_SESS;
    } else {
        tbl_type = EN_QNSM_IPV6_SESS;
    }
    (void)qnsm_del_tbl_item(tbl_type, sess);

    return;
}


#if QNSM_PART("qnsm session ops")

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
              uint32_t init_val)
{
    const union ipv4_5tuple_host *k;
    uint32_t t;
    const uint32_t *p;

    k = data;
    t = k->proto;
    p = (const uint32_t *)&k->port_src;

#ifdef QNSM_HASH_CRC
    init_val = rte_hash_crc_4byte(t, init_val);
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_4byte(*p, init_val);
#else
    init_val = rte_jhash_1word(t, init_val);
    init_val = rte_jhash_1word(k->ip_src, init_val);
    init_val = rte_jhash_1word(k->ip_dst, init_val);
    init_val = rte_jhash_1word(*p, init_val);
#endif

    return init_val;
}

static inline uint32_t
ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len,
              uint32_t init_val)
{
    const union ipv6_5tuple_host *k;
    uint32_t t;
    const uint32_t *p;
#ifdef QNSM_HASH_CRC
    const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
    const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif

    k = data;
    t = k->proto;
    p = (const uint32_t *)&k->port_src;

#ifdef QNSM_HASH_CRC
    ip_src0 = (const uint32_t *) k->ip_src;
    ip_src1 = (const uint32_t *)(k->ip_src+4);
    ip_src2 = (const uint32_t *)(k->ip_src+8);
    ip_src3 = (const uint32_t *)(k->ip_src+12);
    ip_dst0 = (const uint32_t *) k->ip_dst;
    ip_dst1 = (const uint32_t *)(k->ip_dst+4);
    ip_dst2 = (const uint32_t *)(k->ip_dst+8);
    ip_dst3 = (const uint32_t *)(k->ip_dst+12);
    init_val = rte_hash_crc_4byte(t, init_val);
    init_val = rte_hash_crc_4byte(*ip_src0, init_val);
    init_val = rte_hash_crc_4byte(*ip_src1, init_val);
    init_val = rte_hash_crc_4byte(*ip_src2, init_val);
    init_val = rte_hash_crc_4byte(*ip_src3, init_val);
    init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
    init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
    init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
    init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
    init_val = rte_hash_crc_4byte(*p, init_val);
#else
    init_val = rte_jhash_1word(t, init_val);
    init_val = rte_jhash(k->ip_src,
                         sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
    init_val = rte_jhash(k->ip_dst,
                         sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
    init_val = rte_jhash_1word(*p, init_val);
#endif
    return init_val;
}

inline QNSM_SESS* qnsm_sess_find(uint16_t af, QNSM_SESS_ADDR *key)
{
    QNSM_SESS *sess = NULL;

    switch (af) {
        case EN_QNSM_AF_IPv4:
            sess = qnsm_find_tbl_item(EN_QNSM_IPV4_SESS, (void *)key);
            break;
        case EN_QNSM_AF_IPv6:
            sess = qnsm_find_tbl_item(EN_QNSM_IPV6_SESS, (void *)key);
            break;
        default:
            QNSM_ASSERT(0);
            break;
    }
    return sess;
}

inline QNSM_SESS* qnsm_sess_add(int32_t lcore_id, uint16_t af, QNSM_SESS_ADDR *key)
{
    EN_QNSM_TBL_TYPE tbl_type = EN_QNSM_TBL_MAX;
    QNSM_SESS *sess = NULL;
    uint8_t normal_mode = 0;
    uint64_t aging_time = QNSM_SESS_AGING_TIME * rte_get_timer_hz();
    int32_t ret = 0;

    switch (af) {
        case EN_QNSM_AF_IPv4:
            tbl_type = EN_QNSM_IPV4_SESS;
            break;
        case EN_QNSM_AF_IPv6:
            tbl_type = EN_QNSM_IPV6_SESS;
            break;
        default:
            break;
    }

    sess = qnsm_add_tbl_item(tbl_type, (void *)key, &normal_mode);
    if (sess) {
#ifdef __DDOS
        /*sess agg timer init*/
        rte_timer_init(&sess->agg_timer);
        ret = rte_timer_reset(&sess->agg_timer,
                              QNSM_SESS_STATIS_AGG_INTERVAL_SEC * rte_get_timer_hz(), PERIODICAL,
                              lcore_id, qnsm_sess_agg, sess);
        if (ret) {
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_ERR,"Cannot set lcore %d agg timer\n", lcore_id);
            goto ERR_ADD;
        }

        /*
        if (sess->agg_timer.sl_next[0] == &sess->agg_timer)
        {
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_ERR, "exception");
        }
        */
#endif

        /*sess aging timer init*/
        if (0 == normal_mode) {
            aging_time = aging_time >> 1;
        }
        rte_timer_init(&sess->aging_timer);
        ret = rte_timer_reset(&sess->aging_timer,
                              aging_time, PERIODICAL,
                              lcore_id, qnsm_sess_aging, sess);
        if (ret) {
#ifdef __DDOS
            rte_timer_stop(&sess->agg_timer);
#endif
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_ERR,"Cannot set lcore %d aging timer\n", lcore_id);
            goto ERR_ADD;
        }

#ifdef __FLOW_LIFE_STATTIS
        sess->begin_time = jiffies();
#endif
        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_EVT, "add sess success\n");
    }
    return sess;

ERR_ADD:
    (void)qnsm_del_tbl_item(tbl_type, sess);
    return NULL;
}
#endif

inline void qnsm_sess_generate_key(QNSM_PACKET_INFO *pkt_info, QNSM_SESS_ADDR *key)
{
    uint16_t sport = pkt_info->sport;
    uint16_t dport = pkt_info->dport;

    if (EN_QNSM_AF_IPv4 == pkt_info->af) {
        /*v4
        *key store as net order
        *sess not associate with pkt direction
        */
        if (pkt_info->v4_src_ip < pkt_info->v4_dst_ip) {
            key->v4_5tuple.ip_src = pkt_info->v4_src_ip;
            key->v4_5tuple.port_src = sport;
            key->v4_5tuple.ip_dst = pkt_info->v4_dst_ip;
            key->v4_5tuple.port_dst = dport;
            pkt_info->sess_dir = EN_QNSM_SESS_DIR_SAME;
        } else if (pkt_info->v4_src_ip > pkt_info->v4_dst_ip) {
            key->v4_5tuple.ip_src = pkt_info->v4_dst_ip;
            key->v4_5tuple.port_src = dport;
            key->v4_5tuple.ip_dst = pkt_info->v4_src_ip;
            key->v4_5tuple.port_dst = sport;
            pkt_info->sess_dir = EN_QNSM_SESS_DIR_DIFF;
        } else if (sport < dport) {
            key->v4_5tuple.ip_src = pkt_info->v4_src_ip;
            key->v4_5tuple.port_src = sport;
            key->v4_5tuple.ip_dst = pkt_info->v4_dst_ip;
            key->v4_5tuple.port_dst = dport;
            pkt_info->sess_dir = EN_QNSM_SESS_DIR_SAME;
        } else {
            key->v4_5tuple.ip_src = pkt_info->v4_dst_ip;
            key->v4_5tuple.port_src = dport;
            key->v4_5tuple.ip_dst = pkt_info->v4_src_ip;
            key->v4_5tuple.port_dst = sport;
            pkt_info->sess_dir = EN_QNSM_SESS_DIR_DIFF;
        }
        key->v4_5tuple.proto = pkt_info->proto;
    } else {
        QNSM_ASSERT(EN_QNSM_AF_IPv6 == pkt_info->af);
        if (0 > memcmp(pkt_info->v6_src_ip, pkt_info->v6_dst_ip, IPV6_ADDR_LEN)) {
            rte_memcpy(key->v6_5tuple.ip_src, pkt_info->v6_src_ip, IPV6_ADDR_LEN);
            key->v6_5tuple.port_src = sport;
            rte_memcpy(key->v6_5tuple.ip_dst, pkt_info->v6_dst_ip, IPV6_ADDR_LEN);
            key->v6_5tuple.port_dst = dport;
            pkt_info->sess_dir = EN_QNSM_SESS_DIR_SAME;
        } else {
            rte_memcpy(key->v6_5tuple.ip_dst, pkt_info->v6_src_ip, IPV6_ADDR_LEN);
            key->v6_5tuple.port_dst = sport;
            rte_memcpy(key->v6_5tuple.ip_src, pkt_info->v6_dst_ip, IPV6_ADDR_LEN);
            key->v6_5tuple.port_src = dport;
            pkt_info->sess_dir = EN_QNSM_SESS_DIR_DIFF;
        }
        key->v6_5tuple.proto = pkt_info->proto;
    }
    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "sess (0x%x %u 0x%x %u)\n",
               pkt_info->v4_src_ip,
               sport,
               pkt_info->v4_dst_ip,
               dport);
    return;
}

int32_t  qnsm_sess_proc(QNSM_PACKET_INFO *pkt_info, int32_t lcore_id, struct rte_mbuf *mbuf, QNSM_SESS_VIP_DATA *vip_item)
{

    uint8_t          proto;
    uint64_t         pkt_len = 0;
    QNSM_SESS_ADDR sess_key;
    QNSM_SESS   *sess = NULL;
    void *app_arg = NULL;
    int32_t ret = 0;

    if (NULL == pkt_info) {
        ret = -1;
        goto EXIT;
    }

    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "enter\n");
    qnsm_sess_generate_key(pkt_info, &sess_key);
    sess = qnsm_sess_find(pkt_info->af, &sess_key);
    if (NULL == sess) {
        sess = qnsm_sess_add(lcore_id, pkt_info->af, &sess_key);

        if (NULL == sess) {
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_ERR, "failed\n");
            ret = -1;
            goto EXIT;
        }

        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "add new sess node %p\n", sess);
        sess->tcp_stream = NULL;
        sess->app_parse_info = NULL;
        sess->app_proto = EN_QNSM_DPI_PROTO_MAX;

        sess->af = pkt_info->af;

#ifdef    __QNSM_STREAM_REASSEMBLE
        /*init tcp stream que*/
        QNSM_INIT_LIST_HEAD(&sess->data_que.tcp_que);
        sess->data_que.data_cnt = 0;
        sess->data_que.tcp_seq[0] = 0;
        sess->data_que.tcp_seq[1] = 0;
#endif
        sess->vip_item = vip_item;
        sess->vip_is_src = pkt_info->direction ^ pkt_info->sess_dir;
    }

    /*update statis*/
    pkt_len = pkt_info->pkt_len;

    /* ¿¼ÂÇÖ¡¼ä¾à20×Ö½Ú */
    pkt_len += 20;
    sess->sess_statis[pkt_info->sess_dir].pkt_curr++;
    sess->sess_statis[pkt_info->sess_dir].bit_curr += pkt_len << 3;
    sess->last_tick = rte_rdtsc();

    proto = pkt_info->proto;
    switch (proto) {
        case TCP_PROTOCOL: {
#ifndef    __DDOS
            uint32_t tmp_seq[2];

            ret = tcp_conn_proc(pkt_info, sess, tmp_seq);
            if (ret) {
                break;
            }
            ret = -1;
#else

            struct tcp_hdr *this_tcphdr = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
            sess->tcp_flags[pkt_info->direction] |=  this_tcphdr->tcp_flags;
#ifdef __QNSM_STREAM_REASSEMBLE
            TCP_DATA *tcp_data = NULL;
            TCP_DATA *tmp = NULL;
            uint32_t tcp_seq = 0;
            uint32_t data_dir = 0;
            uint32_t *data_seq = NULL;
            uint32_t payload_len = pkt_info->pkt_len - (pkt_info->l3_offset +  pkt_info->l3_len + ((this_tcphdr->data_off >> 4) << 2));

            data_seq = sess->data_que.tcp_seq;
            ret = tcp_conn_proc(pkt_info, sess, data_seq);
            if (ret) {
                break;
            }
            if (EN_QNSM_DPI_PROTO_MAX == sess->app_proto) {
                ret = qnsm_dpi_match(pkt_info, EN_DPI_PROT_TCP, sess, &app_arg);
                if (0 > ret) {
                    break;
                }
                sess->app_proto = ret;
                sess->app_parse_info = app_arg;
            }

            ret = tcp_data_proc(pkt_info, &sess->data_que, pkt_info->sess_dir, payload_len);
            if (ret) {
                break;
            }

            qnsm_list_for_each_entry_safe(tcp_data, tmp, &sess->data_que.tcp_que, node) {
                data_dir = tcp_data->dir;
                tcp_seq = sess->data_que.tcp_seq[data_dir];

                /*
                * pkt len must > 0
                */
                if ((tcp_seq >= tcp_data->seq) && (tcp_seq < tcp_data->seq + tcp_data->len)) {
                    const int32_t offset = tcp_seq - tcp_data->seq;
                    const int len = tcp_data->len - offset;
                    if (len < 0) {
                        QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "!!data len exception!!\n");
                        rte_pktmbuf_free(tcp_data->pkt_info->mbuf);
                        tcp_free_data(tcp_data);
                        sess->data_que.data_cnt--;
                        continue;
                    }

                    (void)qnsm_dpi_prot_cbk(sess->app_proto, tcp_data->pkt_info, sess, sess->app_parse_info);
                    sess->data_que.tcp_seq[data_dir] += len;
                    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "(%p %u %p %u) dir %u seq: %u\n",
                               tcp_data->pkt_info->v4_src_ip,
                               tcp_data->pkt_info->sport,
                               tcp_data->pkt_info->v4_dst_ip,
                               tcp_data->pkt_info->dport,
                               tcp_data->dir,
                               sess->data_que.tcp_seq[data_dir]);

                    /*free resource*/
                    (void)qnsm_port_tx_lb((DIRECTION_IN == tcp_data->pkt_info->direction) ? (tcp_data->pkt_info->v4_dst_ip) : (tcp_data->pkt_info->v4_src_ip),
                                          tcp_free_data(tcp_data);
                                          sess->data_que.data_cnt--;
                                          QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "(%p %u %p %u) data_cnt %u sess %p\n\n",
                                                     tcp_data->pkt_info->v4_src_ip,
                                                     tcp_data->pkt_info->sport,
                                                     tcp_data->pkt_info->v4_dst_ip,
                                                     tcp_data->pkt_info->dport,
                                                     sess->data_que.data_cnt,
                                                     sess);
                }
            }
#else
            ret = -1;
#endif
#endif
            break;
        }
        case UDP_PROTOCOL: {
            QNSM_SESS_DATA *data = NULL;

            if (0 == pkt_info->dpi_policy) {
                ret = 1;
                break;
            }

            if (EN_QNSM_DPI_PROTO_MAX == sess->app_proto) {
                /*port app map*/
                data = qnsm_app_data(EN_QNSM_SESSM);
                pkt_info->dpi_app_prot = data->port_map[pkt_info->dport];
                if (EN_QNSM_DPI_PROTO_MAX != pkt_info->dpi_app_prot) {
                    sess->app_proto = pkt_info->dpi_app_prot;
                    ret = 1;
                    break;
                }
                pkt_info->dpi_app_prot = data->port_map[pkt_info->sport];
                if (EN_QNSM_DPI_PROTO_MAX != pkt_info->dpi_app_prot) {
                    sess->app_proto = pkt_info->dpi_app_prot;
                    ret = 1;
                    break;
                }

                /*
                *1. classfy pkt per sess
                *2. set vip agg pkt type per sess
                */
                ret = qnsm_dpi_match(pkt_info, EN_DPI_PROT_UDP, sess, &app_arg);
                if (0 <= ret) {
                    sess->app_proto = pkt_info->dpi_app_prot;
                    sess->app_parse_info = app_arg;
                }
            }

            if (EN_QNSM_DPI_PROTO_MAX > sess->app_proto) {
                /*
                 *1.parse app pkt
                 *2.set vip agg pkt type per pkt
                 */
                qnsm_dpi_prot_cbk(sess->app_proto, pkt_info, sess, sess->app_parse_info);

                pkt_info->dpi_app_prot = sess->app_proto;
            }
            ret = 1;
            break;
        }
        case ICMP_PROTOCOL: {
            struct icmp_hdr *hdr = rte_pktmbuf_mtod_offset(mbuf, struct icmp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
            sess->icmp_type[pkt_info->direction] = hdr->icmp_type;
            ret = 1;
            break;

        }
        default: {
            ret = 1;
        }
    }


EXIT:
    return ret;
}

void qnsm_sess_tbl_reg(EN_QNSM_APP lcore_type)
{
    uint32_t pool_size = 0;

    pool_size = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_SESSM) * QNSM_SESS_MAX;
    pool_size = (pool_size << 2) / 5;
    QNSM_TBL_PARA  ipv4_sess_para = {
        "V4_SESS",
        QNSM_SESS_MAX,
        pool_size,
        sizeof(QNSM_SESS),
        offsetof(QNSM_SESS, key),
        sizeof(union ipv4_5tuple_host),
        ipv4_hash_crc,
        NULL,
        EN_QNSM_SESSM,
        30,
    };
    QNSM_TBL_PARA   ipv6_sess_para = {
        "V6_SESS",
        QNSM_SESS_MAX,
        pool_size,
        sizeof(QNSM_SESS),
        offsetof(QNSM_SESS, key),
        sizeof(union ipv6_5tuple_host),
        ipv6_hash_crc,
        NULL,
        EN_QNSM_SESSM,
        30,
    };

    qnsm_tbl_para_reg(lcore_type, EN_QNSM_IPV4_SESS, (void *)&ipv4_sess_para);
    qnsm_tbl_para_reg(lcore_type, EN_QNSM_IPV6_SESS, (void *)&ipv6_sess_para);
    return;
}

void qnsm_rx_proc(void *this_app_data, uint32_t lcore_id, struct rte_mbuf *mbuf)
{
    QNSM_PACKET_INFO *pkt_info = NULL;
    uint32_t         pos = 0;
    int32_t ret = 0;
    uint32_t data_len;
    QNSM_SESS_VIP_DATA * vip_item = NULL;
    QNSM_SESS_DATA *app_data = this_app_data;

    pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);
    data_len = rte_pktmbuf_pkt_len(mbuf);

#ifdef __DDOS
    if (qnsm_parse_ptype(mbuf))
#else
    if (qnsm_decode_ethernet(pkt_info, rte_pktmbuf_mtod(mbuf, uint8_t *), data_len))
#endif
    {
        goto FREE;
    }

    /*get mbuf private data*/
    pkt_info->lcore_id = lcore_id;
    pkt_info->dpi_app_prot = EN_QNSM_DPI_PROTO_MAX;
    pkt_info->pkt_len = data_len;

#ifdef __DDOS
    struct qnsm_pkt_rslt *result = NULL;
    uint8_t          direction = DIRECTION_MAX;
    uint8_t session_enable = 0;

    if (1 != app_data->pkt_pass) {
        app_data->pkt_pass--;
    } else {
        session_enable = 1;
        app_data->pkt_pass = app_data->pkt_sample_rate;
    }

    /*
    *ip level
    *first get pkt direction
    */
    result = qnsm_inet_get_pkt_dire(this_app_data, pkt_info, &vip_item);
    if ((EN_QNSM_PKT_DROP == result->act) && (0 == session_enable)) {
        QNSM_SESS_INC_COUNTER(this_app_data, inner_pkt_counter);
        goto FREE;
    }

    QNSM_SESS_INC_COUNTER(this_app_data, outer_pkt_counter);
    direction = result->dir;
    if (vip_item) {
        if (vip_item->is_block_ip) {
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_EVT, "sessm block ip occured\n");
            goto FREE;
        }
        pos = vip_item->tx_pos;
    } else {
        pos = rte_hash_crc_4byte(pkt_info->v4_src_ip, 0);
    }

    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_PKT, "pkt len %d, direction %d\n", data_len, direction);
    if (DIRECTION_MAX == direction) {
        goto TX;
    }

    if (pkt_info->is_frag) {
        goto TX;
    }

    if (session_enable) {
        switch (pkt_info->proto) {
            case TCP_PROTOCOL:
            case UDP_PROTOCOL:
            case ICMP_PROTOCOL:
                ret = qnsm_sess_proc(pkt_info, lcore_id, mbuf, vip_item);
                break;
            default:
                ret = 1;
        }

        if (EN_QNSM_PKT_DROP == result->act) {
            goto FREE;
        }

        /*depends on sess dpi*/
        qnsm_inet_update_vip_sport_statis(vip_item, pkt_info);

        if (0 == ret) {
            return;
        }
    }

#else

    pos = mbuf->hash.rss;
    QNSM_SESS_INC_COUNTER(this_app_data, inner_pkt_counter);
    QNSM_SESS_ADD_COUNTER(this_app_data, bits, data_len);

    if (pkt_info->is_frag) {
        goto TX;
    }

    switch (pkt_info->proto) {
        case TCP_PROTOCOL:
        case UDP_PROTOCOL:
        case ICMP_PROTOCOL:
            ret = qnsm_sess_proc(pkt_info, lcore_id, mbuf, vip_item);
            break;
        default:
            ret = 1;
    }

    if (0 == ret) {
        return;
    }

#endif

TX:
    (void)qnsm_port_dup_tx_lb(rte_hash_crc_4byte(mbuf->hash.rss, 0), mbuf);

    if (pkt_info->need_dump) {
        qnsm_port_dump_tx(mbuf);
        pkt_info->need_dump = 0;
    }
    qnsm_port_tx_lb(pos,
                    mbuf);
    return;

FREE:
    rte_pktmbuf_free(mbuf);
    return;
}

void qnsm_sess_sample_init(QNSM_SESS_DATA *data)
{
    QNSM_SESSM_CFG *sess_cfg = qnsm_get_sessm_conf();

    data->pkt_sample_rate = 1;
    data->flow_sample_rate = 1;
    if (sess_cfg->sample_enable) {
        switch(sess_cfg->sample_method) {
            case EN_QNSM_PACKET_SAMPLE:
                data->pkt_sample_rate = sess_cfg->sample_rate;
                data->pkt_pass = data->pkt_sample_rate;
                break;
            case EN_QNSM_FLOW_SAMPLE:
                data->flow_sample_rate = sess_cfg->sample_rate;
                break;
            default:
                QNSM_ASSERT(0);
        }
    }
    return;
}

int32_t qnsm_sess_service_init(void)
{
    uint16_t lcore_id = 0;
    unsigned lcore = rte_lcore_id();
    EN_QNSM_APP *app_type = app_get_lcore_app_type(qnsm_service_get_cfg_para());
    int32_t ret = 0;
    QNSM_SESS_DATA *data = NULL;

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_SESS, QNSM_DBG_ALL);

    data = qnsm_app_inst_init(sizeof(QNSM_SESS_DATA),
                              qnsm_rx_proc,
                              NULL,
                              NULL);
    if (NULL == data) {
        QNSM_ASSERT(0);
    }

    /*app reg msg*/
    for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++) {
        if ((EN_QNSM_EDGE == app_type[lcore_id])
            || (EN_QNSM_SIP_AGG == app_type[lcore_id])
            || (EN_QNSM_MASTER == app_type[lcore_id])) {
            (void)qnsm_msg_subscribe(lcore_id);
        }
    }
    (void)qnsm_msg_publish();

    qnsm_msg_reg(QNSM_MSG_DPI_PROTO_INFO, NULL, qnsm_dpi_encap_dpi);
#ifdef __DDOS
    qnsm_msg_reg(QNSM_MSG_SESS_AGG, NULL, qnsm_sess_encap_agg_msg);
#endif
#ifdef __FLOW_LIFE_STATTIS
    (void)qnsm_msg_reg(QNSM_MSG_SESS_LIFE_STATIS, NULL, qnsm_sess_life_encap_statis);
#endif
    qnsm_msg_flush_timer_init();

    /*inet init*/
    qnsm_inet_vip_init(data);

    /*tbl reg*/
    qnsm_sess_tbl_reg(EN_QNSM_SESSM);
    ret = tcp_lcore_init(lcore, &data->tcp_data);

    /*sess acl*/
    qnsm_sess_5tuple_acl_init();

    /*common port app map init*/
    memset(data->port_map, EN_QNSM_DPI_PROTO_MAX, sizeof(data->port_map));
    data->port_map[6881] = EN_QNSM_DPI_BitTorrent;
    data->port_map[751] = EN_QNSM_DPI_P2P;
    data->port_map[1434] = EN_QNSM_DPI_MSSQL;
    data->port_map[5353] = EN_QNSM_DPI_MulticaseDNS;
    data->port_map[137] = EN_QNSM_DPI_NetBIOS;
    data->port_map[111] = EN_QNSM_DPI_Portmap;
    data->port_map[27960] = EN_QNSM_DPI_Quake;
    data->port_map[520] = EN_QNSM_DPI_RIPv1;
    data->port_map[27015] = EN_QNSM_DPI_STEAM;
    data->port_map[5683] = EN_QNSM_DPI_CoAP;

    /*dpi module reg*/
    http_init();
    dns_init();
    ntp_init();
    ssdp_init();
    memcached_reg();
    chargen_reg();
    qotd_reg();
    snmp_reg();
    cldap_reg();
    tftp_reg();

    EN_QNSM_DPI_PROTO proto = 0;
    for (proto = EN_QNSM_DPI_HTTP; proto < EN_QNSM_DPI_PROTO_MAX; proto++) {
        qnsm_dpi_proto_init(proto);

    }

    /*init sample*/
    qnsm_sess_sample_init(data);

    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);

#ifdef  DEBUG_QNSM
    qnsm_sess_statis_timer_init(data);
#endif
    return ret;
}


static void qnsm_sess_iter(void *cl, void *para, uint16_t lcore_id, EN_ITER_SESS_TYPE type, ITER_SESS_FUNC fun, void *fun_args)
{
    QNSM_SESS *sess = NULL;
    uint32_t iter = 0;
    void *iter_data = NULL;
    uint8_t proto = 0xFF;

    while(qnsm_cmd_iter_tbl(para, EN_QNSM_IPV4_SESS, (void **)&sess, &iter) >= 0) {
        switch (type) {
            case EN_ITER_SESS_STATIS: {
                break;
            }
            case EN_ITER_SESS_CONN:

            {
                iter_data = sess->tcp_stream;
                break;
            }
            case EN_ITER_SESS_DATA_QUE: {

#ifdef __QNSM_STREAM_REASSEMBLE
                iter_data = &sess->data_que;
#endif
                break;
            }

            case EN_ITER_SESS_ADDR: {
                iter_data = sess;
                break;

            }
            case EN_ITER_SESS_PROTO: {
                proto = sess->key.v4_5tuple.proto;
                iter_data = &proto;
            }
        }
        fun(cl, lcore_id, iter_data, fun_args);
    }
    return;
}

static void qnsm_sess_iter_v6(void *cl, void *para, uint16_t lcore_id, EN_ITER_SESS_TYPE type, ITER_SESS_FUNC fun, void *fun_args)
{
    QNSM_SESS *sess = NULL;
    uint32_t iter = 0;
    void *iter_data = NULL;

    while(qnsm_cmd_iter_tbl(para, EN_QNSM_IPV6_SESS, (void **)&sess, &iter) >= 0) {
        switch (type) {
            case EN_ITER_SESS_STATIS: {
                break;
            }
            case EN_ITER_SESS_CONN:

            {
                iter_data = sess->tcp_stream;
                break;
            }
            case EN_ITER_SESS_DATA_QUE: {

#ifdef __QNSM_STREAM_REASSEMBLE
                iter_data = &sess->data_que;
#endif
                break;
            }

            case EN_ITER_SESS_ADDR: {
                iter_data = sess;
                break;

            }
            case EN_ITER_SESS_PROTO: {
                iter_data = &sess->key.v6_5tuple.proto;
            }
        }
        fun(cl, lcore_id, iter_data, fun_args);
    }
    return;
}


#if QNSM_PART("cmd")

#if QNSM_PART("show sess cmd")

/*cmd show sess*/
struct cmd_show_sess_result {
    cmdline_fixed_string_t show_sess;
    cmdline_fixed_string_t show_sess_type;
};

static uint32_t show_sess_data_cnt;
static uint32_t show_sess_conn_cnt;
static uint32_t udp_sess_cnt;
static uint32_t tcp_sess_cnt;
static inline void cmd_show_sess_data_que(void *cl, uint32_t lcore_id, void *que, void *arg)
{
#ifdef __QNSM_STREAM_REASSEMBLE
    QNSM_TCP_DATA_QUE *data_que = que;
    if (data_que->data_cnt) {
        //cmdline_printf((struct cmdline *)cl, "data cnt %u\n", data_que->data_cnt);
        show_sess_data_cnt += data_que->data_cnt;
    }
#endif
    return;
}
static inline void cmd_show_sess_conn(void *cl, uint32_t lcore_id, void *conn, void *arg)
{
    if (conn) {
        show_sess_conn_cnt++;
    }
    return;
}

static void cmd_show_sess_proto(void *cl, uint32_t lcore_id, void *proto, void *arg)
{
    if (NULL == proto) {
        return;
    }
    switch (*(uint8_t *)proto) {
        case TCP_PROTOCOL: {
            tcp_sess_cnt++;
            break;
        }
        case UDP_PROTOCOL: {
            udp_sess_cnt++;
            break;
        }
        default:
            break;
    }
    return;
}

static void cmd_show_sess_parsed(void *parsed_result,
                                 __attribute__((unused)) struct cmdline *cl,
                                 __attribute__((unused)) void *data)
{
    struct cmd_show_sess_result *res = parsed_result;
    uint32_t p_id = 0;
    uint32_t lcore_id = 0;
    uint64_t prev_data_cnt = 0;
    uint64_t prev_cnt = 0;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;

    if (!strcmp(res->show_sess_type, "type")) {
        uint64_t prev_tcp_cnt = 0;
        uint64_t prev_udp_cnt = 0;

        tcp_sess_cnt = 0;
        udp_sess_cnt = 0;
        for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
            if (EN_QNSM_SESSM == app_paras->pipeline_params[p_id].app_type) {
                pipeline_para = &app_paras->pipeline_params[p_id];
                lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                     pipeline_para->socket_id,
                                                     pipeline_para->core_id,
                                                     pipeline_para->hyper_th_id);

                prev_tcp_cnt = tcp_sess_cnt;
                prev_udp_cnt = udp_sess_cnt;
                qnsm_sess_iter(cl, pipeline_para, lcore_id, EN_ITER_SESS_PROTO, cmd_show_sess_proto, NULL);
                cmdline_printf(cl, "lcore %u tcp_sess(v4) %" PRIu64 " udp_sess %" PRIu64 "\n",
                               lcore_id,
                               tcp_sess_cnt - prev_tcp_cnt,
                               udp_sess_cnt - prev_udp_cnt);

                prev_tcp_cnt = tcp_sess_cnt;
                prev_udp_cnt = udp_sess_cnt;
                qnsm_sess_iter_v6(cl, pipeline_para, lcore_id, EN_ITER_SESS_PROTO, cmd_show_sess_proto, NULL);
                cmdline_printf(cl, "lcore %u tcp_sess(v6) %" PRIu64 "udp_sess %" PRIu64 "\n",
                               lcore_id,
                               tcp_sess_cnt - prev_tcp_cnt,
                               udp_sess_cnt - prev_udp_cnt);

#ifdef  DEBUG_QNSM
                QNSM_SESS_DATA *this = NULL;

                /*inner & outer pkts counter*/
                this = qnsm_cmd_app_data(pipeline_para, EN_QNSM_SESSM);
                cmdline_printf(cl, "lcore %u inner pkts %" PRIu64 " outer pkts %" PRIu64
                               " filter pkts %" PRIu64 "bits %" PRIu64 " pps %" PRIu64 " bps %" PRIu64 "\n",
                               lcore_id,
                               this->inner_pkt_counter,
                               this->outer_pkt_counter,
                               this->filter_pkt_counter,
                               this->bits,
                               this->pps,
                               this->bps);
#endif
            }
        }
        cmdline_printf(cl, "total sess num %u\n", tcp_sess_cnt + udp_sess_cnt);
    }

    if (!strcmp(res->show_sess_type, "conn")) {
        show_sess_conn_cnt = 0;
        for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
            if (EN_QNSM_SESSM == app_paras->pipeline_params[p_id].app_type) {
                pipeline_para = &app_paras->pipeline_params[p_id];
                lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                     pipeline_para->socket_id,
                                                     pipeline_para->core_id,
                                                     pipeline_para->hyper_th_id);

                prev_cnt = show_sess_conn_cnt;
                qnsm_sess_iter(cl, pipeline_para, lcore_id, EN_ITER_SESS_CONN, cmd_show_sess_conn, NULL);
                cmdline_printf(cl, "lcore %u conn(v4) %" PRIu64 "\n", lcore_id, show_sess_conn_cnt - prev_cnt);

                prev_cnt = show_sess_conn_cnt;
                qnsm_sess_iter_v6(cl, pipeline_para, lcore_id, EN_ITER_SESS_CONN, cmd_show_sess_conn, NULL);
                cmdline_printf(cl, "lcore %u conn(v6) %" PRIu64 "\n", lcore_id, show_sess_conn_cnt - prev_cnt);
            }
        }
        cmdline_printf(cl, "total tcp conn %u\n", show_sess_conn_cnt);
    }

    if (!strcmp(res->show_sess_type, "reassemble_que")) {
        show_sess_data_cnt = 0;
        for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
            if (EN_QNSM_SESSM == app_paras->pipeline_params[p_id].app_type) {
                pipeline_para = &app_paras->pipeline_params[p_id];
                lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                     pipeline_para->socket_id,
                                                     pipeline_para->core_id,
                                                     pipeline_para->hyper_th_id);

                prev_data_cnt = show_sess_data_cnt;
                qnsm_sess_iter(cl, pipeline_para, lcore_id, EN_ITER_SESS_DATA_QUE, cmd_show_sess_data_que, NULL);
                cmdline_printf(cl, "lcore %u reassemble(v4) pkt %" PRIu64 "\n",
                               lcore_id, show_sess_data_cnt - prev_data_cnt);

                prev_data_cnt = show_sess_data_cnt;
                qnsm_sess_iter_v6(cl, pipeline_para, lcore_id, EN_ITER_SESS_DATA_QUE, cmd_show_sess_data_que, NULL);
                cmdline_printf(cl, "lcore %u reassemble(v6) pkt %" PRIu64 "\n",
                               lcore_id, show_sess_data_cnt - prev_data_cnt);
            }
        }
        cmdline_printf(cl, "total reassemble pkt cnt %u\n",show_sess_data_cnt);
    }

    return;
}

cmdline_parse_token_string_t cmd_show_sess_string =
    TOKEN_STRING_INITIALIZER(struct cmd_show_sess_result, show_sess,
                             "show_sess");
cmdline_parse_token_string_t cmd_show_sess_type =
    TOKEN_STRING_INITIALIZER(struct cmd_show_sess_result, show_sess_type,
                             "type#conn#reassemble_que");

cmdline_parse_inst_t cmd_show_sess = {
    .f = cmd_show_sess_parsed,
    .data = NULL,
    .help_str = "Show sess.",
    .tokens = {
        (void *)&cmd_show_sess_string,
        (void *)&cmd_show_sess_type,
        NULL,
    },
};
#endif

/*cmd show ip flow*/
uint32_t show_sess_lcore_cnt[APP_MAX_LCORES];

struct cmd_show_ip_flow_result {
    cmdline_fixed_string_t show_ip_flow;
    cmdline_ipaddr_t ip;
};

void cmd_show_sess_addr(void *cl, uint32_t lcore_id, void *iter_data, void *arg)
{
    QNSM_SESS *sess = NULL;
    cmdline_ipaddr_t *ip_addr = arg;
    TCP_STREAM *tcp_stream = NULL;

    if (iter_data) {
        sess = iter_data;
        switch (ip_addr->family) {
            case AF_INET:
                if ((sess->key.v4_5tuple.ip_src == ntohl(ip_addr->addr.ipv4.s_addr))
                    || (sess->key.v4_5tuple.ip_dst == ntohl(ip_addr->addr.ipv4.s_addr))) {
                    show_sess_lcore_cnt[lcore_id]++;
                    cmdline_printf(cl, "lcore %u sess %p (%u %x, %u, %x, %u)\n",
                                   lcore_id,
                                   sess,
                                   sess->key.v4_5tuple.proto,
                                   sess->key.v4_5tuple.ip_src,
                                   sess->key.v4_5tuple.port_src,
                                   sess->key.v4_5tuple.ip_dst,
                                   sess->key.v4_5tuple.port_dst);

                    if (sess->tcp_stream) {
                        tcp_stream = sess->tcp_stream;
                        cmdline_printf(cl, "passive state %d active state %d\n",
                                       tcp_stream->passive.state,
                                       tcp_stream->active.state);
                    }
                    cmdline_printf(cl, "==IN pps %" PRIu64 " bps %" PRIu64 "==\n",
                                   sess->sess_statis[DIRECTION_IN].pps,
                                   sess->sess_statis[DIRECTION_IN].bps);
                    cmdline_printf(cl, "==OUT pps %" PRIu64 " bps %" PRIu64 "==\n",
                                   sess->sess_statis[DIRECTION_OUT].pps,
                                   sess->sess_statis[DIRECTION_OUT].bps);
                }
                break;
            case AF_INET6:
                show_sess_lcore_cnt[lcore_id]++;
                break;
            default:
                return;
        }
    }
    return;
}


static void cmd_show_flow_ip_parsed(void *parsed_result,
                                    __attribute__((unused)) struct cmdline *cl,
                                    __attribute__((unused)) void *data)
{
    uint32_t lcore_id = 0;
    uint32_t p_id = 0;
    struct cmd_show_ip_flow_result *show_ip = (struct cmd_show_ip_flow_result *)parsed_result;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;
    char tmp[128];

    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (EN_QNSM_SESSM == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            lcore_id = cpu_core_map_get_lcore_id(app_paras->core_map,
                                                 pipeline_para->socket_id,
                                                 pipeline_para->core_id,
                                                 pipeline_para->hyper_th_id);
            show_sess_lcore_cnt[lcore_id] = 0;
            switch (show_ip->ip.family) {
                case AF_INET:
                    qnsm_sess_iter(cl, pipeline_para, lcore_id, EN_ITER_SESS_ADDR, cmd_show_sess_addr, (void *)&show_ip->ip);
                    (void)inet_ntop(AF_INET, &show_ip->ip.addr, tmp, sizeof(tmp));
                    cmdline_printf(cl, "v4 lcore %u include ip %s cnt %u\n\n", lcore_id, tmp, show_sess_lcore_cnt[lcore_id]);
                    break;
                case AF_INET6:
                    qnsm_sess_iter_v6(cl, pipeline_para, lcore_id, EN_ITER_SESS_ADDR, cmd_show_sess_addr, (void *)&show_ip->ip);
                    (void)inet_ntop(AF_INET6, &show_ip->ip.addr, tmp, sizeof(tmp));
                    cmdline_printf(cl, "v6 lcore %u include ip %s cnt %u\n\n", lcore_id, tmp, show_sess_lcore_cnt[lcore_id]);
                    break;
            }
        }
    }

    return;
}

cmdline_parse_token_string_t cmd_show_ip_flow_string =
    TOKEN_STRING_INITIALIZER(struct cmd_show_ip_flow_result, show_ip_flow,
                             "show_sess");
cmdline_parse_token_ipaddr_t cmd_show_ip_flow_ip =
    TOKEN_IPADDR_INITIALIZER(struct cmd_show_ip_flow_result, ip);

cmdline_parse_inst_t cmd_show_flow_ip = {
    .f = cmd_show_flow_ip_parsed,
    .data = NULL,
    .help_str = "Show sess include ip(x.x.x.x).",
    .tokens = {
        (void *)&cmd_show_ip_flow_string,
        (void *)&cmd_show_ip_flow_ip,
        NULL,
    },
};

#endif


