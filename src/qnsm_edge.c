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

#include "cJSON.h"
#include "util.h"
#include "bsb.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_service_ex.h"
#include "qnsm_msg_ex.h"
#include "qnsm_ip_agg.h"
#include "qnsm_session_ex.h"
#include "qnsm_edge_ex.h"

static const char *qnsm_pkt_type[] = {
#define XX(num, name, string) #string,
    QNSM_PKT_TYPES_MAP(XX)
#undef XX
    0
};

typedef struct {
    uint64_t time_stamp;
    uint8_t group_valid[QNSM_MAX_SVR_GROUP_NUM];
} __rte_cache_aligned QNSM_EDGE;

#ifdef __FLOW_LIFE_STATTIS
int32_t qnsm_sess_statis_msg_proc(void *data, uint32_t data_len)
{
    QNSM_SESS_LIFE_STATIS_MSG *sess_msg = NULL;
    cJSON *root = NULL;
    cJSON *js_data = NULL;
    char *proto = NULL;
    char  tmp[128];
    uint32_t size =  sizeof(tmp);
    struct in_addr ip_addr;
    void *addr;
    EN_QNSM_KAFKA_TOPIC topic = 0;
    static const char *tcp_state[] = {
        "NON-TRACKED",
#define XX(num, name, string) #string,
        QNSM_TCP_STATE_MAP(XX)
#undef XX
        0
    };

    QNSM_ASSERT(data);
    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "decap len %u\n", data_len);

    //cjson_time_beg = rte_get_tsc_cycles();
    sess_msg = data;
    switch (sess_msg->protocol) {
        case TCP_PROTOCOL:
            proto = "TCP";
            topic = QNSM_KAFKA_TCP_SESS_AGG_TOPIC;
            break;
        case UDP_PROTOCOL:
            proto = "UDP";
            topic = QNSM_KAFKA_UDP_SESS_AGG_TOPIC;
            break;
        default:
            return 0;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "metric", "flow");
    cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);

    cJSON_AddStringToObject(root, "protocol", proto);

    cJSON *js_statis = NULL;
    cJSON_AddNumberToObject(root, "from_time", sess_msg->time_begin);
    cJSON_AddNumberToObject(root, "to_time", sess_msg->time_end);
    cJSON_AddItemToObject(root,"data", js_data = cJSON_CreateArray());

    cJSON_AddItemToArray(js_data, js_statis = cJSON_CreateObject());
    if (EN_QNSM_AF_IPv4 == sess_msg->af) {
        ip_addr.s_addr = htonl(sess_msg->sess_addr.v4_5tuple.ip_src);
        addr = &ip_addr;
        (void)inet_ntop(AF_INET, addr, tmp, size);
    } else {
        addr = sess_msg->sess_addr.v6_5tuple.ip_src;
        (void)inet_ntop(AF_INET6, addr, tmp, size);
    }
    cJSON_AddStringToObject(js_statis,"src_ip", tmp);
    cJSON_AddNumberToObject(js_statis, "src_port", sess_msg->sess_addr.v4_5tuple.port_src);
    if (EN_QNSM_AF_IPv4 == sess_msg->af) {
        ip_addr.s_addr = htonl(sess_msg->sess_addr.v4_5tuple.ip_dst);
        addr = &ip_addr;
        (void)inet_ntop(AF_INET, addr, tmp, size);
    } else {
        addr = sess_msg->sess_addr.v6_5tuple.ip_dst;
        (void)inet_ntop(AF_INET6, addr, tmp, size);
    }
    cJSON_AddStringToObject(js_statis,"dst_ip", tmp);
    cJSON_AddNumberToObject(js_statis, "dst_port", sess_msg->sess_addr.v4_5tuple.port_dst);
    cJSON_AddNumberToObject(js_statis, "pkts", sess_msg->in_pkts);
    cJSON_AddNumberToObject(js_statis, "bits", sess_msg->in_bits);

    cJSON_AddItemToArray(js_data, js_statis = cJSON_CreateObject());
    cJSON_AddStringToObject(js_statis,"src_ip", tmp);
    cJSON_AddNumberToObject(js_statis, "src_port", sess_msg->sess_addr.v4_5tuple.port_dst);
    if (EN_QNSM_AF_IPv4 == sess_msg->af) {
        ip_addr.s_addr = htonl(sess_msg->sess_addr.v4_5tuple.ip_src);
        addr = &ip_addr;
        (void)inet_ntop(AF_INET, addr, tmp, size);
    } else {
        addr = sess_msg->sess_addr.v6_5tuple.ip_src;
        (void)inet_ntop(AF_INET6, addr, tmp, size);
    }
    cJSON_AddStringToObject(js_statis,"dst_ip", tmp);
    cJSON_AddNumberToObject(js_statis, "dst_port", sess_msg->sess_addr.v4_5tuple.port_src);
    cJSON_AddNumberToObject(js_statis, "pkts", sess_msg->out_pkts);
    cJSON_AddNumberToObject(js_statis, "bits", sess_msg->out_bits);

    if (TCP_PROTOCOL == sess_msg->protocol) {
        cJSON_AddStringToObject(root, "active_state", tcp_state[sess_msg->active_state]);
        cJSON_AddStringToObject(root, "passive_state", tcp_state[sess_msg->passive_state]);

        if (EN_QNSM_AF_IPv4 == sess_msg->af) {
            ip_addr.s_addr = htonl(sess_msg->active_ip.in4_addr.s_addr);
            addr = &ip_addr;
            (void)inet_ntop(AF_INET, addr, tmp, size);
        } else {
            addr = sess_msg->active_ip.in6_addr.s6_addr;
            (void)inet_ntop(AF_INET6, addr, tmp, size);
        }
        cJSON_AddStringToObject(root, "active_ip", tmp);
    }

    qnsm_kafka_send_msg(topic, root, sess_msg->sess_addr.v4_5tuple.ip_src);
    return 0;
}
#endif

int32_t qnsm_cus_ip_agg_msg_proc(void *data, uint32_t data_len)
{
    QNSM_CUS_IP_AGG_MSG *agg_msg = data;
    cJSON *root = NULL;
    cJSON *js_data = NULL;
    cJSON *js_statis = NULL;
    char  tmp[128];
    struct in_addr ip_addr;
    BSB cus_bsb;
    uint8_t *buf = NULL;
    uint32_t len = sizeof(QNSM_CUS_VIP_STATISTICS) * EN_CUS_IP_PROT_MAX * DIRECTION_MAX;
    QNSM_IN_ADDR addr;

    QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_INFO, "enter\n");

    root = cJSON_CreateObject();
    if (EN_QNSM_AF_IPv4 == agg_msg->af) {
        ip_addr.s_addr = rte_cpu_to_be_32(agg_msg->key.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, sizeof(tmp));
    } else {
        (void)inet_ntop(AF_INET6, &agg_msg->key.in6_addr, tmp, sizeof(tmp));
    }

    QNSM_LOG(INFO, "[ EDGE ] rcv sip %s\n", tmp);
    cJSON_AddStringToObject(root,"ip", tmp);
    cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);
    cJSON_AddStringToObject(root, "metric", "sip_in");
    cJSON_AddNumberToObject(root, "time", agg_msg->time);

    cJSON_AddItemToObject(root, "data", js_data = cJSON_CreateArray());
    BSB_INIT(cus_bsb, (agg_msg + 1), (data_len - sizeof(QNSM_CUS_IP_AGG_MSG)));
    while (BSB_REMAINING(cus_bsb)) {
        BSB_LIMPORT_skip(cus_bsb, (sizeof(QNSM_IN_ADDR) + len));
        if (BSB_IS_ERROR(cus_bsb)) {
            //BSB_LIMPORT_rewind(cus_bsb, (sizeof(QNSM_IN_ADDR) + len));
            break;
        }
        BSB_LIMPORT_rewind(cus_bsb, (sizeof(QNSM_IN_ADDR) + len));

        cJSON_AddItemToArray(js_data, js_statis = cJSON_CreateObject());

        BSB_IMPORT_byte(cus_bsb, &addr, sizeof(QNSM_IN_ADDR));
        if (EN_QNSM_AF_IPv4 == agg_msg->af) {
            addr.in4_addr.s_addr = rte_cpu_to_be_32(addr.in4_addr.s_addr);
            (void)inet_ntop(AF_INET, &addr, tmp, sizeof(tmp));
        } else {
            (void)inet_ntop(AF_INET6, &addr, tmp, sizeof(tmp));
        }
        cJSON_AddStringToObject(js_statis,"vip", tmp);

        buf = BSB_WORK_PTR(cus_bsb);
        cJSON_AddNumberToObject(js_statis, "tcp_pps_in", *(uint64_t *)buf);
        buf += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "tcp_bps_in", *(uint64_t *)buf);
        buf += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "tcp_pps_out", *(uint64_t *)buf);
        buf += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "tcp_bps_out", *(uint64_t *)buf);
        buf += sizeof(uint64_t);

        cJSON_AddNumberToObject(js_statis, "udp_pps_in", *(uint64_t *)buf);
        buf += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "udp_bps_in", *(uint64_t *)buf);
        buf += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "udp_pps_out", *(uint64_t *)buf);
        buf += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "udp_bps_out", *(uint64_t *)buf);
        //buf += sizeof(uint64_t);
        BSB_LIMPORT_skip(cus_bsb, len);
    }

    qnsm_kafka_send_msg(QNSM_KAFKA_SIP_IN_AGG_TOPIC, root, agg_msg->key.in4_addr.s_addr);
    QNSM_DEBUG(QNSM_DBG_M_CUSTOM_IPAGG, QNSM_DBG_INFO, "leave\n");
    return 0;
}

int32_t qnsm_svr_host_agg_msg_proc(void *data, uint32_t data_len)
{
    cJSON *root = NULL;
    cJSON *js_data = NULL;
    cJSON *js_statis = NULL;
    char  tmp[128];
    struct in_addr ip_addr;
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint64_t time = 0;
    uint16_t group_id = 0;
    QNSM_SVR_IP_GROUP *group = NULL;
    enum en_qnsm_detect pkt_type;
    QNSM_SRV_HOST *host = NULL;
    uint32_t ip = 0;
    uint16_t af = 0;
    uint16_t pos = 0;

    buf = data;
    host = (QNSM_SRV_HOST *)buf;
    af = *(uint16_t *)(host + 1);

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_INFO, "enter\n");
    root = cJSON_CreateObject();
    if (EN_QNSM_AF_IPv4 == af) {
        pos = (uint16_t)host->addr.in4_addr.s_addr;
        ip = host->addr.in4_addr.s_addr;
        ip_addr.s_addr = rte_cpu_to_be_32(ip);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, sizeof(tmp));
    } else {
        pos = host->addr.in6_addr.s6_addr16[7];
        (void)inet_ntop(AF_INET6, &host->addr.in6_addr, tmp, sizeof(tmp));
    }
    len += sizeof(QNSM_SRV_HOST);
    cJSON_AddStringToObject(root,"ip", tmp);

    group_id = 0;
    len += sizeof(uint16_t);
    group = qnsm_get_group(group_id);
    cJSON_AddStringToObject(root, "biz_name", group ? group->name : "");

    cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);
    cJSON_AddStringToObject(root, "metric", "dip_traffic");
    time = *(uint64_t *)(buf + len);
    len += sizeof(uint64_t);
    cJSON_AddNumberToObject(root, "from_time", time - INTVAL);
    cJSON_AddNumberToObject(root, "to_time", time);

    cJSON_AddItemToObject(root,"data", js_data = cJSON_CreateArray());
    while (len < data_len) {
        cJSON_AddItemToArray(js_data, js_statis = cJSON_CreateObject());
        pkt_type = *(uint32_t *)(buf + len);
        len += sizeof(uint32_t);
        cJSON_AddStringToObject(js_statis, "type", qnsm_pkt_type[pkt_type]);
        cJSON_AddNumberToObject(js_statis, "pps_in", *(uint64_t *)(buf + len));
        len += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "bps_in", *(uint64_t *)(buf + len));
        len += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "pps_out", *(uint64_t *)(buf + len));
        len += sizeof(uint64_t);
        cJSON_AddNumberToObject(js_statis, "bps_out", *(uint64_t *)(buf + len));
        len += sizeof(uint64_t);
    }

    /*root node free later after batch send*/
    qnsm_kafka_send_msg(QNSM_KAFKA_VIP_AGG_TOPIC, root, pos);
    return 0;
}

int32_t qnsm_vip_port_msg_proc(void *data, uint32_t data_len)
{
    cJSON *root = NULL;
    cJSON *js_data = NULL;
    cJSON *js_statis = NULL;
    char  tmp[128];
    struct in_addr ip_addr;
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint64_t time;
    enum qnsm_port_type type;
    uint32_t index = 0;
    uint32_t num = 0;
    QNSM_PORT_STATIS *port_statis = NULL;
    uint32_t af = 0;
    QNSM_SRV_HOST *host = NULL;
    uint16_t pos = 0;

    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_INFO, "enter\n");
    buf = data;
    root = cJSON_CreateObject();
    af = *(uint32_t *)(buf + len);
    len += sizeof(uint32_t);

    host = (QNSM_SRV_HOST *)(buf + len);
    if (EN_QNSM_AF_IPv4 == af) {
        pos = (uint16_t)host->addr.in4_addr.s_addr;
        ip_addr.s_addr = rte_cpu_to_be_32(host->addr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, sizeof(tmp));
    } else {
        pos = host->addr.in6_addr.s6_addr16[7];
        (void)inet_ntop(AF_INET6, &host->addr.in6_addr, tmp, sizeof(tmp));
    }
    len += sizeof(QNSM_SRV_HOST);
    cJSON_AddStringToObject(root, "ip", tmp);
    cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);

    time = *(uint64_t *)(buf + len);
    len += sizeof(uint64_t);
    cJSON_AddNumberToObject(root, "time", time);

    type = *(uint64_t *)(buf + len);
    len += sizeof(uint64_t);
    cJSON_AddStringToObject(root, "metric", (EN_QNSM_SRC_PORT == type) ? "sport" : "dport");
    num = *(uint64_t *)(buf + len);
    len += sizeof(uint64_t);

    cJSON_AddItemToObject(root,"data", js_data = cJSON_CreateArray());
    port_statis = (QNSM_PORT_STATIS *)(buf + len);
    for (index = 0; index < num ; index++) {
        cJSON_AddItemToArray(js_data, js_statis = cJSON_CreateObject());
        cJSON_AddNumberToObject(js_statis, "port_id", port_statis[index].port_id);
        cJSON_AddNumberToObject(js_statis, "pkts", port_statis[index].intval_pkts);
        cJSON_AddNumberToObject(js_statis, "bits", port_statis[index].intval_bits);
    }

    /*send kafka msg*/
    if (EN_QNSM_SRC_PORT == type) {
        qnsm_kafka_send_msg(QNSM_KAFKA_VIP_SPORT_TOPIC, root, pos);
    } else {
        qnsm_kafka_send_msg(QNSM_KAFKA_VIP_DPORT_TOPIC, root, pos);
    }
    if (root) {
        cJSON_Delete(root);
    }
    return 0;
}

#ifdef __DDOS
static int32_t qnsm_5tuple_msg_proc(void *data, uint32_t data_len)
{
    QNSM_SESS_AGG_MSG *sess_msg = NULL;
    cJSON *root = NULL;
    char  src_tmp[128];
    char  dst_tmp[128];
    struct in_addr ip_addr;
    void *addr;
    uint16_t port[2] = {0};
    uint8_t ip_ver;

    QNSM_ASSERT(data);
    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO, "decap len %u\n", data_len);

    sess_msg = data;
    if (EN_QNSM_AF_IPv4 == sess_msg->af) {
        ip_addr.s_addr = htonl(sess_msg->sess_addr.v4_5tuple.ip_src);
        addr = &ip_addr;
        (void)inet_ntop(AF_INET, addr, src_tmp, sizeof(src_tmp));

        ip_addr.s_addr = htonl(sess_msg->sess_addr.v4_5tuple.ip_dst);
        addr = &ip_addr;
        (void)inet_ntop(AF_INET, addr, dst_tmp, sizeof(dst_tmp));
        port[0] = sess_msg->sess_addr.v4_5tuple.port_src;
        port[1] = sess_msg->sess_addr.v4_5tuple.port_dst;
        ip_ver = 4;
    } else {
        addr = sess_msg->sess_addr.v6_5tuple.ip_src;
        (void)inet_ntop(AF_INET6, addr, src_tmp, sizeof(src_tmp));

        addr = sess_msg->sess_addr.v6_5tuple.ip_dst;
        (void)inet_ntop(AF_INET6, addr, dst_tmp, sizeof(dst_tmp));
        port[0] = sess_msg->sess_addr.v6_5tuple.port_src;
        port[1] = sess_msg->sess_addr.v6_5tuple.port_dst;
        ip_ver = 6;
    }

    /*in statis*/
    if (0 < sess_msg->in_pps) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);
        cJSON_AddNumberToObject(root, "sampling_interval", qnsm_get_sessm_conf()->sample_rate);
        cJSON_AddNumberToObject(root, "timestamp", sess_msg->time_old);
        cJSON_AddNumberToObject(root, "ip_protocol", sess_msg->protocol);
        cJSON_AddNumberToObject(root, "ip_version", ip_ver);
        cJSON_AddStringToObject(root,"src_ip", src_tmp);
        cJSON_AddNumberToObject(root, "src_port", port[0]);
        cJSON_AddStringToObject(root,"dst_ip", dst_tmp);
        cJSON_AddNumberToObject(root, "dst_port", port[1]);

        cJSON_AddNumberToObject(root, "direction", 0);
        cJSON_AddNumberToObject(root, "tcp_flags", sess_msg->tcp_flags[DIRECTION_IN]);
        cJSON_AddNumberToObject(root, "icmp_type", sess_msg->icmp_type[DIRECTION_IN]);
        cJSON_AddNumberToObject(root, "packets", sess_msg->in_pps);
        cJSON_AddNumberToObject(root, "in_bytes", (sess_msg->in_bps >> 3));
        qnsm_kafka_send_msg(QNSM_KAFKA_SAMPLE_FLOW_TOPIC, root, sess_msg->time_old);
        if (root) {
            cJSON_Delete(root);
        }
    }

    /*out stattis*/
    if (sess_msg->out_pps) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);
        cJSON_AddNumberToObject(root, "sampling_interval", qnsm_get_sessm_conf()->sample_rate);
        cJSON_AddNumberToObject(root, "timestamp", sess_msg->time_old);
        cJSON_AddNumberToObject(root, "ip_protocol", sess_msg->protocol);
        cJSON_AddNumberToObject(root, "ip_version", ip_ver);
        cJSON_AddStringToObject(root,"src_ip", src_tmp);
        cJSON_AddNumberToObject(root, "src_port", port[0]);
        cJSON_AddStringToObject(root,"dst_ip", dst_tmp);
        cJSON_AddNumberToObject(root, "dst_port", port[1]);

        cJSON_AddNumberToObject(root, "direction", 1);
        cJSON_AddNumberToObject(root, "tcp_flags", sess_msg->tcp_flags[DIRECTION_OUT]);
        cJSON_AddNumberToObject(root, "icmp_type", sess_msg->icmp_type[DIRECTION_OUT]);
        cJSON_AddNumberToObject(root, "packets", sess_msg->out_pps);
        cJSON_AddNumberToObject(root, "out_bytes", (sess_msg->out_bps >> 3));
        qnsm_kafka_send_msg(QNSM_KAFKA_SAMPLE_FLOW_TOPIC, root, sess_msg->time_old);
        if (root) {
            cJSON_Delete(root);
        }
    }

    QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_INFO,
               "5tuple leave\n");
    return 0;
}
#endif

int32_t qnsm_edge_service_init(void)
{
    void *kafka_cfg = NULL;

    /*init msg*/
    (void)qnsm_msg_publish();
    (void)qnsm_msg_reg(QNSM_MSG_DPI_PROTO_INFO, qnsm_dpi_msg_proc, NULL);
#ifdef __FLOW_LIFE_STATTIS
    (void)qnsm_msg_reg(QNSM_MSG_SESS_LIFE_STATIS, qnsm_sess_statis_msg_proc, NULL);
#endif
#ifdef __DDOS
    (void)qnsm_msg_reg(QNSM_MSG_SESS_AGG, qnsm_5tuple_msg_proc, NULL);
#endif
    (void)qnsm_msg_reg(QNSM_MSG_CUSTOM_IP_AGG, qnsm_cus_ip_agg_msg_proc, NULL);
    (void)qnsm_msg_reg(QNSM_MSG_SVR_IP_AGG, qnsm_svr_host_agg_msg_proc, NULL);
    (void)qnsm_msg_reg(QNSM_MSG_VIP_SRC_PORT_AGG, qnsm_vip_port_msg_proc, NULL);
    (void)qnsm_msg_reg(QNSM_MSG_VIP_DST_PORT_AGG, qnsm_vip_port_msg_proc, NULL);

    /*init kafka*/
    qnsm_kafka_batch_tx_init(QNSM_KAFKA_TCP_SESS_AGG_TOPIC, "flow", 16);
    qnsm_kafka_batch_tx_init(QNSM_KAFKA_UDP_SESS_AGG_TOPIC, "flow", 16);
    qnsm_kafka_batch_tx_init(QNSM_KAFKA_SIP_IN_AGG_TOPIC, "sip_in", 8);
    qnsm_kafka_batch_tx_init(QNSM_KAFKA_VIP_AGG_TOPIC, "dip_traffic", 8);

    /*init data*/
    (void)qnsm_app_inst_init(sizeof(QNSM_EDGE),
                                   NULL,
                                   NULL,
                                   NULL);

    static const char *kafka_inst[] = {
#define XX(num, name, string) string,
        QNSM_KAFKA_MAP(XX)
#undef XX
    };

    kafka_cfg = qnsm_get_kafka_cfg(kafka_inst[QNSM_EDGE_KAFKA]);
    if (kafka_cfg) {
        (void)qnsm_kafka_app_init_producer(kafka_cfg);
    }
    return 0;
}
