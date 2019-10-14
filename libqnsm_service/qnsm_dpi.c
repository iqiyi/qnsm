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
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/socket.h>
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
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>

#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_msg_ex.h"
#include "app.h"
#include "qnsm_service.h"
#include "qnsm_dpi.h"


QNSM_DPI *g_dpi = NULL;

inline uint8_t qnsm_dpi_proto_enable(EN_QNSM_DPI_PROTO dpi_proto)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    return dpi->dpi_proto[dpi_proto].enable;
}

inline uint8_t qnsm_dpi_proto_parse_enable(EN_QNSM_DPI_PROTO dpi_proto)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    return dpi->dpi_proto[dpi_proto].parse_enable;
}


inline void* qnsm_dpi_proto_data(EN_QNSM_DPI_PROTO dpi_proto)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    return dpi->dpi_proto[dpi_proto].dpi_prot_data;
}

inline void qnsm_dpi_proto_init(EN_QNSM_DPI_PROTO dpi_proto)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    if (dpi->dpi_proto[dpi_proto].init_func) {
        dpi->dpi_proto[dpi_proto].dpi_prot_data = dpi->dpi_proto[dpi_proto].init_func();
        printf("dpi proto %u data %p\n", dpi_proto, dpi->dpi_proto[dpi_proto].dpi_prot_data);
    }
    return;
}

void qnsm_dpi_proto_free(EN_QNSM_DPI_PROTO dpi_proto, void *arg)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    if (dpi->dpi_proto[dpi_proto].free_func) {
        dpi->dpi_proto[dpi_proto].free_func(NULL, arg);
    }
    return;
}

inline int32_t qnsm_dpi_prot_cbk(EN_QNSM_DPI_PROTO dpi_proto, QNSM_PACKET_INFO *pkt_info, void *sess, void *arg)
{
    QNSM_PROTOCOL_ITEM *proto_item = NULL;
    struct qnsm_list_head *proto_list = NULL;
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    EN_QNSM_DPI_OP_RES result = EN_QNSM_DPI_OP_MAX;
    int32_t ret = 0;

    if (EN_QNSM_DPI_PROTO_MAX <= dpi_proto) {
        return -1;
    }
    if ((0 == dpi->dpi_proto[dpi_proto].enable)
        || (0 == dpi->dpi_proto[dpi_proto].parse_enable)) {
        return -1;
    }

    proto_list = &dpi->dpi_proto[dpi_proto].head;
    qnsm_list_for_each_entry(proto_item, proto_list, proto_node) {
        result = proto_item->proto_ops(pkt_info, arg);
        switch (result) {
            case EN_QNSM_DPI_OP_CONTINUE:
                continue;
            case EN_QNSM_DPI_OP_STOP: {
                ret = -1;
                goto EXIT;
            }
            default: {
                ret = -1;
                goto EXIT;
            }
        }
    }

EXIT:
    if (dpi->dpi_proto[dpi_proto].free_func) {
        dpi->dpi_proto[dpi_proto].free_func(sess, arg);
    }
    return ret;
}

inline int32_t qnsm_dpi_match(QNSM_PACKET_INFO *pkt_info, EN_QNSM_DPI_L4_PROT l4_prot, void *sess, void **app_arg)
{
    uint16_t port;
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    QNSM_DPI_CLASS *dpi_class = NULL;
    QNSM_DPI_CLASS *next = NULL;
    struct qnsm_list_head *classifier_list = NULL;
    uint8_t *data = NULL;
    void *arg = NULL;

    port = pkt_info->dport;
    classifier_list = &dpi->classify.service_classifer[l4_prot][port];
    qnsm_list_for_each_entry_safe(dpi_class, next, classifier_list, class_node) {
        if (0 == dpi->dpi_proto[dpi_class->match_proto].enable) {
            continue;
        }
        if (dpi_class->match_func) {
            dpi_class->match_func(pkt_info, sess, &arg);
            goto MATCH;
        }
    }

    port = pkt_info->sport;
    classifier_list = &dpi->classify.service_classifer[l4_prot][port];
    qnsm_list_for_each_entry_safe(dpi_class, next, classifier_list, class_node) {
        if (0 == dpi->dpi_proto[dpi_class->match_proto].enable) {
            continue;
        }
        if (dpi_class->match_func) {
            dpi_class->match_func(pkt_info, sess, &arg);
            goto MATCH;
        }
    }

    data = (uint8_t *)pkt_info->payload;
    if (EN_DPI_PROT_TCP == l4_prot) {
        classifier_list = &dpi->classify.tcp_content_classifer[data[0]][data[1]];
    } else if (EN_DPI_PROT_UDP == l4_prot) {
        classifier_list = &dpi->classify.udp_content_classifer[data[0]][data[1]];
    } else {
        goto NOT_MATCH;
    }

    qnsm_list_for_each_entry_safe(dpi_class, next, classifier_list, class_node) {
        if (0 == dpi->dpi_proto[dpi_class->match_proto].enable) {
            continue;
        }
        if (dpi_class->match_func) {
            if (0 == memcmp(data, dpi_class->match_content_key, dpi_class->match_content_key_len)) {
                dpi_class->match_func(pkt_info, sess, &arg);
                goto MATCH;
            }
        }
    }

NOT_MATCH:
    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "not match dpi class\n");
    return -1;

MATCH:
    *app_arg = arg;
    return dpi_class->match_proto;
}

static inline void qnsm_dpi_proc(QNSM_PACKET_INFO *pkt_info, QNSM_DPI_SESS *dpi_sess)
{
    uint16_t port;
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    void *arg = NULL;
    QNSM_DPI_CLASS *dpi_class = NULL;
    QNSM_DPI_CLASS *next = NULL;
    struct qnsm_list_head *classifier_list = NULL;
    uint8_t *data = NULL;
    EN_QNSM_DPI_L4_PROT l4_prot;

    l4_prot = dpi_sess->l4_proto;

    port = pkt_info->dport;
    classifier_list = &dpi->classify.service_classifer[l4_prot][port];
    qnsm_list_for_each_entry_safe(dpi_class, next, classifier_list, class_node) {
        if (dpi_class->match_func) {
            dpi_class->match_func(pkt_info, dpi_sess->sess, &arg);
            goto MATCH;
        }
    }

    port = pkt_info->sport;
    classifier_list = &dpi->classify.service_classifer[l4_prot][port];
    qnsm_list_for_each_entry_safe(dpi_class, next, classifier_list, class_node) {
        if (dpi_class->match_func) {
            dpi_class->match_func(pkt_info, dpi_sess->sess, &arg);
            goto MATCH;
        }
    }

    data = (uint8_t *)pkt_info->payload;
    if (EN_DPI_PROT_TCP == l4_prot) {
        classifier_list = &dpi->classify.tcp_content_classifer[data[0]][data[1]];
    } else if (EN_DPI_PROT_UDP == l4_prot) {
        classifier_list = &dpi->classify.udp_content_classifer[data[0]][data[1]];
    } else {
        goto NOT_MATCH;
    }

    qnsm_list_for_each_entry_safe(dpi_class, next, classifier_list, class_node) {
        if (dpi_class->match_func) {
            if (0 == memcmp(data, dpi_class->match_content_key, dpi_class->match_content_key_len)) {
                dpi_class->match_func(pkt_info, dpi_sess->sess, &arg);
                goto MATCH;
            }
        }
    }

NOT_MATCH:
    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "not match dpi class\n");
    return;

MATCH:
    if (arg) {
        (void)qnsm_dpi_prot_cbk(dpi_class->match_proto, pkt_info, dpi_sess->sess, arg);
    }
    return;
}

int32_t qnsm_dpi_msg_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_DPI_ENCAP_INFO encap_fun, QNSM_DPI_MSG_PROC msg_proc_fun)
{

    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    QNSM_ASSERT(dpi);
    QNSM_ASSERT(EN_QNSM_DPI_PROTO_MAX > dpi_proto);

    if (0 == dpi->dpi_proto[dpi_proto].parse_enable) {
        return 0;
    }

    dpi->dpi_proto[dpi_proto].encap_func = encap_fun;
    dpi->dpi_proto[dpi_proto].msg_proc_func = msg_proc_fun;
    return 0;
}

int32_t qnsm_dpi_prot_final_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_PROTO_FREE final_func)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    QNSM_ASSERT(dpi);
    QNSM_ASSERT(EN_QNSM_DPI_PROTO_MAX > dpi_proto);

    if (0 == dpi->dpi_proto[dpi_proto].parse_enable) {
        return 0;
    }

    dpi->dpi_proto[dpi_proto].free_func = final_func;

    return 0;
}

int32_t qnsm_dpi_proto_init_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_DPI_PROTO_DATA_INIT init_func)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);

    QNSM_ASSERT(dpi);
    QNSM_ASSERT(EN_QNSM_DPI_PROTO_MAX > dpi_proto);
    dpi->dpi_proto[dpi_proto].init_func = init_func;

    return 0;
}

int32_t qnsm_dpi_prot_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_PROTO_OPS proto_ops, uint32_t pri)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    QNSM_PROTOCOL_ITEM *proto_item = NULL;
    QNSM_PROTOCOL_ITEM *new_item = NULL;
    struct qnsm_list_head *proto_list = NULL;

    QNSM_ASSERT(dpi);
    QNSM_ASSERT(EN_QNSM_DPI_PROTO_MAX > dpi_proto);

    if (0 == dpi->dpi_proto[dpi_proto].parse_enable) {
        return 0;
    }

    proto_list = &dpi->dpi_proto[dpi_proto].head;
    qnsm_list_for_each_entry(proto_item, proto_list, proto_node) {
        if (proto_item->priority < pri) {
            break;
        }
    }

    new_item = rte_zmalloc("QNSM DPI ITEM", sizeof(QNSM_PROTOCOL_ITEM), QNSM_DDOS_MEM_ALIGN);
    if (NULL == new_item) {
        QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_ERR, "failed\n");
        return -1;
    }
    new_item->proto_ops = proto_ops;
    new_item->priority = pri;
    QNSM_INIT_LIST_HEAD(&new_item->proto_node);
    QNSM_LIST_ADD_BEFORE(&new_item->proto_node, &proto_item->proto_node);
    return 0;
}

int32_t qnsm_dpi_content_classify_reg(EN_QNSM_DPI_L4_PROT dpi_classfy_proto, const char *str, const uint8_t len, EN_QNSM_DPI_PROTO match_proto, QNSM_DPI_CLASS_MATCH_FUN func)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    QNSM_DPI_CLASS *dpi_class = NULL;
    struct qnsm_list_head *content_classifer_head = NULL;

    QNSM_ASSERT(str);
    QNSM_ASSERT(func);

    if (EN_DPI_PROT_TCP == dpi_classfy_proto) {
        content_classifer_head = &dpi->classify.tcp_content_classifer[(uint8_t)str[0]][(uint8_t)str[1]];
    } else if (EN_DPI_PROT_UDP == dpi_classfy_proto) {
        content_classifer_head = &dpi->classify.udp_content_classifer[(uint8_t)str[0]][(uint8_t)str[1]];
    } else {
        return -1;
    }

    dpi_class = rte_malloc("DPI CONTENT", sizeof(QNSM_DPI_CLASS), QNSM_DDOS_MEM_ALIGN);
    if (NULL == dpi_class) {
        QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_ERR, "failed\n");
        return -1;
    }
    QNSM_INIT_LIST_HEAD(&dpi_class->class_node);
    rte_memcpy(dpi_class->match_content_key, str, ((len < QNSM_DPI_MATCH_CONTTENT_SIZE) ? len : QNSM_DPI_MATCH_CONTTENT_SIZE));
    dpi_class->match_content_key_len = len;
    dpi_class->match_proto = match_proto;
    dpi_class->match_func = func;
    qnsm_list_add_tail(&dpi_class->class_node, content_classifer_head);
    return 0;
}

int32_t qnsm_dpi_service_classify_reg(EN_QNSM_DPI_L4_PROT dpi_classfy_proto, uint16_t dport, EN_QNSM_DPI_PROTO match_proto, QNSM_DPI_CLASS_MATCH_FUN func)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    QNSM_DPI_CLASS *dpi_class = NULL;
    struct qnsm_list_head *service_classifer_head = NULL;

    QNSM_ASSERT(func);

    service_classifer_head = &dpi->classify.service_classifer[dpi_classfy_proto][dport];
    dpi_class = rte_malloc("DPI CONTENT", sizeof(QNSM_DPI_CLASS), QNSM_DDOS_MEM_ALIGN);
    if (NULL == dpi_class) {
        QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_ERR, "failed\n");
        return -1;
    }
    QNSM_INIT_LIST_HEAD(&dpi_class->class_node);
    memset(dpi_class->match_content_key, 0, sizeof(dpi_class->match_content_key));
    dpi_class->match_proto = match_proto;
    dpi_class->match_func = func;
    qnsm_list_add_tail(&dpi_class->class_node, service_classifer_head);

    SET_LIB_COMMON_STATE(dpi, en_lib_state_load);
    return 0;
}


int32_t qnsm_dpi_init(void **tbl_handle)
{
    int32_t proto_id;
    uint32_t i = 0;
    uint32_t j = 0;
    QNSM_DPI *dpi = NULL;
    QNSM_PROTO_CFG *app_conf = NULL;
    const char *dpi_proto[] = {
#define XX(num, name, string) #string,
        QNSM_DPI_PROTO_MAP(XX)
#undef XX
    };

    dpi = rte_zmalloc_socket("QNSM DPI", sizeof(QNSM_DPI), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == dpi) {
        QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_ERR, "failed\n");
        return -1;
    }
    for (proto_id =  0; proto_id < EN_QNSM_DPI_PROTO_MAX; proto_id++) {
        QNSM_INIT_LIST_HEAD(&dpi->dpi_proto[proto_id].head);
        dpi->dpi_proto[proto_id].encap_func = NULL;
        dpi->dpi_proto[proto_id].msg_proc_func = NULL;
        app_conf = qnsm_get_proto_conf(dpi_proto[proto_id]);
        if (app_conf) {
            dpi->dpi_proto[proto_id].enable = app_conf->enable;
            dpi->dpi_proto[proto_id].parse_enable = app_conf->parse_enable;
        } else {
            dpi->dpi_proto[proto_id].enable = 0;
            dpi->dpi_proto[proto_id].parse_enable = 0;
        }
    }
    for (i = 0; i < EN_DPI_L4_MAX; i++) {
        for (j = 0; j < QNSM_DPI_PORT_MAX; j++) {
            QNSM_INIT_LIST_HEAD(&dpi->classify.service_classifer[i][j]);
        }
    }
    for (i = 0; i < QNSM_DPI_UCHAR_MAX; i++) {
        for (j = 0; j < QNSM_DPI_UCHAR_MAX; j++) {
            QNSM_INIT_LIST_HEAD(&dpi->classify.tcp_content_classifer[i][j]);
            QNSM_INIT_LIST_HEAD(&dpi->classify.udp_content_classifer[i][j]);
        }
    }

    SET_LIB_COMMON_STATE(dpi, en_lib_state_init);
    *tbl_handle = dpi;
    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "success\n");
    return 0;
}

inline int32_t qnsm_dpi_send_info(QNSM_PACKET_INFO *pkt_info, EN_QNSM_DPI_PROTO dpi_proto, void *arg)
{
    QNSM_DPI_MSG msg;

    msg.proto = dpi_proto;
    msg.data = arg;
    msg.pkt_info = pkt_info;

    return qnsm_msg_send_lb(EN_QNSM_EDGE,
                            QNSM_MSG_DPI_PROTO_INFO,
                            &msg,
                            pkt_info->v4_src_ip,
                            0);
}

inline uint32_t qnsm_dpi_encap_tuple(void *msg, QNSM_PACKET_INFO *pkt_info)
{
    QNSM_DPI_IPV4_TUPLE4 *tuple = msg;

    if (EN_QNSM_AF_IPv4 == pkt_info->af) {
        tuple->saddr.in4_addr.s_addr = pkt_info->v4_src_ip;
        tuple->daddr.in4_addr.s_addr = pkt_info->v4_dst_ip;
    } else {
        rte_memcpy(tuple->saddr.in6_addr.s6_addr, pkt_info->v6_src_ip, IPV6_ADDR_LEN);
        rte_memcpy(tuple->daddr.in6_addr.s6_addr, pkt_info->v6_dst_ip, IPV6_ADDR_LEN);
    }
    tuple->af = EN_QNSM_AF_IPv4;
    tuple->source = pkt_info->sport;
    tuple->dest = pkt_info->dport;
    return sizeof(QNSM_DPI_IPV4_TUPLE4);
}

/*
*       DPI encap format
*       | TCP/UDP TUPLE |
*
*       HTTP encap format
*       | REQ TYPE         |
*       | HDR END_STAT     |
*       | HTTP CODE        |
*       | HEAD_FILED1      |
*       | HEAD_FILED2      |
*       | HEAD_FILED3      |
*/
int32_t qnsm_dpi_encap_dpi(void *msg, uint32_t *msg_len, void *send_data)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    QNSM_DPI_MSG *dpi_data = send_data;
    uint8_t *buf = msg;
    uint32_t len = 0;

    QNSM_ASSERT(EN_QNSM_DPI_PROTO_MAX > dpi_data->proto);

    *(uint32_t *)(buf + len) = dpi_data->proto;
    len += sizeof(uint32_t);

    if (dpi->dpi_proto[dpi_data->proto].encap_func) {
        len += dpi->dpi_proto[dpi_data->proto].encap_func(buf + len, dpi_data->pkt_info, dpi_data->data);
    }
    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "dpi encap len %u\n", len);
    *msg_len = len;
    return 0;
}

int32_t qnsm_dpi_msg_proc(void *data, uint32_t data_len)
{
    QNSM_DPI *dpi = qnsm_service_handle(EN_QNSM_SERVICE_DPI);
    EN_QNSM_DPI_PROTO proto;
    QNSM_ASSERT(data);
    uint32_t len = 0;

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "dpi decap len %u\n", data_len);

    proto = *((uint32_t *)data);
    len += sizeof(uint32_t);
    QNSM_ASSERT(EN_QNSM_DPI_PROTO_MAX > proto);

    if (dpi->dpi_proto[proto].msg_proc_func) {
        dpi->dpi_proto[proto].msg_proc_func((uint8_t *)data + len, data_len - len);
    }
    return 0;
}


