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
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>

#include "cJSON.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_msg_ex.h"
#include "qnsm_dpi_ex.h"

/* Methods */
#define SSDP_METHOD_MAP(XX)        \
  /* upnp */                       \
  XX(0, MSEARCH,     M-SEARCH)     \
  XX(1, NOTIFY,      NOTIFY)       \
  XX(2, SUBSCRIBE,   SUBSCRIBE)    \
  XX(3, UNSUBSCRIBE, UNSUBSCRIBE)  \

enum SSDP_METHOD {
#define XX(num, name, string) SSDP_##name = num,
    SSDP_METHOD_MAP(XX)
#undef XX
    SSDP_METHOD_MAX,
};

static const char *method_strings[] = {
#define XX(num, name, string) #string,
    SSDP_METHOD_MAP(XX)
#undef XX
    0
};


#define SSDP_MIN_LEN (32)

typedef struct {
    uint8_t *ssdp_header;
    uint16_t ssdp_length;
    uint16_t is_req;
    uint16_t req_method;
} SSDP_INFO;

SSDP_INFO  *ssdp_udp_info;



void ssdp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    SSDP_INFO *ssdp_info = NULL;

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "enter\n");
    ssdp_info = qnsm_dpi_proto_data(EN_QNSM_DPI_SSDP);
    if (NULL == ssdp_info) {
        QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "failed\n");
        return;
    }
    *arg = ssdp_info;

    pkt_info->dpi_app_prot = EN_QNSM_DPI_SSDP;
    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "leave ssdp_len %u \n", ssdp_info->ssdp_length);
    return;
}

EN_QNSM_DPI_OP_RES ssdp_parse(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    EN_QNSM_DPI_OP_RES   ret = EN_QNSM_DPI_OP_STOP;
    SSDP_INFO *ssdp_info = (SSDP_INFO *)arg;
    enum SSDP_METHOD  method = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "enter\n");
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    ssdp_info->ssdp_header = pkt_info->payload;
    ssdp_info->ssdp_length = QNSM_DPI_NTOHS(uh->dgram_len) - \
                             sizeof(struct udp_hdr);

    if (0 == memcmp(ssdp_info->ssdp_header, "HTTP", 4)) {
        ssdp_info->is_req = 0;
        ssdp_info->req_method = SSDP_METHOD_MAX;
        ret = EN_QNSM_DPI_OP_CONTINUE;
        goto EXIT;
    }

    for ( ; method < SSDP_METHOD_MAX; method++) {
        if (0 == memcmp(ssdp_info->ssdp_header, method_strings[method], strlen(method_strings[method]))) {
            ssdp_info->is_req = 1;
            ssdp_info->req_method = method;
            ret = EN_QNSM_DPI_OP_CONTINUE;
            break;
        }
    }

EXIT:
    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "leave req %u\n", ssdp_info->is_req);
    return ret;
}

EN_QNSM_DPI_OP_RES ssdp_send(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    (void)qnsm_dpi_send_info(pkt_info, EN_QNSM_DPI_SSDP, arg);

    return EN_QNSM_DPI_OP_CONTINUE;
}

void ssdp_free(void *sess, void *arg)
{
    return;
}

uint32_t ssdp_encap_info(uint8_t *buf, void *pkt_info, void *arg)
{
    uint32_t len = 0;
    SSDP_INFO *ssdp_info = (SSDP_INFO *)arg;

    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "enter\n");

    len += qnsm_dpi_encap_tuple(buf, pkt_info);

    *(uint16_t *)(buf + len) = ssdp_info->ssdp_length;
    len += sizeof(uint16_t);

    if (SSDP_MIN_LEN <= ssdp_info->ssdp_length) {
        *(uint16_t *)(buf + len) = ssdp_info->is_req;
        len += sizeof(uint16_t);

        *(uint16_t *)(buf + len) = ssdp_info->req_method;
        len += sizeof(uint16_t);
    }

    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "leave\n");
    return len;
}

void ssdp_msg_proc(void *data, uint32_t data_len)
{
    uint8_t *buf = data;
    QNSM_DPI_IPV4_TUPLE4 *tuple = (QNSM_DPI_IPV4_TUPLE4 *)buf;
    char  tmp[128];
    uint32_t size =  sizeof(tmp);
    struct in_addr ip_addr;
    cJSON *root = NULL;
    uint32_t len = 0;
    uint16_t ssdp_len = 0;

    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "enter\n");


    root = cJSON_CreateObject();
    if (EN_QNSM_AF_IPv4 == tuple->af) {
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->saddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->daddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    } else {
        (void)inet_ntop(AF_INET6, tuple->saddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        (void)inet_ntop(AF_INET6, tuple->daddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    }
    cJSON_AddNumberToObject(root, "sport", tuple->source);
    cJSON_AddNumberToObject(root, "dport", tuple->dest);
    len += sizeof(QNSM_DPI_IPV4_TUPLE4);


    ssdp_len = *(uint16_t *)(buf + len);
    len += sizeof(uint16_t);
    cJSON_AddNumberToObject(root, "ssdp_len", ssdp_len);

    if ((SSDP_MIN_LEN <= ssdp_len) && (len < data_len)) {
        cJSON_AddNumberToObject(root, "is_req", *(uint16_t *)(buf + len));
        len += sizeof(uint16_t);

        cJSON_AddNumberToObject(root, "req_method", *(uint16_t *)(buf + len));
        //len += sizeof(uint16_t);
    }

    qnsm_kafka_send_msg(QNSM_KAFKA_SSDP_TOPIC, root, tuple->saddr.in4_addr.s_addr);
    if(root)
        cJSON_Delete(root);
    QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "leave\n");
    return;
}

void* ssdp_info_init(void)
{
    SSDP_INFO *ssdp_info = NULL;

    ssdp_info = rte_zmalloc("SSDP INFO", sizeof(SSDP_INFO), QNSM_DDOS_MEM_ALIGN);
    if (NULL == ssdp_info) {
        QNSM_DEBUG(QNSM_DBG_M_DPI_SSDP, QNSM_DBG_INFO, "failed\n");
    }

    return ssdp_info;
}

int32_t ssdp_reg(void)
{
    int32_t i = 0;

    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_SSDP)) {
        return 0;
    }

    {
        /*reg classfy to dpi by proto+port*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_UDP, SSDP_PORT, EN_QNSM_DPI_SSDP, ssdp_classify);
        for (i = 0; method_strings[i]; i++) {
            qnsm_dpi_content_classify_reg(EN_DPI_PROT_UDP, method_strings[i], strlen(method_strings[i]), EN_QNSM_DPI_SSDP, ssdp_classify);
        }
        qnsm_dpi_content_classify_reg(EN_DPI_PROT_UDP, "HTTP", 4, EN_QNSM_DPI_SSDP, ssdp_classify);

        /*reg dpi proc*/
        (void)qnsm_dpi_proto_init_reg(EN_QNSM_DPI_SSDP, ssdp_info_init);
        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_SSDP, ssdp_parse, 10);
        (void)qnsm_dpi_prot_final_reg(EN_QNSM_DPI_SSDP, ssdp_free);
    }

    return 0;
}

int32_t ssdp_init(void)
{
    ssdp_reg();

    return 0;
}

