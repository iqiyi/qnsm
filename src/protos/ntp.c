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

typedef struct {
    uint8_t *ntp_header;
    uint16_t ntp_length;
    uint8_t request_code;
    uint8_t version;
} NTP_INFO;

NTP_INFO  *ntp_udp_info;



void ntp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    NTP_INFO *ntp_info = NULL;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "enter\n");
    ntp_info = qnsm_dpi_proto_data(EN_QNSM_DPI_NTP);
    if (NULL == ntp_info) {
        QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "failed\n");
        return;
    }

    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    ntp_info->ntp_header = pkt_info->payload;
    ntp_info->ntp_length = QNSM_DPI_NTOHS(uh->dgram_len) - \
                           sizeof(struct udp_hdr);
    *arg = ntp_info;

    if ((((ntp_info->ntp_header[0] & 0x38) >> 3) <= 4)) {
        pkt_info->dpi_app_prot = EN_QNSM_DPI_NTP;
    }
    QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "leave\n");
    return;
}

EN_QNSM_DPI_OP_RES ntp_parse(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    EN_QNSM_DPI_OP_RES   ret = EN_QNSM_DPI_OP_STOP;
    NTP_INFO *ntp_info = (NTP_INFO *)arg;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    ntp_info->ntp_header = pkt_info->payload;
    ntp_info->ntp_length = QNSM_DPI_NTOHS(uh->dgram_len) - \
                           sizeof(struct udp_hdr);

    if ((((ntp_info->ntp_header[0] & 0x38) >> 3) <= 4)) {
        // 38 in binary representation is 00111000
        ntp_info->version = (ntp_info->ntp_header[0] & 0x38) >> 3;

        if (ntp_info->version == 2) {
            ntp_info->request_code = ntp_info->ntp_header[3];
        }

        QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "detected NTP. ver %u\n", ntp_info->version);
        ret = EN_QNSM_DPI_OP_CONTINUE;
    }

    return ret;
}

EN_QNSM_DPI_OP_RES ntp_send(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    (void)qnsm_dpi_send_info(pkt_info, EN_QNSM_DPI_NTP, arg);

    return EN_QNSM_DPI_OP_CONTINUE;
}

void ntp_free(void *sess, void *arg)
{
    return;
}

uint32_t ntp_encap_info(uint8_t *buf, void *pkt_info, void *arg)
{
    uint32_t len = 0;
    NTP_INFO *ntp_info = (NTP_INFO *)arg;

    QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "enter\n");

    len += qnsm_dpi_encap_tuple(buf, pkt_info);

    *(uint8_t *)(buf + len) = ntp_info->version;
    len += sizeof(uint8_t);

    if (ntp_info->version) {
        *(uint8_t *)(buf + len) = ntp_info->request_code;
        len += sizeof(uint8_t);
    }

    QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "leave\n");
    return len;
}

void ntp_msg_proc(void *data, uint32_t data_len)
{
    uint8_t *buf = data;
    QNSM_DPI_IPV4_TUPLE4 *tuple = (QNSM_DPI_IPV4_TUPLE4 *)buf;
    char  tmp[128];
    uint32_t size =  sizeof(tmp);
    struct in_addr ip_addr;
    cJSON *root = NULL;
    uint32_t len = 0;
    uint8_t version = 0;

    QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "enter\n");

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

    version = *(uint8_t *)(buf + len);
    len += sizeof(uint8_t);
    cJSON_AddNumberToObject(root, "version", version);

    if (version) {
        cJSON_AddNumberToObject(root, "request_code", *(uint8_t *)(buf + len));
        //len += sizeof(uint8_t);
    }

    qnsm_kafka_send_msg(QNSM_KAFKA_NTP_TOPIC, root, tuple->saddr.in4_addr.s_addr);
    if(root)
        cJSON_Delete(root);
    QNSM_DEBUG(QNSM_DBG_M_DPI_NTP, QNSM_DBG_INFO, "leave\n");
    return;
}

void* ntp_info_init(void)
{
    NTP_INFO *ntp_info = NULL;

    ntp_info = rte_zmalloc("NTP INFO", sizeof(NTP_INFO), QNSM_DDOS_MEM_ALIGN);
    if (NULL == ntp_info) {
        QNSM_DEBUG(QNSM_DBG_INFO, QNSM_DBG_ERR, "failed\n");
    }

    return ntp_info;
}

int32_t ntp_reg(void)
{
    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_NTP)) {
        return 0;
    }

    {
        /*reg classfy to dpi by proto+port*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_UDP, NTP_PORT, EN_QNSM_DPI_NTP, ntp_classify);

        /*reg dpi proc*/
        (void)qnsm_dpi_proto_init_reg(EN_QNSM_DPI_NTP, ntp_info_init);
        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_NTP, ntp_parse, 10);
        (void)qnsm_dpi_prot_final_reg(EN_QNSM_DPI_NTP, ntp_free);
    }

    return 0;
}

int32_t ntp_init(void)
{
    ntp_reg();

    return 0;
}

