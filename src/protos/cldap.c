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


void cldap_udp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    char *payload = NULL;
    uint16_t len = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "enter\n");
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    payload = pkt_info->payload;
    len =  QNSM_DPI_NTOHS(uh->dgram_len) - \
           sizeof(struct udp_hdr);

    if (len >= 14 && payload[0] == 0x30) {
        // simple type
        if (payload[1] == 0x0c && len == 14 &&
            payload[len - 1] == 0x00 && payload[2] == 0x02) {

            if ((payload[3] == 0x01)
                && (payload[5] == 0x60 || payload[5] == 0x61)
                && payload[6] == 0x07) {
                pkt_info->dpi_app_prot = EN_QNSM_DPI_CLDAP;
            }

            if ((payload[3] == 0x02)
                && (payload[5] == 0x60 || payload[5] == 0x61)
                && payload[6] == 0x07) {
                pkt_info->dpi_app_prot = EN_QNSM_DPI_CLDAP;
            }
        }

        // normal type
        if (payload[1] == 0x84
            && len >= 0x84
            && payload[2] == 0x00
            && payload[3] == 0x00
            && payload[6] == 0x02) {
            if ((payload[7] == 0x01)
                && (payload[9] == 0x60 || payload[9] == 0x61 || payload[9] == 0x63 || payload[9] == 0x64)
                && payload[10] == 0x84) {
                pkt_info->dpi_app_prot = EN_QNSM_DPI_CLDAP;
            }

            if ((payload[7] == 0x02)
                && (payload[9] == 0x60 || payload[9] == 0x61 || payload[9] == 0x63 || payload[9] == 0x64)
                && payload[10] == 0x84)

            {
                pkt_info->dpi_app_prot = EN_QNSM_DPI_CLDAP;
            }
        }
    }

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "leave\n");
    return;
}

EN_QNSM_DPI_OP_RES cldap_parse(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    EN_QNSM_DPI_OP_RES   ret = EN_QNSM_DPI_OP_STOP;

    return ret;
}

int32_t cldap_reg(void)
{
    char sig1[] = {0x30, 0x0c};
    char sig2[] = {0x30, 0x84};

    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_CLDAP)) {
        return 0;
    }

    {
        /*reg classfy to dpi by l4proto+port*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_UDP, CLDAP_PORT, EN_QNSM_DPI_CLDAP, cldap_udp_classify);
        qnsm_dpi_content_classify_reg(EN_DPI_PROT_UDP, sig1, sizeof(sig1), EN_QNSM_DPI_CLDAP, cldap_udp_classify);
        qnsm_dpi_content_classify_reg(EN_DPI_PROT_UDP, sig2, sizeof(sig2), EN_QNSM_DPI_CLDAP, cldap_udp_classify);

        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_CLDAP, cldap_parse, 10);
    }
    return 0;
}

