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


/* cmds */
#define MEMCACHED_CMD_MAP(XX)     \
  /* Storage commands */          \
  XX(0,  set,           set)      \
  XX(1,  add,           add)      \
  XX(2,  replace,       replace)  \
  XX(3,  append,        append)   \
  XX(4,  prepend,       prepend)  \
  XX(5,  cas,           cas)      \
  /* Retrieval commands */        \
  XX(6,  get,           get)      \
  XX(7,  gets,          gets)     \
  /* del cmds */                  \
  XX(8,  delete,        delete)   \
  /* resp cmd */                  \
  XX(9,  STORED,         STORED)   \
  XX(10, EXISTS,         EXISTS)   \
  XX(11, NOT_FOUND,      NOT_FOUND)\
  XX(12, VALUE,          VALUE)    \
  XX(13, DELETED,        DELETED)  \
  XX(14, incr,           incr)     \
  XX(15, decr,           decr)     \

typedef struct memcached_packet_header {
    uint16_t req_id;
    uint16_t seq;
    uint16_t total_num;
    uint16_t rsvd;
} __attribute__((packed)) MEMCACHED_UDP_HEADER;

/*
*udp payload offset is 8, has a eight bytes header
*req id + seq + total_num + rsvd
*total_num > 0
*/
static void memcached_udp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    MEMCACHED_UDP_HEADER *header = NULL;
    uint16_t len = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "enter\n");

    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    header = (MEMCACHED_UDP_HEADER *)(pkt_info->payload);
    len =  QNSM_DPI_NTOHS(uh->dgram_len) - \
           sizeof(struct udp_hdr);
    if ((len < sizeof(MEMCACHED_UDP_HEADER))
        || (0 >= QNSM_DPI_NTOHS(header->total_num))) {
        QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_ERR, "not udp memcached pkt\n");
        return;
    }

    pkt_info->dpi_app_prot = EN_QNSM_DPI_MEMCACHED;

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "leave\n");
    return;
}

/*
*memcache dpi sig:
*tcp memcached payload offset is 0,
*macth cmd, but stream with segments not matched
*/
void memcached_tcp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "enter\n");

    /*
     *now do nothing,
     *because match cmd need tcp reasssemble
     *but now shutdown tcp stream reassemble
     */
    //pkt_info->pkt_proto = e_memcached;
    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "leave\n");
    return;
}

int32_t memcached_reg(void)
{
    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_MEMCACHED)) {
        return 0;
    }

    {
        /*reg classfy to dpi by l4proto+port*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_UDP, MEMCACHED_PORT, EN_QNSM_DPI_MEMCACHED, memcached_udp_classify);
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_TCP, MEMCACHED_PORT, EN_QNSM_DPI_MEMCACHED, memcached_tcp_classify);
    }
    return 0;
}

