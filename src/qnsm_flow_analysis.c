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
#include <netinet/if_ether.h>
#include <rte_spinlock.h>
#include <rte_mbuf.h>


/* RTE HEAD FILE*/
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_timer.h>


#include "cJSON.h"
#include "util.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_msg_ex.h"
#include "qnsm_dbg.h"
#include "qnsm_min_heap.h"
#include "qnsm_flow_analysis.h"

inline int qnsm_pkt_type_parse(QNSM_PACKET_INFO* pkt_info, int32_t dire, uint32_t lcore_id, uint8_t *en_tcp_type)
{
    uint32_t tcp_flag;
    uint32_t detect_type = 0;
    L4_HEAD       l4_head;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));

    l4_head.raw = rte_pktmbuf_mtod_offset(mbuf, unsigned char *, pkt_info->l3_offset + pkt_info->l3_len);

    if (pkt_info->is_frag) {
        detect_type = e_frag;
        goto label;
    }

    switch (pkt_info->proto) {
        case TCP_PROTOCOL: {
            tcp_flag = l4_head.raw[13];

            detect_type = en_tcp_type[tcp_flag];
            if (e_other_flag == detect_type) {
                if(tcp_flag & TCP_RST) {
                    detect_type = e_rst;
                } else if(tcp_flag & TCP_FIN) {
                    detect_type = e_fin;
                } else if (tcp_flag & TCP_SYN) {
                    detect_type = e_syn;
                }
            }
            break;
        }
        case UDP_PROTOCOL: {
            detect_type = e_udp;
            if (53 == pkt_info->dport) {
                detect_type = e_dns_query;
            }
            break;
        }
        case ICMP_PROTOCOL: {
            detect_type = e_icmp;
            break;
        }
        case ESP_PROTOCOL: {
            detect_type = e_esp;
            break;
        }
        default: {
            detect_type = e_other;
            break;
        }
    }

label:
    return detect_type;
}
