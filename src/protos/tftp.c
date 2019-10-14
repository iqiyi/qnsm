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

#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_msg_ex.h"
#include "qnsm_dpi_ex.h"
#include "tftp.h"

/*
*              ============== rfc 1350 ==============
   TFTP supports five types of packets, all of which have been mentioned
   above:

          opcode  operation
            1     Read request (RRQ)
            2     Write request (WRQ)
            3     Data (DATA)
            4     Acknowledgment (ACK)
            5     Error (ERROR)
    The TFTP header of a packet contains the  opcode  associated  with
   that packet.


            2 bytes     string    1 byte     string   1 byte
           ------------------------------------------------
          | Opcode |  Filename  |   0  |    Mode    |   0  |
           ------------------------------------------------

                      Figure 5-1: RRQ/WRQ packet


                   2 bytes     2 bytes      n bytes
                   ----------------------------------
                  | Opcode |   Block #  |   Data     |
                   ----------------------------------

                        Figure 5-2: DATA packet


   Data is actually transferred in DATA packets depicted in Figure 5-2.
   DATA packets (opcode = 3) have a block number and data field.  The
   block numbers on data packets begin with one and increase by one for
   each new block of data.  This restriction allows the program to use a
   single number to discriminate between new packets and duplicates.
   The data field is from zero to 512 bytes long.  If it is 512 bytes
   long, the block is not the last block of data; if it is from zero to
   511 bytes long, it signals the end of the transfer.  (See the section
   on Normal Termination for details.)


    All  packets other than duplicate ACK's and those used for
    termination are acknowledged unless a timeout occurs [4].  Sending a
    DATA packet is an acknowledgment for the first ACK packet of the
    previous DATA packet. The WRQ and DATA packets are acknowledged by
    ACK or ERROR packets, while RRQ


                          2 bytes     2 bytes
                          ---------------------
                         | Opcode |   Block #  |
                          ---------------------

                          Figure 5-3: ACK packet


    and ACK packets are acknowledged by  DATA  or ERROR packets.  Figure
    5-3 depicts an ACK packet; the opcode is 4.  The  block  number  in
    an  ACK echoes the block number of the DATA packet being
    acknowledged.  A WRQ is acknowledged with an ACK packet having a
    block number of zero.
*/
void tftp_udp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    struct  tftphdr *tftph = NULL;
    uint16_t len = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "enter\n");

    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    tftph = (struct  tftphdr *)(pkt_info->payload);
    len =  QNSM_DPI_NTOHS(uh->dgram_len) - \
           sizeof(struct udp_hdr);
    if (len > 3) {
        switch (QNSM_DPI_NTOHS(tftph->th_opcode)) {
            case RRQ:
            case WRQ: {
                if (TFTP_PORT == pkt_info->dport) {
                    pkt_info->dpi_app_prot = EN_QNSM_DPI_TFTP;
                }
                break;
            }
            case DATA: {
                /*dros pkt has this signature*/
                if (0x0001 == QNSM_DPI_NTOHS(tftph->th_block)) {
                    pkt_info->dpi_app_prot = EN_QNSM_DPI_TFTP;
                }
                break;
            }
            default: {
                break;
            }
        }
    }

    QNSM_DEBUG(QNSM_DBG_M_DPI, QNSM_DBG_INFO, "leave\n");
    return;
}

EN_QNSM_DPI_OP_RES tftp_parse(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    EN_QNSM_DPI_OP_RES   ret = EN_QNSM_DPI_OP_STOP;

    return ret;
}

int32_t tftp_reg(void)
{
    char sig[] = {0x00, 0x03, 0x00, 0x01};

    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_TFTP)) {
        return 0;
    }

    {
        /*reg classfy to dpi by l4proto+port, this is tftp init conn pkt*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_UDP, TFTP_PORT, EN_QNSM_DPI_TFTP, tftp_udp_classify);
        qnsm_dpi_content_classify_reg(EN_DPI_PROT_UDP, sig, sizeof(sig), EN_QNSM_DPI_TFTP, tftp_udp_classify);

        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_TFTP, tftp_parse, 10);
    }
    return 0;
}


