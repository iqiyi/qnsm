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
#include <rte_icmp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_timer.h>

#include "cJSON.h"
#include "util.h"
#include "qnsm_dbg.h"
#include "app.h"
#include "qnsm_service_ex.h"
#include "qnsm_msg_ex.h"
#include "tcp_session.h"
#include "qnsm_session.h"

#define TCP_CONN_PER_LCORE_MAX  (131072UL)

uint64_t g_established_stream_count = 0;

static inline int
before(u_int seq1, u_int seq2)
{
    return ((int)(seq1 - seq2) < 0);
}

static inline int
after(u_int seq1, u_int seq2)
{
    return ((int)(seq2 - seq1) < 0);
}

/*
*https://github.com/google/gopacket/blob/master/tcpassembly/assembly.go
*seq rollover??
*/
int32_t packet_sequence_diff (uint32_t a, uint32_t b)
{
    if (a > 0xc0000000 && b < 0x40000000)
        return (a + 0xffffffffLL - b);

    if (b > 0xc0000000 && a < 0x40000000)
        return (a - b - 0xffffffffLL);

    return b - a;
}

/* 释放 */
static void purge_queue(struct half_stream * h)
{
    struct skbuff *tmp, *p = h->list;

    while (p) {
        if(p->data) {
            free(p->data);
            p->data = NULL;
        }
        tmp = p->next;
        free(p);
        p = NULL;
        p = tmp;
    }
}

#ifdef __FLOW_LIFE_STATTIS
static inline void tcp_on_established(TCP_STREAM *ts, void *sess)
{
    ts->established = 1;
    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "tcp established\n");
    return;
}

static inline void tcp_on_rst(TCP_STREAM *ts, void *sess)
{
    if (0 != ts->active.state) {
        (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                               QNSM_MSG_SESS_LIFE_STATIS,
                               sess,
                               ((QNSM_SESS *)sess)->af,
                               1);
    }
    return;
}

static inline void tcp_on_fin_ack(TCP_STREAM *ts, void *sess)
{
    if (0 != ts->active.state) {
        (void)qnsm_msg_send_lb(EN_QNSM_EDGE,
                               QNSM_MSG_SESS_LIFE_STATIS,
                               sess,
                               ((QNSM_SESS *)sess)->af,
                               1);
    }
    return;
}

#endif

/*释放连接*/
void tcp_free_stream(TCP_STREAM **ts)
{
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    TCP_CACHE *cache = &sess_data->tcp_data;
    TCP_STREAM *tcp_stream = *ts;

    purge_queue(&tcp_stream->active);
    purge_queue(&tcp_stream->passive);

    rte_mempool_put(cache->tcp_conn_cache, (void *)tcp_stream);
#ifdef  DEBUG_QNSM
    tcp_stream->dump_enable = 0;
#endif
    return;
}

void tcp_check_timeouts(void **item)
{
    TCP_STREAM *ts = *item;

    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "aging conn %p\n", ts);
    tcp_free_stream(&ts);
    *item = NULL;

    return;
}

static int get_ts(struct tcp_hdr * this_tcphdr, unsigned int * ts)
{
    int len = 4 * (this_tcphdr->data_off >> 4);
    unsigned int tmp_ts;
    unsigned char * options = (unsigned char*)(this_tcphdr + 1);
    int ind = 0, ret = 0;
    while (ind <=  len - (int)sizeof (struct tcp_hdr) - 10 )
        switch (options[ind]) {
            case 0: /* TCPOPT_EOL */
                return ret;
            case 1: /* TCPOPT_NOP */
                ind++;
                continue;
            case 8: /* TCPOPT_TIMESTAMP */
                rte_memcpy((char*)&tmp_ts, options + ind + 2, 4);
                *ts=ntohl(tmp_ts);
                ret = 1;
            /* no break, intentionally */
            default:
                if (options[ind+1] < 2 ) /* "silly option" */
                    return ret;
                ind += options[ind+1];
        }

    return ret;
}

static int get_wscale(struct tcp_hdr * this_tcphdr, unsigned int * ws)
{
    int len = 4 * (this_tcphdr->data_off >> 4);
    unsigned int tmp_ws;
    unsigned char * options = (unsigned char*)(this_tcphdr + 1);
    int ind = 0, ret = 0;
    *ws=1;
    while (ind <=  len - (int)sizeof (struct tcp_hdr) - 3 )
        switch (options[ind]) {
            case 0: /* TCPOPT_EOL */
                return ret;
            case 1: /* TCPOPT_NOP */
                ind++;
                continue;
            case 3: /* TCPOPT_WSCALE */
                tmp_ws=options[ind+2];
                if (tmp_ws>14)
                    tmp_ws=14;
                *ws=1<<tmp_ws;
                ret = 1;
            /* no break, intentionally */
            default:
                if (options[ind+1] < 2 ) /* "silly option" */
                    return ret;
                ind += options[ind+1];
        }

    return ret;
}

inline int32_t tcp_proc_check(QNSM_PACKET_INFO* pkt_info, uint32_t *data_len)
{
    uint32_t ret = 0;
    uint32_t datalen = 0;
    uint32_t iplen;
    uint32_t ip_hdr_len = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct ipv4_hdr *this_iphdr = NULL;
    struct tcp_hdr *this_tcphdr = NULL;

    if (EN_QNSM_AF_IPv4 != pkt_info->af) {
        return 0;
    }

    this_iphdr  = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, pkt_info->l3_offset);
    ip_hdr_len = ((this_iphdr->version_ihl) & 0x0F) << 2;
    this_tcphdr = (struct tcp_hdr *)((char *)this_iphdr + ip_hdr_len);

    /*tcp hdr check*/
    iplen = ntohs(this_iphdr->total_length);
    if ((unsigned)iplen < (ip_hdr_len + sizeof(struct tcp_hdr))) {
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "check hdr len failed\n");
        ret = -1;
        goto EXIT;
    }

    datalen = iplen - ip_hdr_len - ((this_tcphdr->data_off >> 4) << 2);
    if (datalen < 0) {
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "check datalen failed\n");
        ret = -1;
        goto EXIT;
    }

    if ((this_iphdr->src_addr | this_iphdr->dst_addr) == 0) {
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "check addr failed\n");
        ret = -1;
        goto EXIT;
    }

    /*
    if ((this_tcphdr->tcp_flags & TH_SYN)
        || (this_tcphdr->tcp_flags & TH_FIN))
    {
        datalen += 1;
    }
    */
EXIT:
    *data_len = datalen;
    return ret;
}

int32_t tcp_conn_proc(QNSM_PACKET_INFO* pkt_info, void *sess, uint32_t *tcp_seq)
{
    uint32_t from_active = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct tcp_hdr *this_tcphdr = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    TCP_STREAM *tcp_conn = NULL;
    uint16_t sport = 0;
    uint16_t dport = 0;
    int32_t ret = 0;
    uint32_t recv_ack = ntohl(this_tcphdr->recv_ack);
    uint32_t seq = ntohl(this_tcphdr->sent_seq);
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    TCP_CACHE *cache = &sess_data->tcp_data;
    QNSM_SESS *session = sess;

    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "enter seq %u ack %u\n", seq, recv_ack);
    tcp_conn = session->tcp_stream;
    if (NULL == tcp_conn) {
        if ((this_tcphdr->tcp_flags & TH_SYN) &&
            !(this_tcphdr->tcp_flags & TH_ACK) &&
            !(this_tcphdr->tcp_flags & TH_RST) &&
            !(this_tcphdr->tcp_flags & TH_FIN)) {
            /*now only recvd syn pkt, create tcp conn.
            * whether need consider this situation,
            * if syn missed, but rcvd syn+ack pkt
            */
            if (rte_mempool_get(cache->tcp_conn_cache, (void **)&tcp_conn)) {
                QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_ERR, "failed\n");
                ret = -1;
                goto EXIT;
            }

            /*set addr only for state proc*/
            sport = pkt_info->sport;
            dport = pkt_info->dport;
            tcp_conn->af = pkt_info->af;
            if (EN_QNSM_AF_IPv4 == pkt_info->af) {
                tcp_conn->addr.v4_5tuple.ip_src = pkt_info->v4_src_ip;
                tcp_conn->addr.v4_5tuple.ip_dst = pkt_info->v4_dst_ip;
                tcp_conn->addr.v4_5tuple.port_src = sport;
                tcp_conn->addr.v4_5tuple.port_dst = dport;
                QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "tcp_flag %x, add conn sip %x dip %x sport %u dport %u, conn %p, sess->tcp_stream %p, sess %p\n",
                           this_tcphdr->tcp_flags,
                           pkt_info->v4_src_ip,
                           pkt_info->v4_dst_ip,
                           sport,
                           dport,
                           tcp_conn,
                           session->tcp_stream,
                           session);
#ifdef  DEBUG_QNSM
#endif
            } else {
                rte_memcpy(tcp_conn->addr.v6_5tuple.ip_src, pkt_info->v6_src_ip, IPV6_ADDR_LEN);
                rte_memcpy(tcp_conn->addr.v6_5tuple.ip_dst, pkt_info->v6_dst_ip, IPV6_ADDR_LEN);
                tcp_conn->addr.v6_5tuple.port_src = sport;
                tcp_conn->addr.v6_5tuple.port_dst = dport;
            }

            /*init conn*/
            tcp_conn->active.state = QNSM_TCP_CLOSE;
            tcp_conn->passive.state = QNSM_TCP_CLOSE;

            /*fsm proc*/
            tcp_conn->active.state = QNSM_TCP_SYN_SENT;
            tcp_conn->active.seq = seq + 1;

            /*set seq*/
            tcp_seq[pkt_info->sess_dir % 2] =  tcp_conn->active.seq;
            ret = 1;
        } else {
            QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "not match sess tcp_flag %x\n", this_tcphdr->tcp_flags);

            /*
            *if capture not from syn, just in middle
            */
#if 0
            tcp_seq[pkt_info->sess_dir % 2] = ntohl(this_tcphdr->sent_seq);
            ret = 0;
#else
            ret = -1;
#endif
        }
        goto EXIT;
    }

#ifdef  DEBUG_QNSM
    if (tcp_conn->dump_enable) {
        pkt_info->need_dump = 1;
    }
#endif

    /* passive reply syn ack */
    if ((this_tcphdr->tcp_flags & TH_SYN)) {
        /*active state syn_sent
        * passive state close
        * pkt flag ack bit
        */
        if (tcp_conn->active.state != QNSM_TCP_SYN_SENT ||
            tcp_conn->passive.state != QNSM_TCP_CLOSE ||
            !(this_tcphdr->tcp_flags & TH_ACK)) {
            ret = -1;
            goto EXIT;
        }

        if (tcp_conn->active.seq != recv_ack) {
            QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_ERR, "active seq = %u  passive recv_ack = %u \n",
                       tcp_conn->active.seq, recv_ack);
            ret = -1;
            goto EXIT;
        }
        tcp_conn->passive.state = QNSM_TCP_SYN_RECV;
        tcp_conn->passive.seq = seq + 1;
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "CONN: %p tcp_flag %x passive state change to SYN_RCV\n",
                   tcp_conn, this_tcphdr->tcp_flags);

        /*set seq*/
#if 0
        tcp_seq[(pkt_info->sess_dir + 1) % 2] =  recv_ack;
#else
        tcp_seq[pkt_info->sess_dir % 2] = tcp_conn->passive.seq;
#endif
        ret = 1;
        goto EXIT;
    }

    if ((tcp_conn->addr.v4_5tuple.ip_src == pkt_info->v4_src_ip)
        && (tcp_conn->addr.v4_5tuple.ip_dst == pkt_info->v4_dst_ip)) {
        from_active = 1;
    }

    /* rst*/
    if ((this_tcphdr->tcp_flags & TH_RST)) {
        /*
        *rst flood isnpect, need check seq
        */
        if (packet_sequence_diff(seq, tcp_seq[pkt_info->sess_dir]) < 0) {
            ret = -1;
            goto EXIT;
        }

        if(from_active) {
            tcp_conn->active.state = QNSM_TCP_FIN_CONFIRMED;
        } else {
            tcp_conn->passive.state = QNSM_TCP_FIN_CONFIRMED;
        }
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "CONN: %p tcp_flag %x rcv rst from active %u\n",
                   tcp_conn,
                   this_tcphdr->tcp_flags,
                   from_active);

        if (cache->cb.f_on_rst) {
            cache->cb.f_on_rst(tcp_conn, session);
        }
        ret = 1;
        goto EXIT;
    }

    /* active response ack */
    if (from_active && (this_tcphdr->tcp_flags & TH_ACK)) {
        if ((tcp_conn->active.state == QNSM_TCP_SYN_SENT) &&
            (tcp_conn->passive.state == QNSM_TCP_SYN_RECV)) {
            if (ntohl(this_tcphdr->recv_ack) == tcp_conn->passive.seq) {
                if (EN_QNSM_AF_IPv4 == pkt_info->af) {
                    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "CONN: SRC %x DST %x src_port %u dst_port %u established\n",
                               tcp_conn->addr.v4_5tuple.ip_src,
                               tcp_conn->addr.v4_5tuple.ip_dst,
                               tcp_conn->addr.v4_5tuple.port_src,
                               tcp_conn->addr.v4_5tuple.port_dst);
                }

                /* ---------------连接建立成功---------------- */
                tcp_conn->active.state = QNSM_TCP_ESTABLISHED;

#ifdef  DEBUG_QNSM
                g_established_stream_count++;
#endif
                tcp_conn->passive.state = QNSM_TCP_ESTABLISHED;

                if (cache->cb.f_on_established) {
                    cache->cb.f_on_established(tcp_conn, session);
                }
            }
        }
    }

    /*
    *PUSH ACK
    *FIN ACK
    *rst ack
    */
    if ((this_tcphdr->tcp_flags & TH_ACK)) {
        /*zero window*/
        if ((0 == this_tcphdr->rx_win)
            && (QNSM_TCP_ESTABLISHED == tcp_conn->active.state)
            && (QNSM_TCP_ESTABLISHED == tcp_conn->passive.state)) {

            if (EN_QNSM_AF_IPv4 == pkt_info->af) {
                QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_WARN, "CONN: SRC 0x%x DST 0x%x src_port %u dst_port %u zero window occured\n",
                           tcp_conn->addr.v4_5tuple.ip_src,
                           tcp_conn->addr.v4_5tuple.ip_dst,
                           tcp_conn->addr.v4_5tuple.port_src,
                           tcp_conn->addr.v4_5tuple.port_dst);

            }
        }

        if (from_active && tcp_conn->passive.state == QNSM_TCP_FIN_SENT) {
            tcp_conn->passive.state = QNSM_TCP_FIN_CONFIRMED;
        }
        if (!from_active && tcp_conn->active.state == QNSM_TCP_FIN_SENT) {
            tcp_conn->active.state = QNSM_TCP_FIN_CONFIRMED;
        }
        if ((tcp_conn->passive.state == QNSM_TCP_FIN_CONFIRMED)
            && (tcp_conn->active.state == QNSM_TCP_FIN_CONFIRMED)) {
            if (cache->cb.f_on_fin_ack) {
                cache->cb.f_on_fin_ack(tcp_conn, session);
            }
            QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "CONN: SRC %x DST %x src_port %u dst_port %u free, conn %p\n",
                       tcp_conn->addr.v4_5tuple.ip_src,
                       tcp_conn->addr.v4_5tuple.ip_dst,
                       tcp_conn->addr.v4_5tuple.port_src,
                       tcp_conn->addr.v4_5tuple.port_dst,
                       tcp_conn);
            tcp_free_stream(&tcp_conn);
            tcp_conn = NULL;
            ret = 1;
            goto EXIT;
        }
    }

    /*fin*/
    if(this_tcphdr->tcp_flags & TH_FIN) {
        if(from_active) {
            tcp_conn->active.state = QNSM_TCP_FIN_SENT;
        } else {
            tcp_conn->passive.state = QNSM_TCP_FIN_SENT;
        }
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_EVT, "CONN: %p tcp_flag %x rcv fin from active %u\n",
                   tcp_conn,
                   this_tcphdr->tcp_flags,
                   from_active);
    }

EXIT:
    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "leave ret %d\n", ret);
    session->tcp_stream = tcp_conn;
    return ret;
}

inline void tcp_free_data(TCP_DATA *data)
{
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    TCP_CACHE *cache = &sess_data->tcp_data;
    if (data) {
        /*del node*/
        qnsm_list_del_init(&data->node);
        cache->cur_pkt_num--;

        /*free*/
        rte_mempool_put(cache->pkt_info_cache, (void *)data);
    }
    return;
}

int32_t tcp_data_proc(QNSM_PACKET_INFO* pkt_info, QNSM_TCP_DATA_QUE *que, uint32_t dir, uint32_t payload_len)
{

    struct tcp_hdr *this_tcphdr = NULL;
    uint32_t seq = 0;
    uint32_t ack = 0;
    TCP_DATA *cur_tcp_data = NULL;
    TCP_DATA *tmp_tcp_data = NULL;
    TCP_DATA *n = NULL;
    uint32_t sort1;
    uint32_t sort2;
    int32_t diff = 0;
    uint32_t same_dir = 0;
    int32_t ret = 0;
    QNSM_SESS_DATA *sess_data = qnsm_app_data(EN_QNSM_SESSM);
    TCP_CACHE *cache = &sess_data->tcp_data;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    uint16_t sport = 0;
    uint16_t dport = 0;

    QNSM_ASSERT(pkt_info);
    QNSM_ASSERT(que);
    QNSM_ASSERT(dir < 2);

    this_tcphdr = rte_pktmbuf_mtod_offset(mbuf, struct tcp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    sport = pkt_info->sport;
    dport = pkt_info->dport;
    sport = sport;
    dport = dport;
    seq = ntohl(this_tcphdr->sent_seq);
    ack = ntohl(this_tcphdr->recv_ack);

    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "dir %u seq %u ack %u payload %u\n", dir, seq, ack, payload_len);

    if (payload_len <= 0) {
        ret = -1;
        goto EXIT;
    }

    if (cache->cur_pkt_num >= cache->max_pkt_num) {
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_WARN, "sess lcore %u reach reassemble pkt uplimit\n", pkt_info->lcore_id);
        ret = -1;
        goto EXIT;
    }

    if (que->data_cnt > 8) {
        /*tcp que exceed*/
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_ERR, "sess (%x %u %x %u) exceed max reasemble que len!!\n",
                   pkt_info->v4_src_ip,
                   sport,
                   pkt_info->v4_dst_ip,
                   dport);
        qnsm_list_for_each_entry_safe(tmp_tcp_data, n, &que->tcp_que, node) {
            rte_pktmbuf_free((struct rte_mbuf *)((char *)tmp_tcp_data->pkt_info - sizeof(struct rte_mbuf)));
            tcp_free_data(tmp_tcp_data);
        }
        que->data_cnt = 0;
        ret = -1;
        goto EXIT;
    }

    /*whether to add reassemble que*/
    if (rte_mempool_get(cache->pkt_info_cache, (void **)&cur_tcp_data)) {
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_ERR, "get tcp node failed\n");
        ret = -1;
        goto EXIT;
    }

    QNSM_INIT_LIST_HEAD(&cur_tcp_data->node);
    cur_tcp_data->seq = seq;
    cur_tcp_data->ack = ack;
    cur_tcp_data->len = payload_len;
    cur_tcp_data->dir = dir;
    cur_tcp_data->pkt_info = pkt_info;
    if (qnsm_list_empty(&que->tcp_que)) {
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "(%x %u %x %u) add que dir: %d seq: %u ack: %u len: %d\n",
                   pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
                   dir, seq, ack, payload_len);
        qnsm_list_add_tail(&cur_tcp_data->node, &que->tcp_que);
        que->data_cnt++;
        cache->cur_pkt_num++;
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "(%x %u %x %u) que addr %p, que next %p, cur_tcp_data_node_addr %p, cur_node_next %p\n",
                   pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
                   &que->tcp_que, que->tcp_que.next, &cur_tcp_data->node, cur_tcp_data->node.next);
    } else {
        qnsm_list_for_each_prev_entry(tmp_tcp_data, &que->tcp_que, node) {
            same_dir = (dir == tmp_tcp_data->dir);
            sort1 = cur_tcp_data->seq;
            if (same_dir) {
                sort2 = tmp_tcp_data->seq;
            } else {
                sort2 = tmp_tcp_data->ack;
            }
            diff = packet_sequence_diff(sort2, sort1);
            if (0 < diff) {
                if ((same_dir) &&
                    ((cur_tcp_data->seq + cur_tcp_data->len) <= (tmp_tcp_data->seq + tmp_tcp_data->len))) {
                    rte_mempool_put(cache->pkt_info_cache, (void *)cur_tcp_data);
                    ret = -1;
                    goto EXIT;
                }
                QNSM_LIST_ADD_AFTER(&cur_tcp_data->node, &tmp_tcp_data->node);
                que->data_cnt++;
                cache->cur_pkt_num++;
                QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "(%x %u %x %u) add que dir: %d seq: %u ack: %u len: %d diff seq: %d\n",
                           pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
                           dir, seq, ack, payload_len, diff);
                break;
            } else if (0 == diff) {
                if (same_dir) {
                    if (cur_tcp_data->len > tmp_tcp_data->len) {
                        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "(%x %u %x %u) add que dir: %d seq: %u ack: %u len: %d diff seq: %d\n",
                                   pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
                                   dir, seq, ack, payload_len, diff);
                        QNSM_LIST_ADD_AFTER(&cur_tcp_data->node, &tmp_tcp_data->node);
                        cache->cur_pkt_num++;

                        /*del*/
                        rte_pktmbuf_free((struct rte_mbuf *)((char *)tmp_tcp_data->pkt_info - sizeof(struct rte_mbuf)));
                        tcp_free_data(tmp_tcp_data);
                    } else {
                        /*
                        * cur_tcp_data->len <= tmp_tcp_data->len
                        * dup pkt, not proc
                        */
                        rte_mempool_put(cache->pkt_info_cache, (void *)cur_tcp_data);
                        ret = -1;
                        goto EXIT;
                    }
                    break;
                } else {
                    /*
                    * cur_tcp_data->ack == tmp_tcp_data->seq
                    * dup ack, continue mov prev
                    *
                    */
                    if (0 < packet_sequence_diff(tmp_tcp_data->seq, cur_tcp_data->ack)) {
                        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "(%x %u %x %u) add que dir: %d seq: %u ack: %u len: %d diff seq: %d\n",
                                   pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
                                   dir, seq, ack, payload_len, diff);
                        QNSM_LIST_ADD_AFTER(&cur_tcp_data->node, &tmp_tcp_data->node);
                        que->data_cnt++;
                        cache->cur_pkt_num++;
                        break;
                    }
                }

            }
        }

        if (&tmp_tcp_data->node == &que->tcp_que) {
            QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "(%x %u %x %u) add que dir: %d seq: %u ack: %u len: %d diff seq: %d\n",
                       pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
                       dir, seq, ack, payload_len, diff);
            QNSM_LIST_ADD_AFTER(&cur_tcp_data->node, &tmp_tcp_data->node);
            que->data_cnt++;
            cache->cur_pkt_num++;
        }
    }

EXIT:
    QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_INFO, "leave (%x %u %x %u) add data cnt %u ret %d\n",
               pkt_info->v4_src_ip, sport, pkt_info->v4_dst_ip, dport,
               que->data_cnt, ret);
    return ret;
}

void qnsm_tcp_conn_init(struct rte_mempool *mp,
                        __attribute__((unused)) void *opaque_arg,
                        void *_m,
                        __attribute__((unused)) unsigned i)
{
    char *m = _m;

    memset(m, 0, mp->elt_size);
    return;
}

void qnsm_tcp_data_init(struct rte_mempool *mp,
                        __attribute__((unused)) void *opaque_arg,
                        void *_m,
                        __attribute__((unused)) unsigned i)
{

    char *m = _m;
    TCP_DATA *data = _m;

    memset(m, 0, mp->elt_size);
    QNSM_INIT_LIST_HEAD(&data->node);
    return;
}

int32_t tcp_lcore_init(int32_t lcore_id, TCP_CACHE *cache)
{
    char name[64];
    TCP_CACHE lcore_cache = {0};
    int32_t ret = 0;
    uint32_t socket_id = rte_lcore_to_socket_id(lcore_id);
    uint32_t pool_size = 0;
    uint8_t deploy_num = 0;

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_TCP, QNSM_DBG_ALL);
    /*tcp conn
    *use mempool per lcore!!
    *
    *because rte_malloc/free used spinlock,
    *cause thread syn when sess num increases,
    *finally cause pkt loss
    *
    */
    snprintf(name, sizeof(name), "tcp_conn_%d", lcore_id);
    lcore_cache.tcp_conn_cache = rte_mempool_create(name,
                                 TCP_CONN_PER_LCORE_MAX,
                                 sizeof(TCP_STREAM),
                                 APP_DEFAULT_MEMPOOL_CACHE_SIZE,
                                 0,
                                 NULL, NULL,
                                 qnsm_tcp_conn_init, NULL,
                                 socket_id, 0);
    if (NULL == lcore_cache.tcp_conn_cache) {
        ret = -1;
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_ERR, "tcp conn cache init failed\n");
        goto EXIT;
    }
    cache->tcp_conn_cache = lcore_cache.tcp_conn_cache;

    /*tcp pkt info*/
    snprintf(name, sizeof(name), "tcp_pktinfo_%d", lcore_id);
    lcore_cache.pkt_info_cache = rte_mempool_create(name,
                                 TCP_CONN_PER_LCORE_MAX,
                                 sizeof(TCP_DATA),
                                 APP_DEFAULT_MEMPOOL_CACHE_SIZE,
                                 0,
                                 NULL, NULL,
                                 qnsm_tcp_data_init, NULL,
                                 socket_id, 0);

    if (NULL == lcore_cache.pkt_info_cache) {
        ret = -1;
        QNSM_DEBUG(QNSM_DBG_M_TCP, QNSM_DBG_ERR, "tcp pkt info cache init failed\n");
        goto EXIT;
    }
    cache->pkt_info_cache = lcore_cache.pkt_info_cache;

    cache->cur_pkt_num = 0;
    pool_size = app_mempool_get_pool_size(qnsm_service_get_cfg_para(), socket_id);
    deploy_num = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_SESSM);
    cache->max_pkt_num = (pool_size - (pool_size >> 3)) / deploy_num;
    printf("sessm deploy num is %u, lcore %u max reassemble pkt %" PRIu64 "\n",
           deploy_num, lcore_id, cache->max_pkt_num);

#ifdef __FLOW_LIFE_STATTIS
    cache->cb.f_on_established = tcp_on_established;
    cache->cb.f_on_rst = NULL;
    cache->cb.f_on_fin_ack = tcp_on_fin_ack;
#else
    cache->cb.f_on_established = NULL;
    cache->cb.f_on_rst = NULL;
    cache->cb.f_on_fin_ack = NULL;
#endif

EXIT:
    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);
    return ret;
}
