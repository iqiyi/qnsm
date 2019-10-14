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
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_decode.h"

int qnsm_decode_ipv4(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len);
int qnsm_decode_ipv6(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len);
int qnsm_decode_vlan(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len);

#if QNSM_PART("GRE")

/**
 * \brief Function to decode GRE packets
 */

int qnsm_decode_gre(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    uint16_t header_len = GRE_HDR_LEN;
    GRESreHdr *gsre = NULL;
    GREHdr *greh = NULL;

    if(len < GRE_HDR_LEN) {
        return QNSM_DECODE_FAILED;
    }

    greh = (GREHdr *)pkt;
    if(greh == NULL)
        return QNSM_DECODE_FAILED;

    QNSM_DEBUG(QNSM_DBG_M_DECODE_PKT, QNSM_DBG_PKT, "pkt %p GRE protocol %04x Len: %d GRE version %x",
               pkt, GRE_GET_PROTO(greh), len,GRE_GET_VERSION(greh));

    switch (GRE_GET_VERSION(greh)) {
        case GRE_VERSION_0:

            /* GRE version 0 doenst support the fields below RFC 1701 */

            if (GRE_FLAG_ISSET_RECUR(greh)) {
                return QNSM_DECODE_FAILED;
            }

            if (GREV1_FLAG_ISSET_FLAGS(greh)) {
                return QNSM_DECODE_FAILED;
            }

            /* Adjust header length based on content */

            if (GRE_FLAG_ISSET_KY(greh))
                header_len += GRE_KEY_LEN;

            if (GRE_FLAG_ISSET_SQ(greh))
                header_len += GRE_SEQ_LEN;

            if (GRE_FLAG_ISSET_CHKSUM(greh) || GRE_FLAG_ISSET_ROUTE(greh))
                header_len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

            if (header_len > len) {
                return QNSM_DECODE_FAILED;
            }

            if (GRE_FLAG_ISSET_ROUTE(greh)) {
                while (1) {
                    if ((header_len + GRE_SRE_HDR_LEN) > len) {
                        return QNSM_DECODE_FAILED;
                    }

                    gsre = (GRESreHdr *)(pkt + header_len);

                    header_len += GRE_SRE_HDR_LEN;

                    if ((ntohs(gsre->af) == 0) && (gsre->sre_length == 0))
                        break;

                    header_len += gsre->sre_length;
                    if (header_len > len) {
                        return QNSM_DECODE_FAILED;
                    }
                }
            }
            break;

        case GRE_VERSION_1:

            /* GRE version 1 doenst support the fields below RFC 1701 */

            if (GRE_FLAG_ISSET_CHKSUM(greh)) {
                return QNSM_DECODE_FAILED;
            }

            if (GRE_FLAG_ISSET_ROUTE(greh)) {
                return QNSM_DECODE_FAILED;
            }

            if (GRE_FLAG_ISSET_SSR(greh)) {
                return QNSM_DECODE_FAILED;
            }

            if (GRE_FLAG_ISSET_RECUR(greh)) {
                return QNSM_DECODE_FAILED;
            }

            if (GREV1_FLAG_ISSET_FLAGS(greh)) {
                return QNSM_DECODE_FAILED;
            }

            if (GRE_GET_PROTO(greh) != GRE_PROTO_PPP) {
                return QNSM_DECODE_FAILED;
            }

            if (!(GRE_FLAG_ISSET_KY(greh))) {
                return QNSM_DECODE_FAILED;
            }

            header_len += GRE_KEY_LEN;

            /* Adjust header length based on content */

            if (GRE_FLAG_ISSET_SQ(greh))
                header_len += GRE_SEQ_LEN;

            if (GREV1_FLAG_ISSET_ACK(greh))
                header_len += GREV1_ACK_LEN;

            if (header_len > len) {
                return QNSM_DECODE_FAILED;
            }

            break;
        default:
            return QNSM_DECODE_FAILED;
    }

    switch (GRE_GET_PROTO(greh)) {
        case ETHERNET_TYPE_IP: {
            qnsm_decode_ipv4(pkt_info, pkt + header_len, len - header_len);
            break;
        }

        case ETHERNET_TYPE_IPV6: {
            qnsm_decode_ipv6(pkt_info, pkt + header_len, len - header_len);
            break;
        }

        case ETHERNET_TYPE_8021Q: {
            qnsm_decode_vlan(pkt_info, pkt + header_len, len - header_len);
            break;
        }

        case ETHERNET_TYPE_BRIDGE: {
            qnsm_decode_ethernet(pkt_info, pkt + header_len, len - header_len);
            break;
        }

        default:
            return QNSM_DECODE_FAILED;
    }
    return QNSM_DECODE_OK;
}
#endif

#if QNSM_PART("ICMPV4")
/** DecodeICMPV4
 *  \brief Main ICMPv4 decoding function
 */
int qnsm_decode_icmpv4(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    if (len < ICMPV4_HEADER_LEN) {
        return QNSM_DECODE_FAILED;
    }

    QNSM_DEBUG(QNSM_DBG_M_DECODE_PKT, QNSM_DBG_INFO, "ICMPV4 TYPE %" PRIu32 " CODE %" PRIu32 "",
               ((ICMPV4Hdr *)pkt)->type, ((ICMPV4Hdr *)pkt)->code);

    pkt_info->sport = 0;
    pkt_info->dport = 0;
    pkt_info->payload = pkt + ICMPV4_HEADER_LEN;

    return QNSM_DECODE_OK;
}
#endif

#if QNSM_PART("UDP")
static int DecodeUDPPacket(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    UDPHdr *udph = NULL;
    if (unlikely(len < UDP_HEADER_LEN)) {
        return -1;
    }

    udph = (UDPHdr *)pkt;

    if (unlikely(len < UDP_GET_LEN(udph))) {
        return -1;
    }

    if (unlikely(len != UDP_GET_LEN(udph))) {
        return -1;
    }

    pkt_info->sport = UDP_GET_SRC_PORT(udph);
    pkt_info->dport = UDP_GET_DST_PORT(udph);
    pkt_info->payload = pkt + UDP_HEADER_LEN;

    QNSM_DEBUG(QNSM_DBG_M_DECODE_PKT, QNSM_DBG_PKT, "UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 "",
               UDP_GET_SRC_PORT(udph), UDP_GET_DST_PORT(udph), UDP_HEADER_LEN, len - UDP_HEADER_LEN);

    return 0;
}

int qnsm_decode_udp(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    if (unlikely(DecodeUDPPacket(pkt_info, pkt, len) < 0)) {
        return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}

#endif

#if QNSM_PART("TCP")
static int DecodeTCPPacket(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    TCPHdr *tcph = NULL;

    if (unlikely(len < TCP_HEADER_LEN)) {
        return -1;
    }

    tcph = (TCPHdr *)pkt;

    uint8_t hlen = TCP_GET_HLEN(tcph);
    if (unlikely(len < hlen)) {
        return -1;
    }

    uint8_t tcp_opt_len = hlen - TCP_HEADER_LEN;
    if (unlikely(tcp_opt_len > TCP_OPTLENMAX)) {
        return -1;
    }

    pkt_info->payload = pkt + hlen;
    pkt_info->sport = TCP_GET_SRC_PORT(tcph);
    pkt_info->dport = TCP_GET_DST_PORT(tcph);

    return 0;
}

int qnsm_decode_tcp(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    if (unlikely(DecodeTCPPacket(pkt_info,pkt,len) < 0)) {
        QNSM_DEBUG(QNSM_DBG_M_DECODE_PKT, QNSM_DBG_ERR, "invalid TCP packet");
        return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}
#endif

#if QNSM_PART("IPV4")

#define SET_IPV4_DST_ADDR(ip4h, a) do {                                \
        (a)->in4_addr.s_addr = ntohl((uint32_t)ip4h->s_ip_dst.s_addr); \
    } while (0)
#define SET_IPV4_SRC_ADDR(ip4h, a) do {                                    \
            (a)->in4_addr.s_addr = ntohl((uint32_t)ip4h->s_ip_src.s_addr); \
        } while (0)
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

static int DecodeIPV4Packet(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    struct rte_mbuf *m = NULL;
    IPV4Hdr *ip4h = NULL;

    if (unlikely(len < sizeof(IPV4Hdr))) {
        return -1;
    }

    if (unlikely(IP_GET_RAW_VER(pkt) != 4)) {
        QNSM_DEBUG(QNSM_DBG_M_DECODE_PKT, QNSM_DBG_ERR, "wrong ip version %" PRIu8 "",IP_GET_RAW_VER(pkt));
        return -1;
    }

    ip4h = (IPV4Hdr *)pkt;

    if (unlikely(IPV4_GET_HLEN(ip4h) < sizeof(IPV4Hdr))) {
        return -1;
    }

    if (unlikely(IPV4_GET_IPLEN(ip4h) < IPV4_GET_HLEN(ip4h))) {
        return -1;
    }

    if (unlikely(len < IPV4_GET_IPLEN(ip4h))) {
        return -1;
    }

    /* check the options len */
    uint8_t ip_opt_len = IPV4_GET_HLEN(ip4h) - sizeof(IPV4Hdr);
    if (ip_opt_len > 0) {
        return -1;
    }

    /* set the address struct */
    m = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    SET_IPV4_SRC_ADDR(ip4h, &pkt_info->src_addr);
    SET_IPV4_DST_ADDR(ip4h, &pkt_info->dst_addr);
    pkt_info->l3_offset = (char *)ip4h - rte_pktmbuf_mtod(m, char *);
    pkt_info->l3_len = IPV4_GET_HLEN(ip4h);
    pkt_info->af = EN_QNSM_AF_IPv4;

    return 0;
}

int qnsm_decode_ipv4(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)pkt;

    /* do the actual decoding */
    if (unlikely(DecodeIPV4Packet (pkt_info, pkt, len) < 0)) {
        QNSM_DEBUG(QNSM_DBG_M_DECODE_PKT, QNSM_DBG_ERR, "decoding IPv4 packet failed");
        return QNSM_DECODE_FAILED;
    }
    pkt_info->proto = IPV4_GET_IPPROTO(ip4h);

    /* If a fragment, set frag bit. */
    if (unlikely(IPV4_GET_IPOFFSET(ip4h) > 0 || IPV4_GET_MF(ip4h) == 1)) {
        pkt_info->is_frag = 1;
        return QNSM_DECODE_OK;
    }

    /* check what next decoder to invoke */
    switch (IPV4_GET_IPPROTO(ip4h)) {
        case IPPROTO_TCP:
            qnsm_decode_tcp(pkt_info, pkt + IPV4_GET_HLEN(ip4h),
                            IPV4_GET_IPLEN(ip4h) - IPV4_GET_HLEN(ip4h));
            break;
        case IPPROTO_UDP:
            qnsm_decode_udp(pkt_info, pkt + IPV4_GET_HLEN(ip4h),
                            IPV4_GET_IPLEN(ip4h) - IPV4_GET_HLEN(ip4h));
            break;
        case IPPROTO_ICMP:
            qnsm_decode_icmpv4(pkt_info, pkt + IPV4_GET_HLEN(ip4h),
                               IPV4_GET_IPLEN(ip4h) - IPV4_GET_HLEN(ip4h));
            break;
        case IPPROTO_GRE:
            qnsm_decode_gre(pkt_info, pkt + IPV4_GET_HLEN(ip4h),
                            IPV4_GET_IPLEN(ip4h) - IPV4_GET_HLEN(ip4h));
            break;
        default:
            return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}
#endif

#if QNSM_PART("IPV6")

/* parse ipv6 extended headers, update offset and return next proto */
static uint16_t
qnsm_skip_ip6_ext(uint16_t proto, const struct rte_mbuf *m, uint32_t *off,
                  int *frag)
{
    struct ext_hdr {
        uint8_t next_hdr;
        uint8_t len;
    };
    const struct ext_hdr *xh;
    struct ext_hdr xh_copy;
    unsigned int i;

    *frag = 0;

#define MAX_EXT_HDRS 5
    for (i = 0; i < MAX_EXT_HDRS; i++) {
        switch (proto) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
                xh = rte_pktmbuf_read(m, *off, sizeof(*xh),
                                      &xh_copy);
                if (xh == NULL)
                    return 0;
                *off += (xh->len + 1) * 8;
                proto = xh->next_hdr;
                break;
            case IPPROTO_FRAGMENT:
                xh = rte_pktmbuf_read(m, *off, sizeof(*xh),
                                      &xh_copy);
                if (xh == NULL)
                    return 0;
                *off += 8;
                proto = xh->next_hdr;
                *frag = 1;
                return proto; /* this is always the last ext hdr */
            case IPPROTO_NONE:
                return 0;
            default:
                return proto;
        }
    }
    return 0;
}

int qnsm_decode_ipv6(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    static const uint32_t ip6_ext_proto_map[256] = {
        [IPPROTO_HOPOPTS] = 1,
        [IPPROTO_ROUTING] = 1,
        [IPPROTO_FRAGMENT] = 1,
        [IPPROTO_ESP] = 1,
        [IPPROTO_AH] = 1,
        [IPPROTO_DSTOPTS] = 1,
    };
    const struct rte_mbuf *m = NULL;
    const struct ipv6_hdr *ip6h;
    int frag = 0;
    uint32_t l3_len = 0;
    uint32_t off = 0;
    uint8_t proto = 0;

    ip6h = (struct ipv6_hdr *)pkt;
    if (unlikely(ip6h == NULL))
        return QNSM_DECODE_FAILED;

    m = (const struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    proto = ip6h->proto;
    off += sizeof(*ip6h);
    if (ip6_ext_proto_map[proto]) {
        proto = qnsm_skip_ip6_ext(proto, m, &off, &frag);
        l3_len = off;
    }
    if (proto == 0)
        return QNSM_DECODE_FAILED;

    /*fill pkt info*/
    pkt_info->af = EN_QNSM_AF_IPv6;
    rte_memcpy(pkt_info->src_addr.in6_addr.s6_addr, ip6h->src_addr, IPV6_ADDR_LEN);
    rte_memcpy(pkt_info->dst_addr.in6_addr.s6_addr, ip6h->dst_addr, IPV6_ADDR_LEN);
    pkt_info->l3_offset = (char *)ip6h - rte_pktmbuf_mtod(m, char *);
    pkt_info->l3_len = l3_len;
    pkt_info->is_frag = frag;
    pkt_info->proto = proto;

    switch(proto) {
        case IPPROTO_TCP:
            qnsm_decode_tcp(pkt_info, pkt + l3_len,
                            len - l3_len);
            break;
        case IPPROTO_UDP:
            qnsm_decode_udp(pkt_info, pkt + l3_len,
                            len - l3_len);
            break;
        case IPPROTO_ICMPV6:
            break;
        default:
            return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}

#endif

/**
 * \internal
 * \brief this function is used to decode IEEE802.1q packets
 *
 * \param tv pointer to the thread vars
 * \param dtv pointer code thread vars
 * \param p pointer to the packet struct
 * \param pkt pointer to the raw packet
 * \param len packet len
 * \param pq pointer to the packet queue
 *
 */
int qnsm_decode_vlan(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    uint32_t proto;
    const struct vlan_hdr *vh = (const struct vlan_hdr *)pkt;

    proto = vh->eth_proto;
    switch (proto) {
        case ETHERNET_TYPE_IP:
            qnsm_decode_ipv4(pkt_info, pkt + sizeof(struct vlan_hdr),
                             len - sizeof(struct vlan_hdr));
            break;
        case ETHERNET_TYPE_IPV6:
            qnsm_decode_ipv6(pkt_info, pkt + sizeof(struct vlan_hdr),
                             len - sizeof(struct vlan_hdr));
            break;
        default:
            return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}

int qnsm_decode_qinq(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    uint32_t proto;
    const struct vlan_hdr *vh = (const struct vlan_hdr *)(pkt + sizeof(struct vlan_hdr));

    proto = vh->eth_proto;
    switch (proto) {
        case ETHERNET_TYPE_IP:
            qnsm_decode_ipv4(pkt_info, pkt + sizeof(struct vlan_hdr) * 2,
                             len - (sizeof(struct vlan_hdr) * 2));
            break;
        case ETHERNET_TYPE_IPV6:
            qnsm_decode_ipv4(pkt_info, pkt + sizeof(struct vlan_hdr) * 2,
                             len - (sizeof(struct vlan_hdr)* 2));
            break;
        default:
            return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}

#if QNSM_PART("MPLS")
#define MPLS_HEADER_LEN         4
#define MPLS_PW_LEN             4
#define MPLS_MAX_RESERVED_LABEL 15

#define MPLS_LABEL_IPV4         0
#define MPLS_LABEL_ROUTER_ALERT 1
#define MPLS_LABEL_IPV6         2
#define MPLS_LABEL_NULL         3

#define MPLS_LABEL(shim)        ntohl(shim) >> 12
#define MPLS_BOTTOM(shim)       ((ntohl(shim) >> 8) & 0x1)

/* Inner protocol guessing values. */
#define MPLS_PROTO_ETHERNET_PW  0
#define MPLS_PROTO_IPV4         4
#define MPLS_PROTO_IPV6         6

int qnsm_decode_mpls(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    uint32_t shim;
    int label;
    int event = 0;

    do {
        if (len < MPLS_HEADER_LEN) {
            return QNSM_DECODE_FAILED;
        }
        shim = *(uint32_t *)pkt;
        pkt += MPLS_HEADER_LEN;
        len -= MPLS_HEADER_LEN;
    } while (MPLS_BOTTOM(shim) == 0);

    label = MPLS_LABEL(shim);
    if (label == MPLS_LABEL_IPV4) {
        return qnsm_decode_ipv4(pkt_info, pkt, len);
    } else if (label == MPLS_LABEL_ROUTER_ALERT) {
        /* Not valid at the bottom of the stack. */
        event = 1;
    } else if (label == MPLS_LABEL_IPV6) {
        return qnsm_decode_ipv6(pkt_info, pkt, len);
    } else if (label == MPLS_LABEL_NULL) {
        /* Shouldn't appear on the wire. */
        event = 1;
    } else if (label < MPLS_MAX_RESERVED_LABEL) {
        event = 1;
    }

    if (event) {
        goto end;
    }

    /* Best guess at inner packet. */
    switch (pkt[0] >> 4) {
        case MPLS_PROTO_IPV4:
            qnsm_decode_ipv4(pkt_info, pkt, len);
            break;
        case MPLS_PROTO_IPV6:
            qnsm_decode_ipv6(pkt_info, pkt, len);
            break;
        case MPLS_PROTO_ETHERNET_PW:
            qnsm_decode_ethernet(pkt_info, pkt + MPLS_PW_LEN, len - MPLS_PW_LEN);
            break;
        default:
            return QNSM_DECODE_FAILED;
    }

end:
    if (event) {
        return QNSM_DECODE_FAILED;
    }
    return QNSM_DECODE_OK;
}

#endif

int qnsm_decode_ethernet(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len)
{
    EthernetHdr *ethh = NULL;
    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        return QNSM_DECODE_FAILED;
    }

    ethh = (EthernetHdr *)pkt;
    if (unlikely(ethh == NULL))
        return QNSM_DECODE_FAILED;

    switch (ntohs(ethh->eth_type)) {
        case ETHERNET_TYPE_IP:
            qnsm_decode_ipv4(pkt_info, pkt + ETHERNET_HEADER_LEN,
                             len - ETHERNET_HEADER_LEN);
            break;
        case ETHERNET_TYPE_IPV6:
            qnsm_decode_ipv6(pkt_info, pkt + ETHERNET_HEADER_LEN,
                             len - ETHERNET_HEADER_LEN);
            break;
        case ETHERNET_TYPE_8021Q:
            qnsm_decode_vlan(pkt_info, pkt + ETHERNET_HEADER_LEN,
                             len - ETHERNET_HEADER_LEN);
            break;
        case ETHERNET_TYPE_8021QINQ:
            qnsm_decode_qinq(pkt_info, pkt + ETHERNET_HEADER_LEN,
                             len - ETHERNET_HEADER_LEN);
            break;
        case ETHERNET_TYPE_MPLS_UNICAST:
        case ETHERNET_TYPE_MPLS_MULTICAST:
            qnsm_decode_mpls(pkt_info, pkt + ETHERNET_HEADER_LEN,
                             len - ETHERNET_HEADER_LEN);
            break;
        default:
            QNSM_DEBUG(QNSM_DBG_M_SESS, QNSM_DBG_PKT, "pkt %p ether type %04x not supported",
                       pkt, ntohs(ethh->eth_type));
            return QNSM_DECODE_FAILED;
    }

    return QNSM_DECODE_OK;
}

