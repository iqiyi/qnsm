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
#ifndef __QNSM_DECODE__
#define __QNSM_DECODE__

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum qnsm_decode_rslt {
    QNSM_DECODE_OK = 0,
    QNSM_DECODE_FAILED,
    QNSM_DECODE_MAX,
};

#if QNSM_PART("ETHERNET")
#define ETHERNET_HEADER_LEN           14

/* Cisco Fabric Path / DCE header length. */
#define ETHERNET_DCE_HEADER_LEN       ETHERNET_HEADER_LEN + 2

/* Ethernet types -- taken from Snort and Libdnet */
#define ETHERNET_TYPE_PUP             0x0200 /* PUP protocol */
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_BRIDGE          0x6558 /* transparant ethernet bridge (GRE) */
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPOE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPOE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021AD          0x88a8
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000
#define ETHERNET_TYPE_8021QINQ        0x9100
#define ETHERNET_TYPE_ERSPAN          0x88BE
#define ETHERNET_TYPE_DCE             0x8903 /* Data center ethernet,
                                              * Cisco Fabric Path */

#define ETHERNET_TYPE_MPLS_UNICAST    0x8847
#define ETHERNET_TYPE_MPLS_MULTICAST  0x8848


typedef struct EthernetHdr_ {
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;
} __attribute__((__packed__)) EthernetHdr;
#endif

#if QNSM_PART("IPV4")

typedef struct IPV4Hdr_ {
    uint8_t ip_verhl;     /**< version & header length */
    uint8_t ip_tos;       /**< type of service */
    uint16_t ip_len;      /**< length */
    uint16_t ip_id;       /**< id */
    uint16_t ip_off;      /**< frag offset */
    uint8_t ip_ttl;       /**< time to live */
    uint8_t ip_proto;     /**< protocol (tcp, udp, etc) */
    uint16_t ip_csum;     /**< checksum */
    union {
        struct {
            struct in_addr ip_src;/**< source address */
            struct in_addr ip_dst;/**< destination address */
        } ip4_un1;
        uint16_t ip_addrs[4];
    } ip4_hdrun1;
} __attribute__((__packed__)) IPV4Hdr;

#define s_ip_src                          ip4_hdrun1.ip4_un1.ip_src
#define s_ip_dst                          ip4_hdrun1.ip4_un1.ip_dst
#define s_ip_addrs                        ip4_hdrun1.ip_addrs

#define IPV4_GET_RAW_VER(ip4h)            (((ip4h)->ip_verhl & 0xf0) >> 4)
#define IPV4_GET_RAW_HLEN(ip4h)           ((ip4h)->ip_verhl & 0x0f)
#define IPV4_GET_RAW_IPTOS(ip4h)          ((ip4h)->ip_tos)
#define IPV4_GET_RAW_IPLEN(ip4h)          ((ip4h)->ip_len)
#define IPV4_GET_RAW_IPID(ip4h)           ((ip4h)->ip_id)
#define IPV4_GET_RAW_IPOFFSET(ip4h)       ((ip4h)->ip_off)
#define IPV4_GET_RAW_IPTTL(ip4h)          ((ip4h)->ip_ttl)
#define IPV4_GET_RAW_IPPROTO(ip4h)        ((ip4h)->ip_proto)
#define IPV4_GET_RAW_IPSRC(ip4h)          ((ip4h)->s_ip_src)
#define IPV4_GET_RAW_IPDST(ip4h)          ((ip4h)->s_ip_dst)

/** return the raw (directly from the header) src ip as uint32_t */
#define IPV4_GET_RAW_IPSRC_U32(ip4h)      (uint32_t)((ip4h)->s_ip_src.s_addr)
/** return the raw (directly from the header) dst ip as uint32_t */
#define IPV4_GET_RAW_IPDST_U32(ip4h)      (uint32_t)((ip4h)->s_ip_dst.s_addr)

/* we need to change them as well as get them */
#define IPV4_SET_RAW_VER(ip4h, value)     ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0x0f) | (value << 4)))
#define IPV4_SET_RAW_HLEN(ip4h, value)    ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0xf0) | (value & 0x0f)))
#define IPV4_SET_RAW_IPTOS(ip4h, value)   ((ip4h)->ip_tos = value)
#define IPV4_SET_RAW_IPLEN(ip4h, value)   ((ip4h)->ip_len = value)
#define IPV4_SET_RAW_IPPROTO(ip4h, value) ((ip4h)->ip_proto = value)

/* ONLY call these functions after making sure that:
 * ip4h is valid (len is correct)
 */
#define IPV4_GET_VER(ip4h) \
    IPV4_GET_RAW_VER(ip4h)
#define IPV4_GET_HLEN(ip4h) \
    (IPV4_GET_RAW_HLEN(ip4h) << 2)
#define IPV4_GET_IPTOS(ip4h) \
    IPV4_GET_RAW_IPTOS(ip4h)
#define IPV4_GET_IPLEN(ip4h) \
    (ntohs(IPV4_GET_RAW_IPLEN(ip4h)))
#define IPV4_GET_IPID(ip4h) \
    (ntohs(IPV4_GET_RAW_IPID(ip4h)))
/* _IPV4_GET_IPOFFSET: get the content of the offset header field in host order */
#define _IPV4_GET_IPOFFSET(ip4h) \
    (ntohs(IPV4_GET_RAW_IPOFFSET(ip4h)))
/* IPV4_GET_IPOFFSET: get the final offset */
#define IPV4_GET_IPOFFSET(ip4h) \
    (_IPV4_GET_IPOFFSET(ip4h) & 0x1fff)
/* IPV4_GET_RF: get the RF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_RF(ip4h) \
    (uint8_t)((_IPV4_GET_IPOFFSET((ip4h)) & 0x8000) >> 15)
/* IPV4_GET_DF: get the DF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_DF(ip4h) \
    (uint8_t)((_IPV4_GET_IPOFFSET((ip4h)) & 0x4000) >> 14)
/* IPV4_GET_MF: get the MF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_MF(ip4h) \
    (uint8_t)((_IPV4_GET_IPOFFSET((ip4h)) & 0x2000) >> 13)
#define IPV4_GET_IPTTL(ip4h) \
     IPV4_GET_RAW_IPTTL(ip4h)
#define IPV4_GET_IPPROTO(ip4h) \
    IPV4_GET_RAW_IPPROTO(ip4h)
#endif

#if QNSM_PART("IPV6")
#define IPV6_HEADER_LEN            40
#define IPV6_MAXPACKET             65535 /* maximum packet size */
#define IPV6_MAX_OPT               40

typedef struct IPV6Hdr_ {
    union {
        struct ip6_un1_ {
            uint32_t ip6_un1_flow; /* 20 bits of flow-ID */
            uint16_t ip6_un1_plen; /* payload length */
            uint8_t  ip6_un1_nxt;  /* next header */
            uint8_t  ip6_un1_hlim; /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
    } ip6_hdrun;

    union {
        struct {
            uint32_t ip6_src[4];
            uint32_t ip6_dst[4];
        } ip6_un2;
        uint16_t ip6_addrs[16];
    } ip6_hdrun2;
} __attribute__((__packed__)) IPV6Hdr;

#define s_ip6_src                       ip6_hdrun2.ip6_un2.ip6_src
#define s_ip6_dst                       ip6_hdrun2.ip6_un2.ip6_dst
#define s_ip6_addrs                     ip6_hdrun2.ip6_addrs

#define s_ip6_vfc                       ip6_hdrun.ip6_un2_vfc
#define s_ip6_flow                      ip6_hdrun.ip6_un1.ip6_un1_flow
#define s_ip6_plen                      ip6_hdrun.ip6_un1.ip6_un1_plen
#define s_ip6_nxt                       ip6_hdrun.ip6_un1.ip6_un1_nxt
#define s_ip6_hlim                      ip6_hdrun.ip6_un1.ip6_un1_hlim

#define IPV6_GET_RAW_VER(ip6h)          (((ip6h)->s_ip6_vfc & 0xf0) >> 4)
#define IPV6_GET_RAW_CLASS(ip6h)        ((ntohl((ip6h)->s_ip6_flow) & 0x0FF00000) >> 20)
#define IPV6_GET_RAW_FLOW(ip6h)         (ntohl((ip6h)->s_ip6_flow) & 0x000FFFFF)
#define IPV6_GET_RAW_NH(ip6h)           ((ip6h)->s_ip6_nxt)
#define IPV6_GET_RAW_PLEN(ip6h)         (ntohs((ip6h)->s_ip6_plen))
#define IPV6_GET_RAW_HLIM(ip6h)         ((ip6h)->s_ip6_hlim)

#define IPV6_SET_RAW_VER(ip6h, value)   ((ip6h)->s_ip6_vfc = (((ip6h)->s_ip6_vfc & 0x0f) | (value << 4)))
#define IPV6_SET_RAW_NH(ip6h, value)    ((ip6h)->s_ip6_nxt = (value))

#endif

#if QNSM_PART("TCP")
#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */

/* TCP flags */

#define TH_FIN                               0x01
#define TH_SYN                               0x02
#define TH_RST                               0x04
#define TH_PUSH                              0x08
#define TH_ACK                               0x10
#define TH_URG                               0x20
/** Establish a new connection reducing window */
#define TH_ECN                               0x40
/** Echo Congestion flag */
#define TH_CWR                               0x80

/* tcp option codes */
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_WS                           0x03
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_TS                           0x08

#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_WS_LEN                       3
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_SACK_MIN_LEN                 10 /* hdr 2, 1 pair 8 = 10 */
#define TCP_OPT_SACK_MAX_LEN                 34 /* hdr 2, 4 pair 32= 34 */

/** Max valid wscale value. */
#define TCP_WSCALE_MAX                       14

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_X2(tcph)                 (unsigned char)((tcph)->th_offx2 & 0x0f)
#define TCP_GET_RAW_SRC_PORT(tcph)           ntohs((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           ntohs((tcph)->th_dport)

#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

#define TCP_GET_RAW_SEQ(tcph)                ntohl((tcph)->th_seq)
#define TCP_GET_RAW_ACK(tcph)                ntohl((tcph)->th_ack)

#define TCP_GET_RAW_WINDOW(tcph)             ntohs((tcph)->th_win)
#define TCP_GET_RAW_URG_POINTER(tcph)        ntohs((tcph)->th_urp)
#define TCP_GET_RAW_SUM(tcph)                ntohs((tcph)->th_sum)

#define TCP_GET_OFFSET(tcph)                    TCP_GET_RAW_OFFSET(tcph)
#define TCP_GET_X2(tcph)                        TCP_GET_RAW_X2(tcph)
#define TCP_GET_HLEN(tcph)                      (TCP_GET_OFFSET(tcph) << 2)
#define TCP_GET_SRC_PORT(tcph)                  TCP_GET_RAW_SRC_PORT(tcph)
#define TCP_GET_DST_PORT(tcph)                  TCP_GET_RAW_DST_PORT(tcph)
#define TCP_GET_SEQ(tcph)                       TCP_GET_RAW_SEQ(tcph)
#define TCP_GET_ACK(tcph)                       TCP_GET_RAW_ACK(tcph)
#define TCP_GET_WINDOW(tcph)                    TCP_GET_RAW_WINDOW(tcph)
#define TCP_GET_URG_POINTER(tcph)               TCP_GET_RAW_URG_POINTER(tcph)
#define TCP_GET_SUM(tcph)                       TCP_GET_RAW_SUM(tcph)
#define TCP_GET_FLAGS(tcph)                     tcph->th_flags

#define TCP_ISSET_FLAG_FIN(tcph)                (tcph->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_SYN(tcph)                (tcph->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_RST(tcph)                (tcph->th_flags & TH_RST)
#define TCP_ISSET_FLAG_PUSH(tcph)               (tcph->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_ACK(tcph)                (tcph->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_URG(tcph)                (tcph->th_flags & TH_URG)
#define TCP_ISSET_FLAG_RES2(tcph)               (tcph->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RES1(tcph)               (tcph->th_flags & TH_RES1)

typedef struct TCPHdr_ {
    uint16_t th_sport;  /**< source port */
    uint16_t th_dport;  /**< destination port */
    uint32_t th_seq;    /**< sequence number */
    uint32_t th_ack;    /**< acknowledgement number */
    uint8_t th_offx2;   /**< offset and reserved */
    uint8_t th_flags;   /**< pkt flags */
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} __attribute__((__packed__)) TCPHdr;
#endif

#if QNSM_PART("UDP")
#define UDP_HEADER_LEN         8

/* XXX RAW* needs to be really 'raw', so no ntohs there */
#define UDP_GET_RAW_LEN(udph)                ntohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph)           ntohs((udph)->uh_sport)
#define UDP_GET_RAW_DST_PORT(udph)           ntohs((udph)->uh_dport)
#define UDP_GET_RAW_SUM(udph)                ntohs((udph)->uh_sum)

#define UDP_GET_LEN(udph)                       UDP_GET_RAW_LEN(udph)
#define UDP_GET_SRC_PORT(udph)                  UDP_GET_RAW_SRC_PORT(udph)
#define UDP_GET_DST_PORT(udph)                  UDP_GET_RAW_DST_PORT(udph)
#define UDP_GET_SUM(udph)                       UDP_GET_RAW_SUM(udph)

/* UDP header structure */
typedef struct UDPHdr_ {
    uint16_t uh_sport;  /* source port */
    uint16_t uh_dport;  /* destination port */
    uint16_t uh_len;    /* length */
    uint16_t uh_sum;    /* checksum */
} __attribute__((__packed__)) UDPHdr;

#endif

#if QNSM_PART("ICMPV4")

#define ICMPV4_HEADER_LEN       8

/* ICMPv4 header structure */
typedef struct ICMPV4Hdr_ {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
} __attribute__((__packed__)) ICMPV4Hdr;

#endif

#if QNSM_PART("GRE")

typedef struct GREHdr_ {
    uint8_t flags; /**< GRE packet flags */
    uint8_t version; /**< GRE version */
    uint16_t ether_type; /**< ether type of the encapsulated traffic */

} __attribute__((__packed__)) GREHdr;

/* Generic Routing Encapsulation Source Route Entries (SREs).
 * The header is followed by a variable amount of Routing Information.
 */
typedef struct GRESreHdr_ {
    uint16_t af; /**< Address family */
    uint8_t sre_offset;
    uint8_t sre_length;
} __attribute__((__packed__)) GRESreHdr;

#define GRE_VERSION_0           0x0000
#define GRE_VERSION_1           0x0001

#define GRE_HDR_LEN             4
#define GRE_CHKSUM_LEN          2
#define GRE_OFFSET_LEN          2
#define GRE_KEY_LEN             4
#define GRE_SEQ_LEN             4
#define GRE_SRE_HDR_LEN         4
#define GRE_PROTO_PPP           0x880b

#define GRE_FLAG_ISSET_CHKSUM(r)    (r->flags & 0x80)
#define GRE_FLAG_ISSET_ROUTE(r)     (r->flags & 0x40)
#define GRE_FLAG_ISSET_KY(r)        (r->flags & 0x20)
#define GRE_FLAG_ISSET_SQ(r)        (r->flags & 0x10)
#define GRE_FLAG_ISSET_SSR(r)       (r->flags & 0x08)
#define GRE_FLAG_ISSET_RECUR(r)     (r->flags & 0x07)
#define GRE_GET_VERSION(r)   (r->version & 0x07)
#define GRE_GET_FLAGS(r)     (r->version & 0xF8)
#define GRE_GET_PROTO(r)     ntohs(r->ether_type)

#define GREV1_HDR_LEN           8
#define GREV1_ACK_LEN           4
#define GREV1_FLAG_ISSET_FLAGS(r)  (r->version & 0x78)
#define GREV1_FLAG_ISSET_ACK(r)    (r->version & 0x80)

#endif

int qnsm_decode_ethernet(QNSM_PACKET_INFO *pkt_info, uint8_t *pkt, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif
