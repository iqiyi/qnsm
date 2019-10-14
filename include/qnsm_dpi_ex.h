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

#ifndef __QNSM_DPI_EX__
#define __QNSM_DPI_EX__

#include <arpa/inet.h>

#include "util.h"

/*pkt info*/
#include "qnsm_inspect_main.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_PORT        (53)
#define NTP_PORT        (123)
#define SSDP_PORT       (1900)
#define MEMCACHED_PORT  (11211)
#define CHARGEN_PORT    (19)
#define CLDAP_PORT      (389)
#define QOTD_PORT       (17)    /*Quote of the Day*/
#define TFTP_PORT       (69)    /*Trivial File Transfer Protocol*/


#define QNSM_DPI_NTOHS(a) rte_be_to_cpu_16(a)
#define QNSM_DPI_NTOHL(a) rte_be_to_cpu_32(a)
#define QNSM_DPI_HTONS(a) rte_cpu_to_be_16(a)
#define QNSM_DPI_HTONL(a) rte_cpu_to_be_32(a)


#define DNS_QUESTION_DEFAULT    (16)
#define DNS_RR_DEFAULT         (48)
#define DNS_ANSWER_MAX      (16)
#define DNS_AUTHORITY_MAX   (16)
#define DNS_ADDTIONAL_MAX   (16)

#define QNSM_DPI_CONF_CORE_MAX      (APP_MAX_LCORES - 1)

#define QNSM_DPI_MSG_PREPEND_LEN   (4)
#define QNSM_DPI_MSG_DATA_LEN      (QNSM_MSG_MAX_DATA_LEN - QNSM_DPI_MSG_PREPEND_LEN)

typedef enum {
    EN_DPI_PROT_TCP = 0,
    EN_DPI_PROT_UDP,
    EN_DPI_L4_MAX
} EN_QNSM_DPI_L4_PROT;

#define QNSM_DPI_PROTO_MAP(XX)           \
  XX(0,  QNSM_DPI_HTTP,      http)       \
  XX(1,  QNSM_DPI_DNS,       dns)        \
  XX(2,  QNSM_DPI_NTP,       ntp)        \
  XX(3,  QNSM_DPI_SSDP,      ssdp)       \
  XX(4,  QNSM_DPI_MEMCACHED, memcache)   \
  XX(5,  QNSM_DPI_CHARGEN,   chargen)    \
  XX(6,  QNSM_DPI_CLDAP,     cldap)      \
  XX(7,  QNSM_DPI_QOTD,      qotd)       \
  XX(8,  QNSM_DPI_SNMP,      snmp)       \
  XX(9,  QNSM_DPI_TFTP,      tftp)       \
  XX(10, QNSM_DPI_ESP,       esp)        \
  XX(11, QNSM_DPI_BitTorrent,bittorrent) \
  XX(12, QNSM_DPI_P2P,       p2p)        \
  XX(13, QNSM_DPI_MSSQL,     mssql)      \
  XX(14, QNSM_DPI_MulticaseDNS, multicaseDNS)      \
  XX(15, QNSM_DPI_NetBIOS,   netbios)    \
  XX(16, QNSM_DPI_Portmap,   portmap)    \
  XX(17, QNSM_DPI_Quake,     quake)      \
  XX(18, QNSM_DPI_RIPv1,     ripv1)      \
  XX(19, QNSM_DPI_STEAM,     steam)      \
  XX(20, QNSM_DPI_CoAP,      CoAP)       \
  XX(21, QNSM_DPI_PROTO_MAX, other)      \

typedef enum {
#define XX(num, name, string) EN_##name = num,
    QNSM_DPI_PROTO_MAP(XX)
#undef XX
} EN_QNSM_DPI_PROTO;

/*DPI parse ops*/
typedef enum {
    EN_QNSM_DPI_OP_CONTINUE = 0,
    EN_QNSM_DPI_OP_STOP,
    EN_QNSM_DPI_OP_MAX,
} EN_QNSM_DPI_OP_RES;

typedef struct {

    EN_QNSM_DPI_PROTO proto;
    void *data;
    QNSM_PACKET_INFO  *pkt_info;
} QNSM_DPI_MSG;

typedef struct {
    uint8_t af;
    uint16_t source;
    uint16_t dest;
    QNSM_IN_ADDR saddr;
    QNSM_IN_ADDR daddr;
} QNSM_DPI_IPV4_TUPLE4;

typedef struct {
    EN_QNSM_DPI_L4_PROT l4_proto;
    void *sess;
} QNSM_DPI_SESS;


typedef EN_QNSM_DPI_OP_RES (*QNSM_PROTO_OPS)(QNSM_PACKET_INFO *pkt_info, void *arg);
typedef void (*QNSM_PROTO_FREE)(void *sess, void *arg);
typedef uint32_t (*QNSM_DPI_ENCAP_INFO)(uint8_t *buf, void *pkt_info, void *info);
typedef void (*QNSM_DPI_MSG_PROC)(void *data, uint32_t data_len);

/**
* classify cbk fun prototype
*/
typedef void (*QNSM_DPI_CLASS_MATCH_FUN)(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg);
typedef void* (*QNSM_DPI_PROTO_DATA_INIT)(void);

/*set proto DFI enable*/
inline uint8_t qnsm_dpi_proto_enable(EN_QNSM_DPI_PROTO dpi_proto);

/*set proto DPI enable*/
inline uint8_t qnsm_dpi_proto_parse_enable(EN_QNSM_DPI_PROTO dpi_proto);

/*per proto dpi data*/
inline void* qnsm_dpi_proto_data(EN_QNSM_DPI_PROTO dpi_proto);

/*per proto dpi data init*/
inline void qnsm_dpi_proto_init(EN_QNSM_DPI_PROTO dpi_proto);

/**
 * reg payload content classify cbk
 *
 * @param dpi_classfy_proto
 *   EN_DPI_PROT_TCP/UDP
 * @param str
 *   payload content head
 * @param len
 *   payload content len
 * @param match_proto
 *   app proto
 * @param func
 *   classify cbk fun
 * @return
 *   0 success, other failed
 */
int32_t qnsm_dpi_content_classify_reg(EN_QNSM_DPI_L4_PROT dpi_classfy_proto, const char *str, const uint8_t len, EN_QNSM_DPI_PROTO match_proto, QNSM_DPI_CLASS_MATCH_FUN func);

/**
 * reg dport classify cbk
 *
 * @param dpi_classfy_proto
 *   EN_DPI_PROT_TCP/UDP
 * @param dport
 *   l4 dport
 * @param match_proto
 *   app proto
 * @param func
 *   classify cbk fun
 * @return
 *   0 success, other failed
 */
int32_t qnsm_dpi_service_classify_reg(EN_QNSM_DPI_L4_PROT dpi_classfy_proto, uint16_t dport, EN_QNSM_DPI_PROTO match_proto, QNSM_DPI_CLASS_MATCH_FUN func);

/**
 * reg proto dpi data init cbk
 *
 * @param dpi_proto
 *   EN_QNSM_DPI_PROTO
 * @param init_func
 *   per proto dpi data structure
 * @return
 *   0 success, other failed
 */
int32_t qnsm_dpi_proto_init_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_DPI_PROTO_DATA_INIT init_func);


/**
 * reg proto dpi ops
 *
 * @param dpi_proto
 *   EN_QNSM_DPI_PROTO
 * @param proto_ops
 *   proto ops, parse, send result etc
 * @param pri
 *   priority, maximum means highest priority
 * @return
 *   0 success, other failed
 */
int32_t qnsm_dpi_prot_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_PROTO_OPS proto_ops, uint32_t pri);

/**
 * reg proto dpi data free cbk
 *
 * @param dpi_proto
 *   EN_QNSM_DPI_PROTO
 * @param final_func
 *   free data
 * @return
 *   0 success, other failed
 */
int32_t qnsm_dpi_prot_final_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_PROTO_FREE final_func);

/**
 * DFI, execute proto classfify
 *
 * @param pkt_info
 *   pkt base parse info
 * @param l4_prot
 *   EN_QNSM_DPI_L4_PROT
 * @param sess
 *   5tuple flow
 * @param sess
 *   5tuple flow
 * @param app_arg
 *   argument used for proto parse ops
 * @return
 *   0 success, other failed
 */
inline int32_t qnsm_dpi_match(QNSM_PACKET_INFO *pkt_info, EN_QNSM_DPI_L4_PROT l4_prot, void *sess, void **app_arg);

/**
 * DPI, execute proto parse
 *
 * @param dpi_proto
 *   EN_QNSM_DPI_PROTO
 * @param pkt_info
 *   pkt base parse info
 * @param sess
 *   5tuple flow
 * @param sess
 *   5tuple flow
 * @param app_arg
 *   argument used for proto parse ops
 * @return
 *   0 success, other failed
 */
inline int32_t qnsm_dpi_prot_cbk(EN_QNSM_DPI_PROTO dpi_proto, QNSM_PACKET_INFO *pkt_info, void *sess, void *arg);

/**
 * DPI, free per-session dpi data
 *
 * @param dpi_proto
 *   EN_QNSM_DPI_PROTO
 * @param arg
 *   argument used for per session proto parse ops
 * @return
 *   0 success, other failed
 */
void qnsm_dpi_proto_free(EN_QNSM_DPI_PROTO dpi_proto, void *arg);

/*send/rcv dpi parse result*/
int32_t qnsm_dpi_msg_reg(EN_QNSM_DPI_PROTO dpi_proto, QNSM_DPI_ENCAP_INFO encap_fun, QNSM_DPI_MSG_PROC msg_proc_fun);
int32_t qnsm_dpi_encap_dpi(void *msg, uint32_t *msg_len, void *send_data);
int32_t qnsm_dpi_msg_proc(void *data, uint32_t data_len);
inline uint32_t qnsm_dpi_encap_tuple(void *msg, QNSM_PACKET_INFO *pkt_info);
inline int32_t qnsm_dpi_send_info(QNSM_PACKET_INFO *pkt_info, EN_QNSM_DPI_PROTO dpi_proto, void *arg);


#ifdef __cplusplus
}
#endif

#endif

