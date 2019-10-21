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

#ifndef __QNSM_FLOWM__
#define __QNSM_FLOWM__

#ifdef __LEARN_SERVICE_VIP
#include <hiredis/hiredis.h>
#endif

#include <rte_rwlock.h>
#include <cmdline.h>
#include <cmdline_socket.h>

#include "list.h"
#include "qnsm_kafka_ex.h"
#include "qnsm_dpi_ex.h"


/*pkt info*/
#include "qnsm_inspect_main.h"


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __LEARN_SERVICE_VIP
#define DYN_VIP_REDIS_AUTH_CMD_FORMAT     ("AUTH %s")
#endif

/*lpm tbl size*/
#define QNSM_IPV4_LPM_MAX_RULES    (1024 << 2)
#define QNSM_IPV4_LPM_NUMBER_TBL8S (1 << 9)

/*V6 VIP tbl size*/
#define QNSM_IPV6_VIP_MAX_NUM      (1024)

/*vip group name len*/
#define QNSM_SVR_GROUP_NAME_LEN (16)

/*ipv4 net segment group id*/
#define QNSM_V4_SEG_GROUP_ID    (0)

/*ipv6 net segment group id*/
#define QNSM_V6_SEG_GROUP_ID    (1)
#define QNSM_MAX_SVR_GROUP_NUM  (8)
#define QNSM_DC_NAME_LEN        (32)
#define QNSM_KAFKA_BROKER_ADDR  (QNSM_KAFKA_MAX_BROKER_ADDR_LEN)
#define QNSM_MAX_KAFKA_BROKER   (16)
#define QNSM_KAFKA_TOPIC_LEN    (64)
#define QNSM_MAX_PF_NUM         (4)

/*service port list used for vip learn*/
#define QNSM_SERVICE_CFG_PORT_NUM_MAX    (256)

/*filter some port list pkts, no influence on ddos*/
#define QNSM_PORT_FILTER_SIZE   ((65536UL) >> 3)

enum en_qnsm_sample_method {
    EN_QNSM_PACKET_SAMPLE = 0,          /*sample by packet*/
    EN_QNSM_FLOW_SAMPLE,                /*TODO: sample by flow*/
};

#if QNSM_PART("struct")

#if QNSM_PART("sessm cfg")

typedef struct

{
    uint32_t rsvd_pkts;
} QNSM_SESSM_REASSEMBLE_CFG;

typedef struct {
    uint32_t per_lcore_size;
} QNSM_SESSM_CONN_CFG;

typedef struct {
    char     app_name[16];
    uint8_t  enable;
    uint8_t  parse_enable;
    uint16_t port;
} QNSM_PROTO_CFG;

typedef struct {
    QNSM_SESSM_CONN_CFG conn_cfg;
    QNSM_SESSM_REASSEMBLE_CFG resass_cfg;
    uint32_t care_biz;
    uint32_t app_num;
    QNSM_PROTO_CFG *app_prot_cfg;
    uint8_t  port_filter_map[QNSM_PORT_FILTER_SIZE];
    uint8_t sample_enable;
    enum en_qnsm_sample_method sample_method;
    uint16_t sample_rate;
} QNSM_SESSM_CFG;
#endif


#if QNSM_PART("vip cfg")
typedef struct qnsm_srv_host {
    QNSM_IN_ADDR        addr;
    char                mask;
} QNSM_SRV_HOST;

typedef struct qnsm_svr_ip_group {
    struct qnsm_list_head v4_node;
    struct qnsm_list_head v6_node;
    uint32_t group_id;
    char name[QNSM_SVR_GROUP_NAME_LEN];
    uint16_t threshold_enable;
    uint16_t valid;
    uint32_t threshold_mbps;
    uint32_t threshold_pps;
    uint32_t host_num;
    uint32_t host6_num;
    QNSM_SRV_HOST  *hosts;
    QNSM_SRV_HOST  *v6_hosts;
} QNSM_SVR_IP_GROUP;

typedef struct {
    uint16_t port[QNSM_SERVICE_CFG_PORT_NUM_MAX];
    uint8_t  port_num;
    uint8_t  reserved[7];

    /*service net segments*/
    QNSM_SRV_HOST *v4_net;
    uint32_t v4_net_size;
    uint32_t v4_net_num;

    QNSM_SRV_HOST *v6_net;
    uint32_t v6_net_size;
    uint32_t v6_net_num;
} QNSM_SERVICES_CFG;

#ifdef __PF
typedef struct {
    QNSM_SRV_HOST pf_vip;
    uint16_t port;
    uint8_t  proto;
    uint8_t  rsvd;
} QNSM_PF_CFG;
#endif

typedef struct {
    uint8_t redis_enable;
    char auth_token[64];
    char redis_addr[64];
    uint16_t redis_port;
} QNSM_BORDERM_CFG;

typedef struct {
    struct qnsm_list_head v4_groups;
    struct qnsm_list_head v6_groups;
    QNSM_SVR_IP_GROUP *group[QNSM_MAX_SVR_GROUP_NUM];
    uint32_t group_num;

    /*service_cfg*/
    QNSM_SERVICES_CFG auto_detect_service_cfg;

#ifdef __PF
    /*pf cfg*/
    QNSM_PF_CFG pf_cfg[QNSM_MAX_PF_NUM];
    uint32_t pf_num;
#endif

    /*borderm cfg*/
    QNSM_BORDERM_CFG borderm_cfg;
} QNSM_VIP_CFG;
#endif

#if QNSM_PART("edge cfg")
typedef struct {
    uint32_t partitions;
    uint8_t enable;
    uint8_t rsvd[3];
    char topic_name[QNSM_KAFKA_TOPIC_LEN];
} QNSM_KAFKA_TOPIC_CFG;

typedef struct qnsm_kafka_broker {
    char broker[QNSM_KAFKA_BROKER_ADDR];
} QNSM_KAFKA_BROKER;

typedef struct qnsm_kafka_cfg {
    char kafka_name[32];
    uint16_t  partitions;
    uint16_t  resvd;
    uint16_t broker_num;
    uint16_t topic_num;
    QNSM_KAFKA_BROKER borkers[QNSM_MAX_KAFKA_BROKER];
    QNSM_KAFKA_TOPIC_CFG topics[QNSM_KAFKA_MAX_TOPIC_ID];
} QNSM_KAFKA_CFG;

typedef struct qnsm_edge_cfg {
    char dc_name[QNSM_DC_NAME_LEN];
    char cons_group[32];
    QNSM_KAFKA_CFG *kafka_cfg;
    uint8_t kafka_num;

    char qnsm_inst_name[64];
} QNSM_EDGE_CFG;
#endif

typedef struct qnsm_dump_cfg {
    char *dump_dir;
} QNSM_DUMP_CFG;

#if QNSM_PART("cmd")
typedef struct {
    cmdline_parse_ctx_t ctx[16];
    struct cmdline *cl;
} QNSM_CMD_HANDLE;
#endif

#endif

inline QNSM_SESSM_CFG* qnsm_get_sessm_conf(void);
QNSM_PROTO_CFG* qnsm_get_proto_conf(const char *name);
int32_t qnsm_cmd_init(void **tbl_handle);
int qnsm_conf_parse(void);
inline QNSM_EDGE_CFG* qnsm_get_edge_conf(void);
inline QNSM_DUMP_CFG* qnsm_get_dump_conf(void);
inline QNSM_SVR_IP_GROUP* qnsm_get_group(uint32_t group_id);
inline uint16_t qnsm_group_num(void);
inline uint32_t qnsm_group_is_valid(uint32_t group_id);
inline QNSM_VIP_CFG* qnsm_get_groups(void);
QNSM_SERVICES_CFG *qnsm_get_known_ports(void);
uint32_t qnsm_ipv4_depth_to_mask(uint8_t depth);
int32_t qnsm_match_local_net_segment(enum en_qnsm_ip_af af, QNSM_IN_ADDR *in_addr);
int32_t qnsm_match_all_net_segment(enum en_qnsm_ip_af af, QNSM_IN_ADDR *in_addr);

/*
*return: 0 match failure
*        1 match dst ip
*        2 match src ip
*/
inline int32_t qnsm_match_service(void *data, uint16_t port);
void *qnsm_get_kafka_cfg(const char *name);

#ifdef __cplusplus
}
#endif

#endif
