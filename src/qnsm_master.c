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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <cmdline.h>
#include <rte_table_acl.h>

#ifdef __LEARN_SERVICE_VIP
#include <hiredis/hiredis.h>
#endif

#include "cJSON.h"
#include "util.h"
#include "qnsm_dbg.h"
#include "app.h"
#include "qnsm_msg_ex.h"
#include "qnsm_service_ex.h"
#include "qnsm_ip_agg.h"
#include "qnsm_cfg.h"
#include "qnsm_kafka_ex.h"
#include "qnsm_acl_ex.h"
#include "qnsm_idps_lib_ex.h"
#include "qnsm_session_ex.h"
#include "qnsm_master_ex.h"

#ifdef __LEARN_SERVICE_VIP

#define DYN_VIP_REDIS_GET_CMD_FORMAT ("GET vip:%s:idc_name")
#endif

typedef struct {
    /*global cfg data*/
    QNSM_EDGE_CFG *edge_cfg_data;

    /*ip group data*/
    QNSM_VIP_CFG *vip_cfg_data;
    uint32_t default_group_id;

    /*cmd ctx*/
    QNSM_CMD_HANDLE *cmd_hdl;

    /*kafka ctx*/
    void *kafka_hdl;

    /*time syn*/
    struct rte_timer syn_clock;

#ifdef __LEARN_SERVICE_VIP
    /*hiredis*/
    redisContext *redis_ctx;
#endif

#ifdef QNSM_LIBQNSM_IDPS
    uint8_t deploy_idps;
#endif
} QNSM_MASTER_DATA;


static int32_t qnsm_master_get_addr_family(char *addr)
{
    char *p = addr;
    int32_t af = -1;

    if (NULL == addr) {
        return 0;
    }

    while (('\0' != *p) && (64 > (p - addr))) {
        switch (*p) {
            case '.': {
                /*v4*/
                return EN_QNSM_AF_IPv4;
            }
            case ':': {
                /*v6*/
                return EN_QNSM_AF_IPv6;
            }
            default: {
                break;
            }
        }

        p++;
    }

    return af;
}

static int32_t qnsm_master_encap_biz_vip_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    QNSM_BIZ_VIP_MSG *snd_data = NULL;
    if ((NULL == send_data) || (NULL == msg)) {
        return 0;
    }

    snd_data = send_data;
    *(QNSM_BIZ_VIP_MSG *)msg = *snd_data;
    *msg_len = sizeof(QNSM_BIZ_VIP_MSG);

    return 0;
}

#ifdef __LEARN_SERVICE_VIP
static void qnsm_master_send_json_msg(QNSM_MASTER_DATA *master_data, QNSM_IN_ADDR *in_addr, const char *vip_str)
{
    cJSON *root = NULL;

    QNSM_ASSERT(vip_str);
    root = cJSON_CreateObject();

    cJSON_AddStringToObject(root,"type", "dyn_vip");
    cJSON_AddStringToObject(root, "dc", master_data->edge_cfg_data->dc_name);
    cJSON_AddStringToObject(root, "vip", vip_str);

    qnsm_kafka_send_msg(QNSM_KAFKA_DYN_VIP_TOPIC, root, in_addr->in6_addr.s6_addr32[0]);

    if (root) {
        cJSON_Delete(root);
    }
    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "send vip %s to DYN_VIP_TOPIC success\n", vip_str);
    return;
}

int32_t qnsm_master_redis_init(redisContext **pp_ctx, const char *addr, uint16_t port, const char* token)
{
    redisContext *c = NULL;
    redisReply *reply;
    uint32_t conn_cnt = 0;
    char cmd[128] = {0};

    while ((3 > conn_cnt) && (NULL == *pp_ctx)) {
        c = redisConnect(addr, port);
        if (c == NULL || c->err) {
            if (c) {
                printf("Connection error: %s\n", c->errstr);
                redisFree(c);
            } else {
                printf("Connection error: can't allocate redis context\n");
            }
            conn_cnt++;
        } else {
            *pp_ctx = c;
            snprintf(cmd, sizeof(cmd), DYN_VIP_REDIS_AUTH_CMD_FORMAT, token);

            /*auth*/
            while(NULL == (reply = redisCommand(c, cmd)));
            QNSM_LOG(CRIT, "redis connect success\n");
            break;
        }
    }
    return 0;
}

#endif

static int32_t qnsm_master_vip_add_msg_proc(void *data, uint32_t data_len)
{
    char *buf = data;
    QNSM_IN_ADDR *in_addr;
    QNSM_IN_ADDR tmp_addr;
    QNSM_MASTER_DATA *master_data = qnsm_app_data(EN_QNSM_MASTER);
    char ip_str[64] = {0};
    int32_t ret = 0;
    uint32_t af = 0;
    uint32_t len = 0;
    int32_t mask = 0;
    QNSM_BIZ_VIP_MSG vip_msg;

    af = *(uint32_t *)(buf + len);
    len += sizeof(uint32_t);
    in_addr = (QNSM_IN_ADDR *)(buf + len);


    if (EN_QNSM_AF_IPv4 == af) {
        vip_msg.mask = 32;
        tmp_addr.in4_addr.s_addr =  rte_cpu_to_be_32(in_addr->in4_addr.s_addr);
        inet_ntop(AF_INET, &tmp_addr.in4_addr, ip_str, sizeof(ip_str));
    } else {
        vip_msg.mask = 128;
        inet_ntop(AF_INET6, &in_addr->in6_addr, ip_str, sizeof(ip_str));
    }
    vip_msg.af = af;
    if (EN_QNSM_AF_IPv4 == af) {
        vip_msg.key.in4_addr = tmp_addr.in4_addr;
    } else {
        vip_msg.key.in6_addr = in_addr->in6_addr;
    }
    vip_msg.op = QNSM_BIZ_VIP_ADD;
    vip_msg.group_id = master_data->default_group_id;
    vip_msg.cmd = EN_QNSM_CMD_MAX;

    /*look up local seg cache*/
    if (qnsm_match_local_net_segment(af, in_addr)) {
        vip_msg.cmd_data[0] = 1;

        /*syn local dc biz vip to custom ip/DUMP comp*/
        (void)qnsm_msg_send_multi(EN_QNSM_DUMP,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
        (void)qnsm_msg_send_multi(EN_QNSM_SIP_AGG,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);

        /*
        *QNSM_MSG_SYN_BIZ_VIP msg to sessm
        *local: get direction
        *remote dc vip:store to filter
        */
        (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
        (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
        return ret;
    }

    /*lookup all net seg cache*/
    if ((mask = qnsm_match_all_net_segment(af, in_addr))) {
        /*set remote idc vip*/
        vip_msg.cmd_data[0] = 0;
        (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);

        /*
        *QNSM_MSG_SYN_BIZ_VIP msg to sessm
        *local: get direction
        *remote dc vip segment:store to filter
        */
        if (EN_QNSM_AF_IPv4 == af) {
            in_addr->in4_addr.s_addr = in_addr->in4_addr.s_addr & qnsm_ipv4_depth_to_mask(mask);
            tmp_addr.in4_addr.s_addr = rte_cpu_to_be_32(in_addr->in4_addr.s_addr);
            inet_ntop(AF_INET, &tmp_addr.in4_addr, ip_str, sizeof(ip_str));
            vip_msg.key.in4_addr = tmp_addr.in4_addr;

            /*set mask*/
            vip_msg.mask = mask;
        } else {
            /*not support ipv6 remote idc vip net-segment*/
            vip_msg.mask = 128;
        }
        (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
        QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "remmote idc vip %s\n", ip_str);
        QNSM_LOG(CRIT, "ip:%s, local_vip:0 match all net segments\n", ip_str);
        return ret;
    }

#ifdef __LEARN_SERVICE_VIP
    QNSM_BORDERM_CFG *bm_cfg = &qnsm_get_groups()->borderm_cfg;
    redisReply *reply;
    char cmd[128] = {0};
    uint8_t  is_local_vip = 0;

    snprintf(cmd, sizeof(cmd), DYN_VIP_REDIS_GET_CMD_FORMAT, ip_str);
    if (bm_cfg->redis_enable
        && (master_data->redis_ctx)
        && (reply = redisCommand(master_data->redis_ctx, cmd))) {
        switch (reply->type) {
            case REDIS_REPLY_STRING: {
                if (strncasecmp(reply->str, qnsm_get_edge_conf()->dc_name, strlen(qnsm_get_edge_conf()->dc_name))) {
                    is_local_vip = 0;
                } else {
                    is_local_vip = 1;
                }
                vip_msg.cmd_data[0] = is_local_vip;

                if (is_local_vip) {
                    /*syn local dc biz vip to custom ip/DUMP comp*/
                    (void)qnsm_msg_send_multi(EN_QNSM_DUMP,
                                              QNSM_MSG_SYN_BIZ_VIP,
                                              &vip_msg,
                                              1);
                    (void)qnsm_msg_send_multi(EN_QNSM_SIP_AGG,
                                              QNSM_MSG_SYN_BIZ_VIP,
                                              &vip_msg,
                                              1);
                }

                /*
                *QNSM_MSG_SYN_BIZ_VIP msg to sessm
                *local: get direction
                *remote dc vip:store to filter
                */
                (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
                (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
                QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "rcv redis dyn vip ack %s success\n", ip_str);
                QNSM_LOG(CRIT, "rcv redis dyn vip ack str %s, (ip:%s, local_vip:%u)\n", reply->str, ip_str, is_local_vip);
                break;
            }
            case REDIS_REPLY_NIL:
                /*kafka*/
                qnsm_master_send_json_msg(master_data, in_addr, ip_str);
                is_local_vip = 0;
                vip_msg.cmd_data[0] = is_local_vip;

                (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
                QNSM_LOG(CRIT, "rcv redis dyn vip nil, (ip:%s, local_vip:%u)\n", ip_str, is_local_vip);
                break;
            case REDIS_REPLY_ERROR:
                QNSM_LOG(CRIT, "rcv redis dyn vip ack err %s, (ip:%s)\n", reply->str, ip_str);
                break;
            default:
                break;
        }
        freeReplyObject(reply);
    } else {
        redisFree(master_data->redis_ctx);
        master_data->redis_ctx = NULL;
        qnsm_master_redis_init(&master_data->redis_ctx, bm_cfg->redis_addr, bm_cfg->redis_port, bm_cfg->auth_token);
    }

    return ret;
#endif

    /*set idc vip*/
    vip_msg.cmd_data[0] = 0;
    (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                              QNSM_MSG_SYN_BIZ_VIP,
                              &vip_msg,
                              1);
    QNSM_DEBUG(QNSM_DBG_M_VIPAGG, QNSM_DBG_EVT, "not all idc vip %s\n", ip_str);
    QNSM_LOG(CRIT, "ip:%s, local_vip:0\n", ip_str);

    return ret;
}

int32_t qnsm_dpi_policy_statis_msg_proc(void *data, uint32_t data_len)
{
    cJSON *root = NULL;
    cJSON *js_data = NULL;
    cJSON *js_proto = NULL;
    cJSON *js_statis = NULL;
    char  tmp[128];
    struct in_addr ip_addr;
    void *addr;
    QNSM_SESS_DPI_STATIS_MSG *statis_msg = data;
    uint16_t index = 0;
    static const char *dpi_proto[] = {
#define XX(num, name, string) #string,
        QNSM_DPI_PROTO_MAP(XX)
#undef XX
    };
    char *s = NULL;

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root,"req_id", statis_msg->seq_id);
    cJSON_AddStringToObject(root, "sender", qnsm_get_edge_conf()->qnsm_inst_name);
    cJSON_AddStringToObject(root, "op", "ddos_type_check");

    cJSON_AddItemToObject(root,"content", js_data = cJSON_CreateObject());
    if (EN_QNSM_AF_IPv4 == statis_msg->af) {
        ip_addr.s_addr = rte_cpu_to_be_32(statis_msg->vip_key.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, sizeof(tmp));
    } else {
        addr = statis_msg->vip_key.in6_addr.s6_addr;
        (void)inet_ntop(AF_INET6, addr, tmp, sizeof(tmp));
    }
    cJSON_AddStringToObject(js_data, "vip", tmp);
    cJSON_AddStringToObject(js_data, "idc", qnsm_get_edge_conf()->dc_name);
    cJSON_AddNumberToObject(js_data, "sport", statis_msg->dpi_sport);

    cJSON_AddItemToObject(js_data, "app_protocol", js_proto = cJSON_CreateArray());
    for (index = 0; index < EN_QNSM_DPI_PROTO_MAX + 1; index++) {
        if (statis_msg->statis[index].pkts) {
            cJSON_AddItemToArray(js_proto, js_statis = cJSON_CreateObject());
            cJSON_AddStringToObject(js_statis, "app", dpi_proto[index]);
            cJSON_AddNumberToObject(js_statis, "bits", statis_msg->statis[index].bits);
            cJSON_AddNumberToObject(js_statis, "pkts", statis_msg->statis[index].pkts);
        }
    }

    /*
    *send kafka msg
    */
    qnsm_kafka_send_msg(QNSM_KAFKA_CMD_ACK_TOPIC, root, statis_msg->vip_key.in6_addr.s6_addr32[0]);

    if (root) {
        s = cJSON_Print(root);
        QNSM_LOG(CRIT, "send dpi policy statis to borderm, %s\n", s);
        cJSON_free_fun(s);
        cJSON_Delete(root);
    }
    return 0;
}

static int32_t qnsm_master_encap_clock_msg(void *msg, uint32_t *msg_len, void *send_data)
{
    *(uint64_t *)msg = *(uint64_t *)send_data;
    *msg_len = sizeof(uint64_t);
    return 0;
}
static void qnsm_master_clock_syn_timer(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    uint64_t clock = jiffies();

    (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                              QNSM_MSG_CLOCK_SYN,
                              &clock,
                              1);
    return;
}

static void qnsm_master_kafka_cmd_msg_cons(char *payload, uint32_t payload_len)
{
    QNSM_MASTER_DATA *master_data = qnsm_app_data(EN_QNSM_MASTER);
    QNSM_BIZ_VIP_MSG vip_msg;
    EN_QNSM_BORDERM_CMD cmd = EN_QNSM_CMD_MAX;
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *array_obj = NULL;
    cJSON *array_item = NULL;
    uint32_t arr_size = 0;
    uint32_t index = 0;
    QNSM_POLICY_MSG_DATA *policy_msg_data = NULL;
    int32_t ret = 0;
    int32_t af = 0;
    QNSM_IN_ADDR addr;
    uint8_t dc_name_invalid = 0;

    if (NULL == payload) {
        return;
    }
    QNSM_LOG(CRIT, "master cmd msg %s\n", payload);

    root = cJSON_Parse(payload);
    if (NULL == root) {
        return;
    }
    item = cJSON_GetObjectItem(root, "op");
    if (NULL == item) {
        goto EXIT;
    }

    if (0 == strncasecmp(item->valuestring, "ip_sport_statis_enable", strlen("ip_sport_statis_enable"))) {
        cmd = EN_QNSM_CMD_ENABLE_SPORT_STATIS;
    }
    if (0 == strncasecmp(item->valuestring, "ip_sport_statis_disable", strlen("ip_sport_statis_disable"))) {
        cmd = EN_QNSM_CMD_DISABLE_SPORT_STATIS;
    }
    if (0 == strncasecmp(item->valuestring, "ip_dump_pkt_enable", strlen("ip_dump_pkt_enable"))) {
        cmd = EN_QNSM_CMD_DUMP_PKT;
    }
    if (0 == strncasecmp(item->valuestring, "ip_dump_pkt_disable", strlen("ip_dump_pkt_disable"))) {
        cmd = EN_QNSM_CMD_DISABLE_DUMP_PKT;
    }
    if (0 == strncasecmp(item->valuestring, "ddos_type_check", strlen("ddos_type_check"))) {
        cmd = EN_QNSM_CMD_DPI_CHECK;
    }

    if (EN_QNSM_CMD_MAX == cmd) {
        goto EXIT;
    }

    item = cJSON_GetObjectItem(root, "content");
    switch(cmd) {
        case EN_QNSM_CMD_ENABLE_SPORT_STATIS:
        case EN_QNSM_CMD_DISABLE_SPORT_STATIS: {
            arr_size = cJSON_GetArraySize(item);
            for (index = 0; index < arr_size; index++) {
                dc_name_invalid =  0;
                array_obj = cJSON_GetArrayItem(item, index);
                array_item = cJSON_GetObjectItem(array_obj, "idc");
                if ((NULL == array_item->valuestring)
                    || (strncasecmp(array_item->valuestring, qnsm_get_edge_conf()->dc_name, strlen(qnsm_get_edge_conf()->dc_name)))) {
                    dc_name_invalid = 1;
                }

                array_item = cJSON_GetObjectItem(array_obj, "ip");
                af = qnsm_master_get_addr_family(array_item->valuestring);
                if (EN_QNSM_AF_IPv4 == af) {
                    vip_msg.mask = 32;
                    ret = inet_pton(AF_INET, array_item->valuestring, (void *)&vip_msg.key.in4_addr);
                    addr.in4_addr.s_addr = rte_be_to_cpu_32(vip_msg.key.in4_addr.s_addr);
                } else if (EN_QNSM_AF_IPv6 == af) {
                    vip_msg.mask = 128;
                    ret = inet_pton(AF_INET6, array_item->valuestring, (void *)vip_msg.key.in6_addr.s6_addr);
                    addr.in6_addr = vip_msg.key.in6_addr;
                } else {
                    ret = -1;
                }
                if (0 >= ret) {
                    QNSM_LOG(CRIT, "vip address %s invalid\n", array_item->valuestring);
                    break;
                }
                if (dc_name_invalid && (0 == qnsm_match_local_net_segment(af, &addr))) {
                    continue;
                }

                vip_msg.af = af;
                vip_msg.op = QNSM_BIZ_VIP_ADD;
                vip_msg.group_id = master_data->default_group_id;
                vip_msg.cmd = cmd;

                /*snd msg*/
                (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
                QNSM_LOG(CRIT, "rcv statis cmd msg, (cmd:%d, ip:%s)\n", cmd, array_item->valuestring);
            }
            break;
        }
        case EN_QNSM_CMD_DUMP_PKT:
        case EN_QNSM_CMD_DISABLE_DUMP_PKT: {
            arr_size = cJSON_GetArraySize(item);
            for (index = 0; index < arr_size; index++) {
                dc_name_invalid = 0;
                array_obj = cJSON_GetArrayItem(item, index);
                array_item = cJSON_GetObjectItem(array_obj, "idc");
                if ((NULL == array_item->valuestring)
                    || (strncasecmp(array_item->valuestring, qnsm_get_edge_conf()->dc_name, strlen(qnsm_get_edge_conf()->dc_name)))) {
                    dc_name_invalid = 1;
                }

                vip_msg.op = QNSM_BIZ_VIP_ADD;
                vip_msg.group_id = master_data->default_group_id;
                vip_msg.cmd = cmd;
                vip_msg.cmd_data[0] = 1;
                policy_msg_data = (QNSM_POLICY_MSG_DATA *)(vip_msg.cmd_data + 8);

                array_item = cJSON_GetObjectItem(array_obj, "vip");
                if (strncasecmp(array_item->valuestring, "any", strlen("any"))) {

                    af = qnsm_master_get_addr_family(array_item->valuestring);
                    vip_msg.af = af;
                    if (EN_QNSM_AF_IPv4 == af) {
                        vip_msg.mask = 32;
                        ret = inet_pton(AF_INET, array_item->valuestring, (void *)&vip_msg.key.in4_addr);
                        addr.in4_addr.s_addr = rte_be_to_cpu_32(vip_msg.key.in4_addr.s_addr);
                    } else if (EN_QNSM_AF_IPv6 == af) {
                        vip_msg.mask = 128;
                        ret = inet_pton(AF_INET6, array_item->valuestring, (void *)vip_msg.key.in6_addr.s6_addr);
                        addr.in6_addr = vip_msg.key.in6_addr;
                    } else {
                        ret = -1;
                    }
                    if (0 >= ret) {
                        QNSM_LOG(ERR, "vip address %s invalid\n", array_item->valuestring);
                        break;
                    }

                } else {
                    /*now not support global dump*/
                    //vip_msg.key.ip = 0;
                    break;
                }

                if (dc_name_invalid && (0 == qnsm_match_local_net_segment(af, &addr))) {
                    continue;
                }

                QNSM_LOG(CRIT, "rcv dump cmd msg, (cmd:%d, ip:%s)\n", cmd, array_item->valuestring);
                array_item = cJSON_GetObjectItem(array_obj, "vport");
                if (strncasecmp(array_item->valuestring, "any", strlen("any"))) {
                    policy_msg_data->vport = array_item->valueint;
                } else {
                    policy_msg_data->vport = 0;
                }

                array_item = cJSON_GetObjectItem(array_obj, "proto");
                if (0 == strncasecmp(array_item->valuestring, "any", strlen("any"))) {
                    policy_msg_data->proto = 0;
                } else if (0 == strncasecmp(array_item->valuestring, "tcp", strlen("tcp"))) {
                    policy_msg_data->proto = TCP_PROTOCOL;
                } else if (0 == strncasecmp(array_item->valuestring, "udp", strlen("udp"))) {
                    policy_msg_data->proto = UDP_PROTOCOL;
                } else {
                    QNSM_LOG(CRIT, "rcv dump cmd msg, invalid proto %s\n", array_item->valuestring);
                    continue;
                }

                (void)qnsm_msg_send_multi(EN_QNSM_DUMP,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
                (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);

                /*vip sip agg enable/disable*/
                vip_msg.cmd = (EN_QNSM_CMD_DUMP_PKT == cmd) ? EN_QNSM_CMD_VIP_ENABLE_CUS_IP_AGG : EN_QNSM_CMD_VIP_DISABLE_CUS_IP_AGG;
                (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
                (void)qnsm_msg_send_multi(EN_QNSM_SIP_AGG,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);

                /*vip session enable/disable*/
                vip_msg.cmd = (EN_QNSM_CMD_DUMP_PKT == cmd) ? EN_QNSM_CMD_VIP_ENABLE_SESSION : EN_QNSM_CMD_VIP_DISABLE_SESSION;
                (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                          QNSM_MSG_SYN_BIZ_VIP,
                                          &vip_msg,
                                          1);
            }
            break;
        }
        case EN_QNSM_CMD_DPI_CHECK: {
            cJSON *tmp_item = NULL;
            vip_msg.op = QNSM_BIZ_VIP_ADD;
            vip_msg.group_id = master_data->default_group_id;
            vip_msg.cmd = cmd;
            vip_msg.cmd_data[0] = 1;
            policy_msg_data = (QNSM_POLICY_MSG_DATA *)(vip_msg.cmd_data + 8);

            tmp_item = cJSON_GetObjectItem(root, "id");
            *(uint32_t *)(policy_msg_data + 1) = tmp_item->valueint;
            dc_name_invalid = 0;

            array_item = cJSON_GetObjectItem(item, "idc");
            if ((NULL == array_item->valuestring)
                || (strncasecmp(array_item->valuestring, qnsm_get_edge_conf()->dc_name, strlen(qnsm_get_edge_conf()->dc_name)))) {
                dc_name_invalid = 1;
            }

            array_item = cJSON_GetObjectItem(item, "vip");
            if (strncasecmp(array_item->valuestring, "any", strlen("any"))) {
                af = qnsm_master_get_addr_family(array_item->valuestring);
                vip_msg.af = af;
                if (EN_QNSM_AF_IPv4 == af) {
                    vip_msg.mask = 32;
                    ret = inet_pton(AF_INET, array_item->valuestring, (void *)&vip_msg.key.in4_addr);
                    addr.in4_addr.s_addr = rte_be_to_cpu_32(vip_msg.key.in4_addr.s_addr);
                } else if (EN_QNSM_AF_IPv6 == af) {
                    vip_msg.mask = 128;
                    ret = inet_pton(AF_INET6, array_item->valuestring, (void *)vip_msg.key.in6_addr.s6_addr);
                    addr.in6_addr = vip_msg.key.in6_addr;
                } else {
                    ret = -1;
                }
                if (0 >= ret) {
                    QNSM_LOG(ERR, "vip address %s invalid\n", array_item->valuestring);
                    break;
                }
            } else {
                break;
            }
            if (dc_name_invalid && (0 == qnsm_match_local_net_segment(af, &addr))) {
                break;
            }

            QNSM_LOG(CRIT, "rcv dpi policy cmd msg, (id:%u, ip:%s)\n",
                    *(uint32_t *)(policy_msg_data + 1), array_item->valuestring);
            array_item = cJSON_GetObjectItem(item, "sport");
            if (NULL == array_item->valuestring) {
                policy_msg_data->sport = array_item->valueint;
            } else {
                /*any or others*/
                break;
            }

            (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                      QNSM_MSG_SYN_BIZ_VIP,
                                      &vip_msg,
                                      1);
            break;
        }
        default: {
            break;
        }
    }

EXIT:
    cJSON_Delete(root);
    return;
}

static void qnsm_master_run(void *this)
{
#ifdef  DEBUG_QNSM
    QNSM_MASTER_DATA *master_data = this;
    QNSM_CMD_HANDLE *cmd_handle = master_data->cmd_hdl;
    int32_t status;

    /* Command Line Interface (CLI) */
    status = cmdline_poll(cmd_handle->cl);
    if (status == RDLINE_EXITED) {
        cmdline_stdin_exit(cmd_handle->cl);
        rte_exit(0, "Bye!\n");
    }
#endif

#ifdef QNSM_LIBQNSM_IDPS
    if (((QNSM_MASTER_DATA *)this)->deploy_idps) {
        if (qnsm_idps_sig_act()) {
            /*elegant exit*/
            qnsm_idps_exit();
        }

    } else {
        usleep(10000);
    }
#endif

    qnsm_kafka_msg_dispatch();
    return;
}

int32_t qnsm_master_init(void)
{
    QNSM_MASTER_DATA *master_data = NULL;
    EN_QNSM_APP *app_type = app_get_lcore_app_type(qnsm_service_get_cfg_para());
    uint16_t lcore_id = 0;
    void *kafka_cfg = NULL;
    int32_t ret = 0;

    /*data init*/
    master_data = qnsm_app_inst_init(sizeof(QNSM_MASTER_DATA),
                                     NULL,
                                     NULL,
                                     qnsm_master_run);
    if (NULL == master_data) {
        QNSM_ASSERT(0);
    }
    master_data->edge_cfg_data = qnsm_get_edge_conf();
    master_data->vip_cfg_data = qnsm_get_groups();
    master_data->default_group_id = 0;

#ifdef QNSM_LIBQNSM_IDPS
    struct app_params *app_paras = qnsm_service_get_cfg_para();

    master_data->deploy_idps = app_type_find(app_paras, EN_QNSM_DETECT);
    if (master_data->deploy_idps) {
        /*wait ips*/
        qnsm_idps_wait();
    }
#endif

    /*msg init*/
    for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++) {
        if ((EN_QNSM_SESSM == app_type[lcore_id])
            || (EN_QNSM_SIP_AGG == app_type[lcore_id])
            || ((EN_QNSM_VIP_AGG == app_type[lcore_id]))
            || (EN_QNSM_DUMP == app_type[lcore_id])) {
            (void)qnsm_msg_subscribe(lcore_id);
        }
    }
    (void)qnsm_msg_publish();
    (void)qnsm_msg_reg(QNSM_MSG_DYN_VIP_ADD, qnsm_master_vip_add_msg_proc, NULL);
    (void)qnsm_msg_reg(QNSM_MSG_SESS_DPI_STATIS, qnsm_dpi_policy_statis_msg_proc, NULL);
    (void)qnsm_msg_reg(QNSM_MSG_SYN_BIZ_VIP, NULL, qnsm_master_encap_biz_vip_msg);
    (void)qnsm_msg_reg(QNSM_MSG_CLOCK_SYN, NULL, qnsm_master_encap_clock_msg);

    /*cmd*/
#ifdef  DEBUG_QNSM
    (void)qnsm_cmd_init((void **)&master_data->cmd_hdl);
#endif

    /*kafka*/
    static const char *kafka_inst[] = {
#define XX(num, name, string) string,
        QNSM_KAFKA_MAP(XX)
#undef XX
    };

    kafka_cfg = qnsm_get_kafka_cfg(kafka_inst[QNSM_MASTER_PROD_KAFKA]);
    if (kafka_cfg) {
        (void)qnsm_kafka_app_init_producer(kafka_cfg);
    }

    kafka_cfg = qnsm_get_kafka_cfg(kafka_inst[QNSM_MASTER_CMD_CONS]);
    if (kafka_cfg) {
        (void)qnsm_kafka_app_init_consumer(qnsm_get_edge_conf()->dc_name, kafka_cfg);
        qnsm_kafka_msg_reg(QNSM_KAFKA_CMD_TOPIC, qnsm_master_kafka_cmd_msg_cons);
    }

    ret = rte_timer_reset(&master_data->syn_clock,
                          rte_get_timer_hz(), PERIODICAL,
                          rte_lcore_id(), qnsm_master_clock_syn_timer, NULL);
    QNSM_LOG(CRIT, "syn clock init %d\n", ret);

#ifdef __LEARN_SERVICE_VIP
    QNSM_BORDERM_CFG *bm_cfg = &qnsm_get_groups()->borderm_cfg;

    /*redis init*/
    if (bm_cfg->redis_enable) {
        qnsm_master_redis_init(&master_data->redis_ctx, bm_cfg->redis_addr, bm_cfg->redis_port, bm_cfg->auth_token);
    }
#endif

    return 0;
}

