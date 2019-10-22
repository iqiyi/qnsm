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
#include <getopt.h>

#include <sys/stat.h>
#include <sys/syslog.h>
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
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_lpm.h>
#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_port.h>


#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_socket.h>

/* xml lib */
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "util.h"
#include "qnsm_inspect_main.h"
#include "app.h"
#include "qnsm_msg_ex.h"
#include "qnsm_tbl_ex.h"
#include "qnsm_cfg.h"
#include "qnsm_dbg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_session_ex.h"
#include "qnsm_ip_agg.h"
#include "qnsm_master_ex.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_HASH_CRC 1
#endif


QNSM_SESSM_CFG *g_sessm_cfg;
QNSM_VIP_CFG    g_qnsm_vip_cfg;
QNSM_EDGE_CFG  *g_qnsm_edge_cfg = NULL;
QNSM_DUMP_CFG   g_qnsm_dump_cfg;

uint32_t    g_qnsm_dbg = 0;

/*
 * Converts a given depth value to its corresponding mask value.
 *
 * depth  (IN)      : range = 1 - 32
 * mask   (OUT)     : 32bit mask
 */
uint32_t qnsm_ipv4_depth_to_mask(uint8_t depth)
{
    if ((depth == 0) || (depth > 32)) {
        QNSM_ASSERT(0);
    }

    /* To calculate a mask start with a 1 on the left hand side and right
     * shift while populating the left hand side with 1's
     */
    return (int)0x80000000 >> (depth - 1);
}

/*
 * Takes an array of uint8_t (IPv6 address) and masks it using the depth.
 * It leaves untouched one bit per unit in the depth variable
 * and set the rest to 0.
 */
static inline void
qnsm_mask_ipv6(uint8_t *ip, uint8_t depth)
{
    int16_t part_depth, mask;
    int i;

    part_depth = depth;

    for (i = 0; i < 16; i++) {
        if (part_depth < 8 && part_depth >= 0) {
            mask = (uint16_t)(~(UINT8_MAX >> part_depth));
            ip[i] = (uint8_t)(ip[i] & mask);
        } else if (part_depth < 0) {
            ip[i] = 0;
        }
        part_depth -= 8;
    }
}


#if QNSM_PART("sessm")
inline QNSM_SESSM_CFG* qnsm_get_sessm_conf(void)
{
    return g_sessm_cfg;
}

static int32_t qnsm_sessm_conf_init(void)
{
    g_sessm_cfg = rte_zmalloc(NULL, sizeof(QNSM_SESSM_CFG), QNSM_DDOS_MEM_ALIGN);

    if (NULL == g_sessm_cfg) {
        QNSM_ASSERT(0);
    }

    return 0;
}

QNSM_PROTO_CFG* qnsm_get_proto_conf(const char *name)
{
    QNSM_SESSM_CFG *sessm_cfg = qnsm_get_sessm_conf();
    uint32_t index = 0;

    for (index = 0; index < sessm_cfg->app_num; index++) {
        if (!strncmp(name, sessm_cfg->app_prot_cfg[index].app_name, strlen(name))) {
            break;
        }
    }

    if (index >= sessm_cfg->app_num) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "app %s not exists in conf\n", name);
        return NULL;
    }
    return &sessm_cfg->app_prot_cfg[index];
}


void qnsm_parse_proto(xmlDocPtr doc, xmlNodePtr cur, QNSM_PROTO_CFG *app_proto_cfg)
{
    xmlChar *key;

    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "cur proto : %s\n", cur->name);
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"name"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            strncpy(app_proto_cfg->app_name, (const char *)key, sizeof(app_proto_cfg->app_name) - 1);
            app_proto_cfg->app_name[sizeof(app_proto_cfg->app_name) - 1] = '\0';
            xmlFree(key);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "app : %s\n", app_proto_cfg->app_name);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"enable"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            if (!xmlStrcmp(key, (const xmlChar *)"yes")) {
                app_proto_cfg->enable = 1;
            } else {
                app_proto_cfg->enable = 0;
            }
            xmlFree(key);

            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "enable : %d\n", app_proto_cfg->enable);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"parse"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            if (!xmlStrcmp(key, (const xmlChar *)"yes")) {
                app_proto_cfg->parse_enable = 1;
            } else {
                app_proto_cfg->parse_enable = 0;
            }
            xmlFree(key);

            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "parse_enable : %d\n", app_proto_cfg->parse_enable);
        }
        cur = cur->next;
    }

    return;
}


void qnsm_parse_dpi_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_PROTO_CFG **app_proto_cfg)
{
    xmlNodePtr tmp = cur;
    uint64_t app_num = 0;
    uint64_t index = 0;
    QNSM_PROTO_CFG *conf = NULL;
    QNSM_SESSM_CFG *sessm_cfg = qnsm_get_sessm_conf();

    for(cur = tmp->xmlChildrenNode; cur; cur = cur->next) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"protocol"))) {
            app_num++;
        }
    }

    conf = rte_zmalloc(NULL, sizeof(QNSM_PROTO_CFG) * app_num, QNSM_DDOS_MEM_ALIGN);
    if (NULL == conf) {
        QNSM_ASSERT(0);
        return;
    }
    *app_proto_cfg = conf;
    sessm_cfg->app_num = app_num;

    cur = tmp->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"protocol"))) {
            qnsm_parse_proto(doc, cur, &conf[index]);
            index++;
        }

        cur = cur->next;
    }
    return;
}

void qnsm_parse_filter_port_cfg(xmlDocPtr doc, xmlNodePtr cur, uint8_t *port_filter_map)
{
    xmlNodePtr tmp = cur;
    xmlChar *key;
    uint16_t port = 0;

    cur = tmp->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"port"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);

            port = atoi(key);
            port_filter_map[port >> 3] |= (0x01 << (port & 0x07));

            xmlFree(key);
        }
        cur = cur->next;
    }
    return;
}

void qnsm_parse_sample_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_SESSM_CFG *sess_cfg)
{
    xmlNodePtr tmp = cur;
    xmlChar *key;

    cur = tmp->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"enable"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            if (!xmlStrcmp(key, (const xmlChar *)"yes")) {
                sess_cfg->sample_enable = 1;
            } else {
                sess_cfg->sample_enable = 0;
            }
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"method"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            if (!xmlStrcmp(key, (const xmlChar *)"packet")) {
                sess_cfg->sample_method = EN_QNSM_PACKET_SAMPLE;
            } else if (!xmlStrcmp(key, (const xmlChar *)"flow")) {
                sess_cfg->sample_method = EN_QNSM_FLOW_SAMPLE;
            } else {
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "sample conf error, not support method %s", key);
                xmlFree(key);
                return;
            }
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"rate"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            sess_cfg->sample_rate = atoi(key);
            xmlFree(key);
        }
        cur = cur->next;
    }

    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "sample enable %d method %d rate %d\n",
               sess_cfg->sample_enable,
               sess_cfg->sample_method,
               sess_cfg->sample_rate);
    return;
}

static int32_t qnsm_sessm_conf_parse(const char *conf_file_path)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL, node = NULL;
    xmlChar *key = NULL;
    QNSM_SESSM_CFG *sessm_cfg = qnsm_get_sessm_conf();

    /*init sample method*/
    sessm_cfg->sample_method = EN_QNSM_PACKET_SAMPLE;

    doc = xmlReadFile(conf_file_path, NULL, 0);
    if(doc == NULL) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed conf_file_path = %s", conf_file_path);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    if(root_node == NULL) {
        xmlFreeDoc(doc);
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, " xmlDocGetRootElement failed");
        return -1;
    }

    for(node = root_node->xmlChildrenNode; node; node = node->next) {
        if ((!xmlStrcmp(node->name, (const xmlChar *)"care_biz"))) {
            key = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "care_biz : %s\n", key);
            if (!xmlStrcmp(key, (const xmlChar *)"yes") || !xmlStrcmp(key, (const xmlChar *)"YES")) {
                sessm_cfg->care_biz = 1;
            } else if (!xmlStrcmp(key, (const xmlChar *)"no") || !xmlStrcmp(key, (const xmlChar *)"NO")) {
                sessm_cfg->care_biz = 0;
            } else {
                QNSM_ASSERT(0);
            }
        }
        if (!xmlStrcmp(node->name, (const xmlChar *)"sample")) {
            qnsm_parse_sample_cfg(doc, node, sessm_cfg);
        }
        if ((!xmlStrcmp(node->name, (const xmlChar *)"conn"))) {
            ;
        }
        if ((!xmlStrcmp(node->name, (const xmlChar *)"stream_reassemble"))) {
            ;
        }
        if ((!xmlStrcmp(node->name, (const xmlChar *)"dpi"))) {
            qnsm_parse_dpi_cfg(doc, node, &sessm_cfg->app_prot_cfg);
        }
        if ((!xmlStrcmp(node->name, (const xmlChar *)"filter"))) {
            qnsm_parse_filter_port_cfg(doc, node, sessm_cfg->port_filter_map);
        }
    }

    xmlFreeDoc(doc);
    return 0;
}
#endif


#if QNSM_PART("group cfg parse")

QNSM_SERVICES_CFG *qnsm_get_known_ports(void)
{
    return &g_qnsm_vip_cfg.auto_detect_service_cfg;
}

inline int32_t qnsm_match_service(void *data, uint16_t port)
{
    int32_t ret = 0;
    QNSM_SERVICES_CFG *cfg = &g_qnsm_vip_cfg.auto_detect_service_cfg;
    uint16_t index = 0;

    for (index = 0; index < cfg->port_num; index++) {
        if (port == cfg->port[index]) {
            return 1;
        }
    }
    return ret;
}

inline QNSM_VIP_CFG* qnsm_get_groups(void)
{
    return &g_qnsm_vip_cfg;
}
inline uint32_t qnsm_group_is_valid(uint32_t group_id)
{
    if ((QNSM_MAX_SVR_GROUP_NUM <= group_id)
        || (NULL == g_qnsm_vip_cfg.group[group_id])) {
        return 0;
    }

    return g_qnsm_vip_cfg.group[group_id]->valid;
}

inline QNSM_SVR_IP_GROUP* qnsm_get_group(uint32_t group_id)
{
    if (QNSM_MAX_SVR_GROUP_NUM <= group_id) {
        return NULL;
    }
    return g_qnsm_vip_cfg.group[group_id];
}

inline uint16_t qnsm_group_num(void)
{
    return g_qnsm_vip_cfg.group_num;
}

int32_t qnsm_match_local_net_segment(enum en_qnsm_ip_af af, QNSM_IN_ADDR *in_addr)
{
    QNSM_SVR_IP_GROUP *group = NULL;
    QNSM_SVR_IP_GROUP *tmp = NULL;
    int32_t index = 0;
    uint8_t ip6[16];
    struct qnsm_list_head *groups = NULL;

    switch (af) {
        case EN_QNSM_AF_IPv4: {
            groups = &g_qnsm_vip_cfg.v4_groups;
            if (qnsm_list_empty(groups)) {
                break;
            }
            qnsm_list_for_each_entry_safe(group, tmp, groups, v4_node) {
                for (index = 0; index < group->host_num; index++) {
                    if (rte_be_to_cpu_32(group->hosts[index].addr.in4_addr.s_addr)
                        == (in_addr->in4_addr.s_addr & qnsm_ipv4_depth_to_mask(group->hosts[index].mask))) {
                        return 1;
                    }
                }
            }
            break;
        }
        case EN_QNSM_AF_IPv6: {
            groups = &g_qnsm_vip_cfg.v6_groups;
            if (qnsm_list_empty(groups)) {
                break;
            }
            qnsm_list_for_each_entry_safe(group, tmp, groups, v6_node) {
                for (index = 0; index < group->host6_num; index++) {
                    memcpy(ip6, in_addr->in6_addr.s6_addr, 16);
                    qnsm_mask_ipv6(ip6, group->v6_hosts[index].mask);
                    if (0 == memcmp(group->v6_hosts[index].addr.in6_addr.s6_addr, ip6, 16)) {
                        return 1;
                    }
                }
            }
            break;
        }
        default:
            return 0;
    }

    return 0;
}

int32_t qnsm_match_all_net_segment(enum en_qnsm_ip_af af, QNSM_IN_ADDR *in_addr)
{
    QNSM_SERVICES_CFG *cfg = &g_qnsm_vip_cfg.auto_detect_service_cfg;
    int32_t index = 0;
    uint8_t ip6[16];

    switch (af) {
        case EN_QNSM_AF_IPv4: {
            for (index = 0; index < cfg->v4_net_num; index++) {
                if (rte_be_to_cpu_32(cfg->v4_net[index].addr.in4_addr.s_addr)
                    == (in_addr->in4_addr.s_addr & qnsm_ipv4_depth_to_mask(cfg->v4_net[index].mask))) {
                    return cfg->v4_net[index].mask;
                }
            }
            break;
        }
        case EN_QNSM_AF_IPv6: {
            for (index = 0; index < cfg->v6_net_num; index++) {
                memcpy(ip6, in_addr->in6_addr.s6_addr, 16);
                qnsm_mask_ipv6(ip6, cfg->v6_net[index].mask);
                if (0 == memcmp(cfg->v6_net[index].addr.in6_addr.s6_addr, ip6, 16)) {
                    return cfg->v6_net[index].mask;
                }
            }
            break;
        }
        default:
            return 0;
    }

    return 0;
}


void qnsm_parse_hosts_node(xmlDocPtr doc, xmlNodePtr cur, QNSM_SVR_IP_GROUP *svr_group)
{
    xmlChar *key;
    xmlNodePtr tmp_cur = cur;
    uint16_t host_num = 0;
    QNSM_SRV_HOST *tmp_host = NULL;

    cur = cur->xmlChildrenNode;
    char *p;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"ip"))) {
            host_num++;
        }
        cur = cur->next;
    }
    if (0 == host_num) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "no ip configured\n");
        return;
    }

    svr_group->hosts = (QNSM_SRV_HOST *)rte_malloc("hosts", sizeof(QNSM_SRV_HOST) * host_num, QNSM_DDOS_MEM_ALIGN);
    if (NULL == svr_group->hosts) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, " malloc hosts failed\n");
        return;
    }
    svr_group->host_num = host_num;

    tmp_host = svr_group->hosts;
    cur = tmp_cur->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"ip"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);

            p = strtok(key, "/");
            if(p) {
                tmp_host->addr.in4_addr.s_addr = inet_addr(p);;
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "ip prefix %s \n", p);
            }

            p = strtok(NULL, "/");
            if(p) {
                tmp_host->mask = atoi(p);
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "mask %s\n", p);
            }
            tmp_host++;
            xmlFree(key);
        }
        cur = cur->next;
    }
    return;
}


void qnsm_parse_v6_hosts_node(xmlDocPtr doc, xmlNodePtr cur, QNSM_SVR_IP_GROUP *svr_group)
{
    xmlChar *key;
    xmlNodePtr tmp_cur = cur;
    uint16_t host_num = 0;
    QNSM_SRV_HOST *tmp_host = NULL;

    cur = cur->xmlChildrenNode;
    char *p;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"ipv6"))) {
            host_num++;
        }
        cur = cur->next;
    }
    if (0 == host_num) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "no ip configured\n");
        return;
    }

    svr_group->v6_hosts = (QNSM_SRV_HOST *)rte_malloc("hosts", sizeof(QNSM_SRV_HOST) * host_num, QNSM_DDOS_MEM_ALIGN);
    if (NULL == svr_group->v6_hosts) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, " malloc hosts failed\n");
        return;
    }
    svr_group->host6_num = host_num;

    tmp_host = svr_group->v6_hosts;
    cur = tmp_cur->xmlChildrenNode;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"ipv6"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);

            p = strtok(key, "/");
            if(p) {
                /*v6 addr, net order*/
                inet_pton(AF_INET6, p, tmp_host->addr.in6_addr.s6_addr);
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "ipv6 prefix %s \n", p);
            }

            p = strtok(NULL, "/");
            if(p) {
                tmp_host->mask = atoi(p);
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "mask %s\n", p);
            }

            tmp_host++;
            xmlFree(key);
        }
        cur = cur->next;
    }
    return;
}



void qnsm_parse_group_node(xmlDocPtr doc, xmlNodePtr cur, QNSM_SVR_IP_GROUP *svr_group)
{
    xmlChar *key;
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"name"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "name : %s\n", key);
            strncpy(svr_group->name, (const char*)key, QNSM_SVR_GROUP_NAME_LEN - 1);
            svr_group->name[QNSM_SVR_GROUP_NAME_LEN - 1] = '\0';
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"ban"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "ban : %s\n", key);
            svr_group->threshold_enable = (!xmlStrcmp(key, (const xmlChar *)"on")) ? 1 : 0;
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"threshold_pps"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "threshold_pps : %s\n", key);
            svr_group->threshold_pps = atoi(key);
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"threshold_mbps"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            svr_group->threshold_mbps = atoi(key);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "threshold_mbps : %s\n", key);
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"hosts"))) {
            qnsm_parse_hosts_node(doc, cur, svr_group);
            qnsm_parse_v6_hosts_node(doc, cur, svr_group);
        }
        cur = cur->next;
    }

    return;
}

void qnsm_parse_services_port(xmlDocPtr doc, xmlNodePtr cur, QNSM_SERVICES_CFG *services_cfg)
{
    xmlChar *key;
    cur = cur->xmlChildrenNode;

    key = xmlNodeListGetString(doc, cur, 1);
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "port : %s\n", key);
    services_cfg->port[services_cfg->port_num] = atoi(key);
    services_cfg->port_num++;
    xmlFree(key);

    return;
}

void qnsm_parse_services_net(xmlDocPtr doc, xmlNodePtr cur, QNSM_SERVICES_CFG *services_cfg)
{
    QNSM_SRV_HOST *tmp_net = NULL;
    char *p;
    xmlChar *key;

    cur = cur->xmlChildrenNode;
    key = xmlNodeListGetString(doc, cur, 1);

    if (services_cfg->v4_net_num < services_cfg->v4_net_size) {
        tmp_net = &services_cfg->v4_net[services_cfg->v4_net_num++];

        p = strtok(key, "/");
        if(p) {
            /*v4 addr, net order*/
            tmp_net->addr.in4_addr.s_addr = inet_addr(p);;
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "net prefix %s \n", p);
        }

        p = strtok(NULL, "/");
        if(p) {
            tmp_net->mask = atoi(p);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "mask %s\n", p);
        }
    } else {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "add  %s failed\n", key);
    }

    xmlFree(key);
    return;
}

void qnsm_parse_services_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_SERVICES_CFG *services_cfg)
{

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"port"))) {
            qnsm_parse_services_port(doc, cur, services_cfg);
        }

        if (!xmlStrcmp(cur->name, (const xmlChar *)"net")) {
            qnsm_parse_services_net(doc, cur, services_cfg);
        }
        cur = cur->next;
    }
    return;
}

#ifdef __PF
void qnsm_parse_pf_ip(xmlDocPtr doc, xmlNodePtr cur, QNSM_PF_CFG *pf_cfg)
{
    xmlChar *key;
    char *p;
    QNSM_SRV_HOST *tmp_host = NULL;

    cur = cur->xmlChildrenNode;

    key = xmlNodeListGetString(doc, cur, 1);

    tmp_host = &pf_cfg->pf_vip;
    p = strtok(key, "/");
    if(p) {
        /*v4 addr, net order*/
        tmp_host->addr.in4_addr.s_addr = inet_addr(p);;
    }

    p = strtok(NULL, "/");
    if(p) {
        tmp_host->mask = atoi(p);
    }

    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "pf vip : %s\n", key);

    xmlFree(key);

    return;
}

void qnsm_parse_pf_port(xmlDocPtr doc, xmlNodePtr cur, QNSM_PF_CFG *pf_cfg)
{
    xmlChar *key;

    cur = cur->xmlChildrenNode;

    key = xmlNodeListGetString(doc, cur, 1);
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "pf port : %s\n", key);
    pf_cfg->port = atoi(key);
    xmlFree(key);
    return;
}

void qnsm_parse_pf_proto(xmlDocPtr doc, xmlNodePtr cur, QNSM_PF_CFG *pf_cfg)
{
    xmlChar *key;

    cur = cur->xmlChildrenNode;

    key = xmlNodeListGetString(doc, cur, 1);
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "pf proto : %s\n", key);
    if (!strcmp((const char *)key, "tcp")) {
        pf_cfg->proto = TCP_PROTOCOL;
    } else if (!strcmp((const char *)key, "udp")) {
        pf_cfg->proto = UDP_PROTOCOL;
    } else if (!strcmp((const char *)key, "icmp")) {
        pf_cfg->proto = ICMP_PROTOCOL;
    } else {
        pf_cfg->proto = 0;
    }

    xmlFree(key);
    return;
}


void qnsm_parse_pf_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_PF_CFG *pf_cfg)
{
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"ip"))) {
            qnsm_parse_pf_ip(doc, cur, pf_cfg);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"port"))) {
            qnsm_parse_pf_port(doc, cur, pf_cfg);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"proto"))) {
            qnsm_parse_pf_proto(doc, cur, pf_cfg);
        }
        cur = cur->next;
    }

    return;
}
#endif

void qnsm_parse_borderm_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_BORDERM_CFG *bm_cfg)
{
    xmlNodePtr child_node;
    xmlChar *key;

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"redis"))) {
            /*set redis enable*/
            bm_cfg->redis_enable = 1;

            child_node = cur->xmlChildrenNode;
            while (child_node) {
                if ((!xmlStrcmp(child_node->name, (const xmlChar *)"addr"))) {
                    key = xmlNodeListGetString(doc, child_node->xmlChildrenNode, 1);
                    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "redis addr : %s\n", key);
                    strcpy(bm_cfg->redis_addr, key);
                    xmlFree(key);
                }

                if ((!xmlStrcmp(child_node->name, (const xmlChar *)"port"))) {
                    key = xmlNodeListGetString(doc, child_node->xmlChildrenNode, 1);
                    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "redis port : %s\n", key);
                    bm_cfg->redis_port = atoi(key);
                    xmlFree(key);
                }

                if ((!xmlStrcmp(child_node->name, (const xmlChar *)"auth"))) {
                    key = xmlNodeListGetString(doc, child_node->xmlChildrenNode, 1);
                    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "redis auth token: %s\n", key);
                    strcpy(bm_cfg->auth_token, key);
                    xmlFree(key);
                }
                child_node = child_node->next;
            }
        }

        cur = cur->next;
    }

    return;
}

#ifdef __LEARN_SERVICE_VIP
#define ALL_IPV4_NET_SEGMENTS_GET_CMD_FORMAT ("smembers network:segments:v4")
#define ALL_IPV6_NET_SEGMENTS_GET_CMD_FORMAT ("smembers network:segments:v6")

redisContext* qnsm_cfg_init_redis_ctx(void)
{
    redisContext *c = NULL;
    redisReply *reply;
    uint32_t conn_cnt = 0;
    char cmd[128] = {0};

    while ((3 > conn_cnt) && (NULL == c)) {
        c = redisConnect(g_qnsm_vip_cfg.borderm_cfg.redis_addr, g_qnsm_vip_cfg.borderm_cfg.redis_port);
        if (c == NULL || c->err) {
            if (c) {
                printf("Connection error: %s\n", c->errstr);
                redisFree(c);
            } else {
                printf("Connection error: can't allocate redis context\n");
            }
            conn_cnt++;
        } else {
            snprintf(cmd, sizeof(cmd), DYN_VIP_REDIS_AUTH_CMD_FORMAT, g_qnsm_vip_cfg.borderm_cfg.auth_token);

            /*auth*/
            while(NULL == (reply = redisCommand(c, cmd)));
            QNSM_LOG(INFO, "redis connect success\n");
            break;
        }
    }

    return c;
}
#endif

int qnsm_vip_conf_parse(const char *conf_file_path)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL, node = NULL;
    char name[64];
    int group_num = 0;

    doc = xmlReadFile(conf_file_path, NULL, 0);
    if(doc == NULL) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed conf_file_path = %s\n", conf_file_path);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    if(root_node == NULL) {
        xmlFreeDoc(doc);
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, " xmlDocGetRootElement failed\n");
        return -1;
    }

    for(node = root_node->xmlChildrenNode; node; node = node->next) {
        if ((!xmlStrcmp(node->name, (const xmlChar *)"borderm"))) {
            g_qnsm_vip_cfg.borderm_cfg.redis_enable = 0;
            qnsm_parse_borderm_cfg(doc, node, &g_qnsm_vip_cfg.borderm_cfg);
        }

        if ((!xmlStrcmp(node->name, (const xmlChar *)"group"))) {
            if (group_num >= QNSM_MAX_SVR_GROUP_NUM) {
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "exceed max srv group num\n");
                return -1;
            }
            snprintf(name, sizeof(name), "group_%d", group_num);
            g_qnsm_vip_cfg.group[group_num] = (QNSM_SVR_IP_GROUP *)rte_malloc(name, sizeof(QNSM_SVR_IP_GROUP), QNSM_DDOS_MEM_ALIGN);
            if (NULL == g_qnsm_vip_cfg.group[group_num]) {
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, " malloc srv group failed\n");
                return -1;
            }
            memset(g_qnsm_vip_cfg.group[group_num], 0, sizeof(QNSM_SVR_IP_GROUP));
            QNSM_INIT_LIST_HEAD(&g_qnsm_vip_cfg.group[group_num]->v4_node);
            QNSM_INIT_LIST_HEAD(&g_qnsm_vip_cfg.group[group_num]->v6_node);

            g_qnsm_vip_cfg.group[group_num]->group_id = group_num;
            g_qnsm_vip_cfg.group[group_num]->valid = 1;
            qnsm_parse_group_node(doc, node, g_qnsm_vip_cfg.group[group_num]);
            group_num++;
        }

        if ((!xmlStrcmp(node->name, (const xmlChar *)"services"))) {
            qnsm_parse_services_cfg(doc, node, &g_qnsm_vip_cfg.auto_detect_service_cfg);
        }

#ifdef __PF
        if ((!xmlStrcmp(node->name, (const xmlChar *)"pf"))) {
            if (g_qnsm_vip_cfg.pf_num >= QNSM_MAX_PF_NUM) {
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "exceed max srv pf num\n");
                return -1;
            }
            qnsm_parse_pf_cfg(doc, node, &g_qnsm_vip_cfg.pf_cfg[g_qnsm_vip_cfg.pf_num]);
            g_qnsm_vip_cfg.pf_num++;
        }
#endif
    }
    g_qnsm_vip_cfg.group_num = group_num;

    /*init v4/v6 net-seg group list*/
    uint32_t index = 0;
    for ( ; index < g_qnsm_vip_cfg.group_num; index++) {
        if (0 == strcmp(g_qnsm_vip_cfg.group[index]->name, "disable_ip")) {
            continue;
        }

        if (g_qnsm_vip_cfg.group[index]->host_num) {
            qnsm_list_add_tail(&g_qnsm_vip_cfg.group[index]->v4_node, &g_qnsm_vip_cfg.v4_groups);
        }

        if (g_qnsm_vip_cfg.group[index]->host6_num) {
            qnsm_list_add_tail(&g_qnsm_vip_cfg.group[index]->v6_node, &g_qnsm_vip_cfg.v6_groups);
        }
    }

    xmlFreeDoc(doc);

#ifdef __LEARN_SERVICE_VIP
    if (g_qnsm_vip_cfg.borderm_cfg.redis_enable) {
        redisContext *c = qnsm_cfg_init_redis_ctx();

        /*get all non-local idc vip net segments*/
        QNSM_SERVICES_CFG *services_cfg = &g_qnsm_vip_cfg.auto_detect_service_cfg;
        redisReply *reply;
        int32_t i = 0;
        char *p = NULL;
        QNSM_SRV_HOST net_seg;
        QNSM_IN_ADDR tmp_addr;

        if (NULL == c) {
            return 0;
        }

        reply = redisCommand(c, "select 3");
        if (reply->type == REDIS_REPLY_ERROR) {
            return 0;
        }
        if (reply = redisCommand(c, ALL_IPV4_NET_SEGMENTS_GET_CMD_FORMAT)) {
            if (reply->type == REDIS_REPLY_ARRAY) {
                for (i = 0; i < reply->elements; i++) {
                    if (0 == strncmp(reply->element[i]->str, "10.", strlen("10."))) {
                        continue;
                    }
                    if (0 == strncmp(reply->element[i]->str, "192.", strlen("192."))) {
                        continue;
                    }
                    if (services_cfg->v4_net_num >= services_cfg->v4_net_size) {
                        continue;
                    }

                    QNSM_LOG(INFO, "%u) %s\n", i, reply->element[i]->str);
                    p = strtok(reply->element[i]->str, "/");
                    if(p) {
                        if (0 >= inet_pton(AF_INET, p, &net_seg.addr.in4_addr)) {
                            continue;
                        }
                        tmp_addr.in4_addr.s_addr = ntohl(net_seg.addr.in4_addr.s_addr);
                        if (qnsm_match_local_net_segment(EN_QNSM_AF_IPv4, &tmp_addr)) {
                            QNSM_LOG(INFO, "%u) %s local idc segment\n", i, reply->element[i]->str);
                            continue;
                        }
                    }
                    p = strtok(NULL, "/");
                    if(p) {
                        net_seg.mask = atoi(p);
                    }

                    services_cfg->v4_net[services_cfg->v4_net_num] = net_seg;
                    services_cfg->v4_net_num++;
                }
                QNSM_LOG(INFO, "v4 net segments %u\n", services_cfg->v4_net_num);
            }

            freeReplyObject(reply);
        }

        if (reply = redisCommand(c, ALL_IPV6_NET_SEGMENTS_GET_CMD_FORMAT)) {
            if (reply->type == REDIS_REPLY_ARRAY) {
                for (i = 0; i < reply->elements; i++) {
                    if (services_cfg->v6_net_num >= services_cfg->v6_net_size) {
                        continue;
                    }

                    QNSM_LOG(INFO, "%u) %s\n", i, reply->element[i]->str);
                    p = strtok(reply->element[i]->str, "/");
                    if(p) {
                        if (0 >= inet_pton(AF_INET6, p, &net_seg.addr.in6_addr)) {
                            continue;
                        }

                        if (qnsm_match_local_net_segment(EN_QNSM_AF_IPv6, &net_seg.addr)) {
                            QNSM_LOG(INFO, "%u) %s local idc segment\n", i, reply->element[i]->str);
                            continue;
                        }
                    }
                    p = strtok(NULL, "/");
                    if(p) {
                        net_seg.mask = atoi(p);
                    }

                    services_cfg->v6_net[services_cfg->v6_net_num] = net_seg;
                    services_cfg->v6_net_num++;
                }
            }

            freeReplyObject(reply);
        }

        /*free redis ctx*/
        if (c) {
            redisFree(c);
        }
    }
#endif
    return 0;
}

void qnsm_vip_conf_init(void)
{
    /*init all vip net segments*/
    QNSM_INIT_LIST_HEAD(&g_qnsm_vip_cfg.v4_groups);
    QNSM_INIT_LIST_HEAD(&g_qnsm_vip_cfg.v6_groups);
    g_qnsm_vip_cfg.auto_detect_service_cfg.v4_net_num = 0;
    g_qnsm_vip_cfg.auto_detect_service_cfg.v4_net_size = 4096;
    g_qnsm_vip_cfg.auto_detect_service_cfg.v4_net = rte_zmalloc(NULL, sizeof(QNSM_SRV_HOST) * g_qnsm_vip_cfg.auto_detect_service_cfg.v4_net_size, QNSM_DDOS_MEM_ALIGN);
    if (NULL == g_qnsm_vip_cfg.auto_detect_service_cfg.v4_net) {
        QNSM_ASSERT(0);
    }

    g_qnsm_vip_cfg.auto_detect_service_cfg.v6_net_num = 0;
    g_qnsm_vip_cfg.auto_detect_service_cfg.v6_net_size = 2048;
    g_qnsm_vip_cfg.auto_detect_service_cfg.v6_net = rte_zmalloc(NULL, sizeof(QNSM_SRV_HOST) * g_qnsm_vip_cfg.auto_detect_service_cfg.v6_net_size, QNSM_DDOS_MEM_ALIGN);
    if (NULL == g_qnsm_vip_cfg.auto_detect_service_cfg.v6_net) {
        QNSM_ASSERT(0);
    }

#ifdef __PF
    /*pf cfg init*/
    g_qnsm_vip_cfg.pf_num = 0;
#endif
    return;
}

#endif

void qnsm_parse_partitions(xmlDocPtr doc, xmlNodePtr cur, QNSM_KAFKA_CFG *kafka_cfg)
{
    xmlChar *key;
    cur = cur->xmlChildrenNode;

    key = xmlNodeListGetString(doc, cur, 1);
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "partitions : %s\n", key);
    kafka_cfg->partitions = atoi(key);
    xmlFree(key);
    /*
    if (0 ==  rte_is_power_of_2(kafka_cfg->partitions))
    {
        printf("partitions must power of 2!!!\n");
        QNSM_ASSERT(0);
    }
    */
    return;
}

void qnsm_parse_topic(xmlDocPtr doc, xmlNodePtr cur, QNSM_KAFKA_TOPIC_CFG* topic_cfg, uint32_t default_partitions)
{
    xmlChar *key;
    cur = cur->xmlChildrenNode;

    topic_cfg->enable = 1;
    topic_cfg->partitions = default_partitions;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"partitions"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            topic_cfg->partitions = atoi(key);
            xmlFree(key);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"enable"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            if (!xmlStrncasecmp(key, (const xmlChar *)"off", strlen("off"))
                || !xmlStrncasecmp(key, (const xmlChar *)"no", strlen("no"))) {
                topic_cfg->enable = 0;
            } else {
                topic_cfg->enable = 1;
            }
            xmlFree(key);
        }
        cur = cur->next;
    }
    return;
}

void qnsm_parse_topics(xmlDocPtr doc, xmlNodePtr cur, QNSM_KAFKA_CFG *kafka_cfg)
{
    QNSM_KAFKA_TOPIC_CFG *topic_cfg = NULL;
    uint16_t index = 0;
    uint16_t len = 0;

    cur = cur->xmlChildrenNode;
    topic_cfg = kafka_cfg->topics;
    while (cur != NULL) {
        if (strncmp(cur->name, "qnsm", strlen("qnsm"))) {
            cur = cur->next;
            continue;
        }

        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "topic %s index %u\n", cur->name, index);
        len = strlen(cur->name);
        if (len > QNSM_KAFKA_TOPIC_LEN - 1) {
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "topic %s len exceed %d!!\n", cur->name, QNSM_KAFKA_TOPIC_LEN - 1);
            len  = QNSM_KAFKA_TOPIC_LEN - 1;
        }
        strncpy(topic_cfg[index].topic_name, (const char*)cur->name, len + 1);

        qnsm_parse_topic(doc, cur, topic_cfg + index, kafka_cfg->partitions);
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "topic : %s partition num %u enable %u\n",
                   topic_cfg[index].topic_name,
                   topic_cfg[index].partitions,
                   topic_cfg[index].enable);
        index++;
        if (QNSM_KAFKA_MAX_TOPIC_ID <= index) {
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "exceed max topic num!!\n");
            break;
        }
        cur = cur->next;
    }
    kafka_cfg->topic_num = index;
    return;
}


void qnsm_parse_brokers(xmlDocPtr doc, xmlNodePtr cur, QNSM_KAFKA_CFG *kafka_cfg)
{
    xmlChar *key;
    cur = cur->xmlChildrenNode;
    uint16_t index = 0;
    QNSM_KAFKA_BROKER *brokers = NULL;

    brokers = kafka_cfg->borkers;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"broker"))) {
            if (QNSM_MAX_KAFKA_BROKER > index) {
                key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "broker : %s\n", key);
                if (strlen(key) > QNSM_KAFKA_BROKER_ADDR - 1) {
                    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "broker %d len exceed %d!!\n", index, QNSM_KAFKA_BROKER_ADDR - 1);
                }
                strncpy(brokers[index].broker, (const char*)key, QNSM_KAFKA_BROKER_ADDR - 1);
                brokers[index].broker[QNSM_KAFKA_BROKER_ADDR - 1] = '\0';
                xmlFree(key);
            } else {
                QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "exceed max broker num!!\n");
                break;
            }
            index++;
        }
        cur = cur->next;
    }
    kafka_cfg->broker_num = index;
    return;
}

void qnsm_parse_kafka_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_KAFKA_CFG *kafka_cfg)
{

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"name"))) {
            xmlChar *key = NULL;
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            strncpy(kafka_cfg->kafka_name, (const char*)key, sizeof(kafka_cfg->kafka_name));
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "kafka name : %s\n", key);
            xmlFree(key);
        }
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"partitions"))) {
            qnsm_parse_partitions(doc, cur, kafka_cfg);
        }
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"topics"))) {
            qnsm_parse_topics(doc, cur, kafka_cfg);
        }
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"brokers"))) {
            qnsm_parse_brokers(doc, cur, kafka_cfg);
        }

        cur = cur->next;
    }
    return;
}

static void qnsm_parse_syslog(xmlDocPtr doc, xmlNodePtr cur, QNSM_LOG_CFG *log_cfg)
{
    xmlChar *key;

    cur = cur->xmlChildrenNode;

    log_cfg->sys_log_conf.enabled = 1;
    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"enable"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            if (!xmlStrncasecmp(key, (const xmlChar *)"off", strlen("off"))
                || !xmlStrncasecmp(key, (const xmlChar *)"no", strlen("no"))) {
                log_cfg->sys_log_conf.enabled = 0;
            } else {
                log_cfg->sys_log_conf.enabled = 1;
            }
            xmlFree(key);
        }
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"facility"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            log_cfg->sys_log_conf.facility = strdup((char *)key);
            xmlFree(key);
        }
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"log-level"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            log_cfg->sys_log_conf.log_level = strdup((char *)key);
            xmlFree(key);
        }

        cur = cur->next;
    }

    return;
}

static void qnsm_parse_filelog(xmlDocPtr doc, xmlNodePtr cur, QNSM_LOG_CFG *log_cfg)
{
    xmlChar *key;

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"log-dir"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            log_cfg->file_log_conf.log_dir = strdup((char *)key);
            xmlFree(key);
        }
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"log-level"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            log_cfg->file_log_conf.log_level = strdup((char *)key);
            xmlFree(key);
        }

        cur = cur->next;
    }

    return;
}

static void qnsm_parse_log_cfg(xmlDocPtr doc, xmlNodePtr cur, QNSM_LOG_CFG *log_cfg)
{
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"filelog"))) {
            qnsm_parse_filelog(doc, cur, log_cfg);
        }

        if ((!xmlStrcmp(cur->name, (const xmlChar *)"syslog"))) {
            qnsm_parse_syslog(doc, cur, log_cfg);
        }
        cur = cur->next;
    }
    return;
}

static void qnsm_init_log(void)
{
    static struct {
            char *facility;
            int value;
    } syslog_facility_map[] = {
        { "auth",           LOG_AUTH },
        { "authpriv",       LOG_AUTHPRIV },
        { "cron",           LOG_CRON },
        { "daemon",         LOG_DAEMON },
        { "ftp",            LOG_FTP },
        { "kern",           LOG_KERN },
        { "lpr",            LOG_LPR },
        { "mail",           LOG_MAIL },
        { "news",           LOG_NEWS },
        { "security",       LOG_AUTH },
        { "syslog",         LOG_SYSLOG },
        { "user",           LOG_USER },
        { "uucp",           LOG_UUCP },
        { "local0",         LOG_LOCAL0 },
        { "local1",         LOG_LOCAL1 },
        { "local2",         LOG_LOCAL2 },
        { "local3",         LOG_LOCAL3 },
        { "local4",         LOG_LOCAL4 },
        { "local5",         LOG_LOCAL5 },
        { "local6",         LOG_LOCAL6 },
        { "local7",         LOG_LOCAL7 },
        { NULL,             -1         }
    };
    static struct {
            char *log_level;
            int value;
            int rte_log_level;
    } log_level_map[ ] = {
        { "Not set",        QNSM_LOG_NOTSET,  RTE_LOG_EMERG},
        { "None",           QNSM_LOG_NONE,    RTE_LOG_EMERG},
        { "Emergency",      QNSM_LOG_EMERG,   RTE_LOG_EMERG},
        { "Alert",          QNSM_LOG_ALERT,   RTE_LOG_ALERT},
        { "Critical",       QNSM_LOG_CRIT,    RTE_LOG_CRIT},
        { "Error",          QNSM_LOG_ERR,     RTE_LOG_ERR},
        { "Warning",        QNSM_LOG_WARNING, RTE_LOG_WARNING},
        { "Notice",         QNSM_LOG_NOTICE,  RTE_LOG_NOTICE},
        { "Info",           QNSM_LOG_INFO,    RTE_LOG_INFO },
        { "Debug",          QNSM_LOG_DEBUG,   RTE_LOG_DEBUG },
        { NULL,             -1,               -1}
    };
    QNSM_LOG_CFG *cfg = qnsm_get_log_conf();
    int i = 0;
    int facility = -1;

    if ( cfg  == NULL) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR,
            "Fatal error encountered in qnsm_init_log. Exiting...");
        exit(-1);
    }

    if (cfg->sys_log_conf.enabled) {
        cfg->type = EN_QNSM_LOG_SYSLOG;
    } else {
        cfg->type = EN_QNSM_LOG_RTE;
    }

    switch (cfg->type) {
        case EN_QNSM_LOG_RTE: {
            char path[256] = {0};
            struct app_params *app = qnsm_service_get_cfg_para();
            FILE *log_file = NULL;

            snprintf(path, sizeof(path), "%s/qnsm%s.log",
                (NULL == cfg->file_log_conf.log_dir) ? "/var/log/qnsm" : cfg->file_log_conf.log_dir, app->inst_id);
            log_file = fopen(path, "w+");
            if (log_file) {
                (void)rte_openlog_stream(log_file);
            }

            cfg->log_level = rte_get_log_level();
            for (i = 0; (cfg->file_log_conf.log_level) && (NULL != log_level_map[i].log_level); i++) {
                if (0 == strcmp(log_level_map[i].log_level, cfg->file_log_conf.log_level)) {
                    cfg->log_level = log_level_map[i].rte_log_level;
                    break;
                }
            }
            if (cfg->log_level != rte_get_log_level()) {
                rte_set_log_level(cfg->log_level);
            }
            QNSM_LOG(INFO, "log file is %s\n", path);
            break;
        }
        case EN_QNSM_LOG_SYSLOG: {
            for (i = 0; (cfg->sys_log_conf.facility) && (NULL != syslog_facility_map[i].facility); i++) {
                if (0 == strcmp(syslog_facility_map[i].facility, cfg->sys_log_conf.facility)) {
                    facility = syslog_facility_map[i].value;
                    break;
                }
            }
            cfg->log_level = QNSM_LOG_INFO;
            for (i = 0; (cfg->sys_log_conf.log_level) && (NULL != log_level_map[i].log_level); i++) {
                if (0 == strcmp(log_level_map[i].log_level, cfg->sys_log_conf.log_level)) {
                    cfg->log_level = log_level_map[i].value;
                    break;
                }
            }

            if (facility == -1)
                facility = LOG_LOCAL0;
            openlog(NULL, LOG_PID | LOG_NDELAY, facility);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO,
                "init syslog facility %d level %d", facility, cfg->log_level);
            break;
        }
        default:
            return;
    }

    return;
}

inline QNSM_DUMP_CFG* qnsm_get_dump_conf(void)
{
    return &g_qnsm_dump_cfg;
}

#if QNSM_PART("edge cfg")

uint32_t qnsm_edge_init_inst_id(void)
{
    struct app_params *app = qnsm_service_get_cfg_para();
    const char *inst = app->inst_id;
    uint32_t id = 1;
    int16_t index = 0;

    for (index = 0; index < strlen(inst); index++) {
        if (('0' <= inst[index]) && ('9' >= inst[index])) {
            id = atoi(inst + index);
            break;
        }
    }
    return id;
}

inline QNSM_EDGE_CFG* qnsm_get_edge_conf(void)
{
    return g_qnsm_edge_cfg;
}

void *qnsm_get_kafka_cfg(const char *name)
{
    uint16_t index = 0;
    void *cfg = NULL;

    for (index = 0; index < g_qnsm_edge_cfg->kafka_num; index++) {
        if (!strncmp(g_qnsm_edge_cfg->kafka_cfg[index].kafka_name, name, strlen(name))) {
            cfg = &g_qnsm_edge_cfg->kafka_cfg[index];
            break;
        }
    }
    return cfg;
}

int qnsm_edge_conf_parse(const char *conf_file_path)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL, node = NULL;
    xmlChar *key = NULL;
    uint32_t kafka_cnt = 0;
    uint32_t index = 0;
    QNSM_EDGE_CFG *global_cfg = qnsm_get_edge_conf();
    QNSM_DUMP_CFG *dump_cfg = &g_qnsm_dump_cfg;

    doc = xmlReadFile(conf_file_path, NULL, 0);
    if(doc == NULL) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed conf_file_path = %s", conf_file_path);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    if(root_node == NULL) {
        xmlFreeDoc(doc);
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, " xmlDocGetRootElement failed");
        return -1;
    }

    for(node = root_node->xmlChildrenNode; node; node = node->next) {
        if ((!xmlStrcmp(node->name, (const xmlChar *)"kafka"))) {
            kafka_cnt++;
        }
    }
    global_cfg->kafka_cfg = rte_zmalloc(NULL, kafka_cnt * sizeof(QNSM_KAFKA_CFG), QNSM_DDOS_MEM_ALIGN);
    if (NULL == global_cfg->kafka_cfg) {
        xmlFreeDoc(doc);
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "malloc kafka cfg failed\n");
        return -1;
    }
    global_cfg->kafka_num = kafka_cnt;

    for(node = root_node->xmlChildrenNode; node; node = node->next) {
        if ((!xmlStrcmp(node->name, (const xmlChar *)"dc"))) {
            key = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "dc : %s\n", key);
            strncpy(global_cfg->dc_name, key, QNSM_DC_NAME_LEN - 1);
            global_cfg->dc_name[QNSM_DC_NAME_LEN - 1] = '\0';
            xmlFree(key);
        }

        if ((!xmlStrcmp(node->name, (const xmlChar *)"kafka"))) {
            qnsm_parse_kafka_cfg(doc, node, &global_cfg->kafka_cfg[index]);
            index++;
        }

        if ((!xmlStrcmp(node->name, (const xmlChar *)"consumer_group"))) {
            key = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "consumer_group : %s\n", key);
            strncpy(global_cfg->cons_group, (const char*)key, sizeof(global_cfg->cons_group));
            xmlFree(key);
        }

        if ((!xmlStrcmp(node->name, (const xmlChar *)"log"))) {
            qnsm_parse_log_cfg(doc, node, qnsm_get_log_conf());
        }

        if ((!xmlStrcmp(node->name, (const xmlChar *)"dump-dir"))) {
            key = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
            dump_cfg->dump_dir = strdup((char *)key);
            xmlFree(key);
        }
    }
    snprintf(global_cfg->qnsm_inst_name,
             sizeof(global_cfg->qnsm_inst_name),
             "%s-%u",
             global_cfg->dc_name,
             qnsm_edge_init_inst_id());
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "qnsm inst name: %s\n", global_cfg->qnsm_inst_name);
    xmlFreeDoc(doc);
    return 0;
}

int qnsm_edge_conf_init(void)
{
    QNSM_ASSERT(NULL == g_qnsm_edge_cfg);

    g_qnsm_edge_cfg = (QNSM_EDGE_CFG *)rte_zmalloc("QNSM_EDGE_CFG", sizeof(QNSM_EDGE_CFG), QNSM_DDOS_MEM_ALIGN);
    if (NULL == g_qnsm_edge_cfg) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "malloc failed\n");
        return -1;
    }
    memset(g_qnsm_edge_cfg, 0, sizeof(QNSM_EDGE_CFG));
    return 0;
}

#endif

int qnsm_conf_parse(void)
{
    int32_t ret = 0;
    int32_t custom_conf_dir = 0;
    char path[256] = {0};
    struct app_params *app_paras = NULL;

    app_paras = qnsm_service_get_cfg_para();
    custom_conf_dir = (app_paras->xml_conf_dir != NULL) ? 1 : 0;
    if (0 == custom_conf_dir) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "conf dir not exist\n");
        return ret;
    }

    qnsm_vip_conf_init();
    if (app_type_find(app_paras, EN_QNSM_VIP_AGG)) {
        /*vip conf parse */
        (void)snprintf(path, sizeof(path), "%s/qnsm_vip.xml", app_paras->xml_conf_dir);
        ret = qnsm_vip_conf_parse(path);
        if(ret != 0) {
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "ret = %d\n", ret);
            return ret;
        }
    }

    /*edge conf parse*/
    (void)qnsm_edge_conf_init();
    if (app_type_find(app_paras, EN_QNSM_EDGE)) {
        (void)snprintf(path, sizeof(path), "%s/qnsm_edge.xml", app_paras->xml_conf_dir);
        ret = qnsm_edge_conf_parse(path);
        if(ret != 0) {
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "ret = %d\n", ret);
            return ret;
        }
    }
    qnsm_init_log();

    /*sessm conf*/
    (void)qnsm_sessm_conf_init();
    if (app_type_find(app_paras, EN_QNSM_SESSM)) {

        (void)snprintf(path, sizeof(path), "%s/qnsm_sessm.xml", app_paras->xml_conf_dir);
        ret = qnsm_sessm_conf_parse(path);
        if(ret != 0) {
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "ret = %d\n", ret);
            return ret;
        }
    }


    return 0;
}
