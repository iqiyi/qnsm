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
#include <time.h>
#include <poll.h>

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
#include <sys/un.h>

/*pcap lib*/
#include <pcap.h>
#include <pcap/pcap.h>

#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_lpm.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>

#include "app.h"
#include "qnsm_dbg.h"
#include "qnsm_cfg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_master_ex.h"
#include "qnsm_service_ex.h"
#include "qnsm_msg_ex.h"
#include "qnsm_tbl_ex.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define QNSM_HASH_CRC 1
#endif

/*DUMP PKT PATH*/
#define QNSM_DUMP_PKT_PATH       "./dump/"
#define QNSM_DUMP_DELAY_SEC    (1)
#define QNSM_DUMP_DELAY_NSEC   (0)

#define QNSM_DUMP_RUN_INTVAL_USEC   (1000 * 10)

typedef struct qnsm_dump QNSM_DUMP;
typedef QNSM_DUMP* (*find_ip)(QNSM_IN_ADDR *key);
typedef QNSM_DUMP* (*add_ip)(QNSM_IN_ADDR *key);

struct qnsm_dump_ops {
    find_ip f_find_ip;
    add_ip  f_add_ip;
};

struct qnsm_dump {
    QNSM_IN_ADDR                        key;
    uint16_t                            valid;
    uint16_t                            dump_enable;
    uint32_t                            dump_pkts;
    uint64_t                            dump_time;
    pcap_dumper_t                       *dump_fd;
};

typedef struct {
    struct rte_lpm *vip_tbl;
    QNSM_DUMP      *vip_dump_data;
    pcap_t                              *dump_handle;
    uint16_t lcore_id;
    uint16_t vip_enable_dump_num;

    /*ops*/
    struct qnsm_dump_ops ops[EN_QNSM_AF_MAX];
} QNSM_DUMP_APP_DATA;

#if QNSM_PART("ipv4")
/*
* @return
*   vip dump ptr
*/
static QNSM_DUMP* qnsm_dump_find_vip(QNSM_IN_ADDR *key)
{
    struct rte_lpm *lpm_tbl = NULL;
    QNSM_DUMP_APP_DATA *app_data = qnsm_app_data(EN_QNSM_DUMP);
    int32_t host_id = 0;
    int32_t ret = 0;
    QNSM_DUMP *vip_dump = NULL;

    lpm_tbl = app_data->vip_tbl;

    ret = rte_lpm_lookup(lpm_tbl, key->in4_addr.s_addr, &host_id);
    if (0 == ret) {
        QNSM_ASSERT(QNSM_IPV4_LPM_MAX_RULES > host_id);
        vip_dump = app_data->vip_dump_data + host_id;
    }
    return vip_dump;
}

/**
 * add a vip with key
 *
 * @param key
 *   host order
 * @return
 *   vip dump ptr
 */
static QNSM_DUMP* qnsm_dump_add_vip(QNSM_IN_ADDR *key)
{
    QNSM_DUMP_APP_DATA *app_data = qnsm_app_data(EN_QNSM_DUMP);
    struct rte_lpm *lpm_tbl = app_data->vip_tbl;
    int32_t ret = -1;
    int32_t host_id = 0;
    QNSM_DUMP *vip_dump = NULL;

    if (lpm_tbl) {
        /*get free host*/
        for (host_id = 0; host_id < QNSM_IPV4_LPM_MAX_RULES; host_id++) {
            vip_dump = (QNSM_DUMP *)app_data->vip_dump_data + host_id;
            if (0 == vip_dump->valid) {
                break;
            }
        }
        if (QNSM_IPV4_LPM_MAX_RULES <= host_id) {
            return NULL;
        }

        /*vip data pos as nhp id*/
        ret = rte_lpm_add(lpm_tbl, key->in4_addr.s_addr, 32, host_id);
        if (0 == ret) {
            vip_dump->valid = 1;
            vip_dump->key = *key;
        }
    }
    return vip_dump;
}

static void qnsm_dump_vip_init(void *this)
{
    QNSM_DUMP_APP_DATA *app_data = this;
    struct rte_lpm_config config_ipv4;
    uint8_t name[32];
    struct qnsm_dump_ops ops = {
        .f_find_ip = qnsm_dump_find_vip,
        .f_add_ip = qnsm_dump_add_vip,
    };

    /*ops*/
    app_data->ops[EN_QNSM_AF_IPv4] = ops;

    /*v4 tbl*/
    config_ipv4.max_rules = QNSM_IPV4_LPM_MAX_RULES;
    config_ipv4.number_tbl8s = QNSM_IPV4_LPM_NUMBER_TBL8S;
    config_ipv4.flags = 0;
    snprintf(name, sizeof(name), "dump_vip%d", app_data->lcore_id);
    app_data->vip_tbl = rte_lpm_create(name, rte_socket_id(), &config_ipv4);
    if (NULL == app_data->vip_tbl) {
        QNSM_ASSERT(0);
    }
    app_data->vip_dump_data = rte_zmalloc_socket(NULL,
                              sizeof(QNSM_DUMP) * QNSM_IPV4_LPM_MAX_RULES,
                              QNSM_DDOS_MEM_ALIGN,
                              rte_socket_id());
    if (NULL == app_data->vip_dump_data) {
        QNSM_ASSERT(0);
    }
    memset(app_data->vip_dump_data, 0, sizeof(QNSM_DUMP) * QNSM_IPV4_LPM_MAX_RULES);


    return;
}
#endif

#if QNSM_PART("ipv6")
/*
* @return
*   vip dump ptr
*/
static QNSM_DUMP* qnsm_dump_find_vip6(QNSM_IN_ADDR *key)
{
    QNSM_DUMP *vip_dump = NULL;
    vip_dump = qnsm_find_tbl_item(EN_QNSM_DUMP_IPV6_VIP, (void *)key);

    return vip_dump;
}

/**
 * add a vip with key
 *
 * @param key
 *   host order
 * @return
 *   vip dump ptr
 */
static QNSM_DUMP* qnsm_dump_add_vip6(QNSM_IN_ADDR *key)
{
    QNSM_DUMP *vip_dump = NULL;
    uint8_t normal_mode = 0;

    vip_dump = qnsm_add_tbl_item(EN_QNSM_DUMP_IPV6_VIP, key, &normal_mode);
    if (vip_dump) {
        vip_dump->valid = 1;
    }

    return vip_dump;
}

static inline uint32_t
qnsm_dump_ip6_hash_crc(const void *data, __rte_unused uint32_t data_len,
                       uint32_t init_val)
{
    const struct qnsm_in6_addr *k;
    k = data;

#ifdef QNSM_HASH_CRC
    init_val = rte_hash_crc_4byte(k->s6_addr32[0], init_val);
    init_val = rte_hash_crc_4byte(k->s6_addr32[1], init_val);
    init_val = rte_hash_crc_4byte(k->s6_addr32[2], init_val);
    init_val = rte_hash_crc_4byte(k->s6_addr32[3], init_val);
#else
    init_val = rte_jhash(k->s6_addr,
                         sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
#endif
    return init_val;
}

static void qnsm_dump_ip6_tbl_reg(EN_QNSM_APP lcore_type)
{
    uint32_t pool_size = 0;

    pool_size = app_get_deploy_num(qnsm_service_get_cfg_para(), EN_QNSM_DUMP) * QNSM_IPV6_VIP_MAX_NUM;
    pool_size = (pool_size << 2) / 5;
    QNSM_TBL_PARA  ipv6_para = {
        "dump_ip6",
        QNSM_IPV6_VIP_MAX_NUM,
        pool_size,
        sizeof(QNSM_DUMP),
        offsetof(QNSM_DUMP, key),
        sizeof(QNSM_IN_ADDR),
        qnsm_dump_ip6_hash_crc,
        NULL,
        EN_QNSM_DUMP,
        30,
    };

    qnsm_tbl_para_reg(lcore_type, EN_QNSM_DUMP_IPV6_VIP, (void *)&ipv6_para);
    return;
}

static void qnsm_dump_vip6_init(void *this)
{
    QNSM_DUMP_APP_DATA *app_data = this;
    struct qnsm_dump_ops ops = {
        .f_find_ip = qnsm_dump_find_vip6,
        .f_add_ip = qnsm_dump_add_vip6,
    };

    /*ops*/
    app_data->ops[EN_QNSM_AF_IPv6] = ops;

    /*v6 tbl*/
    qnsm_dump_ip6_tbl_reg(EN_QNSM_DUMP);

    return;
}
#endif

static void qnsm_dump_vip_op(QNSM_DUMP *vip_dump, uint16_t dump_enable)
{
    QNSM_DUMP_APP_DATA *app_data = qnsm_app_data(EN_QNSM_DUMP);

    if (vip_dump->valid) {
        if (NULL != vip_dump->dump_fd) {
            pcap_dump_close(vip_dump->dump_fd);
            vip_dump->dump_fd = NULL;
        }

        if (0 == dump_enable) {
            vip_dump->dump_enable = 0;
            if (0 < app_data->vip_enable_dump_num) {
                app_data->vip_enable_dump_num--;
            }
        } else {
            vip_dump->dump_enable = 1;
            app_data->vip_enable_dump_num++;
        }
    }
    return;
}

static int32_t qnsm_dump_vip_msg_proc(void *data, uint32_t data_len)
{
    int32_t ret = 0;
    QNSM_BIZ_VIP_MSG *vip_msg = data;
    QNSM_IN_ADDR host;
    QNSM_DUMP *vip_dump = NULL;
    char tmp[128];
    struct qnsm_dump_ops *ops = NULL;
    QNSM_DUMP_APP_DATA *app_data = qnsm_app_data(EN_QNSM_DUMP);

    QNSM_ASSERT(EN_QNSM_AF_MAX > vip_msg->af);
    ops = &app_data->ops[vip_msg->af];
    if (EN_QNSM_AF_IPv4 == vip_msg->af) {
        host.in4_addr.s_addr = rte_be_to_cpu_32(vip_msg->key.in4_addr.s_addr);
        inet_ntop(AF_INET, &vip_msg->key, tmp, sizeof(tmp));
    } else {
        host = vip_msg->key;
        inet_ntop(AF_INET6, &vip_msg->key, tmp, sizeof(tmp));
    }

    vip_dump = ops->f_find_ip(&host);
    if (NULL == vip_dump) {
        if ((vip_dump = ops->f_add_ip(&host))) {
            QNSM_LOG(CRIT, "add dump vip %s success\n", tmp);
        } else {
            QNSM_LOG(CRIT, "add dump vip %s failed\n", tmp);
            return -1;
        }
    }

    if (QNSM_BIZ_VIP_ADD == vip_msg->op) {

        if (EN_QNSM_CMD_DUMP_PKT == vip_msg->cmd) {
            qnsm_dump_vip_op(vip_dump, 1);
            QNSM_LOG(CRIT, "vip %s dump enable\n", tmp);
        }
        if (EN_QNSM_CMD_DISABLE_DUMP_PKT == vip_msg->cmd) {
            qnsm_dump_vip_op(vip_dump, 0);
            QNSM_LOG(CRIT, "vip %s dump disable\n", tmp);
        }
    }

    return ret;
}


static void qnsm_dump_pkt(QNSM_PACKET_INFO *pkt_info)
{
    char                    filename[256];
    char                    ip_str[128];
    struct tm               t2;
    struct pcap_pkthdr      hdr;
    uint64_t                time_min = 0;
    uint64_t                time_now = 0;
    uint32_t                format_len = 0;
    char                    *tmp = NULL;
    QNSM_DUMP_APP_DATA      *app_data = qnsm_app_data(EN_QNSM_DUMP);
    QNSM_DUMP               *vip_dump = NULL;
    struct in_addr          addr;
    uint8_t                 af = 0;
    struct qnsm_dump_ops    *ops = NULL;
    struct rte_mbuf *mbuf = NULL;

    if (NULL == pkt_info) {
        return;
    }
    QNSM_ASSERT(pkt_info->need_dump);

    af = pkt_info->af;
    ops = app_data->ops + af;
    vip_dump = ops->f_find_ip(&pkt_info->src_addr);
    if (vip_dump) {
        if (vip_dump->dump_enable) {
            goto DUMP;
        }
    }

    vip_dump = ops->f_find_ip(&pkt_info->dst_addr);
    if (vip_dump) {
        if (vip_dump->dump_enable) {
            goto DUMP;
        }
    }

    return;

DUMP:

    /*dump one minute*/
    time_now = time(NULL);
    time_min = time_now / 60;
    if ((time_min != vip_dump->dump_time) && vip_dump->dump_fd) {
        pcap_dump_close(vip_dump->dump_fd);
        vip_dump->dump_fd = NULL;
    }

    if (NULL == vip_dump->dump_fd) {
        tmp = filename;

        /*设置dump文件名*/
        format_len = snprintf(tmp, sizeof(filename), "%s", qnsm_get_dump_conf()->dump_dir);
        tmp = tmp + format_len;

        if (EN_QNSM_AF_IPv4 == af) {
            addr.s_addr = rte_cpu_to_be_32(vip_dump->key.in4_addr.s_addr);
            inet_ntop(AF_INET, (const void *)&addr.s_addr, ip_str, sizeof(ip_str));
        } else {
            inet_ntop(AF_INET6, (const void *)&vip_dump->key, ip_str, sizeof(ip_str));
        }
        format_len = snprintf(tmp, sizeof(filename), "%s-", ip_str);
        tmp += format_len;

        format_len = snprintf(tmp, sizeof(filename), "core%d-", app_data->lcore_id);
        tmp = tmp + format_len;

        localtime_r (&time_now, &t2);
        format_len = strftime(tmp, sizeof(filename), "%Y%m%d-%H%M", &t2);
        tmp = tmp + format_len;
        (void)snprintf(tmp, sizeof(filename), ".pcap");
        vip_dump->dump_fd = pcap_dump_open(app_data->dump_handle, filename);
        if(vip_dump->dump_fd <= 0) {
            return;
        }

        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_PKT, "open pcap file %s\n", filename);
    }

    /*dump pkt*/
    (void)gettimeofday(&hdr.ts, NULL);
    hdr.len = hdr.caplen = pkt_info->pkt_len;

    mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    pcap_dump((u_char *)vip_dump->dump_fd, &hdr, rte_pktmbuf_mtod(mbuf, u_char*));

    vip_dump->dump_time = time_min;
    vip_dump->dump_pkts++;
    return;
}

void qnsm_dump_run(void *para)
{
    QNSM_DUMP_APP_DATA *app_data = para;

#ifdef RTE_LIBRTE_KNI
    struct app_params *app = qnsm_service_get_cfg_para();
    uint32_t i = 0;

    /* Handle KNI requests from Linux kernel */
    for (i = 0; i < app->n_pktq_kni; i++)
        rte_kni_handle_request(app->kni[i]);
#endif /* RTE_LIBRTE_KNI */

    if (0 == app_data->vip_enable_dump_num)

    {
        usleep(QNSM_DUMP_RUN_INTVAL_USEC);
    }

    return;
}

static void qnsm_dump_hdl_init(pcap_t **dump_hdl)
{
    struct stat             st;
    QNSM_DUMP_CFG           *cfg = qnsm_get_dump_conf();

    QNSM_ASSERT(dump_hdl);

    *dump_hdl = pcap_open_dead(DLT_EN10MB, 1500);
    if(0 == *dump_hdl) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "failed\n");
    }
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "====dump disable====\n");

    /*检查QNSM_DUMP_PKT_PATH是否存在*/
    if (NULL == cfg->dump_dir) {
        cfg->dump_dir = QNSM_DUMP_PKT_PATH;
    }
    if(stat(cfg->dump_dir, &st)) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "dump dir not exist!!\n");
        (void)mkdir(cfg->dump_dir, 0755);
    }

    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "dump init end\n");
    return;
}

void qnsm_servcie_dump_action(struct rte_mbuf *mbuf)
{
    QNSM_PACKET_INFO *pkt_info = NULL;

    pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);

    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_EVT, "dump sip 0x%x dip 0x%x pkt_info %p pf %d need_dump %d\n",
               pkt_info->v4_src_ip,
               pkt_info->v4_dst_ip,
               pkt_info,
               pkt_info->pf,
               pkt_info->need_dump);

    if (pkt_info->need_dump) {
        qnsm_dump_pkt(pkt_info);
        rte_pktmbuf_free(mbuf);
    } else {
        rte_pktmbuf_free(mbuf);
    }
    return;
}

int32_t qnsm_service_dump_init(void)
{
    QNSM_DUMP_APP_DATA *app_data = qnsm_app_inst_init(sizeof(QNSM_DUMP_APP_DATA),
                                   NULL,
                                   qnsm_servcie_dump_action,
                                   qnsm_dump_run);
    uint16_t index = 0;
    struct app_params *app = qnsm_service_get_cfg_para();
    EN_QNSM_APP *app_type = app_get_lcore_app_type(app);

    if (NULL == app_data) {
        QNSM_ASSERT(0);
    }

    app_data->lcore_id = rte_lcore_id();
    app_data->vip_enable_dump_num = 0;
    qnsm_dump_hdl_init(&app_data->dump_handle);

    /*msg reg*/
    (void)qnsm_msg_publish();
    for (index = 0; index < APP_MAX_LCORES; index ++) {
        if (app_type[index] == EN_QNSM_EDGE) {
            (void)qnsm_msg_subscribe(index);
        }
    }
    (void)qnsm_msg_reg(QNSM_MSG_SYN_BIZ_VIP, qnsm_dump_vip_msg_proc, NULL);

    /*v4*/
    qnsm_dump_vip_init(app_data);

    /*v6*/
    qnsm_dump_vip6_init(app_data);

    return 0;
}
