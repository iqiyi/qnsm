/*
 * QNSM is a Network Security Monitor based on DPDK.
 *
 * Copyright (C) 2019 iQIYI (www.iqiyi.com).
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
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>


#include <rte_common.h>
#include <rte_byteorder.h>
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
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>

#include "app.h"
#include "qnsm_inspect_main.h"

#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_dbg.h"
#include "qnsm_service_ex.h"
#include "qnsm_msg_ex.h"
#include "qnsm_session_ex.h"
#include "qnsm_session.h"
#include "qnsm_tbl_ex.h"

typedef struct
{
    struct rte_mempool *pool;
}QNSM_TEST_DATA;

typedef struct
{
    uint32_t key;
    char desc[32];
}QNSM_TEST_TBL_ITEM;

static inline int32_t qnsm_parse_ptype(struct rte_mbuf *m)
{
    struct rte_net_hdr_lens lens = {0};
    QNSM_PACKET_INFO *pkt_info = (QNSM_PACKET_INFO *)(m + 1);
    const struct ipv4_hdr *ip4h;
    struct ipv4_hdr ip4h_copy;
    const struct ipv6_hdr *ip6h;
    struct ipv6_hdr ip6h_copy;
    uint32_t l3_ptypes = 0;
    uint32_t l4_types = 0;

    /*parse pkt*/
    m->packet_type = rte_net_get_ptype(m, &lens, RTE_PTYPE_ALL_MASK);

    pkt_info->payload = NULL;
    if (0 == lens.tunnel_len)
    {
        /*fill pkt info*/
        pkt_info->l3_offset = lens.l2_len;
        pkt_info->l3_len = lens.l3_len;
        l4_types = m->packet_type & RTE_PTYPE_L4_MASK;
        pkt_info->is_frag = (RTE_PTYPE_L4_FRAG == l4_types) ? 1 : 0;

        l3_ptypes = m->packet_type & RTE_PTYPE_L3_MASK;
        if (l3_ptypes == RTE_PTYPE_L3_IPV4 || l3_ptypes == RTE_PTYPE_L3_IPV4_EXT)
        {
            ip4h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv4_hdr), &ip4h_copy);

            QNSM_ASSERT(4 == (ip4h->version_ihl >> 4));
            pkt_info->proto = ip4h->next_proto_id;
            pkt_info->src_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->src_addr);
            pkt_info->dst_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->dst_addr);
            pkt_info->payload = (char *)ip4h + lens.l3_len + lens.l4_len;
            pkt_info->af = EN_QNSM_AF_IPv4;
        }
        else if ((l3_ptypes == RTE_PTYPE_L3_IPV6) || (l3_ptypes == RTE_PTYPE_L3_IPV6_EXT))
        {
            ip6h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv6_hdr), &ip6h_copy);

            QNSM_ASSERT(6 == (((uint8_t)ip6h->vtc_flow) >> 4));
            rte_memcpy(pkt_info->src_addr.in6_addr.s6_addr, ip6h->src_addr, IPV6_ADDR_LEN);
            rte_memcpy(pkt_info->dst_addr.in6_addr.s6_addr, ip6h->dst_addr, IPV6_ADDR_LEN);
            pkt_info->payload = (char *)ip6h + lens.l3_len + lens.l4_len;
            pkt_info->af = EN_QNSM_AF_IPv6;
            if (l3_ptypes == RTE_PTYPE_L3_IPV6)
            {
                pkt_info->proto = ip6h->proto;
            }
            else
            {
                /*ext hdr*/
                pkt_info->proto = *(((uint8_t *)ip6h) + pkt_info->l3_len - 2);
            }
        }
        else
        {
            return -1;
        }
    }
    else
    {
        /*has inner tunnel*/
        pkt_info->l3_offset = lens.l2_len + lens.l3_len + lens.l4_len + lens.tunnel_len + lens.inner_l2_len;
        pkt_info->l3_len = lens.inner_l3_len;
        l4_types = m->packet_type & RTE_PTYPE_INNER_L4_MASK;
        pkt_info->is_frag = (RTE_PTYPE_INNER_L4_FRAG == l4_types) ? 1 : 0;

        l3_ptypes = m->packet_type & RTE_PTYPE_INNER_L3_MASK;

        if ((l3_ptypes == RTE_PTYPE_INNER_L3_IPV4) || (l3_ptypes == RTE_PTYPE_INNER_L3_IPV4_EXT))
        {
            ip4h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv4_hdr), &ip4h_copy);

            pkt_info->proto = ip4h->next_proto_id;
            pkt_info->src_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->src_addr);
            pkt_info->dst_addr.in4_addr.s_addr = rte_be_to_cpu_32(ip4h->dst_addr);
            pkt_info->payload = (char *)ip4h + lens.inner_l3_len + lens.inner_l4_len;
            pkt_info->af = EN_QNSM_AF_IPv4;
        }
        else if ((l3_ptypes == RTE_PTYPE_INNER_L3_IPV6) || (l3_ptypes == RTE_PTYPE_INNER_L3_IPV6_EXT))
        {
            ip6h = rte_pktmbuf_read(m, pkt_info->l3_offset, sizeof(struct ipv6_hdr), &ip6h_copy);

            rte_memcpy(pkt_info->src_addr.in6_addr.s6_addr, ip6h->src_addr, IPV6_ADDR_LEN);
            rte_memcpy(pkt_info->dst_addr.in6_addr.s6_addr, ip6h->dst_addr, IPV6_ADDR_LEN);
            pkt_info->payload = (char *)ip6h + lens.inner_l3_len + lens.inner_l4_len;
            pkt_info->af = EN_QNSM_AF_IPv6;
            if (l3_ptypes == RTE_PTYPE_L3_IPV6)
            {
                pkt_info->proto = ip6h->proto;
            }
            else
            {
                pkt_info->proto = *(((uint8_t *)ip6h) + pkt_info->l3_len - 2);
            }
        }
        else
        {
            return -1;
        }
    }

    /*fill port*/
    switch (pkt_info->proto)
    {
        case TCP_PROTOCOL:
        case UDP_PROTOCOL:
            {
                uint16_t *ports = rte_pktmbuf_mtod_offset(m, uint16_t *, pkt_info->l3_offset + pkt_info->l3_len);
                pkt_info->sport = rte_be_to_cpu_16(ports[0]);
                pkt_info->dport = rte_be_to_cpu_16(ports[1]);
                break;
            }
        case ICMP_PROTOCOL:
            pkt_info->sport = 0;
            pkt_info->dport = 0;
        default:
            {
                break;
            }
    }
    return 0;
}


int qnsm_inspect_init(void)
{
    int ret = 0;

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_CFG, 0xFF);

    time_init();

    /* conf parse
     * now cfg level's vip tbl depend on eal
     */
    ret = qnsm_conf_parse();
    if(ret != 0)
    {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "ret = %d\n", ret);
        return ret;
    }

    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);
    return ret;
}

void qnsm_signal_proc(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    (void)pthread_sigmask(SIG_BLOCK, &set, NULL);
    return;
}

void qnsm_corefile_init(void)
{
    struct rlimit rlim;
    struct rlimit rlim_new;

    if (getrlimit(RLIMIT_CORE, &rlim) == 0)
    {
        rlim_new.rlim_cur = RLIM_INFINITY;
        rlim_new.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &rlim_new) != 0)
        {
            rlim_new.rlim_cur = rlim.rlim_max;
            rlim_new.rlim_max = rlim.rlim_max;
            (void) setrlimit(RLIMIT_CORE, &rlim_new);
        }
    }
    return;
}
static inline uint32_t
test_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
    return *(uint32_t *)data;
}

int test_tbl(void * this)
{
    uint8_t normal_mode = 0;
    uint32_t key = 0x12345678;
    QNSM_TEST_TBL_ITEM * item;

    item = qnsm_add_tbl_item(EN_QNSM_IPV4_SESS, &key, &normal_mode);
    if (NULL == item)
    {
        return -1;
    }

    if (NULL == qnsm_find_tbl_item(EN_QNSM_IPV4_SESS, &key))
    {
        return -2;
    }

    if (qnsm_del_tbl_item(EN_QNSM_IPV4_SESS, item))
    {
        return -3;
    }
    return 0;
}

int test_dpi(void *this)
{
    QNSM_TEST_DATA *test_data = this;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(test_data->pool);
    QNSM_PACKET_INFO *pkt_info = (QNSM_PACKET_INFO *)(mbuf + 1);
    char *payload = NULL;
    static char http[] = {
        0x94, 0x28, 0x2e, 0x59, 0x35, 0x70, 0xf4, 0x8e, 0x38, 0xa6, 0xdd, 0x02, 0x08, 0x00, 0x45, 0x00,
        0x01, 0x30, 0x7e, 0x4b, 0x40, 0x00, 0x80, 0x06, 0xbe, 0xba, 0x0a, 0x05, 0x9b, 0x23, 0x97, 0x8b,
        0x80, 0x0e, 0xf4, 0x96, 0x00, 0x50, 0xb0, 0x63, 0x99, 0x3c, 0x10, 0x2e, 0xfb, 0x14, 0x50, 0x18,
        0x01, 0x00, 0xa1, 0x47, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x43, 0x4f, 0x4d, 0x4f, 0x44,
        0x4f, 0x52, 0x53, 0x41, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x63, 0x72, 0x6c, 0x20, 0x48,
        0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2d, 0x43,
        0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x20,
        0x3d, 0x20, 0x31, 0x34, 0x34, 0x30, 0x30, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
        0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41, 0x6c, 0x69, 0x76, 0x65, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x49, 0x66,
        0x2d, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x53, 0x69, 0x6e, 0x63, 0x65, 0x3a,
        0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20, 0x31, 0x39, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x32, 0x30, 0x31,
        0x39, 0x20, 0x30, 0x39, 0x3a, 0x31, 0x32, 0x3a, 0x33, 0x38, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x49, 0x66, 0x2d, 0x4e, 0x6f, 0x6e, 0x65, 0x2d, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x3a, 0x20, 0x22,
        0x35, 0x63, 0x65, 0x31, 0x31, 0x65, 0x30, 0x36, 0x2d, 0x33, 0x32, 0x63, 0x22, 0x0d, 0x0a, 0x55,
        0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, 0x69, 0x63, 0x72, 0x6f,
        0x73, 0x6f, 0x66, 0x74, 0x2d, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x41, 0x50, 0x49, 0x2f, 0x36,
        0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x63, 0x72, 0x6c, 0x2e, 0x63, 0x6f,
        0x6d, 0x6f, 0x64, 0x6f, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x0d, 0x0a
        };
    QNSM_SESS   sess;
    void *app_arg = NULL;

    rte_pktmbuf_init(test_data->pool, NULL, mbuf, 0);
    payload = rte_pktmbuf_mtod(mbuf, char *);
    rte_memcpy(payload, http, sizeof(http));

    (void)qnsm_decode_ethernet(pkt_info, payload, sizeof(http));
    if (EN_QNSM_DPI_HTTP != qnsm_dpi_match(pkt_info, EN_DPI_PROT_TCP, &sess, &app_arg))
    {
        return -1;
    }
    else
    {
        if (app_arg)
        {
            qnsm_dpi_proto_free(EN_QNSM_DPI_HTTP, app_arg);
        }
    }

    rte_pktmbuf_free(mbuf);
    return 0;
}

void qnsm_test_run(void *this)
{
    int32_t status = 0;

	printf("\n\n\n\n************dpi tests************\n");
	status = test_dpi(this);
    if (status)
    {
        printf("\n\n\n\n************dpi tests failed %d************\n", status);
    }

	printf("\n\n\n\n************tbl tests************\n");
	status = test_tbl(this);
    if (status)
    {
        printf("\n\n\n\n************tbl tests failed %d************\n", status);
    }
    return;
}

int32_t qnsm_test_init(void)
{
    struct app_params *app = qnsm_service_get_cfg_para();
    QNSM_TEST_DATA *data = NULL;

    data = qnsm_app_inst_init(sizeof(QNSM_TEST_DATA),
        NULL,
        NULL,
        NULL);
    if (NULL == data)
    {
        QNSM_ASSERT(0);
    }
    data->pool = app->mempool[0];

    /*dpi module reg*/
    EN_QNSM_DPI_PROTO proto = 0;

    http_init();
    dns_init();
    ntp_init();
    ssdp_init();
    memcached_reg();
    chargen_reg();
    qotd_reg();
    snmp_reg();
    cldap_reg();
    tftp_reg();

    for (proto = EN_QNSM_DPI_HTTP; proto < EN_QNSM_DPI_PROTO_MAX; proto++)
    {
        qnsm_dpi_proto_init(proto);
    }

    /*test tbl reg*/
    QNSM_TBL_PARA  test_para =
    {
        "V4_SESS",
        QNSM_SESS_MAX,
        1024,
        sizeof(QNSM_TEST_TBL_ITEM),
        offsetof(QNSM_TEST_TBL_ITEM, key),
        sizeof(uint32_t),
        test_hash_crc,
        NULL,
        EN_QNSM_TEST,
        30,
    };

    qnsm_tbl_para_reg(EN_QNSM_TEST, EN_QNSM_IPV4_SESS, (void *)&test_para);

    qnsm_service_run_reg(qnsm_test_run);
    return 0;
}

int
app_test_main_loop(void *arg)
{
	unsigned lcore;
	lcore = rte_lcore_id();
    struct app_params *app = qnsm_service_get_cfg_para();
    EN_QNSM_APP app_type = app->app_type[lcore];
    uint16_t lcore_id = 0;
    uint32_t p_id;
    struct app_pipeline_params *params = NULL;

    for (p_id = 0; p_id < app->n_pipelines; p_id++)
    {
        params = &app->pipeline_params[p_id];

        lcore_id = cpu_core_map_get_lcore_id(app->core_map,
        params->socket_id,
        params->core_id,
        params->hyper_th_id);
        if (lcore_id == lcore)
        {
            break;
        }
    }

	if (params && (EN_QNSM_TEST == app_type)) {
		printf("Logical core %u %s startup.\n", lcore, params->name);

        qnsm_servcie_app_launch(params,
            qnsm_test_init);
	}
    return 0;
}


int
MAIN(int argc, char **argv)
{
	int ret;

    /*init json hook*/
    #ifdef __QNSM_JSON_STUB
    qnsm_json_init_hooks();
    #endif

    /*init signal*/
    qnsm_signal_proc();

    /*init coredump file size*/
    qnsm_corefile_init();

	rte_openlog_stream(stderr);

	/*common config */
    struct app_params *app_paras = NULL;
    app_paras = qnsm_service_get_cfg_para();
	app_config_init(app_paras);
	app_config_args(app_paras, argc, argv);
	app_config_preproc(app_paras);
	app_config_parse(app_paras, app_paras->parser_file);
	//app_config_check(app_paras);

	/*eal , link Init */
	app_init(app_paras);

    /*qnsm inspect init*/
    ret = qnsm_inspect_init();
    if(ret != 0)
    {
        rte_exit(EXIT_FAILURE, "qnsm inspect init failed\n");
    }

    /*qnsm service init*/
    ret = qnsm_service_lib_init(app_paras);
    if(ret != 0)
    {
        rte_exit(EXIT_FAILURE, "qnsm service lib init failed\n");
    }

	/* Launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(app_test_main_loop, NULL, CALL_MASTER);

	return 0;
}


