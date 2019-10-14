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

#include "util.h"
#include "qnsm_inspect_main.h"
#include "app.h"
#include "qnsm_dbg.h"
#include "qnsm_service_ex.h"
#include "qnsm_msg_ex.h"
#include "qnsm_port_ex.h"
#include "qnsm_master_ex.h"


#ifdef  DEBUG_QNSM

extern cmdline_parse_inst_t cmd_show_flow_ip;
extern cmdline_parse_inst_t cmd_show_sess;
extern cmdline_parse_inst_t cmd_show_flow;
extern cmdline_parse_inst_t cmd_show_vip;
extern cmdline_parse_inst_t cmd_show_cus_ip;

#if QNSM_PART("help cmd")
struct cmd_help_result {
    cmdline_fixed_string_t help;
};

static void cmd_help_parsed(__attribute__((unused)) void *parsed_result,
                            struct cmdline *cl,
                            __attribute__((unused)) void *data)
{
    cmdline_printf(
        cl,
        "\n"
        "The following commands are currently available:\n\n"
        "    quit                                      : Quit the application.\n"
        "    show_flow                                 : show_flow vip|port|brief.\n"
        "    show_ip_flow                              : Show flow status of flow ip(x.x.x.x).\n"
        "    debug                                     : debug [custom_ip|vip|sess|tcp|cfg|msg|port|tbl|dpi|http|dns|ntp|ssdp|ips|master|none] [info|evt|pkt|warn|err|all].\n"
        "    dump                                      : dump enable|disable.\n"
        "    show_pipe                                 : show_pipe [rx_lcore] [tx_lcore]\n"
        "    show_kafka                                : show_kafka [topic]\n"
        "    show_sess                                 : show_sess type|conn|reassemble_que\n"
        "    show_vip                                  : show vip(x.x.x.x) statis.\n"
        "    reset                                     : Reset port x statis.\n"
        "    show_cus_ip                               : show_cus_ip"
    );

}

cmdline_parse_token_string_t cmd_help_help =
    TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

cmdline_parse_inst_t cmd_help = {
    .f = cmd_help_parsed,
    .data = NULL,
    .help_str = "show help",
    .tokens = {
        (void *)&cmd_help_help,
        NULL,
    },
};
#endif

#if QNSM_PART("quit cmd")
/*** quit ***/
/* exit application */

struct cmd_quit_result {
    cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
                struct cmdline *cl,
                __attribute__((unused)) void *data)
{
    cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_tok =
    TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit,
                             "quit");

cmdline_parse_inst_t cmd_quit = {
    .f = cmd_quit_parsed,  /* function to call */
    .data = NULL,      /* 2nd arg of func */
    .help_str = "exit application",
    .tokens = {        /* token list, NULL terminated */
        (void *)&cmd_quit_tok,
        NULL,
    },
};
#endif

#if QNSM_PART("reset port statis")
struct cmd_reset_port_result {
    cmdline_fixed_string_t reset;
    cmdline_fixed_string_t port;
    uint8_t port_id;
};

static void cmd_reset_port_parsed(void *parsed_result,
                                  __attribute__((unused)) struct cmdline *cl,
                                  __attribute__((unused)) void *data)
{
    struct cmd_reset_port_result *res = parsed_result;
    unsigned portid;

    portid = res->port_id;
    rte_eth_stats_reset(portid);
    return;
}

cmdline_parse_token_string_t cmd_reset_string =
    TOKEN_STRING_INITIALIZER(struct cmd_reset_port_result, reset,
                             "reset");
cmdline_parse_token_string_t cmd_port_string =
    TOKEN_STRING_INITIALIZER(struct cmd_reset_port_result, port,
                             "port");
cmdline_parse_token_num_t cmd_portid =
    TOKEN_NUM_INITIALIZER(struct cmd_reset_port_result,
                          port_id, UINT8);


cmdline_parse_inst_t cmd_reset_port = {
    .f = cmd_reset_port_parsed,
    .data = NULL,
    .help_str = "Reset port x statis.",
    .tokens = {
        (void *)&cmd_reset_string,
        (void *)&cmd_port_string,
        (void *)&cmd_portid,
        NULL,
    },
};

#endif


#if QNSM_PART("dbg cmd")
/*dbg cmd*/
struct cmd_dbg_result {
    cmdline_fixed_string_t dbg;
    cmdline_fixed_string_t dbg_module;
    cmdline_fixed_string_t dbg_type;
};

static void cmd_dbg_parsed(void *parsed_result, struct cmdline *cl,
                           __attribute__((unused)) void *data)
{
    struct cmd_dbg_result *res = parsed_result;
    EN_QNSM_DBG_MODULE module_id = 0;
    static char *module[] = {
        "",
        "custom_ip",
        "vip",
        "sess",
        "tcp",
        "cfg",
        "msg",
        "swq",
        "tbl",
        "none",
        "dpi",
        "http",
        "dns",
        "ntp",
        "ssdp",
        "ips",
        "master"
    };

    for (module_id = 1; module_id < QNSM_DBG_M_MAX; module_id++) {
        if (!strcmp(res->dbg_module, module[module_id])) {
            break;

        }
    }
    if (QNSM_DBG_M_NONE == module_id) {
        QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);
        return;
    }

    if (!strcmp(res->dbg_type, "info")) {
        QNSM_DEBUG_ENABLE(module_id, QNSM_DBG_INFO);
    }

    if (!strcmp(res->dbg_type, "evt")) {
        QNSM_DEBUG_ENABLE(module_id, QNSM_DBG_EVT);
    }

    if (!strcmp(res->dbg_type, "pkt")) {
        QNSM_DEBUG_ENABLE(module_id, QNSM_DBG_PKT);
    }

    if (!strcmp(res->dbg_type, "warn")) {
        QNSM_DEBUG_ENABLE(module_id, QNSM_DBG_WARN);
    }

    if (!strcmp(res->dbg_type, "err")) {
        QNSM_DEBUG_ENABLE(module_id, QNSM_DBG_ERR);
    }

    if (!strcmp(res->dbg_type, "all")) {
        QNSM_DEBUG_ENABLE(module_id, QNSM_DBG_ALL);
    }
    return;
}

cmdline_parse_token_string_t cmd_debug_string =
    TOKEN_STRING_INITIALIZER(struct cmd_dbg_result, dbg, "debug");

cmdline_parse_token_string_t cmd_debug_module =
    TOKEN_STRING_INITIALIZER(struct cmd_dbg_result, dbg_module,
                             "custom_ip#vip#sess#tcp#cfg#msg#port#tbl#dpi#http#dns#ntp#ssdp#ips#master#none");

cmdline_parse_token_string_t cmd_debug_type =
    TOKEN_STRING_INITIALIZER(struct cmd_dbg_result, dbg_type,
                             "info#evt#pkt#warn#err#all");

cmdline_parse_inst_t cmd_dbg = {
    .f = cmd_dbg_parsed,
    .data = NULL,
    .help_str = "debug [custom_ip|vip|sess|tcp|cfg|msg|port|tbl|dpi|http|dns|ntp|ssdp|ips|master|none] [info|evt|pkt|warn|err|all]",
    .tokens = {
        (void *)&cmd_debug_string,
        (void *)&cmd_debug_module,
        (void *)&cmd_debug_type,
        NULL,
    },
};

#endif

#if QNSM_PART("policy cmd")
/*policy cmd*/
struct cmd_policy_result {
    cmdline_fixed_string_t policy;
    cmdline_fixed_string_t policy_type;
    cmdline_fixed_string_t enable;
    cmdline_ipaddr_t vip;
    uint16_t port_id;
};

static void cmd_policy_parsed(void *parsed_result, struct cmdline *cl,
                              __attribute__((unused)) void *data)
{
    QNSM_BIZ_VIP_MSG vip_msg = {0};
    EN_QNSM_BORDERM_CMD cmd;
    QNSM_POLICY_MSG_DATA *policy_msg_data = NULL;
    policy_msg_data = (QNSM_POLICY_MSG_DATA *)(vip_msg.cmd_data + 8);
    struct cmd_policy_result *res = parsed_result;

    if (AF_INET == res->vip.family) {
        vip_msg.key.in4_addr.s_addr = res->vip.addr.ipv4.s_addr;
        vip_msg.af = EN_QNSM_AF_IPv4;
    } else {
        rte_memcpy(&vip_msg.key, &res->vip.addr, IPV6_ADDR_LEN);
        vip_msg.af = EN_QNSM_AF_IPv6;
    }

    /*set local vip*/
    vip_msg.cmd_data[0] = 1;

    if (!strcmp(res->policy_type, "dump")) {
        if (!strcmp(res->enable, "enable")) {
            vip_msg.cmd = EN_QNSM_CMD_DUMP_PKT;
        }

        if (!strcmp(res->enable, "disable")) {
            vip_msg.cmd = EN_QNSM_CMD_DISABLE_DUMP_PKT;
        }
        vip_msg.op = QNSM_BIZ_VIP_ADD;
        policy_msg_data->vport = res->port_id;

        (void)qnsm_msg_send_multi(EN_QNSM_DUMP,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
        (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);

        cmd = vip_msg.cmd;

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

    if (!strcmp(res->policy_type, "dpi")) {
        if (!strcmp(res->enable, "enable")) {
            vip_msg.cmd = EN_QNSM_CMD_DPI_CHECK;
        }

        if (!strcmp(res->enable, "disable")) {
            return;
        }

        vip_msg.op = QNSM_BIZ_VIP_ADD;
        policy_msg_data->sport = res->port_id;
        *(uint32_t *)(policy_msg_data + 1) = 1111;
        (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
    }

    if (!strcmp(res->policy_type, "pf")) {
        if (!strcmp(res->enable, "enable")) {
            vip_msg.cmd = EN_QNSM_CMD_ADD_PASSIVE_FINGERPRINT;
        }

        if (!strcmp(res->enable, "disable")) {
            vip_msg.cmd = EN_QNSM_CMD_DEL_PASSIVE_FINGERPRINT;
        }
        vip_msg.op = QNSM_BIZ_VIP_ADD;
        policy_msg_data->vport = res->port_id;

        (void)qnsm_msg_send_multi(EN_QNSM_SESSM,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
    }

    /*enable vip+sport statis*/
    if (!strcmp(res->policy_type, "sport")) {
        if (!strcmp(res->enable, "enable")) {
            vip_msg.cmd = EN_QNSM_CMD_ENABLE_SPORT_STATIS;
        }
        if (!strcmp(res->enable, "disable")) {
            vip_msg.cmd = EN_QNSM_CMD_DISABLE_SPORT_STATIS;
        }
        vip_msg.op = QNSM_BIZ_VIP_ADD;

        (void)qnsm_msg_send_multi(EN_QNSM_VIP_AGG,
                                  QNSM_MSG_SYN_BIZ_VIP,
                                  &vip_msg,
                                  1);
    }
    return;
}

cmdline_parse_token_string_t cmd_policy_string =
    TOKEN_STRING_INITIALIZER(struct cmd_policy_result, policy, "policy");

cmdline_parse_token_string_t cmd_policy_type_string =
    TOKEN_STRING_INITIALIZER(struct cmd_policy_result, policy_type, "dump#dpi#pf#sport");

cmdline_parse_token_string_t cmd_enable =
    TOKEN_STRING_INITIALIZER(struct cmd_policy_result, enable,
                             "enable#disable");

cmdline_parse_token_ipaddr_t cmd_arg_vip =
    TOKEN_IPADDR_INITIALIZER(struct cmd_policy_result, vip);

cmdline_parse_token_num_t cmd_arg_portid =
    TOKEN_NUM_INITIALIZER(struct cmd_policy_result,
                          port_id, UINT16);



cmdline_parse_inst_t cmd_policy = {
    .f = cmd_policy_parsed,
    .data = NULL,
    .help_str = "policy dump|dpi|pf enable|disable ip(x.x.x.x) port",
    .tokens = {
        (void *)&cmd_policy_string,
        (void *)&cmd_policy_type_string,
        (void *)&cmd_enable,
        (void *)&cmd_arg_vip,
        (void *)&cmd_arg_portid,
        NULL,
    },
};
#endif


#if QNSM_PART("msg show cmd")

struct cmd_pipe_result {
    cmdline_fixed_string_t show_pipe;
    uint8_t rx_lcore;
    uint8_t tx_lcore;
};

cmdline_parse_token_string_t cmd_show_pipe_string =
    TOKEN_STRING_INITIALIZER(struct cmd_pipe_result, show_pipe, "show_pipe");

cmdline_parse_token_num_t cmd_pipe_rx_lcore =
    TOKEN_NUM_INITIALIZER(struct cmd_pipe_result,
                          rx_lcore, UINT8);

cmdline_parse_token_num_t cmd_pipe_tx_lcore =
    TOKEN_NUM_INITIALIZER(struct cmd_pipe_result,
                          tx_lcore, UINT8);

static void cmd_show_pipe_parsed(void *parsed_result,
                                 __attribute__((unused)) struct cmdline *cl,
                                 __attribute__((unused)) void *data)
{
    struct cmd_pipe_result *res = parsed_result;
    uint8_t rx_lcore;
    uint8_t tx_lcore;
    QNSM_MSG_PIPE_STATIS statis = {0};
    uint64_t total_rx_msg = 0;
    uint64_t total_tx_msg = 0;
    uint64_t total_drop_msg = 0;
    uint8_t index = 0;

    rx_lcore = res->rx_lcore;
    tx_lcore = res->tx_lcore;

    if (rx_lcore >= APP_MAX_LCORES) {
        return;
    }

    if (tx_lcore < APP_MAX_LCORES) {
        if (0 == qnsm_msg_get_pipe_statis(rx_lcore, tx_lcore, &statis)) {
            cmdline_printf(cl, "pipe success rx_statis %" PRIu64 " tx_statis %" PRIu64 "; tx_drop_statis %" PRIu64 "\n",
                           statis.rx_statistics,
                           statis.tx_statistics,
                           statis.tx_drop_statistics);
        }
    } else {
        for (index = 0; index < APP_MAX_LCORES; index++) {
            if (qnsm_msg_get_pipe_statis(rx_lcore, index, &statis)) {
                continue;
            }
            total_rx_msg += statis.rx_statistics;
            total_tx_msg += statis.tx_statistics;
            total_drop_msg += statis.tx_drop_statistics;
        }
        cmdline_printf(cl, "pipe total success rx_statis %" PRIu64 " tx_statis %" PRIu64 "; tx_drop_statis %" PRIu64 "\n",
                       total_rx_msg,
                       total_tx_msg,
                       total_drop_msg);
    }
    return;
}

cmdline_parse_inst_t cmd_show_pipe = {
    .f = cmd_show_pipe_parsed,
    .data = NULL,
    .help_str = "show_pipe [rx_lcore] [tx_lcore]",
    .tokens = {
        (void *)&cmd_show_pipe_string,
        (void *)&cmd_pipe_rx_lcore,
        (void *)&cmd_pipe_tx_lcore,
        NULL,
    },
};


#endif

#if QNSM_PART("port show cmd")

struct cmd_port_result {
    cmdline_fixed_string_t show_port;
    uint8_t app_type;
};

cmdline_parse_token_string_t cmd_show_port_string =
    TOKEN_STRING_INITIALIZER(struct cmd_port_result, show_port, "show_port");

cmdline_parse_token_num_t cmd_app_type =
    TOKEN_NUM_INITIALIZER(struct cmd_port_result,
                          app_type, UINT8);

static void cmd_show_port_parsed(void *parsed_result,
                                 __attribute__((unused)) struct cmdline *cl,
                                 __attribute__((unused)) void *data)
{
    struct cmd_port_result *res = parsed_result;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;
    uint32_t p_id = 0;
    int32_t n_port = 0;
    int32_t index = 0;
    struct rte_port_out_stats out_stats;

    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (res->app_type == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            n_port = qnsm_port_in_num(pipeline_para);
            cmdline_printf(cl, "name %s in port num %u\n",
                           pipeline_para->name,
                           n_port);
        }
    }

    cmdline_printf(cl, "\n");
    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (res->app_type == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            n_port = qnsm_port_out_num(pipeline_para);
            for (index = 0; index < n_port; index++) {
                qnsm_port_out_statis(pipeline_para, &out_stats, index);
                cmdline_printf(cl, "name %s port %u tx %" PRIu64 " drop %" PRIu64 "\n",
                               pipeline_para->name,
                               index,
                               out_stats.n_pkts_in,
                               out_stats.n_pkts_drop);
            }
        }
    }

    cmdline_printf(cl, "\n");
    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (res->app_type == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            n_port = qnsm_port_dup_num(pipeline_para);
            for (index = 0; index < n_port; index++) {
                qnsm_port_dup_statis(pipeline_para, &out_stats, index);
                cmdline_printf(cl, "name %s dup port %u tx %" PRIu64 " drop %" PRIu64 "\n",
                               pipeline_para->name,
                               index,
                               out_stats.n_pkts_in,
                               out_stats.n_pkts_drop);
            }
        }
    }

    cmdline_printf(cl, "\n");
    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (res->app_type == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            if (0 == qnsm_port_dump_statis(pipeline_para, &out_stats)) {
                cmdline_printf(cl, "name %s dump port %u tx %" PRIu64 " drop %" PRIu64 "\n",
                               pipeline_para->name,
                               index,
                               out_stats.n_pkts_in,
                               out_stats.n_pkts_drop);
            }
        }
    }

    cmdline_printf(cl, "\n");
    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        if (res->app_type == app_paras->pipeline_params[p_id].app_type) {
            pipeline_para = &app_paras->pipeline_params[p_id];
            n_port = qnsm_port_tap_num(pipeline_para);
            for (index = 0; index < n_port; index++) {
                qnsm_port_tap_statis(pipeline_para, &out_stats, index);
                cmdline_printf(cl, "name %s tap port %u tx %" PRIu64 " drop %" PRIu64 "\n",
                               pipeline_para->name,
                               index,
                               out_stats.n_pkts_in,
                               out_stats.n_pkts_drop);
            }
        }
    }
    return;
}

cmdline_parse_inst_t cmd_show_port = {
    .f = cmd_show_port_parsed,
    .data = NULL,
    .help_str = "show_port [app_type]",
    .tokens = {
        (void *)&cmd_show_port_string,
        (void *)&cmd_app_type,
        NULL,
    },
};


#endif


#if QNSM_PART("kafka show cmd")

struct cmd_kafka_result {
    cmdline_fixed_string_t show_kafka;
    uint32_t topic;
};

cmdline_parse_token_string_t cmd_show_kafka_string =
    TOKEN_STRING_INITIALIZER(struct cmd_kafka_result, show_kafka, "show_kafka");

cmdline_parse_token_num_t cmd_kafka_topic =
    TOKEN_NUM_INITIALIZER(struct cmd_kafka_result,
                          topic, UINT32);

static void cmd_show_kafka_parsed(void *parsed_result,
                                  __attribute__((unused)) struct cmdline *cl,
                                  __attribute__((unused)) void *data)
{
    struct cmd_kafka_result *res = parsed_result;
    QNSM_KAFKA_TOPIC_PART_STATIS *statis = NULL;
    uint16_t part_num = 0;
    uint8_t index = 0;
    uint8_t p_id = 0;
    struct app_params *app_paras = qnsm_service_get_cfg_para();
    struct app_pipeline_params *pipeline_para = NULL;

    for (p_id = 0; p_id < app_paras->n_pipelines; p_id++) {
        pipeline_para = &app_paras->pipeline_params[p_id];
        if (!qnsm_cmd_lib_load(pipeline_para, EN_QNSM_SERVICE_KAFKA)) {
            continue;
        }

        statis = qnsm_kafka_get_statis(pipeline_para, res->topic, &part_num);
        if (NULL == statis) {
            continue;
        }
        cmdline_printf(cl, "================\n");
        cmdline_printf(cl, "topic %s\n", qnsm_kafka_topic_name(res->topic));
        for (index = 0; index < part_num; index++) {
            cmdline_printf(cl, "partition %u tx_statis %" PRIu64 " tx_drop_statis %" PRIu64 " rx_statis %" PRIu64 "\n",
                           index,
                           statis[index].tx_statis,
                           statis[index].tx_drop_statis,
                           statis[index].rx_statis);
        }
    }
    return;
}

cmdline_parse_inst_t cmd_show_kafka = {
    .f = cmd_show_kafka_parsed,
    .data = NULL,
    .help_str = "show_kafka [topic]",
    .tokens = {
        (void *)&cmd_show_kafka_string,
        (void *)&cmd_kafka_topic,
        NULL,
    },
};
#endif


cmdline_parse_ctx_t main_ctx[] = {
    (cmdline_parse_inst_t *)&cmd_help,
    (cmdline_parse_inst_t *)&cmd_reset_port,
    (cmdline_parse_inst_t *)&cmd_show_flow,
    (cmdline_parse_inst_t *)&cmd_show_flow_ip,
    (cmdline_parse_inst_t *)&cmd_dbg,
    (cmdline_parse_inst_t *)&cmd_policy,
    (cmdline_parse_inst_t *)&cmd_show_pipe,
    (cmdline_parse_inst_t *)&cmd_quit,
    (cmdline_parse_inst_t *)&cmd_show_sess,
    (cmdline_parse_inst_t *)&cmd_show_kafka,
    (cmdline_parse_inst_t *)&cmd_show_vip,
    (cmdline_parse_inst_t *)&cmd_show_cus_ip,
    (cmdline_parse_inst_t *)&cmd_show_port,
    NULL,
};

int32_t qnsm_cmd_init(void **tbl_handle)
{
    QNSM_CMD_HANDLE *handle = NULL;

    handle = rte_zmalloc_socket(NULL, sizeof(QNSM_CMD_HANDLE), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (handle) {
        memcpy(handle->ctx, main_ctx, sizeof(main_ctx));
        handle->cl = cmdline_stdin_new(handle->ctx, "QNSM>> ");
    } else {
        return -1;
    }

    *tbl_handle = handle;

    return 0;
}
#endif

