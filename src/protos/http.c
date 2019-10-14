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
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>

#include "cJSON.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_msg_ex.h"
#include "qnsm_dpi_ex.h"
#include "qnsm_session_ex.h"

#include "qnsm_dpi_ex.h"
#include "bsb.h"
#include "../qnsm_session.h"
#include "http_parser.h"
#include "http.h"


static http_parser_settings  parserSettings;
//HTTP_DATA http_data;

void http_cache_data_init(struct rte_mempool *mp,
                          __attribute__((unused)) void *opaque_arg,
                          void *_m,
                          __attribute__((unused)) unsigned i)
{
    char *m = _m;

    memset(m, 0, mp->elt_size);
    return;
}

void *http_data_init(void)
{
    char name[32];
    HTTP_DATA *http_data = NULL;
    struct rte_mempool *pool = NULL;

    http_data = rte_zmalloc_socket(NULL, sizeof(HTTP_DATA), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == http_data) {
        QNSM_ASSERT(0);
    }
    snprintf(name, sizeof(name), "HTTP_ECNAP%u", rte_lcore_id());
    pool = rte_mempool_create(name,
                              HTTP_DATA_PER_LCORE_MAX,
                              sizeof(uint8_t) * 1024,
                              APP_DEFAULT_MEMPOOL_CACHE_SIZE,
                              0,
                              NULL, NULL,
                              http_cache_data_init, NULL,
                              rte_socket_id(), (MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET));
    http_data->encap_data_cache = pool;

    pool = NULL;
    snprintf(name, sizeof(name), "HTTP_INFO%u", rte_lcore_id());
    pool = rte_mempool_create(name,
                              HTTP_DATA_PER_LCORE_MAX * 4,
                              sizeof(HTTP_INFO),
                              APP_DEFAULT_MEMPOOL_CACHE_SIZE,
                              0,
                              NULL, NULL,
                              http_cache_data_init, NULL,
                              rte_socket_id(), (MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET));
    http_data->info_cache = pool;

    QNSM_ASSERT(http_data->encap_data_cache);
    QNSM_ASSERT(http_data->info_cache);
    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "leave\n");
    return http_data;
}

void http_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    HTTP_INFO *http_info = NULL;
    HTTP_PARSER_INFO *parse_info = NULL;
    QNSM_SESS *tcp_sess = sess;
    uint16_t direction;
    uint16_t total_hdr_len = 0;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "enter\n");

    direction = pkt_info->sess_dir;
    if (EN_QNSM_SESS_DIR_MAX <= direction) {
        QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_WARN, "direction exceed!!\n");
        return;
    }

    if (tcp_sess) {
        if (tcp_sess->app_parse_info) {
            http_info = (HTTP_INFO *)tcp_sess->app_parse_info;
        }
    }

    if (NULL == http_info) {
        HTTP_DATA *http_data = qnsm_dpi_proto_data(EN_QNSM_DPI_HTTP);
        struct rte_mempool *info_cache = http_data->info_cache;
        int32_t ret = 0;

        ret = rte_mempool_get(info_cache, (void **)&http_info);
        if (ret || (NULL == http_info)) {
            QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_ERR, "failed ret %d\n", ret);
            *arg = NULL;
            return;
        }
        parse_info = http_info->parser_info;
        parse_info[DIRECTION_IN].parse_state = HTTP_PARSE_INIT;
        parse_info[DIRECTION_OUT].parse_state = HTTP_PARSE_INIT;
        parse_info[DIRECTION_IN].same_state_cnt = 0;
        parse_info[DIRECTION_OUT].same_state_cnt = 0;
        parse_info[DIRECTION_IN].encap_data = NULL;
        parse_info[DIRECTION_OUT].encap_data = NULL;
        if (tcp_sess) {
            tcp_sess->app_parse_info = http_info;
        }

        /*init method for diff req/resp*/
        parse_info[DIRECTION_IN].parser.method = HTTP_INIT;
        parse_info[DIRECTION_OUT].parser.method = HTTP_INIT;
    }

    /*http info init*/
    http_info->http_hdr = (uint8_t *)pkt_info->payload;
    http_info->direction = direction;

    /*parser info init*/
    parse_info = &http_info->parser_info[direction];
    parse_info->parser.data = parse_info;
    total_hdr_len = pkt_info->payload - rte_pktmbuf_mtod(mbuf, char *);
    parse_info->hp_length = pkt_info->pkt_len - total_hdr_len;
    parse_info->pkt_info = pkt_info;

    if (HTTP_PARSE_FIN == parse_info->parse_state) {
        parse_info->parse_state = HTTP_PARSE_INIT;
    }
    if (HTTP_PARSE_INIT == parse_info->parse_state) {
        /*first seg init*/
        parse_info->body_len = 0;
        parse_info->body_start = NULL;
        parse_info->seg_info.num_hdr_segs = 0;
        parse_info->seg_info.num_body_segs = 0;


        http_parser_init(&parse_info->parser, HTTP_BOTH);
    }

    *arg = http_info;
    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "leave\n");

    return;
}

EN_QNSM_DPI_OP_RES http_parse(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    EN_QNSM_DPI_OP_RES   ret = EN_QNSM_DPI_OP_STOP;
    HTTP_INFO *http_info = (HTTP_INFO *)arg;
    char *data = NULL;
    uint32_t remaining = 0;
    http_parser *parser = NULL;
    HTTP_PARSER_INFO *parser_info = NULL;
    enum en_http_parse_state prev_parse_state = 0;

    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "enter\n");

    if (NULL == http_info) {
        QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_WARN, "http_info NULL");
        return EN_QNSM_DPI_OP_STOP;
    }

    data = (char *)http_info->http_hdr;
    parser_info = &http_info->parser_info[http_info->direction];
    prev_parse_state = parser_info->parse_state;
    remaining = parser_info->hp_length;
    parser = &parser_info->parser;
    while (remaining > 0) {
        int len = http_parser_execute(parser, &parserSettings, data, remaining);


        if ((len <= 0) || (HPE_OK != parser->http_errno)) {

            /*
             *NOTE:
             *more tcp segments may parse err,
             *now not inform,
             */
            ret = EN_QNSM_DPI_OP_STOP;
            QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_ERR, "parse result: %d input: %d errno: %d state %d\n", len, remaining, parser->http_errno, parser->state);
            break;
        }

        QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "parse result: %d input: %d errno: %d state %d\n", len, remaining, parser->http_errno, parser->state);

        data += len;
        remaining -= len;

        if (prev_parse_state != parser_info->parse_state) {
            parser_info->same_state_cnt = 0;
        } else {
            parser_info->same_state_cnt++;
        }

#if __MIRR_MODE_BOTH
        /*http req, not send data, wait reponse*/
        if ((HTTP_NOTREQ == parser->method) &&
            (HTTP_PARSE_FIN == parser_info->parse_state)) {
            ret = EN_QNSM_DPI_OP_CONTINUE;
            break;
        }
#else
        if (HTTP_PARSE_FIN == parser_info->parse_state) {
            ret = EN_QNSM_DPI_OP_CONTINUE;
            break;
        }
#endif
        else {
            if ((HTTP_NOTREQ <= parser->method) || (5 > parser_info->same_state_cnt)) {
                ret = EN_QNSM_DPI_OP_STOP;
            } else {
                /*for slowloris, slowpost*/
                if ((HTTP_PARSE_HEADER == parser_info->parse_state)
                    || (HTTP_PARSE_BODY == parser_info->parse_state)) {
                    ret = EN_QNSM_DPI_OP_CONTINUE;
                    break;
                }
            }
        }
    }

    /*
     *current seg parse finish,
     *according by parse state
     */
    if (HTTP_PARSE_HEADER_COMPLETE >= parser_info->parse_state) {
        parser_info->seg_info.num_hdr_segs++;
    }

    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "leave\n");
    return ret;
}

uint32_t http_encap_req(uint8_t *buf, uint16_t offset, HTTP_PARSER_INFO *parser_info)
{
    uint8_t *tmp_buf = buf + offset;
    uint32_t len = sizeof(HTTP_MSG_HEADER);
    http_parser *parser = NULL;
    HTTP_MSG_HEADER *header = (HTTP_MSG_HEADER *)tmp_buf;

    header->type = 0;
    if (NULL == parser_info) {
        header->len = 0;
        return len;
    }

    /*HPE_OK is zero,
    *if parse err, this field is > 0*/
    parser = &parser_info->parser;
    *(uint32_t *)(tmp_buf + len) = parser->http_errno;
    len += sizeof(uint32_t);

    *(uint32_t *)(tmp_buf + len) = parser_info->hp_length;
    len += sizeof(uint32_t);

    if (HPE_OK != parser->http_errno) {
        header->len = len - sizeof(HTTP_MSG_HEADER);
        return len;
    }

    *(uint32_t *)(tmp_buf + len) = parser->method;
    len += sizeof(uint32_t);
    header->len = len - sizeof(HTTP_MSG_HEADER);

    /*add feature for slowloris/slowpost*/
    *(uint8_t *)(tmp_buf + len) = parser_info->same_state_cnt;
    len += sizeof(uint8_t);
    *(uint8_t *)(tmp_buf + len) = parser_info->parse_state;
    len += sizeof(uint8_t);

    QNSM_ASSERT(HTTP_RESERVED_LEN >= (offset + len));
    if ((NULL != parser_info->encap_data) &&
        (HTTP_RESERVED_LEN <= parser_info->data_len)) {
        rte_memcpy(buf + HTTP_RESERVED_LEN, parser_info->encap_data + HTTP_RESERVED_LEN, parser_info->data_len - HTTP_RESERVED_LEN);
        len = parser_info->data_len - offset;
    }
    return len;
}

uint32_t http_encap_resp(uint8_t *buf, uint16_t offset, HTTP_PARSER_INFO *parser_info)
{
    uint8_t *tmp_buf = buf + offset;
    uint32_t len = sizeof(HTTP_MSG_HEADER);
    http_parser *parser = NULL;
    HTTP_MSG_HEADER *header = (HTTP_MSG_HEADER *)tmp_buf;

    header->type = 1;
    if (NULL == parser_info) {
        header->len = 0;
        return len;
    }

    parser = &parser_info->parser;
    *(uint32_t *)(tmp_buf + len) = parser->http_errno;
    len += sizeof(uint32_t);
    *(uint16_t *)(tmp_buf + len) = parser_info->hp_length;
    len += sizeof(uint16_t);
    *(uint16_t *)(tmp_buf + len) = parser->status_code;
    len += sizeof(uint16_t);

    header->len  = len - sizeof(HTTP_MSG_HEADER);

    return len;
}

#if __MIRR_MODE_BOTH
uint32_t http_encap_info(uint8_t *buf, void *pkt_info, void *arg)
{
    uint32_t len = 0;
    QNSM_ASSERT(buf);
    HTTP_INFO *http_info = (HTTP_INFO *)arg;

    HTTP_PARSER_INFO *parser_info_req = NULL;
    HTTP_PARSER_INFO *parser_info_resp = NULL;
    HTTP_PARSER_INFO *cur_parser_info = &http_info->parser_info[http_info->direction];
    uint8_t dir = 0;
    //QNSM_PACKET_INFO tmp_pkt_info;
    QNSM_PACKET_INFO *cur_pkt_info = pkt_info;

    for (dir = 0; dir < DIRECTION_MAX; dir++) {
        if (HTTP_NOTREQ <= http_info->parser_info[dir].parser.method) {
            parser_info_resp = &http_info->parser_info[dir];
        }
        if (HTTP_NOTREQ > http_info->parser_info[dir].parser.method) {
            parser_info_req = &http_info->parser_info[dir];
        }
    }

    if ((HTTP_NOTREQ <= cur_parser_info->parser.method) &&
        (HPE_OK == cur_parser_info->parser.http_errno)) {
#if 0
        tmp_pkt_info.src_ip = cur_pkt_info->dst_ip;
        tmp_pkt_info.sport = cur_pkt_info->dport;
        tmp_pkt_info.dst_ip= cur_pkt_info->src_ip;
        tmp_pkt_info.dport = cur_pkt_info->sport;
        cur_pkt_info = &tmp_pkt_info;
#endif
    } else {
        parser_info_resp = NULL;
    }

    len += qnsm_dpi_encap_tuple(buf, cur_pkt_info);

    len += http_encap_resp(buf, len, parser_info_resp);
    len += http_encap_req(buf, len, parser_info_req);
    return len;
}

void http_msg_proc(void *data, uint32_t data_len)
{
    static const char *http_method_strings[] = {
#define XX(num, name, string) #string,
        HTTP_METHOD_MAP(XX)
#undef XX
    };
#if 1
    static const char *http_parser_state[] = {
#define XX(num, name, string) #string,
        HTTP_PARSE_STATE_MAP(XX)
#undef XX
    };
#endif
    cJSON *root = NULL;
    //cJSON *js_statis = NULL;
    char  tmp[128];
    uint32_t size =  sizeof(tmp);
    struct in_addr ip_addr;
    uint8_t  method = 0;
    uint16_t http_code;
    uint32_t len = 0;
    uint8_t *buf = data;
    QNSM_DPI_IPV4_TUPLE4 *tuple = (QNSM_DPI_IPV4_TUPLE4 *)buf;
    uint32_t name_len = 0;
    uint32_t value_len = 0;
    uint32_t hp_len = 0;
    uint8_t  http_errno = 0;
    char *name_pos = NULL;
    uint32_t resp_err = 0;
    uint16_t resp_len = 0;
    uint16_t with_resp = 0;
    HTTP_MSG_HEADER *header = NULL;

    /*add feature for slowloris/slowpost*/
    uint8_t same_state_cnt = 0;
    enum en_http_parse_state parse_state = 0;

    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "enter\n");
    root = cJSON_CreateObject();

    if (EN_QNSM_AF_IPv4 == tuple->af) {
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->saddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->daddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    } else {
        (void)inet_ntop(AF_INET6, tuple->saddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        (void)inet_ntop(AF_INET6, tuple->daddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    }
    cJSON_AddNumberToObject(root, "sport", tuple->source);
    cJSON_AddNumberToObject(root, "dport", tuple->dest);
    len += sizeof(QNSM_DPI_IPV4_TUPLE4);
    cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);

    header = (HTTP_MSG_HEADER *)(buf + len);
    if ((len < data_len) && (1 == header->type)) {
        len += sizeof(HTTP_MSG_HEADER);
        if (header->len > 0) {
            resp_err = *(uint32_t *)(buf + len);
            len += sizeof(uint32_t);
            resp_len = *(uint16_t *)(buf + len);
            len += sizeof(uint16_t);
            http_code = *(uint16_t *)(buf + len);
            len += sizeof(uint16_t);
            with_resp = 1;
        }
    }

    header = (HTTP_MSG_HEADER *)(buf + len);
    if ((len < data_len) && (0 == header->type)) {
        len += sizeof(HTTP_MSG_HEADER);

        if (header->len > 0) {
            http_errno = *(uint32_t *)(buf + len);
            cJSON_AddNumberToObject(root, "parse_err", http_errno);
            len += sizeof(uint32_t);

            hp_len = *(uint32_t *)(buf + len);
            cJSON_AddNumberToObject(root, "http_len", hp_len);
            len += sizeof(uint32_t);

            if (http_errno > HPE_OK) {
                goto EXIT;
            }

            method = *(uint32_t *)(buf + len);
            if (HTTP_NOTREQ > method) {
                cJSON_AddStringToObject(root, "method", http_method_strings[method]);
            }
            len += sizeof(uint32_t);

            /*feature for slowloris/slowpost*/
            same_state_cnt = *(uint8_t *)(buf + len);
            len += sizeof(uint8_t);
            cJSON_AddNumberToObject(root, "same_state_cnt", same_state_cnt);
            parse_state = *(uint8_t *)(buf + len);
            //len += sizeof(uint8_t);
            cJSON_AddStringToObject(root, "parse_state", http_parser_state[parse_state]);
        }
    }

    len = HTTP_RESERVED_LEN;
    if (len < data_len) {
        BSB bsb;
        char *value_pos = NULL;

        BSB_INIT(bsb, buf + len, data_len - len);
        while (BSB_REMAINING(bsb)) {
            /*host byte order*/
            BSB_LIMPORT_u32(bsb, name_len);
            BSB_LIMPORT_ptr(bsb, name_pos, name_len);

            BSB_LIMPORT_u32(bsb, value_len);
            BSB_LIMPORT_ptr(bsb, value_pos, value_len);
            if (BSB_IS_ERROR(bsb)) {
                break;
            }
            cJSON_AddStringToObject(root, name_pos, value_pos);
        }
    }

    if (with_resp) {
        cJSON_AddNumberToObject(root, "resp_parse_err", resp_err);
        cJSON_AddNumberToObject(root, "resp_http_len", resp_len);
        cJSON_AddNumberToObject(root, "resp_http_code", http_code);
    }

EXIT:
    qnsm_kafka_send_msg(QNSM_KAFKA_HTTP_TOPIC, root, tuple->saddr.in4_addr.s_addr);

    if(root)
        cJSON_Delete(root);
    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "leave method %s\n", http_method_strings[method]);
    return;
}

#else

uint32_t http_encap_info(uint8_t *buf, void *pkt_info, void *arg)
{
    uint32_t len = 0;
    QNSM_ASSERT(buf);
    HTTP_INFO *http_info = (HTTP_INFO *)arg;
    HTTP_PARSER_INFO *parser_info = &http_info->parser_info[http_info->direction];
    http_parser *parser = &parser_info->parser;

    len += qnsm_dpi_encap_tuple(buf, pkt_info);

    if (HTTP_NOTREQ > parser->method) {
        len += http_encap_req(buf, len, parser_info);
    } else {
        len += http_encap_resp(buf, len, parser_info);
    }
    return len;
}

void http_msg_proc(void *data, uint32_t data_len)
{
    static const char *http_method_strings[] = {
#define XX(num, name, string) #string,
        HTTP_METHOD_MAP(XX)
#undef XX
    };
    static const char *http_parser_state[] = {
#define XX(num, name, string) #string,
        HTTP_PARSE_STATE_MAP(XX)
#undef XX
    };

    cJSON *root = NULL;
    char  tmp[128];
    uint32_t size =  sizeof(tmp);
    struct in_addr ip_addr;
    uint8_t  method;
    uint16_t http_code;
    uint32_t len = 0;
    uint8_t *buf = data;
    QNSM_DPI_IPV4_TUPLE4 *tuple = (QNSM_DPI_IPV4_TUPLE4 *)buf;
    uint32_t name_len = 0;
    uint32_t value_len = 0;
    uint32_t hp_len = 0;
    uint8_t  http_errno = 0;
    uint8_t *name_pos = NULL;
    uint32_t resp_err = 0;
    uint16_t resp_len = 0;
    HTTP_MSG_HEADER *header = NULL;

    /*add feature for slowloris/slowpost*/
    uint8_t same_state_cnt = 0;
    enum en_http_parse_state parse_state = 0;

    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "enter\n");
    root = cJSON_CreateObject();

    if (EN_QNSM_AF_IPv4 == tuple->af) {
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->saddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->daddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    } else {
        (void)inet_ntop(AF_INET6, tuple->saddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        (void)inet_ntop(AF_INET6, tuple->daddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    }
    cJSON_AddNumberToObject(root, "sport", tuple->source);
    cJSON_AddNumberToObject(root, "dport", tuple->dest);
    len += sizeof(QNSM_DPI_IPV4_TUPLE4);
    cJSON_AddStringToObject(root, "dc", qnsm_get_edge_conf()->dc_name);

    header = (HTTP_MSG_HEADER *)(buf + len);
    if (len < data_len) {
        len += sizeof(HTTP_MSG_HEADER);
        if (header->len  > 0) {
            if (1 == header->type) {
                resp_err = *(uint32_t *)(buf + len);
                len += sizeof(uint32_t);
                resp_len = *(uint16_t *)(buf + len);
                len += sizeof(uint16_t);
                http_code = *(uint16_t *)(buf + len);
                len += sizeof(uint16_t);

                cJSON_AddNumberToObject(root, "resp_parse_err", resp_err);
                cJSON_AddNumberToObject(root, "resp_http_len", resp_len);
                cJSON_AddNumberToObject(root, "resp_http_code", http_code);
            } else {
                http_errno = *(uint32_t *)(buf + len);
                cJSON_AddNumberToObject(root, "parse_err", http_errno);
                len += sizeof(uint32_t);

                hp_len = *(uint32_t *)(buf + len);
                cJSON_AddNumberToObject(root, "http_len", hp_len);
                len += sizeof(uint32_t);

                if (http_errno > HPE_OK) {
                    goto EXIT;
                }

                method = *(uint32_t *)(buf + len);
                if (HTTP_NOTREQ > method) {
                    cJSON_AddStringToObject(root, "method", http_method_strings[method]);
                }
                len += sizeof(uint32_t);

                /*feature for slowloris/slowpost*/
                same_state_cnt = *(uint8_t *)(buf + len);
                len += sizeof(uint8_t);
                cJSON_AddNumberToObject(root, "same_state_cnt", same_state_cnt);
                parse_state = *(uint8_t *)(buf + len);
                len += sizeof(uint8_t);
                cJSON_AddStringToObject(root, "parse_state", http_parser_state[parse_state]);
            }
        }
    }

    len = HTTP_RESERVED_LEN;
    if (len < data_len) {
        BSB bsb;
        char *value_pos = NULL;

        BSB_INIT(bsb, buf + len, data_len - len);
        while (BSB_REMAINING(bsb)) {
            /*host byte order*/
            BSB_LIMPORT_u32(bsb, name_len);
            BSB_LIMPORT_ptr(bsb, name_pos, name_len);

            BSB_LIMPORT_u32(bsb, value_len);
            BSB_LIMPORT_ptr(bsb, value_pos, value_len);
            if (BSB_IS_ERROR(bsb)) {
                break;
            }
            cJSON_AddStringToObject(root, name_pos, value_pos);
        }
    }

EXIT:
    qnsm_kafka_send_msg(QNSM_KAFKA_HTTP_TOPIC, root, tuple->saddr.in4_addr.s_addr);

    if(root)
        cJSON_Delete(root);
    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "leave method %s\n", http_method_strings[method]);
    return;
}

#endif

#if QNSM_PART("http cbk")
int  http_on_message_begin(http_parser* parser)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;
    HTTP_DATA *http_data = qnsm_dpi_proto_data(EN_QNSM_DPI_HTTP);
    struct rte_mempool *http_data_cache = http_data->encap_data_cache;

    QNSM_ASSERT(http_data_cache);

    /*req*/
    if (HTTP_NOTREQ > parser->method) {
        if ((NULL == parser_info->encap_data) && rte_mempool_get(http_data_cache, (void **)&parser_info->encap_data)) {
            QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_ERR, "failed\n");

            /*
            rte_free(http_info);
            http_info = NULL;
            */
            return -1;
        }
        parser_info->data_len = HTTP_RESERVED_LEN;
        QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "set req rsvd data len\n");
    }
    return 0;
}

int http_on_url(http_parser *parser, const char *at, size_t length)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;
    uint32_t len = parser_info->data_len;
    uint8_t *buf = parser_info->encap_data;

    /*skip response*/
    if ((NULL == buf) || (HTTP_NOTREQ <= parser->method)) {
        return 0;
    }

    /*set parse state*/
    parser_info->parse_state = HTTP_PARSE_URL;

    /*encap url*/
    uint32_t   name_len = strlen("URI") + 1;
    uint32_t   field_len = length + 1;
    if ((len + sizeof(uint32_t) * 2 + name_len + field_len) <= (QNSM_DPI_MSG_DATA_LEN)) {
        *(uint32_t *)(buf + len) = name_len;
        len += sizeof(uint32_t);
        rte_memcpy(buf + len, "URI", name_len - 1);
        len += name_len;
        buf[len - 1] = '\0';

        *(uint32_t *)(buf + len) = field_len;
        len += sizeof(uint32_t);
        rte_memcpy(buf + len, at, field_len - 1);
        len += field_len;
        buf[len - 1] = '\0';

        parser_info->data_len = len;
    }

    return 0;
}

int http_on_header_field(http_parser *parser, const char *at, size_t length)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;
    uint8_t *buf = parser_info->encap_data;
    uint32_t len = parser_info->data_len;
    uint32_t   name_len = length + 1;

    /*skip response*/
    if ((NULL == buf) || (HTTP_NOTREQ <= parser->method)) {
        return 0;
    }

    /*set parse state*/
    parser_info->parse_state = HTTP_PARSE_HEADER;

    /*ecnap header name*/
    if ((len + sizeof(uint32_t) + name_len) <= (QNSM_DPI_MSG_DATA_LEN)) {
        *(uint32_t *)(buf + len) = name_len;
        len += sizeof(uint32_t);
        rte_memcpy(buf + len, at, name_len - 1);
        len += name_len;
        buf[len - 1] = '\0';

        parser_info->data_len = len;
    }
    return 0;
}

int http_on_header_value(http_parser *parser, const char *at, size_t length)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;
    uint8_t *buf = parser_info->encap_data;
    uint32_t len = parser_info->data_len;
    uint32_t   field_len = length + 1;

    /*skip response*/
    if ((NULL == buf) || (HTTP_NOTREQ <= parser->method)) {
        return 0;
    }

    /*ecnap header value*/
    if ((len + sizeof(uint32_t) + field_len) <= (QNSM_DPI_MSG_DATA_LEN)) {
        *(uint32_t *)(buf + len) = field_len;
        len += sizeof(uint32_t);
        rte_memcpy(buf + len, at, field_len - 1);
        len += field_len;
        buf[len - 1] = '\0';

        parser_info->data_len = len;
    }
    return 0;
}

int  http_on_headers_complete(http_parser* parser)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;

    parser_info->parse_state = HTTP_PARSE_HEADER_COMPLETE;
    return 0;
}

int http_on_body(http_parser *parser, const char *at, size_t length)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;
    uint8_t body_name_len = 0;
    uint8_t *buf = parser_info->encap_data;
    uint32_t offset = parser_info->data_len;

    /*skip response*/
    if ((NULL == buf) || (HTTP_NOTREQ <= parser->method)) {
        return 0;
    }

    parser_info->parse_state = HTTP_PARSE_BODY;

    /*encap body
    *
    * |lenof("body")|
    * |"body"|
    * |lenof(body data)|
    * |body data|
    */
    if (HTTP_BODY_SEGS_MAX > parser_info->seg_info.num_body_segs) {
        if (0 == parser_info->seg_info.num_body_segs) {
            body_name_len = strlen("BODY") + 1;
            if ((offset + sizeof(uint32_t) + body_name_len) <= QNSM_DPI_MSG_DATA_LEN) {
                *(uint32_t *)(buf + offset) = body_name_len;
                offset += sizeof(uint32_t);
                rte_memcpy(buf + offset, "BODY", body_name_len - 1);
                offset += body_name_len;
                buf[offset -1] = '\0';
                parser_info->data_len = offset;

                /*body data*/
                parser_info->body_start = parser_info->encap_data + offset;
                offset += sizeof(uint32_t);
            } else {
                /*parse body err because not enough buf space*/
                return -1;
            }

        }

        if ((offset + length + 1) <= QNSM_DPI_MSG_DATA_LEN) {
            parser_info->body_len += length;

            /*update body total len assumed end with '\0'*/
            *(uint32_t *)(parser_info->body_start) = parser_info->body_len + 1;

            /*fill seg body data*/
            rte_memcpy(buf + offset, at, length);
            offset += length;
            parser_info->data_len = offset;
        }

        parser_info->seg_info.seg_body_data_len[parser_info->seg_info.num_body_segs] = length;
        parser_info->seg_info.num_body_segs++;

    }
    return 0;
}

/*
**req/rsp's last seg cause this evt
*/
int  http_on_message_complete(http_parser* parser)
{
    HTTP_PARSER_INFO *parser_info = (HTTP_PARSER_INFO *)parser->data;
    uint8_t *buf = parser_info->encap_data;
    uint32_t offset = parser_info->data_len;

    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "enter\n");

    parser_info->parse_state = HTTP_PARSE_FIN;

    /*skip response*/
    if ((NULL == buf) || (HTTP_NOTREQ <= parser->method)) {
        goto EXIT;
    }

    if ((offset + 1) <= QNSM_DPI_MSG_DATA_LEN) {
        buf[offset] = '\0';
        parser_info->data_len += 1;
    }

EXIT:
    QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_INFO, "leave, parser state %d\n", parser->state);
    return 0;
}
#endif

static inline void http_parser_settings_init(void)
{
    parserSettings.on_url = http_on_url;
    parserSettings.on_header_field = http_on_header_field;
    parserSettings.on_header_value = http_on_header_value;
    parserSettings.on_headers_complete = http_on_headers_complete;
    parserSettings.on_body = http_on_body;
    parserSettings.on_message_complete = http_on_message_complete;
    parserSettings.on_message_begin = http_on_message_begin;
    return;
}

void http_free(void *sess, void *arg)
{
    HTTP_INFO *http_info = (HTTP_INFO *)arg;
    HTTP_DATA *http_data = qnsm_dpi_proto_data(EN_QNSM_DPI_HTTP);
    struct rte_mempool *http_data_cache = http_data->encap_data_cache;

    if (NULL == http_info) {
        QNSM_ASSERT(0);
        return;
    }

    /*
    *free encap data
    *err occured
    *resp parse fin
    */
    if (http_info->parser_info[DIRECTION_IN].encap_data) {
        rte_mempool_put(http_data_cache, http_info->parser_info[DIRECTION_IN].encap_data);
    }
    if (http_info->parser_info[DIRECTION_OUT].encap_data) {
        rte_mempool_put(http_data_cache, http_info->parser_info[DIRECTION_OUT].encap_data);
    }

    if (NULL == sess) {
        rte_mempool_put(http_data->info_cache, http_info);
        QNSM_DEBUG(QNSM_DBG_M_DPI_HTTP, QNSM_DBG_EVT, "free resource\n");
    }

    return;
}

EN_QNSM_DPI_OP_RES http_send(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    (void)qnsm_dpi_send_info(pkt_info, EN_QNSM_DPI_HTTP, arg);

    return EN_QNSM_DPI_OP_CONTINUE;
}

int32_t http_reg(void)
{
    static const char *method_strings[] = {
#define XX(num, name, string) #string,
        HTTP_METHOD_MAP(XX)
#undef XX
        0
    };
    int32_t i = 0;

    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_HTTP)) {
        return 0;
    }

    {
        /*reg classfy to dpi*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_TCP, 80, EN_QNSM_DPI_HTTP, http_classify);
        for (i = 0; method_strings[i]; i++) {
            (void)qnsm_dpi_content_classify_reg(EN_DPI_PROT_TCP, method_strings[i], strlen(method_strings[i]), EN_QNSM_DPI_HTTP, http_classify);
        }
        qnsm_dpi_content_classify_reg(EN_DPI_PROT_TCP, "HTTP", 4, EN_QNSM_DPI_HTTP, http_classify);

        /*reg dpi proc*/
        (void)qnsm_dpi_proto_init_reg(EN_QNSM_DPI_HTTP, http_data_init);
        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_HTTP, http_parse, 10);
        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_HTTP, http_send, 5);
        (void)qnsm_dpi_prot_final_reg(EN_QNSM_DPI_HTTP, http_free);

    }

    return 0;
}

void http_init(void)
{
    http_reg();
    http_parser_settings_init();
    return;
}

