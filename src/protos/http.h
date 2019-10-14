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
#ifndef __QNSM_HTTP__
#define __QNSM_HTTP__

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_RESERVED_LEN           (64)
#define HTTP_BODY_SEGS_MAX          (8)
#define HTTP_DATA_PER_LCORE_MAX     (65536UL << 1)

#define HTTP_PARSE_STATE_MAP(XX)                    \
    XX(0,  INIT,      INIT)                         \
    XX(1,  URL,       URL)                          \
    XX(2,  HEADER,    HEADER)                       \
    XX(3,  HEADER_COMPLETE,    HEADER_COMPLETE)     \
    XX(4,  BODY,      BODY)                         \
    XX(5,  FIN,       FIN)                          \
    XX(6,  RESP_LINE_COMPLETE, RESP_LINE_COMPLETE)

enum en_http_parse_state {
#define XX(num, name, string) HTTP_PARSE_##name = num,
    HTTP_PARSE_STATE_MAP(XX)
#undef XX
};

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t value[0];
} HTTP_MSG_HEADER;

typedef struct {
    uint16_t seg_body_data_len[HTTP_BODY_SEGS_MAX];               /*signature for slow post*/
    uint8_t  num_body_segs;
    uint8_t  num_hdr_segs;                                        /*signature for slowloris*/
} HTTP_SEG_INFO;

/*
 * storage of http field in common use
 */
typedef struct {
    const uint8_t    *sp;                                /*start pointer*/
    uint16_t   length;                             /*length of this field*/
} HTTP_FIELD;

typedef struct {
    uint16_t   hp_length;                          /*http cur seg length*/

    /*save body*/
    uint16_t body_len;
    const uint8_t *body_start;

    HTTP_SEG_INFO seg_info;
    uint8_t parse_state;
    uint8_t same_state_cnt;

    /*http encap data*/
    uint16_t data_len;
    uint8_t *encap_data;

    /*pkt info*/
    void *pkt_info;

    http_parser parser;
} __rte_cache_aligned HTTP_PARSER_INFO;


typedef struct {
    uint8_t    *http_hdr;                          /*http header*/
    uint16_t   direction;                          /*pkt direc*/

    HTTP_PARSER_INFO parser_info[DIRECTION_MAX];
    //QNSM_SESS  *sess;
} __rte_cache_aligned HTTP_INFO;

typedef struct {
    void *info_cache;
    void *encap_data_cache;
} HTTP_DATA;

EN_QNSM_DPI_OP_RES http_parse(QNSM_PACKET_INFO *pkt_info, void *arg);
uint32_t http_encap_info(uint8_t *buf, void *pkt_info, void *arg);
void http_msg_proc(void *data, uint32_t data_len);



#ifdef __cplusplus
}
#endif

#endif
