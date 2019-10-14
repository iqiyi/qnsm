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
#ifndef __QNSM_DPI__
#define __QNSM_DPI__

#include "list.h"
#include "qnsm_service.h"

#include "qnsm_dpi_ex.h"

#ifdef __cplusplus
extern "C" {
#endif


#define QNSM_DPI_PORT_MAX   (0xFFFF)
#define QNSM_DPI_UCHAR_MAX   (256)
#define QNSM_DPI_MATCH_CONTTENT_SIZE (16)

typedef struct {
    struct qnsm_list_head head;
    QNSM_DPI_ENCAP_INFO encap_func;
    QNSM_DPI_MSG_PROC msg_proc_func;
    QNSM_PROTO_FREE   free_func;
    QNSM_DPI_PROTO_DATA_INIT init_func;
    void *dpi_prot_data;
    uint8_t enable;
    uint8_t parse_enable;
    uint8_t rsvd[6];
} __rte_cache_aligned QNSM_DPI_PROTO;

typedef struct {
    struct qnsm_list_head class_node;
    char match_content_key[QNSM_DPI_MATCH_CONTTENT_SIZE];
    uint32_t match_content_key_len;
    EN_QNSM_DPI_PROTO match_proto;
    QNSM_DPI_CLASS_MATCH_FUN match_func;
} __rte_cache_aligned QNSM_DPI_CLASS;

typedef struct {
    struct qnsm_list_head  service_classifer[EN_DPI_L4_MAX][QNSM_DPI_PORT_MAX];
    struct qnsm_list_head  tcp_content_classifer[QNSM_DPI_UCHAR_MAX][QNSM_DPI_UCHAR_MAX];
    struct qnsm_list_head  udp_content_classifer[QNSM_DPI_UCHAR_MAX][QNSM_DPI_UCHAR_MAX];
} __rte_cache_aligned QNSM_DPI_CLASSIFY;

typedef struct {
    SERVICE_LIB_COMMON
    QNSM_DPI_PROTO dpi_proto[EN_QNSM_DPI_PROTO_MAX];
    QNSM_DPI_CLASSIFY classify;
} QNSM_DPI;

typedef struct {
    struct qnsm_list_head proto_node;
    uint32_t priority;
    QNSM_PROTO_OPS proto_ops;
} QNSM_PROTOCOL_ITEM;

int32_t qnsm_dpi_init(void **tbl_handle);


#ifdef __cplusplus
}
#endif

#endif
