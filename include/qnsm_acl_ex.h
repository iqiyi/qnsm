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

#ifndef __QNSM_ACL_EX_H__
#define __QNSM_ACL_EX_H__

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_ACL_RULE_MAX_NUM  (64)
#define OFF_ETHHEAD (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))

/*
*acl action include pkt dump , dpi
*/
enum qnsm_acl_action {
    EN_QNSM_ACL_ACT_DUMP = 0,
    EN_QNSM_ACL_ACT_DPI,
    EN_QNSM_ACL_ACT_MAX,
};

/*
*include IPv4/IPv6 5tuple tbl
*/
enum en_qnsm_acl_tbl_type {
    EN_QSNM_ACL_TBL_5TUPLE = 0,
    EN_QSNM_ACL_TBL_IPv6_5TUPLE,
    EN_QSNM_ACL_TBL_MAX
};

typedef struct {
    enum qnsm_acl_action act;

} QNSM_ACL_ENTRY;

typedef struct {
    struct rte_table_acl_params acl_tbl_para;
} QNSM_ACL_TBL_PARA;

typedef void (*qnsm_acl_act)(struct rte_mbuf *mbuf, QNSM_ACL_ENTRY *act_entry);

/**
 * create acl tbl
 *
 * @param type
 *   acl tbl type
 * @param params
 *   QNSM_ACL_TBL_PARA
 * @param entry_size
 *   acl entry size
 * @return
 *   0 success, other failed
 */
inline void* qnsm_acl_tbl_create(enum en_qnsm_acl_tbl_type type,
                                 void *params,
                                 uint32_t entry_size);

/*add acl rules*/
int qnsm_acl_tbl_add_bulk(
    enum en_qnsm_acl_tbl_type type,
    struct rte_table_acl_rule_add_params *keys,
    QNSM_ACL_ENTRY *entries,
    uint32_t n_keys,
    int *key_found,
    QNSM_ACL_ENTRY *entries_ptr);

/*del acl rules*/
int qnsm_acl_tbl_delete_bulk(
    enum en_qnsm_acl_tbl_type type,
    struct rte_table_acl_rule_delete_params *keys,
    uint32_t n_keys,
    int *key_found,
    QNSM_ACL_ENTRY *entries);

/*acl act register*/
void qnsm_acl_act_reg(enum en_qnsm_acl_tbl_type type, qnsm_acl_act f_acl_act);




#ifdef __cplusplus
}
#endif

#endif
