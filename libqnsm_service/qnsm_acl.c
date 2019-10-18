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


#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_acl.h>
#include <rte_table_acl.h>

#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_service_ex.h"
#include "qnsm_service.h"
#include "qnsm_acl_ex.h"
#include "qnsm_acl.h"

inline void* qnsm_acl_tbl_create(enum en_qnsm_acl_tbl_type type,
                                 void *params,
                                 uint32_t entry_size)
{
    QNSM_ACL_HANDLE *acl_hdl = qnsm_service_handle(EN_QNSM_SERVICE_ACL);
    void *tbl = NULL;
    QNSM_ACL_TBL_PARA *tbl_para = params;

    QNSM_ASSERT(EN_QSNM_ACL_TBL_MAX > type);

    tbl = rte_table_acl_ops.f_create(&tbl_para->acl_tbl_para, rte_socket_id(), entry_size);
    acl_hdl->acl_tbl[type].tbl = tbl;
    acl_hdl->acl_tbl[type].valid = 1;
    return tbl;
}

int qnsm_acl_tbl_add_bulk(
    enum en_qnsm_acl_tbl_type type,
    struct rte_table_acl_rule_add_params *keys,
    QNSM_ACL_ENTRY *entries,
    uint32_t n_keys,
    int *key_found,
    QNSM_ACL_ENTRY *entries_ptr)
{
    QNSM_ACL_HANDLE *acl_hdl = qnsm_service_handle(EN_QNSM_SERVICE_ACL);
    int ret = 0;
    uint32_t index = 0;
    void *tbl = acl_hdl->acl_tbl[type].tbl;
    void *key_arr[n_keys];
    void *entries_arr[n_keys];
    void *entries_ptr_arr[n_keys];

    for (index = 0; index < n_keys; index++) {
        key_arr[index] = &keys[index];
        entries_arr[index] = &entries[index];
        entries_ptr_arr[index] = &entries_ptr[index];
    }

    ret = rte_table_acl_ops.f_add_bulk(tbl,
                                       key_arr,
                                       entries_arr,
                                       n_keys,
                                       key_found,
                                       entries_ptr_arr);

#ifdef  DEBUG_QNSM
    if (0 == ret) {
        for (index = 0; index < n_keys; index++) {
            QNSM_LOG(INFO, "add acl rule %u action %d\n",
                    index,
                    ((QNSM_ACL_ENTRY *)(entries_ptr_arr[index]))->act);
        }
    }
#endif
    return ret;
}

int qnsm_acl_tbl_delete_bulk(
    enum en_qnsm_acl_tbl_type type,
    struct rte_table_acl_rule_delete_params *keys,
    uint32_t n_keys,
    int *key_found,
    QNSM_ACL_ENTRY *entries)
{
    QNSM_ACL_HANDLE *acl_hdl = qnsm_service_handle(EN_QNSM_SERVICE_ACL);
    int ret = 0;
    uint32_t index = 0;
    void *tbl = acl_hdl->acl_tbl[type].tbl;
    void *key_arr[n_keys];
    void *entries_arr[n_keys];

    for (index = 0; index < n_keys; index++) {
        key_arr[index] = &keys[index];
        entries_arr[index] = &entries[index];
    }

    ret = rte_table_acl_ops.f_delete_bulk(tbl,
                                          key_arr,
                                          n_keys,
                                          key_found,
                                          entries_arr);
    return ret;
}

static inline int qnsm_acl_tbl_lookup(
    QNSM_ACL_HANDLE *acl_hdl,
    enum en_qnsm_acl_tbl_type type,
    struct rte_mbuf **pkts,
    uint64_t pkts_mask,
    uint64_t *lookup_hit_mask,
    void **entries)
{
    int ret = 0;
    void *tbl = acl_hdl->acl_tbl[type].tbl;

    ret = rte_table_acl_ops.f_lookup(tbl,
                                     pkts,
                                     pkts_mask,
                                     lookup_hit_mask,
                                     entries);
    return ret;
}

void qnsm_acl_run(
    QNSM_ACL_HANDLE *acl_hdl,
    struct rte_mbuf **pkts,
    int32_t nb_pkts)
{
    enum en_qnsm_acl_tbl_type type = EN_QSNM_ACL_TBL_5TUPLE;
    qnsm_acl_act f_acl_act = NULL;
    void **act_entries = NULL;
    uint64_t hit_mask = 0;
    void *tbl = NULL;

    for ( ; type < EN_QSNM_ACL_TBL_MAX; type++) {
        tbl = acl_hdl->acl_tbl[type].tbl;
        act_entries = acl_hdl->acl_tbl[type].act_entries;
        (void)rte_table_acl_ops.f_lookup(tbl,
                                         pkts,
                                         RTE_LEN2MASK(nb_pkts, uint64_t),
                                         &hit_mask,
                                         act_entries);

        /*act*/
        if (0 == hit_mask) {
            continue;
        }
        f_acl_act = acl_hdl->acl_tbl[type].f_acl_act;
#if 0
        if ((hit_mask & (hit_mask + 1)) == 0) {
            uint64_t n_pkts = __builtin_popcountll(hit_mask);
            uint32_t i;

            for (i = 0; i < (n_pkts & (~0x3LLU)); i += 4)
                f_acl_act(&pkts[i], acl_hdl->act_entries[i]);

            for ( ; i < n_pkts; i++)
                f_acl_act(pkts[i],  acl_hdl->act_entries[i]);
        } else
#endif
        {
            for ( ; hit_mask; ) {
                uint32_t pos = __builtin_ctzll(hit_mask);
                uint64_t pkt_mask = 1LLU << pos;

                hit_mask &= ~pkt_mask;
                f_acl_act(pkts[pos], act_entries[pos]);
            }
        }

    }

    return;
}

void qnsm_acl_act_reg(enum en_qnsm_acl_tbl_type type, qnsm_acl_act f_acl_act)
{
    QNSM_ACL_HANDLE *tbl_hdl = qnsm_service_handle(EN_QNSM_SERVICE_ACL);

    QNSM_ASSERT(NULL != f_acl_act);
    QNSM_ASSERT(EN_QSNM_ACL_TBL_MAX  > type);

    tbl_hdl->acl_tbl[type].f_acl_act = f_acl_act;
    SET_LIB_COMMON_STATE(tbl_hdl, en_lib_state_load);
    return;
}

int qnsm_acl_init(void **tbl_handle)
{
    QNSM_ACL_HANDLE *tbl_hdl = NULL;

    tbl_hdl = rte_zmalloc_socket("ACL", sizeof(QNSM_ACL_HANDLE), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == tbl_hdl) {
        QNSM_LOG(ERR, "acl handle init failed\n");
        return -1;
    }
    memset(tbl_hdl, 0, sizeof(QNSM_ACL_HANDLE));

    SET_LIB_COMMON_STATE(tbl_hdl, en_lib_state_init);
    *tbl_handle = tbl_hdl;
    return 0;
}
