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
#ifndef __QNSM_ACL_H__
#define __QNSM_ACL_H__

#include <rte_mbuf.h>
#include <rte_port.h>
#include <rte_table_acl.h>

#include "util.h"
#include "qnsm_service_ex.h"
#include "qnsm_acl_ex.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *tbl;
    uint8_t  valid;
    uint8_t  rsvd[7];
    qnsm_acl_act f_acl_act;
    void *act_entries[RTE_PORT_IN_BURST_SIZE_MAX];
} QNSM_ACL_TBL;

typedef struct {
    SERVICE_LIB_COMMON
    QNSM_ACL_TBL acl_tbl[EN_QSNM_ACL_TBL_MAX];
} QNSM_ACL_HANDLE;


void qnsm_acl_run(
    QNSM_ACL_HANDLE *acl_hdl,
    struct rte_mbuf **pkts,
    int32_t nb_pkts);
int qnsm_acl_init(void **tbl_handle);




#ifdef __cplusplus
}
#endif

#endif
