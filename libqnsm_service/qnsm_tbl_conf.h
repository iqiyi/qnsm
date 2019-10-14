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

#ifndef __QNSM_TBL_CONF__
#define __QNSM_TBL_CONF__

#include <rte_hash.h>
#include "util.h"
#include "list.h"
#include "qnsm_service.h"

#include "qnsm_tbl_ex.h"


#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_TBL_CONF_SOCKET_MAX    (2)
#define QNSM_TBL_CONF_CORE_MAX      (48)
#define QNSM_POOL_CACHE_SIZE        (256)

typedef struct qnsm_tbl {
    struct rte_hash *tbl;
    struct rte_mempool *pool;

    QNSM_TBL_PARA      *para;
    volatile uint32_t   item_num;
    uint32_t emergency_mode;
} QNSM_TBL;

typedef struct qnsm_lcore_tbl {
    QNSM_TBL tbl[EN_QNSM_TBL_MAX];
    uint32_t          lcore_id;
    uint32_t          socket_id;
} QNSM_LCORE_TBL;

typedef struct {
    uint32_t           deploy_num;
    uint32_t           per_lcore_size;
    uint32_t           emergency_recovery_num;
    uint32_t           emergency_diff_num;
} QNSM_TBL_INFO;

typedef struct {
    rte_spinlock_t      info_lock[APP_MAX_SOCKETS];
    QNSM_TBL_INFO       *tbl_info[APP_MAX_SOCKETS];
    rte_spinlock_t lock[APP_MAX_SOCKETS][EN_QNSM_TBL_MAX];
    struct rte_mempool *object_pool[APP_MAX_SOCKETS][EN_QNSM_TBL_MAX];
} QNSM_TBL_POOLS;

typedef struct {
    SERVICE_LIB_COMMON
    QNSM_TBL_PARA       tbl_para[EN_QNSM_TBL_MAX];
    QNSM_LCORE_TBL      tbls;
    QNSM_TBL_INFO       *tbl_info;
} QNSM_TBL_HANDLE;

int32_t qnsm_tbl_pre_init(void);
int32_t qnsm_tbl_init(void **tbl_handle);


#ifdef __cplusplus
}
#endif

#endif

