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
#include <rte_timer.h>
#include <rte_hash.h>


#include "qnsm_dbg.h"
#include "app.h"
#include "qnsm_service.h"
#include "qnsm_tbl_conf.h"

static QNSM_TBL_POOLS qnsm_tbl_pools;

#define QNSM_TBL_EMERGENCY_DIFF (8192)

static int32_t qnsm_tbl_setup(int32_t socket_id, int32_t lcore_id, QNSM_TBL *qnsm_tbl, void *pool, QNSM_TBL_PARA *tbl_para);

static void qnsm_tbl_item_init(struct rte_mempool *mp,
                               __attribute__((unused)) void *opaque_arg,
                               void *_m,
                               __attribute__((unused)) unsigned i)
{

    char *m = _m;

    memset(m, 0, mp->elt_size);
    return;
}

inline void qnsm_tbl_para_reg(EN_QNSM_APP app_type, EN_QNSM_TBL_TYPE type, void *para)
{
    QNSM_TBL_HANDLE *tbl_handle = qnsm_service_handle(EN_QNSM_SERVICE_TBL);
    uint32_t socket_id = 0;
    uint16_t lcore_id = 0;
    char pool_name[128];
    QNSM_TBL_POOLS *tbl_pools = &qnsm_tbl_pools;

    QNSM_ASSERT(EN_QNSM_TBL_MAX > type);
    rte_memcpy(tbl_handle->tbl_para + type, para, sizeof(QNSM_TBL_PARA));

    /*check para*/
    if ((0 >= tbl_handle->tbl_para[type].key_size)
        || (0 >= tbl_handle->tbl_para[type].object_size)
        || (0 >= tbl_handle->tbl_para[type].pool_size)
        || (100 < tbl_handle->tbl_para[type].emergency_recovery)) {

        QNSM_ASSERT(0);
    }

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_TBL, QNSM_DBG_ALL);

    socket_id = rte_socket_id();

    rte_spinlock_lock(&tbl_pools->info_lock[socket_id]);
    if (NULL == tbl_pools->tbl_info[socket_id]) {
        tbl_pools->tbl_info[socket_id] = rte_zmalloc_socket(NULL,
                                         sizeof(QNSM_TBL_INFO) * EN_QNSM_TBL_MAX,
                                         QNSM_DDOS_MEM_ALIGN,
                                         socket_id);
        QNSM_ASSERT(tbl_pools->tbl_info[socket_id]);
    }

    if (tbl_pools->tbl_info[socket_id]) {
        /*init tbl info*/
        tbl_pools->tbl_info[socket_id][type].deploy_num = 0;
        tbl_pools->tbl_info[socket_id][type].per_lcore_size = 0xFFFFFFFF;
        tbl_pools->tbl_info[socket_id][type].emergency_recovery_num = 0xFFFFFFFF;

        /*associate tbl info*/
        tbl_handle->tbl_info = tbl_pools->tbl_info[socket_id];
    }
    rte_spinlock_unlock(&tbl_pools->info_lock[socket_id]);

    rte_spinlock_lock(&tbl_pools->lock[socket_id][type]);
    if (NULL == tbl_pools->object_pool[socket_id][type]) {
        uint64_t pool_mem_size = 0;
        snprintf(pool_name, sizeof(pool_name), "%s_socket%d", tbl_handle->tbl_para[type].name, socket_id);
        tbl_pools->object_pool[socket_id][type] = rte_mempool_create(pool_name,
                tbl_handle->tbl_para[type].pool_size,
                tbl_handle->tbl_para[type].object_size,
                QNSM_POOL_CACHE_SIZE,
                0,
                NULL, NULL,
                qnsm_tbl_item_init, NULL,
                socket_id, 0);

        if (NULL == tbl_pools->object_pool[socket_id][type]) {
            QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_ERR, "malloc tbl type %u failed\n", type);
            return;
        }

        pool_mem_size = (uint64_t)tbl_handle->tbl_para[type].pool_size * tbl_handle->tbl_para[type].object_size;
        printf("create pool %s size %" PRIu64 "\n",
               pool_name,
               pool_mem_size);
    }
    rte_spinlock_unlock(&tbl_pools->lock[socket_id][type]);


    /*per-lcore tbl setup*/
    if (tbl_handle->tbl_para[type].deploy_type == app_type) {
        lcore_id = rte_lcore_id();
        socket_id = rte_socket_id();
        tbl_handle->tbls.lcore_id = lcore_id;
        tbl_handle->tbls.socket_id = socket_id;
        rte_spinlock_lock(&tbl_pools->lock[socket_id][type]);
        qnsm_tbl_setup(socket_id,
                       lcore_id,
                       &tbl_handle->tbls.tbl[type],
                       tbl_pools->object_pool[socket_id][type],
                       para);

        QNSM_ASSERT(NULL != tbl_handle->tbls.tbl[type].tbl);
        tbl_pools->tbl_info[socket_id][type].deploy_num++;
        rte_spinlock_unlock(&tbl_pools->lock[socket_id][type]);
    }

    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);

    SET_LIB_COMMON_STATE(tbl_handle, en_lib_state_load);
    return;
}

inline uint32_t qnsm_get_tbl_item_no(EN_QNSM_TBL_TYPE type)
{
    QNSM_TBL_HANDLE *tbl_handle = qnsm_service_handle(EN_QNSM_SERVICE_TBL);
    QNSM_TBL *lcore_tbl = NULL;

    lcore_tbl = &tbl_handle->tbls.tbl[type];
    return lcore_tbl->item_num;
}

void* qnsm_find_tbl_item(EN_QNSM_TBL_TYPE type, void *item_key)
{
    QNSM_TBL_HANDLE *tbl_handle = qnsm_service_handle(EN_QNSM_SERVICE_TBL);
    QNSM_TBL *lcore_tbl = NULL;
    void *item = NULL;

    lcore_tbl = &tbl_handle->tbls.tbl[type];

    if (0 > rte_hash_lookup_data(lcore_tbl->tbl, item_key, &item)) {
        return NULL;
    }
    return item;
}

static inline void  qnsm_updt_tbl_mode(QNSM_TBL_PARA *tbl_para, QNSM_TBL_INFO *tbl_info, QNSM_TBL *tbl)
{
    uint32_t per_lcore_size = 0;
    uint32_t diff = 0;

    /*first time set per lcore size*/
    if (0xFFFFFFFF == tbl_info->per_lcore_size) {
        per_lcore_size = tbl_para->pool_size / tbl_info->deploy_num;
        if (per_lcore_size > tbl_para->entry_num) {

            per_lcore_size = tbl_para->entry_num;
        }
        tbl_info->per_lcore_size = per_lcore_size;
        tbl_info->emergency_recovery_num = per_lcore_size * tbl_para->emergency_recovery / 100;
        tbl_info->emergency_diff_num = (tbl_info->emergency_recovery_num >> 2);
    }

    if (tbl_info->per_lcore_size > tbl->item_num) {
        diff = tbl_info->per_lcore_size - tbl->item_num;
        if (1 == tbl->emergency_mode) {
            QNSM_ASSERT(0xFFFFFFFF != tbl_info->per_lcore_size);
            if (diff >= tbl_info->emergency_recovery_num) {
                tbl->emergency_mode = 0;
                QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_WARN, "[%s] tbl switch to normal mode\n", tbl_para->name);
                QNSM_LOG(CRIT, "[%s, lcore %u] tbl switch to normal mode\n",
                        tbl_para->name, rte_lcore_id());
            }
        } else {
            if (diff < tbl_info->emergency_diff_num) {
                tbl->emergency_mode = 1;
                QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_WARN, "[%s] tbl switch to emergency mode\n", tbl_para->name);
                QNSM_LOG(CRIT, "[%s, lcore %u] tbl switch to emergency mode, diff_item_num %u\n",
                        tbl_para->name, rte_lcore_id(), tbl_info->emergency_diff_num);
            }
        }
    } else {
        uint32_t prev_mode = tbl->emergency_mode;

        tbl->emergency_mode = 1;
        if (0 == prev_mode) {
            QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_WARN, "[%s] tbl switch to emergency mode\n", tbl_para->name);
            QNSM_LOG(CRIT, "[%s, lcore %u] tbl switch to emergency mode, diff_item_num %u\n",
                    tbl_para->name, rte_lcore_id(), tbl_info->emergency_diff_num);
        }
    }

    return;
}

void* qnsm_add_tbl_item(EN_QNSM_TBL_TYPE type, void *item_key, uint8_t *normal_mode)
{
    QNSM_TBL_HANDLE *tbl_handle = qnsm_service_handle(EN_QNSM_SERVICE_TBL);
    QNSM_TBL *lcore_tbl = NULL;
    void *data = NULL;
    int32_t ret = 0;

    lcore_tbl = &tbl_handle->tbls.tbl[type];

    /*
    *if enter emergency mode, not allowed add tbl item util recovery
    *this policy can defend scala pressure
    */
    if (lcore_tbl->emergency_mode) {
        *normal_mode = !lcore_tbl->emergency_mode;
        return  NULL;
    }

    if (rte_mempool_get(lcore_tbl->pool, (void **)&data)) {
        QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_ERR, "[lcore %d] malloc item type %u failed\n", tbl_handle->tbls.lcore_id, type);
        qnsm_updt_tbl_mode(&tbl_handle->tbl_para[type], &tbl_handle->tbl_info[type], lcore_tbl);
        *normal_mode = !lcore_tbl->emergency_mode;
        return  NULL;
    }
    ret = rte_hash_add_key_data(lcore_tbl->tbl, item_key, data);
    if (ret) {

        QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_ERR, "[lcore %d] add item to tbl %u failed\n", tbl_handle->tbls.lcore_id, type);
        goto ERR_ADD;
    }

    lcore_tbl->item_num++;
    rte_memcpy((char *)data, (char *)item_key, tbl_handle->tbl_para[type].key_size);
    //qnsm_updt_tbl_mode(&tblm->tbl_para[type], &tblm->tbl_info[type], lcore_tbl);
    *normal_mode = !lcore_tbl->emergency_mode;
    QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_EVT, "[lcore %d] add item tbl type %u success, item_num %u\n", tbl_handle->tbls.lcore_id, type, lcore_tbl->item_num);
    return (void *)data;

ERR_ADD:
    *normal_mode = !lcore_tbl->emergency_mode;
    rte_mempool_put(lcore_tbl->pool, data);
    return NULL;
}

int32_t qnsm_del_tbl_item(EN_QNSM_TBL_TYPE type, void *item)
{
    QNSM_TBL_HANDLE *tbl_handle = qnsm_service_handle(EN_QNSM_SERVICE_TBL);
    QNSM_TBL *lcore_tbl = NULL;
    int32_t pos = 0;

    /*get key by offset to the item*/
    void *key = (char *)item + tbl_handle->tbl_para[type].key_offset;

    lcore_tbl = &tbl_handle->tbls.tbl[type];
    pos = rte_hash_del_key(lcore_tbl->tbl, key);
    if (0 > pos) {
        return -1;
    }
    rte_mempool_put(lcore_tbl->pool, item);
    lcore_tbl->item_num--;

    qnsm_updt_tbl_mode(&tbl_handle->tbl_para[type], &tbl_handle->tbl_info[type], lcore_tbl);

    QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_EVT, "[lcore %d] del item tbl type %u success , item_num %u\n", tbl_handle->tbls.lcore_id, type, lcore_tbl->item_num);
    return 0;
}

/*
* @param data
*   Output containing the data .
*   Returns NULL if data was not stored.
* @param next
*   Pointer to iterator. Should be 0 to start iterating the hash table.
*   Iterator is incremented after each call of this function.
* @return
*   Position where key was stored, if successful.
*   - -EINVAL if the parameters are invalid.
*   - -ENOENT if end of the hash table.
*/
int32_t qnsm_iterate_tbl(EN_QNSM_TBL_TYPE type, void **data, uint32_t *next)
{
    QNSM_TBL_HANDLE *tbl_handle = qnsm_service_handle(EN_QNSM_SERVICE_TBL);
    QNSM_TBL *lcore_tbl = NULL;
    const void *key;

    lcore_tbl = &tbl_handle->tbls.tbl[type];
    return rte_hash_iterate(lcore_tbl->tbl, (const void **)&key, data, next);
}

#if QNSM_PART("cmd")
int32_t qnsm_cmd_iter_tbl(void *para, EN_QNSM_TBL_TYPE type, void **data, uint32_t *next)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_TBL_HANDLE *tbl_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_TBL];
    QNSM_TBL *lcore_tbl = NULL;
    const void *key;

    lcore_tbl = &tbl_handle->tbls.tbl[type];
    return rte_hash_iterate(lcore_tbl->tbl, (const void **)&key, data, next);
}

inline uint32_t qnsm_cmd_get_tbl_item_no(void *para, EN_QNSM_TBL_TYPE type)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_TBL_HANDLE *tbl_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_TBL];
    QNSM_TBL *lcore_tbl = NULL;

    lcore_tbl = &tbl_handle->tbls.tbl[type];
    return lcore_tbl->item_num;
}

void* qnsm_cmd_find_tbl_item(void *para, EN_QNSM_TBL_TYPE type, void *item_key)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_TBL_HANDLE *tbl_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_TBL];
    QNSM_TBL *lcore_tbl = NULL;
    void *item = NULL;

    lcore_tbl = &tbl_handle->tbls.tbl[type];
    if (0 > rte_hash_lookup_data(lcore_tbl->tbl, item_key, &item)) {
        return NULL;
    }
    return item;
}
#endif

int32_t qnsm_tbl_setup(int32_t socket_id, int32_t lcore_id, QNSM_TBL *qnsm_tbl, void *pool, QNSM_TBL_PARA *tbl_para)
{
    char tbl_name[128];

    if (NULL == qnsm_tbl) {
        return -1;
    }
    snprintf(tbl_name, sizeof(tbl_name), "%s_lcore%d", tbl_para->name, lcore_id);

    struct rte_hash_parameters hash_para;
    hash_para.name = tbl_name;
    hash_para.entries = tbl_para->entry_num;
    hash_para.key_len = tbl_para->key_size;
    hash_para.hash_func = tbl_para->hash_func;
    hash_para.hash_func_init_val = 0;
    hash_para.socket_id = socket_id;

    qnsm_tbl->tbl = rte_hash_create(&hash_para);
    qnsm_tbl->pool = pool;
    qnsm_tbl->para = tbl_para;
    qnsm_tbl->item_num = 0;
    qnsm_tbl->emergency_mode = 0;

    QNSM_DEBUG(QNSM_DBG_M_TBL, QNSM_DBG_INFO, "tbl %s %p pool %p\n", tbl_name, qnsm_tbl->tbl, qnsm_tbl->pool);
    return 0;
}

int32_t qnsm_tbl_pre_init(void)
{
    QNSM_TBL_POOLS *tbl_pools = &qnsm_tbl_pools;
    EN_QNSM_TBL_TYPE type = 0;
    uint16_t index = 0;

    for (index = 0; index < APP_MAX_SOCKETS; index++) {
        rte_spinlock_init(&tbl_pools->info_lock[index]);
        for (type = EN_QNSM_IPV4_SESS; type < EN_QNSM_TBL_MAX; type++) {
            rte_spinlock_init(&tbl_pools->lock[index][type]);
        }
    }
    return 0;

}

int32_t qnsm_tbl_init(void **tbl_handle)
{
    QNSM_TBL_HANDLE *tbl_hdl = NULL;

    tbl_hdl = rte_zmalloc_socket("TBLM", sizeof(QNSM_TBL_HANDLE), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == tbl_hdl) {
        printf("[ERR]tbl init failed\n");
        return -1;
    }
    SET_LIB_COMMON_STATE(tbl_hdl, en_lib_state_init);

    *tbl_handle = tbl_hdl;
    return 0;
}

