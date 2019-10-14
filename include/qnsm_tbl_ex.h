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
#ifndef __QNSM_TBL_EX__
#define __QNSM_TBL_EX__

#include <rte_hash.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EN_QNSM_IPV4_SESS = 0,
    EN_QNSM_IPV6_SESS,
    EN_QNSM_IPV4_CUSTOM,
    EN_QNSM_IPV6_CUSTOM,
    EN_QNSM_IPV6_VIP,
    EN_QNSM_SESS_IPV6_VIP,
    EN_QNSM_DUMP_IPV6_VIP,
    EN_QNSM_TBL_MAX,
} EN_QNSM_TBL_TYPE;

typedef uint32_t (*QNSM_ITEM_HASH)(void *key);
typedef int32_t (*QNSM_ITEM_CMP)(void *key, void *item_key);
typedef struct qnsm_tbl_para {
    char            name[64];       /*tbl name*/
    uint32_t        entry_num;      /*per lcore tbl size*/
    uint32_t        pool_size;      /*total size*/
    uint32_t        object_size;
    uint32_t        key_offset;
    uint32_t        key_size;
    rte_hash_function  hash_func;
    QNSM_ITEM_CMP   cmp_func;
    EN_QNSM_APP     deploy_type;    /*owned by which app*/

    /*
     *mode :mormal / emergency
     *
     *when reach the per lcore entry_num,
     *enter emergency mode, new tbl item less aging time
     *
     *percentage of per lcore entry_num
     *after which the flow-engine will be back to normal
     */
    uint8_t emergency_recovery;
} QNSM_TBL_PARA;

/**
 * register tbl
 *
 * @param app_type
 *   EN_QNSM_APP
 * @param type
 *   tbl type
 * @param para
 *   QNSM_TBL_PARA
 */
inline void qnsm_tbl_para_reg(EN_QNSM_APP app_type, EN_QNSM_TBL_TYPE type, void *para);

/**
 * find tbl item by key ptr
 *
 * @param type
 *   tbl type
 * @param item_key
 *   key ptr
 * @return
 *   item ptr, NULL if failed
 */
void* qnsm_find_tbl_item(EN_QNSM_TBL_TYPE type, void *item_key);

/**
 * add tbl item by key ptr
 *
 * @param type
 *   tbl type
 * @param item_key
 *   key ptr
 * @param normal_mode
 *   mode :mormal / emergency
 * @return
 *   item ptr
 */
void* qnsm_add_tbl_item(EN_QNSM_TBL_TYPE type, void *item_key, uint8_t *normal_mode);

/**
 * del tbl item
 *
 * @param type
 *   tbl type
 * @param item
 *   item ptr
 * @return
 *   0 success, other failed
 */
int32_t qnsm_del_tbl_item(EN_QNSM_TBL_TYPE type, void *item);
int32_t qnsm_iterate_tbl(EN_QNSM_TBL_TYPE type, void **data, uint32_t *next);

/*
*only used by cmd
*/
int32_t qnsm_cmd_iter_tbl(void *para, EN_QNSM_TBL_TYPE type, void **data, uint32_t *next);
inline uint32_t qnsm_cmd_get_tbl_item_no(void *para, EN_QNSM_TBL_TYPE type);
void* qnsm_cmd_find_tbl_item(void *para, EN_QNSM_TBL_TYPE type, void *item_key);

inline uint32_t qnsm_get_tbl_item_no(EN_QNSM_TBL_TYPE type);


#ifdef __cplusplus
}
#endif

#endif



