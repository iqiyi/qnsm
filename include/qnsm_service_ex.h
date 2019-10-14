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
#ifndef __QNSM_SERVICE_EX_H__
#define __QNSM_SERVICE_EX_H__


#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EN_QNSM_SERVICE_MSG = 0,
    EN_QNSM_SERVICE_TBL,
    EN_QNSM_SERVICE_PORT,
    EN_QNSM_SERVICE_CFG,
    EN_QNSM_SERVICE_KAFKA,
    EN_QNSM_SERVICE_DPI,
    EN_QNSM_SERVICE_CMD_MSGQ,   /*unused*/
    EN_QNSM_SERVICE_CRM,
    EN_QNSM_SERVICE_ACL,
    EN_QNSM_SERVCIE_MAX,
} EN_QNSM_SERVICE;

typedef enum {
    EN_QNSM_SESSM = 0,
    EN_QNSM_SIP_AGG,
    EN_QNSM_VIP_AGG,
    EN_QNSM_EDGE,
    EN_QNSM_MASTER,
    EN_QNSM_DETECT,
    EN_QNSM_DUMP,
    EN_QNSM_TEST,
    EN_QNSM_DUMMY,
    EN_QNSM_APP_MAX
} EN_QNSM_APP;

typedef int32_t (*QNSM_APP_INIT)(void);
typedef void (*QNSM_APP_RUN)(void *this_app_data);
typedef void (*QNSM_APP_PKT_PROC)(void *this_app_data, uint32_t lcore_id, struct rte_mbuf *mbuf);
typedef void (*QNSM_APP_ACTION)(struct rte_mbuf *mbuf);

int32_t qnsm_service_lib_init(void *app_params);

/**
 * launch app
 *
 * @param para
 *   app para
 * @param init_fun
 *   app init cbk fun
 * @return
 *   0 success, other failed
 */
int32_t qnsm_servcie_app_launch(void *para,
                                QNSM_APP_INIT init_fun);

/**
 * register app own service run
 *
 * @param run
 *   app own run function
 * @return
 *   0 success, other failed
 */
int32_t qnsm_service_run_reg(QNSM_APP_RUN run);


/**
 * get app data
 *
 * @param type
 *   component/app type
 * @return
 *   app data ptr
 */
inline void* qnsm_app_data(EN_QNSM_APP type);

/**
* init app inst
* @param size
*   app data structure size
* @param pkt_proc
*   pkt proc fun, may be null
* @param action
*   after pkt proc, execute action
* @param run
*   app custom run fun, normally null
*/
inline void* qnsm_app_inst_init(uint32_t size,
                                QNSM_APP_PKT_PROC pkt_proc,
                                QNSM_APP_ACTION action,
                                QNSM_APP_RUN run);
inline void* qnsm_service_get_cfg_para(void);

inline void* qnsm_cmd_app_data(void *para, EN_QNSM_APP type);
inline void* qnsm_cmd_service_handle(void *para, EN_QNSM_SERVICE handle_type);
inline uint8_t qnsm_cmd_lib_load(void *para, EN_QNSM_SERVICE handle_type);

#ifdef __cplusplus
}
#endif

#endif

