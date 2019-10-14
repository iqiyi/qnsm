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
#ifndef __QNSM_MSG_EX__
#define __QNSM_MSG_EX__


#include "rte_ring.h"
#include "qnsm_service_ex.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_MSG_MAX_DATA_LEN   (1024)

typedef enum {
    QNSM_MSG_MODULE_IP    = (0x01 << 16),
    QNSM_MSG_MODULE_UNUSED = (0x02 << 16),
    QNSM_MSG_MOUDULE_DPI  = (0x03 << 16),
    QNSM_MSG_MOUDULE_SESS = (0x04 << 16),
    QNSM_MSG_MODULE_MAX   = (0xff << 16),
} EN_QNSM_MSG_MODULE;

enum {
    ITEM_MAX = 0xffff,
} EN_QNSM_MSG_TYPE;


#define QNSM_MSG_ID(MODULE, TYPE)  ((MODULE) | (TYPE))

/*
*msg id
*new msg id need add here
*/
typedef enum {
    QNSM_MSG_CUSTOM_IP_AGG  = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x10),
    QNSM_MSG_SVR_IP_AGG     = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x11),
    QNSM_MSG_CUSTOM_IP_NUM  = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x12),
    QNSM_MSG_DYN_VIP_ADD    = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x13),
    QNSM_MSG_DYN_VIP_DEL    = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x14),
    QNSM_MSG_VIP_SRC_PORT_AGG   = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x15),
    QNSM_MSG_VIP_DST_PORT_AGG   = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x16),
    QNSM_MSG_PF_SIGNATURE      = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x17),
    QNSM_MSG_CLOCK_SYN         = QNSM_MSG_ID(QNSM_MSG_MODULE_IP, 0x18),
    QNSM_MSG_DPI_PROTO_INFO    = QNSM_MSG_ID(QNSM_MSG_MOUDULE_DPI, 1),
    QNSM_MSG_SESS_AGG          = QNSM_MSG_ID(QNSM_MSG_MOUDULE_SESS, 1),
    QNSM_MSG_TCP_CONN          = QNSM_MSG_ID(QNSM_MSG_MOUDULE_SESS, 2),
    QNSM_MSG_SYN_BIZ_VIP       = QNSM_MSG_ID(QNSM_MSG_MOUDULE_SESS, 3),
    QNSM_MSG_SESS_DPI_STATIS   = QNSM_MSG_ID(QNSM_MSG_MOUDULE_SESS, 4),
    QNSM_MSG_SESS_LIFE_STATIS  = QNSM_MSG_ID(QNSM_MSG_MOUDULE_SESS, 5),
    QNSM_MSG_MAX               = QNSM_MSG_ID(QNSM_MSG_MODULE_MAX, ITEM_MAX),
} EN_QNSM_MSG_ID;

typedef struct {
    uint64_t tx_statistics;
    uint64_t tx_drop_statistics;
    uint64_t rx_statistics;
} QNSM_MSG_PIPE_STATIS;

typedef int32_t (*QNSM_MSG_PROC)(void *data, uint32_t data_len);
typedef int32_t (*QNSM_MSG_ENCAP)(void *msg, uint32_t *msg_len, void *data);

inline int32_t qnsm_msg_get_pipe_statis(uint16_t rx_lcore, uint16_t tx_lcore, QNSM_MSG_PIPE_STATIS *statis);

/**
 * app publish msg service
 *
 * @return
 *   0 success, other failed
 */
int32_t qnsm_msg_publish(void);

/**
 * msg subscribe
 *
 * @param target_lcore_id
 *   subscribe app deployed on target_lcore_id
 * @return
 *   0 success, other failed
 */
int32_t qnsm_msg_subscribe(uint32_t target_lcore_id);

/**
 * regesiter msg rcv or send encap cbk
 *
 * @param msg_id
 *   msg id used
 * @param msg_proc
 *   rcv cbk
 * @param msg_encap
 *   encap cbk when send msg
 * @return
 *   0 success, -1 failed
 */
int32_t qnsm_msg_reg(EN_QNSM_MSG_ID msg_id, QNSM_MSG_PROC msg_proc, QNSM_MSG_ENCAP msg_encap);

/**
 * send msg to all app instances
 *
 * @param app_type
 *   send msg to app
 * @param msg_id
 *   msg id used
 * @param data
 *   msg data ptr
 * @param sync
 *   whether send sync
 * @return
 *   0 success, -1 failed
 */
int32_t qnsm_msg_send_multi(EN_QNSM_APP app_type, EN_QNSM_MSG_ID msg_id, void *data, uint16_t sync);
int32_t qnsm_msg_send_lb(EN_QNSM_APP app_type, EN_QNSM_MSG_ID msg_id, void *data, uint32_t seed, uint16_t sync);
int32_t qnsm_msg_send_all(EN_QNSM_MSG_ID msg_id, void *data);

/**
 * flush need send msg
 */
void qnsm_msg_flush_timer_init(void);



#ifdef __cplusplus
}
#endif

#endif

