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
#ifndef __QNSM_MASTER_EX_H__
#define __QNSM_MASTER_EX_H__

#include "qnsm_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QNSM_BIZ_VIP_ADD = 0,
    QNSM_BIZ_VIP_DEL = 1,
} QNSM_BIZ_VIP_OP;

typedef enum {
    EN_QNSM_CMD_ENABLE_SPORT_STATIS =     0,
    EN_QNSM_CMD_DISABLE_SPORT_STATIS =    1,
    EN_QNSM_CMD_DUMP_PKT             =    2,
    EN_QNSM_CMD_DISABLE_DUMP_PKT     =    3,
    EN_QNSM_CMD_DPI_CHECK            =    4,
    EN_QNSM_CMD_ADD_PASSIVE_FINGERPRINT = 5,
    EN_QNSM_CMD_DEL_PASSIVE_FINGERPRINT = 6,
    EN_QNSM_CMD_VIP_ENABLE_CUS_IP_AGG   = 7,
    EN_QNSM_CMD_VIP_DISABLE_CUS_IP_AGG  = 8,
    EN_QNSM_CMD_VIP_ENABLE_SESSION      = 9,
    EN_QNSM_CMD_VIP_DISABLE_SESSION     = 10,
    EN_QNSM_CMD_MAX,
} EN_QNSM_BORDERM_CMD;

typedef struct {
    QNSM_BIZ_VIP_OP op;
    uint32_t group_id;          /*deprecated*/
    uint8_t  af;                /*enum en_qnsm_ip_af*/
    uint8_t  rsvd[2];
    uint8_t  mask;
    QNSM_IN_ADDR key;

    /*borderm cmd*/
    EN_QNSM_BORDERM_CMD cmd;
    char cmd_data[32];        /*first 8byte: is local vip; then: QNSM_POLICY_MSG_DATA*/
} QNSM_BIZ_VIP_MSG;

typedef struct {
    uint8_t proto;
    uint16_t vport;
    uint16_t sport;
    uint32_t sip;
} QNSM_POLICY_MSG_DATA;

int32_t qnsm_master_init(void);


#ifdef __cplusplus
}
#endif

#endif

