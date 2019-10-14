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

#ifndef __QNSM_DBG_H__
#define __QNSM_DBG_H__

#include <rte_log.h>

#include <assert.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t    g_qnsm_dbg;

#define RTE_LOGTYPE_QNSM (RTE_LOGTYPE_USER1)

typedef enum {
    QNSM_DBG_INFO =  0x01,
    QNSM_DBG_EVT  =  0x02,
    QNSM_DBG_PKT  =  0x04,
    QNSM_DBG_WARN  = 0x08,
    QNSM_DBG_ERR  =  0x10,
    //QNSM_DBG_DPI  =  0x20,
    QNSM_DBG_ALL  =  0xff,
} EN_QNSM_DBG_TYPE;

typedef enum {
    QNSM_DBG_M_CUSTOM_IPAGG   = 0x01,
    QNSM_DBG_M_VIPAGG         = 0x02,
    QNSM_DBG_M_SESS           = 0x03,
    QNSM_DBG_M_TCP            = 0x04,
    QNSM_DBG_M_CFG            = 0x05,
    QNSM_DBG_M_MSG            = 0x06,
    QNSM_DBG_M_PORT            = 0x07,
    QNSM_DBG_M_TBL            = 0x08,
    QNSM_DBG_M_NONE           = 0x09,
    QNSM_DBG_M_DPI            = 0x0A,
    QNSM_DBG_M_DPI_HTTP       = 0x0B,
    QNSM_DBG_M_DPI_DNS        = 0x0C,
    QNSM_DBG_M_DPI_NTP        = 0x0D,
    QNSM_DBG_M_DPI_SSDP       = 0x0E,
    QNSM_DBG_M_DPI_IPS        = 0x0F,
    QNSM_DBG_M_DPI_MASTER     = 0x10,
    QNSM_DBG_M_DECODE_PKT     = 0x11,
    QNSM_DBG_M_MAX,
} EN_QNSM_DBG_MODULE;

/*support one module dbg all type, but not support multi or all module dbg*/
#define QNSM_DEBUG_ENABLE(module, type)   (g_qnsm_dbg) = ((module) << 16) | ((g_qnsm_dbg & 0x000000FF) | type);
#define QNSM_DEBUG_DISABLE(module, type)  (g_qnsm_dbg) = ((module) << 16) | ((g_qnsm_dbg & 0x000000FF) & ((uint8_t)(~type)));


#ifdef  DEBUG_QNSM
#define QNSM_DEBUG(module, type, format, ...)   \
    do{                                 \
        if ((module == (g_qnsm_dbg >> 16))     \
            && (g_qnsm_dbg & type))    \
        {                               \
            if (QNSM_DBG_PKT != type)   \
            {                           \
                printf("[QNSM]%s:%d "format, __FUNCTION__, __LINE__, ##__VA_ARGS__);  \
            }                           \
            else                        \
            {                           \
                printf(format, ##__VA_ARGS__);  \
            }                           \
        }                               \
      }while(0);
#else
#define QNSM_DEBUG(module, type, format, ...) do{}while(0);
#endif

#define QNSM_ASSERT(exp) assert(exp)

#ifdef __cplusplus
}
#endif

#endif

