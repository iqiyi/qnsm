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
#ifndef __QNSM_SERVICE_H__
#define __QNSM_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <sys/prctl.h>
#include "qnsm_service_ex.h"

#define THREAD_NAME_LEN 16

/*
 * OS specific macro's for setting the thread name. "top" can display
 * this name.
 */
#if defined OS_FREEBSD /* FreeBSD */
/** \todo Add implementation for FreeBSD */
#define QnsmSetThreadName(n) ({ \
    char tname[16] = ""; \
    if (strlen(n) > 16) \
    strncpy(tname, n, 16); \
    pthread_set_name_np(pthread_self(), tname); \
    0; \
})
#elif defined __OpenBSD__ /* OpenBSD */
/** \todo Add implementation for OpenBSD */
#define QnsmSetThreadName(n) (0)
#elif defined PR_SET_NAME /* PR_SET_NAME */
/**
 * \brief Set the threads name
 */
#define QnsmSetThreadName(n) ({ \
    char tname[THREAD_NAME_LEN + 1] = ""; \
    strncpy(tname, n, THREAD_NAME_LEN); \
    (void)prctl(PR_SET_NAME, tname, 0, 0, 0); \
})
#else
#define QnsmSetThreadName(n) (0)
#endif


#define QNSM_GET_DATA() RTE_PER_LCORE(qnsm_data)

enum en_service_lib_state {
    en_lib_state_init = 0,
    en_lib_state_load,
    en_lib_state_max
};

#define SERVICE_LIB_COMMON \
    enum en_service_lib_state lib_state;

#define SET_LIB_COMMON_STATE(hdl, state) (hdl)->lib_state = (state)
#define GET_LIB_COMMON_STATE(hdl) (hdl)->lib_state

typedef struct {
    char name[64];
} QNSM_SERVICE_TYPE;

typedef struct {

    void *service_lib_handle[EN_QNSM_SERVCIE_MAX];

    void *app_handle;
    EN_QNSM_APP app_type;
    QNSM_APP_INIT init_fun;
    QNSM_APP_RUN run;
    QNSM_APP_RUN service_run;
    QNSM_APP_PKT_PROC pkt_proc;
    QNSM_APP_ACTION action;
} QNSM_DATA;

inline void* qnsm_service_handle(EN_QNSM_SERVICE handle_type);

#ifdef __cplusplus
}
#endif

#endif


