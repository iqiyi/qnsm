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
#ifndef __UTIL__
#define __UTIL__

#include <rte_common.h>
#include <rte_log.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/syslog.h>


#define QNSM_DDOS_MEM_ALIGN (RTE_CACHE_LINE_SIZE)

#define MPLS_UNICAST_PRO_ID        0x8847
#define MPLS_MULTICAST_PRO_ID      0x8848
#define ETH_P_8021Q                0x8100
#define VLAN_LEN                   4
#define ETH_HEAD_LEN               14

#define TCP_PROTOCOL       6
#define UDP_PROTOCOL       17
#define ICMP_PROTOCOL      1
#define GRE_PROTOCOL       47
#define ESP_PROTOCOL       50

#define TCP_FIN         0x01
#define TCP_SYN         0x02
#define TCP_SYNFIN      0x03
#define TCP_RST         0x04
#define TCP_FINRST      0x05
#define TCP_SYNRST      0x06
#define TCP_PUSH        0x08
#define TCP_ACK         0x10
#define TCP_FINACK      0x11
#define TCP_SYNACK      0x12
#define TCP_PUSHACK     0x18
#define TCP_URG         0x20
#define TCP_ECN         0x40

enum DIRECTION {
    DIRECTION_IN    = 0x0,
    DIRECTION_OUT   = 0x1,
    DIRECTION_MAX   = 0x2,
};

void time_init(void);
uint64_t jiffies(void);
uint64_t get_diff_time(uint64_t time_now, uint64_t prev_time);

/* Logical cores */
#ifndef APP_MAX_SOCKETS
#define APP_MAX_SOCKETS 2
#endif

#ifndef APP_MAX_LCORES
#define APP_MAX_LCORES       (RTE_MAX_LCORE)
#endif

#ifndef APP_DEFAULT_MEMPOOL_CACHE_SIZE
#define APP_DEFAULT_MEMPOOL_CACHE_SIZE  256
#endif

#define QNSM_PART(desc)    1
#define UNUSED(x) x //__attribute((unused))


/*
* QNSM_TIME_AFTER(a,b) returns true if the time a is after time b.
*/
#define QNSM_TIME_AFTER(a, b)       \
    (((int64_t)((b) - (a)) < 0))
#define QNSM_TIME_BEFORE(a, b)   QNSM_TIME_AFTER(b, a)

#define QNSM_SWAP(x, y) { x ^= y; y ^= x; x ^= y; }

#define INTVAL (10)

#define PREFETCH_OFFSET 4

enum en_qnsm_log_type {
    EN_QNSM_LOG_RTE = 0,
    EN_QNSM_LOG_SYSLOG,
    EN_QNSM_LOG_MAX,
};

enum {
    QNSM_LOG_NOTSET = -1,
    QNSM_LOG_NONE = 0,
    QNSM_LOG_EMERG,
    QNSM_LOG_ALERT,
    QNSM_LOG_CRIT,
    QNSM_LOG_ERR,
    QNSM_LOG_WARNING,
    QNSM_LOG_NOTICE,
    QNSM_LOG_INFO,
    QNSM_LOG_DEBUG,
    QNSM_LOG_LEVEL_MAX,
};

typedef struct qnsm_log_cfg {
    enum en_qnsm_log_type type;
    int log_level;

    /*file log conf*/
    struct {
        char *log_dir;
        char *log_level;
    } file_log_conf;

    /*syslog conf*/
    struct {
        uint8_t enabled;
        char *facility;
        char *log_level;
    } sys_log_conf;
} QNSM_LOG_CFG;

inline QNSM_LOG_CFG* qnsm_get_log_conf(void);

#define QNSM_LOG(level, format, ...)\
{\
    switch (qnsm_get_log_conf()->type) {\
        case EN_QNSM_LOG_RTE: {\
            RTE_LOG(level, QNSM, "%" PRIu64 " - (%s:%d) <%s> "format, \
                jiffies(), __FILE__, __LINE__, #level, ##__VA_ARGS__);\
            break;\
        }\
        case EN_QNSM_LOG_SYSLOG: {\
            if (qnsm_get_log_conf()->log_level >= QNSM_LOG_##level) {\
                syslog(LOG_##level, "%" PRIu64 " - (%s:%d) <%s> "format, \
                    jiffies(), __FILE__, __LINE__, #level, ##__VA_ARGS__);\
            }\
            break;\
        }\
        case EN_QNSM_LOG_MAX: {\
            break;\
        }\
    }\
}

#endif
