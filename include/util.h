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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>


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

/* ctrl conditions */
#define QnsmCtrlCondT pthread_cond_t
#define QnsmCtrlCondInit pthread_cond_init
#define QnsmCtrlCondSignal pthread_cond_signal
#define QnsmCtrlCondTimedwait pthread_cond_timedwait
#define QnsmCtrlCondWait pthread_cond_wait
#define QnsmCtrlCondDestroy pthread_cond_destroy

/* ctrl mutex */
#define QnsmCtrlMutex pthread_mutex_t
#define QnsmCtrlMutexAttr pthread_mutexattr_t
#define QnsmCtrlMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define QnsmCtrlMutexLock(mut) pthread_mutex_lock(mut)
#define QnsmCtrlMutexTrylock(mut) pthread_mutex_trylock(mut)
#define QnsmCtrlMutexUnlock(mut) pthread_mutex_unlock(mut)
#define QnsmCtrlMutexDestroy pthread_mutex_destroy


#endif
