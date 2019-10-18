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

#include <rte_cycles.h>
#include <time.h>
#include <stdio.h>

#include "util.h"

QNSM_LOG_CFG    g_qnsm_log_cfg = {
    .type = EN_QNSM_LOG_MAX,
};

static uint64_t cycles_second_shift;

void time_init()
{

    uint64_t second;

    /* caclulate closest shift to convert from cycles to ms (approximate) */
    second = rte_get_tsc_hz();
    cycles_second_shift = sizeof(second) * CHAR_BIT - __builtin_clzll(second) - 1;

    return;
}

uint64_t jiffies(void)
{
    time_t t;
    t = time(NULL);
    return t;
}

uint64_t get_diff_time(uint64_t time_now, uint64_t prev_time)
{
    if(time_now >= prev_time) {
        return (time_now - prev_time);
    } else {
#if 0
        /*code bug, calc from left to right*/
        return (time_now + 0xFFFFFFFFFFFFFFFF - prev_time);
#else
        return (0xFFFFFFFFFFFFFFFF - prev_time) + time_now;
#endif
    }
}

inline QNSM_LOG_CFG* qnsm_get_log_conf(void)
{
    return &g_qnsm_log_cfg;
}
