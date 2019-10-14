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
#ifndef __QNSM_MIN_HEAP_H__
#define __QNSM_MIN_HEAP_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*QNSM_ELEM_COMPARE)(void *elem1, void *elem2);

typedef struct qnsm_heap {
    void *elem;
    uint32_t elem_size;
    uint32_t heap_size;
    uint32_t cur_elem_num;
    QNSM_ELEM_COMPARE compare_func;
} QNSM_HEAP;

#define QNSM_CLEAR_HEAP(HEAP)   memset((HEAP)->elem, 0, ((HEAP)->heap_size) * ((HEAP)->elem_size))

void qnsm_min_heap_adjust_down(QNSM_HEAP *heap, uint32_t index);
void qnsm_min_heap_construct(QNSM_HEAP *heap);
void qnsm_min_heap_init(QNSM_HEAP *heap, uint32_t heap_size, uint32_t elem_size, QNSM_ELEM_COMPARE compare_func);
void qnsm_min_heap_destroy(QNSM_HEAP *heap);
inline void qnsm_min_heap_reset(QNSM_HEAP *heap);


#ifdef __cplusplus
}
#endif

#endif
