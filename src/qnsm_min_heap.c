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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

/* RTE HEAD FILE*/
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>


#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_min_heap.h"

void qnsm_min_heap_adjust_down(QNSM_HEAP *heap, uint32_t index)
{
    uint32_t lchild = 0;
    uint32_t rchild = 0;
    uint32_t half;
    uint32_t pos = 0;
    char * elem = NULL;
    uint32_t elem_size = 0;
    void *object = NULL;

    if ((NULL == heap) || (NULL == heap->elem)) {
        return;
    }

    elem_size = heap->elem_size;
    elem = (char *)heap->elem;
    half = heap->heap_size >> 1;

    /*临时保存要下沉元素*/
    object = elem + heap->heap_size * elem_size;
    rte_memcpy(object, elem + index * elem_size, elem_size);
    while (half > index) {
        lchild = (index << 1) + 1;
        rchild = lchild + 1;

        pos = lchild;
        if (rchild < heap->heap_size) {
            if (0 > heap->compare_func(elem + rchild * elem_size, elem + lchild * elem_size)) {
                pos = rchild;
            }
        }

        /*下沉元素比左右孩子中小者小*/
        if (0 > heap->compare_func(object, elem + pos * elem_size)) {
            break;
        }

        rte_memcpy(elem + index * elem_size, elem + pos * elem_size, elem_size);
        index = pos;
    }
    rte_memcpy(elem + index * elem_size, object, elem_size);

    return;
}


void qnsm_min_heap_construct(QNSM_HEAP *heap)
{
    int32_t pos = 0;

    if (heap->heap_size <= 1) {
        return;
    }

    pos = ((heap->heap_size) >> 1) - 1;
    while (0 <= pos) {
        qnsm_min_heap_adjust_down(heap, pos);
        pos--;
    }
    return;
}

void qnsm_min_heap_init(QNSM_HEAP *heap, uint32_t heap_size, uint32_t elem_size, QNSM_ELEM_COMPARE compare_func)
{
    QNSM_ASSERT(heap);
    QNSM_ASSERT(compare_func);

    heap->heap_size = heap_size;
    heap->elem_size = elem_size;
    heap->elem = (void *)rte_zmalloc(NULL, elem_size * (heap_size + 1), rte_socket_id());
    if (NULL == heap->elem) {
        //QNSM_ASSERT(0);
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "malloc heap failed\n");
        return;
    }
    heap->cur_elem_num = 0;
    heap->compare_func = compare_func;

    return;
}

void qnsm_min_heap_destroy(QNSM_HEAP *heap)
{
    QNSM_ASSERT(heap);

    if (heap->elem) {
        rte_free(heap->elem);
        heap->elem = NULL;
    }
    return;
}

inline void qnsm_min_heap_reset(QNSM_HEAP *heap)
{
    QNSM_ASSERT(heap);

    if (NULL != heap->elem) {
        memset(heap->elem, 0, heap->elem_size * heap->heap_size);
        heap->cur_elem_num = 0;
    }
    return;
}


