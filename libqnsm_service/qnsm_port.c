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

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_alarm.h>
#include <rte_port_ring.h>
#ifdef RTE_LIBRTE_KNI
#include <rte_port_kni.h>
#endif
#include <rte_port_ethdev.h>
#include <rte_port_fd.h>
#include <rte_port.h>


#include "app.h"
#include "util.h"
#include "qnsm_inspect_main.h"
#include "qnsm_service.h"
#include "qnsm_dbg.h"
#include "qnsm_port_ex.h"
#include "qnsm_port.h"

static QNSM_PORT_OPS qnsm_port_ops;

static inline int
qnsm_port_pktmbuf_copy_data(struct rte_mbuf *seg, const struct rte_mbuf *m)
{
    if (rte_pktmbuf_tailroom(seg) < m->data_len) {
        QNSM_DEBUG(QNSM_DBG_M_PORT, QNSM_DBG_EVT,
                   "User mempool: insufficient data_len of mbuf\n");
        return -EINVAL;
    }

    seg->port = m->port;
    seg->vlan_tci = m->vlan_tci;
    seg->hash = m->hash;
    seg->tx_offload = m->tx_offload;
    seg->ol_flags = m->ol_flags;
    seg->packet_type = m->packet_type;
    seg->vlan_tci_outer = m->vlan_tci_outer;
    seg->data_len = m->data_len;
    seg->pkt_len = seg->data_len;
    rte_memcpy(rte_pktmbuf_mtod(seg, void *),
               rte_pktmbuf_mtod(m, void *),
               rte_pktmbuf_data_len(seg));
#if 1
    rte_memcpy((void *)(seg + 1),
               (const void *)(m + 1),
               m->priv_size);
#endif
    return 0;
}

static inline struct rte_mbuf *
qnsm_port_pktmbuf_copy(struct rte_mbuf *m, struct rte_mempool *mp)
{
    struct rte_mbuf *m_dup, *seg, **prev;
    uint32_t pktlen;
    uint8_t nseg;

    m_dup = rte_pktmbuf_alloc(mp);
    if (unlikely(m_dup == NULL))
        return NULL;

    seg = m_dup;
    prev = &seg->next;
    pktlen = m->pkt_len;
    nseg = 0;

    do {
        nseg++;
        if (qnsm_port_pktmbuf_copy_data(seg, m) < 0) {
            rte_pktmbuf_free(m_dup);
            return NULL;
        }
        *prev = seg;
        prev = &seg->next;
    } while ((m = m->next) != NULL &&
             (seg = rte_pktmbuf_alloc(mp)) != NULL);

    *prev = NULL;
    m_dup->nb_segs = nseg;
    m_dup->pkt_len = pktlen;

    /* Allocation of new indirect segment failed */
    if (unlikely(seg == NULL)) {
        rte_pktmbuf_free(m_dup);
        return NULL;
    }

    __rte_mbuf_sanity_check(m_dup, 1);
    return m_dup;
}


int32_t qnsm_port_pre_init(void)
{
    QNSM_PORT_OPS *port_ops = &qnsm_port_ops;
    uint16_t index = 0;

    QNSM_DEBUG_ENABLE(QNSM_DBG_M_PORT, QNSM_DBG_ALL);

    for (index = 0; index < APP_PKTQ_IN_MAX; index++) {
        if (APP_PKTQ_IN_HWQ == index) {
            port_ops->in_ops[index] = &rte_port_ethdev_reader_ops;
        }

        if (APP_PKTQ_IN_SWQ == index) {
            port_ops->in_ops[index] = &rte_port_ring_reader_ops;
        }

#ifdef RTE_LIBRTE_KNI
        if (APP_PKTQ_IN_KNI == index) {
            port_ops->in_ops[index] = &rte_port_kni_reader_ops;
        }
#endif

        if (APP_PKTQ_IN_TAP == index) {
            port_ops->in_ops[index] = &rte_port_fd_reader_ops;
        }
    }

    for (index = 0; index < APP_PKTQ_OUT_MAX; index++) {
        if (APP_PKTQ_OUT_HWQ == index) {
            port_ops->out_ops[index] = &rte_port_ethdev_writer_ops;
        }

        if (APP_PKTQ_OUT_SWQ == index) {
            port_ops->out_ops[index] = &rte_port_ring_writer_ops;
        }
#ifdef RTE_LIBRTE_KNI
        if (APP_PKTQ_OUT_KNI == index) {
            port_ops->out_ops[index] = &rte_port_kni_writer_ops;
        }
#endif
        if (APP_PKTQ_OUT_TAP == index) {
            port_ops->out_ops[index] = &rte_port_fd_writer_ops;
        }
    }

    QNSM_DEBUG_DISABLE(0, QNSM_DBG_ALL);
    return 0;
}


int32_t qnsm_port_service_init(struct app_params *app, struct app_pipeline_params *pipeline_params, void **tbl_handle)
{
    uint16_t index = 0;
    QNSM_PORT_OPS *port_ops = &qnsm_port_ops;
    struct app_pktq_in_params *pktq_in = NULL;
    struct app_pktq_out_params *pktq_out = NULL;
    QNSM_PORT_HANDLE *port_handle = NULL;

    QNSM_ASSERT(QNSM_PORT_MAX >= pipeline_params->n_pktq_in);

    if ((0 >= pipeline_params->n_pktq_in)
        && (0 >= pipeline_params->n_msgq_out)) {
        return 0;
    }

    port_handle = rte_zmalloc_socket("QNSM_PORT", sizeof(QNSM_PORT_HANDLE), QNSM_DDOS_MEM_ALIGN, pipeline_params->socket_id);
    if (NULL == port_handle) {
        QNSM_ASSERT(0);
        return -1;
    }
    port_handle->tx_port_cnt = 0;
    port_handle->n_tx_port_pow2 = 0;
    port_handle->n_dump_port = 0;
    port_handle->n_dup_port = 0;

    for (index = 0; index < pipeline_params->n_pktq_in; index++) {
        pktq_in = &pipeline_params->pktq_in[index];
        switch (pktq_in->type) {
            case APP_PKTQ_IN_HWQ: {
                struct rte_port_ethdev_reader_params port_ethdev_params;
                struct app_pktq_hwq_in_params *p_hwq_in =
                        &app->hwq_in_params[pktq_in->id];
                struct app_link_params *p_link =
                    app_get_link_for_rxq(app, p_hwq_in);
                uint32_t rxq_link_id, rxq_queue_id;

                sscanf(p_hwq_in->name, "RXQ%" SCNu32 ".%" SCNu32,
                       &rxq_link_id,
                       &rxq_queue_id);

                port_ethdev_params.port_id = p_link->pmd_id;
                port_ethdev_params.queue_id = rxq_queue_id;
                port_handle->port_in[index].h_port =
                    port_ops->in_ops[APP_PKTQ_IN_HWQ]->f_create(&port_ethdev_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_in[index].h_port);
                if (RTE_PORT_IN_BURST_SIZE_MAX < p_hwq_in->burst) {
                    port_handle->port_in[index].burst_size = RTE_PORT_IN_BURST_SIZE_MAX;
                } else {
                    port_handle->port_in[index].burst_size = p_hwq_in->burst;
                }
                memcpy(&port_handle->port_in[index].ops, port_ops->in_ops[APP_PKTQ_IN_HWQ], sizeof(struct rte_port_in_ops));
                break;
            }
            case APP_PKTQ_IN_SWQ: {
                struct rte_port_ring_reader_params port_ring_reader_params;

                port_ring_reader_params.ring = app->swq[pktq_in->id];
                port_handle->port_in[index].h_port =
                    port_ops->in_ops[APP_PKTQ_IN_SWQ]->f_create(&port_ring_reader_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_in[index].h_port);
                port_handle->port_in[index].burst_size = RTE_PORT_IN_BURST_SIZE_MAX >> 1;
                memcpy(&port_handle->port_in[index].ops, port_ops->in_ops[APP_PKTQ_IN_SWQ], sizeof(struct rte_port_in_ops));
                break;
            }
#ifdef RTE_LIBRTE_KNI
            case APP_PKTQ_IN_KNI: {
                struct rte_port_kni_reader_params kni_params;

                kni_params.kni = app->kni[pktq_in->id];
                port_handle->port_in[index].h_port =
                    port_ops->in_ops[APP_PKTQ_IN_KNI]->f_create(&kni_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_in[index].h_port);
                port_handle->port_in[index].burst_size = RTE_PORT_IN_BURST_SIZE_MAX >> 1;
                memcpy(&port_handle->port_in[index].ops, port_ops->in_ops[APP_PKTQ_IN_KNI], sizeof(struct rte_port_in_ops));
                break;
            }
#endif
            case APP_PKTQ_IN_TAP: {
                struct rte_port_fd_reader_params fd_reader_params;
                struct app_pktq_tap_params *p_tap = &app->tap_params[pktq_in->id];

                fd_reader_params.fd = app->tap[pktq_in->id];
                fd_reader_params.mempool = app->mempool[p_tap->mempool_id];
                fd_reader_params.mtu = app->mempool_params[p_tap->mempool_id].buffer_size - sizeof(struct rte_mbuf);
                port_handle->port_in[index].h_port =
                    port_ops->in_ops[APP_PKTQ_IN_TAP]->f_create(&fd_reader_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_in[index].h_port);
                port_handle->port_in[index].burst_size = RTE_PORT_IN_BURST_SIZE_MAX >> 1;
                memcpy(&port_handle->port_in[index].ops, port_ops->in_ops[APP_PKTQ_IN_TAP], sizeof(struct rte_port_in_ops));
                break;
            }
            default: {
                break;
            }
        }
    }
    port_handle->rx_port_cnt = pipeline_params->n_pktq_in;

    QNSM_ASSERT(QNSM_PORT_MAX >= pipeline_params->n_pktq_out);
    for (index = 0; index < pipeline_params->n_pktq_out; index++) {
        pktq_out = &pipeline_params->pktq_out[index];
        switch (pktq_out->type) {
            case APP_PKTQ_OUT_HWQ: {
                struct rte_port_ethdev_writer_params port_ethdev_writer_params;
                struct app_pktq_hwq_out_params *p_hwq_out =
                        &app->hwq_out_params[pktq_out->id];
                struct app_link_params *p_link =
                    app_get_link_for_txq(app, p_hwq_out);
                uint32_t txq_link_id, txq_queue_id;

                sscanf(p_hwq_out->name,
                       "TXQ%" SCNu32 ".%" SCNu32,
                       &txq_link_id,
                       &txq_queue_id);

                port_ethdev_writer_params.port_id = p_link->pmd_id;
                port_ethdev_writer_params.queue_id = txq_queue_id;
                port_ethdev_writer_params.tx_burst_sz = p_hwq_out->burst;
                port_handle->port_out[index].h_port =
                    port_ops->out_ops[APP_PKTQ_OUT_HWQ]->f_create(&port_ethdev_writer_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_out[index].h_port);
                memcpy(&port_handle->port_out[index].ops, port_ops->out_ops[APP_PKTQ_OUT_HWQ], sizeof(struct rte_port_out_ops));
                port_handle->tx_port_cnt++;
                break;
            }
            case APP_PKTQ_OUT_SWQ: {
                struct rte_port_ring_writer_params port_ring_writer_params;
                struct app_pktq_swq_params *p_swq_out =
                        &app->swq_params[pktq_out->id];
                uint16_t port_id  = port_handle->tx_port_cnt;
                uint16_t dup_id  = port_handle->n_dup_port;

                if (1 == p_swq_out->dump) {
                    port_ring_writer_params.ring = app->swq[pktq_out->id];
                    port_ring_writer_params.tx_burst_sz = RTE_PORT_IN_BURST_SIZE_MAX;
                    port_handle->port_dump.h_port =
                        port_ops->out_ops[APP_PKTQ_OUT_SWQ]->f_create(&port_ring_writer_params, pipeline_params->socket_id);
                    QNSM_ASSERT(port_handle->port_dump.h_port);
                    memcpy(&port_handle->port_dump.ops, port_ops->out_ops[APP_PKTQ_OUT_SWQ], sizeof(struct rte_port_out_ops));

                    port_handle->port_dump.pool = NULL;
                    if (0xFF != p_swq_out->mempool_id) {
                        port_handle->port_dump.pool = app->mempool[p_swq_out->mempool_id];
                        printf("port name %s service name %s\n", p_swq_out->name, pipeline_params->name);
                    }
                    port_handle->n_dump_port++;
                    QNSM_ASSERT(2 > port_handle->n_dump_port);
                } else if (1 == p_swq_out->dup) {
                    port_ring_writer_params.ring = app->swq[pktq_out->id];
                    port_ring_writer_params.tx_burst_sz = RTE_PORT_IN_BURST_SIZE_MAX;
                    port_handle->port_dup_tx[dup_id].h_port =
                        port_ops->out_ops[APP_PKTQ_OUT_SWQ]->f_create(&port_ring_writer_params, pipeline_params->socket_id);
                    QNSM_ASSERT(port_handle->port_dup_tx[dup_id].h_port);
                    memcpy(&port_handle->port_dup_tx[dup_id].ops, port_ops->out_ops[APP_PKTQ_OUT_SWQ], sizeof(struct rte_port_out_ops));

                    if (0xFF != p_swq_out->mempool_id) {
                        port_handle->port_dup_tx[dup_id].pool = app->mempool[p_swq_out->mempool_id];
                        printf("dup port name %s service name %s\n", p_swq_out->name, pipeline_params->name);
                    }
                    port_handle->n_dup_port++;
                } else {
                    port_ring_writer_params.ring = app->swq[pktq_out->id];
                    port_ring_writer_params.tx_burst_sz = RTE_PORT_IN_BURST_SIZE_MAX;
                    port_handle->port_out[port_id].h_port =
                        port_ops->out_ops[APP_PKTQ_OUT_SWQ]->f_create(&port_ring_writer_params, pipeline_params->socket_id);
                    QNSM_ASSERT(port_handle->port_out[port_id].h_port);
                    memcpy(&port_handle->port_out[port_id].ops, port_ops->out_ops[APP_PKTQ_OUT_SWQ], sizeof(struct rte_port_out_ops));

                    /*set pkt pool*/
                    port_handle->port_out[port_id].pool = NULL;
                    if (0xFF != p_swq_out->mempool_id) {
                        QNSM_ASSERT(0);
                    }
                    port_handle->tx_port_cnt++;
                }
                break;
            }

#ifdef RTE_LIBRTE_KNI
            case APP_PKTQ_OUT_KNI: {
                struct rte_port_kni_writer_params kni_writer_params;
                struct app_pktq_kni_params *p_kni_out =
                        &app->kni_params[pktq_out->id];
                uint16_t kni_id = port_handle->n_kni_port;

                kni_writer_params.kni = app->kni[pktq_out->id];
                kni_writer_params.tx_burst_sz = RTE_PORT_IN_BURST_SIZE_MAX;
                port_handle->port_kni_tx[kni_id].h_port =
                    port_ops->out_ops[APP_PKTQ_OUT_KNI]->f_create(&kni_writer_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_kni_tx[kni_id].h_port);
                memcpy(&port_handle->port_kni_tx[kni_id].ops, port_ops->out_ops[APP_PKTQ_OUT_KNI], sizeof(struct rte_port_out_ops));

                port_handle->port_kni_tx[kni_id].pool = NULL;
                port_handle->n_kni_port++;
                printf("kni(%p) port name %s service name %s\n", app->kni[pktq_out->id], p_kni_out->name, pipeline_params->name);
                break;
            }
#endif
            case APP_PKTQ_OUT_TAP: {
                struct rte_port_fd_writer_params tap_writer_params;
                uint16_t tap_id = port_handle->n_tap_port;

                tap_writer_params.fd =  app->tap[pktq_out->id];
                tap_writer_params.tx_burst_sz = RTE_PORT_IN_BURST_SIZE_MAX;
                port_handle->port_tap_tx[tap_id].h_port =
                    port_ops->out_ops[APP_PKTQ_OUT_TAP]->f_create(&tap_writer_params, pipeline_params->socket_id);
                QNSM_ASSERT(port_handle->port_tap_tx[tap_id].h_port);
                memcpy(&port_handle->port_tap_tx[tap_id].ops, port_ops->out_ops[APP_PKTQ_OUT_TAP], sizeof(struct rte_port_out_ops));

                port_handle->port_tap_tx[tap_id].pool = NULL;
                port_handle->n_tap_port++;
                break;
            }
            default:

                break;
        }
    }
    QNSM_ASSERT(2 > port_handle->n_dump_port);
    port_handle->n_tx_port_pow2 = rte_is_power_of_2(port_handle->tx_port_cnt);
    port_handle->n_dup_port_pow2 = rte_is_power_of_2(port_handle->n_dup_port);
#ifdef RTE_LIBRTE_KNI
    port_handle->n_kni_port_pow2 = rte_is_power_of_2(port_handle->n_kni_port);
#endif
    port_handle->n_tap_port_pow2 = rte_is_power_of_2(port_handle->n_tap_port);

    /*init reta*/
    if (0 < port_handle->tx_port_cnt) {
        uint8_t tx_pos = 0;
        QNSM_ASSERT(QNSM_PORT_RETA_SIZE >= port_handle->tx_port_cnt);

        for (index = 0; index < QNSM_PORT_RETA_SIZE; index++) {
            tx_pos = index % port_handle->tx_port_cnt;
            port_handle->reta[index] = tx_pos;
        }
    }

    SET_LIB_COMMON_STATE(port_handle, en_lib_state_init);
    if ((0 < port_handle->tx_port_cnt)
        || (0 < port_handle->rx_port_cnt)
        || (0 < port_handle->n_dump_port)
        || (0 < port_handle->n_dup_port)
        || (0 < port_handle->n_tap_port)) {
        SET_LIB_COMMON_STATE(port_handle, en_lib_state_load);
    }
    *tbl_handle = port_handle;
    return 0;
}

int32_t qnsm_port_tap_tx_lb(uint32_t pos, struct rte_mbuf *mbuf)
{
    QNSM_PORT_HANDLE *port_handle = qnsm_service_handle(EN_QNSM_SERVICE_PORT);
    QNSM_PORT_OUT *port_out = NULL;
    uint16_t port_id = 0;

    if (0 < port_handle->n_tap_port) {
        if (port_handle->n_tap_port_pow2) {
            port_id = pos & (port_handle->n_tap_port - 1);
        } else {
            port_id = pos % (port_handle->n_tap_port);
        }

        port_out = &port_handle->port_tap_tx[port_id];
        port_out->ops.f_tx(port_out->h_port, mbuf);
    }

    return 0;
}

static int32_t qnsm_port_kni_tx_lb(uint32_t pos, struct rte_mbuf *mbuf)
{
#ifdef RTE_LIBRTE_KNI
    QNSM_PORT_HANDLE *port_handle = qnsm_service_handle(EN_QNSM_SERVICE_PORT);
    QNSM_PORT_OUT *port_out = NULL;
    uint16_t port_id = 0;

    if (0 < port_handle->n_kni_port) {
        if (port_handle->n_kni_port_pow2) {
            port_id = pos & (port_handle->n_kni_port - 1);
        } else {
            port_id = pos % (port_handle->n_kni_port);
        }

        port_out = &port_handle->port_kni_tx[port_id];
        port_out->ops.f_tx(port_out->h_port, mbuf);
    }
#else
#endif
    return 0;
}

int32_t qnsm_port_dup_tx_lb(uint32_t pos, struct rte_mbuf *mbuf)
{
    QNSM_PORT_HANDLE *port_handle = qnsm_service_handle(EN_QNSM_SERVICE_PORT);
    QNSM_PORT_OUT *port_out = NULL;
    struct rte_mbuf *tx_mbuf = NULL;
    uint16_t port_id = 0;

    /*dup pkt*/
    if (0 < port_handle->n_dup_port) {
        if (port_handle->n_dup_port_pow2) {
            port_id = pos & (port_handle->n_dup_port - 1);
        } else {
            port_id = pos % (port_handle->n_dup_port);
        }
        port_out = &port_handle->port_dup_tx[port_id];

        tx_mbuf = qnsm_port_pktmbuf_copy(mbuf, port_out->pool);
        if (tx_mbuf) {
            port_handle->port_dump.ops.f_tx(port_out->h_port, tx_mbuf);
        } else {
            QNSM_DEBUG(QNSM_DBG_M_PORT, QNSM_DBG_EVT, "cpy pkt failed\n");
        }
    }
    return 0;
}

int32_t qnsm_port_dump_tx(struct rte_mbuf *mbuf)
{
    QNSM_PORT_HANDLE *port_handle = qnsm_service_handle(EN_QNSM_SERVICE_PORT);
    struct rte_mbuf *tx_mbuf = NULL;

    if (0 < port_handle->n_dump_port) {
        tx_mbuf = qnsm_port_pktmbuf_copy(mbuf, port_handle->port_dump.pool);
        if (tx_mbuf) {
            return port_handle->port_dump.ops.f_tx(port_handle->port_dump.h_port, tx_mbuf);
        }
    }
    return 0;
}

int32_t qnsm_port_tx_lb(uint32_t pos, struct rte_mbuf *mbuf)
{

    QNSM_PORT_HANDLE *port_handle = qnsm_service_handle(EN_QNSM_SERVICE_PORT);
    uint16_t port_id = 0;
    QNSM_PORT_OUT *port_out = NULL;
    struct rte_mbuf *tx_mbuf = NULL;

    /*no tx port just free pkt/mbuf*/
    if (0 == port_handle->tx_port_cnt) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }

    /*
    * if send failed, f_tx free mbuf, qnsm port not need care
    */
    tx_mbuf = mbuf;
#if 0
    if (likely(port_handle->n_tx_port_pow2)) {
        port_id = pos & (port_handle->tx_port_cnt - 1);
    } else {
        port_id = pos % (port_handle->tx_port_cnt);
    }
#else
    port_id = port_handle->reta[pos & ((uint8_t)(QNSM_PORT_RETA_SIZE - 1))];
    QNSM_ASSERT(port_id < port_handle->tx_port_cnt);
#endif
    port_out = &port_handle->port_out[port_id];

#if 0
    /*cross socket*/
    if (NULL != port_out->pool) {
        tx_mbuf = qnsm_port_pktmbuf_copy(mbuf, port_out->pool);
        rte_pktmbuf_free(mbuf);
        if (NULL == tx_mbuf) {
            QNSM_DEBUG(QNSM_DBG_M_PORT, QNSM_DBG_EVT, "cpy pkt failed\n");
            return 0;
        }
    }
#endif

    return port_out->ops.f_tx(port_out->h_port, tx_mbuf);
}

int32_t qnsm_port_tx_flush(void *hdl)
{
    QNSM_PORT_HANDLE *port_handle = hdl;
    uint16_t index = 0;
    QNSM_PORT_OUT *port_out = NULL;
    int32_t ret = 0;

    for (index = 0; index < port_handle->tx_port_cnt; index++) {
        port_out = &port_handle->port_out[index];
        ret |= port_out->ops.f_flush(port_out->h_port);
    }

    for (index = 0; index < port_handle->n_dup_port; index++) {
        port_out = &port_handle->port_dup_tx[index];
        ret |= port_out->ops.f_flush(port_out->h_port);
    }

    if (port_handle->n_dump_port) {
        port_out = &port_handle->port_dump;
        ret |= port_out->ops.f_flush(port_out->h_port);
    }

#ifdef RTE_LIBRTE_KNI
    for (index = 0; index < port_handle->n_kni_port; index++) {
        port_out = &port_handle->port_kni_tx[index];
        ret |= port_out->ops.f_flush(port_out->h_port);
    }
#endif

    for (index = 0; index < port_handle->n_tap_port; index++) {
        port_out = &port_handle->port_tap_tx[index];
        ret |= port_out->ops.f_flush(port_out->h_port);
    }

    return ret;
}

inline int32_t qnsm_port_rx(void *hdl, uint16_t port_id, struct rte_mbuf **mbuf)
{
    QNSM_PORT_HANDLE *port_handle = hdl;
    int32_t nb_pkts;
    QNSM_PORT_IN *port_in = NULL;

    port_in = &port_handle->port_in[port_id];
    nb_pkts = port_in->ops.f_rx(port_in->h_port, mbuf, port_in->burst_size);
    return nb_pkts;
}

inline uint16_t qnsm_rx_port_num(void *hdl)
{
    QNSM_PORT_HANDLE *port_handle = hdl;
    return port_handle->rx_port_cnt;
}

inline struct rte_mbuf **qnsm_port_mbuf_array(void *hdl)
{
    QNSM_PORT_HANDLE *port_handle = hdl;
    return port_handle->pkts;
}

void* qnsm_port_hdl(void)
{
    return qnsm_service_handle(EN_QNSM_SERVICE_PORT);
}

#if QNSM_PART("dbg fun")

int32_t qnsm_port_in_num(void *para)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    return port_handle->rx_port_cnt;
}

int32_t qnsm_port_out_num(void *para)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    return port_handle->tx_port_cnt;
}

int32_t qnsm_port_out_statis(void *para, void *out_stats, uint32_t port_index)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    QNSM_PORT_OUT *port_out = NULL;

    if ((0 == port_handle->tx_port_cnt)
        || (port_index >= port_handle->tx_port_cnt)) {
        return -1;
    }

    port_out = &port_handle->port_out[port_index];
    return port_out->ops.f_stats(port_out->h_port, out_stats, 0);
}

int32_t qnsm_port_dup_num(void *para)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    return port_handle->n_dup_port;
}

int32_t qnsm_port_dup_statis(void *para, void *out_stats, uint32_t port_index)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    QNSM_PORT_OUT *port_out = NULL;

    if ((0 == port_handle->n_dup_port)
        || (port_index >= port_handle->n_dup_port)) {
        return -1;
    }

    port_out = &port_handle->port_dup_tx[port_index];
    return port_out->ops.f_stats(port_out->h_port, out_stats, 0);
}

int32_t qnsm_port_dump_statis(void *para, void *out_stats)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    QNSM_PORT_OUT *port_out = NULL;

    if (1 != port_handle->n_dump_port) {
        return -1;
    }

    port_out = &port_handle->port_dump;
    return port_out->ops.f_stats(port_out->h_port, out_stats, 0);
}

int32_t qnsm_port_tap_num(void *para)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    return port_handle->n_tap_port;
}

int32_t qnsm_port_tap_statis(void *para, void *out_stats, uint32_t port_index)
{
    struct app_pipeline_params *params = para;
    QNSM_DATA *app_data = params->app_data;
    QNSM_PORT_HANDLE *port_handle = app_data->service_lib_handle[EN_QNSM_SERVICE_PORT];
    QNSM_PORT_OUT *port_out = NULL;

    if ((0 == port_handle->n_tap_port)
        || (port_index >= port_handle->n_tap_port)) {
        return -1;
    }

    port_out = &port_handle->port_tap_tx[port_index];
    return port_out->ops.f_stats(port_out->h_port, out_stats, 0);
}
#endif
