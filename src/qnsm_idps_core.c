#define _GNU_SOURCE

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "util-debug.h"
#include "util-checksum.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-host-info.h"
#include "runmodes.h"
#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"
#include "util-signal.h"

#ifdef _SYS_QUEUE_H_
#undef _SYS_QUEUE_H_
#endif
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mbuf.h>

#include "app.h"
#include "util.h"
#include "qnsm_dbg.h"
//#include "qnsm_service.h"
#include "qnsm_port_ex.h"
#include "qnsm_idps_lib_ex.h"
#include "qnsm_idps_core.h"

rte_spinlock_t idps_mod_lock;

#if QNSM_PART("tm")

#if QNSM_PART("func declare")
TmEcode QnsmTMReceiveInit(ThreadVars *tv, const void *initdata, void **data);
TmEcode QnsmTMReceiveLoop(ThreadVars *tv, void *data, void *slot);
TmEcode QnsmTMReceiveDeinit(ThreadVars *tv, void *data);
TmEcode QnsmTMDecodeInit(ThreadVars *tv, const void *initdata, void **data);
TmEcode QnsmTMDecodeDeinit(ThreadVars *tv, void *data);
TmEcode QnsmTMDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);
#endif

/**
 * \brief Registration Function for RecieveDpdk.
 * \todo Unit tests are needed for this module.
 */
static void* TmModuleReceiveQnsmRegister(void)
{
    rte_spinlock_lock(&idps_mod_lock);
    if (NULL == tmm_modules[TMM_RECEIVEDPDK].name) {
        tmm_modules[TMM_RECEIVEDPDK].name = "QnsmReceive";
        tmm_modules[TMM_RECEIVEDPDK].ThreadInit = QnsmTMReceiveInit;
        tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
        tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = QnsmTMReceiveLoop;
        tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
        tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = QnsmTMReceiveDeinit;
        tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
        tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
    }
    rte_spinlock_unlock(&idps_mod_lock);

    return &tmm_modules[TMM_RECEIVEDPDK];
}

/**
 * \brief Registration Function for DecodeDpdk.
 * \todo Unit tests are needed for this module.
 */
static void* TmModuleDecodeQnsmRegister(void)
{
    rte_spinlock_lock(&idps_mod_lock);
    if (NULL == tmm_modules[TMM_DECODEDPDK].name) {
        tmm_modules[TMM_DECODEDPDK].name = "QnsmDecode";
        tmm_modules[TMM_DECODEDPDK].ThreadInit = QnsmTMDecodeInit;
        tmm_modules[TMM_DECODEDPDK].Func = QnsmTMDecode;
        tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
        tmm_modules[TMM_DECODEDPDK].ThreadDeinit = QnsmTMDecodeDeinit;
        tmm_modules[TMM_DECODEDPDK].RegisterTests = NULL;
        tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
    }
    rte_spinlock_unlock(&idps_mod_lock);

    return &tmm_modules[TMM_DECODEDPDK];
}

static void QnsmTMReleasePacket(Packet *p)
{
    void *m = (struct rte_mbuf *) p->mbufPtr;

    assert(((struct rte_mbuf *)m)->pool);

#if 0
    /* Use this thread's context to free the packet. */
    if (DPDKINTEL_GENCFG.OpMode == IPS || DPDKINTEL_GENCFG.OpMode == BYPASS) {

        if (rte_eth_tx_burst(portId, 0, (struct rte_mbuf **)&m, 1) != 1) {
            //SCLogError(SC_ERR_DPDKINTEL_DPDKAPI, " Unable to TX via port %d for %p in OpMode %d",
            //portId, m, DPDKINTEL_GENCFG.OpMode);
            rte_pktmbuf_free(m);
        }

        PacketFreeOrRelease (p);
        return;
    }
#endif

    QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_PKT, "QnsmTMReleasePacket\n");
    rte_pktmbuf_free(m);
    PacketFreeOrRelease(p);

    return;
}

/**
 * \brief construct tm packet
 *
 * This function fills in our packet structure from DPDK.
 * From here the packets are picked up by the  DecodeDpdk thread.
 *
 * param
 * - h pointer to mbuf packet header
 *
 * return
 * - p pointer to the current packet
 */
static inline Packet *QnsmTMConstructPacket(struct rte_mbuf *m)
{
    int caplen = m->pkt_len;
    char *pkt = ((char *)m->buf_addr + m->data_off);

    /* ToDo: each mbuff has private memory area - phase 2
     *       We can store Packet information in the head room
     *       This will reduce the memory alloc or get for Packet
     */

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        //ptv->drops += ;
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to get Packet Buffer for DPDK mbuff!");
        return NULL;
    }

    SCLogDebug(" Suricata packet %p for bte %d", p, caplen);

    PACKET_RECYCLE(p);
    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->datalink = LINKTYPE_ETHERNET;
    gettimeofday(&p->ts, NULL);
    PacketSetData(p, (uint8_t *) pkt, caplen);

    /* mbuf ptr*/
    p->mbufPtr = (void *) m;

#if 0
    p->livedev = ptv->livedev;

    ptv->bytes += caplen;
    ptv->pkts++;
#endif

    p->ReleasePacket = QnsmTMReleasePacket;

    return p;
}

TmEcode QnsmTMReceiveInit(ThreadVars *tv, const void *initdata, void **data)
{
    QNSM_ASSERT(initdata);

    *data = (void *)initdata;
    SCLogNotice("thread %s rcv tm initdata %p", tv->name, initdata);
    return TM_ECODE_OK;
}


/**
 * \brief Recieves packets from an interface via qnsm.
 *
 *  This function recieves packets from an interface and passes to Decode thread.
 *
 * param
   - tv pointer to ThreadVars
 * - data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 * - slot slot containing task information
 * retval
   - TM_ECODE_OK on success
 * - TM_ECODE_FAILED on failure
 */
TmEcode QnsmTMReceiveLoop(ThreadVars *tv, void *data, void *slot)
{
    struct rte_mbuf **mbuf = NULL;
    uint16_t port_id = 0;
    uint16_t index = 0;
    int32_t nb_pkts = 0;
    Packet *p = NULL;
    TmSlot *s = (TmSlot *)slot;
    uint16_t rx_port_cnt = 0;

    rx_port_cnt = qnsm_rx_port_num(data);
    mbuf =  qnsm_port_mbuf_array(data);
    for (port_id = 0; port_id < rx_port_cnt; port_id++) {
        nb_pkts = qnsm_port_rx(data, port_id, mbuf);
        if (0 >= nb_pkts) {
            continue;
        }

        /* Prefetch first packets */
        for (index = 0; index < PREFETCH_OFFSET && index < nb_pkts; index++) {
            rte_prefetch0(rte_pktmbuf_mtod(
                              mbuf[index], void *));
        }

        for (index = 0; index < (nb_pkts - PREFETCH_OFFSET); index++) {
            rte_prefetch0(rte_pktmbuf_mtod(mbuf[index + PREFETCH_OFFSET],
                                           void *));

            p = QnsmTMConstructPacket(mbuf[index]);
            if (NULL == p) {
                QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_ERR, "failed to construct pkt\n");
                rte_pktmbuf_free(mbuf[index]);
                continue;
            }

            SCLogDebug("Acquired Suricata Pkt %p", p);
            SCLogDebug(" mbuff %p len %u offset %u ", mbuf[index], mbuf[index]->pkt_len, mbuf[index]->data_off);

            SET_PKT_LEN(p, mbuf[index]->pkt_len);

            if (unlikely(TmThreadsSlotProcessPkt(tv, s->slot_next, p) != TM_ECODE_OK)) {
                TmqhOutputPacketpool(tv, p);
                rte_pktmbuf_free(mbuf[index]);

                QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_ERR, "thread slot process pkt failed\n");
                continue;
            }
        }

        /* Process left packets */
        for (; index < nb_pkts; index++) {
            p = QnsmTMConstructPacket(mbuf[index]);
            if (NULL == p) {
                QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_ERR, "failed to construct pkt\n");
                rte_pktmbuf_free(mbuf[index]);
                continue;
            }

            SCLogDebug("Acquired Suricata Pkt %p", p);
            SCLogDebug(" mbuff %p len %u offset %u ", mbuf[index], mbuf[index]->pkt_len, mbuf[index]->data_off);

            SET_PKT_LEN(p, mbuf[index]->pkt_len);

            if (unlikely(TmThreadsSlotProcessPkt(tv, s->slot_next, p) != TM_ECODE_OK)) {
                TmqhOutputPacketpool(tv, p);
                rte_pktmbuf_free(mbuf[index]);
                QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_ERR, "thread slot process pkt failed\n");
                continue;
            }
        }
    }
    StatsSyncCountersIfSignalled(tv);

    return TM_ECODE_OK;
}

static void QnsmReceiveTMThreadExitStats(ThreadVars *tv, void *data)
{
    /*
    *TODO
    *1. dump pmd drv stats
    *2. per tm stats
    */
    return;
}


/**
 * \brief DeInit function closes pd at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DpdkIntelThreadVars_t for ptvi
 * \retval TM_ECODE_OK is always returned
 */
TmEcode QnsmTMReceiveDeinit(ThreadVars *tv, void *data)
{
#if 0
    if (NULL != data)
        SCFree(data);
#endif

    return TM_ECODE_OK;
}


/**
 * \brief This an Init function for DecodeDpdk
 *
 * \param
   - tv pointer to ThreadVars
 * - initdata pointer to initilization data.
 * - data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 * \retval
   - TM_ECODE_OK is returned on success
 * - TM_ECODE_FAILED is returned on error
 */
TmEcode QnsmTMDecodeInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
    return TM_ECODE_OK;
}

TmEcode QnsmTMDecodeDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}


/**
 * \brief This function passes off to link type decoders.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into DpdkIntelThreadVars_t for ptv
 * \param pq pointer to the current PacketQueue
 *
 * \todo Verify that PF_RING only deals with ethernet traffic
 *
 * \warning This function bypasses the pkt buf and len macro's
 *
 * \retval TM_ECODE_OK is always returned
 */
TmEcode QnsmTMDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;
    struct rte_mbuf *dptr = (struct rte_mbuf *)p->mbufPtr;

    SCLogDebug(" DecodeDpdk mbuff %p len %d plen %d",
               dptr, dptr->pkt_len, GET_PKT_LEN(p));

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    StatsIncr(tv, dtv->counter_pkts);
    StatsAddUI64(tv, dtv->counter_bytes, GET_PKT_LEN(p));
    StatsAddUI64(tv, dtv->counter_avg_pkt_size, GET_PKT_LEN(p));
    StatsSetUI64(tv, dtv->counter_max_pkt_size, GET_PKT_LEN(p));

    /* If suri has set vlan during reading, we increase vlan counter */
    if (p->vlan_idx) {
        StatsIncr(tv, dtv->counter_vlan);
    }

    DecodeEthernet(tv, dtv, p, ((uint8_t *)dptr->buf_addr + dptr->data_off), dptr->pkt_len, pq);

    //TODO: check return code of DecodeEthernet and release mbuf for failures.
    PacketDecodeFinalize(tv, dtv, p);

    return TM_ECODE_OK;
}

#endif

/**
 * \brief Creates and returns a TV instance for a Packet Processing Thread.
 *        This function doesn't support custom slots, and hence shouldn't be
 *        supplied \"custom\" as its slot type.  All PPT threads are created
 *        with a mucond(see TmThreadCreate declaration) of 0. Hence the tv
 *        conditional variables are not used to kill the thread.
 *
 * \param name       Name of this TV instance
 * \param inq_name   Incoming queue name
 * \param inqh_name  Incoming queue handler name as set by TmqhSetup()
 * \param outq_name  Outgoing queue name
 * \param outqh_name Outgoing queue handler as set by TmqhSetup()
 * \param slots      String representation for the slot function to be used
 *
 * \retval the newly created TV instance, or NULL on error
 */
static ThreadVars *QnsmTmThreadCreatePacketHandler(const char *name, const char *inq_name,
        const char *inqh_name, const char *outq_name,
        const char *outqh_name, void *(fn_p)(void *))
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, inq_name, inqh_name, outq_name, outqh_name,
                        "custom", fn_p, 0);

    if (tv != NULL) {
        tv->type = TVT_PPT;
        tv->id = TmThreadsRegisterThread(tv, tv->type);

        /*init id*/
        tv->t = pthread_self();
    }


    return tv;
}


/** \internal
 *
 *  \brief Process flow timeout packets
 *
 *  Process flow timeout pseudo packets. During shutdown this loop
 *  is run until the flow engine kills the thread and the queue is
 *  empty.
 */
static int QnsmTmThreadTimeoutLoop(ThreadVars *tv, TmSlot *s)
{
    TmSlot *stream_slot = NULL, *slot = NULL;
    int run = 1;
    int r = TM_ECODE_OK;

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->tm_id == TMM_FLOWWORKER) {
            stream_slot = slot;
            break;
        }
    }

    if (tv->stream_pq == NULL || stream_slot == NULL) {
        SCLogDebug("not running TmThreadTimeoutLoop %p/%p", tv->stream_pq, stream_slot);
        return r;
    }

    SCLogDebug("flow end loop starting");
    while(run) {
        Packet *p;
        if (tv->stream_pq->len != 0) {
            SCMutexLock(&tv->stream_pq->mutex_q);
            p = PacketDequeue(tv->stream_pq);
            SCMutexUnlock(&tv->stream_pq->mutex_q);
            BUG_ON(p == NULL);

            if ((r = TmThreadsSlotProcessPkt(tv, stream_slot, p) != TM_ECODE_OK)) {
                if (r == TM_ECODE_FAILED)
                    run = 0;
            }
        } else {
            usleep(1);
        }

        if (tv->stream_pq->len == 0 && TmThreadsCheckFlag(tv, THV_KILL)) {
            run = 0;
        }
    }
    SCLogDebug("flow end loop complete");

    return r;
}


/*

    pcap/nfq

    pkt read
        callback
            process_pkt

    pfring

    pkt read
        process_pkt

    slot:
        setup

        pkt_ack_loop(tv, slot_data)

        deinit

    process_pkt:
        while(s)
            run s;
        queue;

 */
static void *QnsmTmThreadsSlotPktAcqLoop(void *td)
{
    /* block usr2.  usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *tv = (ThreadVars *)td;
    char run = 1;
    TmEcode r = TM_ECODE_OK;
    TmSlot *s = tv->tm_slots;
    TmSlot *slot = NULL;

    SCLogNotice("ips %s run tv %p pctx %p", tv->name, tv, &tv->perf_public_ctx);
    TmThreadsUnsetFlag(tv, THV_PAUSE);
    while(run) {
        if (TmThreadsCheckFlag(tv, THV_PAUSE)) {
            TmThreadsSetFlag(tv, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv);
            TmThreadsUnsetFlag(tv, THV_PAUSED);
        }

        r = s->PktAcqLoop(tv, SC_ATOMIC_GET(s->slot_data), s);

        if (r == TM_ECODE_FAILED) {
            TmThreadsSetFlag(tv, THV_FAILED);
            run = 0;
        }
        if (TmThreadsCheckFlag(tv, THV_KILL_PKTACQ) || suricata_ctl_flags) {
            QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_EVT, "usr stop ips engine %s\n", tv->name);
            run = 0;
        }
        if (r == TM_ECODE_DONE) {
            run = 0;
        }
    }
    StatsSyncCounters(tv);

    QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_EVT, "%s set flag THV_FLOW_LOOP\n", tv->name);
    TmThreadsSetFlag(tv, THV_FLOW_LOOP);

    /* process all pseudo packets the flow timeout may throw at us */
    QnsmTmThreadTimeoutLoop(tv, s);

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    PacketPoolDestroy();

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadExitPrintStats != NULL) {
            slot->SlotThreadExitPrintStats(tv, SC_ATOMIC_GET(slot->slot_data));
        }

        if (slot->SlotThreadDeinit != NULL) {
            r = slot->SlotThreadDeinit(tv, SC_ATOMIC_GET(slot->slot_data));
            if (r != TM_ECODE_OK) {
                TmThreadsSetFlag(tv, THV_CLOSED);
                goto error;
            }
        }

        BUG_ON(slot->slot_pre_pq.len);
        BUG_ON(slot->slot_post_pq.len);
    }

    tv->stream_pq = NULL;
    QNSM_DEBUG(QNSM_DBG_M_DPI_IPS, QNSM_DBG_EVT, "%s ending\n", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;

error:
    tv->stream_pq = NULL;
    pthread_exit((void *) -1);
    return NULL;
}

void *QnsmTmThreadsInit(const char* mode, const char *recv_mod_name, const char *decode_mod_name)
{
    ThreadVars *tv = NULL;
    char tname[TM_THREAD_NAME_MAX];
    TmModule *tm_module = NULL;
    TmSlot *s = NULL;
    TmSlot *slot = NULL;
    TmEcode r = TM_ECODE_OK;
    const void *rcv_mod_initdata = qnsm_port_hdl();

    /*create pkt hdl*/
    snprintf(tname, sizeof(tname), "%s#%u", mode, rte_lcore_id());
    tv = QnsmTmThreadCreatePacketHandler(tname,
                                         "packetpool", "packetpool",
                                         "packetpool", "packetpool",
                                         QnsmTmThreadsSlotPktAcqLoop);
    if (tv == NULL) {
        SCLogError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
        exit(EXIT_FAILURE);
    }
    SCLogNotice("init begin ips engine %s tv %p pctx %p", tv->name, tv, &tv->perf_public_ctx);

    /*construct thread module list*/
#if 0
    tm_module = TmModuleGetByName(recv_mod_name);
    if (tm_module == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
        exit(EXIT_FAILURE);
    }
#else
    tm_module = TmModuleReceiveQnsmRegister();
#endif
    TmSlotSetFuncAppend(tv, tm_module, rcv_mod_initdata);

#if 0
    tm_module = TmModuleGetByName(decode_mod_name);
    if (tm_module == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "TmModuleGetByName %s failed", decode_mod_name);
        exit(EXIT_FAILURE);
    }
#else
    tm_module = TmModuleDecodeQnsmRegister();
#endif
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_RUNMODE, "TmModuleGetByName RespondReject failed");
        exit(EXIT_FAILURE);
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    /* Set the thread name */
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    PacketPoolInit();

    /* check if we are setup properly */
    s = tv->tm_slots;
    if (s == NULL || s->PktAcqLoop == NULL || tv->tmqh_in == NULL || tv->tmqh_out == NULL) {
        SCLogError(SC_ERR_FATAL, "TmSlot or ThreadVars badly setup: s=%p,"
                   " PktAcqLoop=%p, tmqh_in=%p,"
                   " tmqh_out=%p",
                   s, s ? s->PktAcqLoop : NULL, tv->tmqh_in, tv->tmqh_out);
        TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
        pthread_exit((void *) -1);
        return NULL;
    }

    /*init thread modules*/
    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadInit != NULL) {
            void *slot_data = NULL;
            r = slot->SlotThreadInit(tv, slot->slot_initdata, &slot_data);
            if (r != TM_ECODE_OK) {
                if (r == TM_ECODE_DONE) {
                    EngineDone();
                    TmThreadsSetFlag(tv, THV_CLOSED | THV_INIT_DONE | THV_RUNNING_DONE);
                    goto error;
                } else {
                    TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                    goto error;
                }
            }
            (void)SC_ATOMIC_SET(slot->slot_data, slot_data);
        }
        memset(&slot->slot_pre_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&slot->slot_pre_pq.mutex_q, NULL);
        memset(&slot->slot_post_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&slot->slot_post_pq.mutex_q, NULL);

        /* get the 'pre qeueue' from module before the stream module */
        if (slot->slot_next != NULL && (slot->slot_next->tm_id == TMM_FLOWWORKER)) {
            SCLogDebug("pre-stream packetqueue %p (postq)", &s->slot_post_pq);
            tv->stream_pq = &slot->slot_post_pq;
            /* if the stream module is the first, get the threads input queue */
        } else if (slot == (TmSlot *)tv->tm_slots && (slot->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = &trans_q[tv->inq->id];
            SCLogDebug("pre-stream packetqueue %p (inq)", &slot->slot_pre_pq);
        }
    }

    StatsSetupPrivate(tv);

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    TmThreadAppend(tv, tv->type);
    SCLogNotice("init end ips engine %s tv %p pctx %p", tv->name, tv, &tv->perf_public_ctx);
    return tv;

error:
    tv->stream_pq = NULL;
    pthread_exit((void *) -1);
    return NULL;
}

void QnsmTMThreadsRun(void *var)
{
    ThreadVars *tv = (ThreadVars *)var;

    tv->tm_func(tv);
    return;
}
