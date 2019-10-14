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
#include <signal.h>

#include <errno.h>
#include <librdkafka/rdkafka.h>

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
#include <rte_timer.h>

#include "cJSON.h"
#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_service.h"

#include "qnsm_cfg.h"
#include "app.h"
#include "qnsm_kafka_ex.h"
#include "qnsm_kafka.h"

struct qnsm_topic {
    uint32_t kafka_id;
    uint32_t topic_id;
    const char *topic_name;
};

static struct qnsm_topic qnsm_topics[] = {
#define QNSM_KAFKA_TOPIC_GEN(k, t, name, s) {k, t, s },
    QNSM_KAFKA_TOPIC_MAP(QNSM_KAFKA_TOPIC_GEN)
#undef QNSM_KAFKA_TOPIC_GEN
};

#if QNSM_PART("karfka")

const char *qnsm_kafka_topic_name(EN_QNSM_KAFKA_TOPIC topic)
{
    uint16_t index = 0;

    for (index = 0; index < sizeof(qnsm_topics)/sizeof(struct qnsm_topic); index++) {
        if ((uint32_t)QNSM_KAFKA_TOPIC(qnsm_topics[index].kafka_id, qnsm_topics[index].topic_id) == topic) {
            return qnsm_topics[index].topic_name;
        }
    }

    return NULL;
}

QNSM_KAFKA_TOPIC_PART_STATIS *qnsm_kafka_get_statis(void *para, EN_QNSM_KAFKA_TOPIC topic, uint16_t *part_num)
{
    QNSM_KAFKA_DATA *kafka_handle = qnsm_cmd_service_handle(para, EN_QNSM_SERVICE_KAFKA);
    uint16_t kafka_id = QNSM_KAFKA_KAFKA_ID(topic);
    uint16_t topic_id = QNSM_KAFKA_TOPIC_ID(topic);
    QNSM_KAFKA *qnsm_kafka = NULL;

    if (NULL == kafka_handle) {
        return NULL;
    }

    if ((QNSM_KAFKA_MAX_TOPIC_ID <= topic_id)
        || (QNSM_MAX_KAFKA <= kafka_id)) {
        return NULL;
    }

    qnsm_kafka = (kafka_handle->kafka) + kafka_id;
    *part_num = qnsm_kafka->partitions[topic_id];
    return qnsm_kafka->statis[topic_id];
}


void qnsm_kafka_batch_tx_init(EN_QNSM_KAFKA_TOPIC topic, const char *batch_metric, uint16_t batch_cnt)
{
    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    uint16_t kafka_id = QNSM_KAFKA_KAFKA_ID(topic);
    uint16_t topic_id = QNSM_KAFKA_TOPIC_ID(topic);
    QNSM_KAFKA *qnsm_kafka = NULL;

    if ((QNSM_KAFKA_MAX_TOPIC_ID <= topic_id)
        || (QNSM_MAX_KAFKA <= kafka_id)
        || (NULL == batch_metric)) {
        QNSM_ASSERT(0);
        return;
    }
    QNSM_ASSERT(batch_cnt <= QNSM_KAFKA_BATCH_MSGS);

    qnsm_kafka = (kafka_handle->kafka) + kafka_id;

    /*malloc batch buf*/
    if (NULL == qnsm_kafka->batch_buf) {
        qnsm_kafka->batch_buf = rte_zmalloc("QNSM_KAFKA", sizeof(QNSM_KAFKA_BATCH_BUF), QNSM_DDOS_MEM_ALIGN);
        QNSM_ASSERT(qnsm_kafka->batch_buf);
    }
    memset(qnsm_kafka->batch_buf, sizeof(QNSM_KAFKA_BATCH_BUF), 0);

    /*set per metric batch cnt*/
    qnsm_kafka->batch_cnt[topic_id] = batch_cnt;
    qnsm_kafka->batch_metric[topic_id] = batch_metric;
    return;
}

#if QNSM_PART("private")
static void __qnsm_kafka_send_msg(void *kafka_instance, uint16_t topic_id, char *buf, int len, uint16_t partition)
{
    QNSM_KAFKA_TOPIC_PART_STATIS *topic_part_statis = NULL;
    QNSM_KAFKA *qnsm_kafka = NULL;

    qnsm_kafka = kafka_instance;
    if (QNSM_KAFKA_MAX_TOPIC_ID <= topic_id) {
        QNSM_ASSERT(0);
        return;
    }

    if (0 == qnsm_kafka->enable[topic_id]) {
        return;
    }

    topic_part_statis = qnsm_kafka->statis[topic_id];
    if (rd_kafka_produce(qnsm_kafka->rkt[topic_id], partition,
                         RD_KAFKA_MSG_F_COPY,
                         /* Payload and length */
                         buf, len,
                         /* Optional key and its length */
                         NULL, 0,
                         /* Message opaque, provided in
                          * delivery report callback as
                          * msg_opaque. */
                         NULL) == -1) {
        topic_part_statis[partition].tx_drop_statis++;
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR,
                   "%% Failed to produce to topic %s "
                   "partition %i: %s\n",
                   rd_kafka_topic_name(qnsm_kafka->rkt[topic_id]), partition,
                   rd_kafka_err2str(
                       rd_kafka_errno2err(errno)));
        /* Poll to handle delivery reports */
        rd_kafka_poll(qnsm_kafka->rk, 0);
    }

    /*kafka statis*/
    topic_part_statis[partition].tx_statis++;
    return;
}

static void __qnsm_kafka_send_json_msg(void *qnsm_kafka, uint16_t topic_id, const char *batch_metric, uint16_t part_id, QNSM_KAFKA_BATCH_TX *batch_tx)
{
    cJSON *root = NULL;
    cJSON *js_data = NULL;
    cJSON *tmp_obj = NULL;
    char *s = NULL;
    uint16_t index = 0;

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "metric", batch_metric);
    cJSON_AddItemToObject(root, "data", js_data = cJSON_CreateArray());
    for (index = 0; index < batch_tx->tx_cnt; index++) {
        tmp_obj = (cJSON *)batch_tx->msg[index].obj;
        if (tmp_obj) {
            cJSON_AddItemToArray(js_data, tmp_obj);
        }
    }

    /*send json format msg*/
#ifndef __json_format
    s = cJSON_PrintUnformatted(root);
#else
    s = cJSON_Print(root);
#endif
    if (s) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "topic %u %s\n", topic_id, s);
        __qnsm_kafka_send_msg(qnsm_kafka, topic_id, s, strlen(s) + 1, part_id);
        cJSON_free_fun(s);
    }

    /*free resources*/
    cJSON_Delete(root);

    return;
}

static void msg_delivered (rd_kafka_t *rk,
                           void *payload, size_t len,
                           int error_code,
                           void *opaque, void *msg_opaque)
{
    rk = rk;
    payload = payload;
    len = len;
    opaque = opaque;
    msg_opaque = msg_opaque;
    if (error_code)
        fprintf(stderr, "%% Message delivery failed: %s\n",
                rd_kafka_err2str(error_code));
}

#endif

void qnsm_kafka_send_msg(EN_QNSM_KAFKA_TOPIC topic, void *obj, uint16_t partition)
{
    QNSM_KAFKA_BATCH_BUF *batch_buf = NULL;
    uint16_t part_id = 0;
    QNSM_KAFKA_BATCH_TX *batch_tx = NULL;
    uint16_t kafka_id = QNSM_KAFKA_KAFKA_ID(topic);
    uint16_t topic_id = QNSM_KAFKA_TOPIC_ID(topic);
    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    QNSM_KAFKA *qnsm_kafka = NULL;

    QNSM_ASSERT(QNSM_MAX_KAFKA >= kafka_id);
    QNSM_ASSERT(QNSM_KAFKA_MAX_TOPIC_ID >= topic_id);

    qnsm_kafka = (kafka_handle->kafka) + kafka_id;
    QNSM_ASSERT(1 <= qnsm_kafka->partitions[topic_id]);

    part_id = (partition & 0xFF) ^ ((partition >> 8) & 0xFF);
    part_id = part_id % (qnsm_kafka->partitions[topic_id]);

    if ((0 < qnsm_kafka->batch_cnt[topic_id]) && (batch_buf = qnsm_kafka->batch_buf)) {
        /*now just agg topic batch( > 1) send*/
        batch_tx = &batch_buf->batch_tx[topic_id][part_id];
        batch_tx->msg[batch_tx->tx_cnt].obj = obj;
        batch_tx->tx_cnt++;

        if (batch_tx->tx_cnt >= qnsm_kafka->batch_cnt[topic_id]) {
            __qnsm_kafka_send_json_msg(qnsm_kafka, topic_id, qnsm_kafka->batch_metric[topic_id], part_id, batch_tx);

            /*rst tx cnt*/
            batch_tx->tx_cnt = 0;
        }
    } else {
        char *s = NULL;

#ifndef __json_format
        s = cJSON_PrintUnformatted(obj);
#else
        s = cJSON_Print(obj);
#endif
        if (s) {
            QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "%s\n", s);
            __qnsm_kafka_send_msg(qnsm_kafka, topic_id, s, strlen(s) + 1, part_id);
            cJSON_free_fun(s);
        }
    }

    return;
}

static inline uint16_t qnsm_kafka_get_topic(const char *name)
{
    uint16_t index = 0;

    if (NULL == name) {
        return  QNSM_KAFKA_MAX_TOPIC_ID;
    }
    for (index = 0; index < sizeof(qnsm_topics)/sizeof(struct qnsm_topic); index++) {
        if (strcasestr(name, qnsm_topics[index].topic_name)) {
            return qnsm_topics[index].topic_id;
        }
    }
    return QNSM_KAFKA_MAX_TOPIC_ID;
}

static void qnsm_kafka_flush_timer(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
    QNSM_KAFKA_DATA *kafka_handle = arg;
    QNSM_KAFKA *qnsm_kafka = NULL;
    QNSM_KAFKA_BATCH_BUF *batch_buf = NULL;
    QNSM_KAFKA_BATCH_TX *batch_tx = NULL;
    uint8_t index = 0;
    uint8_t topic_id = 0;
    uint16_t part_id = 0;

    for (; index < QNSM_MAX_KAFKA; index++) {
        qnsm_kafka = kafka_handle->kafka + index;
        if (NULL == qnsm_kafka->rk) {
            continue;
        }

        batch_buf = qnsm_kafka->batch_buf;
        if (NULL == batch_buf) {
            continue;
        }

        for (topic_id = 0; topic_id < QNSM_KAFKA_MAX_TOPIC_ID; topic_id++) {
            if (0 == qnsm_kafka->batch_cnt[topic_id]) {
                continue;
            }

            for (part_id = 0; part_id < qnsm_kafka->partitions[topic_id]; part_id++) {
                batch_tx = &batch_buf->batch_tx[topic_id][part_id];
                if (batch_tx->tx_cnt > 0) {
                    __qnsm_kafka_send_json_msg(qnsm_kafka, topic_id, qnsm_kafka->batch_metric[topic_id], part_id, batch_tx);
                    batch_tx->tx_cnt = 0;
                }
            }
        }
    }

    return;
}

int32_t qnsm_kafka_app_init_producer(void *cfg)
{
    char tmp[16];
    char errstr[512];
    uint32_t broker_index = 0;
    uint32_t broker_num = 0;
    char *brokers = NULL;
    QNSM_KAFKA_BROKER *broker_list = NULL;
    uint32_t broker_len = 0;
    uint32_t len = 0;
    rd_kafka_conf_t *conf;
    rd_kafka_topic_conf_t *topic_conf;
    char *topic = NULL;
    uint32_t topic_index = 0;
    uint16_t kafka_topic;

    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    QNSM_KAFKA *qnsm_kafka = kafka_handle->kafka;
    uint16_t index = 0;
    int32_t ret = 0;
    QNSM_KAFKA_CFG *kafka_cfg = cfg;
    static const char *kafka_inst[] = {
#define XX(num, name, string) string,
        QNSM_KAFKA_MAP(XX)
#undef XX
    };

    SET_LIB_COMMON_STATE(kafka_handle, en_lib_state_load);
    rte_timer_init(&kafka_handle->flush_timer);
    ret = rte_timer_reset(&kafka_handle->flush_timer,
                          rte_get_timer_hz(), PERIODICAL,
                          rte_lcore_id(), qnsm_kafka_flush_timer, kafka_handle);
    if (ret < 0) {
        fprintf(stderr, "lcore %d Cannot set kafka flush timer\n", rte_lcore_id());
        return -1;
    }

    /*here, why use lock, forget..*/
    rte_spinlock_lock(&kafka_handle->lock);

    for (index = 0; index < QNSM_MAX_KAFKA; index++) {
        if (!strncmp(kafka_inst[index], kafka_cfg->kafka_name, strlen(kafka_cfg->kafka_name))) {
            break;
        }
    }
    if (QNSM_MAX_KAFKA == index) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed\n");
        ret = -1;
        goto EXIT;
    }

    qnsm_kafka += index;
    if (strlen(qnsm_kafka->kafka_name) != 0) {
        ret = 0;
        goto EXIT;
    }
    strncpy(qnsm_kafka->kafka_name, (const char*)kafka_cfg->kafka_name, strlen(kafka_cfg->kafka_name));

    /*broker init*/
    broker_list= kafka_cfg->borkers;
    broker_num = kafka_cfg->broker_num;
    brokers = (char *)rte_zmalloc("KAFKA", broker_num * QNSM_KAFKA_MAX_BROKER_ADDR_LEN, QNSM_DDOS_MEM_ALIGN);
    if (NULL == brokers) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed\n");
        ret = -1;
        goto EXIT;
    }
    broker_index = 0;
    len = 0;
    while (broker_index < broker_num) {
        //brokers += broker_index * QNSM_KAFKA_BROKER_ADDR;
        broker_len = strlen(broker_list[broker_index].broker);
        strncpy(brokers + len, (const char*)broker_list[broker_index].broker, broker_len);
        len += broker_len;
        brokers[len++] = ',';
        broker_index++;
    }
    brokers[len - 1] = '\0';
    qnsm_kafka->brokers = brokers;
    QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_INFO, "broker is %s\n", brokers);

    conf = rd_kafka_conf_new();
    snprintf(tmp, sizeof(tmp), "%i", SIGIO);

    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf, "internal.termination.signal", tmp, errstr, sizeof(errstr))) {
        printf("%s\n", errstr);
    }
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf, "broker.version.fallback", "0.8.2", errstr, sizeof(errstr))) {
        printf("%s\n", errstr);
    }
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf, "queue.buffering.max.messages", "500000",
            errstr, sizeof(errstr))) {
        printf("%s\n", errstr);
    }

    rd_kafka_conf_set_dr_cb(conf, msg_delivered);
    if (!(qnsm_kafka->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr)))) {
        fprintf(stderr, "%% Failed to create new producer: %s\n", errstr);
        ret = -1;
        goto EXIT;
    }

    if (rd_kafka_brokers_add(qnsm_kafka->rk, brokers) == 0) {
        fprintf(stderr, "%% No valid brokers specified\n");
        ret = -1;
        goto EXIT;
    }

    /*topic init*/
    for (topic_index = 0; topic_index < kafka_cfg->topic_num; topic_index++) {
        topic = kafka_cfg->topics[topic_index].topic_name;
        topic_conf = rd_kafka_topic_conf_new();
        kafka_topic = qnsm_kafka_get_topic(topic);
        if (QNSM_KAFKA_MAX_TOPIC_ID > kafka_topic) {
            QNSM_ASSERT(QNSM_KAFKA_PARTITION_MAX_NUM >= kafka_cfg->topics[topic_index].partitions);
            qnsm_kafka->partitions[kafka_topic] = kafka_cfg->topics[topic_index].partitions;
            qnsm_kafka->rkt[kafka_topic] = rd_kafka_topic_new(qnsm_kafka->rk, topic, topic_conf);
            qnsm_kafka->enable[kafka_topic] = kafka_cfg->topics[topic_index].enable;

            qnsm_kafka->statis[kafka_topic] = rte_zmalloc("KAFKA_STATIS",
                                              sizeof(QNSM_KAFKA_TOPIC_PART_STATIS) * qnsm_kafka->partitions[kafka_topic],
                                              QNSM_DDOS_MEM_ALIGN);
            if (NULL == qnsm_kafka->statis[kafka_topic]) {
                QNSM_ASSERT(0);
            }
        } else {
            QNSM_ASSERT(0);
        }
    }

EXIT:
    rte_spinlock_unlock(&kafka_handle->lock);
    return ret;
}

static void print_partition_list (FILE *fp __attribute__((unused)),
                                  const rd_kafka_topic_partition_list_t
                                  *partitions)
{
    int i;
    for (i = 0 ; i < partitions->cnt ; i++) {
        fprintf(stderr, "%s %s [%"PRId32"] offset %"PRId64,
                i > 0 ? ",":"",
                partitions->elems[i].topic,
                partitions->elems[i].partition,
                partitions->elems[i].offset);
    }
    fprintf(stderr, "\n");

}

static void rebalance_cb (rd_kafka_t *rk,
                          rd_kafka_resp_err_t err,
                          rd_kafka_topic_partition_list_t *partitions,
                          void *opaque __attribute__((unused)))
{

    fprintf(stderr, "%% Consumer group rebalanced: ");

    switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
            fprintf(stderr, "assigned:\n");
            print_partition_list(stderr, partitions);
            rd_kafka_assign(rk, partitions);
            //wait_eof += partitions->cnt;
            break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
            fprintf(stderr, "revoked:\n");
            print_partition_list(stderr, partitions);
            rd_kafka_assign(rk, NULL);
            //wait_eof = 0;
            break;

        default:
            fprintf(stderr, "failed: %s\n",
                    rd_kafka_err2str(err));
            rd_kafka_assign(rk, NULL);
            break;
    }
}

int32_t qnsm_kafka_app_init_consumer(const char *dc_name, void *cfg)
{
    char tmp[16];
    rd_kafka_conf_t *conf;
    rd_kafka_topic_conf_t *topic_conf;
    rd_kafka_topic_partition_list_t *topic_list;
    char errstr[512];
    char group[128];
    int32_t ret = 0;

    uint32_t broker_index = 0;
    uint32_t broker_num = 0;
    uint32_t broker_len = 0;
    uint32_t len = 0;
    char *brokers = NULL;
    QNSM_KAFKA_BROKER *broker_list = NULL;
    uint16_t index = 0;
    QNSM_KAFKA_CFG *kafka_cfg = cfg;
    static const char *kafka_inst[] = {
#define XX(num, name, string) string,
        QNSM_KAFKA_MAP(XX)
#undef XX
    };
    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    QNSM_KAFKA *qnsm_kafka = kafka_handle->kafka;

    SET_LIB_COMMON_STATE(kafka_handle, en_lib_state_load);
    rte_spinlock_lock(&kafka_handle->lock);

    for (index = 0; index < QNSM_MAX_KAFKA; index++) {
        if (!strncmp(kafka_inst[index], kafka_cfg->kafka_name, strlen(kafka_cfg->kafka_name))) {
            break;
        }
    }
    if (QNSM_MAX_KAFKA == index) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed\n");
        ret = -1;
        goto EXIT;
    }

    qnsm_kafka += index;
    if (strlen(qnsm_kafka->kafka_name) != 0) {
        ret = 0;
        goto EXIT;
    }
    strncpy(qnsm_kafka->kafka_name, (const char*)kafka_cfg->kafka_name, strlen(kafka_cfg->kafka_name));

    /*broker init*/
    broker_list= kafka_cfg->borkers;
    broker_num = kafka_cfg->broker_num;
    brokers = (char *)rte_zmalloc("KAFKA", broker_num * QNSM_KAFKA_MAX_BROKER_ADDR_LEN, QNSM_DDOS_MEM_ALIGN);
    if (NULL == brokers) {
        QNSM_DEBUG(QNSM_DBG_M_CFG, QNSM_DBG_ERR, "failed\n");
        ret = -1;
        goto EXIT;
    }
    broker_index = 0;
    len = 0;
    while (broker_index < broker_num) {
        //brokers += broker_index * QNSM_KAFKA_BROKER_ADDR;
        broker_len = strlen(broker_list[broker_index].broker);
        strncpy(brokers + len, (const char*)broker_list[broker_index].broker, broker_len);
        len += broker_len;
        brokers[len++] = ',';
        broker_index++;
    }
    brokers[len - 1] = '\0';
    qnsm_kafka->brokers = brokers;

    /* Kafka configuration */
    conf = rd_kafka_conf_new();

    /* Topic configuration */
    topic_conf = rd_kafka_topic_conf_new();

    /* Quick termination */
    snprintf(tmp, sizeof(tmp), "%i", SIGIO);
    rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);

    /*
    *set group id
    *use pid consumer group id + instance id as group id
    */
    struct app_params *app = qnsm_service_get_cfg_para();
    snprintf(group, sizeof(group), "%s_%s_qnsm%s", dc_name, qnsm_get_edge_conf()->cons_group, app->inst_id);
    if (rd_kafka_conf_set(conf, "group.id", group,
                          errstr, sizeof(errstr)) !=
        RD_KAFKA_CONF_OK) {
        fprintf(stderr, "%% %s\n", errstr);
        ret = -1;
        goto EXIT;
    }

    /*broker version*/
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf, "broker.version.fallback", "0.8.2", errstr, sizeof(errstr))) {
        printf("%s\n", errstr);
        ret = -1;
        goto EXIT;
    }

    /*latest offset*/
    if (rd_kafka_topic_conf_set(topic_conf, "auto.offset.reset",
                                "latest",
                                errstr, sizeof(errstr)) !=
        RD_KAFKA_CONF_OK) {
        fprintf(stderr, "%% %s\n", errstr);
        ret = -1;
        goto EXIT;
    }

    /* Consumer groups always use broker based offset storage */
    if (rd_kafka_topic_conf_set(topic_conf, "offset.store.method",
                                "broker",
                                errstr, sizeof(errstr)) !=
        RD_KAFKA_CONF_OK) {
        fprintf(stderr, "%% %s\n", errstr);
        ret = -1;
        goto EXIT;
    }

    /* Set default topic config for pattern-matched topics. */
    rd_kafka_conf_set_default_topic_conf(conf, topic_conf);

    /* Callback called on partition assignment changes */
    rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);

    /* Create Kafka handle */
    if (!(qnsm_kafka->rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf,
                                        errstr, sizeof(errstr)))) {
        fprintf(stderr,
                "%% Failed to create new consumer: %s\n",
                errstr);
        ret = -1;
        goto EXIT;
    }

    /* Add brokers */
    if (rd_kafka_brokers_add(qnsm_kafka->rk, brokers) == 0) {
        fprintf(stderr, "%% No valid brokers specified\n");
        ret = -1;
        goto EXIT;
    }

    /* Redirect rd_kafka_poll() to consumer_poll() */
    rd_kafka_poll_set_consumer(qnsm_kafka->rk);

    /*
    *can be more than one topic
    */
    for (index = 0 ; index < kafka_cfg->topic_num ; index++) {
        if (kafka_cfg->topics[index].enable) {
            char *topic = kafka_cfg->topics[index].topic_name;
            uint32_t partition_index = 0;
            topic_list = rd_kafka_topic_partition_list_new(kafka_cfg->partitions);

            for (partition_index = 0; partition_index < kafka_cfg->partitions; partition_index++) {
                rd_kafka_topic_partition_list_add(topic_list, topic, partition_index);
            }

            rd_kafka_resp_err_t err;
            fprintf(stderr, "%% Assigning %d partitions\n", topic_list->cnt);
            if ((err = rd_kafka_assign(qnsm_kafka->rk, topic_list))) {
                fprintf(stderr,
                        "%% Failed to assign partitions: %s\n",
                        rd_kafka_err2str(err));
            }
        }
    }

EXIT:
    rte_spinlock_unlock(&kafka_handle->lock);
    return ret;
}

/**
 * Handle and print a consumed message.
 * Internally crafted messages are also used to propagate state from
 * librdkafka to the application. The application needs to check
 * the `rkmessage->err` field for this purpose.
 */
static void msg_consume (rd_kafka_message_t *rkmessage,
                         void *opaque __attribute__((unused)), QNSM_KAFKA_MSG_CONSUMER cons_fun)
{
    if (rkmessage->err) {
        if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
            /*
            fprintf(stderr,
                "%% Consumer reached end of %s [%"PRId32"] "
                   "message queue at offset %"PRId64"\n",
                   rd_kafka_topic_name(rkmessage->rkt),
                   rkmessage->partition, rkmessage->offset);
            */
            return;
        }

        if (rkmessage->rkt)
            fprintf(stderr, "%% Consume error for "
                    "topic \"%s\" [%"PRId32"] "
                    "offset %"PRId64": %s\n",
                    rd_kafka_topic_name(rkmessage->rkt),
                    rkmessage->partition,
                    rkmessage->offset,
                    rd_kafka_message_errstr(rkmessage));
        else
            fprintf(stderr, "%% Consumer error: %s: %s\n",
                    rd_kafka_err2str(rkmessage->err),
                    rd_kafka_message_errstr(rkmessage));


        if (rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION ||
            rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
            QNSM_ASSERT(0);

        return;
    }

    /*
    if (!quiet)
        fprintf(stdout, "%% Message (topic %s [%"PRId32"], "
                        "offset %"PRId64", %zd bytes):\n",
                        rd_kafka_topic_name(rkmessage->rkt),
                        rkmessage->partition,
            rkmessage->offset, rkmessage->len);
    if (rkmessage->key_len) {
        if (output == OUTPUT_HEXDUMP)
            hexdump(stdout, "Message Key",
                rkmessage->key, rkmessage->key_len);
        else
            printf("Key: %.*s\n",
                   (int)rkmessage->key_len, (char *)rkmessage->key);
    }

    if (output == OUTPUT_HEXDUMP)
        hexdump(stdout, "Message Payload",
            rkmessage->payload, rkmessage->len);
    else
        printf("%.*s\n",
               (int)rkmessage->len, (char *)rkmessage->payload);
    */
    cons_fun((char *)rkmessage->payload, (int)rkmessage->len);
}

static void qnsm_kafka_poll_msg(EN_QNSM_KAFKA_TOPIC topic, QNSM_KAFKA_MSG_CONSUMER cons_fun)
{
    uint16_t kafka_id = QNSM_KAFKA_KAFKA_ID(topic);
    uint16_t topic_id = QNSM_KAFKA_TOPIC_ID(topic);
    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    QNSM_KAFKA *qnsm_kafka = NULL;

    QNSM_ASSERT(QNSM_MAX_KAFKA >= kafka_id);
    QNSM_ASSERT(QNSM_KAFKA_MAX_TOPIC_ID >= topic_id);

    topic_id = topic_id;
    qnsm_kafka = (kafka_handle->kafka) + kafka_id;
    rd_kafka_message_t *rkmessage;

    /*
    *poll nowait
    *if timeout too long, affect cmd exe & cause pkt loss
    */
    rkmessage = rd_kafka_consumer_poll(qnsm_kafka->rk, 0);
    if (rkmessage) {
        msg_consume(rkmessage, NULL, cons_fun);
        rd_kafka_message_destroy(rkmessage);
    }
    return;
}

void qnsm_kafka_msg_reg(EN_QNSM_KAFKA_TOPIC topic, QNSM_KAFKA_MSG_CONSUMER cons_fun)
{
    uint16_t kafka_id = QNSM_KAFKA_KAFKA_ID(topic);
    uint16_t topic_id = QNSM_KAFKA_TOPIC_ID(topic);
    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    QNSM_KAFKA *qnsm_kafka = NULL;

    QNSM_ASSERT(QNSM_MAX_KAFKA >= kafka_id);
    QNSM_ASSERT(QNSM_KAFKA_MAX_TOPIC_ID >= topic_id);

    qnsm_kafka = (kafka_handle->kafka) + kafka_id;
    qnsm_kafka->msg_cb[topic_id].msg_cons_fun = cons_fun;
    qnsm_kafka->msg_cb[topic_id].kafka_topic = topic;
    kafka_handle->msg_cons_num++;
    return;
}

void qnsm_kafka_msg_dispatch(void)
{
    QNSM_KAFKA_DATA *kafka_handle = qnsm_service_handle(EN_QNSM_SERVICE_KAFKA);
    uint16_t kafka_id = 0;
    uint16_t topic_id = 0;
    QNSM_KAFKA *qnsm_kafka = NULL;

    if ((NULL == kafka_handle) || (0 == kafka_handle->msg_cons_num)) {
        return;
    }

    if (en_lib_state_load != GET_LIB_COMMON_STATE(kafka_handle)) {
        return;
    }

    for (kafka_id = 0; kafka_id < QNSM_MAX_KAFKA; kafka_id++) {
        qnsm_kafka = (kafka_handle->kafka) + kafka_id;
        if (0 == strlen(qnsm_kafka->kafka_name)) {
            continue;
        }
        for (topic_id = 0; topic_id < QNSM_KAFKA_MAX_TOPIC_ID; topic_id++) {
            if (qnsm_kafka->msg_cb[topic_id].msg_cons_fun) {
                qnsm_kafka_poll_msg(qnsm_kafka->msg_cb[topic_id].kafka_topic,
                                    qnsm_kafka->msg_cb[topic_id].msg_cons_fun);
            }
        }
    }

    return;
}

int32_t qnsm_kafka_init(void **tbl_handle)
{
    uint8_t kafka_num = QNSM_MAX_KAFKA;
    QNSM_KAFKA_DATA *kafka_handle = NULL;

    kafka_handle = rte_zmalloc_socket(NULL, sizeof(QNSM_KAFKA_DATA), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (kafka_handle) {
        kafka_handle->kafka = rte_zmalloc(NULL, sizeof(QNSM_KAFKA) * kafka_num, QNSM_DDOS_MEM_ALIGN);
        rte_spinlock_init(&kafka_handle->lock);

        SET_LIB_COMMON_STATE(kafka_handle, en_lib_state_init);
    }

    QNSM_ASSERT(kafka_handle);
    QNSM_ASSERT(kafka_handle->kafka);
    *tbl_handle = kafka_handle;

    return 0;
}

#endif
