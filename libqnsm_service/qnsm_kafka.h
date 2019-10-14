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
#ifndef _QNSM_KAFKA_H_
#define _QNSM_KAFKA_H_

#include <librdkafka/rdkafka.h>

#include "list.h"
#include "qnsm_service.h"

#ifdef __cplusplus
extern "C" {
#endif

#if QNSM_PART("kafka")

#define QNSM_KAFKA_BATCH_MSGS      (256)
#define QNSM_KAFKA_PARTITION_BUF_SIZE    (1280)
#define QNSM_KAFKA_PARTITION_MAX_NUM     (256)   /*this is very important!!!!, if one topic greater than, may cause array exceed*/
#define QNSM_KAFKA_CONF_CORE_MAX      (RTE_MAX_LCORE)


typedef struct {
    void *obj;
} QNSM_KAFKA_MSG;

typedef struct {
    QNSM_KAFKA_MSG msg[QNSM_KAFKA_BATCH_MSGS];

    uint16_t tx_cnt;
} QNSM_KAFKA_BATCH_TX;

typedef struct {
    QNSM_KAFKA_BATCH_TX batch_tx[QNSM_KAFKA_MAX_TOPIC_ID][QNSM_KAFKA_PARTITION_MAX_NUM];
} QNSM_KAFKA_BATCH_BUF;

typedef struct {
    EN_QNSM_KAFKA_TOPIC     kafka_topic;
    QNSM_KAFKA_MSG_CONSUMER msg_cons_fun;
} QNSM_KAFKA_MSG_CB;

typedef struct {
    char kafka_name[32];
    rd_kafka_t *rk;
    rd_kafka_topic_t *rkt[QNSM_KAFKA_MAX_TOPIC_ID];
    char *brokers;
    uint16_t partitions[QNSM_KAFKA_MAX_TOPIC_ID];
    uint16_t  enable[QNSM_KAFKA_MAX_TOPIC_ID];

    /*batch msg send*/
    QNSM_KAFKA_BATCH_BUF *batch_buf;

    /*per metric batch send cnt*/
    uint16_t batch_cnt[QNSM_KAFKA_MAX_TOPIC_ID];
    const char *batch_metric[QNSM_KAFKA_MAX_TOPIC_ID];

    /*kafka statis*/
    QNSM_KAFKA_TOPIC_PART_STATIS *statis[QNSM_KAFKA_MAX_TOPIC_ID];

    /*kafka inst msg cons*/
    QNSM_KAFKA_MSG_CB msg_cb[QNSM_KAFKA_MAX_TOPIC_ID];
} QNSM_KAFKA;

typedef struct {
    SERVICE_LIB_COMMON
    QNSM_KAFKA *kafka;
    rte_spinlock_t lock;

    uint16_t msg_cons_num;

    struct rte_timer flush_timer;
} QNSM_KAFKA_DATA;
#endif

int32_t qnsm_kafka_init(void **tbl_handle);

#ifdef __cplusplus
}
#endif

#endif
