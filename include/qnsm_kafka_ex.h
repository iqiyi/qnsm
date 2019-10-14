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
#ifndef _QNSM_KAFKA_EX_H_
#define _QNSM_KAFKA_EX_H_

#ifdef __cplusplus
extern "C" {
#endif

#define QNSM_KAFKA_MAX_BROKER_ADDR_LEN  (128)

#define QNSM_KAFKA_MAP(XX)                               \
    XX(0, QNSM_EDGE_KAFKA, "edge_producer")              \
    XX(1, QNSM_MASTER_CONS_KAFKA, "master_consumer")     \
    XX(2, QNSM_MASTER_PROD_KAFKA, "master_producer")     \
    XX(3, QNSM_MASTER_CMD_CONS, "cmd_consumer")

typedef enum {
#define XX(kafka_id, name, string) name = kafka_id,
    QNSM_KAFKA_MAP(XX)
#undef XX
    QNSM_MAX_KAFKA = 0x04,
} EN_QNSM_KAFKA;

/*one kafka instance max topic num*/
#define QNSM_KAFKA_MAX_TOPIC_ID   (16)

#define QNSM_KAFKA_TOPIC(kafka, topic_id)  (((kafka) << 16) | (topic_id))
#define QNSM_KAFKA_TOPIC_ID(kafka_topic)  ((kafka_topic) & 0xFF)
#define QNSM_KAFKA_KAFKA_ID(kafka_topic)  ((kafka_topic >> 16) & 0xFF)


/*
*xml conf file topic name must one of them,
*diff kafka topic name can't be same
*/
#define QNSM_KAFKA_TOPIC_MAP(XX)                        \
    XX(QNSM_EDGE_KAFKA, 0,  TCP_SESS_AGG, "qnsm_tcp_sess_agg")                 \
    XX(QNSM_EDGE_KAFKA, 1,  UDP_SESS_AGG, "qnsm_udp_sess_agg")                 \
    XX(QNSM_EDGE_KAFKA, 2,  SIP_IN_AGG, "qnsm_sip_agg")                        \
    XX(QNSM_EDGE_KAFKA, 3,  VIP_AGG, "qnsm_vip_agg")                           \
    XX(QNSM_EDGE_KAFKA, 4,  DNS, "qnsm_dns")                                   \
    XX(QNSM_EDGE_KAFKA, 5,  HTTP, "qnsm_http")                                 \
    XX(QNSM_EDGE_KAFKA, 6,  SSDP, "qnsm_ssdp")                                 \
    XX(QNSM_EDGE_KAFKA, 7,  NTP, "qnsm_ntp")                                   \
    XX(QNSM_EDGE_KAFKA, 8,  ALL_SIP_IN_AGG, "qnsm_all_sip_in_agg")             \
    XX(QNSM_EDGE_KAFKA, 9,  ALL_TCP_CONN, "qnsm_all_tcp_conn")                 \
    XX(QNSM_EDGE_KAFKA, 10, ALL_IP_CHG, "qnsm_all_ip_chg")                     \
    XX(QNSM_EDGE_KAFKA, 11, VIP_SPORT, "qnsm_vip_sport")                       \
    XX(QNSM_EDGE_KAFKA, 12, VIP_DPORT, "qnsm_vip_dport")                       \
    XX(QNSM_EDGE_KAFKA, 13, PF_SIG, "qnsm_pf_sig")                             \
    XX(QNSM_EDGE_KAFKA, 14, SAMPLE_FLOW, "qnsm_sample_flow")                   \
    XX(QNSM_MASTER_PROD_KAFKA, 0, DYN_VIP, "qnsm_dyn_vip")                     \
    XX(QNSM_MASTER_PROD_KAFKA, 1, CMD_ACK, "qnsm_command_ack")                 \
    XX(QNSM_MASTER_CONS_KAFKA, 0, DYN_VIP_ACK, "qnsm_dyn_vip_ack")             \
    XX(QNSM_MASTER_CMD_CONS, 0, CMD, "qnsm_command")

typedef enum {
#define XX(kafka, topic, name, string) QNSM_KAFKA_##name##_TOPIC = QNSM_KAFKA_TOPIC(kafka, topic),
    QNSM_KAFKA_TOPIC_MAP(XX)
#undef XX
} EN_QNSM_KAFKA_TOPIC;

typedef struct {
    uint64_t tx_statis;
    uint64_t tx_drop_statis;
    uint64_t rx_statis;
} QNSM_KAFKA_TOPIC_PART_STATIS;

typedef void (*QNSM_KAFKA_MSG_CONSUMER)(char *payload, uint32_t payload_len);

const char *qnsm_kafka_topic_name(EN_QNSM_KAFKA_TOPIC topic);
void qnsm_kafka_batch_tx_init(EN_QNSM_KAFKA_TOPIC topic, const char *batch_metric, uint16_t batch_cnt);

/**
 * init kafka producer
 *
 * @param cfg ptr
 *   kafka conf parsed from qnsm_edge.xml
 * @return
 *   0 success, other failed
 */
int32_t qnsm_kafka_app_init_producer(void *cfg);

/**
 * init kafka consumer
 *
 * @param dc_name
 *   idc name, as part of kafka consumer group name
 * @param cfg ptr
 *   kafka conf parsed from qnsm_edge.xml
 * @return
 *   0 success, other failed
 */
int32_t qnsm_kafka_app_init_consumer(const char *dc_name, void *cfg);

/**
 * register topic's consumer cbk
 *
 * @param topic
 *   topic id
 * @param cons_fun
 *   consume topic cbk fun
 */
void qnsm_kafka_msg_reg(EN_QNSM_KAFKA_TOPIC topic, QNSM_KAFKA_MSG_CONSUMER cons_fun);

/**
 * send kafka msg
 *
 * @param topic
 *   topic id
 * @param type
 *   just set 0
 * @param obj
 *   cJSON obj
 * @param partition
 *   set partition id
 */
void qnsm_kafka_send_msg(EN_QNSM_KAFKA_TOPIC topic, void *obj, uint16_t partition);

/**
 * dispatch kafka msg
 */
void qnsm_kafka_msg_dispatch(void);

/*only for cmd*/
QNSM_KAFKA_TOPIC_PART_STATIS *qnsm_kafka_get_statis(void *para, EN_QNSM_KAFKA_TOPIC topic, uint16_t *part_num);




#ifdef __cplusplus
}
#endif

#endif

