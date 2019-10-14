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
#ifndef __QNSM_DNS__
#define __QNSM_DNS__

#ifdef __cplusplus
extern "C" {
#endif

#define QR_MASK         (0x8000)
#define OPCODE_MASK     (0x7800)
#define AA_MASK         (0x0400)
#define TC_MASK         (0x0200)
#define RD_MASK         (0x0100)
#define RA_MASK         (0x0080)
#define RCODE_MASK      (0x000F)

/* Response Type */
enum {
    Ok_ResponseType = 0,
    FormatError_ResponseType = 1,
    ServerFailure_ResponseType = 2,
    NameError_ResponseType = 3,
    NotImplemented_ResponseType = 4,
    Refused_ResponseType = 5
};

/* Resource Record Types */
typedef enum {
    A_Resource_RecordType = 1,
    NS_Resource_RecordType = 2,
    CNAME_Resource_RecordType = 5,
    SOA_Resource_RecordType = 6,
    PTR_Resource_RecordType = 12,
    MX_Resource_RecordType = 15,
    TXT_Resource_RecordType = 16,
    AAAA_Resource_RecordType = 28,
    SRV_Resource_RecordType = 33,
    RESOURCE_RECORD_TYPE_MAX,
} EN_RESOURCE_RECORD_TYPE;

/* Operation Code */
typedef enum {
    QUERY_OperationCode = 0, /* standard query */
    IQUERY_OperationCode = 1, /* inverse query */
    STATUS_OperationCode = 2, /* server status request */
    NOTIFY_OperationCode = 4, /* request zone transfer */
    UPDATE_OperationCode = 5, /* change resource records */
    OPCODE_MAX,
} EN_OPCODE;

/* Response Code */
enum {
    NoError_ResponseCode = 0,
    FormatError_ResponseCode = 1,
    ServerFailure_ResponseCode = 2,
    NameError_ResponseCode = 3
};

/* Query Type */
enum {
    IXFR_QueryType = 251,
    AXFR_QueryType = 252,
    MAILB_QueryType = 253,
    MAILA_QueryType = 254,
    STAR_QueryType = 255
};

/* Map for errno-related constants
 *
 * The provided argument should be a macro that takes 2 arguments.
 */
#define DNS_ERRNO_MAP(XX)                                            \
  /* No error */                                                     \
  XX(OK, "success")                                                  \
                                                                     \
  /*errors */                                                        \
  XX(PKT_LEN, "invalid pkt len")                                 \
  XX(QDCOUNT, "qdcount invalid")                                     \
  XX(OPCODE, "opcode invalid")                                       \
  XX(REQUERY_DOMAINNAME, "requery domain name invalid")              \
  XX(RR_DOMAINNAME, "rr domain name invalid")                        \
  XX(RR_CNAME, "cname name invalid")                                 \
  XX(RR_MX_RECORD_EXCHANGE, "mx exchange name invalid")              \
  XX(DOMAIN_TYPE, "type invalid")                                    \
  XX(DOMAIN_CLASS, "class invalid")                                  \
  XX(A_RECORD_DATA_LENTH, "a record data length invalid")            \
  XX(UNKNOWN, "an unknown error occurred")


/* Define HPE_* values for each errno value above */
#define DNS_ERRNO_GEN(n, s) DNS_ERR_##n,
enum dns_errno {
    DNS_ERRNO_MAP(DNS_ERRNO_GEN)
};
#undef DNS_ERRNO_GEN


/*
* Types.
*/
#ifdef _MSC_VER
/* Windows */
#define PACK_ON   __pragma(pack(push, 1))
#define PACK_OFF  __pragma(pack(pop))
#elif defined(__GNUC__)
/* GNU C */
#define PACK_ON
#define PACK_OFF  __attribute__((packed))
#endif


/* Question Section */
typedef struct {
    char *qName;
    uint16_t qType;
    uint16_t qClass;
    //struct qnsm_list_head node;
} QUESTION;

/* Data part of a Resource Record */
union ResourceData {
    struct {
        char *txt_data;
    } txt_record;
    struct {
        uint32_t addr;
    } a_record;
    struct {
        char* MName;
        char* RName;
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    } soa_record;
    struct {
        char *name;
    } name_server_record;
    struct {
        char *name;
    } cname_record;
    struct {
        char *name;
    } ptr_record;
    struct {
        uint16_t preference;
        char *exchange;
    } mx_record;
    struct {
        uint8_t addr[16];
    } aaaa_record;
    struct {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        char *target;
    } srv_record;
};

/* Resource Record Section */
typedef struct {
    char *rr_name;
    uint16_t rr_type;
    uint16_t rr_class;
    uint32_t rr_ttl;
    uint16_t rd_length;
    union ResourceData rd_data;
    //struct qnsm_list_head node;
} RESOURCE_RECORD;

typedef struct {
    char name;      /*must be zero*/
    uint16_t type;
    uint16_t payload_size;
    uint32_t ext_RCODE;
    uint16_t len;
    uint8_t data[0];
} RR_OPT;


typedef struct dns_packet_header {
    uint16_t tr_id;

#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t qr:1;
    uint16_t opcode:4;
    uint16_t aa:1;
    uint16_t tc:1;
    uint16_t rd:1;
    uint16_t ra:1;
    uint16_t rsvd:3;
    uint16_t rcode:4;

#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd:1;
    uint16_t tc:1;
    uint16_t aa:1;
    uint16_t opcode:4;
    uint16_t qr:1;
    uint16_t rcode:4;
    uint16_t rsvd:3;
    uint16_t ra:1;

#else
# error "Please fix <bits/endian.h>"
#endif
    uint16_t num_queries;
    uint16_t num_answers;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
} __attribute__((packed)) DNS_PKT_HEADER;


/*
* dns parse info
* udp: per lcore
* tcp: per sess
*/
typedef struct {
    uint8_t *dns_header;
    uint16_t dns_length;
    uint16_t num_queries;
    uint16_t num_rr;
    uint16_t num_rr_opt;

    /*
    * Resource records
    */
    uint16_t ques_size;
    uint16_t rr_size;
    QUESTION *questions;
    RESOURCE_RECORD *rr;
    enum dns_errno dns_err;

    /*save dns requery name*/
    char domain_name[256];
} DNS_INFO;

#define DNS_SET_ERRNO(info, e)                                           \
do {                                                                 \
  (info)->dns_err = (e);                                           \
} while(0)



#ifdef __cplusplus
}
#endif

#endif
