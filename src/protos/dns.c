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

#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


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
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>

#include "cJSON.h"
#include "qnsm_dbg.h"
#include "qnsm_inspect_main.h"
#include "qnsm_cfg.h"
#include "qnsm_flow_analysis.h"
#include "qnsm_msg_ex.h"
#include "qnsm_dpi_ex.h"
#include "bsb.h"
#include "dns.h"

DNS_INFO  *dns_udp_info;
static char                 *statuses[16] = {
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMPL",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "11",
    "12",
    "13",
    "14",
    "15"
};


/* Map errno values to strings for human-readable output */
#define DNS_STRERROR_GEN(n, s) { "DNS_ERR_" #n, s },
static struct {
    const char *name;
    const char *description;
} dns_strerror_tab[] = {
    DNS_ERRNO_MAP(DNS_STRERROR_GEN)
};
#undef DNS_STRERROR_GEN


unsigned char DnsNameTable[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0X2A,0,0,0X2D,0,0,
    0X30,0X31,0X32,0X33,0X34,0X35,0X36,0X37,0X38,0X39,0,0,0,0,0,0,
    0,0X61,0X62,0X63,0X64,0X65,0X66,0X67,0X68,0X69,0X6A,0X6B,0X6C,0X6D,0X6E,0X6F,
    0X70,0X71,0X72,0X73,0X74,0X75,0X76,0X77,0X78,0X79,0X7A,0,0,0,0,0X5F,
    0,0X61,0X62,0X63,0X64,0X65,0X66,0X67,0X68,0X69,0X6A,0X6B,0X6C,0X6D,0X6E,0X6F,
    0X70,0X71,0X72,0X73,0X74,0X75,0X76,0X77,0X78,0X79,0X7A,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

#define ISVALIDDNSCHAR(_ch)  DnsNameTable[((unsigned char)_ch)]

#define DNS_DOMAIN_NAME_HAS_PTR(ch) ((ch) & (0xc0))



static void dns_udp_classify(QNSM_PACKET_INFO *pkt_info, void *sess, void **arg)
{
    DNS_INFO *dns_info = NULL;

    QNSM_ASSERT(NULL != pkt_info);
    QNSM_ASSERT(NULL != arg);

    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "enter\n");

    dns_info = qnsm_dpi_proto_data(EN_QNSM_DPI_DNS);
    if (NULL == dns_info) {
        QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_ERR, "failed\n");
        return;
    }

    /*set dpi app*/
    pkt_info->dpi_app_prot = EN_QNSM_DPI_DNS;
    *arg = dns_info;
    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "leave\n");
    return;
}

/******************************************************************************/
static int32_t dns_name_element(BSB *nbsb, BSB *bsb)
{
    int nlen = 0;
    BSB_IMPORT_u08(*bsb, nlen);

    if (nlen == 0 || nlen > BSB_REMAINING(*bsb)) {
        return 1;
    }

    int j;
    for (j = 0; j < nlen; j++) {
        register u_char c = 0;
        BSB_IMPORT_u08(*bsb, c);

#if 1
        if (!isascii(c)) {
            BSB_EXPORT_u08(*nbsb, 'M');
            BSB_EXPORT_u08(*nbsb, '-');
            c = toascii(c);
        }
        if (!isprint(c)) {
            BSB_EXPORT_u08(*nbsb, '^');
            c ^= 0x40;
        }
#else
        if (!ISVALIDDNSCHAR(c)) {
            BSB_EXPORT_u08(*nbsb, 'M');
            BSB_EXPORT_u08(*nbsb, '-');
            c = toascii(c);
        }
#endif
        BSB_EXPORT_u08(*nbsb, c);
    }

    return 0;
}

/******************************************************************************
*dns proto may compress domain name
******************************************************************************/
static unsigned char *dns_name(const unsigned char *full, uint32_t fulllen, BSB *inbsb, unsigned char *name, uint32_t *namelen)
{
    BSB  nbsb;
    int  didPointer = 0;
    BSB  tmpbsb;
    BSB *curbsb;
    int32_t ret = 0;

    BSB_INIT(nbsb, name, *namelen);

    curbsb = inbsb;

    while (BSB_REMAINING(*curbsb)) {
        unsigned char ch = 0;
        BSB_IMPORT_u08(*curbsb, ch);

        if (ch == 0)
            break;

        BSB_EXPORT_rewind(*curbsb, 1);

        if (DNS_DOMAIN_NAME_HAS_PTR(ch)) {
            if (didPointer > 5)
                return 0;
            didPointer++;
            int tpos = 0;
            BSB_IMPORT_u16(*curbsb, tpos);
            tpos &= 0x3fff;

            BSB_INIT(tmpbsb, full+tpos, fulllen - tpos);
            curbsb = &tmpbsb;
            continue;
        }

        if (BSB_LENGTH(nbsb)) {
            BSB_EXPORT_u08(nbsb, '.');
        }

        ret = dns_name_element(&nbsb, curbsb);
        if ((0 < ret) && BSB_LENGTH(nbsb))
            BSB_EXPORT_rewind(nbsb, 1); // Remove last .
    }
    *namelen = BSB_LENGTH(nbsb);
    BSB_EXPORT_u08(nbsb, 0);
    return name;
}


/*
*return : parse len
*if parse err happens, set err no
*/
static int32_t dns_parse_exceute(DNS_INFO *dns_info, const char *data, uint16_t len)
{
    const char *tmp_data = NULL;
    uint16_t offset = 0;
    uint16_t index = 0;
    uint16_t num_query = 0;
    uint16_t num_rr = 0;
    DNS_PKT_HEADER *dns_header = NULL;
    BSB bsb;
    unsigned char *name = NULL;
    uint32_t name_len = 0;

    QNSM_ASSERT(dns_info);
    QNSM_ASSERT(data);

    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "enter\n");

    if (len < (sizeof(DNS_PKT_HEADER) + 5)) {
        DNS_SET_ERRNO(dns_info, DNS_ERR_PKT_LEN);
        return offset;
    }

    /*1. parse header*/
    dns_header = (DNS_PKT_HEADER *)data;
    if (OPCODE_MAX <= dns_header->opcode) {
        DNS_SET_ERRNO(dns_info, DNS_ERR_OPCODE);
        return offset;
    }

    /*2. parse data*/
    num_query = QNSM_DPI_NTOHS(dns_header->num_queries);
    if (10 < num_query) {
        DNS_SET_ERRNO(dns_info, DNS_ERR_QDCOUNT);
        offset = (char *)&dns_header->num_queries - (char *)dns_header;
        return offset;
    }
    dns_info->num_queries = num_query;
    if (dns_info->ques_size < num_query) {
        dns_info->questions =  (QUESTION *)rte_realloc(dns_info->questions, sizeof(QUESTION) * num_query, QNSM_DDOS_MEM_ALIGN);
        if (NULL == dns_info->questions) {
            DNS_SET_ERRNO(dns_info, DNS_ERR_UNKNOWN);
            dns_info->ques_size = 0;
            return offset;
        }
        dns_info->ques_size = num_query;
    }
    num_rr = QNSM_DPI_NTOHS(dns_header->num_answers)
             + QNSM_DPI_NTOHS(dns_header->additional_rrs)
             + QNSM_DPI_NTOHS(dns_header->authority_rrs);
    dns_info->num_rr = num_rr;
    if (dns_info->rr_size < num_rr) {
        dns_info->rr = (RESOURCE_RECORD *)rte_realloc(dns_info->rr, sizeof(RESOURCE_RECORD) * num_rr, QNSM_DDOS_MEM_ALIGN);
        if (NULL == dns_info->rr) {
            DNS_SET_ERRNO(dns_info, DNS_ERR_UNKNOWN);
            dns_info->rr_size = 0;
            return offset;
        }
        dns_info->rr_size = num_rr;
    }

    /*2.1 parse queries*/
    uint8_t req_name[256];
    offset = sizeof(DNS_PKT_HEADER);
    tmp_data = data + offset;
    for (index = 0; (index < num_query) && (offset < len); index++) {
        BSB_INIT(bsb, tmp_data, len - offset);
        name_len = sizeof(req_name);
        dns_name(data, len, &bsb, req_name, &name_len);
        if (BSB_IS_ERROR(bsb)) {
            DNS_SET_ERRNO(dns_info, DNS_ERR_REQUERY_DOMAINNAME);
            offset = tmp_data - data;
            goto EXIT;

        }

        if (0 == name_len) {
            name = (unsigned char*)"<root>";
        }
        dns_info->questions[index].qName = strdup(req_name);

        tmp_data = BSB_WORK_PTR(bsb);
        if (NULL == dns_info->questions[index].qName) {
            DNS_SET_ERRNO(dns_info, DNS_ERR_REQUERY_DOMAINNAME);
            offset = tmp_data - data;
            goto EXIT;

        }
        dns_info->questions[index].qType = QNSM_DPI_NTOHS(*(uint16_t *)(tmp_data));
        if (RESOURCE_RECORD_TYPE_MAX <= dns_info->questions[index].qType) {
            DNS_SET_ERRNO(dns_info, DNS_ERR_DOMAIN_TYPE);
            offset = tmp_data - data;
            goto EXIT;

        }
        tmp_data += sizeof(uint16_t);
        dns_info->questions[index].qClass = QNSM_DPI_NTOHS(*(uint16_t *)(tmp_data));
        tmp_data += sizeof(uint16_t);
        offset = tmp_data - data;
    }
    if (!dns_header->qr) {
        goto EXIT;

    }

    /*2.2 parse rr*/
    for (index = 0; (index < num_rr) && (offset < len); index++) {

        BSB_INIT(bsb, tmp_data, len - offset);
        name_len = sizeof(dns_info->domain_name);
        name = dns_name(data, len, &bsb, dns_info->domain_name, &name_len);

        /*OPT RR*/
        if ((0 == name_len) && (0 == tmp_data[0])) {
            tmp_data += sizeof(RR_OPT);
            offset = tmp_data - data;
            dns_info->num_rr_opt++;
            continue;
        }
        if (BSB_IS_ERROR(bsb) || !name) {
            DNS_SET_ERRNO(dns_info, DNS_ERR_RR_DOMAINNAME);
            goto EXIT;
        }

        /*rr name now not used*/
        tmp_data = BSB_WORK_PTR(bsb);

        dns_info->rr[index].rr_type = QNSM_DPI_NTOHS(*(uint16_t *)(tmp_data));
        tmp_data += sizeof(uint16_t);
        dns_info->rr[index].rr_class = QNSM_DPI_NTOHS(*(uint16_t *)(tmp_data));
        tmp_data += sizeof(uint16_t);
        dns_info->rr[index].rr_ttl = QNSM_DPI_NTOHL(*(uint16_t *)(tmp_data));
        tmp_data += sizeof(uint32_t);
        dns_info->rr[index].rd_length = QNSM_DPI_NTOHS(*(uint16_t *)(tmp_data));
        tmp_data += sizeof(uint16_t);

        switch (dns_info->rr[index].rr_type) {
            case A_Resource_RecordType: {
                if (dns_info->rr[index].rd_length != 4) {
                    DNS_SET_ERRNO(dns_info, DNS_ERR_A_RECORD_DATA_LENTH);
                    offset = tmp_data - data;
                    goto EXIT;

                }
                dns_info->rr[index].rd_data.a_record.addr =
                    QNSM_DPI_NTOHL(*(uint32_t *)(tmp_data));
                tmp_data += sizeof(uint32_t);
                break;
            }
            case SOA_Resource_RecordType: {
                BSB_INIT(bsb, tmp_data, (len - (tmp_data - data)));

                /*primary name server*/
                name_len = sizeof(dns_info->domain_name);
                name = dns_name(data, len, &bsb, dns_info->domain_name, &name_len);
                if (BSB_IS_ERROR(bsb) || !name) {
                    DNS_SET_ERRNO(dns_info, DNS_ERR_RR_CNAME);
                    goto EXIT;
                }
                dns_info->rr[index].rd_data.soa_record.MName = strdup(dns_info->domain_name);

                /*responsible authority's mailbox*/
                name_len = sizeof(dns_info->domain_name);
                name = dns_name(data, len, &bsb, dns_info->domain_name, &name_len);
                if (BSB_IS_ERROR(bsb) || !name) {
                    DNS_SET_ERRNO(dns_info, DNS_ERR_RR_CNAME);
                    goto EXIT;
                }

                /*attention BSB_IMPORT_uxx also done byte order transform*/
                BSB_IMPORT_u32(bsb, dns_info->rr[index].rd_data.soa_record.serial);
                BSB_IMPORT_u32(bsb, dns_info->rr[index].rd_data.soa_record.refresh);
                BSB_IMPORT_u32(bsb, dns_info->rr[index].rd_data.soa_record.retry);
                BSB_IMPORT_u32(bsb, dns_info->rr[index].rd_data.soa_record.expire);
                BSB_IMPORT_u32(bsb, dns_info->rr[index].rd_data.soa_record.minimum);
                tmp_data = BSB_WORK_PTR(bsb);
                break;
            }
            case CNAME_Resource_RecordType: {
                BSB_INIT(bsb, tmp_data, (len - (tmp_data - data)));
                name_len = sizeof(dns_info->domain_name);
                name = dns_name(data, len, &bsb, dns_info->domain_name, &name_len);
                if (BSB_IS_ERROR(bsb) || !name) {
                    DNS_SET_ERRNO(dns_info, DNS_ERR_RR_CNAME);
                    goto EXIT;
                }
                dns_info->rr[index].rd_data.cname_record.name = strdup(dns_info->domain_name);
                tmp_data = BSB_WORK_PTR(bsb);
                break;
            }
            case MX_Resource_RecordType: {
                dns_info->rr[index].rd_data.mx_record.preference = QNSM_DPI_NTOHS(*(uint16_t *)(tmp_data));
                tmp_data += sizeof(uint16_t);

                BSB_INIT(bsb, tmp_data, (len - (tmp_data - data)));
                name_len = sizeof(dns_info->domain_name);
                name = dns_name(data, len, &bsb, dns_info->domain_name, &name_len);
                if (BSB_IS_ERROR(bsb) || !name) {
                    DNS_SET_ERRNO(dns_info, DNS_ERR_RR_MX_RECORD_EXCHANGE);
                    goto EXIT;
                }
                dns_info->rr[index].rd_data.mx_record.exchange = strdup(dns_info->domain_name);
                tmp_data = BSB_WORK_PTR(bsb);
                break;
            }
            default: {
                tmp_data += dns_info->rr[index].rd_length;
            }
        }

        offset = tmp_data - data;
    }

EXIT:
    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "leave\n");
    return offset;
}

static EN_QNSM_DPI_OP_RES dns_parse(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    EN_QNSM_DPI_OP_RES   ret = EN_QNSM_DPI_OP_STOP;
    DNS_INFO *dns_info = (DNS_INFO *)arg;
    struct rte_mbuf *mbuf = (struct rte_mbuf *)((char *)pkt_info - sizeof(struct rte_mbuf));
    struct udp_hdr   *uh = NULL;

    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pkt_info->l3_offset + pkt_info->l3_len);
    dns_info->dns_header = (uint8_t *)pkt_info->payload;
    dns_info->dns_length = QNSM_DPI_NTOHS(uh->dgram_len) - sizeof(struct udp_hdr);
    DNS_SET_ERRNO(dns_info, DNS_ERR_OK);
    if (dns_info->rr) {
        memset(dns_info->rr, 0, dns_info->rr_size * sizeof(RESOURCE_RECORD));
    }
    if (dns_info->questions) {
        memset(dns_info->questions, 0, dns_info->ques_size * sizeof(QUESTION));
    }
    dns_info->num_rr = 0;
    dns_info->num_rr_opt = 0;

    if (UDP_PROTOCOL == pkt_info->proto) {
#if __DNS_VERBOSE_PARSE

        uint32_t parse_len = 0;
        parse_len = dns_parse_exceute(dns_info, dns_info->dns_header, dns_info->dns_length);
        QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "parse result: %d input: %d errno: %d\n", parse_len, dns_info->dns_length, dns_info->dns_err);
        if (DNS_ERR_OK == dns_info->dns_err) {
            ret = EN_QNSM_DPI_OP_CONTINUE;
        } else {
            QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_ERR, "parse err errno: %d\n", dns_info->dns_err);
            ret = EN_QNSM_DPI_OP_CONTINUE;
        }
#endif

        ret = EN_QNSM_DPI_OP_CONTINUE;

    } else if (TCP_PROTOCOL == pkt_info->proto) {
        ;
    }

    return ret;
}

EN_QNSM_DPI_OP_RES dns_send(QNSM_PACKET_INFO *pkt_info, void *arg)
{
    (void)qnsm_dpi_send_info(pkt_info, EN_QNSM_DPI_DNS, arg);

    return EN_QNSM_DPI_OP_CONTINUE;
}

uint32_t dns_encap_info(uint8_t *buf, void *pkt_info, void *arg)
{
    uint32_t len = 0;
    DNS_INFO *dns_info = (DNS_INFO *)arg;
    uint16_t index = 0;
    uint16_t name_len;
    RESOURCE_RECORD *record = NULL;
    uint16_t num_rr = 0;
    DNS_PKT_HEADER *dns_header = (DNS_PKT_HEADER *)dns_info->dns_header;

    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "enter\n");
    len += qnsm_dpi_encap_tuple(buf, pkt_info);

    *(uint16_t *)(buf + len) = dns_info->dns_err;
    len += sizeof(uint16_t);

    *(uint16_t *)(buf + len) = dns_info->dns_length;
    len += sizeof(uint16_t);
    if (DNS_ERR_OK != dns_info->dns_err) {
        goto EXIT;
    }
    *(uint16_t *)(buf + len) = dns_header->qr;
    len += sizeof(uint16_t);
    *(uint16_t *)(buf + len) = dns_header->rcode;
    len += sizeof(uint16_t);
    *(uint16_t *)(buf + len) = QNSM_DPI_NTOHS(dns_header->num_queries);
    len += sizeof(uint16_t);

    num_rr = dns_info->num_rr;
    if (dns_info->num_rr >= dns_info->num_rr_opt) {
        num_rr -= dns_info->num_rr_opt;
    } else {
        QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_ERR, "num rr opt greater than num_rr\n");
        num_rr = 0;
    }
    *(uint16_t *)(buf + len) = num_rr;
    len += sizeof(uint16_t);

    BSB dns_info_bsb;
    BSB_INIT(dns_info_bsb, (buf + len), (QNSM_DPI_MSG_DATA_LEN - len));
    for (index = 0; index < dns_info->num_queries; index++) {
        if (NULL == dns_info->questions[index].qName) {
            BSB_LEXPORT_u16(dns_info_bsb, 0);
            continue;
        }

        name_len = strlen(dns_info->questions[index].qName) + 1;
        BSB_LEXPORT_u16(dns_info_bsb, name_len);
        BSB_EXPORT_ptr(dns_info_bsb, dns_info->questions[index].qName, name_len);
        BSB_LEXPORT_u16(dns_info_bsb, dns_info->questions[index].qType);
        BSB_LEXPORT_u16(dns_info_bsb, dns_info->questions[index].qClass);

        if (BSB_IS_ERROR(dns_info_bsb)) {
            len = BSB_WORK_PTR(dns_info_bsb) - buf;
            goto EXIT;
        }
    }

    for (index = 0; index < num_rr; index++) {
        record = &dns_info->rr[index];
        BSB_LEXPORT_u16(dns_info_bsb, record->rr_type);
        BSB_LEXPORT_u16(dns_info_bsb, record->rd_length);

        switch(record->rr_type) {
            case A_Resource_RecordType: {
                BSB_LEXPORT_u32(dns_info_bsb, record->rd_data.a_record.addr);
                break;
            }
            case SOA_Resource_RecordType: {
                if (record->rd_data.soa_record.MName) {
                    name_len = strlen(record->rd_data.soa_record.MName) + 1;
                    BSB_LEXPORT_u16(dns_info_bsb, name_len);
                    BSB_EXPORT_ptr(dns_info_bsb, record->rd_data.soa_record.MName, name_len);

                    free(record->rd_data.soa_record.MName);
                    record->rd_data.soa_record.MName = NULL;
                } else {
                    BSB_LEXPORT_u16(dns_info_bsb, 0);
                }
                break;
            }
            case CNAME_Resource_RecordType: {
                if (record->rd_data.cname_record.name) {
                    name_len = strlen(record->rd_data.cname_record.name) + 1;
                    BSB_LEXPORT_u16(dns_info_bsb, name_len);
                    BSB_EXPORT_ptr(dns_info_bsb, record->rd_data.cname_record.name, name_len);

                    free(record->rd_data.cname_record.name);
                    record->rd_data.cname_record.name = NULL;
                } else {
                    BSB_LEXPORT_u16(dns_info_bsb, 0);
                }
                break;
            }
            case MX_Resource_RecordType: {
                if (record->rd_data.mx_record.exchange) {
                    name_len = strlen(record->rd_data.mx_record.exchange) + 1;
                    BSB_LEXPORT_u16(dns_info_bsb, name_len);
                    BSB_EXPORT_ptr(dns_info_bsb, record->rd_data.mx_record.exchange, name_len);

                    free(record->rd_data.mx_record.exchange);
                    record->rd_data.mx_record.exchange = NULL;
                } else {
                    BSB_LEXPORT_u16(dns_info_bsb, 0);
                }
                break;
            }
        }

        if (BSB_IS_ERROR(dns_info_bsb)) {
            len = BSB_WORK_PTR(dns_info_bsb) - buf;
            goto EXIT;
        }
    }

    len = BSB_WORK_PTR(dns_info_bsb) - buf;

EXIT:
    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "leave len %u\n", len);
    return len;
}

void dns_msg_proc(void *data, uint32_t data_len)
{
    cJSON *root = NULL;
    char  tmp[128];
    uint32_t size =  sizeof(tmp);
    struct in_addr ip_addr;
    uint32_t len = 0;
    uint8_t *buf = data;
    QNSM_DPI_IPV4_TUPLE4 *tuple = (QNSM_DPI_IPV4_TUPLE4 *)buf;
    uint16_t qr = 0;
    uint16_t rep_code = 0;
    uint16_t num_queries = 0;
    uint16_t num_rrs = 0;
    uint16_t index = 0;
    uint16_t name_len = 0;
    uint16_t rr_type;
    uint16_t dns_errno;

    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "enter\n");
    root = cJSON_CreateObject();

    if (EN_QNSM_AF_IPv4 == tuple->af) {
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->saddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        ip_addr.s_addr = QNSM_DPI_HTONL(tuple->daddr.in4_addr.s_addr);
        (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    } else {
        (void)inet_ntop(AF_INET6, tuple->saddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"sip", tmp);
        (void)inet_ntop(AF_INET6, tuple->daddr.in6_addr.s6_addr, tmp, size);
        cJSON_AddStringToObject(root,"dip", tmp);
    }
    cJSON_AddNumberToObject(root, "sport", tuple->source);
    cJSON_AddNumberToObject(root, "dport", tuple->dest);
    len += sizeof(QNSM_DPI_IPV4_TUPLE4);

    dns_errno = *(uint16_t *)(buf + len);
    cJSON_AddStringToObject(root, "dns errno", dns_strerror_tab[dns_errno].description);
    len += sizeof(uint16_t);
    cJSON_AddNumberToObject(root, "dns length", *(uint16_t *)(buf + len));
    len += sizeof(uint16_t);
    if (DNS_ERR_OK != dns_errno) {
        goto EXIT;
    }

    /*req or response*/
    qr = *(uint16_t *)(buf + len);
    len += sizeof(uint16_t);
    cJSON_AddStringToObject(root, "qr", qr ? "response" : "request");
    rep_code = *(uint16_t *)(buf + len);
    len += sizeof(uint16_t);
    if (qr) {
        cJSON_AddStringToObject(root, "reply code", statuses[rep_code]);
    }

    /**/
    num_queries = *(uint16_t *)(buf + len);
    len += sizeof(uint16_t);
    num_rrs += *(uint16_t *)(buf + len);
    len += sizeof(uint16_t);

    BSB dns_info_bsb;
    uint8_t *ptr = NULL;
    BSB_INIT(dns_info_bsb, (buf + len), (data_len - len));

    for (index = 0; index < num_queries; index++) {
        BSB_LIMPORT_u16(dns_info_bsb, name_len);
        if (0 < name_len) {
            /*decode check*/
            BSB_LIMPORT_skip(dns_info_bsb, (name_len + sizeof(uint16_t) * 2));
            if (BSB_IS_ERROR(dns_info_bsb)) {
                BSB_LIMPORT_rewind(dns_info_bsb, (name_len + sizeof(uint16_t) * 2));
                break;
            }
            BSB_LIMPORT_rewind(dns_info_bsb, ((name_len + sizeof(uint16_t) * 2)));

            BSB_LIMPORT_ptr(dns_info_bsb, ptr, name_len);
            cJSON_AddStringToObject(root, "query name", ptr);

            BSB_LIMPORT_ptr(dns_info_bsb, ptr, sizeof(uint16_t));
            cJSON_AddNumberToObject(root, "query type", *(uint16_t *)(ptr));

            /*skip class*/
            BSB_LIMPORT_skip(dns_info_bsb, sizeof(uint16_t));
        }
    }

    for (index = 0; index < num_rrs; index++) {
        BSB_LIMPORT_u16(dns_info_bsb, rr_type);
        BSB_LIMPORT_ptr(dns_info_bsb, ptr, sizeof(uint16_t));
        if (BSB_IS_ERROR(dns_info_bsb)) {
            break;
        }
        cJSON_AddNumberToObject(root, "rr type", rr_type);
        cJSON_AddNumberToObject(root, "query type", *(uint16_t *)(ptr));

        name_len  = 0;
        switch(rr_type) {
            case A_Resource_RecordType: {
                BSB_LIMPORT_ptr(dns_info_bsb, ptr, sizeof(uint32_t));
                if (ptr) {
                    ip_addr.s_addr = QNSM_DPI_HTONL(*(uint32_t *)(ptr));
                    (void)inet_ntop(AF_INET, &ip_addr, tmp, size);
                    cJSON_AddStringToObject(root,"type A ip", tmp);
                }
                break;
            }

            case SOA_Resource_RecordType: {
                BSB_LIMPORT_u16(dns_info_bsb, name_len);
                if (name_len > 0) {
                    BSB_LIMPORT_ptr(dns_info_bsb, ptr, name_len);
                    if (ptr) {
                        cJSON_AddStringToObject(root, "type SOA primary", ptr);
                    }
                }
                break;
            }
            case CNAME_Resource_RecordType: {
                BSB_LIMPORT_u16(dns_info_bsb, name_len);
                if (name_len > 0) {
                    BSB_LIMPORT_ptr(dns_info_bsb, ptr, name_len);
                    if (ptr) {
                        cJSON_AddStringToObject(root, "type CNAME name", ptr);
                    }
                }
                break;
            }
            case MX_Resource_RecordType: {
                BSB_LIMPORT_u16(dns_info_bsb, name_len);
                if (name_len > 0) {
                    BSB_LIMPORT_ptr(dns_info_bsb, ptr, name_len);
                    if (ptr) {
                        cJSON_AddStringToObject(root, "type MX name", ptr);
                    }
                }
                break;
            }
        }
    }

EXIT:
    qnsm_kafka_send_msg(QNSM_KAFKA_DNS_TOPIC, root, tuple->saddr.in4_addr.s_addr);

    if(root)
        cJSON_Delete(root);
    QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "leave\n");
    return;
}
void dns_free(void *sess, void *arg)
{
    DNS_INFO *dns_info = (DNS_INFO *)arg;
    uint16_t index = 0;
    QUESTION *query;

    if (dns_info) {
        for (index = 0; index < dns_info->ques_size; index++) {
            query = &dns_info->questions[index];
            if (query->qName) {
                free(query->qName);
                query->qName = NULL;
            }
        }
        QNSM_DEBUG(QNSM_DBG_M_DPI_DNS, QNSM_DBG_INFO, "free resource\n");
    }

    return;
}


static void* dns_udp_info_init(void)
{
    DNS_INFO *dns_info = NULL;

    dns_info = rte_zmalloc_socket(NULL, sizeof(DNS_INFO), QNSM_DDOS_MEM_ALIGN, rte_socket_id());
    if (NULL == dns_info) {
        QNSM_ASSERT(0);
    }

    dns_info->ques_size = DNS_QUESTION_DEFAULT;
    dns_info->questions = rte_zmalloc("DNS QUESTION", sizeof(QUESTION) * DNS_QUESTION_DEFAULT, QNSM_DDOS_MEM_ALIGN);
    if (NULL == dns_info->questions) {
        QNSM_ASSERT(0);
    }
    dns_info->rr_size = DNS_RR_DEFAULT;
    dns_info->rr = rte_zmalloc("DNS QUESTION", sizeof(RESOURCE_RECORD) * DNS_RR_DEFAULT, QNSM_DDOS_MEM_ALIGN);
    if (NULL == dns_info->rr) {
        QNSM_ASSERT(0);
    }
    return dns_info;
}

int32_t dns_reg(void)
{
    if (0 == qnsm_dpi_proto_enable(EN_QNSM_DPI_DNS)) {
        return 0;
    }

    {
        /*reg classfy to dpi by proto+port*/
        qnsm_dpi_service_classify_reg(EN_DPI_PROT_UDP, DNS_PORT, EN_QNSM_DPI_DNS, dns_udp_classify);

        /*reg dpi proc*/
        (void)qnsm_dpi_proto_init_reg(EN_QNSM_DPI_DNS, dns_udp_info_init);
        (void)qnsm_dpi_prot_reg(EN_QNSM_DPI_DNS, dns_parse, 10);
        (void)qnsm_dpi_prot_final_reg(EN_QNSM_DPI_DNS, dns_free);
    }

    return 0;
}

int32_t dns_init(void)
{
    dns_reg();

    return 0;
}



