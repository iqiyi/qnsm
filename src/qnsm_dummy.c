#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/time.h>
#include <sched.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_mbuf.h>

#include "util.h"
#include "qnsm_dbg.h"
#include "qnsm_service_ex.h"

/*
* dummy data, just pkt stats
*/
typedef struct {
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint32_t run_time;
} DUMMY_DATA;

void qnsm_dummy_pkt_proc(void *this_app_data, uint32_t lcore_id, struct rte_mbuf *mbuf)
{
    DUMMY_DATA *data = this_app_data;

    data->total_pkts++;
    data->total_bytes += rte_pktmbuf_pkt_len(mbuf);

    rte_pktmbuf_free(mbuf);
    return;
}

int32_t qnsm_dummy_init(void)
{
    DUMMY_DATA *data = NULL;

    data = qnsm_app_inst_init(sizeof(DUMMY_DATA),
                              qnsm_dummy_pkt_proc,
                              NULL,
                              NULL);
    if (NULL == data) {
        QNSM_ASSERT(0);
    }

    return 0;
}

#if QNSM_PART("cmd")

#endif
