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
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>


/* RTE HEAD FILE*/
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_mbuf.h>

#include "qnsm_dbg.h"
#include "qnsm_service_ex.h"
#include "qnsm_idps_core.h"


enum en_qnsm_detect_mode {
    EN_QNSM_DETECT_IPS = 0,
    EN_QNSM_DETECT_IDS,
};

#define DETECT_MODE_MAP(XX)                    \
  XX(EN_QNSM_DETECT_IPS,     "IPS")            \
  XX(EN_QNSM_DETECT_IDS,     "IDS")

typedef struct {
    enum en_qnsm_detect_mode mode;
    void *tv;
} QNSM_DETECT_APP_DATA;


void qnsm_detect_run(void *para)
{
    QNSM_DETECT_APP_DATA *data = para;

    QNSM_ASSERT(data->tv);

    QnsmTMThreadsRun(data->tv);
    return;
}

/*
*now just support ids because of qnsm bypass deploy
*
*/
int32_t qnsm_detect_service_init(void)
{
    static const char *mode_strings[] = {
#define XX(num, string) string,
        DETECT_MODE_MAP(XX)
#undef XX
        0
    };
    QNSM_DETECT_APP_DATA *data = NULL;

    data = qnsm_app_inst_init(sizeof(QNSM_DETECT_APP_DATA),
                              NULL,
                              NULL,
                              NULL);
    if (NULL == data) {
        QNSM_ASSERT(0);
    }
    data->mode = EN_QNSM_DETECT_IDS;
    data->tv = NULL;

    /*todo : init mode by conf*/

    /*init thread vars*/
    data->tv = QnsmTmThreadsInit(mode_strings[data->mode], "QnsmReceive", "QnsmDecode");
    qnsm_service_run_reg(qnsm_detect_run);
    return 0;
}

