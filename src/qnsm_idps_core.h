#ifndef __QNSM_IDPS_CORE_H__
#define __QNSM_IDPS_CORE_H__

#ifdef __cplusplus
extern "C" {
#endif

void *QnsmTmThreadsInit(const char* mode, const char *recv_mod_name, const char *decode_mod_name);
void QnsmTMThreadsRun(void *var);


#ifdef __cplusplus
}
#endif

#endif

