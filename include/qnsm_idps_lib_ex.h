#ifndef __QNSM_IDPS_LIB_EX_H__
#define __QNSM_IDPS_LIB_EX_H__

#ifdef __cplusplus
extern "C" {
#endif

int qnsm_idps_init(int argc, char **argv);
void qnsm_idps_wait(void);
int32_t qnsm_idps_sig_act(void);
void qnsm_idps_exit(void);



#ifdef __cplusplus
}
#endif

#endif
