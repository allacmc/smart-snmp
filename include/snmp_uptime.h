#pragma once

#include <stdint.h>
#include "lwip/sockets.h"  // necessário para struct sockaddr_in

#ifdef __cplusplus
extern "C" {
#endif

void f_RegisterUptimeTarget(const char *ip, int port, int display);
int  f_GetUptimeDisplay(const char *ip, int port);
void f_LiberaUptimeTargets(void);
void f_ProcessaUptimeSNMP(int sock, const char *ip, int port, struct sockaddr_in *dest);
esp_err_t f_GetDeviceUptime(int sock, const char *ip_address, long port, uint32_t *out_ticks);


#ifdef __cplusplus
}
#endif
