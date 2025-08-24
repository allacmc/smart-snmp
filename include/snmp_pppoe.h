#pragma once

#include <stdint.h>
#include "lwip/sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

void f_RegisterPPPoETarget(const char *ip, int port, int display);
int  f_GetPPPoEDisplay(const char *ip, int port);
bool f_IsPPPoETarget(const char *ip, int port);
void f_LiberaPPPoETargets(void);
//void f_ProcessaPPPoECount(int sock, const char *ip, int port, struct sockaddr_in *dest);
void f_ProcessaPPPoECount(int sock, const char *ip, int port, struct sockaddr_in *dest, const char *communit, bool PrintDebug);

#ifdef __cplusplus
}
#endif
