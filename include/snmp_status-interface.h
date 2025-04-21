#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "lwip/sockets.h"
#include "snmp_defs.h"

bool f_RegistraOIDStatusInterface(IPInfo *device, const char *display, int index);
void f_ProcessaStatusInterface(int sock, IPInfo *device, struct sockaddr_in *dest);
bool f_SnmpStatusBad(const char *status);
