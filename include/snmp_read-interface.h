#ifndef SNMP_READ_INTERFACE_H
#define SNMP_READ_INTERFACE_H

#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"

#include "snmp_defs.h"  // supondo que você tem as structs TipoSelecionado, IPInfo etc.

int f_PopulaDispositivos(IPInfo *dispositivos, int max_dispositivos);
void f_ExecutaLeituraSNMP(IPInfo *dispositivos, int total_ips);
void f_LiberaDispositivos(IPInfo *dispositivos, int total_ips);
void f_stopReadInterfaces();

#endif // SNMP_READ_INTERFACE_H
